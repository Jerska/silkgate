#!/usr/bin/env python3
"""`silkgate ui` tests: the events-file tailer, the history reader and the HTTP API.

Everything runs against a temp state tree — never ~/.silkgate — with the module's
directory attributes reassigned in setUp (UI_DIR included, so the static routes serve a
fixture directory: the real ui/ assets are not this module's contract). cli/silkgate has
no .py extension, so it is loaded through SourceFileLoader; no mitmproxy is needed. The
HTTP tests bind ("127.0.0.1", 0) and drive the server through http.client; the SSE tests
speak the protocol over a raw socket with a deadline, because http.client has no notion
of a response that never ends.

    python3 test/test_ui.py -v

What is covered:
  * _EventsTailer: EOF start, appended records with per-line cursors, a torn trailing
    line left for the next poll, in-place truncation, a proxy restart swapping the
    events path, a stale start cursor, and no proxy at all
  * _events_history/_event_passes: merge order across retained files, every filter
    (since/until/session/decision/method/host), session=null, the limit, garbage lines
  * HTTP: /api/sessions with and without a live proxy, /api/events filters + cursor +
    naive-timestamp 400, static routes with nosniff/CSP on every response, 404 on a
    traversal path, 405 on non-GET
  * SSE: retry preamble, record frames carrying resumable cursor ids, heartbeats while
    no proxy runs, and Last-Event-ID resume yielding only the suffix
  * cmd_ui: dies understandably without ui/ assets and on a taken port
"""
import contextlib
import http.client
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("SILKGATE_CLI", REPO / "cli" / "silkgate"))

_loader = SourceFileLoader("silkgate_cli_ui", str(CLI))
_spec = importlib.util.spec_from_file_location("silkgate_cli_ui", CLI, loader=_loader)
MOD = importlib.util.module_from_spec(_spec)
sys.modules["silkgate_cli_ui"] = MOD
_loader.exec_module(MOD)


def event(**kw):
    """One audit record with the addon's shape; keywords override any field."""
    rec = {"ts": "2026-08-04T12:00:00.000+00:00", "decision": "allow", "id": "f1",
           "method": "GET", "host": "api.anthropic.com", "port": 443,
           "path": "/v1/messages", "reason": "rule", "session": "demo",
           "listen_port": 8090}
    rec.update(kw)
    return rec


class _ControlSock(threading.Thread):
    """Answers the control protocol on a unix socket path, in-process — so the kernel
    names this test process as the peer, which is all _proxy_ident needs."""

    def __init__(self, path):
        super().__init__(daemon=True)
        self.path = str(path)
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(self.path)
        self.srv.listen(8)
        self.start()

    def run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn):
        with conn:
            f = conn.makefile("rw")
            for _ in f:
                f.write('{"ok": true}\n')
                f.flush()

    def close(self):
        self.srv.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass


class UiTest(unittest.TestCase):
    """Base: every path the module touches points into a temp tree, never ~/.silkgate,
    and UI_DIR points at a fixture directory this class populates."""

    maxDiff = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sgui-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        silk = self.root / "silk"
        self._saved = {k: getattr(MOD, k) for k in
                       ("SILK_DIR", "LOG_DIR", "SESSIONS_DIR", "PROXY_JSON",
                        "PROXY_SOCK", "UI_DIR")}
        self.addCleanup(self._restore)
        MOD.SILK_DIR = silk
        MOD.LOG_DIR = silk / "logs"
        MOD.SESSIONS_DIR = silk / "sessions"
        MOD.PROXY_JSON = silk / "proxy.json"
        MOD.PROXY_SOCK = silk / "proxy.sock"
        MOD.UI_DIR = self.root / "ui"
        MOD.LOG_DIR.mkdir(parents=True)
        MOD.SESSIONS_DIR.mkdir(parents=True)
        MOD.UI_DIR.mkdir()
        self.assets = {"index.html": "<!doctype html><title>silkgate</title>\n",
                       "app.js": "export {};\n", "store.js": "export const x = 1;\n",
                       "style.css": "body { }\n"}
        for name, text in self.assets.items():
            (MOD.UI_DIR / name).write_text(text)

    def _restore(self):
        for k, v in self._saved.items():
            setattr(MOD, k, v)

    # -- helpers ---------------------------------------------------------------

    def events_file(self, name, *recs):
        p = MOD.LOG_DIR / name
        p.write_text("".join(json.dumps(r) + "\n" for r in recs))
        return p

    def proxy_meta(self, events=None, **extra):
        meta = {"pid": os.getpid(), "base_port": 8090,
                "ports": list(range(8090, 8090 + MOD.POOL_SIZE)),
                "log": str(MOD.LOG_DIR / "proxy-live.log"),
                "sock": str(MOD.PROXY_SOCK), "started": "2026-08-04T11:00:00+00:00"}
        if events is not None:
            meta["events"] = str(events)
        meta.update(extra)
        MOD._write_json(MOD.PROXY_JSON, meta)
        return meta

    def write_session(self, name, port=8090):
        sdir = MOD.session_dir(name)
        sdir.mkdir(parents=True)
        MOD._write_json(sdir / "meta.json",
                        {"name": name, "sandbox": "sg-" + name, "port": port})


# -- the tailer -------------------------------------------------------------------

class EventsTailerTest(UiTest):

    def test_no_proxy_yields_nothing_and_keeps_waiting(self):
        t = MOD._EventsTailer()
        self.assertEqual(t.poll(None), [])
        self.assertEqual(t.poll({}), [])
        self.assertEqual(t.poll({"log": "x"}), [])   # a meta without an events file

    def test_starts_at_eof_and_streams_appends_with_cursors(self):
        first = event(id="old")
        p = self.events_file("events-live.jsonl", first)
        meta = {"events": str(p)}
        t = MOD._EventsTailer()
        self.assertEqual(t.poll(meta), [], "history is /api/events' job, not the stream's")
        line_a, line_b = json.dumps(event(id="a")), json.dumps(event(id="b"))
        with open(p, "a") as fh:
            fh.write(line_a + "\n" + line_b + "\n")
        out = t.poll(meta)
        base = len(json.dumps(first)) + 1
        self.assertEqual(out, [
            ("record", line_a, f"events-live.jsonl:{base + len(line_a) + 1}"),
            ("record", line_b, f"events-live.jsonl:{base + len(line_a) + len(line_b) + 2}"),
        ])
        self.assertEqual(t.poll(meta), [], "nothing new, nothing emitted")

    def test_cursor_resumes_mid_file(self):
        line_a, line_b = json.dumps(event(id="a")), json.dumps(event(id="b"))
        p = MOD.LOG_DIR / "events-live.jsonl"
        p.write_text(line_a + "\n" + line_b + "\n")
        t = MOD._EventsTailer(f"events-live.jsonl:{len(line_a) + 1}")
        out = t.poll({"events": str(p)})
        self.assertEqual([(k, v) for k, v, _ in out], [("record", line_b)],
                         "resume must yield only what follows the cursor")

    def test_torn_trailing_line_waits_for_its_newline(self):
        p = self.events_file("events-live.jsonl")
        meta = {"events": str(p)}
        t = MOD._EventsTailer()
        t.poll(meta)
        line = json.dumps(event(id="a"))
        with open(p, "a") as fh:
            fh.write(line[:10])                      # a write caught mid-line
        self.assertEqual(t.poll(meta), [])
        with open(p, "a") as fh:
            fh.write(line[10:] + "\n")
        out = t.poll(meta)
        self.assertEqual([(k, v) for k, v, _ in out], [("record", line)],
                         "the completed line must arrive whole, not split")

    def test_truncation_resets_and_replays_from_zero(self):
        line_a = json.dumps(event(id="a"))
        p = self.events_file("events-live.jsonl", event(id="x"), event(id="y"))
        meta = {"events": str(p)}
        t = MOD._EventsTailer()
        t.poll(meta)                                 # now at EOF of the two-line file
        p.write_text(line_a + "\n")                  # shorter: truncated in place
        out = t.poll(meta)
        self.assertEqual(out[0], ("reset", None, "events-live.jsonl:0"))
        self.assertEqual([(k, v) for k, v, _ in out[1:]], [("record", line_a)])

    def test_proxy_restart_swaps_the_file_and_adopts_it_from_zero(self):
        old = self.events_file("events-old.jsonl", event(id="x"))
        t = MOD._EventsTailer()
        t.poll({"events": str(old)})
        line = json.dumps(event(id="fresh"))
        new = MOD.LOG_DIR / "events-new.jsonl"
        new.write_text(line + "\n")
        out = t.poll({"events": str(new)})
        self.assertEqual(out[0], ("reset", None, "events-new.jsonl:0"))
        self.assertEqual(out[1], ("record", line, f"events-new.jsonl:{len(line) + 1}"),
                         "a fresh file is short: replaying it from 0 is the resync")

    def test_stale_cursor_resets_to_the_live_files_eof(self):
        p = self.events_file("events-live.jsonl", event(id="x"))
        t = MOD._EventsTailer("events-gone.jsonl:57")
        out = t.poll({"events": str(p)})
        size = p.stat().st_size
        self.assertEqual(out, [("reset", None, f"events-live.jsonl:{size}")],
                         "an unknown cursor must not replay the whole live file — the "
                         "client refetches history on reset")
        self.assertEqual(t.poll({"events": str(p)}), [])

    def test_garbage_line_is_skipped_but_advances_the_cursor(self):
        p = self.events_file("events-live.jsonl")
        meta = {"events": str(p)}
        t = MOD._EventsTailer()
        t.poll(meta)
        line = json.dumps(event(id="a"))
        with open(p, "a") as fh:
            fh.write("not json\n" + line + "\n")
        out = t.poll(meta)
        self.assertEqual([(k, v) for k, v, _ in out], [("record", line)])
        self.assertEqual(out[0][2], f"events-live.jsonl:{p.stat().st_size}")


# -- history ------------------------------------------------------------------------

class EventsHistoryTest(UiTest):

    def test_merges_files_in_stamp_order_and_skips_garbage(self):
        self.events_file("events-02.jsonl", event(id="c"))
        p = self.events_file("events-01.jsonl", event(id="a"), event(id="b"))
        with open(p, "a") as fh:
            fh.write("mitmdump chatter, not json\n[7]\n")   # a list parses; only dicts pass
        got = MOD._events_history({}, 100)
        self.assertEqual([r["id"] for r in got], ["a", "b", "c"],
                         "filename order is chronological order")

    def test_limit_keeps_the_newest(self):
        self.events_file("events-01.jsonl", *(event(id=f"r{i}") for i in range(6)))
        got = MOD._events_history({}, 2)
        self.assertEqual([r["id"] for r in got], ["r4", "r5"])

    def test_every_filter(self):
        recs = [event(id="a", session="demo", decision="allow", method="GET",
                      host="api.anthropic.com", ts="2026-08-04T12:00:00+00:00"),
                event(id="b", session="other", decision="deny", method="POST",
                      host="pypi.org", ts="2026-08-04T13:00:00+00:00"),
                event(id="c", session=None, decision="deny", method="GET",
                      host="evil.example", ts="2026-08-04T14:00:00+00:00")]
        self.events_file("events-01.jsonl", *recs)

        def ids(filters):
            return [r["id"] for r in MOD._events_history(filters, 100)]

        self.assertEqual(ids({"session": "demo"}), ["a"])
        self.assertEqual(ids({"session": "null"}), ["c"],
                         "session=null selects the unattributed records")
        self.assertEqual(ids({"decision": "deny"}), ["b", "c"])
        self.assertEqual(ids({"method": "post"}), ["b"], "method compares case-folded")
        self.assertEqual(ids({"host": "PYPI"}), ["b"], "host is a case-folded substring")
        from datetime import datetime
        since = datetime.fromisoformat("2026-08-04T12:30:00+00:00")
        until = datetime.fromisoformat("2026-08-04T13:30:00+00:00")
        self.assertEqual(ids({"since": since}), ["b", "c"])
        self.assertEqual(ids({"until": until}), ["a", "b"])
        self.assertEqual(ids({"since": since, "until": until}), ["b"])
        self.assertEqual(ids({"since": since, "session": "null"}), ["c"])

    def test_time_filter_excludes_records_without_a_usable_ts(self):
        from datetime import datetime
        self.events_file("events-01.jsonl", event(id="a", ts="not a time"),
                         event(id="b", ts="2026-08-04T12:00:00"),      # naive: unusable
                         event(id="c", ts="2026-08-04T12:00:00+00:00"))
        since = datetime.fromisoformat("2026-08-04T00:00:00+00:00")
        got = MOD._events_history({"since": since}, 100)
        self.assertEqual([r["id"] for r in got], ["c"],
                         "a record that cannot be placed in time fails a time filter")


# -- the HTTP server -----------------------------------------------------------------

class UiServerTest(UiTest):
    """Base for the endpoint tests: a live server on an ephemeral loopback port."""

    def setUp(self):
        super().setUp()
        self.server = MOD._ui_server(0)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def request(self, path, method="GET", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(conn.close)
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        return resp, resp.read()

    def get_json(self, path):
        resp, body = self.request(path)
        return resp, json.loads(body)


class UiHttpTest(UiServerTest):

    def assertSecured(self, resp):
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("Content-Security-Policy"),
                         "default-src 'self'")

    def test_static_routes_serve_the_fixture_with_the_right_types(self):
        for path, name, ctype in (("/", "index.html", "text/html"),
                                  ("/app.js", "app.js", "text/javascript"),
                                  ("/store.js", "store.js", "text/javascript"),
                                  ("/style.css", "style.css", "text/css")):
            resp, body = self.request(path)
            self.assertEqual(resp.status, 200, path)
            self.assertEqual(body.decode(), self.assets[name])
            self.assertTrue(resp.headers["Content-Type"].startswith(ctype), path)
            self.assertSecured(resp)

    def test_unrouted_and_traversal_paths_404(self):
        for path in ("/nope", "/index.html", "/../proxy.json", "/./app.js",
                     "/app.js/../../silk/proxy.json"):
            resp, _ = self.request(path)
            self.assertEqual(resp.status, 404, path)
            self.assertSecured(resp)

    def test_non_get_is_405(self):
        resp, _ = self.request("/", method="POST")
        self.assertEqual(resp.status, 405)
        self.assertSecured(resp)
        resp, _ = self.request("/api/events", method="PUT")
        self.assertEqual(resp.status, 405)

    def test_sessions_without_a_proxy(self):
        self.write_session("foo")
        self.write_session("bar")
        resp, got = self.get_json("/api/sessions")
        self.assertEqual(resp.status, 200)
        self.assertSecured(resp)
        self.assertEqual([s["name"] for s in got["sessions"]], ["bar", "foo"])
        self.assertFalse(got["proxy"]["running"])
        self.assertIsNone(got["proxy"]["pid"])

    def test_sessions_reports_the_live_proxy_by_socket_identity(self):
        srv = _ControlSock(MOD.PROXY_SOCK)
        self.addCleanup(srv.close)
        live = self.events_file("events-live.jsonl")
        self.proxy_meta(events=live)
        _, got = self.get_json("/api/sessions")
        self.assertTrue(got["proxy"]["running"])
        self.assertEqual(got["proxy"]["events"], str(live))
        self.assertEqual(got["proxy"]["ports"][0], 8090)

    def test_stale_proxy_json_alone_does_not_read_as_running(self):
        self.proxy_meta(events=self.events_file("events-live.jsonl"))
        _, got = self.get_json("/api/sessions")           # record exists, socket doesn't
        self.assertFalse(got["proxy"]["running"])

    def test_events_returns_history_and_the_live_cursor(self):
        self.events_file("events-01.jsonl", event(id="a"), event(id="b", session=None))
        live = self.events_file("events-02.jsonl", event(id="c"))
        self.proxy_meta(events=live)
        resp, got = self.get_json("/api/events")
        self.assertEqual(resp.status, 200)
        self.assertEqual([r["id"] for r in got["events"]], ["a", "b", "c"])
        self.assertEqual(got["cursor"], f"events-02.jsonl:{live.stat().st_size}")

    def test_events_cursor_is_null_without_a_proxy(self):
        self.events_file("events-01.jsonl", event(id="a"))
        _, got = self.get_json("/api/events")
        self.assertIsNone(got["cursor"])

    def test_events_filters_reach_the_records(self):
        self.events_file("events-01.jsonl",
                         event(id="a", session="demo", decision="allow"),
                         event(id="b", session=None, decision="deny"),
                         event(id="c", session="demo", decision="deny",
                               host="pypi.org", method="POST"))
        for query, want in (("session=demo", ["a", "c"]),
                            ("session=null", ["b"]),
                            ("decision=deny", ["b", "c"]),
                            ("method=post", ["c"]),
                            ("host=pypi", ["c"]),
                            ("session=demo&decision=deny", ["c"]),
                            ("limit=1", ["c"])):
            _, got = self.get_json(f"/api/events?{query}")
            self.assertEqual([r["id"] for r in got["events"]], want, query)

    def test_events_time_window(self):
        self.events_file("events-01.jsonl",
                         event(id="a", ts="2026-08-04T12:00:00+00:00"),
                         event(id="b", ts="2026-08-04T14:00:00+00:00"))
        _, got = self.get_json("/api/events?since=2026-08-04T13:00:00%2b00:00")
        self.assertEqual([r["id"] for r in got["events"]], ["b"])
        _, got = self.get_json("/api/events?until=2026-08-04T13:00:00%2b00:00")
        self.assertEqual([r["id"] for r in got["events"]], ["a"])

    def test_events_rejects_a_naive_since_with_400(self):
        resp, got = self.get_json("/api/events?since=2026-08-04T13:00:00")
        self.assertEqual(resp.status, 400)
        self.assertIn("offset", got["error"])
        resp, _ = self.get_json("/api/events?until=2026-08-04T13:00:00")
        self.assertEqual(resp.status, 400)
        resp, _ = self.get_json("/api/events?since=yesterday")
        self.assertEqual(resp.status, 400)

    def test_events_rejects_a_broken_limit(self):
        for query in ("limit=many", "limit=0", "limit=-3"):
            resp, _ = self.request(f"/api/events?{query}")
            self.assertEqual(resp.status, 400, query)

    def test_events_limit_is_capped(self):
        self.events_file("events-01.jsonl", event(id="a"))
        resp, got = self.get_json(f"/api/events?limit={MOD.UI_EVENTS_LIMIT_MAX * 10}")
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(got["events"]), 1)


# -- SSE over a raw socket -------------------------------------------------------------

class UiStreamTest(UiServerTest):

    DEADLINE = 5.0

    def setUp(self):
        super().setUp()
        # Real time still passes; only the waits shrink so the suite stays fast.
        self._patches = [mock.patch.object(MOD, "UI_STREAM_POLL", 0.02),
                         mock.patch.object(MOD, "UI_STREAM_HEARTBEAT", 0.2)]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def sse_open(self, cursor_header=None, cursor_param=None):
        """Open /api/stream raw; return the socket once the response head + the retry
        preamble arrived, with whatever body bytes followed them. Without a cursor the
        stream starts at the live file's EOF, sampled at the server's own pace — so a
        deterministic test pins its start with one, exactly as the real client does."""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=self.DEADLINE)
        self.addCleanup(s.close)
        path = "/api/stream" + (f"?cursor={cursor_param}" if cursor_param else "")
        req = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n"
        if cursor_header is not None:
            req += f"Last-Event-ID: {cursor_header}\r\n"
        s.sendall((req + "\r\n").encode())
        head = self.read_until(s, b"\r\n\r\n")
        self.assertIn(b" 200 ", head.split(b"\r\n", 1)[0])
        self.assertIn(b"Content-Type: text/event-stream", head)
        self.assertIn(b"Cache-Control: no-cache", head)
        self.assertIn(b"X-Content-Type-Options: nosniff", head)
        self.assertNotIn(b"Content-Length:", head, "an endless body cannot have one")
        body = head.split(b"\r\n\r\n", 1)[1]
        body = self.read_until(s, b"retry: 2000\n\n", got=body)
        return s, body

    def read_until(self, sock, token, got=b""):
        """Bytes received until `token` has been seen, bounded by a deadline."""
        deadline = time.monotonic() + self.DEADLINE
        data = got
        while token not in data:
            if time.monotonic() >= deadline:
                self.fail(f"SSE deadline: waited for {token!r}, got {data!r}")
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                self.fail(f"stream closed while waiting for {token!r}: {data!r}")
            data += chunk
        return data

    def test_records_arrive_as_frames_with_cursor_ids(self):
        live = self.events_file("events-live.jsonl")
        self.proxy_meta(events=live)
        s, _ = self.sse_open(cursor_param="events-live.jsonl:0")   # the /api/events handover
        line = json.dumps(event(id="a"))
        with open(live, "a") as fh:
            fh.write(line + "\n")
        frame = f"id: events-live.jsonl:{len(line) + 1}\ndata: {line}\n\n"
        data = self.read_until(s, frame.encode())
        self.assertNotIn(b"event: reset", data,
                         "a cursor for the live file resumes, it does not reset")

    def test_heartbeats_flow_while_no_proxy_runs(self):
        s, _ = self.sse_open()                       # no proxy.json at all
        data = self.read_until(s, b": alive\n\n")
        self.assertNotIn(b"data:", data, "nothing to say but the pipe stays warm")

    def test_last_event_id_resume_yields_only_the_suffix(self):
        line_a, line_b = json.dumps(event(id="a")), json.dumps(event(id="b"))
        live = MOD.LOG_DIR / "events-live.jsonl"
        live.write_text(line_a + "\n" + line_b + "\n")
        self.proxy_meta(events=live)
        s, body = self.sse_open(cursor_header=f"events-live.jsonl:{len(line_a) + 1}")
        data = self.read_until(s, line_b.encode(), got=body)
        self.assertNotIn(line_a.encode(), data,
                         "the record before the cursor must not be replayed")
        self.assertIn(f"id: events-live.jsonl:{len(line_a) + len(line_b) + 2}".encode(),
                      data)

    def test_proxy_restart_mid_stream_sends_reset_then_the_new_file(self):
        old = self.events_file("events-old.jsonl", event(id="x"))
        self.proxy_meta(events=old)
        s, _ = self.sse_open(cursor_header=f"events-old.jsonl:{old.stat().st_size}")
        (MOD.LOG_DIR / "events-new.jsonl").write_text("")   # a restart begins empty …
        self.proxy_meta(events=MOD.LOG_DIR / "events-new.jsonl")
        got = self.read_until(s, b"event: reset")
        line = json.dumps(event(id="fresh"))
        with open(MOD.LOG_DIR / "events-new.jsonl", "a") as fh:   # … then records land
            fh.write(line + "\n")
        data = self.read_until(s, line.encode(), got=got)
        self.assertIn(f"id: events-new.jsonl:{len(line) + 1}\ndata: {line}\n\n".encode(),
                      data, "after the reset, the stream follows the adopted file")
        self.assertNotIn(b'"id": "x"', data, "the old file's history is not replayed")


# -- cmd_ui ---------------------------------------------------------------------------

class CmdUiTest(UiTest):

    def cmd_ui(self, port):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                MOD.cmd_ui(types.SimpleNamespace(port=port))
        self.assertNotEqual(ctx.exception.code, 0)
        return err.getvalue()

    def test_dies_understandably_without_ui_assets(self):
        (MOD.UI_DIR / "index.html").unlink()
        msg = self.cmd_ui(port=0)
        self.assertIn("ui", msg)
        self.assertIn(str(MOD.UI_DIR), msg)

    def test_dies_naming_the_holder_when_the_port_is_taken(self):
        holder = socket.socket()
        self.addCleanup(holder.close)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        msg = self.cmd_ui(port=port)
        self.assertIn(str(port), msg)
        self.assertIn("lsof", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
