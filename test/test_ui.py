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
  * HTTP: /api/sessions with and without a live proxy (plus state/last_rc and the
    archived list), /api/events filters + cursor + naive-timestamp 400, static routes
    with nosniff/CSP on every response, 404 on a traversal path, 405 on non-GET
  * SSE: retry preamble, record frames carrying resumable cursor ids, heartbeats while
    no proxy runs, and Last-Event-ID resume yielding only the suffix — for the audit
    stream and (parameterized) the capture stream
  * wave 2: the new static routes and their traversal 404s, the CSRF/rebinding matrix,
    /api/session/<ident> (live + archived + bad idents + the briefs map with its
    per-exec/default/workspace source labeling),
    /output (TTL cache, caps), /api/metrics (TTL, empty registry, cached failures),
    /diff (guest/host modes, 409s, 429, truncation) with stubbed seams, /api/capture
    history, /api/search (substring, caps, min length), and the control plane
    (freeze/resume swap round-trip, kill argv, down through the stubbed teardown)
  * the shipped ui/ sources (NOT the fixtures): no markup sinks, and every reference
    in a served file resolves to a _UI_ROUTES key
  * cmd_ui: dies understandably without ui/ assets and on a taken port
"""
import contextlib
import hashlib
import http.client
import importlib.util
import io
import json
import os
import posixpath
import re
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
                       ("SILK_DIR", "LOG_DIR", "SESSIONS_DIR", "ARCHIVE_DIR",
                        "PROXY_JSON", "PROXY_SOCK", "UI_DIR")}
        self.addCleanup(self._restore)
        MOD.SILK_DIR = silk
        MOD.LOG_DIR = silk / "logs"
        MOD.SESSIONS_DIR = silk / "sessions"
        MOD.ARCHIVE_DIR = silk / "archive"
        MOD.PROXY_JSON = silk / "proxy.json"
        MOD.PROXY_SOCK = silk / "proxy.sock"
        MOD.UI_DIR = self.root / "ui"
        MOD.LOG_DIR.mkdir(parents=True)
        MOD.SESSIONS_DIR.mkdir(parents=True)
        MOD.UI_DIR.mkdir()
        # The wave-2 caches and the busy set live once per process; every test
        # starts them cold so no test reads another's answers.
        MOD._METRICS_CACHE.update(at=None, payload=None)
        MOD._OUTPUT_CACHE.clear()
        MOD._DIFF_BUSY.clear()
        self.assets = {"index.html": "<!doctype html><title>silkgate</title>\n",
                       "app.js": "export {};\n", "store.js": "export const x = 1;\n",
                       "style.css": "body { }\n",
                       "router.js": "export {};\n", "capture.js": "export {};\n",
                       "pricing.js": "export {};\n", "render.js": "export {};\n",
                       "views/overview.js": "export {};\n",
                       "views/session.js": "export {};\n",
                       "views/calls.js": "export {};\n"}
        for name, text in self.assets.items():
            p = MOD.UI_DIR / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

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

    def write_session(self, name, port=8090, rules="api.anthropic.com/** GET\n",
                      **extra):
        sdir = MOD.session_dir(name)
        sdir.mkdir(parents=True)
        (sdir / "rules.txt").write_text(rules)
        MOD._write_json(sdir / "meta.json",
                        {"name": name, "sandbox": "sg-" + name, "port": port, **extra})
        return sdir

    def write_archive(self, name="old1", **extra):
        """One archived session dir under the repointed ARCHIVE_DIR -> (sid, dir)."""
        sid = MOD._new_sid(name)
        adir = MOD.ARCHIVE_DIR / sid
        adir.mkdir(parents=True)
        MOD._write_json(adir / "meta.json",
                        {"name": name, "sandbox": "sg-" + name, "port": 8091,
                         "sid": sid, "created": "2026-08-04T10:00:00+00:00",
                         "ended": "2026-08-04T12:00:00+00:00", **extra})
        return sid, adir


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

    # 20 s, not 5: the stream tests wait on real socket reads, and a loaded machine
    # (the sharded runner beside other suites) has pushed a 5 s wait past its deadline.
    DEADLINE = 20.0

    def setUp(self):
        super().setUp()
        # Real time still passes; only the waits shrink so the suite stays fast.
        self._patches = [mock.patch.object(MOD, "UI_STREAM_POLL", 0.02),
                         mock.patch.object(MOD, "UI_STREAM_HEARTBEAT", 0.2)]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def sse_open(self, cursor_header=None, cursor_param=None, endpoint="/api/stream"):
        """Open an SSE endpoint raw; return the socket once the response head + the
        retry preamble arrived, with whatever body bytes followed them. Without a
        cursor the stream starts at the live file's EOF, sampled at the server's own
        pace — so a deterministic test pins its start with one, exactly as the real
        client does."""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=self.DEADLINE)
        self.addCleanup(s.close)
        path = endpoint + (f"?cursor={cursor_param}" if cursor_param else "")
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


# -- the wave-2 static routes ---------------------------------------------------------

class UiWave2StaticTest(UiServerTest):

    def test_new_routes_serve_javascript(self):
        for path in ("/router.js", "/capture.js", "/pricing.js", "/render.js",
                     "/views/overview.js", "/views/session.js", "/views/calls.js"):
            resp, body = self.request(path)
            self.assertEqual(resp.status, 200, path)
            self.assertEqual(body.decode(), self.assets[path.lstrip("/")], path)
            self.assertTrue(resp.headers["Content-Type"].startswith("text/javascript"),
                            path)
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")

    def test_traversal_and_test_files_stay_unserved(self):
        (MOD.UI_DIR / "store.test.js").write_text("export {};\n")
        (MOD.UI_DIR / "fixtures.test.js").write_text("export {};\n")
        for path in ("/views/../store.js", "/views/../../silk/proxy.json",
                     "/store.test.js", "/fixtures.test.js", "/views/",
                     "/views/nope.js"):
            resp, _ = self.request(path)
            self.assertEqual(resp.status, 404, path)


# -- CSRF / rebinding ------------------------------------------------------------------

class UiCsrfTest(UiServerTest):

    def test_evil_origin_is_403_on_get_and_post(self):
        for path, method in (("/", "GET"), ("/api/sessions", "GET"),
                             ("/api/session/x/freeze", "POST"),
                             ("/api/session/x/resume", "POST"),
                             ("/api/session/x/down", "POST"),
                             ("/api/session/x/diff", "POST"),
                             ("/api/session/x/exec/cafe1234/kill", "POST")):
            resp, body = self.request(path, method=method,
                                      headers={"Origin": "https://evil.example"})
            self.assertEqual(resp.status, 403, path)
            self.assertIn("forbidden", json.loads(body)["error"])

    def test_rebound_host_is_403(self):
        for host in ("evil.example", "evil.example:8642", "10.1.2.3:80"):
            resp, _ = self.request("/api/sessions", headers={"Host": host})
            self.assertEqual(resp.status, 403, host)

    def test_loopback_host_without_origin_passes(self):
        resp, _ = self.request("/api/sessions")     # http.client sends Host itself
        self.assertEqual(resp.status, 200)
        for host in ("localhost:1", "127.0.0.1", "[::1]:8642"):
            resp, _ = self.request("/api/sessions", headers={"Host": host})
            self.assertEqual(resp.status, 200, host)

    def test_loopback_origin_passes(self):
        resp, _ = self.request("/api/sessions",
                               headers={"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(resp.status, 200)

    def test_null_origin_is_403(self):
        resp, _ = self.request("/api/sessions", headers={"Origin": "null"})
        self.assertEqual(resp.status, 403)

    def test_put_stays_405_and_post_off_the_control_plane_too(self):
        resp, _ = self.request("/api/session/x/freeze", method="PUT")
        self.assertEqual(resp.status, 405)
        resp, _ = self.request("/api/events", method="POST")
        self.assertEqual(resp.status, 405)


# -- /api/sessions extensions -----------------------------------------------------------

class UiSessionsListTest(UiServerTest):

    def test_live_rows_carry_state_and_last_rc(self):
        self.write_session("foo", last_rc=7)
        self.write_session("bar")
        _, got = self.get_json("/api/sessions")
        by_name = {s["name"]: s for s in got["sessions"]}
        self.assertEqual(by_name["foo"]["state"], "live")
        self.assertEqual(by_name["foo"]["last_rc"], 7)
        self.assertNotIn("last_rc", by_name["bar"])

    def test_frozen_rows_say_so_and_resume_restores_live(self):
        self.write_session("foo")
        resp, _ = self.request("/api/session/foo/freeze", method="POST")
        self.assertEqual(resp.status, 200)
        _, got = self.get_json("/api/sessions")
        self.assertEqual(got["sessions"][0]["state"], "frozen",
                         "the row reports the real state, not a stamp")
        resp, _ = self.request("/api/session/foo/resume", method="POST")
        self.assertEqual(resp.status, 200)
        _, got = self.get_json("/api/sessions")
        self.assertEqual(got["sessions"][0]["state"], "live")

    def test_archived_rows_are_the_newest_fifty_reduced(self):
        old = [self.write_archive(f"s{i}")[0] for i in range(3)]
        _, got = self.get_json("/api/sessions")
        self.assertEqual([a["sid"] for a in got["archived"]], old[::-1],
                         "newest first")
        self.assertEqual(set(got["archived"][0]), {"sid", "name", "created", "ended"},
                         "reduced rows; /api/session/<sid> has the rest")
        with mock.patch.object(MOD, "UI_ARCHIVED_LIMIT", 2):
            _, got = self.get_json("/api/sessions")
        self.assertEqual(len(got["archived"]), 2)
        self.assertEqual(got["archived"][0]["sid"], old[-1])

    def test_archived_row_carries_branch_only_when_the_meta_names_one(self):
        # A branch meta must also name a valid base, or read_archived_meta
        # refuses the whole meta (_check_meta_fields).
        withb, _ = self.write_archive("withb", branch="agent/x", base=_BASE)
        plain, _ = self.write_archive("plain")
        _, got = self.get_json("/api/sessions")
        by_sid = {a["sid"]: a for a in got["archived"]}
        self.assertEqual(by_sid[withb]["branch"], "agent/x")
        self.assertNotIn("branch", by_sid[plain])


# -- /api/session/<ident> ---------------------------------------------------------------

class UiSessionDetailTest(UiServerTest):

    def test_live_session_detail(self):
        sdir = self.write_session("s1", rules="pypi.org/** GET\n")
        MOD._journal("s1", "created", meta={})
        MOD._journal("s1", "exec_start", exec_id="cafe1234", argv=["true"])
        cap = self.events_file("capture-01.jsonl")
        resp, got = self.get_json("/api/session/s1")
        self.assertEqual(resp.status, 200)
        self.assertEqual(got["state"], "live")
        self.assertEqual(got["session"]["name"], "s1")
        self.assertEqual([r["event"] for r in got["journal"]],
                         ["created", "exec_start"])
        self.assertEqual(got["rules"], "pypi.org/** GET\n")
        self.assertEqual(got["briefs"], {}, "no brief anywhere: an empty map")
        self.assertNotIn("brief", got, "the singular field is gone — briefs is the map")
        self.assertEqual(got["pointers"]["captures"], [str(cap)])
        self.assertIsNone(got["pointers"]["events"], "no proxy runs")

    def test_frozen_live_session_reports_frozen_and_archived_stays_archived(self):
        self.write_session("s7")
        resp, _ = self.request("/api/session/s7/freeze", method="POST")
        self.assertEqual(resp.status, 200)
        _, got = self.get_json("/api/session/s7")
        self.assertEqual(got["state"], "frozen")
        sid, _ = self.write_archive("oldf")
        _, got = self.get_json(f"/api/session/{sid}")
        self.assertEqual(got["state"], "archived",
                         "frozen is a live-session state; archive is placement")

    def test_default_brief_is_keyed_and_labeled_and_beats_the_fallback(self):
        sdir = self.write_session("s2", workspace=str(self.root / "ws"))
        (self.root / "ws").mkdir()
        (self.root / "ws" / "BRIEF.md").write_text("# from the guest\n")
        (sdir / "brief.md").write_bytes(b"# the operator's ask\n")
        _, got = self.get_json("/api/session/s2")
        self.assertEqual(sorted(got["briefs"]), ["default"],
                         "an operator brief exists, so the fallback stays out")
        entry = got["briefs"]["default"]
        self.assertEqual(entry["source"], "default")
        self.assertEqual(entry["text"], "# the operator's ask\n")
        self.assertEqual(entry["sha256"],
                         hashlib.sha256(b"# the operator's ask\n").hexdigest())
        self.assertFalse(entry["truncated"])

    def test_exec_briefs_are_keyed_by_exec_id_with_journaled_sources(self):
        sdir = self.write_session("s6")
        (sdir / "brief.md").write_bytes(b"# the default\n")
        bdir = sdir / "briefs"
        bdir.mkdir()
        (bdir / "cafe1234.md").write_bytes(b"# exec one's own ask\n")
        (bdir / "beef5678.md").write_bytes(b"# the default\n")
        (bdir / "not-an-exec-id.md").write_bytes(b"planted\n")
        MOD._journal("s6", "exec_start", exec_id="cafe1234", argv=["true"],
                     brief_sha256="x", brief_source="flag")
        MOD._journal("s6", "exec_start", exec_id="beef5678", argv=["true"],
                     brief_sha256="y", brief_source="default")
        _, got = self.get_json("/api/session/s6")
        self.assertEqual(sorted(got["briefs"]),
                         ["beef5678", "cafe1234", "default"],
                         "one entry per exec brief plus the session default; a "
                         "foreign file in briefs/ is never served")
        self.assertEqual(got["briefs"]["cafe1234"]["source"], "flag")
        self.assertEqual(got["briefs"]["cafe1234"]["text"], "# exec one's own ask\n")
        self.assertEqual(got["briefs"]["beef5678"]["source"], "default",
                         "the journal's exec_start record labels each entry")
        self.assertEqual(
            got["briefs"]["cafe1234"]["sha256"],
            hashlib.sha256(b"# exec one's own ask\n").hexdigest(),
            "the sha covers the bytes served")

    def test_workspace_brief_is_the_live_fallback(self):
        self.write_session("s3", workspace=str(self.root / "ws"))
        (self.root / "ws").mkdir()
        (self.root / "ws" / "BRIEF.md").write_text("# guest-authored\n")
        _, got = self.get_json("/api/session/s3")
        self.assertEqual(sorted(got["briefs"]), ["workspace"])
        self.assertEqual(got["briefs"]["workspace"]["source"], "workspace",
                         "guest-writable, and the label says so")
        self.assertEqual(got["briefs"]["workspace"]["text"], "# guest-authored\n")

    def test_symlinked_workspace_brief_is_not_followed(self):
        secret = self.root / "secret.txt"
        secret.write_text("host secret\n")
        self.write_session("s4", workspace=str(self.root / "ws"))
        (self.root / "ws").mkdir()
        (self.root / "ws" / "BRIEF.md").symlink_to(secret)
        _, got = self.get_json("/api/session/s4")
        self.assertEqual(got["briefs"], {})

    def test_briefs_are_capped_and_marked_truncated(self):
        sdir = self.write_session("s5")
        (sdir / "brief.md").write_bytes(b"x" * (MOD.UI_BRIEF_MAX_BYTES + 5))
        (sdir / "briefs").mkdir()
        (sdir / "briefs" / "cafe1234.md").write_bytes(
            b"y" * (MOD.UI_BRIEF_MAX_BYTES + 5))
        _, got = self.get_json("/api/session/s5")
        for key in ("default", "cafe1234"):
            self.assertTrue(got["briefs"][key]["truncated"], key)
            self.assertEqual(len(got["briefs"][key]["text"]),
                             MOD.UI_BRIEF_MAX_BYTES, key)

    def test_archived_session_detail_without_workspace_fallback(self):
        sid, adir = self.write_archive("olda", workspace=str(self.root / "ws"))
        (self.root / "ws").mkdir()
        (self.root / "ws" / "BRIEF.md").write_text("# too late\n")
        (adir / "rules.txt").write_text("RULES\n")
        MOD._journal_into(adir, "down")
        _, got = self.get_json(f"/api/session/{sid}")
        self.assertEqual(got["state"], "archived")
        self.assertEqual(got["session"]["sid"], sid)
        self.assertEqual([r["event"] for r in got["journal"]], ["down"])
        self.assertEqual(got["rules"], "RULES\n")
        self.assertEqual(got["briefs"], {}, "the fallback is for live sessions alone")

    def test_archived_briefs_still_serve(self):
        sid, adir = self.write_archive("oldb")
        (adir / "brief.md").write_bytes(b"# archived ask\n")
        (adir / "briefs").mkdir()
        (adir / "briefs" / "cafe1234.md").write_bytes(b"# archived exec ask\n")
        _, got = self.get_json(f"/api/session/{sid}")
        self.assertEqual(got["briefs"]["default"]["source"], "default")
        self.assertEqual(got["briefs"]["cafe1234"]["text"], "# archived exec ask\n")

    def test_bad_idents_are_404_never_paths(self):
        for ident in ("..", "no-such", "20990101T000000Z-gone-abcdef",
                      "a" * 33, "x%2f..%2fy"):
            resp, _ = self.get_json(f"/api/session/{ident}")
            self.assertEqual(resp.status, 404, ident)

    def test_planted_meta_is_refused_as_404(self):
        sdir = MOD.session_dir("evil")
        sdir.mkdir(parents=True)
        MOD._write_json(sdir / "meta.json", {"name": "other"})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            resp, _ = self.get_json("/api/session/evil")
        self.assertEqual(resp.status, 404)


# -- /api/session/<ident>/output --------------------------------------------------------

class UiOutputTest(UiServerTest):

    def test_archived_output_reads_the_snapshot(self):
        sid, adir = self.write_archive("olda")
        (adir / "output.log").write_text("one\ntwo\nthree\n")
        _, got = self.get_json(f"/api/session/{sid}/output?tail=2")
        self.assertEqual(got, {"source": "archive", "lines": ["two", "three"],
                               "truncated": True})
        _, got = self.get_json(f"/api/session/{sid}/output")
        self.assertEqual(got["lines"], ["one", "two", "three"])
        self.assertFalse(got["truncated"])

    def test_live_output_is_cached_per_ttl(self):
        self.write_session("s1")
        calls = []

        def fake_logs(sandbox, tail_n=None, since=None):
            calls.append((sandbox, tail_n))
            return ["line"], None

        with mock.patch.object(MOD, "_run_msb_logs", fake_logs):
            _, got = self.get_json("/api/session/s1/output")
            _, again = self.get_json("/api/session/s1/output")
        self.assertEqual(got["source"], "live")
        self.assertEqual(got["lines"], ["line"])
        self.assertFalse(got["truncated"], "a short tail means msb had no more")
        self.assertEqual(calls, [("sg-s1", MOD.UI_OUTPUT_TAIL)],
                         "two requests inside the TTL cost one msb call")
        self.assertEqual(again, got)

    def test_live_failure_is_502_and_cached(self):
        self.write_session("s2")
        calls = []

        def dead(sandbox, tail_n=None, since=None):
            calls.append(sandbox)
            return None, "sandbox gone"

        with mock.patch.object(MOD, "_run_msb_logs", dead):
            resp, got = self.get_json("/api/session/s2/output")
            self.get_json("/api/session/s2/output")
        self.assertEqual(resp.status, 502)
        self.assertIn("sandbox gone", got["error"])
        self.assertEqual(len(calls), 1, "a dead sandbox is not re-poked every poll")

    def test_tail_is_validated_and_capped(self):
        self.write_session("s3")
        for query in ("tail=abc", "tail=0", "tail=-1"):
            resp, _ = self.request(f"/api/session/s3/output?{query}")
            self.assertEqual(resp.status, 400, query)
        seen = []

        def fake_logs(sandbox, tail_n=None, since=None):
            seen.append(tail_n)
            return [], None

        with mock.patch.object(MOD, "_run_msb_logs", fake_logs):
            self.get_json("/api/session/s3/output?tail=999999")
        self.assertEqual(seen, [MOD.UI_OUTPUT_TAIL_MAX])

    def test_unknown_ident_is_404(self):
        resp, _ = self.get_json("/api/session/none/output")
        self.assertEqual(resp.status, 404)


# -- /api/metrics ------------------------------------------------------------------------

class UiMetricsTest(UiServerTest):

    def test_empty_registry_skips_the_subprocess(self):
        calls = []
        with mock.patch.object(MOD, "_run_msb_metrics",
                               lambda: calls.append(1) or []):
            resp, got = self.get_json("/api/metrics")
        self.assertEqual(resp.status, 200)
        self.assertEqual(got["metrics"], [])
        self.assertEqual(got["ttl"], MOD.UI_METRICS_TTL)
        self.assertIn("sampled", got)
        self.assertEqual(calls, [], "no live sessions: nothing to ask msb about")

    def test_two_requests_inside_the_ttl_cost_one_seam_call(self):
        self.write_session("s1")
        calls = []

        def fake_metrics():
            calls.append(1)
            return [{"name": "sg-s1", "cpu_pct": 12, "mem_mib": 256}]

        with mock.patch.object(MOD, "_run_msb_metrics", fake_metrics):
            _, first = self.get_json("/api/metrics")
            _, second = self.get_json("/api/metrics")
        self.assertEqual(len(calls), 1)
        self.assertEqual(first["metrics"],
                         [{"session": "s1", "cpu_pct": 12, "mem_mib": 256}],
                         "msb's sandbox row becomes the session's, renamed")
        self.assertEqual(second, first)

    def test_failure_is_cached_too(self):
        self.write_session("s1")
        calls = []

        def broken():
            calls.append(1)
            return None

        with mock.patch.object(MOD, "_run_msb_metrics", broken):
            _, got = self.get_json("/api/metrics")
            self.get_json("/api/metrics")
        self.assertEqual(got["metrics"], [])
        self.assertEqual(len(calls), 1, "a hung msb is not re-poked inside the TTL")

    def test_memory_gauge_is_served_as_rss_beside_an_untouched_limit(self):
        """msb's memory gauge is the VMM process's host RSS, which can honestly read
        above the guest cap — so the row names it memory_rss_bytes and keeps the
        limit a separate field, never a denominator."""
        self.write_session("s1")
        fake = [{"name": "sg-s1", "cpu_percent": 3, "memory_bytes": 880_000_000,
                 "memory_limit_bytes": 512 << 20, "uptime_secs": 60}]
        with mock.patch.object(MOD, "_run_msb_metrics", lambda: fake):
            _, got = self.get_json("/api/metrics")
        row = got["metrics"][0]
        self.assertEqual(row["memory_rss_bytes"], 880_000_000)
        self.assertNotIn("memory_bytes", row, "the ambiguous name must not survive")
        self.assertEqual(row["memory_limit_bytes"], 512 << 20)
        self.assertEqual(row["cpu_percent"], 3, "other gauges pass through unchanged")


# -- /api/session/<ident>/diff ------------------------------------------------------------

_BASE = "0" * 40


class UiDiffTest(UiServerTest):

    def post_json(self, path, headers=None):
        resp, body = self.request(path, method="POST", headers=headers)
        return resp, json.loads(body)

    def branch_session(self, name="b1"):
        return self.write_session(name, branch="agent/x", base=_BASE,
                                  git_dir="/g/.git", workspace="/w",
                                  workspace_derived=True)

    def test_live_branch_diff_is_guest_mode(self):
        self.branch_session()
        seen = {}

        def fake_diff(meta):
            seen["meta"] = meta
            return " M a.py\n", "diff --git a/a.py b/a.py\n", None

        with mock.patch.object(MOD, "_diff_in_guest", fake_diff):
            resp, got = self.post_json("/api/session/b1/diff")
        self.assertEqual(resp.status, 200)
        self.assertEqual(got, {"mode": "guest", "status": " M a.py\n",
                               "diff": "diff --git a/a.py b/a.py\n",
                               "truncated": False})
        self.assertEqual(seen["meta"]["name"], "b1")

    def test_live_checkout_diff_is_guest_mode_too(self):
        self.write_session("c1", checkout="HEAD", base=_BASE, git_dir="/g/.git")
        with mock.patch.object(MOD, "_diff_in_guest",
                               lambda meta: ("", "the diff", None)):
            resp, got = self.post_json("/api/session/c1/diff")
        self.assertEqual(resp.status, 200)
        self.assertEqual(got["mode"], "guest")

    def test_live_session_without_git_is_409(self):
        self.write_session("p1")
        resp, got = self.post_json("/api/session/p1/diff")
        self.assertEqual(resp.status, 409)
        self.assertIn("no git", got["error"])

    def test_guest_failure_is_409(self):
        self.branch_session()
        with mock.patch.object(MOD, "_diff_in_guest",
                               lambda meta: (None, None, "guest did not answer")):
            resp, got = self.post_json("/api/session/b1/diff")
        self.assertEqual(resp.status, 409)
        self.assertIn("guest did not answer", got["error"])

    def test_diff_is_capped_and_marked_truncated(self):
        self.branch_session()
        with mock.patch.object(MOD, "_diff_in_guest",
                               lambda meta: ("", "d" * 64, None)), \
                mock.patch.object(MOD, "_DIFF_MAX_BYTES", 16):
            _, got = self.post_json("/api/session/b1/diff")
        self.assertTrue(got["truncated"])
        self.assertEqual(got["diff"], "d" * 16)

    def test_busy_session_answers_429(self):
        self.branch_session()
        MOD._DIFF_BUSY.add("b1")
        try:
            resp, got = self.post_json("/api/session/b1/diff")
        finally:
            MOD._DIFF_BUSY.discard("b1")
        self.assertEqual(resp.status, 429)
        self.assertIn("already running", got["error"])

    def test_archived_ingested_branch_diffs_on_the_host(self):
        sid, _ = self.write_archive("olda", branch="agent/x", base=_BASE,
                                    git_dir="/g/.git", workspace="/w",
                                    branch_ingested="1" * 40)
        seen = {}

        def fake_git(git_dir, *argv):
            seen["git_dir"], seen["argv"] = git_dir, argv
            return types.SimpleNamespace(returncode=0, stdout="the host diff")

        with mock.patch.object(MOD, "_git", fake_git):
            resp, got = self.post_json(f"/api/session/{sid}/diff")
        self.assertEqual(resp.status, 200)
        self.assertEqual(got, {"mode": "host", "status": "", "diff": "the host diff",
                               "truncated": False})
        self.assertEqual(seen["git_dir"], "/g/.git")
        self.assertEqual(seen["argv"],
                         ("diff", f"{_BASE}..refs/heads/agent/x"))

    def test_archived_never_harvested_is_409(self):
        sid, _ = self.write_archive("oldb", branch="agent/x", base=_BASE,
                                    git_dir="/g/.git", workspace="/w")
        resp, got = self.post_json(f"/api/session/{sid}/diff")
        self.assertEqual(resp.status, 409)
        self.assertIn("never harvested", got["error"])

    def test_archived_without_branch_is_409(self):
        sid, _ = self.write_archive("oldc")
        resp, _ = self.post_json(f"/api/session/{sid}/diff")
        self.assertEqual(resp.status, 409)

    def test_host_git_failure_is_409(self):
        sid, _ = self.write_archive("oldd", branch="agent/x", base=_BASE,
                                    git_dir="/g/.git", workspace="/w",
                                    branch_ingested="1" * 40)
        with mock.patch.object(MOD, "_git", lambda *a: None):
            resp, _ = self.post_json(f"/api/session/{sid}/diff")
        self.assertEqual(resp.status, 409)

    def test_diff_is_post_only(self):
        self.branch_session()
        resp, _ = self.request("/api/session/b1/diff")
        self.assertEqual(resp.status, 404, "GET has no diff route")

    def test_diff_seam_builds_a_no_pager_git_argv(self):
        """The in-guest gits must never page: a pager blocks the exec against its
        timeout and draws its chrome on the guest console, which the session's
        output snapshot reads. Output must ride the captured exec channel alone."""
        for meta in ({"sandbox": "sg-b1", "branch": "agent/x", "base": _BASE},
                     {"sandbox": "sg-c1", "checkout": "HEAD", "base": _BASE}):
            seen = {}

            def fake_run(argv, **kwargs):
                seen["argv"], seen["kwargs"] = argv, kwargs
                return types.SimpleNamespace(
                    returncode=0, stdout="SILKGATE_DIFF_SPLIT\n", stderr="")

            with mock.patch.object(MOD, "_msb", lambda: "msb"), \
                    mock.patch.object(MOD.subprocess, "run", fake_run):
                MOD._diff_in_guest(meta)
            script = seen["argv"][seen["argv"].index("-c") + 1]
            self.assertIn("git --no-pager status --porcelain", script)
            self.assertIn('git --no-pager diff "$1"', script)
            self.assertIn("GIT_PAGER=cat", script)
            self.assertNotRegex(script, r"(?<!--no-pager )git (status|diff)",
                                "every git in the seam must carry --no-pager")
            self.assertEqual(seen["argv"][-1], meta["base"],
                             "the base rides argv, never spliced into the script")
            self.assertTrue(seen["kwargs"].get("capture_output"),
                            "diff output is captured host-side, off the console")


# -- /api/capture -------------------------------------------------------------------------

def capture_event(**kw):
    rec = {"ts": "2026-08-04T12:00:00+00:00", "kind": "turn_start", "id": "f1",
           "session": "demo", "exec": "cafe1234", "model": "claude-fable-5"}
    rec.update(kw)
    return rec


class UiCaptureTest(UiServerTest):

    def test_history_merges_files_and_filters_by_session(self):
        self.events_file("capture-01.jsonl", capture_event(id="a"),
                         capture_event(id="b", session="other"))
        self.events_file("capture-02.jsonl", capture_event(id="c"))
        _, got = self.get_json("/api/capture")
        self.assertEqual([r["id"] for r in got["events"]], ["a", "b", "c"])
        _, got = self.get_json("/api/capture?session=demo")
        self.assertEqual([r["id"] for r in got["events"]], ["a", "c"])
        _, got = self.get_json("/api/capture?limit=1")
        self.assertEqual([r["id"] for r in got["events"]], ["c"])

    def test_capture_ignores_the_audit_trail_and_vice_versa(self):
        self.events_file("events-01.jsonl", event(id="audit1"))
        self.events_file("capture-01.jsonl", capture_event(id="cap1"))
        _, got = self.get_json("/api/capture")
        self.assertEqual([r["id"] for r in got["events"]], ["cap1"])
        _, got = self.get_json("/api/events")
        self.assertEqual([r["id"] for r in got["events"]], ["audit1"])

    def test_cursor_names_the_live_capture_file(self):
        live = self.events_file("capture-live.jsonl", capture_event(id="a"))
        self.proxy_meta(events=self.events_file("events-live.jsonl"),
                        capture=str(live))
        _, got = self.get_json("/api/capture")
        self.assertEqual(got["cursor"], f"capture-live.jsonl:{live.stat().st_size}")

    def test_cursor_is_null_without_a_proxy(self):
        self.events_file("capture-01.jsonl", capture_event(id="a"))
        _, got = self.get_json("/api/capture")
        self.assertIsNone(got["cursor"])

    def test_bad_limit_is_400(self):
        for query in ("limit=many", "limit=0"):
            resp, _ = self.request(f"/api/capture?{query}")
            self.assertEqual(resp.status, 400, query)


class UiCaptureStreamTest(UiStreamTest):
    """The capture stream is the audit stream pointed at the other trail, so one
    resume test and one follow test pin the parameterization; the shared semantics
    are UiStreamTest's."""

    def test_capture_records_arrive_as_frames(self):
        live = self.events_file("capture-live.jsonl")
        self.proxy_meta(capture=str(live))
        s, _ = self.sse_open(cursor_param="capture-live.jsonl:0",
                             endpoint="/api/capture/stream")
        line = json.dumps(capture_event(id="a"))
        with open(live, "a") as fh:
            fh.write(line + "\n")
        frame = f"id: capture-live.jsonl:{len(line) + 1}\ndata: {line}\n\n"
        self.read_until(s, frame.encode())

    def test_capture_stream_ignores_the_audit_file(self):
        audit = self.events_file("events-live.jsonl")
        live = self.events_file("capture-live.jsonl")
        self.proxy_meta(events=str(audit), capture=str(live))
        s, _ = self.sse_open(cursor_param="capture-live.jsonl:0",
                             endpoint="/api/capture/stream")
        with open(audit, "a") as fh:
            fh.write(json.dumps(event(id="noise")) + "\n")
        line = json.dumps(capture_event(id="signal"))
        with open(live, "a") as fh:
            fh.write(line + "\n")
        data = self.read_until(s, line.encode())
        self.assertNotIn(b"noise", data)


# -- /api/search --------------------------------------------------------------------------

class UiSearchTest(UiServerTest):

    def fixture(self):
        self.events_file("events-01.jsonl",
                         event(id="a", host="pypi.org"),
                         event(id="b", host="evil.example", session="other"))
        self.events_file("capture-01.jsonl",
                         capture_event(id="c", model="claude-fable-5"))
        sid, adir = self.write_archive("olds")
        MOD._journal_into(adir, "exec_start", exec_id="cafe1234",
                          argv=["claude", "-p", "fix pypi build"])
        return sid

    def test_substring_is_case_folded_across_sources(self):
        self.fixture()
        _, got = self.get_json("/api/search?q=PYPI")
        self.assertEqual({r["source"] for r in got["results"]}, {"audit", "journal"})
        self.assertFalse(got["truncated"])
        _, got = self.get_json("/api/search?q=fable")
        self.assertEqual([r["source"] for r in got["results"]], ["capture"])

    def test_session_filter_reaches_journals_via_the_sid(self):
        self.fixture()
        _, got = self.get_json("/api/search?q=pypi&session=olds")
        self.assertEqual([r["source"] for r in got["results"]], ["journal"])
        _, got = self.get_json("/api/search?q=evil&session=other")
        self.assertEqual([r["record"]["id"] for r in got["results"]], ["b"])
        _, got = self.get_json("/api/search?q=evil&session=demo")
        self.assertEqual(got["results"], [])

    def test_short_queries_are_400(self):
        for q in ("", "ab"):
            resp, _ = self.request(f"/api/search?q={q}")
            self.assertEqual(resp.status, 400, repr(q))

    def test_result_cap_early_exits_and_marks_truncation(self):
        self.events_file("events-01.jsonl",
                         *(event(id=f"r{i}", host="pypi.org") for i in range(6)))
        _, got = self.get_json("/api/search?q=pypi&limit=3")
        self.assertEqual(len(got["results"]), 3)
        self.assertTrue(got["truncated"])

    def test_scanned_bytes_ceiling_stops_the_scan(self):
        self.events_file("events-01.jsonl", event(id="a", host="pypi.org"))
        self.events_file("events-02.jsonl", event(id="b", host="pypi.org"))
        with mock.patch.object(MOD, "UI_SEARCH_MAX_BYTES", 1):
            _, got = self.get_json("/api/search?q=pypi")
        self.assertEqual(len(got["results"]), 1, "one file read, then the ceiling")
        self.assertTrue(got["truncated"])

    def test_newest_file_wins_the_early_exit(self):
        older = self.events_file("events-01.jsonl", event(id="old", host="pypi.org"))
        newer = self.events_file("events-02.jsonl", event(id="new", host="pypi.org"))
        os.utime(older, (1, 1))
        _, got = self.get_json("/api/search?q=pypi&limit=1")
        self.assertEqual(got["results"][0]["record"]["id"], "new")


# -- the control plane ----------------------------------------------------------------

class UiControlTest(UiServerTest):

    def post_json(self, path, headers=None):
        resp, body = self.request(path, method="POST", headers=headers)
        return resp, json.loads(body)

    def test_freeze_swaps_the_rules_and_resume_restores_them(self):
        sdir = self.write_session("s1", rules="pypi.org/** GET\n")
        resp, got = self.post_json("/api/session/s1/freeze")
        self.assertEqual((resp.status, got), (200, {"ok": True}))
        self.assertEqual((sdir / "rules.txt").read_text(), "",
                         "an empty ruleset: deny-by-default does the rest")
        self.assertEqual((sdir / "rules.frozen").read_text(), "pypi.org/** GET\n")
        resp, got = self.post_json("/api/session/s1/freeze")
        self.assertEqual(resp.status, 409)
        self.assertIn("already frozen", got["error"])
        resp, got = self.post_json("/api/session/s1/resume")
        self.assertEqual((resp.status, got), (200, {"ok": True}))
        self.assertEqual((sdir / "rules.txt").read_text(), "pypi.org/** GET\n")
        self.assertFalse((sdir / "rules.frozen").exists())
        resp, got = self.post_json("/api/session/s1/resume")
        self.assertEqual(resp.status, 409)
        self.assertIn("not frozen", got["error"])
        events = [r["event"] for r in
                  MOD._read_journal(sdir / "journal.jsonl")]
        self.assertEqual(events, ["frozen", "resumed"])

    def test_down_drives_the_shared_teardown_path(self):
        sdir = self.write_session("s2")
        seen = {}

        def fake_down(meta):
            seen["meta"] = meta
            return False

        with mock.patch.object(MOD, "_down_session", fake_down):
            resp, got = self.post_json("/api/session/s2/down")
        self.assertEqual((resp.status, got), (200, {"ok": True}))
        self.assertEqual(seen["meta"]["name"], "s2")

    def test_down_failure_is_409_not_a_dead_thread(self):
        self.write_session("s3")

        def dies(meta):
            raise SystemExit(1)

        with mock.patch.object(MOD, "_down_session", dies):
            resp, got = self.post_json("/api/session/s3/down")
        self.assertEqual(resp.status, 409)
        self.assertIn("kept", got["error"])

    def test_kill_builds_the_group_signal_argv(self):
        sdir = self.write_session("k1")
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            return types.SimpleNamespace(returncode=0, stdout="SILKGATE_KILLED\n",
                                         stderr="")

        with mock.patch.object(MOD, "_msb", lambda: "msb"), \
                mock.patch.object(MOD.subprocess, "run", fake_run):
            resp, got = self.post_json("/api/session/k1/exec/cafe1234/kill")
        self.assertEqual((resp.status, got), (200, {"ok": True}))
        self.assertEqual(seen["argv"][:3], ["msb", "exec", "-q"])
        self.assertIn("sg-k1", seen["argv"])
        script = seen["argv"][seen["argv"].index("-c") + 1] \
            if "-c" in seen["argv"] else " ".join(seen["argv"])
        self.assertIn(f"{MOD.GUEST_EXECS}/$1.pid", script)
        self.assertIn('kill -TERM -- -"$pgid"', script)
        self.assertIn('kill -KILL -- -"$pgid"', script)
        self.assertEqual(seen["argv"][-1], "cafe1234",
                         "the exec id rides argv, never spliced into the script")
        events = MOD._read_journal(sdir / "journal.jsonl")
        self.assertEqual([(r["event"], r.get("exec_id")) for r in events],
                         [("killed", "cafe1234")])

    def test_kill_validates_the_exec_id_first(self):
        self.write_session("k2")
        for bad in ("xyz", "..", "CAFE1234", "cafe12345", "cafe123"):
            resp, _ = self.post_json(f"/api/session/k2/exec/{bad}/kill")
            self.assertEqual(resp.status, 400, bad)

    def test_kill_without_a_pidfile_is_409(self):
        self.write_session("k3")
        with mock.patch.object(MOD, "_kill_in_guest",
                               lambda meta, eid: ("SILKGATE_NO_PIDFILE", "")):
            resp, got = self.post_json("/api/session/k3/exec/cafe1234/kill")
        self.assertEqual(resp.status, 409)
        self.assertIn("already ended", got["error"])

    def test_control_refuses_archived_sessions(self):
        sid, _ = self.write_archive("olda")
        for action in ("freeze", "resume", "down"):
            resp, _ = self.post_json(f"/api/session/{sid}/{action}")
            self.assertEqual(resp.status, 409, action)
        resp, _ = self.post_json(f"/api/session/{sid}/exec/cafe1234/kill")
        self.assertEqual(resp.status, 409)

    def test_control_refuses_unknown_sessions(self):
        for action in ("freeze", "resume", "down", "diff"):
            resp, _ = self.post_json(f"/api/session/nosuch/{action}")
            self.assertEqual(resp.status, 404, action)

    def test_every_control_route_refuses_cross_origin(self):
        self.write_session("s9")
        evil = {"Origin": "https://evil.example"}
        for path in ("/api/session/s9/freeze", "/api/session/s9/resume",
                     "/api/session/s9/down", "/api/session/s9/diff",
                     "/api/session/s9/exec/cafe1234/kill"):
            resp, _ = self.post_json(path, headers=evil)
            self.assertEqual(resp.status, 403, path)


# -- the shipped assets ---------------------------------------------------------------

_BANNED_SINKS = re.compile(
    r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|srcdoc")
# Path-like specifiers only (./, ../, /): those are the references this server must
# route. A bare specifier cannot be fetched from here whatever the map says, and the
# unanchored form also matched prose like `"rename from", "…"` inside string literals.
_JS_REFS = re.compile(r"""(?:import|from)\s*\(?\s*["'](\.{0,2}/[^"']+)["']""")
_HTML_REFS = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)["']""")


class ShippedAssetInvariantsTest(unittest.TestCase):
    """Unlike every fixture-based class above (which repoints UI_DIR at a temp
    directory), this one reads the SHIPPED ui/ sources in the repository: the
    invariants are the contract of the real assets. A routed file that does not
    exist yet is skipped — another branch lands it — so the invariants hold for
    whatever actually ships."""

    def served(self):
        for key, (name, _) in MOD._UI_ROUTES.items():
            path = REPO / "ui" / name
            if path.is_file():
                yield key, path

    def test_no_markup_sinks_in_the_shipped_sources(self):
        checked = 0
        for path in (REPO / "ui").rglob("*"):
            if path.suffix not in (".js", ".html") or path.name.endswith(".test.js"):
                continue
            checked += 1
            hit = _BANNED_SINKS.search(path.read_text(encoding="utf-8"))
            self.assertIsNone(hit, f"{path.name} uses {hit and hit.group(0)!r} — "
                                   "render through textContent/DOM nodes instead")
        self.assertGreater(checked, 0, "no shipped sources found to check")

    def test_every_reference_in_served_files_resolves_to_a_route(self):
        for key, path in self.served():
            text = path.read_text(encoding="utf-8")
            refs = (_JS_REFS.findall(text) if path.suffix == ".js"
                    else _HTML_REFS.findall(text))
            for ref in refs:
                if "//" in ref or ref.startswith(("data:", "#")):
                    continue                     # not this server's to serve
                resolved = posixpath.normpath(
                    posixpath.join(posixpath.dirname(key), ref))
                self.assertIn(resolved, MOD._UI_ROUTES,
                              f"{path.name} references {ref!r} ({resolved}), "
                              "which the server does not route")


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
