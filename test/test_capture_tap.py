#!/usr/bin/env python3
"""Tap tests for LLM capture in mitmaddon/proxy_addon.py — in-process, no network.

    python3 test/test_capture_tap.py

Follows test/test_addon.py's pattern: real hooks driven against synthetic flows, with
assertions on every output at once — the forwarded chunks, the audit pair, and now the
capture file. The ruleset is the real claude profile, so these tests also pin that its
POST /v1/messages rule (and only that rule) opts into capture.

The property everything here defends: capture is observability layered on flows the
audit already covers, so no capture failure — decoder, sink, or setup — may change
what is forwarded, what is counted, or whether the audit pair is emitted.
"""
import json
import logging
import os
import pathlib
import sys
import tempfile
import unittest
import unittest.mock
from datetime import datetime

try:
    import mitmproxy  # noqa: F401
except ModuleNotFoundError:
    raise unittest.SkipTest("mitmproxy is not installed — the addon tap tests need it")

SENTINEL_VALUE = "SENTINEL-NOT-A-REAL-KEY"
REPO = pathlib.Path(__file__).resolve().parents[1]
PROFILE_RULES = REPO / "profiles" / "claude" / "rules.txt"

os.environ.setdefault("SILKGATE_EGRESS_RULES", str(PROFILE_RULES))
os.environ.setdefault("SILKGATE_EGRESS_SECRET_ANTHROPIC", f"x-api-key: {SENTINEL_VALUE}")
os.environ.pop("SILKGATE_EGRESS_SESSIONS_DIR", None)
os.environ.pop("SILKGATE_EGRESS_CONTROL_SOCK", None)

sys.path.insert(0, str(REPO / "mitmaddon"))
import proxy_addon                                             # noqa: E402
import rule_engine                                             # noqa: E402
from mitmproxy.flow import Error                               # noqa: E402
from mitmproxy.test import tflow, tutils                       # noqa: E402

LISTEN_PORT = 8090

# One short, complete SSE turn: enough to produce every record kind on the happy path.
MODEL = "claude-sonnet-4-5"
SSE_TURN = b"".join(
    f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()
    for name, payload in [
        ("message_start", {"type": "message_start", "message": {
            "id": "msg_01TAP", "type": "message", "role": "assistant", "model": MODEL,
            "content": [], "stop_reason": None,
            "usage": {"input_tokens": 25, "output_tokens": 1,
                      "cache_creation_input_tokens": 3, "cache_read_input_tokens": 7}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": "Hi there."}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta",
                           "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                           "usage": {"output_tokens": 42}}),
        ("message_stop", {"type": "message_stop"}),
    ])


class AuditCapture(logging.Handler):
    """Collect the addon's log lines verbatim, so a malformed one fails a test loudly."""

    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())

    def records(self):
        return [json.loads(line) for line in self.lines]


class TapCase(unittest.TestCase):
    """One flow through the real hooks, with the claude profile resolved for every
    port and the capture sink swapped for a readable temp file."""

    def setUp(self):
        self.audit = AuditCapture()
        self.logger = logging.getLogger("egress")
        self.logger.addHandler(self.audit)
        self.logger.setLevel(logging.INFO)
        self.addCleanup(self.logger.removeHandler, self.audit)

        ruleset = rule_engine.RuleSet.parse(PROFILE_RULES.read_text())

        class Stub:
            def resolve(self, port):
                return None, ruleset

        real_reg, proxy_addon.REGISTRY = proxy_addon.REGISTRY, Stub()
        self.addCleanup(setattr, proxy_addon, "REGISTRY", real_reg)

        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.capture_path = os.path.join(d.name, "capture.jsonl")
        self.swap_capture(proxy_addon._CaptureFile(self.capture_path))

    def swap_capture(self, sink):
        real, proxy_addon.CAPTURE = proxy_addon.CAPTURE, sink
        self.addCleanup(setattr, proxy_addon, "CAPTURE", real)
        # The production sink lives as long as the process; a test's must not outlive it.
        self.addCleanup(lambda: sink._fh and sink._fh.close())
        return sink

    # --- driving flows --------------------------------------------------------
    def run_request(self, *, host="api.anthropic.com", method="POST",
                    path="/v1/messages", body=b'{"model": "x"}', headers=()):
        fields = [(b"Host", host.encode()), (b"x-api-key", b"guest-dummy")]
        fields += list(headers)
        req = tutils.treq(host=host, port=443, method=method.encode(),
                          path=path.encode(), headers=tuple(fields), content=body)
        f = tflow.tflow(req=req)
        f.client_conn.sockname = ("127.0.0.1", LISTEN_PORT)
        f.client_conn.sni = None
        proxy_addon.request(f)
        self.assertIsNone(f.response, "expected the request to be allowed")
        return f

    def respond(self, f, chunks, content_type="text/event-stream", status=200,
                encoding=None):
        """Play mitmproxy's streaming: responseheaders installs the tap, every chunk
        passes through it (b"" marks end of message), then response() concludes."""
        f.response = tutils.tresp(status_code=status)
        f.response.headers["content-type"] = content_type
        if encoding is not None:
            f.response.headers["content-encoding"] = encoding
        proxy_addon.responseheaders(f)
        self.assertTrue(callable(f.response.stream),
                        "an allowed response must stream through the tap")
        for chunk in chunks:
            self.assertEqual(f.response.stream(chunk), chunk,
                             "chunks pass through the tap unchanged")
        f.response.stream(b"")
        proxy_addon.response(f)

    # --- reading the outputs ---------------------------------------------------
    def capture_records(self):
        with open(self.capture_path) as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def audit_response(self):
        recs = [r for r in self.audit.records() if r.get("decision") == "response"]
        self.assertEqual(len(recs), 1, "expected exactly one response record")
        return recs[0]


class SseEndToEnd(TapCase):

    def test_records_audit_and_chunks(self):
        f = self.run_request()
        # Torn chunk boundaries: the tap must be as chunking-proof as the decoder.
        self.respond(f, [SSE_TURN[:37], SSE_TURN[37:1201], SSE_TURN[1201:]])

        records = self.capture_records()
        self.assertEqual([r["kind"] for r in records],
                         ["turn_start", "content_block", "turn_end"])
        for rec in records:
            self.assertEqual(rec["id"], f.id, "the envelope joins the audit pair")
            self.assertIsNone(rec["session"])
            self.assertEqual(rec["host"], "api.anthropic.com")
            self.assertNotIn("exec", rec, "no marker was sent, so none is recorded")
            datetime.fromisoformat(rec["ts"])          # dated, or this raises
        turn_start, block, turn_end = records
        self.assertEqual(turn_start["model"], MODEL)
        self.assertEqual(turn_start["input_tokens"], 25)
        self.assertIsInstance(turn_start["ttfb_ms"], int)
        self.assertEqual(block["text"], "Hi there.")
        self.assertEqual(turn_end["stop_reason"], "end_turn")
        self.assertEqual(turn_end["output_tokens"], 42)
        self.assertIsInstance(turn_end["duration_ms"], int)

        resp = self.audit_response()
        self.assertEqual(resp["model"], MODEL)
        self.assertEqual(resp["tokens_in"], 25)
        self.assertEqual(resp["tokens_out"], 42)
        self.assertEqual(resp["stop_reason"], "end_turn")
        self.assertIsInstance(resp["ttfb_ms"], int)
        self.assertEqual(resp["response_bytes"], len(SSE_TURN))

    def test_aborted_stream_flushes_an_incomplete_turn(self):
        f = self.run_request()
        f.response = tutils.tresp(status_code=200)
        f.response.headers["content-type"] = "text/event-stream"
        proxy_addon.responseheaders(f)
        f.response.stream(SSE_TURN[:400])              # ...and the stream dies here
        f.error = Error("connection reset")
        proxy_addon.error(f)
        records = self.capture_records()
        self.assertEqual(records[-1]["kind"], "turn_end")
        self.assertTrue(records[-1]["incomplete"])
        resp = self.audit_response()
        self.assertEqual(resp["model"], MODEL, "what the decoder learned still lands")
        self.assertEqual(resp["response_bytes"], 400)

    def test_json_mode_via_content_type(self):
        body = json.dumps({"id": "msg_01J", "type": "message", "role": "assistant",
                           "model": MODEL, "content": [{"type": "text", "text": "hi"}],
                           "stop_reason": "end_turn",
                           "usage": {"input_tokens": 2, "output_tokens": 3}}).encode()
        f = self.run_request()
        self.respond(f, [body], content_type="application/json; charset=utf-8")
        self.assertEqual([r["kind"] for r in self.capture_records()],
                         ["turn_start", "content_block", "turn_end"])
        self.assertEqual(self.audit_response()["tokens_out"], 3)


class FailOpen(TapCase):
    """Every capture failure costs the transcript and nothing else."""

    def test_encoded_response_is_metadata_only(self):
        """Streamed chunks arrive still content-encoded; growing a decompressor in
        the proxy would hand the guest a zip-bomb lever, so gzip means no decoder."""
        f = self.run_request()
        self.respond(f, [b"\x1f\x8b-not-really-gzip", b"more"], encoding="gzip")
        records = self.capture_records()
        self.assertEqual([r["kind"] for r in records], ["capture_error"])
        self.assertIn("gzip", records[0]["reason"])
        resp = self.audit_response()
        self.assertEqual(resp["response_bytes"], len(b"\x1f\x8b-not-really-gzipmore"))
        self.assertNotIn("model", resp)
        self.assertIsInstance(resp["ttfb_ms"], int)

    def test_a_dying_decoder_leaves_traffic_and_counts_intact(self):
        f = self.run_request()
        f.response = tutils.tresp(status_code=200)
        f.response.headers["content-type"] = "text/event-stream"
        proxy_addon.responseheaders(f)
        self.assertIn("capture", f.metadata)
        f.metadata["capture"] = unittest.mock.Mock(
            feed=unittest.mock.Mock(side_effect=RuntimeError("decoder bug")))
        for chunk in (SSE_TURN[:100], SSE_TURN[100:]):
            self.assertEqual(f.response.stream(chunk), chunk,
                             "the dying decoder must not touch the wire")
        f.response.stream(b"")
        proxy_addon.response(f)
        self.assertNotIn("capture", f.metadata, "the dead decoder was popped")
        records = self.capture_records()
        self.assertEqual([r["kind"] for r in records], ["capture_error"],
                         "one record says why, and only one")
        self.assertIn("RuntimeError", records[0]["reason"])
        resp = self.audit_response()
        self.assertEqual(resp["response_bytes"], len(SSE_TURN),
                         "counting sits outside the capture try")
        self.assertEqual(resp["status"], 200)

    def test_a_broken_sink_disables_itself_once(self):
        """The deliberate contrast with the events mirror: EVENTS failing fails the
        flow closed, CAPTURE failing only stops observability."""
        sink = self.swap_capture(proxy_addon._CaptureFile(self.capture_path))
        sink._fh = unittest.mock.MagicMock()
        sink._fh.write.side_effect = OSError("disk full")
        f = self.run_request()
        self.respond(f, [SSE_TURN])                    # traffic must be unaffected
        self.assertIsNone(sink._fh, "first failure disables the sink for good")
        control = [r for r in self.audit.records() if r.get("decision") == "control"]
        self.assertEqual(len(control), 1, "one line says so — not one per record")
        self.assertIn("capture sink disabled", control[0]["reason"])
        self.assertEqual(self.audit_response()["status"], 200)

    def test_a_non_2xx_response_attaches_no_decoder(self):
        f = self.run_request()
        f.response = tutils.tresp(status_code=429)
        f.response.headers["content-type"] = "application/json"
        proxy_addon.responseheaders(f)
        self.assertNotIn("capture", f.metadata,
                         "only a 200 carries the grammar the decoders parse")
        chunk = b'{"type": "error"}'
        self.assertEqual(f.response.stream(chunk), chunk,
                         "chunks pass through the tap unchanged")
        f.response.stream(b"")
        proxy_addon.response(f)
        records = self.capture_records()
        self.assertEqual([r["kind"] for r in records], ["capture_error"],
                         "the rate-limited turn leaves one record, not silence")
        self.assertIn("429", records[0]["reason"])
        self.assertEqual(self.audit_response()["status"], 429)

    def test_an_unexpected_content_type_is_one_capture_error(self):
        f = self.run_request()
        self.respond(f, [b"<html>"], content_type="text/html")
        records = self.capture_records()
        self.assertEqual([r["kind"] for r in records], ["capture_error"])
        self.assertIn("text/html", records[0]["reason"])


class NotCaptured(TapCase):
    """Flows without capture= must look exactly like they did before this feature."""

    def plain_flow(self):
        return self.run_request(method="GET", path="/v1/models", body=b"")

    def test_profile_opts_in_the_messages_post_only(self):
        ruleset = rule_engine.RuleSet.parse(PROFILE_RULES.read_text())
        captured = [r.raw.split()[0] for r in ruleset.rules if r.capture]
        self.assertEqual(captured, ["api.anthropic.com/v1/messages"])
        self.assertEqual([r.capture for r in ruleset.rules if r.capture], ["anthropic"])
        post_rules = [r for r in ruleset.rules if "POST" in r.methods and r.capture]
        self.assertEqual(len(post_rules), 1, "only the content-carrying POST captures")

    def test_records_stay_as_they_were(self):
        """The regression the brief pins: a non-captured rule produces no capture
        records and no new audit fields — ttfb_ms, now on every allowed flow, is
        the single deliberate exception."""
        f = self.plain_flow()
        self.respond(f, [b'{"data": []}'], content_type="application/json")
        self.assertEqual(self.capture_records(), [], "no capture rule, no records")
        self.assertNotIn("capture", f.metadata)
        resp = self.audit_response()
        self.assertEqual(set(resp), {"ts", "decision", "id", "method", "host", "port",
                                     "path", "reason", "session", "listen_port",
                                     "status", "request_bytes", "response_bytes",
                                     "duration_ms", "ttfb_ms"})

    def test_ttfb_is_present_on_a_plain_flow(self):
        f = self.plain_flow()
        self.respond(f, [b"x" * 10], content_type="application/json")
        resp = self.audit_response()
        self.assertIsInstance(resp["ttfb_ms"], int)


class ExecMarker(TapCase):
    """X-Silkgate-Exec joins records to the run that caused them — inside the audit
    and capture files only. The id is internal and must never reach Anthropic."""

    def test_header_is_stripped_and_stamped(self):
        f = self.run_request(headers=[(b"X-Silkgate-Exec", b"exec-42")])
        self.assertNotIn("x-silkgate-exec", f.request.headers,
                         "the id must not leave for upstream")
        allow = next(r for r in self.audit.records() if r["decision"] == "allow")
        self.assertEqual(allow["exec"], "exec-42")
        self.respond(f, [SSE_TURN])
        self.assertEqual(self.audit_response()["exec"], "exec-42")
        for rec in self.capture_records():
            self.assertEqual(rec["exec"], "exec-42",
                             "every capture record carries the join key")

    def test_h_star_does_not_save_the_header(self):
        """The claude profile grants h:*, which skips header hygiene — exactly why
        the strip is unconditional rather than hygiene's job."""
        ruleset = rule_engine.RuleSet.parse(PROFILE_RULES.read_text())
        rule = ruleset.match("api.anthropic.com", "/v1/messages", "POST")
        self.assertTrue(rule.allow_all_headers, "the premise: hygiene is off")
        f = self.run_request(headers=[(b"X-Silkgate-Exec", b"exec-7")])
        self.assertNotIn("x-silkgate-exec", f.request.headers)

    def test_a_missing_marker_is_simply_absent(self):
        f = self.run_request()
        allow = next(r for r in self.audit.records() if r["decision"] == "allow")
        self.assertNotIn("exec", allow)
        self.respond(f, [SSE_TURN])
        self.assertNotIn("exec", self.audit_response())


if __name__ == "__main__":
    unittest.main(verbosity=2)
