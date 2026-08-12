#!/usr/bin/env python3
"""Pure-decoder tests for proxy_addon._AnthropicCapture — no flows, no hooks, no network.

    python3 test/test_capture_decoder.py

The decoder is the parsing half of LLM capture: bytes in through feed(), records out,
with flush() as the abort path. These tests pin the whole grammar directly, byte-exactly,
because the tap that wraps the decoder treats any exception as "capture died" — so the
line between what the decoder tolerates (unknown types, torn chunks, oversized blocks)
and what kills it (over-cap lines, malformed JSON) is itself the contract under test.

Importing proxy_addon needs mitmproxy installed, so the module skips exactly like
test_addon.py does; the decoder itself never touches mitmproxy.
"""
import json
import os
import pathlib
import sys
import unittest

try:
    import mitmproxy  # noqa: F401
except ModuleNotFoundError:
    raise unittest.SkipTest("mitmproxy is not installed — importing the addon needs it")

REPO = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("SILKGATE_EGRESS_RULES",
                      str(REPO / "profiles" / "claude" / "rules.txt"))
os.environ.pop("SILKGATE_EGRESS_SESSIONS_DIR", None)

sys.path.insert(0, str(REPO / "mitmaddon"))
import proxy_addon                                             # noqa: E402
from proxy_addon import _AnthropicCapture                      # noqa: E402


# --- a realistic Anthropic SSE stream, built from the pieces the API sends -------
MODEL = "claude-sonnet-4-5"
THINKING = "let me think about the wörld first…"
TEXT = "Hello wörld 🎉 — done."
TOOL_JSON = '{"cmd":"ls -la","timeout":5}'       # compact, like real input_json_delta


def event(name, payload):
    return f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()


def message_start():
    return event("message_start", {"type": "message_start", "message": {
        "id": "msg_01TEST", "type": "message", "role": "assistant", "model": MODEL,
        "content": [], "stop_reason": None,
        "usage": {"input_tokens": 25, "output_tokens": 1,
                  "cache_creation_input_tokens": 3, "cache_read_input_tokens": 7}}})


def block_start(index, btype, **fields):
    return event("content_block_start", {"type": "content_block_start", "index": index,
                                         "content_block": {"type": btype, **fields}})


def delta(index, dtype, **fields):
    return event("content_block_delta", {"type": "content_block_delta", "index": index,
                                         "delta": {"type": dtype, **fields}})


def block_stop(index):
    return event("content_block_stop", {"type": "content_block_stop", "index": index})


def message_delta(stop_reason, output_tokens):
    return event("message_delta", {"type": "message_delta",
                                   "delta": {"stop_reason": stop_reason,
                                             "stop_sequence": None},
                                   "usage": {"output_tokens": output_tokens}})


FIXTURE = b"".join([
    message_start(),
    block_start(0, "thinking", thinking=""),
    delta(0, "thinking_delta", thinking=THINKING[:11]),
    delta(0, "thinking_delta", thinking=THINKING[11:]),
    delta(0, "signature_delta", signature="EqQBCgIYAhIM"),     # ignored delta type
    block_stop(0),
    block_start(1, "text", text=""),
    delta(1, "text_delta", text=TEXT[:7]),
    event("ping", {"type": "ping"}),
    delta(1, "text_delta", text=TEXT[7:]),
    event("banana_split", {"type": "banana_split", "flavor": 3}),   # unknown event
    block_stop(1),
    block_start(2, "tool_use", id="toolu_01A", name="bash", input={}),
    delta(2, "input_json_delta", partial_json=TOOL_JSON[:9]),
    delta(2, "input_json_delta", partial_json=TOOL_JSON[9:]),
    block_stop(2),
    message_delta("end_turn", 42),
    event("message_stop", {"type": "message_stop"}),
])

# What FIXTURE must decode to, byte-exactly. Thinking is length only; the tool input
# parses back to the object the deltas spelled; chars are true pre-truncation lengths.
EXPECTED = [
    {"kind": "turn_start", "model": MODEL, "message_id": "msg_01TEST",
     "input_tokens": 25, "cache_creation_input_tokens": 3, "cache_read_input_tokens": 7},
    {"kind": "content_block", "index": 0, "type": "thinking", "chars": len(THINKING)},
    {"kind": "content_block", "index": 1, "type": "text", "chars": len(TEXT),
     "text": TEXT},
    {"kind": "content_block", "index": 2, "type": "tool_use", "chars": len(TOOL_JSON),
     "tool_name": "bash", "tool_id": "toolu_01A",
     "tool_input": {"cmd": "ls -la", "timeout": 5}},
    {"kind": "turn_end", "stop_reason": "end_turn", "output_tokens": 42},
]

# The same content as a stream=false body. The record sequence must come out
# identical — both modes share the block accumulators, and this pins that.
JSON_BODY = json.dumps({
    "id": "msg_01TEST", "type": "message", "role": "assistant", "model": MODEL,
    "content": [
        {"type": "thinking", "thinking": THINKING, "signature": "EqQBCgIYAhIM"},
        {"type": "text", "text": TEXT},
        {"type": "tool_use", "id": "toolu_01A", "name": "bash",
         "input": {"cmd": "ls -la", "timeout": 5}},
    ],
    "stop_reason": "end_turn", "stop_sequence": None,
    "usage": {"input_tokens": 25, "output_tokens": 42,
              "cache_creation_input_tokens": 3, "cache_read_input_tokens": 7},
}).encode()


def decode(data, mode="sse", sizes=(len(FIXTURE) or 1,)):
    """Run bytes through a fresh decoder in `sizes`-byte slices, then end the message."""
    d = _AnthropicCapture(mode)
    out = []
    step = sizes[0]
    for i in range(0, len(data), step):
        out.extend(d.feed(data[i:i + step]))
    out.extend(d.feed(b""))
    return out, d


class Grammar(unittest.TestCase):

    def test_realistic_stream_decodes_exactly(self):
        records, d = decode(FIXTURE)
        self.assertEqual(records, EXPECTED)
        self.assertEqual(d.summary(), {"model": MODEL, "tokens_in": 25,
                                       "tokens_out": 42, "stop_reason": "end_turn"})

    def test_chunking_cannot_change_the_emissions(self):
        """1- and 7-byte re-feeds tear every line, every UTF-8 sequence and every
        event boundary; the records must not notice."""
        for size in (1, 7):
            with self.subTest(size=size):
                records, _ = decode(FIXTURE, sizes=(size,))
                self.assertEqual(records, EXPECTED)

    def test_crlf_line_endings_decode_the_same(self):
        records, _ = decode(FIXTURE.replace(b"\n", b"\r\n"))
        self.assertEqual(records, EXPECTED)

    def test_data_accumulates_across_lines(self):
        """The SSE grammar joins consecutive data: lines with a newline before parsing."""
        d = _AnthropicCapture("sse")
        d.feed(b'event: message_delta\n'
               b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},\n'
               b'data: "usage":{"output_tokens":5}}\n\n')
        self.assertEqual(d.summary(), {"tokens_out": 5, "stop_reason": "end_turn"})

    def test_unknown_block_type_is_length_only(self):
        """A block type this decoder does not know has unknown sensitivity, so it gets
        thinking's treatment: the length is recorded, the content never is."""
        d = _AnthropicCapture("sse")
        records = []
        for chunk in (block_start(0, "future_widget"), block_stop(0)):
            records.extend(d.feed(chunk))
        self.assertEqual(records, [{"kind": "content_block", "index": 0,
                                    "type": "future_widget", "chars": 0}])

    def test_end_of_message_mid_turn_is_incomplete(self):
        d = _AnthropicCapture("sse")
        records = []
        for chunk in (message_start(), block_start(0, "text", text=""),
                      delta(0, "text_delta", text="partial answ")):
            records.extend(d.feed(chunk))
        records.extend(d.feed(b""))
        self.assertEqual(records, [
            EXPECTED[0],
            {"kind": "content_block", "index": 0, "type": "text",
             "chars": 12, "text": "partial answ"},
            {"kind": "turn_end", "output_tokens": 1, "incomplete": True},
        ])
        self.assertEqual(d.feed(b""), [], "the turn already ended; nothing more to say")
        self.assertEqual(d.flush(), [])

    def test_flush_is_the_same_abort_path(self):
        d = _AnthropicCapture("sse")
        d.feed(message_start() + block_start(0, "text", text="")
               + delta(0, "text_delta", text="cut off"))
        flushed = d.flush()
        self.assertEqual([r["kind"] for r in flushed], ["content_block", "turn_end"])
        self.assertTrue(flushed[-1]["incomplete"])
        self.assertEqual(d.flush(), [], "flushing twice must not double-emit")

    def test_upstream_error_event_ends_the_turn(self):
        """The error event is the upstream ending the turn itself: open blocks hold
        real content, so they are closed and kept rather than lost with the stream."""
        d = _AnthropicCapture("sse")
        records = []
        for chunk in (message_start(), block_start(0, "text", text=""),
                      delta(0, "text_delta", text="half an ans"),
                      event("error", {"type": "error",
                                      "error": {"type": "overloaded_error",
                                                "message": "Overloaded"}})):
            records.extend(d.feed(chunk))
        self.assertEqual(records[-1], {"kind": "turn_end", "stop_reason": "error",
                                       "output_tokens": 1,
                                       "error": {"type": "overloaded_error",
                                                 "message": "Overloaded"}})
        self.assertEqual(records[-2]["text"], "half an ans")
        self.assertEqual(d.summary()["stop_reason"], "error")
        self.assertEqual(d.flush(), [], "the error already ended the turn")

    def test_json_mode_emits_the_identical_sequence(self):
        for size in (len(JSON_BODY), 7):
            with self.subTest(size=size):
                records, d = decode(JSON_BODY, mode="json", sizes=(size,))
                self.assertEqual(records, EXPECTED)
                self.assertEqual(d.summary(), {"model": MODEL, "tokens_in": 25,
                                               "tokens_out": 42,
                                               "stop_reason": "end_turn"})

    def test_json_mode_abort_is_incomplete_not_a_parse(self):
        """flush() means the body never finished arriving; parsing half a JSON
        document would raise, so the abort path must not try."""
        d = _AnthropicCapture("json")
        d.feed(JSON_BODY[:40])
        self.assertEqual(d.flush(), [{"kind": "turn_end", "incomplete": True}])

    def test_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            _AnthropicCapture("xml")


class Surprises(unittest.TestCase):
    """What must raise out of feed(): the tap contains it by killing the decoder,
    so anything here that stopped raising would silently mis-record instead."""

    def test_malformed_event_json_raises(self):
        d = _AnthropicCapture("sse")
        with self.assertRaises(ValueError):
            d.feed(b"event: message_start\ndata: {broken\n\n")

    def test_delta_for_an_unopened_block_raises(self):
        d = _AnthropicCapture("sse")
        d.feed(message_start())
        with self.assertRaises(KeyError):
            d.feed(delta(5, "text_delta", text="x"))

    def test_malformed_json_body_raises_at_end(self):
        d = _AnthropicCapture("json")
        d.feed(b'{"model": "claude-')
        with self.assertRaises(ValueError):
            d.feed(b"")


class Caps(unittest.TestCase):
    """Every bound, exercised at its failure mode: line and total caps kill the
    decoder (fail open, the tap's job to contain), the block cap only degrades."""

    def test_partial_line_over_the_cap_dies(self):
        d = _AnthropicCapture("sse")
        with self.assertRaises(ValueError):
            d.feed(b"data: " + b"x" * proxy_addon._CAPTURE_LINE_MAX)

    def test_complete_line_over_the_cap_dies(self):
        d = _AnthropicCapture("sse")
        with self.assertRaises(ValueError):
            d.feed(b"x" * (proxy_addon._CAPTURE_LINE_MAX + 1) + b"\n")

    def test_block_over_the_cap_truncates_and_keeps_counting(self):
        cap = proxy_addon._CAPTURE_BLOCK_MAX
        piece = "x" * 50_000
        d = _AnthropicCapture("sse")
        records = []
        records.extend(d.feed(message_start() + block_start(0, "text", text="")))
        for _ in range(6):                       # 300_000 chars, over the 256 KiB cap
            records.extend(d.feed(delta(0, "text_delta", text=piece)))
        records.extend(d.feed(block_stop(0)))
        block = records[-1]
        self.assertEqual(block["chars"], 300_000, "chars is the true length")
        self.assertTrue(block["truncated"])
        self.assertEqual(len(block["text"]), cap, "storage stops exactly at the cap")

    def test_stream_over_the_total_cap_dies(self):
        d = _AnthropicCapture("sse")
        filler = b": keepalive\n" * 100_000      # comments are ignored but still fed
        with self.assertRaises(ValueError):
            for _ in range(3):
                d.feed(filler)

    def test_json_body_over_the_cap_dies(self):
        d = _AnthropicCapture("json")
        with self.assertRaises(ValueError):
            d.feed(b"x" * (proxy_addon._CAPTURE_JSON_MAX + 1))


class Sightings(unittest.TestCase):
    """Secret sighting names the pattern and redacts the stored copy — never the wire,
    and never the matched value."""

    def text_block(self, text):
        d = _AnthropicCapture("sse")
        records = []
        for chunk in (message_start(), block_start(0, "text", text=""),
                      delta(0, "text_delta", text=text), block_stop(0)):
            records.extend(d.feed(chunk))
        return records[1:]                       # drop turn_start

    def test_prefixed_tokens_are_sighted(self):
        cases = [
            ("anthropic-api-key", "sk-ant-api03-" + "a" * 24),
            ("github-pat", "ghp_" + "a" * 36),
            ("aws-access-key-id", "AKIA" + "B" * 16),
            ("slack-bot-token", "xoxb-1234567890-1234567890123-abcdef"),
            ("private-key-pem", "-----BEGIN OPENSSH PRIVATE KEY-----"),
            ("jwt", "eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 10),
        ]
        for name, token in cases:
            with self.subTest(pattern=name):
                records = self.text_block(f"the value is {token} — careful")
                self.assertEqual(records[0], {"kind": "secret_sighting",
                                              "pattern": name, "index": 0})
                block = records[1]
                self.assertNotIn(token, block["text"], "the value must never be stored")
                self.assertIn(f"[redacted:{name}]", block["text"])
                self.assertEqual(block["chars"], len(f"the value is {token} — careful"),
                                 "chars is the pre-redaction length")

    def test_shas_and_hashes_are_not_secrets(self):
        """The patterns are prefixed shapes only — a transcript full of digests must
        stay quiet, or the sighting channel gets filtered instead of read."""
        records = self.text_block("commit 3f786850e387550fdab836ed7e6dc881de23001b "
                                  "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b"
                                  "822cd15d6c15b0f00a08")
        self.assertEqual([r["kind"] for r in records], ["content_block"])

    def test_the_guest_dummy_key_is_allowlisted(self):
        """profiles/claude/env plants sk-ant-DUMMY-replaced-by-egress-proxy in every
        guest, and agents echo their env — the dummy must not light up the channel."""
        text = "ANTHROPIC_API_KEY=sk-ant-DUMMY-replaced-by-egress-proxy"
        records = self.text_block(text)
        self.assertEqual([r["kind"] for r in records], ["content_block"])
        self.assertEqual(records[0]["text"], text, "the dummy is stored as-is")

    def test_a_real_key_beside_the_dummy_is_still_sighted(self):
        """The allowlist is exact matched text, never a prefix."""
        records = self.text_block("dummy sk-ant-DUMMY-replaced-by-egress-proxy real "
                                  "sk-ant-api03-" + "z" * 24)
        self.assertEqual(records[0]["kind"], "secret_sighting")
        self.assertIn("sk-ant-DUMMY-replaced-by-egress-proxy", records[1]["text"])
        self.assertNotIn("z" * 24, records[1]["text"])

    def test_tool_input_is_scanned_and_redacted(self):
        secret = "AKIA" + "C" * 16
        d = _AnthropicCapture("sse")
        records = []
        for chunk in (message_start(),
                      block_start(0, "tool_use", id="t1", name="bash", input={}),
                      delta(0, "input_json_delta",
                            partial_json=json.dumps({"cmd": f"export K={secret}"})),
                      block_stop(0)):
            records.extend(d.feed(chunk))
        self.assertEqual(records[1], {"kind": "secret_sighting",
                                      "pattern": "aws-access-key-id", "index": 0})
        self.assertEqual(records[2]["tool_input"],
                         {"cmd": "export K=[redacted:aws-access-key-id]"},
                         "redaction lands inside the parsed input")

    def test_thinking_is_never_scanned_because_never_stored(self):
        d = _AnthropicCapture("sse")
        records = []
        for chunk in (message_start(), block_start(0, "thinking", thinking=""),
                      delta(0, "thinking_delta", thinking="ghp_" + "a" * 36),
                      block_stop(0)):
            records.extend(d.feed(chunk))
        self.assertEqual([r["kind"] for r in records[1:]], ["content_block"])
        self.assertNotIn("text", records[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
