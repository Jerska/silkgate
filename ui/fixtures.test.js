// fixtures.test.js — realistic capture record sequences matching the wave-1
// contract, shared by the capture tests (node --test runs this file too; the
// tests at the bottom pin the fixtures to the contract's shape). Never served,
// never imported by served files.
//
// Contract: every record carries ts, kind, id, session, host, and optionally
// exec. Kinds and their fields:
//   turn_start     model, message_id, input_tokens, cache_creation_input_tokens,
//                  cache_read_input_tokens, ttfb_ms
//   content_block  index, type, text | tool_name+tool_id+tool_input, chars,
//                  truncated?
//   turn_end       stop_reason, output_tokens, duration_ms, incomplete?, error?
//   capture_error  reason
//   secret_sighting pattern, index
import test from "node:test";
import assert from "node:assert/strict";

let seq = 0;

function ts(offsetSec = 0) {
  const base = Date.parse("2026-08-12T12:00:00.000+00:00");
  return new Date(base + offsetSec * 1000).toISOString().replace("Z", "+00:00");
}

// One complete turn: start, a text block, a tool block, end. Overrides land on
// every record (session, exec, id, at) or on a specific kind via the second arg.
export function turn({ session = "demo", exec = "e1", id = null, at = 0,
                       model = "claude-sonnet-4-5-20250929" } = {}, over = {}) {
  const flow = id ?? `flow-${++seq}`;
  const common = { id: flow, session, host: "api.anthropic.com" };
  if (exec !== null) common.exec = exec;
  return [
    { ts: ts(at), kind: "turn_start", ...common, model,
      message_id: `msg_01${flow}`, input_tokens: 4231,
      cache_creation_input_tokens: 512, cache_read_input_tokens: 18211,
      ttfb_ms: 640, ...(over.turn_start || {}) },
    { ts: ts(at + 1), kind: "content_block", ...common, index: 0, type: "text",
      text: "Reading the failing test first, then the module it pins.",
      chars: 56, ...(over.text || {}) },
    { ts: ts(at + 2), kind: "content_block", ...common, index: 1,
      type: "tool_use", tool_name: "bash", tool_id: `toolu_01${flow}`,
      tool_input: { command: "node --test ui/", timeout: 120000 },
      chars: 47, ...(over.tool || {}) },
    { ts: ts(at + 3), kind: "turn_end", ...common, stop_reason: "tool_use",
      output_tokens: 187, duration_ms: 5210, ...(over.turn_end || {}) },
  ];
}

export function captureError({ session = "demo", id = "flow-err", at = 0 } = {}) {
  return { ts: ts(at), kind: "capture_error", id, session,
           host: "api.anthropic.com", reason: "response was not SSE" };
}

export function secretSighting({ session = "demo", exec = "e1", id = "flow-sec",
                                 at = 0, index = 1 } = {}) {
  return { ts: ts(at), kind: "secret_sighting", id, session,
           host: "api.anthropic.com", exec, pattern: "anthropic api key", index };
}

// A believable session: two execs, one unattributed record, an error and a
// sighting — what a busy coding agent's capture trail looks like.
export function demoSequence() {
  return [
    ...turn({ session: "dash", exec: "e1", id: "f1", at: 0 }),
    ...turn({ session: "dash", exec: "e1", id: "f2", at: 10 }),
    ...turn({ session: "dash", exec: "e2", id: "f3", at: 20,
              model: "claude-haiku-4-5" }),
    ...turn({ session: "dash", exec: null, id: "f4", at: 30 }),
    captureError({ session: "dash", id: "f5", at: 40 }),
    secretSighting({ session: "dash", exec: "e1", id: "f2", at: 41 }),
  ];
}

// --- the fixtures hold the contract's shape -----------------------------------

test("every fixture record carries ts, kind, id, session, host", () => {
  for (const rec of demoSequence()) {
    for (const field of ["ts", "kind", "id", "session", "host"]) {
      assert.ok(rec[field] != null, `${rec.kind}: ${field}`);
    }
  }
});

test("fixture kinds and per-kind fields match the contract", () => {
  const [start, text, tool, end] = turn();
  assert.equal(start.kind, "turn_start");
  for (const f of ["model", "message_id", "input_tokens",
                   "cache_creation_input_tokens", "cache_read_input_tokens",
                   "ttfb_ms"]) {
    assert.ok(f in start, f);
  }
  assert.equal(text.kind, "content_block");
  assert.equal(text.type, "text");
  assert.equal(typeof text.text, "string");
  assert.equal(tool.type, "tool_use");
  for (const f of ["tool_name", "tool_id", "tool_input"]) {
    assert.ok(f in tool, f);
  }
  assert.equal(end.kind, "turn_end");
  for (const f of ["stop_reason", "output_tokens", "duration_ms"]) {
    assert.ok(f in end, f);
  }
});

test("a turn built without an exec omits the field — never a guess", () => {
  for (const rec of turn({ exec: null })) {
    assert.equal("exec" in rec, false);
  }
});
