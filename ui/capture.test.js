// capture.test.js — the capture fold contract: idempotence by replacement,
// (session, exec) bucketing, and the two evictions (turns fold their tokens
// once; text sheds without moving a token meter). Never served, never imported
// by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { newCapture, foldCapture, sessionTotals } from "./capture.js";
import { turn, captureError, secretSighting, demoSequence } from "./fixtures.test.js";

function foldAll(cap, recs) {
  for (const rec of recs) foldCapture(cap, rec);
}

// Comparable snapshot of one session's state — totals plus block identities.
function snapshot(cap, session) {
  const S = cap.sessions.get(session);
  const t = sessionTotals(S);
  const blocks = [];
  for (const [exec, bucket] of S.execs) {
    for (const [id, tn] of bucket.turns) {
      for (const [idx, b] of tn.blocks) {
        blocks.push([exec, id, idx, b.type, b.text, b.tool_name]);
      }
    }
  }
  return { ...t, byModel: [...t.byModel.entries()], blocks };
}

test("replaying a whole sequence is a no-op — folds land on themselves", () => {
  const a = newCapture();
  const b = newCapture();
  const seq = demoSequence();
  foldAll(a, seq);
  foldAll(b, seq);
  foldAll(b, seq);                       // history/stream overlap, resets, resends
  assert.deepEqual(snapshot(b, "dash"), snapshot(a, "dash"));
});

test("a replayed block replaces itself, never duplicates", () => {
  const cap = newCapture();
  const [start, text] = turn({ id: "f1" });
  foldCapture(cap, start);
  foldCapture(cap, text);
  foldCapture(cap, { ...text, text: "amended by the resend" });
  const t = cap.sessions.get("demo").execs.get("e1").turns.get("f1");
  assert.equal(t.blocks.size, 1);
  assert.equal(t.blocks.get(0).text, "amended by the resend", "last write wins");
});

test("turn_end closes by replacement — replays never accumulate output", () => {
  const cap = newCapture();
  const recs = turn({ id: "f1" });
  foldAll(cap, recs);
  foldCapture(cap, recs[3]);             // turn_end again
  const S = cap.sessions.get("demo");
  assert.equal(sessionTotals(S).output, 187);
  assert.equal(sessionTotals(S).openTurns, 0);
});

test("sub-state is keyed by (session, exec), missing exec is its own bucket", () => {
  const cap = newCapture();
  foldAll(cap, demoSequence());
  const S = cap.sessions.get("dash");
  assert.deepEqual([...S.execs.keys()], ["e1", "e2", null]);
  assert.equal(S.execs.get(null).turns.size, 1, "unattributed, never guessed");
});

test("eviction folds a closed turn's tokens exactly once", () => {
  const cap = newCapture({ turnCap: 2 });
  foldAll(cap, turn({ id: "f1", at: 0 }));
  foldAll(cap, turn({ id: "f2", at: 10 }));
  const before = sessionTotals(cap.sessions.get("demo"));
  foldAll(cap, turn({ id: "f3", at: 20 }));   // f1 falls off the turn window
  const after = sessionTotals(cap.sessions.get("demo"));
  const bucket = cap.sessions.get("demo").execs.get("e1");
  assert.equal(bucket.turns.size, 2, "the cap holds");
  assert.equal(bucket.turns.has("f1"), false);
  assert.equal(after.input, before.input + 4231, "f1's tokens survive eviction");
  assert.equal(after.output, before.output + 187);
  assert.equal(after.turns, 3, "an evicted turn still counts");
});

test("turn_end after eviction is a no-op", () => {
  const cap = newCapture({ turnCap: 1 });
  const first = turn({ id: "f1", at: 0 });
  foldCapture(cap, first[0]);                 // f1 open, never ended
  foldAll(cap, turn({ id: "f2", at: 10 }));   // evicts open f1
  const before = sessionTotals(cap.sessions.get("demo"));
  assert.equal(foldCapture(cap, first[3]), null, "the fold reports the no-op");
  const after = sessionTotals(cap.sessions.get("demo"));
  assert.deepEqual({ ...after, byModel: null }, { ...before, byModel: null },
                   "an evicted turn cannot resurrect or double-count");
});

test("block and turn_start replays for an evicted turn are no-ops too", () => {
  const cap = newCapture({ turnCap: 1 });
  const first = turn({ id: "f1", at: 0 });
  foldAll(cap, first);
  foldAll(cap, turn({ id: "f2", at: 10 }));   // evicts closed f1
  assert.equal(foldCapture(cap, first[0]), null);
  assert.equal(foldCapture(cap, first[1]), null);
  assert.equal(cap.sessions.get("demo").execs.get("e1").turns.has("f1"), false);
});

test("token meters do not drift when text falls off", () => {
  const cap = newCapture({ textCap: 100 });
  const big = "x".repeat(90);
  foldAll(cap, turn({ id: "f1", at: 0 }, { text: { text: big, chars: 90 } }));
  const before = sessionTotals(cap.sessions.get("demo"));
  // The second turn's text pushes the bucket over textCap: f1's payloads shed.
  foldAll(cap, turn({ id: "f2", at: 10 }, { text: { text: big, chars: 90 } }));
  const after = sessionTotals(cap.sessions.get("demo"));
  const b1 = cap.sessions.get("demo").execs.get("e1").turns.get("f1").blocks;
  assert.equal(b1.get(0).text, null, "the oldest text payload was shed");
  assert.equal(b1.get(0).dropped, true);
  assert.equal(after.input, before.input * 2, "input tokens: untouched");
  assert.equal(after.output, before.output * 2, "output tokens: untouched");
  assert.equal(after.cacheRead, before.cacheRead * 2);
  assert.equal(after.cacheWrite, before.cacheWrite * 2);
});

test("sessionTotals aggregates across execs, priced per model", () => {
  const cap = newCapture();
  foldAll(cap, demoSequence());
  const t = sessionTotals(cap.sessions.get("dash"));
  assert.equal(t.execs, 3);
  assert.equal(t.turns, 4);
  assert.equal(t.openTurns, 0);
  assert.equal(t.input, 4231 * 4);
  assert.equal(t.output, 187 * 4);
  assert.deepEqual([...t.byModel.keys()],
                   ["claude-sonnet-4-5-20250929", "claude-haiku-4-5"]);
  assert.equal(t.byModel.get("claude-haiku-4-5").input, 4231);
  assert.equal(t.errors, 1);
  assert.equal(t.sightings, 1);
  assert.equal(t.lastContext.tokens, 4231 + 18211 + 512 + 187,
               "the newest turn's context footprint");
});

test("an open turn shows in openTurns and pins lastContext", () => {
  const cap = newCapture();
  const [start, text] = turn({ id: "f1" });
  foldCapture(cap, start);
  foldCapture(cap, text);
  const t = sessionTotals(cap.sessions.get("demo"));
  assert.equal(t.openTurns, 1);
  assert.equal(t.lastContext.model, "claude-sonnet-4-5-20250929");
  assert.equal(t.lastContext.tokens, 4231 + 18211 + 512, "no output yet");
});

test("errors and sightings replay onto themselves", () => {
  const cap = newCapture();
  const err = captureError({ session: "demo" });
  const sight = secretSighting({ session: "demo" });
  for (const rec of [err, err, sight, sight]) foldCapture(cap, rec);
  const t = sessionTotals(cap.sessions.get("demo"));
  assert.equal(t.errors, 1);
  assert.equal(t.sightings, 1);
});

test("unfoldable records answer null and change nothing", () => {
  const cap = newCapture();
  assert.equal(foldCapture(cap, null), null);
  assert.equal(foldCapture(cap, {}), null);
  assert.equal(foldCapture(cap, { id: "x", kind: "nonsense", session: "s" }), null);
  assert.equal(foldCapture(cap, { id: "x", kind: "content_block",
                                  session: "s", index: "0" }), null,
               "a block without an integer index has no identity");
  assert.equal(cap.sessions.size, 1, "the bucket exists; nothing folded into it");
});
