// pricing.test.js — the price table's lookup rules, not its figures: those are
// hand-maintained estimates the host verifies. Never served, never imported by
// served files.
import test from "node:test";
import assert from "node:assert/strict";
import { priceFor, estimateCost, contextWindow } from "./pricing.js";

test("the longest matching prefix wins", () => {
  const dated = priceFor("claude-opus-4-5-20251101");
  const bare = priceFor("claude-opus-4-20250514");
  assert.notEqual(dated.input, bare.input,
                  "opus-4-5 must not fall into the shorter claude-opus-4 row");
  assert.equal(dated.input, priceFor("claude-opus-4-5").input);
});

test("a prefix matches only at a segment boundary", () => {
  assert.equal(priceFor("claude-sonnet-4-60"), null,
               "claude-sonnet-4-60 must not take the claude-sonnet-4-6 row");
  assert.equal(priceFor("claude-sonnet-4-5x"), null,
               "a mid-segment continuation is a different model, not a match");
  assert.deepEqual(priceFor("claude-sonnet-4-6"),
                   priceFor("claude-sonnet-4-6-20991231"),
                   "an exact id and its dated form find the same row");
});

test("an unknown model answers null everywhere — never a guess", () => {
  assert.equal(priceFor("gpt-oss-120b"), null);
  assert.equal(priceFor("claude-9-quantum"), null);
  assert.equal(priceFor(""), null);
  assert.equal(priceFor(null), null);
  assert.equal(estimateCost("claude-9-quantum", { input: 1e6 }), null);
  assert.equal(contextWindow("claude-9-quantum"), null);
});

test("estimateCost prices each token class per MTok", () => {
  // sonnet-4-5: $3 in, $15 out, $0.30 cache-read, $3.75 cache-write per MTok
  const usd = estimateCost("claude-sonnet-4-5-20250929",
                           { input: 1_000_000, output: 100_000,
                             cacheRead: 2_000_000, cacheWrite: 200_000 });
  assert.equal(usd, 3 + 1.5 + 0.6 + 0.75);
});

test("zero tokens on a known model cost 0, which is not unknown", () => {
  assert.equal(estimateCost("claude-haiku-4-5", {}), 0);
  assert.equal(estimateCost("claude-haiku-4-5"), 0);
});

test("contextWindow answers the model's window", () => {
  assert.equal(contextWindow("claude-sonnet-4-5-20250929"), 200_000);
  assert.equal(contextWindow("claude-fable-5"), 1_000_000);
});
