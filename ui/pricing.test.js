// pricing.test.js — the price table's lookup rules, not its figures: those are
// hand-maintained estimates the host verifies. Never served, never imported by
// served files.
import test from "node:test";
import assert from "node:assert/strict";
import { priceFor, estimateCost, contextWindow } from "./pricing.js";

test("a dated snapshot finds its row", () => {
  assert.deepEqual(priceFor("claude-opus-4-5-20251101"), priceFor("claude-opus-4-5"));
  assert.deepEqual(priceFor("claude-sonnet-4-6-20991231"), priceFor("claude-sonnet-4-6"));
  assert.notEqual(priceFor("claude-opus-4-5-20251101").input,
                  priceFor("claude-opus-4-20250514").input,
                  "opus-4-5 must not fall into the claude-opus-4 row");
});

test("an unlisted release never borrows a sibling's price", () => {
  assert.equal(priceFor("claude-opus-6"), null, "not claude-opus-5's price");
  assert.equal(priceFor("claude-sonnet-4-60"), null);
  assert.equal(priceFor("claude-sonnet-45"), null);
  assert.equal(priceFor("claude-opus-4-5-latest"), null, "only an 8-digit date suffix");
  assert.equal(priceFor("claude-opus-4-5-2025110"), null);
  assert.equal(priceFor("constructor"), null, "only own rows answer");
  assert.equal(priceFor("toString-20250101"), null);
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
