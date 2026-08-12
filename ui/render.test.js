// render.test.js — the pure half of render.js: formatters and the diff-line
// classifier. The DOM builders need a document and are exercised by the app
// itself; importing the module here also pins that its top level stays
// DOM-free. Never served, never imported by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { diffLineClass, fmtTokens, fmtCost } from "./render.js";

test("fmtTokens: readable magnitudes, and null is not a zero", () => {
  assert.equal(fmtTokens(0), "0");
  assert.equal(fmtTokens(999), "999");
  assert.equal(fmtTokens(1000), "1.0k");
  assert.equal(fmtTokens(12345), "12.3k");
  assert.equal(fmtTokens(999_949), "999.9k");
  assert.equal(fmtTokens(2_500_000), "2.50M");
  assert.equal(fmtTokens(null), "—");
  assert.equal(fmtTokens(undefined), "—");
  assert.equal(fmtTokens("nope"), "—");
});

test("fmtCost: always an estimate, never a guessed zero", () => {
  assert.equal(fmtCost(null), "—", "no price known is not free");
  assert.equal(fmtCost(0), "~$0.00");
  assert.equal(fmtCost(0.5), "~$0.50");
  assert.equal(fmtCost(0.004), "~$0.0040");
  assert.equal(fmtCost(123.4), "~$123");
});

test("diffLineClass: file headers before hunks and signs", () => {
  assert.equal(diffLineClass("+++ b/rules.txt"), "diff-file");
  assert.equal(diffLineClass("--- a/rules.txt"), "diff-file");
  assert.equal(diffLineClass("@@ -1,3 +1,4 @@"), "diff-hunk");
  assert.equal(diffLineClass("+allow github.com"), "diff-add");
  assert.equal(diffLineClass("-deny *"), "diff-del");
  assert.equal(diffLineClass(" context"), "");
  assert.equal(diffLineClass(""), "");
});
