// render.test.js — the pure half of render.js: formatters and the diff-line
// classifier. The DOM builders need a document and are exercised by the app
// itself; importing the module here also pins that its top level stays
// DOM-free. Never served, never imported by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { diffLineClass, diffLines, DIFF_LINE_CAP, sparkPoints,
         sparkSamples, sparkIndexAt, fmtTokens, fmtCost } from "./render.js";

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

test("diffLineClass: every prefix maps, file headers before signs", () => {
  assert.equal(diffLineClass("+++ b/rules.txt"), "file");
  assert.equal(diffLineClass("--- a/rules.txt"), "file");
  assert.equal(diffLineClass("@@ -1,3 +1,4 @@"), "hunk");
  assert.equal(diffLineClass("+allow github.com"), "add");
  assert.equal(diffLineClass("-deny *"), "del");
  for (const meta of ["diff --git a/x b/x", "index 3f2a1c9..d4e5f60 100644",
                      "new file mode 100644", "deleted file mode 100644",
                      "old mode 100644", "new mode 100755",
                      "rename from a", "rename to b", "similarity index 90%",
                      "copy from a", "copy to b",
                      "Binary files a/x and b/x differ",
                      "\\ No newline at end of file"]) {
    assert.equal(diffLineClass(meta), "meta", meta);
  }
  assert.equal(diffLineClass(" context"), "ctx");
  assert.equal(diffLineClass(""), "ctx");
});

test("diffLines caps at 20k lines and counts what it dropped", () => {
  assert.equal(DIFF_LINE_CAP, 20_000);
  const small = diffLines("+a\n-b\n c");
  assert.equal(small.dropped, 0);
  assert.deepEqual(small.lines.map((l) => l.cls), ["add", "del", "ctx"]);
  assert.deepEqual(small.lines.map((l) => l.text), ["+a", "-b", " c"]);
  const big = diffLines(Array.from({ length: 7 }, (_, i) => "+" + i).join("\n"), 5);
  assert.equal(big.lines.length, 5);
  assert.equal(big.dropped, 2);
  assert.equal(diffLines(null).lines.length, 1, "null reads as one empty line");
});

test("sparkSamples pairs plotted values with their stamps, holes dropped", () => {
  const s = sparkSamples([1, null, "junk", 4], ["t0", "t1", "t2", "t3"]);
  assert.deepEqual(s, [{ v: 1, ts: "t0" }, { v: 4, ts: "t3" }],
                   "the same filter as sparkPoints, stamps riding along");
  assert.deepEqual(sparkSamples([1, 2]), [{ v: 1, ts: null }, { v: 2, ts: null }],
                   "no stamps means null stamps, not an off-by-one");
  assert.deepEqual(sparkSamples(null, null), []);
});

test("sparkIndexAt inverts the x scale onto the nearest plotted sample", () => {
  // three points over width 100, pad 2: x = 2, 50, 98
  assert.equal(sparkIndexAt(3, 100, 2), 0);
  assert.equal(sparkIndexAt(3, 100, 49), 1);
  assert.equal(sparkIndexAt(3, 100, 97), 2);
  assert.equal(sparkIndexAt(3, 100, -50), 0, "clamped, never out of range");
  assert.equal(sparkIndexAt(3, 100, 500), 2);
  assert.equal(sparkIndexAt(1, 100, 50), null, "one point draws nothing");
  assert.equal(sparkIndexAt(0, 100, 50), null);
  assert.equal(sparkIndexAt(3, 100, NaN), null);
});

test("sparkPoints: only finite numbers reach the SVG, min-max scaled", () => {
  const pts = sparkPoints([0, "junk", 5, null, 10, NaN], 100, 20);
  assert.match(pts, /^(\d+(\.\d)?,\d+(\.\d)?)( \d+(\.\d)?,\d+(\.\d)?)*$/,
               "nothing but numeric pairs, whatever the input held");
  assert.equal(pts.split(" ").length, 3, "junk and nulls dropped, not zeroed");
  assert.equal(pts.split(" ")[0], "2.0,18.0", "min lands at the bottom");
  assert.equal(pts.split(" ")[2], "98.0,2.0", "max lands at the top");
  assert.equal(sparkPoints([7], 100, 20), "", "one point draws nothing");
  assert.equal(sparkPoints([], 100, 20), "");
  const flat = sparkPoints([3, 3, 3], 100, 20);
  assert.ok(flat.split(" ").every((p) => p.endsWith(",18.0")),
            "a flat series is a flat line, not a divide-by-zero");
});
