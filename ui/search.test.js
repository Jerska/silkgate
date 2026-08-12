// search.test.js — result grouping and per-source summary lines for the global
// search view. Never served, never imported by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { groupResults, resultLine, SEARCH_MIN_CHARS } from "./search.js";

test("results group by source in fixed order, unknowns last, empties gone", () => {
  const groups = groupResults([
    { source: "journal", record: { event: "harvest" } },
    { source: "audit", record: { decision: "deny" } },
    { source: "weird", record: {} },
    { source: "audit", record: { decision: "allow" } },
  ]);
  assert.deepEqual([...groups.keys()], ["audit", "journal", "other"],
                   "capture had no hits, so no capture group");
  assert.equal(groups.get("audit").length, 2);
  assert.equal(groups.get("audit")[0].record.decision, "deny",
               "server order stands inside a group");
  assert.equal(groups.get("other")[0].source, "weird");
});

test("dud inputs group to nothing", () => {
  assert.equal(groupResults(null).size, 0);
  assert.equal(groupResults([null, "junk"]).size, 0);
});

test("audit lines read as verdict + target + reason", () => {
  const line = resultLine({ source: "audit",
                            record: { session: "dash", ts: "t", decision: "deny",
                                      method: "GET", host: "evil.example",
                                      path: "/x", reason: "no matching rule" } });
  assert.equal(line.session, "dash");
  assert.equal(line.text, "deny GET evil.example /x — no matching rule");
});

test("capture lines name the kind, tool or a text snippet", () => {
  assert.equal(resultLine({ source: "capture",
                            record: { kind: "content_block", type: "tool_use",
                                      tool_name: "Bash" } }).text,
               "tool_use Bash");
  assert.equal(resultLine({ source: "capture",
                            record: { kind: "turn_start",
                                      model: "claude-sonnet-5" } }).text,
               "turn_start claude-sonnet-5");
  const long = resultLine({ source: "capture",
                            record: { kind: "content_block", type: "text",
                                      text: "y".repeat(300) } });
  assert.ok(long.text.length <= 121 && long.text.endsWith("…"), "snippets cap");
});

test("journal lines carry event, argv and rc; unknown sources fall back", () => {
  assert.equal(resultLine({ source: "journal",
                            record: { event: "exec_end", rc: 3 } }).text,
               "exec_end rc 3");
  assert.equal(resultLine({ source: "journal",
                            record: { event: "exec_start",
                                      argv: ["claude", "-p", "go"] } }).text,
               "exec_start claude -p go");
  const fb = resultLine({ source: "mystery", record: { a: 1 } });
  assert.equal(fb.text, '{"a":1}');
  assert.equal(resultLine(null).session, null, "a dud result still yields a line");
});

test("the minimum query length is three characters", () => {
  assert.equal(SEARCH_MIN_CHARS, 3);
});
