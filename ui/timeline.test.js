// timeline.test.js — the merged-timeline fold: ordering across the four
// trails, deny↔tool proximity tagging, journal normalization and the
// files-touched extraction, all over fixture record streams folded through
// the real capture and store modules. Never served, never imported by served
// files.
import test from "node:test";
import assert from "node:assert/strict";
import { timelineItems, tagDenies, journalEvent, filesTouched,
         DENY_TAG_WINDOW_MS } from "./timeline.js";
import { newCapture, foldCapture } from "./capture.js";
import { newStore, fold } from "./store.js";
import { turn, secretSighting } from "./fixtures.test.js";

const BASE = Date.parse("2026-08-12T12:00:00.000+00:00");

function ts(offsetSec) {
  return new Date(BASE + offsetSec * 1000).toISOString().replace("Z", "+00:00");
}

function deny(id, atSec, session = "dash") {
  return { ts: ts(atSec), id, session, decision: "deny", method: "GET",
           host: "evil.example", path: "/exfil", reason: "no matching rule" };
}

function captureOf(records) {
  const cap = newCapture();
  for (const rec of records) foldCapture(cap, rec);
  return cap;
}

test("the column interleaves all four trails in time order", () => {
  const cap = captureOf([
    ...turn({ session: "dash", exec: "e1", id: "f1", at: 0 }),
    secretSighting({ session: "dash", exec: "e1", id: "f1", at: 8 }),
  ]);
  const store = newStore();
  fold(store, deny("d1", 5));
  fold(store, { ts: ts(6), id: "r1", session: "dash", decision: "allow",
                method: "GET", host: "api.anthropic.com", path: "/v1/messages" });
  fold(store, { ts: ts(7), id: "r1", session: "dash", decision: "response",
                status: 200, duration_ms: 900 });
  const journal = [
    { ts: ts(-10), event: "created" },
    { ts: ts(20), event: "exec_end", exec_id: "e1", rc: 0 },
  ];
  const items = timelineItems({ captureSession: cap.sessions.get("dash"),
                                session: "dash", rows: store.rows, journal });
  assert.deepEqual(items.map((i) => i.kind),
                   ["journal", "turn", "deny", "response", "sighting", "journal"]);
  assert.ok(items.every((i, n) => n === 0 || items[n - 1].at <= i.at),
            "sorted by parsed time");
});

test("a deny shortly after a tool_use is tagged; a distant one is not", () => {
  // The fixture turn's tool block lands at +2s.
  const cap = captureOf(turn({ session: "dash", exec: "e1", id: "f1", at: 0 }));
  const store = newStore();
  fold(store, deny("near", 4));                        // 2s after the tool
  fold(store, deny("far", 2 + DENY_TAG_WINDOW_MS / 1000 + 5));
  const items = timelineItems({ captureSession: cap.sessions.get("dash"),
                                session: "dash", rows: store.rows });
  const near = items.find((i) => i.kind === "deny" && i.row.id === "near");
  const far = items.find((i) => i.kind === "deny" && i.row.id === "far");
  assert.deepEqual(near.after, { tool: "bash", dtMs: 2000 });
  assert.equal(far.after, undefined, "outside the window, no causal claim");
});

test("a deny BEFORE the tool_use is never its consequence", () => {
  const cap = captureOf(turn({ session: "dash", exec: "e1", id: "f1", at: 0 }));
  const store = newStore();
  fold(store, deny("early", 1));                       // 1s before the tool
  const items = timelineItems({ captureSession: cap.sessions.get("dash"),
                                session: "dash", rows: store.rows });
  assert.equal(items.find((i) => i.kind === "deny").after, undefined);
});

test("tagDenies works over bare arrays too — the window is the contract", () => {
  const items = [{ kind: "deny", at: 3000 }, { kind: "deny", at: 30_000 }];
  tagDenies(items, [{ at: 1000, name: "Bash" }]);
  assert.deepEqual(items[0].after, { tool: "Bash", dtMs: 2000 });
  assert.equal(items[1].after, undefined);
});

test("rows from other sessions and still-pending flows stay out", () => {
  const store = newStore();
  fold(store, deny("other", 1, "elsewhere"));
  fold(store, { ts: ts(2), id: "p1", session: "dash", decision: "allow",
                method: "GET", host: "registry.npmjs.org", path: "/x" });
  const items = timelineItems({ session: "dash", rows: store.rows });
  assert.equal(items.length, 0,
               "no deny from elsewhere, no response item before a status lands");
});

test("journalEvent keeps env NAMES and drops the values", () => {
  const ev = journalEvent({ ts: ts(0), event: "exec_start", exec_id: "e1",
                            argv: ["claude", "-p", "fix the tests"], tty: true,
                            env: { PATH: "/usr/bin", API_KEY: "sk-SECRET" } });
  assert.deepEqual(ev.envNames, ["PATH", "API_KEY"]);
  assert.ok(!JSON.stringify(ev).includes("sk-SECRET"),
            "an env VALUE never survives normalization");
  assert.equal(ev.tty, true);
  assert.deepEqual(ev.argv, ["claude", "-p", "fix the tests"]);
});

test("journalEvent tolerates spelling drift and rejects the shapeless", () => {
  assert.equal(journalEvent({ ts: ts(0), kind: "harvest" }).event, "harvest");
  assert.equal(journalEvent({ ts: ts(0), type: "frozen" }).event, "frozen");
  assert.equal(journalEvent({ ts: ts(0), event: "exec_end", exit_code: 3 }).rc, 3);
  assert.equal(journalEvent({ ts: ts(0) }), null);
  assert.equal(journalEvent("junk"), null);
  assert.deepEqual(journalEvent({ event: "exec_start", env: ["A", "B"] }).envNames,
                   ["A", "B"], "an env already reduced to names passes through");
  assert.deepEqual(journalEvent({ event: "exec_start",
                                  env_names: ["FOO", "PATH"] }).envNames,
                   ["FOO", "PATH"], "env_names is the backend's actual spelling");
});

test("filesTouched maps known tool inputs to paths, requested not executed", () => {
  const recs = [
    ...turn({ session: "dash", exec: "e1", id: "f1", at: 0 },
            { tool: { tool_name: "Edit",
                      tool_input: { file_path: "/w/a.js", old_string: "x" } } }),
    ...turn({ session: "dash", exec: "e1", id: "f2", at: 10 },
            { tool: { tool_name: "Write",
                      tool_input: { file_path: "/w/b.js", content: "y" } } }),
    ...turn({ session: "dash", exec: "e2", id: "f3", at: 20 },
            { tool: { tool_name: "Read",
                      tool_input: { file_path: "/w/a.js" } } }),
    ...turn({ session: "dash", exec: "e1", id: "f4", at: 30 }),  // bash: not a file tool
    ...turn({ session: "dash", exec: "e1", id: "f5", at: 40 },
            { tool: { tool_name: "Edit", tool_input: { file_path: 42 } } }),
  ];
  const cap = captureOf(recs);
  const files = filesTouched(cap.sessions.get("dash"));
  assert.deepEqual(files.map((f) => f.path), ["/w/a.js", "/w/b.js"],
                   "first-touch order, across exec buckets");
  const a = files[0];
  assert.equal(a.count, 2);
  assert.deepEqual([...a.tools].sort(), ["Edit", "Read"]);
  assert.ok(!files.some((f) => f.path === 42), "a non-string path never lands");
});

test("an empty world yields an empty column", () => {
  assert.deepEqual(timelineItems({}), []);
  assert.deepEqual(filesTouched(null), []);
  assert.deepEqual(filesTouched(undefined), []);
});
