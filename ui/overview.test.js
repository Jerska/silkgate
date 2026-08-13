// overview.test.js — the triage function behind the card grid: pure over
// (activity, open turns, deny bursts, rc), so the thresholds and the sort
// ranks pin down here without a DOM. Never served, never imported by served
// files.
import test from "node:test";
import assert from "node:assert/strict";
import { triage, fmtAge, archiveRows } from "./views/overview.js";

const NOW = Date.parse("2026-08-12T12:00:00+00:00");

function at(secondsAgo) {
  return NOW - secondsAgo * 1000;
}

test("recent egress is working; the dot pulses", () => {
  const s = triage({ lastActivity: at(5), now: NOW });
  assert.equal(s.state, "working");
  assert.equal(s.pulse, true);
});

test("an open turn keeps working through a lull, but not forever", () => {
  assert.equal(triage({ lastActivity: at(120), openTurn: true, now: NOW }).state,
               "working", "a slow generation emits nothing for a while");
  assert.equal(triage({ lastActivity: at(360), openTurn: true, now: NOW }).state,
               "waiting");
});

test("a deny storm is recognized even though denies are egress", () => {
  const s = triage({ lastActivity: at(1), denyBurst: 5, now: NOW });
  assert.equal(s.state, "deny-storm");
  assert.ok(s.label.includes("5"));
  assert.equal(triage({ lastActivity: at(1), denyBurst: 4, now: NOW }).state,
               "working", "under the threshold, denies are just traffic");
});

test("idle hardens: idle at 61s, waiting at 3m, stuck at 10m", () => {
  assert.equal(triage({ lastActivity: at(61), now: NOW }).label, "idle 1m");
  const w = triage({ lastActivity: at(200), now: NOW });
  assert.equal(w.state, "waiting");
  assert.ok(w.label.startsWith("waiting"));
  assert.equal(triage({ lastActivity: at(601), now: NOW }).state, "stuck");
});

test("a clean last rc turns 10-minute silence into done, not stuck", () => {
  assert.equal(triage({ lastActivity: at(601), lastRc: 0, now: NOW }).state,
               "done");
});

test("a non-zero rc is stuck at any idle age — unless it is working again", () => {
  const s = triage({ lastActivity: at(120), lastRc: 3, now: NOW });
  assert.equal(s.state, "stuck");
  assert.ok(s.label.includes("exit 3"));
  assert.equal(triage({ lastActivity: at(5), lastRc: 3, now: NOW }).state,
               "working", "current activity outranks an old failure");
});

test("archived is archived, whatever else is true", () => {
  const s = triage({ archived: true, lastActivity: at(1), denyBurst: 99, now: NOW });
  assert.equal(s.state, "archived");
});

test("no activity anchor at all reads as waiting, honestly labeled", () => {
  const s = triage({ now: NOW });
  assert.equal(s.state, "waiting");
  assert.equal(s.label, "no activity yet");
});

test("ranks sort working > deny-storm > waiting > stuck > done > archived", () => {
  const ranks = [
    triage({ lastActivity: at(5), now: NOW }),
    triage({ lastActivity: at(5), denyBurst: 9, now: NOW }),
    triage({ lastActivity: at(200), now: NOW }),
    triage({ lastActivity: at(9000), now: NOW }),
    triage({ lastActivity: at(9000), lastRc: 0, now: NOW }),
    triage({ archived: true, now: NOW }),
  ].map((s) => s.rank);
  for (let i = 1; i < ranks.length; i++) {
    assert.ok(ranks[i] > ranks[i - 1], `rank ${i}: ${ranks[i]} > ${ranks[i - 1]}`);
  }
});

test("archive rows sort by end date, newest first, oldest last", () => {
  const rows = archiveRows([
    { sid: "a", name: "a", ended: "2026-08-10T12:00:00+00:00" },
    { sid: "c", name: "c", ended: "2026-08-12T12:00:00+00:00" },
    { sid: "b", name: "b", ended: "2026-08-11T12:00:00+00:00" },
  ]);
  assert.deepEqual(rows.map((r) => r.sid), ["c", "b", "a"]);
});

test("the sort stamp falls back: ended, then created, then the sid stamp", () => {
  const rows = archiveRows([
    { sid: "20260812T090000Z-old-abc123", name: "old" },
    { sid: "x", name: "x", created: "2026-08-12T11:00:00+00:00" },
    { sid: "y", name: "y", created: "2026-08-01T00:00:00+00:00",
      ended: "2026-08-12T10:00:00+00:00" },
  ]);
  assert.deepEqual(rows.map((r) => r.name), ["x", "y", "old"],
                   "x by created, y by ended over created, old by its sid");
});

test("branches is always an array: absent, one string, or a list", () => {
  const [none, one, many] = archiveRows([
    { sid: "20260812T120000Z-n-000000", name: "n" },
    { sid: "20260811T120000Z-o-000000", name: "o", branch: "agent/x" },
    { sid: "20260810T120000Z-m-000000", name: "m",
      branch: ["agent/x", "agent/y"] },
  ]);
  assert.deepEqual(none.branches, []);
  assert.deepEqual(one.branches, ["agent/x"]);
  assert.deepEqual(many.branches, ["agent/x", "agent/y"]);
});

test("last_rc passes through as lastRc; absent reads as null", () => {
  const [rc, no] = archiveRows([
    { sid: "20260812T120000Z-r-000000", name: "r", last_rc: 7 },
    { sid: "20260811T120000Z-s-000000", name: "s" },
  ]);
  assert.equal(rc.lastRc, 7);
  assert.equal(no.lastRc, null);
});

test("fmtAge picks the readable unit", () => {
  assert.equal(fmtAge(45_000), "45s");
  assert.equal(fmtAge(150_000), "2m");
  assert.equal(fmtAge(7_200_000), "2h");
  assert.equal(fmtAge(90 * 86400e3), "90d");
  assert.equal(fmtAge(null), "?");
});
