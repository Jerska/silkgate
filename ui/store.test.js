// store.test.js — the per-session tallies fold() keeps, plus the fold contract
// they lean on. Never served, never imported by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { newStore, fold, rowPasses, sessionToFilter, filterToSession }
  from "./store.js";

function rec(over = {}) {
  return { ts: "2026-08-12T12:00:00.000+00:00", decision: "allow", id: "f1",
           method: "GET", host: "api.anthropic.com", port: 443,
           path: "/v1/messages", reason: "rule", session: "demo",
           listen_port: 8090, ...over };
}

test("an allow/response pair is one request, not two", () => {
  const s = newStore();
  fold(s, rec({ id: "a", decision: "allow" }));
  fold(s, rec({ id: "a", decision: "response", status: 200 }));
  assert.deepEqual(s.tallies.get("demo"),
                   { denies: 0, requests: 1, lastTs: rec().ts });
});

test("a deny counts as a request and a deny, once", () => {
  const s = newStore();
  fold(s, rec({ id: "a", decision: "deny", reason: "no matching rule" }));
  fold(s, rec({ id: "a", decision: "deny" }));       // history/stream overlap
  fold(s, rec({ id: "a", decision: "response" }));   // shadowed by the terminal deny
  const t = s.tallies.get("demo");
  assert.equal(t.requests, 1);
  assert.equal(t.denies, 1);
});

test("an allow upgraded to deny tallies the deny under the row's session", () => {
  const s = newStore();
  fold(s, rec({ id: "a", decision: "allow" }));
  fold(s, rec({ id: "a", decision: "deny" }));
  assert.deepEqual(s.tallies.get("demo").denies, 1);
  assert.equal(s.tallies.get("demo").requests, 1);
});

test("unattributed rows tally under the null session", () => {
  const s = newStore();
  fold(s, rec({ id: "a", session: null, decision: "deny" }));
  assert.equal(s.tallies.get(null).denies, 1);
  assert.equal(s.tallies.has("demo"), false);
});

test("a response that attributes a null-session row moves the count", () => {
  const s = newStore();
  fold(s, rec({ id: "a", decision: "allow", session: null }));
  assert.equal(s.tallies.get(null).requests, 1);
  fold(s, rec({ id: "a", decision: "response", session: "demo", status: 200 }));
  assert.equal(s.tallies.get(null).requests, 0, "moved out, not double-counted");
  assert.equal(s.tallies.get("demo").requests, 1);
});

test("eviction never decrements a tally", () => {
  const s = newStore(2);
  for (const id of ["a", "b", "c", "d"]) {
    fold(s, rec({ id }));
  }
  assert.equal(s.rows.size, 2, "the cap holds");
  assert.equal(s.tallies.get("demo").requests, 4,
               "tallies are a recent-window counter, not a mirror of rows");
});

test("lastTs tracks the newest parsable stamp, out-of-order safe", () => {
  const s = newStore();
  fold(s, rec({ id: "a", ts: "2026-08-12T12:00:05+00:00" }));
  fold(s, rec({ id: "b", ts: "2026-08-12T12:00:01+00:00" }));  // resume overlap
  fold(s, rec({ id: "c", ts: "not a time" }));
  assert.equal(s.tallies.get("demo").lastTs, "2026-08-12T12:00:05+00:00");
});

test("duplicate records never touch the tallies", () => {
  const s = newStore();
  fold(s, rec({ id: "a" }));
  fold(s, rec({ id: "a" }));
  assert.equal(s.tallies.get("demo").requests, 1);
});

// --- the session filter's sentinel vs a session literally named "null" ---------

test("filter space spells the name null as (null), and only that name", () => {
  assert.equal(sessionToFilter("null"), "(null)");
  assert.equal(sessionToFilter("demo"), "demo");
  assert.equal(filterToSession("(null)"), "null");
  assert.equal(filterToSession("demo"), "demo");
  assert.equal(filterToSession(sessionToFilter("null")), "null");
});

test('the "null" filter admits only unattributed rows', () => {
  const unattributed = { ...rec(), session: null };
  const named = { ...rec(), session: "null" };   // a legal name
  assert.equal(rowPasses(unattributed, { session: "null" }), true);
  assert.equal(rowPasses(named, { session: "null" }), false);
});

test('the "(null)" filter admits only the session named null', () => {
  const unattributed = { ...rec(), session: null };
  const named = { ...rec(), session: "null" };
  assert.equal(rowPasses(named, { session: "(null)" }), true);
  assert.equal(rowPasses(unattributed, { session: "(null)" }), false);
  assert.equal(rowPasses({ ...rec(), session: "demo" }, { session: "(null)" }),
               false);
});

test("an ordinary name still filters as itself", () => {
  assert.equal(rowPasses({ ...rec(), session: "demo" }, { session: "demo" }), true);
  assert.equal(rowPasses({ ...rec(), session: "other" }, { session: "demo" }),
               false);
});
