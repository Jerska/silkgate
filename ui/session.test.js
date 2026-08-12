// session.test.js — the pure logic behind the session detail view: the
// meta lookup (sid→name resolution and the archived verdict). Never served,
// never imported by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { findMeta, extraText } from "./views/session.js";
import { triage } from "./views/overview.js";

const SESSIONS = {
  sessions: [
    { name: "live", state: "running", branch: "agent/x" },
    { name: "cooling", state: "archived" },
  ],
  archived: [
    { sid: "a1b2c3", name: "demo", state: "archived" },
    { sid: "d4e5f6", name: "old" },        // archived metas may carry no state
  ],
};

test("a live meta answers by name and is not archived", () => {
  const f = findMeta(SESSIONS, "live", "live");
  assert.equal(f.meta.branch, "agent/x");
  assert.equal(f.archived, false);
});

test("a live meta with an archived state reads archived", () => {
  assert.equal(findMeta(SESSIONS, "cooling", "cooling").archived, true);
});

test("an archived meta answers by sid, and placement makes it archived", () => {
  const f = findMeta(SESSIONS, "d4e5f6", "d4e5f6");
  assert.equal(f.meta.name, "old");
  assert.equal(f.archived, true,
               "the archived list is the verdict — no state field needed");
});

test("the sid resolves to the name the data is keyed under", () => {
  assert.equal(findMeta(SESSIONS, "a1b2c3", "a1b2c3").meta.name, "demo");
});

test("no payload yet, or no match, answers null and not archived", () => {
  assert.deepEqual(findMeta(null, "x", "x"), { meta: null, archived: false });
  assert.deepEqual(findMeta(SESSIONS, "nope", "nope"),
                   { meta: null, archived: false });
});

test("the ruleset string renders verbatim, never as a JSON literal", () => {
  const rules = "github.com/*/* GET\napi.anthropic.com/v1/messages POST\n";
  assert.equal(extraText(rules), rules, "real newlines, no quoting");
  assert.ok(!extraText(rules).includes("\\n"));
  assert.equal(extraText({ a: 1 }), '{\n  "a": 1\n}',
               "structured values still read as indented JSON");
});

test("the archived verdict drives triage to archived, matching the card", () => {
  const f = findMeta(SESSIONS, "d4e5f6", "d4e5f6");
  const s = triage({ archived: f.archived, lastActivity: Date.parse(
    "2026-08-12T11:56:00+00:00"), now: Date.parse("2026-08-12T12:00:00+00:00") });
  assert.equal(s.state, "archived",
               "never \"waiting 4m\" for a session in the archive");
});
