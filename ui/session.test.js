// session.test.js — the pure logic behind the session detail view: the
// meta lookup (sid→name resolution and the archived verdict), the brief
// selection, and the tool-call line. Never served, never imported by
// served files.
import test from "node:test";
import assert from "node:assert/strict";
import { findMeta, extraText, selectBrief, toolCallView }
  from "./views/session.js";
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

test("an archived meta answers by name when no sid matches", () => {
  // A session downed while its detail view is open under its name: the live
  // list drops the name, no archived sid equals it, and the name fallback
  // resolves the newest archived row (the list arrives newest-first).
  const sessions = {
    sessions: [],
    archived: [
      { sid: "f7g8h9", name: "demo" },     // newer run of the same name
      { sid: "a1b2c3", name: "demo" },
    ],
  };
  const f = findMeta(sessions, "demo", "demo");
  assert.equal(f.meta.sid, "f7g8h9", "the first match is the newest");
  assert.equal(f.archived, true);
});

test("a live meta with the same name wins over an archived row", () => {
  const sessions = {
    sessions: [{ name: "demo", state: "running" }],
    archived: [{ sid: "a1b2c3", name: "demo" }],
  };
  const f = findMeta(sessions, "demo", "demo");
  assert.equal(f.meta.state, "running");
  assert.equal(f.archived, false);
});

test("a sid match still wins over the name fallback", () => {
  const f = findMeta(SESSIONS, "a1b2c3", "old");
  assert.equal(f.meta.name, "demo", "the sid pass answers first");
  assert.equal(f.archived, true);
});

test("no payload yet, or no match, answers null and not archived", () => {
  assert.deepEqual(findMeta(null, "x", "x"), { meta: null, archived: false });
  assert.deepEqual(findMeta(SESSIONS, "nope", "nope"),
                   { meta: null, archived: false });
});

const BRIEFS = {
  "default": { source: "flag", text: "the session brief" },
  "workspace": { source: "workspace", text: "guest-writable fallback" },
  "a1b2c3d4": { source: "default", text: "for one exec" },
};

test("the selected exec's brief wins", () => {
  assert.deepEqual(selectBrief(BRIEFS, "a1b2c3d4"),
                   { key: "a1b2c3d4", brief: BRIEFS["a1b2c3d4"] });
});

test("no selection, or a selection with no brief, falls to the default", () => {
  assert.equal(selectBrief(BRIEFS, null).key, "default");
  assert.equal(selectBrief(BRIEFS, "ffffffff").key, "default");
});

test("without a default the workspace fallback answers, and it alone", () => {
  const only = { workspace: BRIEFS.workspace };
  assert.equal(selectBrief(only, null).key, "workspace");
  assert.equal(selectBrief(only, null).brief.source, "workspace",
               "the untrusted badge keys off this source");
});

test("an empty or absent map answers null — 'no brief recorded'", () => {
  assert.equal(selectBrief({}, null), null);
  assert.equal(selectBrief(null, "a1b2c3d4"), null);
  assert.equal(selectBrief("junk", null), null);
});

test("an exec id is record data: inherited keys never answer", () => {
  assert.equal(selectBrief({}, "constructor"), null);
  assert.equal(selectBrief({}, "__proto__"), null);
  assert.equal(selectBrief({ "default": "not-an-object" }, null), null,
               "a malformed entry reads as absent, not as a brief");
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

test("a short bash call opens with its command and drops the description", () => {
  const v = toolCallView({ tool_name: "Bash",
    tool_input: { command: "ls -la", description: "x" } });
  assert.deepEqual(v, { line: "Bash", body: "ls -la", open: true });
  assert.ok(!v.body.includes("x"), "the description never renders");
});

test("the bash boundary: 8 lines stay open, 9 collapse behind the first", () => {
  const eight = Array.from({ length: 8 }, (_, i) => `l${i}`).join("\n");
  const short = toolCallView({ tool_name: "Bash",
    tool_input: { command: eight } });
  assert.equal(short.open, true);
  assert.equal(short.line, "Bash");
  const nine = eight + "\nl8";
  const v = toolCallView({ tool_name: "Bash", tool_input: { command: nine } });
  assert.equal(v.open, false);
  assert.equal(v.line, "Bash l0…");
  assert.equal(v.body, nine, "the whole command still sits in the <pre>");
});

test("a bash call without a usable command takes the generic path", () => {
  for (const tool_input of [{}, { command: "" }, { command: 42 }]) {
    const v = toolCallView({ tool_name: "Bash", tool_input });
    assert.equal(v.line, `Bash(${JSON.stringify(tool_input)})`);
    assert.equal(v.body, null);
    assert.equal(v.open, false);
  }
});

test("read and edit stay bodyless, whatever the input holds", () => {
  const old_string = Array.from({ length: 50 }, () => "line").join("\n");
  for (const tool_name of ["Read", "Edit"]) {
    const v = toolCallView({ tool_name,
      tool_input: { file_path: "/w/a.js", old_string } });
    assert.equal(v.line, `${tool_name}(/w/a.js)`);
    assert.equal(v.body, null, "the path replaces the JSON body entirely");
  }
});

test("write keeps its path line; a long pretty JSON earns a collapsed body", () => {
  const content = Array.from({ length: 20 }, (_, i) => `l${i}`).join("\n");
  const v = toolCallView({ tool_name: "Write",
    tool_input: { file_path: "/workspace/x", content } });
  assert.equal(v.line, "Write(/workspace/x)");
  // JSON.stringify escapes the content's newlines, so 20 lines of content
  // pretty-print as one JSON line — under the 8-line rule, no expander.
  assert.equal(v.body, null);
  const wide = toolCallView({ tool_name: "Write",
    tool_input: { file_path: "/workspace/x", content, mode: "w", a: 1, b: 2,
                  c: 3, d: 4 } });
  assert.equal(wide.line, "Write(/workspace/x)");
  assert.notEqual(wide.body, null);
  assert.equal(wide.open, false);
});

test("a salient value past 120 characters is capped and marked", () => {
  const long = "x".repeat(130);
  const g = toolCallView({ tool_name: "Grep", tool_input: { pattern: long } });
  assert.equal(g.line, `Grep(${"x".repeat(120)}…)`);
  const nine = [long, ...Array.from({ length: 8 }, (_, i) => `l${i}`)].join("\n");
  const b = toolCallView({ tool_name: "Bash", tool_input: { command: nine } });
  assert.equal(b.line, `Bash ${"x".repeat(120)}…`);
});

test("an unmapped tool falls back to compact JSON in the parens", () => {
  const v = toolCallView({ tool_name: "TodoWrite",
    tool_input: { todos: [1, 2] } });
  assert.equal(v.line, 'TodoWrite({"todos":[1,2]})');
  assert.equal(v.body, null);
});

test("a mapped tool whose salient key is missing falls back to JSON", () => {
  const v = toolCallView({ tool_name: "Grep", tool_input: { glob: "*.js" } });
  assert.equal(v.line, 'Grep({"glob":"*.js"})');
});

test("a null tool_name renders as ?", () => {
  const v = toolCallView({ tool_name: null, tool_input: { pattern: "x" } });
  assert.equal(v.line, '?({"pattern":"x"})');
});

test("a null tool_input renders empty parens and no body", () => {
  assert.deepEqual(toolCallView({ tool_name: "Read", tool_input: null }),
                   { line: "Read()", body: null, open: false });
  assert.deepEqual(toolCallView({ tool_name: "Bash" }),
                   { line: "Bash()", body: null, open: false });
});

test("truncated appends its mark on every path", () => {
  assert.equal(toolCallView({ tool_name: "Bash", truncated: true,
    tool_input: { command: "ls" } }).line, "Bash (truncated)");
  assert.equal(toolCallView({ tool_name: "Read", truncated: true,
    tool_input: { file_path: "/w/a" } }).line, "Read(/w/a) (truncated)");
});

test("the map is case-insensitive but the name shows as it arrived", () => {
  const v = toolCallView({ tool_name: "BASH", tool_input: { command: "ls" } });
  assert.deepEqual(v, { line: "BASH", body: "ls", open: true });
});

test("the generic boundary: exactly 8 pretty lines means no expander", () => {
  const eight = { pattern: "x", a: 1, b: 2, c: 3, d: 4, e: 5 };
  assert.equal(JSON.stringify(eight, null, 2).split("\n").length, 8);
  assert.equal(toolCallView({ tool_name: "Grep", tool_input: eight }).body,
               null);
  const nine = { ...eight, f: 6 };
  const v = toolCallView({ tool_name: "Grep", tool_input: nine });
  assert.equal(v.body, JSON.stringify(nine, null, 2));
  assert.equal(v.open, false);
});
