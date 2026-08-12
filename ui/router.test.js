// router.test.js — the route grammar, pinned: parse/build round-trips, default
// omission, and the legacy-hash redirect. Never served, never imported by
// served files.
import test from "node:test";
import assert from "node:assert/strict";
import { parseRoute, buildRoute, legacyRedirect } from "./router.js";

test("empty, bare and root hashes all mean the overview", () => {
  for (const h of ["", "#", "#/", "/"]) {
    assert.deepEqual(parseRoute(h), { view: "overview" }, JSON.stringify(h));
  }
});

test("unknown routed paths land on the overview, not a dead view", () => {
  assert.equal(parseRoute("#/nope").view, "overview");
  assert.equal(parseRoute("#/session").view, "overview");        // no ident
  assert.equal(parseRoute("#/session/a/b").view, "overview");    // too deep
});

test("traffic params parse with their old names and nothing extra", () => {
  const r = parseRoute("#/traffic?session=demo&decision=deny&method=GET"
                       + "&host=pypi&window=15m&follow=0&junk=1");
  assert.deepEqual(r, { view: "traffic",
                        params: { session: "demo", decision: "deny", method: "GET",
                                  host: "pypi", window: "15m", follow: "0" } });
});

test("empty traffic params read as absent, as they always did", () => {
  assert.deepEqual(parseRoute("#/traffic?session=&host=").params, {});
  assert.deepEqual(parseRoute("#/traffic").params, {});
});

test("session routes carry ident and a clamped tab", () => {
  assert.deepEqual(parseRoute("#/session/demo"),
                   { view: "session", ident: "demo", tab: "activity" });
  assert.deepEqual(parseRoute("#/session/demo?tab=calls"),
                   { view: "session", ident: "demo", tab: "calls" });
  assert.equal(parseRoute("#/session/demo?tab=bogus").tab, "activity",
               "an unknown tab falls back to the default, not a blank pane");
});

test("every wave-2 tab parses and round-trips", () => {
  for (const tab of ["diff", "config", "brief", "output", "metrics"]) {
    const hash = `#/session/demo?tab=${tab}`;
    assert.deepEqual(parseRoute(hash), { view: "session", ident: "demo", tab });
    assert.equal(buildRoute(parseRoute(hash)), hash);
  }
});

test("search routes carry q; an empty q is omitted on build", () => {
  assert.deepEqual(parseRoute("#/search?q=api+key"),
                   { view: "search", q: "api key" });
  assert.deepEqual(parseRoute("#/search"), { view: "search", q: "" });
  assert.equal(buildRoute({ view: "search", q: "api key" }), "#/search?q=api+key");
  assert.equal(buildRoute({ view: "search", q: "" }), "#/search");
  assert.equal(buildRoute({ view: "search", params: { q: "x" } }), "#/search?q=x",
               "navigate() callers pass params like every other view");
});

test("a malformed percent-escape falls back to the raw ident, never throws", () => {
  assert.deepEqual(parseRoute("#/session/100%"),
                   { view: "session", ident: "100%", tab: "activity" });
  assert.deepEqual(parseRoute("#/session/%E0"),
                   { view: "session", ident: "%E0", tab: "activity" });
  assert.equal(parseRoute("#/session/%E0?tab=calls").tab, "calls",
               "the tab still parses beside a junk ident");
});

test("session idents survive URL encoding both ways", () => {
  const ident = "a b/c%d";
  const hash = buildRoute({ view: "session", ident });
  assert.deepEqual(parseRoute(hash),
                   { view: "session", ident, tab: "activity" });
});

test("buildRoute canonicalizes: fixed param order, defaults omitted", () => {
  assert.equal(buildRoute({ view: "overview" }), "#/");
  assert.equal(buildRoute({ view: "traffic", params: {} }), "#/traffic");
  assert.equal(buildRoute({ view: "traffic",
                            params: { follow: "0", session: "demo" } }),
               "#/traffic?session=demo&follow=0");
  assert.equal(buildRoute({ view: "session", ident: "demo", tab: "activity" }),
               "#/session/demo");
  assert.equal(buildRoute({ view: "session", ident: "demo", tab: "config" }),
               "#/session/demo?tab=config");
  assert.equal(buildRoute(null), "#/");
  assert.equal(buildRoute({ view: "session" }), "#/", "no ident, no route");
});

test("parse ∘ build is identity on canonical hashes", () => {
  for (const h of ["#/",
                   "#/traffic",
                   "#/traffic?session=demo",
                   "#/traffic?session=null&decision=deny&method=GET&host=py"
                   + "&window=1h&follow=0",
                   "#/session/demo",
                   "#/session/demo?tab=calls",
                   "#/session/demo?tab=config"]) {
    assert.equal(buildRoute(parseRoute(h)), h, h);
  }
});

test("legacy hashes redirect to #/traffic with the same params", () => {
  assert.equal(legacyRedirect("#session=demo&decision=deny"),
               "#/traffic?session=demo&decision=deny");
  assert.equal(legacyRedirect("#follow=0"), "#/traffic?follow=0");
  assert.equal(legacyRedirect("#session=null"), "#/traffic?session=null");
  assert.equal(legacyRedirect("#junk=1"), "#/traffic",
               "only the six filter names carry over");
  assert.equal(legacyRedirect("#whatever"), "#/traffic");
});

test("routed and empty hashes never redirect", () => {
  for (const h of ["", "#", "#/", "#/traffic?session=demo", "#/session/x"]) {
    assert.equal(legacyRedirect(h), null, JSON.stringify(h));
  }
});
