// router.js — the hash is the app's whole navigation state, and this module is
// its grammar: parse a hash into a route, build a hash from a route, and map the
// pre-route era's bare filter hashes onto today's #/traffic. Pure on purpose —
// no DOM, no location — so every corner of the grammar is testable in node.
//
// Routes:
//   #/                          the overview grid
//   #/traffic?session=&…        the calls table; param names predate the router
//                               (they were the whole hash once) and keep their
//                               exact semantics, so old bookmarks survive
//   #/session/<ident>?tab=…     one session's detail; tab defaults to activity

const TRAFFIC_PARAMS = ["session", "decision", "method", "host", "window", "follow"];
const TABS = new Set(["activity", "calls", "config"]);

function strip(hash) {
  return typeof hash === "string" && hash.startsWith("#") ? hash.slice(1) : hash || "";
}

// Parse a raw location.hash into a route object. Anything unrecognized lands on
// the overview rather than a dead view: a stale bookmark should show the app,
// not an error. Legacy hashes also fall through to overview here — the caller
// runs legacyRedirect first, and by the time parseRoute sees the hash it is
// either routed or junk.
export function parseRoute(hash) {
  const h = strip(hash);
  if (!h.startsWith("/")) {
    return { view: "overview" };
  }
  const q = h.indexOf("?");
  const path = q === -1 ? h : h.slice(0, q);
  const query = new URLSearchParams(q === -1 ? "" : h.slice(q + 1));
  if (path === "/") {
    return { view: "overview" };
  }
  if (path === "/traffic") {
    const params = {};
    for (const k of TRAFFIC_PARAMS) {
      const v = query.get(k);
      if (v) params[k] = v;      // absent and empty read the same, as they always did
    }
    return { view: "traffic", params };
  }
  const m = /^\/session\/([^/]+)$/.exec(path);
  if (m) {
    const tab = query.get("tab");
    return { view: "session", ident: decodeURIComponent(m[1]),
             tab: TABS.has(tab) ? tab : "activity" };
  }
  return { view: "overview" };
}

// Build the canonical hash for a route. The inverse of parseRoute up to
// canonicalization: params serialize in one fixed order and defaults are
// omitted (tab=activity, empty params), so two routes that mean the same thing
// compare equal as strings.
export function buildRoute(route) {
  if (!route || typeof route !== "object") {
    return "#/";
  }
  if (route.view === "traffic") {
    const p = new URLSearchParams();
    for (const k of TRAFFIC_PARAMS) {
      const v = (route.params || {})[k];
      if (v) p.set(k, v);
    }
    const qs = p.toString();
    return "#/traffic" + (qs ? "?" + qs : "");
  }
  if (route.view === "session" && route.ident) {
    const tab = TABS.has(route.tab) && route.tab !== "activity"
      ? "?tab=" + route.tab : "";
    return "#/session/" + encodeURIComponent(route.ident) + tab;
  }
  return "#/";
}

// The pre-route app kept its filters as a bare query in the hash
// (#session=demo&decision=deny). Any non-empty hash that does not start with
// "/" is one of those: answer the #/traffic hash it should become, or null when
// the hash is empty or already routed. Only the six filter names carry over —
// nothing else ever lived in the old hash, and forwarding junk would just
// enshrine it in the new URL. The caller redirects via location.replace, so the
// old form never enters history.
export function legacyRedirect(hash) {
  const h = strip(hash);
  if (!h || h.startsWith("/")) {
    return null;
  }
  const query = new URLSearchParams(h);
  const params = {};
  for (const k of TRAFFIC_PARAMS) {
    const v = query.get(k);
    if (v) params[k] = v;
  }
  return buildRoute({ view: "traffic", params });
}
