// router.js — the hash is the app's whole navigation state, and this is its
// grammar: hash to route, route to hash, and bare filter hashes to #/traffic.
// Pure, with no DOM or location, so it tests in node.
//
// Routes:
//   #/                          the overview grid
//   #/traffic?session=&…        the calls table (its params also work as a bare
//                               hash, #session=…, which redirects here)
//   #/session/<ident>?tab=…     one session's detail; tab defaults to activity
//   #/search?q=…                global search across audit/capture/journal

const TRAFFIC_PARAMS = ["session", "decision", "method", "host", "window", "follow"];
const TABS = new Set(["activity", "calls", "diff", "config", "brief",
                      "output", "metrics"]);

function strip(hash) {
  return typeof hash === "string" && hash.startsWith("#") ? hash.slice(1) : hash || "";
}

// Parse location.hash into a route. Anything unrecognized lands on the
// overview, not an error. The caller runs legacyRedirect first.
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
  if (path === "/search") {
    return { view: "search", q: query.get("q") ?? "" };
  }
  const m = /^\/session\/([^/]+)$/.exec(path);
  if (m) {
    const tab = query.get("tab");
    // decodeURIComponent throws URIError on a malformed escape ("100%",
    // "%E0"); a pasted hash must never blank the app, so the raw match is
    // the fallback ident.
    let ident = m[1];
    try {
      ident = decodeURIComponent(m[1]);
    } catch {
      // keep the raw match
    }
    return { view: "session", ident,
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
  if (route.view === "search") {
    const q = route.q ?? (route.params || {}).q ?? "";
    if (!q) return "#/search";
    const p = new URLSearchParams();
    p.set("q", q);                 // URLSearchParams keeps the form canonical:
    return "#/search?" + p;        // parse ∘ build is identity, spaces as "+"
  }
  return "#/";
}

// A bare filter hash (#session=demo&decision=deny) is any non-empty hash not
// starting with "/". Answer its #/traffic form, or null. Only the six filter
// names carry over. The caller uses location.replace, so the bare form never
// enters browser history.
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
