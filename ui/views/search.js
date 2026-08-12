// views/search.js — global search results as one flat list grouped by source,
// each hit linking to its session's detail. The query lives in the hash
// (#/search?q=…), so a search is a shareable URL; the top-bar box just
// navigates here. Fetches once per query — refining the query refetches —
// and every state (too short, empty, no hits, endpoint missing) says so in
// words via the .state-msg pattern. Result records are trail data and reach
// the DOM only as textContent.

import { el } from "../render.js";
import { fmtTime } from "../store.js";
import { groupResults, resultLine, SEARCH_MIN_CHARS } from "../search.js";

const SEARCH_LIMIT = 200;

export function newSearchView() {
  let ctx = null;
  let root = null;
  let list, msg;
  let q = null;                    // the query the shown results answer
  let seq = 0;                     // stale responses lose to newer queries

  function state(text) {
    list.textContent = "";
    msg.textContent = text;
    msg.hidden = false;
  }

  function renderResults(payload) {
    list.textContent = "";
    const groups = groupResults(payload.results);
    let total = 0;
    for (const [source, results] of groups) {
      total += results.length;
      const box = el("section", { class: "search-group" },
        el("h2", null, `${source} — ${results.length}`));
      for (const r of results) {
        const line = resultLine(r);
        const where = line.session === null
          ? el("span", { class: "search-session" }, "(unattributed)")
          : el("a", { href: "#/session/" + encodeURIComponent(line.session),
                      class: "search-session" }, line.session);
        box.append(el("div", { class: "search-hit" },
          el("span", { class: "num search-time", title: line.ts ?? "" },
             fmtTime(line.ts)),
          where,
          el("span", { class: "search-text" }, line.text)));
      }
      list.append(box);
    }
    if (total === 0) {
      state(`no matches for “${q}”`);
      return;
    }
    msg.hidden = true;
    if (payload.truncated) {
      list.append(el("p", { class: "state-msg" },
                     "more matches exist — narrow the query"));
    }
  }

  async function run() {
    if (q.length < SEARCH_MIN_CHARS) {
      state(q.length === 0
            ? "type a query — audit, capture and journal trails are searched"
            : `type at least ${SEARCH_MIN_CHARS} characters`);
      return;
    }
    const mine = ++seq;
    state("searching…");
    let payload;
    try {
      const resp = await fetch(`/api/search?q=${encodeURIComponent(q)}`
                               + `&limit=${SEARCH_LIMIT}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      payload = await resp.json();
    } catch (err) {
      if (mine === seq) {
        state(`search not available yet — /api/search lands with the backend`
              + ` (${err.message})`);
      }
      return;
    }
    if (mine === seq) renderResults(payload);
  }

  function mount(host, appCtx, route) {
    ctx = appCtx;
    list = el("div", { class: "search-results" });
    msg = el("p", { class: "state-msg" });
    root = el("section", { class: "search" }, list, msg);
    host.appendChild(root);
    q = (route.q ?? "").trim();
    run();
  }

  function unmount() {
    root?.remove();
    root = null;
  }

  function onRoute(route) {
    const next = (route.q ?? "").trim();
    if (next !== q) {
      q = next;
      run();
    }
  }

  function onFlush() {}            // results are a snapshot, not a feed

  function rebuild() {}

  return { mount, unmount, onFlush, onRoute, rebuild };
}
