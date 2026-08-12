// views/overview.js — one card per session, sorted by how much attention it
// needs. Triage is a pure function over what the folds already know (tallies,
// capture, session metas), so the interesting part is testable without a DOM.
//
// Update discipline, in order of cost: the grid REBUILDS only when the set of
// sessions changes; a dirty card gets its text nodes rewritten; the 1 s ticker
// only re-derives idle labels (and the dot/order when the passage of time
// alone changed a state). Cards never rebuild on a tick.

import { el, statusDot, meterBar, sparkline, fmtTokens, fmtCost } from "../render.js";
import { fmtCpuPct, fmtMiB } from "../metrics.js";
import { sessionTotals } from "../capture.js";
import { estimateCost, contextWindow } from "../pricing.js";
import { newControlBar } from "../controls.js";

const WORKING_MS = 60_000;       // egress this recent reads as "working"
const OPEN_TURN_MS = 300_000;    // an open turn keeps "working" through a lull —
                                 // a slow generation emits nothing for a while
const WAITING_MS = 180_000;      // "idle" hardens into "waiting" here
const STUCK_MS = 600_000;
const DENY_STORM = 5;            // denies per minute; five reads as a loop, not a typo
const DENY_WINDOW_MS = 60_000;

export function fmtAge(ms) {
  if (ms == null || !Number.isFinite(ms)) return "?";
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

// The triage vocabulary, ranked by who needs eyes first. The rank ORDER is the
// grid's sort contract: working > deny-storm > waiting > stuck > done/archived.
// Classification precedence differs from sort in one spot: a deny storm IS
// egress, so it must be recognized before "working" or it could never exist.
export function triage({ archived = false, lastRc = null, lastActivity = null,
                         openTurn = false, denyBurst = 0, now }) {
  if (archived) {
    return { state: "archived", rank: 6, label: "archived", pulse: false };
  }
  const idle = lastActivity == null ? null : Math.max(0, now - lastActivity);
  if (denyBurst >= DENY_STORM) {
    return { state: "deny-storm", rank: 1,
             label: `deny storm — ${denyBurst} in 60s`, pulse: true };
  }
  if (idle !== null
      && (idle < WORKING_MS || (openTurn && idle < OPEN_TURN_MS))) {
    return { state: "working", rank: 0, label: "working", pulse: true };
  }
  if (lastRc != null && lastRc !== 0) {
    return { state: "stuck", rank: 4, label: `stuck — exit ${lastRc}`, pulse: false };
  }
  if (idle === null) {
    return { state: "waiting", rank: 2, label: "no activity yet", pulse: false };
  }
  if (idle >= STUCK_MS) {
    return lastRc === 0
      ? { state: "done", rank: 5, label: "done", pulse: false }
      : { state: "stuck", rank: 4, label: `stuck ${fmtAge(idle)}`, pulse: false };
  }
  const label = idle < WAITING_MS ? `idle ${fmtAge(idle)}` : `waiting ${fmtAge(idle)}`;
  return { state: "waiting", rank: idle < WAITING_MS ? 2 : 3, label, pulse: false };
}

export function newOverviewView() {
  let ctx = null;
  let root = null;
  let grid, msg;
  let ticker = null;
  let setKey = null;               // which session set the grid was built for
  const cards = new Map();         // ident → card
  const denyTs = new Map();        // session → recent deny stamps (epoch ms)
  const denyCounted = new Set();   // deny row ids already stamped

  // --- deny-storm bookkeeping ---------------------------------------------------

  function stampDeny(session, ts) {
    const t = Date.parse(ts || "");
    const at = Number.isNaN(t) ? Date.now() : t;
    if (Date.now() - at > DENY_WINDOW_MS) return;    // history replay, already old
    let list = denyTs.get(session);
    if (!list) {
      list = [];
      denyTs.set(session, list);
    }
    list.push(at);
  }

  function denyBurst(session, now) {
    const list = denyTs.get(session);
    if (!list) return 0;
    while (list.length && now - list[0] > DENY_WINDOW_MS) {
      list.shift();
    }
    return list.length;
  }

  // denyBurst prunes on read, but only sessions with cards are ever read: a
  // deny loop attributed to null or to a name absent from /api/sessions would
  // stamp forever. The 1 s tick sweeps every list and drops the empty ones.
  function pruneDenies(now) {
    for (const [session, list] of denyTs) {
      while (list.length && now - list[0] > DENY_WINDOW_MS) {
        list.shift();
      }
      if (list.length === 0) denyTs.delete(session);
    }
  }

  function seedDenies() {
    denyTs.clear();
    denyCounted.clear();
    for (const [id, row] of ctx.store.rows) {
      if (row.decision === "deny") {
        denyCounted.add(id);
        stampDeny(row.session, row.ts);
      }
    }
  }

  function trackDenies(rowIds) {
    for (const id of rowIds) {
      const row = ctx.store.rows.get(id);
      if (!row || row.decision !== "deny" || denyCounted.has(id)) continue;
      denyCounted.add(id);
      stampDeny(row.session, row.ts);
    }
    while (denyCounted.size > 4096) {              // ids, not storms: bounded memory
      denyCounted.delete(denyCounted.keys().next().value);
    }
  }

  // --- what a card knows --------------------------------------------------------

  // Live metas first, then the archived list; an ident appearing in both keeps
  // its live entry. `session` is the name data is keyed under; `ident` is the
  // link target (the sid, for archived sessions).
  function entries() {
    const out = new Map();
    for (const meta of ctx.sessions?.sessions ?? []) {
      if (meta && meta.name) {
        out.set(meta.name, { ident: meta.name, session: meta.name, meta,
                             archived: meta.state === "archived" });
      }
    }
    for (const meta of ctx.sessions?.archived ?? []) {
      const ident = meta?.sid ?? meta?.name;
      if (ident != null && !out.has(String(ident))) {
        out.set(String(ident), { ident: String(ident),
                                 session: meta.name ?? String(ident), meta,
                                 archived: true });
      }
    }
    return [...out.values()];
  }

  function cardTriage(card, now) {
    const tally = ctx.store.tallies.get(card.session);
    const totals = card.totals;
    let last = null;
    for (const ts of [tally?.lastTs, totals?.lastTs, card.meta?.created]) {
      const t = Date.parse(ts || "");
      if (!Number.isNaN(t) && (last === null || t > last)) last = t;
    }
    return triage({
      archived: card.archived,
      lastRc: card.meta?.last_rc ?? null,        // absent today; lands with the backend
      lastActivity: last,
      openTurn: (totals?.openTurns ?? 0) > 0,
      denyBurst: denyBurst(card.session, now),
      now,
    });
  }

  // --- rendering ------------------------------------------------------------------

  // The card is a div with a stretched link over it — buttons cannot legally
  // nest inside an anchor, so the link covers the card via CSS and the control
  // bar sits above it on its own z-index.
  function createCard(entry) {
    const nodes = {
      dot: statusDot("waiting"),
      label: el("span", { class: "card-label" }, "…"),
      deny: el("span", { class: "num" }, ""),
      req: el("span", { class: "num" }, ""),
      age: el("span", { class: "num" }, ""),
      met: el("div", { class: "card-metrics" }),
      usage: el("div", { class: "card-usage" }),
      gauge: el("div", { class: "card-gauge" }),
    };
    nodes.met.hidden = true;
    nodes.usage.hidden = true;
    nodes.gauge.hidden = true;
    const card = { ...entry, nodes, rank: 99, totals: null, ctl: null };
    card.ctl = newControlBar({
      ident: entry.ident,
      getMeta: () => (card.archived ? { state: "archived" } : card.meta),
      onChanged: () => ctx.refreshSessions(),
    });
    card.root = el("div", { class: "card" },
      el("a", { class: "card-link",
                href: "#/session/" + encodeURIComponent(entry.ident) },
        el("div", { class: "card-head" },
          nodes.dot,
          el("span", { class: "card-name" }, entry.session),
          entry.meta?.branch
            ? el("span", { class: "card-branch" }, String(entry.meta.branch)) : null),
        el("div", { class: "card-status" }, nodes.label)),
      el("div", { class: "card-counters" }, nodes.deny, nodes.req, nodes.age),
      nodes.met, nodes.usage, nodes.gauge,
      el("div", { class: "card-ctl" }, card.ctl.root));
    return card;
  }

  // CPU/RAM numbers with their 30-sample sparklines; hidden until /api/metrics
  // answers for this session. Memory is VMM RSS — the label keeps saying so.
  function updateCardMetrics(card) {
    const rows = ctx.metrics?.metrics;
    const m = Array.isArray(rows)
      ? rows.find((r) => r?.session === card.session) : null;
    card.nodes.met.textContent = "";
    if (!m) {
      card.nodes.met.hidden = true;
      return;
    }
    const h = ctx.metricsHistory?.bySession.get(card.session);
    card.nodes.met.append(
      el("span", { class: "num" }, `cpu ${fmtCpuPct(m.cpu_percent) ?? "—"}`),
      h ? sparkline(h.cpu, { unit: "%", times: h.ts, fmt: fmtCpuPct }) : null,
      el("span", { class: "num", title: "VMM RSS" },
         `mem ${fmtMiB(m.memory_bytes) ?? "—"}`),
      h ? sparkline(h.mem, { unit: "MiB", times: h.ts, fmt: fmtMiB }) : null);
    card.nodes.met.hidden = false;
  }

  // The cross-card scale for the usage meter: a bar means "this session's share
  // of everything captured", so bars are comparable across the grid.
  function totalTokens() {
    let sum = 0;
    for (const card of cards.values()) {
      const t = card.totals;
      if (t) sum += t.input + t.output + t.cacheRead + t.cacheWrite;
    }
    return sum;
  }

  function updateStatus(card, now) {
    const s = cardTriage(card, now);
    if (s.label !== card.nodes.label.textContent) {
      card.nodes.label.textContent = s.label;
    }
    const dotClass = "dot " + s.state + (s.pulse ? " pulse" : "");
    if (card.nodes.dot.className !== dotClass) {
      card.nodes.dot.className = dotClass;
    }
    card.rank = s.rank;
    const created = Date.parse(card.meta?.created || "");
    card.nodes.age.textContent =
      Number.isNaN(created) ? "" : "age " + fmtAge(now - created);
  }

  function updateCard(card, now) {
    const S = ctx.capture?.sessions.get(card.session);
    card.totals = S ? sessionTotals(S) : null;
    const tally = ctx.store.tallies.get(card.session);
    const denies = tally?.denies ?? 0;
    card.nodes.deny.textContent = `deny ${denies}`;
    card.nodes.deny.className = "num" + (denies > 0 ? " deny-hot" : "");
    card.nodes.req.textContent = `req ${tally?.requests ?? 0}`;
    updateCardMetrics(card);
    updateUsage(card);
    updateStatus(card, now);
    card.ctl.sync();
  }

  function updateUsage(card) {
    const t = card.totals;
    if (!t || t.turns === 0) {
      card.nodes.usage.hidden = true;
      card.nodes.gauge.hidden = true;
      return;
    }
    // Cost only when every model in the mix is priced: a partial sum would
    // read as the whole. Tokens always show.
    let cost = 0;
    for (const [model, tk] of t.byModel) {
      const c = estimateCost(model, tk);
      if (c === null) {
        cost = null;
        break;
      }
      cost += c;
    }
    const tokens = t.input + t.output + t.cacheRead + t.cacheWrite;
    card.nodes.usage.textContent = "";
    card.nodes.usage.append(
      el("span", { class: "num" },
         `${fmtTokens(t.input + t.cacheRead + t.cacheWrite)} in · `
         + `${fmtTokens(t.output)} out · ${fmtCost(cost)}`),
      meterBar(totalTokens() ? tokens / totalTokens() : 0));
    card.nodes.usage.hidden = false;
    const win = t.lastContext ? contextWindow(t.lastContext.model) : null;
    if (win == null) {
      card.nodes.gauge.hidden = true;            // unknown model: no gauge, no guess
    } else {
      const frac = t.lastContext.tokens / win;
      card.nodes.gauge.textContent = "";
      card.nodes.gauge.append(
        el("span", { class: "num" },
           `ctx ${fmtTokens(t.lastContext.tokens)} / ${fmtTokens(win)}`),
        meterBar(frac));
      card.nodes.gauge.hidden = false;
    }
  }

  function reorder() {
    const order = [...cards.values()].sort((a, b) =>
      a.rank - b.rank || (a.session < b.session ? -1 : a.session > b.session ? 1 : 0));
    let moved = false;
    for (let i = 0; i < order.length; i++) {
      if (grid.children[i] !== order[i].root) {
        moved = true;
        break;
      }
    }
    if (moved) {
      for (const card of order) {
        grid.appendChild(card.root);             // append moves; nothing rebuilds
      }
    }
  }

  // Reconcile cards with /api/sessions. Only a changed session SET rebuilds the
  // grid; otherwise every card gets a text refresh (metas may have moved).
  function syncCards() {
    const now = Date.now();
    const list = entries();
    const key = list.map((e) => e.ident).sort().join(" ");
    if (key !== setKey) {
      setKey = key;
      cards.clear();
      grid.textContent = "";
      for (const entry of list) {
        const card = createCard(entry);
        cards.set(entry.ident, card);
        grid.appendChild(card.root);
      }
    } else {
      for (const entry of list) {
        const card = cards.get(entry.ident);
        card.meta = entry.meta;
        card.archived = entry.archived;
      }
    }
    for (const card of cards.values()) {
      updateCard(card, now);
    }
    reorder();
    msg.hidden = cards.size > 0;
    grid.hidden = cards.size === 0;
  }

  // --- the view interface -----------------------------------------------------

  function mount(host, appCtx) {
    ctx = appCtx;
    grid = el("div", { class: "grid" });
    msg = el("p", { class: "state-msg" },
             "no sessions — `silkgate up <name>` starts one");
    root = el("section", { class: "overview" }, grid, msg);
    seedDenies();
    syncCards();
    host.appendChild(root);
    // The 1 s tick re-derives what only time changes: idle labels, and the
    // dot/order on the state flips those labels cross.
    ticker = setInterval(() => {
      const now = Date.now();
      pruneDenies(now);
      for (const card of cards.values()) {
        updateStatus(card, now);
      }
      reorder();
    }, 1000);
  }

  function unmount() {
    clearInterval(ticker);
    ticker = null;
    root?.remove();
    root = null;
    cards.clear();
    setKey = null;
  }

  function onRoute() {}            // #/ has no params

  function onFlush({ rows, sessions, polled }) {
    trackDenies(rows);
    if (polled) {
      syncCards();                 // set/meta changes, and every card re-derives
      return;
    }
    const now = Date.now();
    let touched = false;
    for (const name of sessions) {
      for (const card of cards.values()) {
        if (card.session === name) {
          updateCard(card, now);
          touched = true;
        }
      }
    }
    // Deny stamps change triage without touching a tally's session set.
    for (const id of rows) {
      const session = ctx.store.rows.get(id)?.session;
      for (const card of cards.values()) {
        if (card.session === session) {
          updateStatus(card, now);
          touched = true;
        }
      }
    }
    if (touched) reorder();
  }

  function rebuild() {
    seedDenies();
    setKey = null;                 // force the grid to rebuild from scratch
    syncCards();
  }

  // The overview consumes metrics (cards show CPU/RAM + sparklines), so the
  // 2 s poll runs while it is mounted.
  return { mount, unmount, onFlush, onRoute, rebuild, wantsMetrics: true };
}
