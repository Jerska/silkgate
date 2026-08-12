// views/session.js — one session up close: a header that triages like the
// overview card, then tabs. Wave 1 fills `activity` (the turn feed folded by
// capture.js) and `calls` (the calls component pinned to this session);
// `config` names itself and waits for wave 2.
//
// The feed renders whole blocks — capture emits blocks complete, so there is
// no token-by-token churn — and re-renders only turns whose fold `rev` moved,
// which is what keeps an open <details> open while other turns stream past.
// LLM output is attacker-influenced text and reaches the DOM only as text
// nodes; tool input renders as JSON.stringify inside a <pre>.

import { el, statusDot, fmtTokens } from "../render.js";
import { fmtBytes, fmtDur } from "../store.js";
import { sessionTotals } from "../capture.js";
import { triage, fmtAge } from "./overview.js";
import { newCallsView } from "./calls.js";

const TABS = ["activity", "calls", "config"];

export function newSessionView() {
  let ctx = null;
  let root = null;
  let ident = null;
  let session = null;              // the name data is keyed under
  let tab = null;
  let ticker = null;
  const head = {};                 // dot, label, branch, metrics
  let tabBar, tabBody;

  // The active tab's teardown state: a mounted calls view, or a feed.
  let callsView = null;
  let feed = null;                 // {list, strip, execSel, execs, selected, nodes}

  function meta() {
    for (const m of ctx.sessions?.sessions ?? []) {
      if (m?.name === session) return m;
    }
    for (const m of ctx.sessions?.archived ?? []) {
      if (String(m?.sid ?? m?.name) === ident) return m;
    }
    return null;
  }

  // --- header ---------------------------------------------------------------

  function updateHead() {
    const m = meta();
    const now = Date.now();
    const S = ctx.capture?.sessions.get(session);
    const totals = S ? sessionTotals(S) : null;
    const tally = ctx.store.tallies.get(session);
    let last = null;
    for (const ts of [tally?.lastTs, totals?.lastTs, m?.created]) {
      const t = Date.parse(ts || "");
      if (!Number.isNaN(t) && (last === null || t > last)) last = t;
    }
    const s = triage({
      archived: m ? m.state === "archived" : false,
      lastRc: m?.last_rc ?? null,
      lastActivity: last,
      openTurn: (totals?.openTurns ?? 0) > 0,
      denyBurst: 0,                // the overview watches for storms; here the
      now,                        // feed itself is the evidence
    });
    head.dot.className = "dot " + s.state + (s.pulse ? " pulse" : "");
    head.label.textContent = m === null && !tally && !totals?.turns
      ? "unknown session" : s.label;
    head.branch.textContent = m?.branch ? String(m.branch) : "";
    updateMetrics();
  }

  function updateMetrics() {
    const rows = ctx.metrics?.metrics;
    const m = Array.isArray(rows) ? rows.find((r) => r?.session === session) : null;
    if (!m) {
      head.metrics.textContent = "";   // not available yet — the poll may land it
      return;
    }
    const parts = [];
    if (m.cpu_percent != null) parts.push(`cpu ${m.cpu_percent}%`);
    if (m.memory_bytes != null) {
      const limit = m.memory_limit_bytes != null
        ? `/${fmtBytes(m.memory_limit_bytes)}` : "";
      parts.push(`mem ${fmtBytes(m.memory_bytes)}${limit} (VMM RSS)`);
    }
    if (m.net_rx_bytes != null || m.net_tx_bytes != null) {
      parts.push(`net ↓${fmtBytes(m.net_rx_bytes ?? 0)} ↑${fmtBytes(m.net_tx_bytes ?? 0)}`);
    }
    if (m.disk_read_bytes != null || m.disk_write_bytes != null) {
      parts.push(`disk r${fmtBytes(m.disk_read_bytes ?? 0)}`
                 + ` w${fmtBytes(m.disk_write_bytes ?? 0)}`);
    }
    if (m.uptime_secs != null) parts.push(`up ${fmtAge(m.uptime_secs * 1000)}`);
    head.metrics.textContent = parts.join(" · ");
  }

  // --- the activity feed ------------------------------------------------------

  function execLabel(exec) {
    return exec === null ? "(unattributed)" : String(exec);
  }

  function scopeBuckets() {
    const S = ctx.capture?.sessions.get(session);
    if (!S) return [];
    const all = [...S.execs.entries()];
    if (feed.selected === "") return all;
    const i = Number(feed.selected);
    return all[i] ? [all[i]] : all;
  }

  function renderTurn(t) {
    const tok = `in ${fmtTokens(t.input_tokens)} · cache r ${fmtTokens(
      t.cache_read_input_tokens)} w ${fmtTokens(t.cache_creation_input_tokens)}`
      + (t.open ? "" : ` · out ${fmtTokens(t.output_tokens)}`);
    const timing = [t.ttfb_ms != null ? `ttfb ${fmtDur(t.ttfb_ms)}` : null,
                    t.duration_ms != null ? fmtDur(t.duration_ms) : null,
                    t.open ? null : (t.stop_reason ?? "?")]
      .filter(Boolean).join(" · ");
    const node = el("article", { class: "turn" + (t.open ? " open" : "") },
      el("header", { class: "turn-head" },
        el("span", { class: "turn-model" }, t.model ?? "model?"),
        el("span", { class: "num" }, tok),
        el("span", { class: "num turn-timing" }, timing)));
    for (const idx of [...t.blocks.keys()].sort((a, b) => a - b)) {
      const b = t.blocks.get(idx);
      if (b.dropped) {
        node.append(el("div", { class: "block-note" },
                       `(${b.type ?? "block"} ${idx}: text evicted to stay under`
                       + " the memory cap)"));
      } else if (b.type === "tool_use") {
        node.append(el("details", { class: "block-tool" },
          el("summary", null, `tool: ${b.tool_name ?? "?"}`
             + (b.truncated ? " (truncated)" : "")),
          el("pre", null, JSON.stringify(b.tool_input, null, 2) ?? "")));
      } else {
        node.append(el("div", { class: "block-text" }, b.text ?? "",
                       b.truncated ? el("span", { class: "block-note" },
                                        " (truncated)") : null));
      }
    }
    if (t.error) {
      node.append(el("div", { class: "turn-error" }, `error: ${t.error}`));
    }
    if (t.incomplete) {
      node.append(el("div", { class: "turn-error" }, "incomplete turn"));
    }
    if (t.open) {
      node.append(el("span", { class: "caret" }, "▌"));
    }
    return node;
  }

  function renderFeed() {
    if (!feed) return;
    const S = ctx.capture?.sessions.get(session);
    const buckets = S ? [...S.execs.entries()] : [];

    // The per-exec selector appears once there is something to choose between.
    // Options are indexed, not exec-string-valued: exec ids are record data.
    const names = buckets.map(([exec]) => execLabel(exec)).join(" ");
    if (names !== feed.execs) {
      feed.execs = names;
      feed.execSel.textContent = "";
      feed.execSel.append(el("option", { value: "" }, "all execs"));
      buckets.forEach(([exec], i) => {
        feed.execSel.append(el("option", { value: String(i) }, execLabel(exec)));
      });
      feed.selected = "";
      feed.execSel.value = "";
    }
    feed.execSel.parentElement.hidden = buckets.length < 2;

    const scope = scopeBuckets();

    // Errors and sightings, small enough to rebuild wholesale.
    feed.strip.textContent = "";
    for (const [, bucket] of scope) {
      for (const s of bucket.sightings.values()) {
        feed.strip.append(el("div", { class: "sighting" },
          `secret sighting: ${s.pattern}`
          + (s.index != null ? ` (block ${s.index})` : "")));
      }
      for (const [id, e] of bucket.errors) {
        feed.strip.append(el("div", { class: "capture-err" },
          `capture error on ${id}: ${e.reason}`));
      }
    }

    // Turns across the scope, oldest first; only changed revs re-render.
    const want = [];
    for (const [exec, bucket] of scope) {
      for (const t of bucket.turns.values()) {
        want.push({ key: execLabel(exec) + " " + t.id, t });
      }
    }
    want.sort((a, b) => (Date.parse(a.t.ts || "") || 0)
                        - (Date.parse(b.t.ts || "") || 0));
    const seen = new Set();
    for (const { key, t } of want) {
      seen.add(key);
      const have = feed.nodes.get(key);
      if (!have || have.rev !== t.rev) {
        const node = renderTurn(t);
        if (have) have.node.replaceWith(node);
        feed.nodes.set(key, { node, rev: t.rev });
      }
    }
    for (const [key, have] of feed.nodes) {
      if (!seen.has(key)) {                      // evicted turns leave the feed
        have.node.remove();
        feed.nodes.delete(key);
      }
    }
    // Append in order: moving a node keeps its state (an open <details> stays open).
    let cursor = 0;
    for (const { key } of want) {
      const node = feed.nodes.get(key).node;
      if (feed.list.children[cursor] !== node) {
        feed.list.insertBefore(node, feed.list.children[cursor] ?? null);
      }
      cursor++;
    }

    if (want.length === 0 && feed.strip.childElementCount === 0) {
      feed.msg.textContent = ctx.captureState === "live"
        ? "no capture records for this session yet"
        : "capture not available yet — /api/capture lands with the backend;"
          + " the calls tab works today";
      feed.msg.hidden = false;
    } else {
      feed.msg.hidden = true;
    }
  }

  // --- tabs -------------------------------------------------------------------

  function teardownTab() {
    if (callsView) {
      callsView.unmount();
      callsView = null;
    }
    feed = null;
    tabBody.textContent = "";
  }

  function showTab(next) {
    tab = next;
    for (const a of tabBar.children) {
      if (a.dataset.tab === tab) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    teardownTab();
    if (tab === "calls") {
      callsView = newCallsView({ fixedSession: session });
      callsView.mount(tabBody, ctx);
    } else if (tab === "activity") {
      const execSel = el("select");
      execSel.addEventListener("change", () => {
        feed.selected = execSel.value;
        renderFeed();
      });
      const strip = el("div", { class: "feed-strip" });
      const list = el("div", { class: "feed" });
      const msg = el("p", { class: "state-msg" });
      msg.hidden = true;
      const picker = el("label", { class: "exec-pick" }, "exec ", execSel);
      picker.hidden = true;
      tabBody.append(el("section", { class: "activity" }, picker, strip, list, msg));
      feed = { execSel, strip, list, msg, nodes: new Map(), selected: "", execs: null };
      renderFeed();
    } else {
      tabBody.append(el("p", { class: "state-msg" },
                        `${tab} — wave 2 fills this tab`));
    }
  }

  // --- the view interface -------------------------------------------------------

  function mount(host, appCtx, route) {
    ctx = appCtx;
    ident = route.ident;
    session = ident;               // archived sids resolve to metas; data keys by name
    const m = meta();
    if (m?.name) session = m.name;

    head.dot = statusDot("waiting");
    head.label = el("span", { class: "num" }, "…");
    head.branch = el("span", { class: "session-branch" });
    head.metrics = el("span", { class: "num session-metrics" });
    tabBar = el("nav", { class: "tabs" },
      ...TABS.map((t) => el("a", { href: "#/session/" + encodeURIComponent(ident)
                                         + (t === "activity" ? "" : "?tab=" + t),
                                   dataset: { tab: t } }, t)));
    tabBody = el("div", { class: "tab-body" });
    root = el("section", { class: "session" },
      el("header", { class: "session-head" },
        el("a", { href: "#/", class: "back" }, "← overview"),
        head.dot,
        el("span", { class: "session-name" }, session),
        head.branch,
        head.label,
        head.metrics),
      tabBar,
      tabBody);
    host.appendChild(root);
    updateHead();
    showTab(route.tab);
    ticker = setInterval(updateHead, 1000);   // idle labels move with time alone
  }

  function unmount() {
    clearInterval(ticker);
    ticker = null;
    teardownTab();
    root?.remove();
    root = null;
  }

  function onRoute(route) {
    if (route.tab !== tab) {
      showTab(route.tab);
    }
  }

  function onFlush(payload) {
    if (callsView) {
      callsView.onFlush(payload);
    }
    if (payload.sessions.has(session) || payload.polled) {
      updateHead();
      if (feed) renderFeed();
    }
  }

  function rebuild() {
    updateHead();
    if (callsView) callsView.rebuild();
    if (feed) {
      feed.nodes.clear();
      feed.list.textContent = "";
      feed.execs = null;
      renderFeed();
    }
  }

  return { mount, unmount, onFlush, onRoute, rebuild, wantsMetrics: true };
}
