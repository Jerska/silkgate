// views/calls.js — the audit table as a mountable view: the pre-shell app's
// table, filters, follow mode and "(unattributed)" handling, extracted whole
// rather than rewritten. Two homes share this component: #/traffic mounts it
// with filters living in the route (a filtered view stays a shareable URL),
// and the session detail's calls tab mounts it with `fixedSession` pinning the
// session filter and keeping the rest as local state — a tab is not a place,
// so its knobs do not belong in the hash.
//
// The app owns the store, the flush clock and the polls; this view owns the
// <tr> per row id and which of them a filter admits. All record data reaches
// the DOM as textContent.

import { rowPasses, sessionToFilter, statusText, fmtTime, fmtBytes, fmtDur,
         badges } from "../store.js";
import { el } from "../render.js";

const WINDOWS = { "15m": 15 * 60e3, "1h": 3600e3, "24h": 86400e3 };

const COLUMNS = ["TIME", "SESSION", "DECISION", "METHOD", "HOST",
                 "PATH", "STATUS", "DUR", "BYTES", "ACTIONS"];

export function newCallsView({ fixedSession = null } = {}) {
  let ctx = null;
  let root = null;
  let tbody, rowCount, stateMsg;
  const controls = {};
  const trs = new Map();           // row id → its <tr>

  // --- filters ---------------------------------------------------------------

  function currentFilters() {
    const w = controls.window.value;
    return {
      // Filter space, not names: a pinned session named "null" must not read
      // as the unattributed sentinel.
      session: fixedSession != null ? sessionToFilter(fixedSession)
        : (controls.session.value || null),
      decision: controls.decision.value || null,
      method: controls.method.value.trim() || null,
      host: controls.host.value.trim() || null,
      since: WINDOWS[w] ? Date.now() - WINDOWS[w] : null,
    };
  }

  // Controls → route (or, pinned to a session, controls → table directly).
  // applyFilters always runs here: hashchange stays silent when nothing changed.
  // Keystroke-driven callers pass replace, so typing a filter rewrites the
  // current history entry instead of pushing one per character.
  function writeFilters({ replace = false } = {}) {
    if (!fixedSession) {
      const params = {};
      if (controls.session.value) params.session = controls.session.value;
      if (controls.decision.value) params.decision = controls.decision.value;
      if (controls.method.value.trim()) params.method = controls.method.value.trim();
      if (controls.host.value.trim()) params.host = controls.host.value.trim();
      if (controls.window.value !== "all") params.window = controls.window.value;
      if (!controls.follow.checked) params.follow = "0";
      ctx.navigate({ view: "traffic", params }, { replace });
    }
    applyFilters();
  }

  // Route → controls. Assign only on change: navigate echoes back through
  // hashchange, and rewriting an input's value mid-keystroke would throw the
  // caret to the end.
  function syncControls(params) {
    const p = params || {};
    const set = (input, v) => { if (input.value !== v) input.value = v; };
    ensureSessionOption(p.session || "");
    set(controls.session, p.session || "");
    set(controls.decision, p.decision || "");
    set(controls.method, p.method || "");
    set(controls.host, p.host || "");
    set(controls.window, WINDOWS[p.window] ? p.window : "all");
    controls.follow.checked = p.follow !== "0";
  }

  // A session named in the route or clicked in a row may no longer have a
  // meta — the select must still be able to show it, or the filter would
  // silently drop.
  function ensureSessionOption(name) {
    if (!name || fixedSession) return;
    for (const o of controls.session.options) {
      if (o.value === name) return;
    }
    controls.session.appendChild(el("option", { value: name }, name));
  }

  // The select's options track /api/sessions, past the two fixed entries.
  function refreshSessionOptions() {
    if (fixedSession) return;
    const current = controls.session.value;
    while (controls.session.options.length > 2) {  // past "all" and "(unattributed)"
      controls.session.remove(2);
    }
    for (const meta of ctx.sessions?.sessions || []) {
      if (meta && meta.name) ensureSessionOption(sessionToFilter(meta.name));
    }
    ensureSessionOption(current);
    controls.session.value = current;
  }

  // --- rendering ---------------------------------------------------------------

  function cell(tr, text, cls, title) {
    const td = document.createElement("td");
    td.textContent = text ?? "";
    if (cls) td.className = cls;
    if (title) td.title = title;
    tr.appendChild(td);
    return td;
  }

  function renderRow(row, tr) {
    tr.className = row.decision === "deny" ? "deny" : row.state;
    tr.textContent = "";
    cell(tr, fmtTime(row.ts), "time", row.ts || "");
    const s = cell(tr, row.session === null ? "·" : row.session, "session",
                   fixedSession ? "" : "click to filter by this session");
    s.dataset.session = row.session === null ? "null" : sessionToFilter(row.session);
    cell(tr, row.decision, "decision", row.reason || "");
    cell(tr, row.method, "method");
    cell(tr, row.host + (row.port != null ? ":" + row.port : ""), "host",
         row.listen_port != null ? `via listener :${row.listen_port}` : "");
    cell(tr, row.path, "path", row.path || "");
    cell(tr, statusText(row), "status");
    cell(tr, fmtDur(row.duration_ms), "dur");
    cell(tr, row.request_bytes == null && row.response_bytes == null ? ""
         : `${fmtBytes(row.request_bytes)}/${fmtBytes(row.response_bytes)}`, "bytes",
         "request/response bytes");
    const actions = cell(tr, "", "actions");
    for (const b of badges(row)) {
      actions.appendChild(el("span", { class: "badge", title: b.title || null }, b.text));
    }
  }

  function updateCounts() {
    let shown = 0;
    for (const tr of trs.values()) {
      if (!tr.hidden) shown++;
    }
    rowCount.textContent = `rows: ${shown} shown / ${trs.size} total`;
    if (trs.size === 0) {
      stateMsg.textContent = "no traffic yet — allowed and denied flows appear"
        + " here as they happen";
      stateMsg.hidden = false;
    } else if (shown === 0) {
      stateMsg.textContent = "no rows match the filters";
      stateMsg.hidden = false;
    } else {
      stateMsg.hidden = true;
    }
  }

  function applyFilters() {
    const f = currentFilters();
    for (const [id, tr] of trs) {
      const row = ctx.store.rows.get(id);   // gone between fold and flush: evicted
      tr.hidden = !row || !rowPasses(row, f);
    }
    updateCounts();
  }

  function follow(lastShown) {
    if (controls.follow.checked && lastShown) {
      lastShown.scrollIntoView({ block: "nearest" });
    }
  }

  // --- the view interface ------------------------------------------------------

  function mount(host, appCtx, route) {
    ctx = appCtx;
    controls.session = el("select", null,
      el("option", { value: "" }, "all"),
      el("option", { value: "null" }, "(unattributed)"));
    controls.decision = el("select", null,
      el("option", { value: "" }, "all"),
      el("option", { value: "allow" }, "allow"),
      el("option", { value: "deny" }, "deny"));
    controls.method = el("input", { size: "8", placeholder: "GET" });
    controls.host = el("input", { size: "20", placeholder: "substring" });
    controls.window = el("select", null,
      el("option", { value: "all" }, "all"),
      el("option", { value: "15m" }, "15m"),
      el("option", { value: "1h" }, "1h"),
      el("option", { value: "24h" }, "24h"));
    controls.follow = el("input", { type: "checkbox" });
    const clear = el("button", { type: "button" }, "clear");

    tbody = el("tbody");
    rowCount = el("span", { class: "count" });
    stateMsg = el("p", { class: "state-msg" });
    stateMsg.hidden = true;

    root = el("section", { class: "calls" + (fixedSession ? " fixed" : "") },
      el("div", { class: "toolbar" },
        fixedSession ? null : el("label", null, "session ", controls.session),
        el("label", null, "decision ", controls.decision),
        el("label", null, "method ", controls.method),
        el("label", null, "host ", controls.host),
        el("label", null, "window ", controls.window),
        el("label", null, controls.follow, " follow"),
        clear,
        rowCount),
      el("div", { class: "table-wrap" },
        el("table", null,
          el("thead", null, el("tr", null, ...COLUMNS.map((c) => el("th", null, c)))),
          tbody)),
      stateMsg);

    for (const c of [controls.session, controls.decision, controls.window]) {
      c.addEventListener("change", () => writeFilters());
    }
    for (const c of [controls.method, controls.host]) {
      c.addEventListener("input", () => writeFilters({ replace: true }));
    }
    controls.follow.addEventListener("change", () => writeFilters());
    clear.addEventListener("click", () => {
      if (fixedSession) {
        syncControls({});
        applyFilters();
      } else {
        ctx.navigate({ view: "traffic", params: {} });
        syncControls({});          // hashchange stays silent when nothing changed
        applyFilters();
      }
    });
    if (!fixedSession) {
      tbody.addEventListener("click", (e) => {
        const td = e.target.closest("td.session");
        if (td && td.dataset.session) {
          ensureSessionOption(td.dataset.session);
          controls.session.value = td.dataset.session;
          writeFilters();
        }
      });
    }

    syncControls(route?.params);
    refreshSessionOptions();
    host.appendChild(root);
    rebuild();
  }

  function unmount() {
    root?.remove();
    root = null;
    trs.clear();
  }

  function onRoute(route) {
    if (fixedSession) return;      // pinned mode has no route-borne filters
    syncControls(route.params);
    applyFilters();
  }

  // One batch of folded changes: evicted rows leave, dirty rows render, and a
  // sessions poll re-applies the filters so the sliding time window ages rows
  // out even when nothing new arrived.
  function onFlush({ rows, evicted, polled }) {
    for (const id of evicted || []) {
      const tr = trs.get(id);
      if (tr) {
        tr.remove();
        trs.delete(id);
      }
    }
    const f = currentFilters();
    let lastShown = null;
    for (const id of rows) {
      const row = ctx.store.rows.get(id);
      if (!row) continue;          // evicted before it ever reached the table
      let tr = trs.get(id);
      if (!tr) {
        tr = document.createElement("tr");
        trs.set(id, tr);
        tbody.appendChild(tr);     // records arrive in trail order: append is sort
      }
      renderRow(row, tr);
      tr.hidden = !rowPasses(row, f);
      if (!tr.hidden) lastShown = tr;
    }
    if (polled) {
      refreshSessionOptions();
      applyFilters();
    } else {
      updateCounts();
    }
    follow(lastShown);
  }

  // The store was replaced under us (stream reset, view mount): re-render
  // everything it now holds. Store iteration order is trail order.
  function rebuild() {
    trs.clear();
    tbody.textContent = "";
    const f = currentFilters();
    let lastShown = null;
    for (const [id, row] of ctx.store.rows) {
      const tr = document.createElement("tr");
      trs.set(id, tr);
      tbody.appendChild(tr);
      renderRow(row, tr);
      tr.hidden = !rowPasses(row, f);
      if (!tr.hidden) lastShown = tr;
    }
    updateCounts();
    follow(lastShown);
  }

  return { mount, unmount, onFlush, onRoute, rebuild };
}
