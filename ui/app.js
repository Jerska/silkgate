// app.js — the wiring: fetch and EventSource on one side, the table on the other.
// Boot is /api/sessions → /api/events → EventSource("/api/stream?cursor=…"), with
// the cursor handed over from history so the two views seam without a gap; the
// overlap a record can land in is deduped by store.js on (id, decision). Filters
// live in location.hash, so a filtered view is a shareable URL and future panes
// can hang off the same routing. All record data reaches the DOM as textContent.

import { newStore, fold, rowPasses, statusText,
         fmtTime, fmtBytes, fmtDur, badges } from "./store.js";

const ROW_CAP = 5000;            // newest rows kept; older ones fall off the top
const FLUSH_MS = 100;            // batch window — a package install emits hundreds
                                 // of records/s, and per-event DOM writes lock the tab
const SESSIONS_POLL_MS = 5000;
const WINDOWS = { "15m": 15 * 60e3, "1h": 3600e3, "24h": 86400e3 };

const $ = (id) => document.getElementById(id);
const controls = {
  session: $("f-session"),
  decision: $("f-decision"),
  method: $("f-method"),
  host: $("f-host"),
  window: $("f-window"),
  follow: $("f-follow"),
};
const tbody = $("rows");
const proxyState = $("proxy-state");
const rowCount = $("row-count");
const streamState = $("stream-state");

let store = newStore(ROW_CAP);
const trs = new Map();           // row id → its <tr>
const dirty = new Set();         // row ids folded since the last flush
let flushTimer = null;
let stream = null;

// --- filters in the hash -----------------------------------------------------

function syncControlsFromHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  // Assign only on change: writeHash echoes back through hashchange, and
  // rewriting an input's value mid-keystroke would throw the caret to the end.
  const set = (el, v) => { if (el.value !== v) el.value = v; };
  ensureSessionOption(p.get("session") || "");
  set(controls.session, p.get("session") || "");
  set(controls.decision, p.get("decision") || "");
  set(controls.method, p.get("method") || "");
  set(controls.host, p.get("host") || "");
  set(controls.window, WINDOWS[p.get("window")] ? p.get("window") : "all");
  controls.follow.checked = p.get("follow") !== "0";
}

function writeHash() {
  const p = new URLSearchParams();
  if (controls.session.value) p.set("session", controls.session.value);
  if (controls.decision.value) p.set("decision", controls.decision.value);
  if (controls.method.value.trim()) p.set("method", controls.method.value.trim());
  if (controls.host.value.trim()) p.set("host", controls.host.value.trim());
  if (controls.window.value !== "all") p.set("window", controls.window.value);
  if (!controls.follow.checked) p.set("follow", "0");
  location.hash = p.toString();
  applyFilters();                // hashchange stays silent when nothing changed
}

function currentFilters() {
  const w = controls.window.value;
  return {
    session: controls.session.value || null,
    decision: controls.decision.value || null,
    method: controls.method.value.trim() || null,
    host: controls.host.value.trim() || null,
    since: WINDOWS[w] ? Date.now() - WINDOWS[w] : null,
  };
}

// A session named in the hash or clicked in a row may no longer have a meta —
// the select must still be able to show it, or the filter would silently drop.
function ensureSessionOption(name) {
  if (!name) return;
  for (const o of controls.session.options) {
    if (o.value === name) return;
  }
  const opt = document.createElement("option");
  opt.value = name;
  opt.textContent = name;
  controls.session.appendChild(opt);
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
                 "click to filter by this session");
  s.dataset.session = row.session === null ? "null" : row.session;
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
    const span = document.createElement("span");
    span.className = "badge";
    span.textContent = b.text;
    if (b.title) span.title = b.title;
    actions.appendChild(span);
  }
}

function updateCounts() {
  let shown = 0;
  for (const tr of trs.values()) {
    if (!tr.hidden) shown++;
  }
  rowCount.textContent = `rows: ${shown} shown / ${trs.size} total`;
}

function applyFilters() {
  const f = currentFilters();
  for (const [id, tr] of trs) {
    const row = store.rows.get(id);          // gone between fold and flush: evicted
    tr.hidden = !row || !rowPasses(row, f);
  }
  updateCounts();
}

function scheduleFlush() {
  if (flushTimer === null) {
    flushTimer = setTimeout(flush, FLUSH_MS);
  }
}

function flush() {
  flushTimer = null;
  const f = currentFilters();
  for (const id of store.evicted.splice(0)) {
    const tr = trs.get(id);
    if (tr) {
      tr.remove();
      trs.delete(id);
    }
  }
  let lastShown = null;
  for (const id of dirty) {
    const row = store.rows.get(id);
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
  dirty.clear();
  updateCounts();
  if (controls.follow.checked && lastShown) {
    lastShown.scrollIntoView({ block: "nearest" });
  }
}

// --- data flow ---------------------------------------------------------------

async function fetchJSON(url) {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`${url}: HTTP ${resp.status}`);
  }
  return resp.json();
}

function rebuild(events) {
  store = newStore(ROW_CAP);
  dirty.clear();
  trs.clear();
  tbody.textContent = "";
  for (const rec of events) {
    if (fold(store, rec)) {
      dirty.add(rec.id);
    }
  }
  flush();
}

async function refreshSessions() {
  let data;
  try {
    data = await fetchJSON("/api/sessions");
  } catch {
    proxyState.textContent = "proxy: ? (ui server unreachable)";
    return;
  }
  const current = controls.session.value;
  while (controls.session.options.length > 2) {   // past "all" and "(unattributed)"
    controls.session.remove(2);
  }
  for (const meta of data.sessions || []) {
    if (meta && meta.name) {
      ensureSessionOption(meta.name);
    }
  }
  ensureSessionOption(current);
  controls.session.value = current;
  const p = data.proxy || {};
  if (p.running) {
    const ports = Array.isArray(p.ports) && p.ports.length
      ? ` ports ${p.ports[0]}–${p.ports[p.ports.length - 1]}` : "";
    proxyState.textContent = `proxy: running (pid ${p.pid}${ports})`;
  } else {
    proxyState.textContent = "proxy: not running";
  }
  applyFilters();                // and the time window ages rows out as it slides
}

function openStream(cursor) {
  if (stream) {
    stream.close();
  }
  const url = "/api/stream"
    + (cursor ? `?cursor=${encodeURIComponent(cursor)}` : "");
  stream = new EventSource(url);
  stream.onopen = () => { streamState.textContent = "live"; };
  stream.onerror = () => { streamState.textContent = "reconnecting…"; };
  stream.onmessage = (e) => {
    let rec;
    try {
      rec = JSON.parse(e.data);
    } catch {
      return;
    }
    if (fold(store, rec)) {
      dirty.add(rec.id);
      scheduleFlush();
    }
  };
  // A reset means the tail adopted a different position (proxy restart, stale
  // cursor, truncation): refetch history and rebuild. The stream itself stays
  // open — dedupe on (id, decision) makes the refetch/stream overlap harmless.
  // A dropped connection needs no code at all: EventSource reconnects on its
  // own and resends the last frame id as Last-Event-ID.
  stream.addEventListener("reset", async () => {
    try {
      rebuild((await fetchJSON(`/api/events?limit=${ROW_CAP}`)).events);
    } catch {
      // the next reset or reconnect retries; the stream keeps flowing meanwhile
    }
  });
}

// --- boot ----------------------------------------------------------------------

async function boot() {
  syncControlsFromHash();
  window.addEventListener("hashchange", () => {
    syncControlsFromHash();
    applyFilters();
  });
  for (const el of [controls.session, controls.decision, controls.window]) {
    el.addEventListener("change", writeHash);
  }
  for (const el of [controls.method, controls.host]) {
    el.addEventListener("input", writeHash);
  }
  controls.follow.addEventListener("change", writeHash);
  $("f-clear").addEventListener("click", () => {
    location.hash = "";
    syncControlsFromHash();
    applyFilters();
  });
  tbody.addEventListener("click", (e) => {
    const td = e.target.closest("td.session");
    if (td && td.dataset.session) {
      ensureSessionOption(td.dataset.session);
      controls.session.value = td.dataset.session;
      writeHash();
    }
  });
  await refreshSessions();
  setInterval(refreshSessions, SESSIONS_POLL_MS);
  let cursor = null;
  try {
    const hist = await fetchJSON(`/api/events?limit=${ROW_CAP}`);
    cursor = hist.cursor;
    rebuild(hist.events);
  } catch (err) {
    streamState.textContent = String(err);
  }
  openStream(cursor);
}

boot();
