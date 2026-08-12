// app.js — the wiring: fetch and EventSource on one side, one mounted view on
// the other. Boot is /api/sessions → /api/events → EventSource("/api/stream?
// cursor=…"), with the cursor handed over from history so the two views seam
// without a gap; the overlap a record can land in is deduped by store.js on
// (id, decision). The hash routes between views (router.js is the grammar);
// each view implements {mount, unmount, onFlush, onRoute, rebuild} and exactly
// one is mounted at a time. Folds land in dirty sets and reach the view on one
// shared flush clock — a package install emits hundreds of records/s, and
// per-event DOM writes lock the tab. All record data reaches the DOM as
// textContent.

import { newStore, fold } from "./store.js";
import { newCapture, foldCapture } from "./capture.js";
import { newHistory, pushSamples } from "./metrics.js";
import { parseRoute, buildRoute, legacyRedirect } from "./router.js";
import { newCallsView } from "./views/calls.js";
import { newOverviewView } from "./views/overview.js";
import { newSessionView } from "./views/session.js";
import { newSearchView } from "./views/search.js";

const ROW_CAP = 5000;            // newest rows kept; older ones fall off the top
const CAPTURE_LIMIT = 2000;      // /api/capture history page
const FLUSH_MS = 100;
const SESSIONS_POLL_MS = 5000;
const METRICS_POLL_MS = 2000;    // only while a metrics-consuming view is mounted

const viewHost = document.getElementById("view");
const proxyState = document.getElementById("proxy-state");
const streamState = document.getElementById("stream-state");
const searchBox = document.getElementById("search-box");
const navLinks = {
  overview: document.getElementById("nav-overview"),
  traffic: document.getElementById("nav-traffic"),
};

// Everything a view may read, in one bag handed over at mount. `store` is
// reassigned on a stream reset, so views must reach it as ctx.store each time,
// never hold the old one.
const ctx = {
  store: newStore(ROW_CAP),
  capture: newCapture(),         // stays empty until the capture stream lands
  captureState: "unknown",       // unknown | live | unavailable
  sessions: null,                // the last /api/sessions payload, verbatim
  metrics: null,                 // the last /api/metrics payload, or null
  metricsHistory: newHistory(),  // 30-sample rings behind the sparklines
  navigate(route) { location.hash = buildRoute(route); },
  refreshSessions,               // views nudge the poll after a control POST
};

// --- flush: one clock, two dirty sets ------------------------------------------

let dirtyRows = new Set();       // row ids folded since the last flush
let dirtySessions = new Set();   // session names whose tallies/capture moved
let polled = false;              // a fresh /api/sessions payload landed
let flushTimer = null;

function scheduleFlush() {
  if (flushTimer === null) {
    flushTimer = setTimeout(flush, FLUSH_MS);
  }
}

function flush() {
  flushTimer = null;
  const payload = { rows: dirtyRows, sessions: dirtySessions,
                    evicted: ctx.store.evicted.splice(0), polled };
  dirtyRows = new Set();
  dirtySessions = new Set();
  polled = false;
  if (view) view.onFlush(payload);
}

// --- data flow ---------------------------------------------------------------

async function fetchJSON(url) {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`${url}: HTTP ${resp.status}`);
  }
  return resp.json();
}

function foldEvent(rec) {
  if (fold(ctx.store, rec)) {
    dirtyRows.add(rec.id);
    // The row's session (not the record's — a response can attribute the row)
    // is whose tally moved.
    dirtySessions.add(ctx.store.rows.get(rec.id)?.session ?? null);
    scheduleFlush();
  }
}

// Refetch history into a fresh store and let the view start over. Used at boot
// and on stream resets; returns the cursor that seams history to the stream.
async function reloadEvents() {
  const hist = await fetchJSON(`/api/events?limit=${ROW_CAP}`);
  ctx.store = newStore(ROW_CAP);
  dirtyRows = new Set();
  for (const rec of hist.events) {
    fold(ctx.store, rec);
  }
  if (view) view.rebuild();
  return hist.cursor;
}

// The badge answers for BOTH streams: "live" only when everything that should
// be open is open, a suffix when capture has no backend yet, "reconnecting…"
// the moment either trail drops — a gap in either is a gap in the picture.
let eventsUp = null;             // null until the first open
let captureUp = null;

function updateStreamBadge() {
  const capExpected = ctx.captureState === "live";
  if (eventsUp === false || (capExpected && captureUp === false)) {
    streamState.textContent = "reconnecting…";
  } else if (eventsUp) {
    streamState.textContent = capExpected && captureUp
      ? "live" : "live — no capture";
  } else {
    streamState.textContent = "…";
  }
}

let stream = null;

function openStream(cursor) {
  if (stream) {
    stream.close();
  }
  const url = "/api/stream"
    + (cursor ? `?cursor=${encodeURIComponent(cursor)}` : "");
  stream = new EventSource(url);
  stream.onopen = () => { eventsUp = true; updateStreamBadge(); };
  stream.onerror = () => { eventsUp = false; updateStreamBadge(); };
  stream.onmessage = (e) => {
    let rec;
    try {
      rec = JSON.parse(e.data);
    } catch {
      return;
    }
    foldEvent(rec);
  };
  // A reset means the tail adopted a different position (proxy restart, stale
  // cursor, truncation): refetch history and rebuild. The stream itself stays
  // open — dedupe on (id, decision) makes the refetch/stream overlap harmless.
  // A dropped connection needs no code at all: EventSource reconnects on its
  // own and resends the last frame id as Last-Event-ID.
  stream.addEventListener("reset", async () => {
    try {
      await reloadEvents();
    } catch {
      // the next reset or reconnect retries; the stream keeps flowing meanwhile
    }
  });
}

// --- the capture stream: its own cursor, its own resets --------------------------
// Never multiplexed with /api/stream — the two trails restart, truncate and
// reset independently, so sharing a pipe would tangle their recoveries.

let captureStream = null;

function foldCaptureRec(rec) {
  const hit = foldCapture(ctx.capture, rec);
  if (hit) {
    dirtySessions.add(hit.session);
    scheduleFlush();
  }
}

async function reloadCapture() {
  const hist = await fetchJSON(`/api/capture?limit=${CAPTURE_LIMIT}`);
  ctx.capture = newCapture();
  for (const rec of hist.events ?? []) {   // the envelope froze on `events`
    foldCapture(ctx.capture, rec);
  }
  if (view) view.rebuild();
  return hist.cursor;
}

// Availability detection: /api/capture 404s until its backend lands. One probe
// at boot decides — no retries beyond it; reloading the page probes again.
async function bootCapture() {
  let cursor;
  try {
    cursor = await reloadCapture();
  } catch {
    ctx.captureState = "unavailable";
    updateStreamBadge();
    return;
  }
  ctx.captureState = "live";
  openCaptureStream(cursor);
}

function openCaptureStream(cursor) {
  if (captureStream) {
    captureStream.close();
  }
  const url = "/api/capture/stream"
    + (cursor ? `?cursor=${encodeURIComponent(cursor)}` : "");
  captureStream = new EventSource(url);
  captureStream.onopen = () => { captureUp = true; updateStreamBadge(); };
  captureStream.onerror = () => { captureUp = false; updateStreamBadge(); };
  captureStream.onmessage = (e) => {
    let rec;
    try {
      rec = JSON.parse(e.data);
    } catch {
      return;
    }
    foldCaptureRec(rec);
  };
  // Same reset semantics as /api/stream, recovered on this stream's own cursor.
  captureStream.addEventListener("reset", async () => {
    try {
      await reloadCapture();
    } catch {
      // the next reset or reconnect retries; the stream keeps flowing meanwhile
    }
  });
}

// --- polls, paused while the tab is hidden --------------------------------------

let sessionsTimer = null;
let metricsTimer = null;

async function refreshSessions() {
  let data;
  try {
    data = await fetchJSON("/api/sessions");
  } catch {
    proxyState.textContent = "proxy: ? (ui server unreachable)";
    return;
  }
  ctx.sessions = data;
  const p = data.proxy || {};
  if (p.running) {
    const ports = Array.isArray(p.ports) && p.ports.length
      ? ` ports ${p.ports[0]}–${p.ports[p.ports.length - 1]}` : "";
    proxyState.textContent = `proxy: running (pid ${p.pid}${ports})`;
  } else {
    proxyState.textContent = "proxy: not running";
  }
  polled = true;                 // views re-apply filters: the window slides
  scheduleFlush();
}

async function refreshMetrics() {
  let data;
  try {
    data = await fetchJSON("/api/metrics");
  } catch {
    // Not available yet (the backend lands in parallel): stop asking while
    // this mount lasts — the next metrics-consuming mount probes again.
    ctx.metrics = null;
    stopMetricsPoll();
    return;
  }
  ctx.metrics = data;
  pushSamples(ctx.metricsHistory, data);
  for (const m of data.metrics ?? []) {
    if (m && m.session != null) {
      dirtySessions.add(m.session);
    }
  }
  scheduleFlush();
}

// Metrics cost the host a sampling pass, so the 2 s poll runs ONLY while the
// mounted view declares wantsMetrics.
function startMetricsPoll() {
  if (metricsTimer === null && view?.wantsMetrics) {
    refreshMetrics();
    metricsTimer = setInterval(refreshMetrics, METRICS_POLL_MS);
  }
}

function stopMetricsPoll() {
  clearInterval(metricsTimer);
  metricsTimer = null;
}

function startPolls() {
  if (sessionsTimer === null) {
    refreshSessions();           // catch up right away after a hidden stretch
    sessionsTimer = setInterval(refreshSessions, SESSIONS_POLL_MS);
  }
  startMetricsPoll();
}

function stopPolls() {
  clearInterval(sessionsTimer);
  sessionsTimer = null;
  stopMetricsPoll();
}

// --- routing: one view at a time -------------------------------------------------

let view = null;
let viewKey = null;              // which mount the current view answers for

function makeView(route) {
  if (route.view === "traffic") return newCallsView();
  if (route.view === "session") return newSessionView();
  if (route.view === "search") return newSearchView();
  return newOverviewView();
}

function syncNav(route) {
  for (const [name, a] of Object.entries(navLinks)) {
    if (route.view === name) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  // The box mirrors the route's query, but never mid-keystroke.
  if (route.view === "search" && document.activeElement !== searchBox
      && searchBox.value !== (route.q ?? "")) {
    searchBox.value = route.q ?? "";
  }
}

function dispatch() {
  const redirect = legacyRedirect(location.hash);
  if (redirect !== null) {
    location.replace(redirect);  // hashchange re-enters dispatch with the new hash
    return;
  }
  const route = parseRoute(location.hash);
  // Same key → the mounted view absorbs the change (filter edits, tab flips).
  // A different session ident is a different mount, not a param change.
  const key = route.view + (route.view === "session" ? " " + route.ident : "");
  if (view && key === viewKey) {
    view.onRoute(route);
    syncNav(route);
    // wantsMetrics can flip on a tab change (only the metrics tab and the
    // overview poll): re-decide without remounting.
    stopMetricsPoll();
    if (document.visibilityState !== "hidden") {
      startMetricsPoll();
    }
    return;
  }
  if (view) view.unmount();
  viewKey = key;
  view = makeView(route);
  view.mount(viewHost, ctx, route);
  syncNav(route);
  stopMetricsPoll();             // the new mount decides whether metrics flow
  if (document.visibilityState !== "hidden") {
    startMetricsPoll();
  }
}

// --- boot ----------------------------------------------------------------------

async function boot() {
  window.addEventListener("hashchange", dispatch);
  searchBox.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      ctx.navigate({ view: "search", q: searchBox.value.trim() });
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") stopPolls();
    else startPolls();
  });
  dispatch();
  startPolls();
  let cursor = null;
  try {
    cursor = await reloadEvents();
  } catch (err) {
    streamState.textContent = String(err);
  }
  openStream(cursor);
  bootCapture();                 // additive: the app is whole without it
}

boot();
