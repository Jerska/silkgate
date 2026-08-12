// views/session.js — one session up close: a header that triages like the
// overview card (plus the freeze/resume/down bar), then tabs. `activity` is
// the capture feed, merged on demand with denies, responses and journal
// events into one timeline; `calls` pins the calls component to this session;
// `diff`, `config`, `brief`, `output` and `metrics` each read one endpoint
// and degrade to a concrete message while its backend is missing.
//
// The feed renders whole blocks — capture emits blocks complete, so there is
// no token-by-token churn — and re-renders only items whose fold `rev` moved,
// which is what keeps an open <details> open while other items stream past.
// LLM output, guest stdout and diffs are attacker-influenced text and reach
// the DOM only as text nodes; tool input renders as JSON.stringify in a <pre>.

import { el, statusDot, renderDiff, sparkline, fmtTokens } from "../render.js";
import { fmtBytes, fmtDur, fmtTime } from "../store.js";
import { metricsSummary, fmtCpuPct, fmtMiB } from "../metrics.js";
import { sessionTotals } from "../capture.js";
import { journalEvent, timelineItems, filesTouched } from "../timeline.js";
import { newControlBar, newKillControl } from "../controls.js";
import { triage, fmtAge } from "./overview.js";
import { newCallsView } from "./calls.js";

const TABS = ["activity", "calls", "diff", "config", "brief", "output", "metrics"];

// The meta behind a session view, looked up fresh each call: live metas answer
// by name, archived metas by the sid the overview links with. Archived-ness is
// placement (the archived list) or an explicit state — the same derivation the
// overview grid uses, so the detail header can never disagree with the card.
// Pure so the lookup and the archived verdict pin down in node.
export function findMeta(sessions, ident, session) {
  for (const m of sessions?.sessions ?? []) {
    if (m?.name === session) {
      return { meta: m, archived: m.state === "archived" };
    }
  }
  for (const m of sessions?.archived ?? []) {
    if (String(m?.sid ?? m?.name) === ident) {
      return { meta: m, archived: true };
    }
  }
  return { meta: null, archived: false };
}
const DETAIL_MS = 5000;          // min gap between /api/session/<ident> fetches
const OUTPUT_TAIL = 500;
const OUTPUT_MIN_MS = 1000;      // min gap between manual output refreshes

export function newSessionView() {
  let ctx = null;
  let root = null;
  let ident = null;
  let session = null;              // the name data is keyed under
  let tab = null;
  let ticker = null;
  const head = {};                 // dot, label, branch, metrics
  let ctlBar = null;
  let tabBar, tabBody;

  // The active tab's teardown state: a mounted calls view, a feed, or a pane.
  let callsView = null;
  let feed = null;                 // {list, strip, execSel, execs, selected, nodes}
  let cfgPane = null;
  let briefPane = null;
  let metricsPane = null;

  // The /api/session/<ident> payload feeds the config and brief tabs and the
  // activity timeline's journal events. Fetched on mount and re-fetched at
  // most every DETAIL_MS while a consuming tab is up.
  let detail = null;               // null | "unavailable" | the payload
  let detailAt = 0;

  function meta() {
    return findMeta(ctx.sessions, ident, session).meta;
  }

  function isArchived() {
    return findMeta(ctx.sessions, ident, session).archived;
  }

  // A diff exists only where a git workspace does. Without a meta the answer
  // is unknown — show the tab and let the endpoint speak for itself. The meta
  // spells the mode as the backend's diff guard reads it: a `branch` name or a
  // `checkout` ref, never a separate mode field.
  function hasWorkspace() {
    const m = meta();
    if (!m) return true;
    return Boolean(m.branch || m.checkout);
  }

  async function fetchDetail(force = false) {
    const now = Date.now();
    if (!force && now - detailAt < DETAIL_MS) return;
    detailAt = now;
    try {
      const resp = await fetch(`/api/session/${encodeURIComponent(ident)}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      detail = await resp.json();
    } catch {
      if (detail === null) detail = "unavailable";
      return;                      // a stale payload beats an error banner
    }
    if (!root) return;             // unmounted while the fetch was in flight
    if (tab === "config") renderConfig();
    if (tab === "brief") renderBrief();
    if (tab === "activity" && feed) renderFeed();
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
      archived: isArchived(),      // placement or state, like the overview card
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
    ctlBar?.sync();
    if (head.diffTab) head.diffTab.hidden = !hasWorkspace();
    updateMetrics();
  }

  function updateMetrics() {
    const rows = ctx.metrics?.metrics;
    const m = Array.isArray(rows) ? rows.find((r) => r?.session === session) : null;
    // Empty until the poll lands one; metricsSummary rounds and keeps VMM RSS
    // from reading as "X/limit".
    head.metrics.textContent = m ? metricsSummary(m).join(" · ") : "";
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
          el("summary", null, `running ${b.tool_name ?? "?"}…`
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

  // One non-turn timeline item → its node. Everything in them is trail data:
  // text nodes only, like the turns.
  function renderItem(item) {
    if (item.kind === "turn") return renderTurn(item.turn);
    const when = el("span", { class: "num tl-time", title: item.ts ?? "" },
                    fmtTime(item.ts));
    if (item.kind === "deny") {
      const row = item.row;
      const node = el("div", { class: "tl tl-deny" }, when,
        el("span", null, `deny ${row.method} ${row.host}${row.path}`
           + (row.reason ? ` — ${row.reason}` : "")));
      if (item.after) {
        node.append(el("div", { class: "tl-tag" },
          `↳ ${fmtDur(item.after.dtMs)} after ${item.after.tool} started —`
          + " likely its consequence (wire-proximity heuristic, not proof)"));
      }
      return node;
    }
    if (item.kind === "response") {
      const row = item.row;
      return el("div", { class: "tl tl-resp" }, when,
        el("span", null, `${row.status ?? "?"} ${row.method} ${row.host}${row.path}`
           + (row.response_bytes != null
              ? ` · ${fmtBytes(row.response_bytes)}` : "")));
    }
    if (item.kind === "sighting") {
      return el("div", { class: "tl tl-alert" }, when,
        el("span", null, `SECRET SIGHTING: ${item.pattern}`
           + (item.index != null ? ` (block ${item.index})` : "")
           + " — a match in a RESPONSE means the secret already left"));
    }
    if (item.kind === "journal") {
      const node = journalLine(item.ev);
      node.classList.add("tl");
      return node;
    }
    return el("div", { class: "tl" });
  }

  // Reconciliation identity + change marker per item. Keys never collide
  // across kinds (each has its own prefix); a deny re-renders if its
  // consequence tag appears later, a turn on its fold rev, the rest never.
  function wantEntry(item) {
    if (item.kind === "turn") {
      return { key: "t " + execLabel(item.exec) + " " + item.turn.id,
               rev: item.turn.rev, item };
    }
    if (item.kind === "deny") {
      return { key: "d " + item.row.id, rev: item.after ? 1 : 0, item };
    }
    if (item.kind === "response") {
      return { key: "r " + item.row.id, rev: 0, item };
    }
    if (item.kind === "sighting") {
      return { key: "s " + execLabel(item.exec) + " " + item.flowId
                    + " " + (item.index ?? ""), rev: 0, item };
    }
    return { key: "j " + (item.ts ?? "") + " " + item.ev.event
                  + " " + (item.ev.execId ?? ""), rev: item.ev.rc ?? -1, item };
  }

  function updateFilesPanel(scope) {
    const files = filesTouched({ execs: new Map(scope) });
    feed.files.hidden = files.length === 0;
    feed.filesSummary.textContent = `files touched (requested) — ${files.length}`;
    feed.filesList.textContent = "";
    for (const f of files) {
      feed.filesList.append(el("div", { class: "file-line" },
        el("span", { class: "file-path" }, f.path),
        el("span", { class: "num file-ops" },
           `${[...f.tools].join("/")} ×${f.count}`)));
    }
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
    feed.kill.hidden = feed.selected === "" || scope.length !== 1
      || scope[0][0] == null || isArchived();   // nothing left to signal

    updateFilesPanel(scope);

    // Errors always strip at the top; sightings too in turns-only mode (the
    // merged column carries them inline instead, at their moment).
    feed.strip.textContent = "";
    for (const [, bucket] of scope) {
      if (!feed.all) {
        for (const s of bucket.sightings.values()) {
          feed.strip.append(el("div", { class: "sighting" },
            `secret sighting: ${s.pattern}`
            + (s.index != null ? ` (block ${s.index})` : "")));
        }
      }
      for (const [id, e] of bucket.errors) {
        feed.strip.append(el("div", { class: "capture-err" },
          `capture error on ${id}: ${e.reason}`));
      }
    }

    // What the column holds: turns only, or the merged timeline. Only changed
    // revs re-render either way.
    const want = [];
    const seen = new Set();
    if (feed.all) {
      const scoped = S ? { execs: new Map(scope) } : null;
      // Journal events follow the exec selector when they name an exec;
      // session-level events (created, harvest, down) always show.
      const exec = scope.length === 1 ? scope[0][0] : null;
      const journal = (Array.isArray(detail?.journal) ? detail.journal : [])
        .filter((e) => {
          if (feed.selected === "") return true;
          const id = journalEvent(e)?.execId;
          return id == null || id === exec;
        });
      for (const item of timelineItems({ captureSession: scoped, session,
                                         rows: ctx.store.rows, journal })) {
        const w = wantEntry(item);
        if (!seen.has(w.key)) {
          seen.add(w.key);
          want.push(w);
        }
      }
    } else {
      for (const [exec, bucket] of scope) {
        for (const t of bucket.turns.values()) {
          want.push({ key: "t " + execLabel(exec) + " " + t.id, rev: t.rev,
                      item: { kind: "turn", turn: t },
                      at: Date.parse(t.ts || "") || 0 });
        }
      }
      want.sort((a, b) => a.at - b.at);
      for (const w of want) seen.add(w.key);
    }

    for (const w of want) {
      const have = feed.nodes.get(w.key);
      if (!have || have.rev !== w.rev) {
        const node = renderItem(w.item);
        if (have) have.node.replaceWith(node);
        feed.nodes.set(w.key, { node, rev: w.rev });
      }
    }
    for (const [key, have] of feed.nodes) {
      if (!seen.has(key)) {                      // evicted items leave the feed
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
        ? (feed.all ? "nothing recorded for this session yet"
                    : "no capture records for this session yet — the all-events"
                      + " toggle also shows denies, responses and journal")
        : "capture not available yet — /api/capture lands with the backend;"
          + " the calls tab works today"
          + (feed.all ? "" : ", and the all-events toggle shows the audit trail");
      feed.msg.hidden = false;
    } else {
      feed.msg.hidden = true;
    }
  }

  // --- the diff tab -----------------------------------------------------------
  // Everything in it comes back from a guest-side git run, so the pane wears
  // the untrusted label and renders through renderDiff/textContent only. The
  // diff never runs on its own — one POST per explicit click.

  function renderDiffResult(out, body) {
    out.textContent = "";
    if (body.mode != null) {
      out.append(el("div", { class: "pane-note" }, `mode: ${body.mode}`));
    }
    const status = typeof body.status === "string" ? body.status : "";
    out.append(el("h3", null, "git status --porcelain"),
               status.trim() === ""
                 ? el("p", { class: "state-msg" }, "clean — nothing to report")
                 : el("pre", { class: "porcelain" }, status));
    out.append(el("h3", null, "diff"));
    const diffText = typeof body.diff === "string" ? body.diff : "";
    if (diffText.trim() === "") {
      out.append(el("p", { class: "state-msg" }, "empty diff"));
    } else {
      out.append(renderDiff(diffText));
    }
    if (body.truncated) {
      out.append(el("div", { class: "diff-trunc" },
                    "the server truncated this diff"));
    }
  }

  function showDiffTab() {
    const btn = el("button", { type: "button" }, "load diff");
    const out = el("div");
    const msg = el("p", { class: "state-msg" });
    msg.textContent = hasWorkspace()
      ? "nothing loaded — the diff runs in the guest on demand, never on its own"
      : "this session has no git workspace to diff";
    btn.disabled = !hasWorkspace();
    tabBody.append(el("section", { class: "pane diff-pane" },
      el("div", { class: "pane-bar" }, btn,
         el("span", { class: "badge untrusted" }, "untrusted — guest output")),
      out, msg));
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      out.textContent = "";
      msg.textContent = "diffing…";
      msg.hidden = false;
      let resp;
      let body = null;
      try {
        resp = await fetch(`/api/session/${encodeURIComponent(ident)}/diff`,
                           { method: "POST" });
        try {
          body = await resp.json();
        } catch {
          // no JSON body — the status alone will have to explain
        }
      } catch {
        msg.textContent = "ui server unreachable";
        btn.disabled = false;
        return;
      }
      if (!out.isConnected) return;          // the tab was torn down meanwhile
      btn.disabled = false;
      if (resp.status === 409) {
        msg.textContent = `cannot diff: ${body?.error ?? "conflict"}`;
      } else if (resp.status === 429) {
        msg.textContent = "a diff is already running — try again in a moment";
      } else if (!resp.ok) {
        msg.textContent = body?.error
          ? `diff failed: ${body.error}`
          : `diff not available yet — the endpoint lands with the backend`
            + ` (HTTP ${resp.status})`;
      } else {
        msg.hidden = true;
        renderDiffResult(out, body ?? {});
      }
    });
  }

  // --- the config tab -----------------------------------------------------------

  // Key/value rendering for the meta: argv holds the operator prompt and every
  // value is trail data, so nothing here is markup — dt/dd text only.
  function kvList(obj) {
    const dl = el("dl", { class: "kv" });
    for (const [k, v] of Object.entries(obj)) {
      dl.append(el("dt", null, k),
                el("dd", null, typeof v === "string" ? v : JSON.stringify(v)));
    }
    return dl;
  }

  function journalLine(ev) {
    const parts = [ev.event];
    if (ev.execId != null) parts.push(`exec ${ev.execId}`);
    if (ev.rc != null) parts.push(`rc ${ev.rc}`);
    if (ev.tty != null) parts.push(ev.tty ? "tty" : "no tty");
    const node = el("div", { class: "journal-line" },
      el("span", { class: "num j-time", title: ev.ts ?? "" }, fmtTime(ev.ts)),
      el("span", { class: "j-event" + (ev.rc != null && ev.rc !== 0 ? " bad" : "") },
         parts.join(" · ")));
    if (ev.argv) {
      node.append(el("div", { class: "j-detail" }, "argv: " + ev.argv.join(" ")));
    }
    if (ev.envNames?.length) {
      node.append(el("div", { class: "j-detail" },
                     "env: " + ev.envNames.join(" ")));
    }
    return node;
  }

  function renderConfig() {
    if (!cfgPane) return;
    cfgPane.textContent = "";
    const m = meta();
    if (detail === null) {
      cfgPane.append(el("p", { class: "state-msg" }, "loading session detail…"));
      return;
    }
    if (detail === "unavailable") {
      cfgPane.append(el("p", { class: "state-msg" },
        "session detail not available yet — GET /api/session/<ident> lands"
        + " with the backend"));
      if (m) {
        cfgPane.append(el("h3", null, "meta (from /api/sessions)"), kvList(m));
      }
      return;
    }
    const info = detail.session && typeof detail.session === "object"
      ? detail.session : m;
    cfgPane.append(el("h3", null, "invocation"));
    cfgPane.append(info ? kvList(info)
                        : el("p", { class: "state-msg" }, "no meta known"));
    cfgPane.append(el("h3", null, "journal"));
    const events = (Array.isArray(detail.journal) ? detail.journal : [])
      .map(journalEvent).filter(Boolean);
    if (events.length === 0) {
      cfgPane.append(el("p", { class: "state-msg" }, "empty journal"));
    } else {
      cfgPane.append(...events.map(journalLine));
    }
    for (const key of ["rules", "pointers"]) {
      if (detail[key] != null) {
        cfgPane.append(el("details", { class: "cfg-extra" },
          el("summary", null, key),
          el("pre", null, JSON.stringify(detail[key], null, 2))));
      }
    }
  }

  // --- the brief tab --------------------------------------------------------------

  function renderBrief() {
    if (!briefPane) return;
    briefPane.textContent = "";
    if (detail === null) {
      briefPane.append(el("p", { class: "state-msg" }, "loading session detail…"));
      return;
    }
    if (detail === "unavailable") {
      briefPane.append(el("p", { class: "state-msg" },
        "session detail not available yet — GET /api/session/<ident> lands"
        + " with the backend"));
      return;
    }
    const b = detail.brief;
    if (b == null) {
      briefPane.append(el("p", { class: "state-msg" },
                          "no brief recorded for this session"));
      return;
    }
    briefPane.append(el("div", { class: "pane-bar" },
      el("span", { class: "pane-note" }, `source: ${b.source ?? "?"}`),
      b.source === "workspace"
        ? el("span", { class: "badge untrusted" }, "guest-writable — untrusted")
        : null,
      b.sha256
        ? el("span", { class: "num", title: String(b.sha256) },
             `sha256 ${String(b.sha256).slice(0, 12)}…`)
        : null,
      b.truncated ? el("span", { class: "pane-note" }, "(truncated)") : null));
    briefPane.append(el("pre", { class: "brief-text" }, b.text ?? ""));
  }

  // --- the output tab --------------------------------------------------------------

  function showOutputTab() {
    const refresh = el("button", { type: "button" }, "refresh");
    const label = el("span", { class: "num" });
    const pre = el("pre", { class: "output-text" });
    const msg = el("p", { class: "state-msg" }, "loading output…");
    pre.hidden = true;
    refresh.hidden = isArchived();                   // a done guest is done
    tabBody.append(el("section", { class: "pane output-pane" },
      el("div", { class: "pane-bar" }, refresh, label,
         el("span", { class: "badge untrusted" }, "untrusted — guest stdout")),
      pre, msg));
    async function load() {
      let body;
      try {
        const resp = await fetch(`/api/session/${encodeURIComponent(ident)}`
                                 + `/output?tail=${OUTPUT_TAIL}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        body = await resp.json();
      } catch (err) {
        if (pre.isConnected) {
          msg.textContent = "output not available yet — the endpoint lands"
            + ` with the backend (${err.message})`;
          msg.hidden = false;
        }
        return;
      }
      if (!pre.isConnected) return;
      const lines = Array.isArray(body.lines) ? body.lines
        : typeof body.lines === "string" ? body.lines.split("\n") : [];
      pre.textContent = lines.join("\n");
      pre.hidden = false;
      label.textContent = `showing last ${lines.length} lines`
        + (body.truncated ? " (truncated)" : "")
        + (body.source != null ? ` · ${body.source}` : "");
      msg.hidden = lines.length > 0;
      if (lines.length === 0) msg.textContent = "no output yet";
    }
    refresh.addEventListener("click", () => {
      refresh.disabled = true;     // one manual refresh per second, no faster
      setTimeout(() => { refresh.disabled = false; }, OUTPUT_MIN_MS);
      load();
    });
    load();
  }

  // --- the metrics tab --------------------------------------------------------------

  function renderMetricsTab() {
    if (!metricsPane) return;
    metricsPane.textContent = "";
    const rows = ctx.metrics?.metrics;
    const m = Array.isArray(rows)
      ? rows.find((r) => r?.session === session) : null;
    if (!m) {
      metricsPane.append(el("p", { class: "state-msg" },
        ctx.metrics === null
          ? "metrics not available yet — /api/metrics lands with the backend"
          : "no metrics for this session in the last sample"));
      return;
    }
    const h = ctx.metricsHistory?.bySession.get(session);
    const row = (label, value, series, spark) => el("div", { class: "metric-row" },
      el("span", { class: "metric-label" }, label),
      el("span", { class: "num metric-value" }, value),
      series ? sparkline(series, { width: 240, height: 32, ...spark }) : null);
    metricsPane.append(
      row("cpu", fmtCpuPct(m.cpu_percent) ?? "—", h?.cpu,
          { unit: "%", times: h?.ts, fmt: fmtCpuPct }),
      // VMM RSS is the VMM process's resident set: it legitimately exceeds
      // the guest allocation, so it never renders beside the limit as X/Y.
      row("mem (VMM RSS)", fmtMiB(m.memory_bytes) ?? "—", h?.mem,
          { unit: "MiB", times: h?.ts, fmt: fmtMiB }),
      m.memory_limit_bytes != null
        ? row("guest allocation", fmtMiB(m.memory_limit_bytes), null)
        : null,
      row("net", `↓${fmtBytes(m.net_rx_bytes ?? 0)} ↑${fmtBytes(m.net_tx_bytes ?? 0)}`,
          null),
      row("disk", `r${fmtBytes(m.disk_read_bytes ?? 0)}`
                  + ` w${fmtBytes(m.disk_write_bytes ?? 0)}`, null),
      m.uptime_secs != null ? row("up", fmtAge(m.uptime_secs * 1000), null) : null,
      ctx.metrics.sampled != null
        ? el("p", { class: "pane-note num" },
             `sampled ${fmtTime(ctx.metrics.sampled)} · 30-sample history,`
             + " collected while this tab or the overview is open")
        : null);
  }

  // --- tabs -------------------------------------------------------------------

  function teardownTab() {
    if (callsView) {
      callsView.unmount();
      callsView = null;
    }
    feed = null;
    cfgPane = null;
    briefPane = null;
    metricsPane = null;
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
      // Kill escalates less than down but still confirms; it aims at the one
      // exec the selector currently names, never at "all execs".
      const killCtl = newKillControl({
        getUrl: () => {
          const scope = scopeBuckets();
          if (feed.selected === "" || scope.length !== 1) return null;
          const exec = scope[0][0];
          if (exec == null) return null;   // unattributed: nothing to signal
          return `/api/session/${encodeURIComponent(ident)}`
            + `/exec/${encodeURIComponent(exec)}/kill`;
        },
        onDone: () => ctx.refreshSessions(),
      });
      const strip = el("div", { class: "feed-strip" });
      const list = el("div", { class: "feed" });
      const msg = el("p", { class: "state-msg" });
      msg.hidden = true;
      const picker = el("label", { class: "exec-pick" }, "exec ", execSel,
                        " ", killCtl.root);
      picker.hidden = true;
      // Turns-only vs the merged column; flipping changes every node's
      // identity, so the reconciler starts clean.
      const toggle = el("input", { type: "checkbox" });
      toggle.addEventListener("change", () => {
        feed.all = toggle.checked;
        feed.nodes.clear();
        feed.list.textContent = "";
        renderFeed();
      });
      const filesSummary = el("summary", null, "files touched (requested) — 0");
      const filesList = el("div", { class: "files-list" });
      const files = el("details", { class: "files",
        title: "paths named in tool inputs — the wire shows intent,"
               + " not execution" },
        filesSummary,
        el("p", { class: "pane-note" },
           "what the agent asked to touch, mapped from tool inputs on the"
           + " wire — requested, not proof of execution"),
        filesList);
      files.hidden = true;
      tabBody.append(el("section", { class: "activity" },
        el("div", { class: "feed-bar" }, picker,
           el("label", { class: "feed-toggle" }, toggle,
              " all events (denies, responses, journal)")),
        files, strip, list, msg));
      feed = { execSel, kill: killCtl.root, strip, list, msg,
               files, filesSummary, filesList, all: false,
               nodes: new Map(), selected: "", execs: null };
      renderFeed();
      fetchDetail();               // journal events feed the merged timeline
    } else if (tab === "diff") {
      showDiffTab();
    } else if (tab === "config") {
      cfgPane = el("section", { class: "pane config-pane" });
      tabBody.append(cfgPane);
      renderConfig();
      fetchDetail();
    } else if (tab === "brief") {
      briefPane = el("section", { class: "pane brief-pane" });
      tabBody.append(briefPane);
      renderBrief();
      fetchDetail();
    } else if (tab === "output") {
      showOutputTab();
    } else if (tab === "metrics") {
      metricsPane = el("section", { class: "pane metrics-pane" });
      tabBody.append(metricsPane);
      renderMetricsTab();
    }
  }

  // --- the view interface -------------------------------------------------------

  function mount(host, appCtx, route) {
    ctx = appCtx;
    ident = route.ident;
    // Archived sids resolve to metas; data keys by name. On a cold load the
    // sessions payload has not landed yet, so onFlush re-resolves when it does.
    session = findMeta(ctx.sessions, ident, ident).meta?.name ?? ident;

    head.dot = statusDot("waiting");
    head.name = el("span", { class: "session-name" }, session);
    head.label = el("span", { class: "num" }, "…");
    head.branch = el("span", { class: "session-branch" });
    head.metrics = el("span", { class: "num session-metrics" });
    ctlBar = newControlBar({
      ident,
      // An archived-list meta may carry no state field; the bar gates on the
      // placement verdict, so freeze/resume/down never show for the archive.
      getMeta: () => (isArchived() ? { ...meta(), state: "archived" } : meta()),
      onChanged: () => ctx.refreshSessions(),
    });
    tabBar = el("nav", { class: "tabs" },
      ...TABS.map((t) => el("a", { href: "#/session/" + encodeURIComponent(ident)
                                         + (t === "activity" ? "" : "?tab=" + t),
                                   dataset: { tab: t } }, t)));
    head.diffTab = [...tabBar.children].find((a) => a.dataset.tab === "diff");
    tabBody = el("div", { class: "tab-body" });
    root = el("section", { class: "session" },
      el("header", { class: "session-head" },
        el("a", { href: "#/", class: "back" }, "← overview"),
        head.dot,
        head.name,
        head.branch,
        head.label,
        head.metrics,
        ctlBar.root),
      tabBar,
      tabBody);
    host.appendChild(root);
    updateHead();
    showTab(route.tab);
    fetchDetail(true);
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
    // An archived session opened by URL mounts before /api/sessions answers,
    // with the sid standing in for the name. Re-resolve when a payload lands:
    // rows, capture buckets and tallies all key by name.
    if (payload.polled) {
      const name = findMeta(ctx.sessions, ident, session).meta?.name;
      if (name && name !== session) {
        session = name;
        head.name.textContent = session;
        showTab(tab);            // the mounted tab keyed its data by the old name
      }
    }
    if (callsView) {
      callsView.onFlush(payload);
    }
    if (payload.sessions.has(session) || payload.polled) {
      updateHead();
      if (feed) renderFeed();
      renderMetricsTab();
    }
    // The journal grows as the session lives (exec ends, freezes, harvests);
    // ride the sessions poll, throttled inside fetchDetail.
    if (payload.polled && (tab === "config" || tab === "activity")) {
      fetchDetail();
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
    renderMetricsTab();
  }

  return { mount, unmount, onFlush, onRoute, rebuild,
           // Only the metrics tab consumes the 2 s sampling poll; the header's
           // one-line summary rides whatever the last consumer fetched.
           get wantsMetrics() { return tab === "metrics"; } };
}
