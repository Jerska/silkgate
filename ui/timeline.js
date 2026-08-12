// timeline.js — the merged activity timeline, with nothing attached: no DOM,
// no network. One session's story comes from four trails that never agreed on
// a format — capture turns, audit denies, egress responses, journal events —
// and this module folds them into one time-ordered column of plain items. The
// session view renders items; everything here returns data.
//
// Ordering is by parsed timestamp; an unparsable stamp sorts to the front
// rather than vanishing. Ties keep build order: turns, sightings, denies,
// responses, journal — stable sort makes that deterministic.

export const DENY_TAG_WINDOW_MS = 10_000;

function at(ts) {
  const t = Date.parse(ts || "");
  return Number.isNaN(t) ? 0 : t;
}

// Journal entries arrive from a backend that lands in parallel, so the reader
// is tolerant on key spellings but strict on meaning: env reduces to NAMES
// only — values never leave this function — and argv stays an array of
// strings. Returns null for anything that names no event.
export function journalEvent(e) {
  if (!e || typeof e !== "object") return null;
  const event = e.event ?? e.kind ?? e.type;
  if (event == null) return null;
  let envNames = null;
  const env = e.env_names ?? e.env;         // the backend writes env_names
  if (Array.isArray(env)) envNames = env.map(String);
  else if (env && typeof env === "object") envNames = Object.keys(env);
  return {
    ts: e.ts ?? e.time ?? null,
    event: String(event),
    execId: e.exec_id ?? e.exec ?? null,
    argv: Array.isArray(e.argv) ? e.argv.map(String) : null,
    tty: typeof e.tty === "boolean" ? e.tty : null,
    envNames,
    rc: typeof e.rc === "number" ? e.rc
      : typeof e.exit_code === "number" ? e.exit_code : null,
  };
}

// Every tool_use block in a capture session entry, time-ordered — the anchors
// the deny tagger measures from. Blocks without a stamp cannot anchor.
function toolMarks(captureSession) {
  const marks = [];
  for (const bucket of captureSession?.execs.values() ?? []) {
    for (const t of bucket.turns.values()) {
      for (const b of t.blocks.values()) {
        if (b.type === "tool_use" && b.ts != null) {
          marks.push({ at: at(b.ts), name: b.tool_name ?? "?" });
        }
      }
    }
  }
  marks.sort((a, b) => a.at - b.at);
  return marks;
}

// Tag each deny that lands within the window AFTER a tool_use with the newest
// such tool: a Bash block at t and a refusal at t+2s usually share a cause.
// It is a heuristic over wire proximity, not attribution — the caller labels
// it as such — so the tag names the tool and the gap and claims nothing more.
export function tagDenies(items, marks, windowMs = DENY_TAG_WINDOW_MS) {
  let i = 0;
  let latest = null;
  for (const item of items) {                    // both sides are time-ordered
    if (item.kind !== "deny") continue;
    while (i < marks.length && marks[i].at <= item.at) {
      latest = marks[i++];
    }
    if (latest && item.at - latest.at <= windowMs) {
      item.after = { tool: latest.name, dtMs: item.at - latest.at };
    }
  }
  return items;
}

// The merged column. `captureSession` is one entry of capture.sessions;
// `rows` is the audit store's rows (Map or iterable of row objects);
// `journal` is the detail endpoint's list. Each absent trail simply
// contributes nothing — the column degrades to whatever is known.
export function timelineItems({ captureSession = null, session = null,
                                rows = null, journal = null } = {}) {
  const items = [];
  for (const [exec, bucket] of captureSession?.execs ?? []) {
    for (const t of bucket.turns.values()) {
      items.push({ kind: "turn", at: at(t.ts), ts: t.ts, exec, turn: t });
    }
    for (const s of bucket.sightings.values()) {
      items.push({ kind: "sighting", at: at(s.ts), ts: s.ts, exec,
                   pattern: s.pattern, flowId: s.id, index: s.index });
    }
  }
  const rowList = rows instanceof Map ? rows.values() : rows ?? [];
  for (const row of rowList) {
    if (!row || row.session !== session) continue;
    if (row.decision === "deny") {
      items.push({ kind: "deny", at: at(row.ts), ts: row.ts, row });
    } else if (row.status != null) {
      items.push({ kind: "response", at: at(row.ts), ts: row.ts, row });
    }
  }
  for (const e of journal ?? []) {
    const ev = journalEvent(e);
    if (ev) items.push({ kind: "journal", at: at(ev.ts), ts: ev.ts, ev });
  }
  items.sort((a, b) => a.at - b.at);
  return tagDenies(items, toolMarks(captureSession));
}

// The files-touched panel: known file-carrying tool inputs, mapped to their
// paths. The wire shows what the agent ASKED to touch, not what the sandbox
// executed — the caller labels the panel "requested" — which is exactly why
// it works for checkout sessions whose diff endpoint has nothing to say.
const FILE_KEYS = new Map([["edit", "file_path"], ["write", "file_path"],
                           ["read", "file_path"], ["multiedit", "file_path"],
                           ["notebookedit", "notebook_path"]]);

export function filesTouched(captureSession) {
  const byPath = new Map();
  for (const bucket of captureSession?.execs.values() ?? []) {
    for (const t of bucket.turns.values()) {
      for (const b of t.blocks.values()) {
        if (b.type !== "tool_use" || !b.tool_input) continue;
        const key = FILE_KEYS.get(String(b.tool_name ?? "").toLowerCase());
        const path = key ? b.tool_input[key] : null;
        if (typeof path !== "string" || !path) continue;
        let f = byPath.get(path);
        if (!f) {
          f = { path, count: 0, tools: new Set() };
          byPath.set(path, f);
        }
        f.count++;
        f.tools.add(b.tool_name ?? "?");
      }
    }
  }
  return [...byPath.values()];     // first-touch order
}
