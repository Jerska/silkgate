// store.js — the meaning of the audit trail, with no DOM or network: records
// fold into rows, filters admit rows, values become cell text. It returns data
// only, and rendering uses textContent, so hostile values stay inert.
//
// A request has at most two records, joined by `id`: the decision, and for an
// allow, a "response". A deny is terminal. A CONNECT allow never concludes, so
// it renders as "tunnel", not a "pending" that never resolves.

export function newStore(cap = 5000) {
  // tallies: session → {denies, requests, lastTs}, kept by fold() as rows land.
  // They are "recent window" counters over what the store has admitted, not an
  // all-time ledger: eviction never decrements one, and a record replayed after
  // its row was evicted counts again — exactly like the row it re-admits.
  return { rows: new Map(), seen: new Set(), evicted: [], cap, tallies: new Map() };
}

function tally(store, session) {
  let t = store.tallies.get(session);
  if (!t) {
    t = { denies: 0, requests: 0, lastTs: null };
    store.tallies.set(session, t);
  }
  return t;
}

// The later of two record stamps; an unparsable stamp always loses. Guards the
// tallies against a resume delivering a pair's records out of trail order.
function laterTs(a, b) {
  const ta = Date.parse(a || "");
  const tb = Date.parse(b || "");
  if (Number.isNaN(tb)) return a ?? null;
  if (Number.isNaN(ta)) return b;
  return tb >= ta ? b : a;
}

function baseRow(rec) {
  return {
    id: rec.id,
    ts: rec.ts ?? null,
    session: rec.session ?? null,
    method: rec.method ?? "",
    host: rec.host ?? "",
    port: rec.port ?? null,
    path: rec.path ?? "",
    reason: rec.reason ?? "",
    listen_port: rec.listen_port ?? null,
    decision: "allow",
    state: "pending",            // pending | tunnel | done | denied
    status: null,
    duration_ms: null,
    request_bytes: null,
    response_bytes: null,
    injected: null,
    inject_skipped: null,
    stripped_query: [],
    stripped_headers: [],
    claimed: null,
  };
}

// Fold one record in. Returns the row's id when something changed, else null
// (a duplicate on (id, decision), unfoldable, or after a deny). The cap evicts in
// arrival order. Evicted ids go to store.evicted for the caller to drain.
export function fold(store, rec) {
  if (!rec || typeof rec !== "object" || typeof rec.id !== "string" || !rec.id) {
    return null;
  }
  const d = rec.decision;
  if (d !== "allow" && d !== "deny" && d !== "response") {
    return null;
  }
  const key = rec.id + "\u0000" + d;
  if (store.seen.has(key)) {
    return null;
  }
  store.seen.add(key);
  let row = store.rows.get(rec.id);
  let isNew = false;
  if (!row) {
    row = baseRow(rec);
    isNew = true;
    store.rows.set(rec.id, row);
    while (store.rows.size > store.cap) {
      const oldest = store.rows.keys().next().value;
      store.rows.delete(oldest);
      for (const k of ["allow", "deny", "response"]) {
        store.seen.delete(oldest + "\u0000" + k);
      }
      store.evicted.push(oldest);
    }
  }
  if (row.decision === "deny") {
    return null;                 // a deny is terminal: nothing upgrades it
  }
  const prevSession = row.session;
  if (d === "deny") {
    Object.assign(row, {
      ts: rec.ts ?? row.ts,
      session: rec.session ?? null,
      method: rec.method ?? row.method,
      host: rec.host ?? row.host,
      port: rec.port ?? row.port,
      path: rec.path ?? row.path,
      reason: rec.reason ?? row.reason,
      listen_port: rec.listen_port ?? row.listen_port,
      decision: "deny",
      state: "denied",
      status: rec.status ?? null,
      claimed: rec.claimed ?? row.claimed,
    });
  } else if (d === "allow") {
    row.ts = rec.ts ?? row.ts;
    row.session = rec.session ?? null;
    row.method = rec.method ?? row.method;
    row.host = rec.host ?? row.host;
    row.port = rec.port ?? row.port;
    row.path = rec.path ?? row.path;
    row.reason = rec.reason ?? row.reason;
    row.listen_port = rec.listen_port ?? row.listen_port;
    row.injected = rec.injected ?? null;
    row.inject_skipped = rec.inject_skipped ?? null;
    row.stripped_query = rec.stripped_query ?? [];
    row.stripped_headers = rec.stripped_headers ?? [];
    row.claimed = rec.claimed ?? row.claimed;
    if (row.method === "CONNECT") {
      row.state = "tunnel";
    }
    // otherwise the state stands: a resume can deliver the response record
    // first, and its "done" must not fall back to "pending"
  } else {
    row.status = rec.status ?? null;
    row.duration_ms = rec.duration_ms ?? null;
    row.request_bytes = rec.request_bytes ?? null;
    row.response_bytes = rec.response_bytes ?? null;
    if (row.session === null) {
      row.session = rec.session ?? null;
    }
    if (row.state !== "tunnel") {
      row.state = "done";
    }
  }
  // Tallies. A new row is one request under its session; a record that
  // re-attributes the row (a response filling in a null session, a deny naming
  // one) moves that count with it — moving is not the decrementing that
  // eviction forswears, the row was simply counted in the wrong bucket.
  const t = tally(store, row.session);
  if (isNew) {
    t.requests++;
  } else if (prevSession !== row.session) {
    tally(store, prevSession).requests--;
    t.requests++;
  }
  if (d === "deny") {
    t.denies++;                  // dedupe + terminal deny keep this to once per row
  }
  t.lastTs = laterTs(t.lastTs, rec.ts ?? null);
  return rec.id;
}

// In filters, "null" selects unattributed rows, as in /api/events. A session
// literally named "null" is spelled "(null)", which no real name can be. These
// two functions are the only crossing between names and filter values.
export function sessionToFilter(name) {
  return name === "null" ? "(null)" : name;
}

export function filterToSession(value) {
  return value === "(null)" ? "null" : value;
}

// Whether a row passes the filters, as /api/events does: `session` and
// `decision` exact, `method` case-folded, `host` a case-folded substring, and
// `since` (epoch ms) drops rows whose ts can't be parsed.
export function rowPasses(row, f) {
  if (f.session) {
    if (f.session === "null") {
      if (row.session !== null) return false;
    } else if (row.session !== filterToSession(f.session)) {
      return false;
    }
  }
  if (f.decision && row.decision !== f.decision) {
    return false;
  }
  if (f.method
      && (row.method || "").toUpperCase() !== f.method.toUpperCase()) {
    return false;
  }
  if (f.host && !(row.host || "").toLowerCase().includes(f.host.toLowerCase())) {
    return false;
  }
  if (f.since != null) {
    const t = Date.parse(row.ts || "");
    if (Number.isNaN(t) || t < f.since) {
      return false;
    }
  }
  return true;
}

export function statusText(row) {
  if (row.state === "tunnel") return "tunnel";
  if (row.state === "pending") return "…";
  return row.status == null ? "—" : String(row.status);
}

export function fmtTime(ts) {
  const t = Date.parse(ts || "");
  if (Number.isNaN(t)) {
    return ts || "";
  }
  const d = new Date(t);
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
    + `.${p(d.getMilliseconds(), 3)}`;
}

export function fmtBytes(n) {
  if (n == null) return "";
  if (n < 1024) return `${n}B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)}K`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)}M`;
  return `${(n / 1024 ** 3).toFixed(1)}G`;
}

export function fmtDur(ms) {
  if (ms == null) return "";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

// The ACTIONS badges: what enforcement did on the way through, names only —
// the records never carry credential or stripped values, so neither can a cell.
export function badges(row) {
  const out = [];
  if (row.injected) {
    out.push({ text: `inj:${row.injected}`,
               title: "credential injected (name only — the value is not in the trail)" });
  }
  if (row.inject_skipped) {
    out.push({ text: `skip:${row.inject_skipped}`,
               title: "rule injects this credential, but the guest sent no auth header" });
  }
  if (row.stripped_query && row.stripped_query.length) {
    out.push({ text: `q:${row.stripped_query.length}`,
               title: `stripped query params: ${row.stripped_query.join(", ")}` });
  }
  if (row.stripped_headers && row.stripped_headers.length) {
    out.push({ text: `h:${row.stripped_headers.length}`,
               title: `stripped headers: ${row.stripped_headers.join(", ")}` });
  }
  if (row.claimed) {
    out.push({ text: "claimed",
               title: `client claimed a different authority: ${row.claimed}` });
  }
  return out;
}
