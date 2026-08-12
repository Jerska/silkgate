// capture.js — the meaning of the LLM-capture trail, with nothing attached: no
// DOM, no network. Capture records replay freely — history and stream overlap,
// resets refetch, reconnects resend — so every fold is idempotent by
// replacement: turns are keyed by flow id (a repeated turn_start rewrites the
// start fields), blocks are last-write-wins on (id, index), and turn_end closes
// a turn by replacing its end fields, never by accumulating. Replaying a
// sequence lands the state exactly where it already was.
//
// Sub-state is keyed by (session, exec). A record without an exec belongs to
// the "unattributed" bucket for its session — never guessed into a neighbor.
//
// Two caps bound memory, and they shed different things:
//   turnCap  — turns per bucket. An evicted turn folds the tokens it reported
//              into closedTotals exactly once (an evicted OPEN turn folds what
//              it had; its later turn_end is a no-op — the id is remembered so
//              replays cannot resurrect it or double-count).
//   textCap  — held text/tool-input chars per bucket. Shedding text drops
//              payloads from the oldest blocks but never touches a token
//              number: token meters must not drift when text falls off.

const ERROR_CAP = 50;            // capture_error entries kept per bucket
const SIGHTING_CAP = 100;        // secret_sighting entries kept per bucket
const EVICTED_MEMORY = 1000;     // evicted flow ids remembered per bucket; a
                                 // replay older than this only comes from a
                                 // reset, which rebuilds the capture anyway

const KINDS = new Set(["turn_start", "content_block", "turn_end",
                       "capture_error", "secret_sighting"]);

export function newCapture({ turnCap = 200, textCap = 2_000_000 } = {}) {
  // sessions: session → { execs: exec → bucket }. sessionTotals() takes one
  // session's entry; views walk buckets for the per-exec feed.
  return { sessions: new Map(), turnCap, textCap };
}

// The later of two record stamps; an unparsable stamp always loses. (store.js
// keeps its twin — both modules stay self-contained.)
function laterTs(a, b) {
  const ta = Date.parse(a || "");
  const tb = Date.parse(b || "");
  if (Number.isNaN(tb)) return a ?? null;
  if (Number.isNaN(ta)) return b;
  return tb >= ta ? b : a;
}

function getBucket(cap, session, exec) {
  let S = cap.sessions.get(session);
  if (!S) {
    S = { execs: new Map() };
    cap.sessions.set(session, S);
  }
  let b = S.execs.get(exec);
  if (!b) {
    b = { exec, turns: new Map(), evicted: new Set(), closedTotals: new Map(),
          errors: new Map(), sightings: new Map(), textChars: 0,
          lastTs: null, rev: 0 };
    S.execs.set(exec, b);
  }
  return b;
}

function evictTurn(bucket, id) {
  const t = bucket.turns.get(id);
  bucket.turns.delete(id);
  bucket.evicted.add(id);
  while (bucket.evicted.size > EVICTED_MEMORY) {
    bucket.evicted.delete(bucket.evicted.keys().next().value);  // oldest first
  }
  bucket.textChars -= t.textChars;
  const key = t.model ?? null;
  let c = bucket.closedTotals.get(key);
  if (!c) {
    c = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, turns: 0 };
    bucket.closedTotals.set(key, c);
  }
  c.input += t.input_tokens ?? 0;
  c.output += t.output_tokens ?? 0;
  c.cacheRead += t.cache_read_input_tokens ?? 0;
  c.cacheWrite += t.cache_creation_input_tokens ?? 0;
  c.turns++;
}

function insertTurn(cap, bucket, id, ts) {
  const t = { id, ts: ts ?? null, model: null, message_id: null,
              input_tokens: null, cache_creation_input_tokens: null,
              cache_read_input_tokens: null, ttfb_ms: null,
              open: true, stop_reason: null, output_tokens: null,
              duration_ms: null, incomplete: false, error: null,
              blocks: new Map(), textChars: 0, rev: 0 };
  bucket.turns.set(id, t);
  while (bucket.turns.size > cap.turnCap) {
    evictTurn(bucket, bucket.turns.keys().next().value);
  }
  return t;
}

// Shed held text, oldest blocks first, until the bucket fits its cap again.
// Only payloads leave — the block stays, flagged, and every token count stays.
function shedText(cap, bucket) {
  if (bucket.textChars <= cap.textCap) return;
  for (const t of bucket.turns.values()) {
    for (const b of t.blocks.values()) {
      if (b.heldChars === 0) continue;
      bucket.textChars -= b.heldChars;
      t.textChars -= b.heldChars;
      b.heldChars = 0;
      b.text = null;
      b.tool_input = null;
      b.dropped = true;
      t.rev++;
      if (bucket.textChars <= cap.textCap) return;
    }
  }
}

// Fold one capture record. Returns {session, exec} when the record was
// admitted — the caller's dirty key — or null when it was unfoldable or a
// no-op replay of an evicted turn. Turns keep a `rev` counter so a view can
// re-render only the turns a flush actually touched.
export function foldCapture(cap, rec) {
  if (!rec || typeof rec !== "object" || typeof rec.id !== "string" || !rec.id
      || !KINDS.has(rec.kind)) {
    return null;
  }
  const session = rec.session ?? null;
  const exec = rec.exec ?? null;
  const bucket = getBucket(cap, session, exec);
  switch (rec.kind) {
    case "turn_start": {
      if (bucket.evicted.has(rec.id)) return null;
      const t = bucket.turns.get(rec.id) ?? insertTurn(cap, bucket, rec.id, rec.ts);
      // Replace on repeat: start fields are the record's, whole. Blocks and the
      // end state survive, so a replayed sequence converges instead of piling up.
      t.ts = rec.ts ?? t.ts;
      t.model = rec.model ?? null;
      t.message_id = rec.message_id ?? null;
      t.input_tokens = rec.input_tokens ?? null;
      t.cache_creation_input_tokens = rec.cache_creation_input_tokens ?? null;
      t.cache_read_input_tokens = rec.cache_read_input_tokens ?? null;
      t.ttfb_ms = rec.ttfb_ms ?? null;
      t.rev++;
      break;
    }
    case "content_block": {
      if (bucket.evicted.has(rec.id)) return null;
      if (!Number.isInteger(rec.index)) return null;   // block identity is (id, index)
      // A block for a turn we never saw start (a cursor landing mid-turn) gets
      // a stub turn rather than the floor — turn_start may still replay in.
      const t = bucket.turns.get(rec.id) ?? insertTurn(cap, bucket, rec.id, rec.ts);
      const old = t.blocks.get(rec.index);
      if (old) {
        t.textChars -= old.heldChars;
        bucket.textChars -= old.heldChars;
      }
      const b = { index: rec.index, type: rec.type ?? null,
                  text: typeof rec.text === "string" ? rec.text : null,
                  tool_name: rec.tool_name ?? null, tool_id: rec.tool_id ?? null,
                  tool_input: rec.tool_input ?? null,
                  chars: rec.chars ?? null, truncated: rec.truncated === true,
                  dropped: false, heldChars: 0 };
      b.heldChars = (b.text ? b.text.length : 0)
        + (b.tool_input != null ? JSON.stringify(b.tool_input).length : 0);
      t.blocks.set(rec.index, b);
      t.textChars += b.heldChars;
      bucket.textChars += b.heldChars;
      t.rev++;
      shedText(cap, bucket);
      break;
    }
    case "turn_end": {
      if (bucket.evicted.has(rec.id)) return null;     // its tokens were folded once
      const t = bucket.turns.get(rec.id) ?? insertTurn(cap, bucket, rec.id, rec.ts);
      t.open = false;
      t.stop_reason = rec.stop_reason ?? null;
      t.output_tokens = rec.output_tokens ?? null;     // closes by replacement
      t.duration_ms = rec.duration_ms ?? null;
      t.incomplete = rec.incomplete === true;
      t.error = rec.error ?? null;
      t.rev++;
      break;
    }
    case "capture_error": {
      bucket.errors.set(rec.id, { ts: rec.ts ?? null, reason: rec.reason ?? "" });
      while (bucket.errors.size > ERROR_CAP) {
        bucket.errors.delete(bucket.errors.keys().next().value);
      }
      break;
    }
    case "secret_sighting": {
      // Keyed by (flow, block index): a replayed sighting lands on itself.
      bucket.sightings.set(rec.id + " " + (rec.index ?? ""),
                           { ts: rec.ts ?? null, id: rec.id,
                             pattern: rec.pattern ?? "", index: rec.index ?? null });
      while (bucket.sightings.size > SIGHTING_CAP) {
        bucket.sightings.delete(bucket.sightings.keys().next().value);
      }
      break;
    }
  }
  bucket.lastTs = laterTs(bucket.lastTs, rec.ts ?? null);
  bucket.rev++;
  return { session, exec };
}

function addTokens(out, model, input, output, cacheRead, cacheWrite) {
  out.input += input;
  out.output += output;
  out.cacheRead += cacheRead;
  out.cacheWrite += cacheWrite;
  let m = out.byModel.get(model);
  if (!m) {
    m = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
    out.byModel.set(model, m);
  }
  m.input += input;
  m.output += output;
  m.cacheRead += cacheRead;
  m.cacheWrite += cacheWrite;
}

// Totals for one session's entry in cap.sessions — live turns plus everything
// eviction folded into closedTotals, across every exec bucket. byModel exists
// because cost is priced per model: a session that mixed models cannot be
// priced from a single sum. lastContext is the newest turn's prompt+output
// footprint, for the context-window gauge.
export function sessionTotals(S) {
  const out = { turns: 0, openTurns: 0,
                input: 0, output: 0, cacheRead: 0, cacheWrite: 0,
                byModel: new Map(), lastTs: null, lastContext: null,
                errors: 0, sightings: 0, execs: 0 };
  if (!S) return out;
  let last = null;
  for (const bucket of S.execs.values()) {
    out.execs++;
    out.errors += bucket.errors.size;
    out.sightings += bucket.sightings.size;
    out.lastTs = laterTs(out.lastTs, bucket.lastTs);
    for (const [model, c] of bucket.closedTotals) {
      out.turns += c.turns;
      addTokens(out, model, c.input, c.output, c.cacheRead, c.cacheWrite);
    }
    for (const t of bucket.turns.values()) {
      out.turns++;
      if (t.open) out.openTurns++;
      addTokens(out, t.model ?? null, t.input_tokens ?? 0, t.output_tokens ?? 0,
                t.cache_read_input_tokens ?? 0, t.cache_creation_input_tokens ?? 0);
      if (last === null || (t.ts != null && laterTs(last.ts, t.ts) === t.ts)) {
        last = t;
      }
    }
  }
  if (last) {
    out.lastContext = {
      model: last.model ?? null,
      tokens: (last.input_tokens ?? 0) + (last.cache_read_input_tokens ?? 0)
        + (last.cache_creation_input_tokens ?? 0) + (last.output_tokens ?? 0),
    };
  }
  return out;
}
