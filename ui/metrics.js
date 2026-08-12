// metrics.js — the client-side sample history behind the sparklines, with
// nothing attached: no DOM, no network. app.js pushes each /api/metrics
// payload here; the overview cards and the metrics tab read the rings back as
// plain number arrays. Thirty samples per session is the whole memory — at the
// 2 s poll that is one minute of shape, which is what a sparkline is for.
//
// The payload's `sampled` stamp dedupes: the host samples on its own ttl, so
// two polls can return the same measurement and a repeated push must not bend
// the line. A missing number lands as null — a gap in the series, never a
// zero — and sparkPoints drops nulls on the way to geometry.

export const SPARK_SAMPLES = 30;

export function newHistory() {
  return { bySession: new Map(), lastSampled: null };
}

function asSample(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

// Fold one /api/metrics payload into the rings. Returns the session names
// whose rings moved (the caller's dirty keys), or [] for a dud or a replay.
export function pushSamples(hist, payload, cap = SPARK_SAMPLES) {
  const rows = payload?.metrics;
  if (!Array.isArray(rows)) return [];
  if (payload.sampled != null && payload.sampled === hist.lastSampled) {
    return [];                     // same host-side sample, already folded
  }
  hist.lastSampled = payload.sampled ?? null;
  const touched = [];
  for (const m of rows) {
    if (!m || m.session == null) continue;
    let h = hist.bySession.get(m.session);
    if (!h) {
      h = { cpu: [], mem: [] };
      hist.bySession.set(m.session, h);
    }
    h.cpu.push(asSample(m.cpu_percent));
    h.mem.push(asSample(m.memory_bytes));
    while (h.cpu.length > cap) h.cpu.shift();
    while (h.mem.length > cap) h.mem.shift();
    touched.push(m.session);
  }
  return touched;
}
