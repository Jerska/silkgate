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

import { fmtBytes } from "./store.js";

export const SPARK_SAMPLES = 30;

export function newHistory() {
  return { bySession: new Map(), lastSampled: null };
}

// --- readout formatting -----------------------------------------------------
// The sampler answers raw floats (cpu 0.004325448535382748) and raw bytes; a
// readout is not a ledger, so cpu rounds to one decimal and memory reads in
// MiB. null for junk — callers show "—", never a guessed zero.

export function fmtCpuPct(v) {
  return typeof v === "number" && Number.isFinite(v) ? v.toFixed(1) + "%" : null;
}

export function fmtMiB(bytes) {
  return typeof bytes === "number" && Number.isFinite(bytes)
    ? (bytes / 1048576).toFixed(1) + " MiB" : null;
}

function fmtUptime(secs) {
  if (typeof secs !== "number" || !Number.isFinite(secs)) return null;
  const s = Math.max(0, Math.floor(secs));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

// The header's one-line summary from one /api/metrics row. Memory is the
// VMM's own resident set, which legitimately exceeds the guest allocation —
// it must never render as "X/limit", which reads as a machine over 100%.
// RSS stands alone with its label.
export function metricsSummary(m) {
  if (!m || typeof m !== "object") return [];
  const parts = [];
  const cpu = fmtCpuPct(m.cpu_percent);
  if (cpu !== null) parts.push(`cpu ${cpu}`);
  const mem = fmtMiB(m.memory_bytes);
  if (mem !== null) parts.push(`mem ${mem} (VMM RSS)`);
  if (m.net_rx_bytes != null || m.net_tx_bytes != null) {
    parts.push(`net ↓${fmtBytes(m.net_rx_bytes ?? 0)}`
               + ` ↑${fmtBytes(m.net_tx_bytes ?? 0)}`);
  }
  if (m.disk_read_bytes != null || m.disk_write_bytes != null) {
    parts.push(`disk r${fmtBytes(m.disk_read_bytes ?? 0)}`
               + ` w${fmtBytes(m.disk_write_bytes ?? 0)}`);
  }
  const up = fmtUptime(m.uptime_secs);
  if (up !== null) parts.push(`up ${up}`);
  return parts;
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
