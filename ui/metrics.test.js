// metrics.test.js — the sample-history ring behind the sparklines: dedupe on
// the host's sampled stamp, the 30-sample cap, and null-not-zero gaps. Never
// served, never imported by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { newHistory, pushSamples, SPARK_SAMPLES,
         fmtCpuPct, fmtMiB, metricsSummary } from "./metrics.js";

function payload(sampled, rows) {
  return { sampled, ttl: 2, metrics: rows };
}

test("samples accumulate per session, independently", () => {
  const h = newHistory();
  pushSamples(h, payload("t1", [{ session: "a", cpu_percent: 10, memory_bytes: 100 },
                                { session: "b", cpu_percent: 90, memory_bytes: 900 }]));
  const touched = pushSamples(h, payload("t2", [{ session: "a", cpu_percent: 20,
                                                  memory_bytes: 200 }]));
  assert.deepEqual(touched, ["a"]);
  assert.deepEqual(h.bySession.get("a").cpu, [10, 20]);
  assert.deepEqual(h.bySession.get("b").cpu, [90], "b kept its own ring");
});

test("a replayed sampled stamp folds nothing — polls outpace the host ttl", () => {
  const h = newHistory();
  pushSamples(h, payload("t1", [{ session: "a", cpu_percent: 10 }]));
  assert.deepEqual(pushSamples(h, payload("t1", [{ session: "a", cpu_percent: 10 }])),
                   []);
  assert.equal(h.bySession.get("a").cpu.length, 1);
});

test("the ring holds 30 samples and sheds the oldest", () => {
  const h = newHistory();
  for (let i = 0; i < SPARK_SAMPLES + 5; i++) {
    pushSamples(h, payload("t" + i, [{ session: "a", cpu_percent: i }]));
  }
  const ring = h.bySession.get("a").cpu;
  assert.equal(ring.length, SPARK_SAMPLES);
  assert.equal(ring[0], 5, "the oldest five fell off");
  assert.equal(ring[ring.length - 1], SPARK_SAMPLES + 4);
});

test("a missing or junk number is a null gap, never a zero", () => {
  const h = newHistory();
  pushSamples(h, payload("t1", [{ session: "a", memory_bytes: 100 }]));
  pushSamples(h, payload("t2", [{ session: "a", cpu_percent: "97%",
                                  memory_bytes: 200 }]));
  assert.deepEqual(h.bySession.get("a").cpu, [null, null]);
  assert.deepEqual(h.bySession.get("a").mem, [100, 200]);
});

test("cpu rounds to one decimal; junk answers null, never a zero", () => {
  assert.equal(fmtCpuPct(0.004325448535382748), "0.0%");
  assert.equal(fmtCpuPct(12.34), "12.3%");
  assert.equal(fmtCpuPct(0), "0.0%", "a real zero is a measurement");
  assert.equal(fmtCpuPct("97%"), null);
  assert.equal(fmtCpuPct(NaN), null);
  assert.equal(fmtCpuPct(null), null);
});

test("memory reads in MiB at one decimal", () => {
  assert.equal(fmtMiB(880_620_339), "839.8 MiB");
  assert.equal(fmtMiB(0), "0.0 MiB");
  assert.equal(fmtMiB(undefined), null);
});

test("the summary shows RSS alone with its label — never X/limit", () => {
  const parts = metricsSummary({ cpu_percent: 0.004325448535382748,
                                 memory_bytes: 880_620_339,
                                 memory_limit_bytes: 536_870_912,
                                 uptime_secs: 245 });
  assert.equal(parts[0], "cpu 0.0%");
  assert.equal(parts[1], "mem 839.8 MiB (VMM RSS)",
               "VMM RSS exceeds the guest allocation; a /limit rendering"
               + " reads as a machine over 100%");
  assert.ok(!parts.some((p) => p.includes("/512") || p.includes("512.0")),
            "the limit stays out of the one-line summary");
  assert.equal(parts[2], "up 4m");
});

test("the summary skips what the row does not carry", () => {
  assert.deepEqual(metricsSummary({}), []);
  assert.deepEqual(metricsSummary(null), []);
  assert.deepEqual(metricsSummary({ net_rx_bytes: 2048 }), ["net ↓2.0K ↑0B"]);
});

test("dud payloads fold nothing", () => {
  const h = newHistory();
  assert.deepEqual(pushSamples(h, null), []);
  assert.deepEqual(pushSamples(h, { metrics: "nope" }), []);
  assert.deepEqual(pushSamples(h, payload("t1", [{ cpu_percent: 5 }, null])), [],
                   "rows without a session have no ring to land in");
  assert.equal(h.bySession.size, 0);
});
