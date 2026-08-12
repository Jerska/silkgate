// render.js — the small vocabulary every view builds its DOM from. Everything
// record-derived enters the document as a text node or an attribute value, never
// as markup: LLM output and guest traffic are attacker-influenced, and this file
// is where that rule is enforced once instead of in every view. No module-level
// DOM access — the formatters and classifiers at the bottom are pure, so node
// can import this file for tests without a document.

// el("div", { class: "card", title: t }, "text", childNode, …) — attributes by
// assignment for the safe common ones, setAttribute for the rest; string
// children become text nodes. There is no path from a value to parsed markup.
export function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null) continue;
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

// The 8px status dot. `state` comes from our own triage vocabulary, never from
// a record, so it is safe as a class name — keep it that way.
export function statusDot(state) {
  return el("span", { class: "dot " + state });
}

// A horizontal meter filled to `frac` (0..1). The fill width is set through the
// CSSOM, not a style attribute: the server's CSP has no 'unsafe-inline', which
// blocks style="…" but not property assignment. Above 0.85 the fill turns hot —
// meters here mean "how close to a limit".
export function meterBar(frac) {
  const f = Math.max(0, Math.min(1, Number(frac) || 0));
  const fill = el("span", { class: "meter-fill" + (f > 0.85 ? " hot" : "") });
  fill.style.width = (f * 100).toFixed(1) + "%";
  return el("span", { class: "meter" }, fill);
}

// Unified-diff line classes, one per prefix: add/del/hunk/file/meta/ctx. File
// headers before add/del — "+++ b/x" starts with "+" too. `meta` is git's
// bookkeeping between the file header and the hunks (diff --git, index, mode
// and rename lines, binary notes); everything unclaimed is context.
const DIFF_META = ["diff ", "index ", "new file mode", "deleted file mode",
                   "old mode", "new mode", "rename from", "rename to",
                   "similarity index", "dissimilarity index",
                   "copy from", "copy to", "Binary files", "\\ No newline"];

export function diffLineClass(line) {
  if (line.startsWith("+++") || line.startsWith("---")) return "file";
  if (line.startsWith("@@")) return "hunk";
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "del";
  if (DIFF_META.some((p) => line.startsWith(p))) return "meta";
  return "ctx";
}

// A diff as classified lines, capped: a guest can emit a diff of any size, and
// 20k lines is past what anyone reads in a pane. Pure, so the cap and the
// class mapping pin down in node; renderDiff is its DOM twin.
export const DIFF_LINE_CAP = 20_000;

export function diffLines(text, cap = DIFF_LINE_CAP) {
  const all = String(text ?? "").split("\n");
  const kept = all.length > cap ? all.slice(0, cap) : all;
  return { lines: kept.map((l) => ({ cls: diffLineClass(l), text: l })),
           dropped: all.length - kept.length };
}

// One <div class="dl dl-<cls>"> per line, written via textContent — diffs quote
// guest-written files, so they get the same inert treatment as every other
// record-derived string. Past the cap, a footer says how much was dropped.
export function renderDiff(text, cap = DIFF_LINE_CAP) {
  const { lines, dropped } = diffLines(text, cap);
  const box = el("div", { class: "diff" });
  for (const l of lines) {
    box.append(el("div", { class: "dl dl-" + l.cls }, l.text));
  }
  if (dropped > 0) {
    box.append(el("div", { class: "diff-trunc" },
                  `… ${dropped} more lines not shown (${cap}-line cap)`));
  }
  return box;
}

// Sparkline geometry: values → "x,y x,y …" for an SVG <polyline>. Only finite
// numbers survive the filter — record-derived junk cannot reach the SVG, and a
// null sample is a gap, never a zero. The scale is min–max per series (a
// sparkline shows shape, not magnitude). Fewer than two points draw nothing.
export function sparkPoints(values, width, height, pad = 2) {
  const v = (values ?? []).filter((x) => typeof x === "number"
                                         && Number.isFinite(x));
  if (v.length < 2) return "";
  const min = Math.min(...v);
  const span = (Math.max(...v) - min) || 1;
  const step = (width - 2 * pad) / (v.length - 1);
  return v.map((n, i) =>
    (pad + i * step).toFixed(1) + ","
    + (height - pad - ((n - min) / span) * (height - 2 * pad)).toFixed(1))
    .join(" ");
}

// The inline sparkline itself. SVG nodes need their own namespace — el() only
// speaks HTML — and everything set on them here is a computed number.
const SVG_NS = "http://www.w3.org/2000/svg";

export function sparkline(values, { width = 120, height = 24 } = {}) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "spark");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("aria-hidden", "true");
  const line = document.createElementNS(SVG_NS, "polyline");
  line.setAttribute("points", sparkPoints(values, width, height));
  svg.append(line);
  return svg;
}

// Token counts read at a glance: 999 → "999", 12345 → "12.3k", 2.5e6 → "2.50M".
// null/undefined mean "not reported", which is "—", never "0" — a zero is a
// real measurement.
export function fmtTokens(n) {
  if (n == null || Number.isNaN(Number(n))) return "—";
  const v = Number(n);
  if (v < 1000) return String(v);
  if (v < 1e6) return (v / 1e3).toFixed(1) + "k";
  return (v / 1e6).toFixed(2) + "M";
}

// Costs are estimates off a hand-maintained price table, so they always render
// with a leading "~". null means "no price known" and shows as "—" — showing
// $0.00 for an unknown model would be a guess dressed as a measurement.
export function fmtCost(usd) {
  if (usd == null || Number.isNaN(Number(usd))) return "—";
  const v = Number(usd);
  if (v >= 100) return "~$" + v.toFixed(0);
  if (v >= 0.01 || v === 0) return "~$" + v.toFixed(2);
  return "~$" + v.toFixed(4);
}
