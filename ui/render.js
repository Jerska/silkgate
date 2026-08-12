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

// Unified-diff line classes, for the config tab's rule diffs (wave 2 renders
// them; the vocabulary ships now so the styles and tests can pin it). File
// headers before hunk/add: "+++ b/x" starts with "+" too.
export function diffLineClass(line) {
  if (line.startsWith("+++") || line.startsWith("---")) return "diff-file";
  if (line.startsWith("@@")) return "diff-hunk";
  if (line.startsWith("+")) return "diff-add";
  if (line.startsWith("-")) return "diff-del";
  return "";
}

// A diff as one element, one div per line, classified by diffLineClass and
// written via textContent — diffs quote guest-written files, so they get the
// same inert treatment as every other record-derived string.
export function renderDiff(text) {
  const box = el("div", { class: "diff" });
  for (const line of String(text ?? "").split("\n")) {
    box.append(el("div", { class: ("diff-line " + diffLineClass(line)).trim() }, line));
  }
  return box;
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
