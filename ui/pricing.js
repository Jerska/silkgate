// pricing.js — a longest-prefix table of Claude model prices and context
// windows, with nothing attached: no DOM, no network. THE FIGURES ARE ESTIMATES
// MAINTAINED BY HAND (per-MTok USD, cache-write at the 5-minute TTL; last
// reconciled 2026-08-12 against public price lists) — the UI renders every cost
// with a leading "~", and this table is the first place to check when a number
// looks off. A model id that matches no prefix answers null everywhere: the UI
// then shows tokens with no cost and hides the context gauge. Never guess a
// price — a wrong "$0.02" reads as a fact, a "—" reads as what it is.

//                            $/MTok in   out   cache-read  cache-write  context
const PRICES = {
  "claude-fable-5":           [10,        50,   1,          12.5,        1_000_000],
  "claude-mythos-5":          [10,        50,   1,          12.5,        1_000_000],
  "claude-opus-5":            [5,         25,   0.5,        6.25,        1_000_000],
  // INTRODUCTORY rate, expires 2026-08-31 (verified 2026-08-12): becomes
  // [3, 15, 0.3, 3.75, 1_000_000] after that date.
  "claude-sonnet-5":          [2,         10,   0.2,        2.5,         1_000_000],
  "claude-opus-4-8":          [5,         25,   0.5,        6.25,        1_000_000],
  "claude-opus-4-7":          [5,         25,   0.5,        6.25,        1_000_000],
  "claude-opus-4-6":          [5,         25,   0.5,        6.25,        1_000_000],
  "claude-opus-4-5":          [5,         25,   0.5,        6.25,        200_000],
  "claude-opus-4-1":          [15,        75,   1.5,        18.75,       200_000],
  "claude-opus-4":            [15,        75,   1.5,        18.75,       200_000],
  "claude-sonnet-4-6":        [3,         15,   0.3,        3.75,        1_000_000],
  "claude-sonnet-4-5":        [3,         15,   0.3,        3.75,        200_000],
  "claude-sonnet-4":          [3,         15,   0.3,        3.75,        200_000],
  "claude-haiku-4-5":         [1,         5,    0.1,        1.25,        200_000],
  "claude-3-7-sonnet":        [3,         15,   0.3,        3.75,        200_000],
  "claude-3-5-sonnet":        [3,         15,   0.3,        3.75,        200_000],
  "claude-3-5-haiku":         [0.8,       4,    0.08,       1,           200_000],
  "claude-3-opus":            [15,        75,   1.5,        18.75,       200_000],
  "claude-3-haiku":           [0.25,      1.25, 0.03,       0.3,         200_000],
};

// The longest prefix that matches wins, so "claude-opus-4-5-20251101" finds
// claude-opus-4-5, never the shorter claude-opus-4 row. A prefix only matches
// at a segment boundary: the next character must be "-" or the end — without
// that, "claude-sonnet-4-60" would take the claude-sonnet-4-6 row.
export function priceFor(model) {
  if (typeof model !== "string" || !model) {
    return null;
  }
  let best = null;
  for (const prefix of Object.keys(PRICES)) {
    if (model.startsWith(prefix)
        && (model.length === prefix.length || model[prefix.length] === "-")
        && (best === null || prefix.length > best.length)) {
      best = prefix;
    }
  }
  if (best === null) {
    return null;
  }
  const [input, output, cacheRead, cacheWrite, window] = PRICES[best];
  return { input, output, cacheRead, cacheWrite, window };
}

// Estimated USD for a token bundle, or null for a model the table does not
// know. Zero tokens on a known model price to 0 — that is a measurement, not
// an unknown.
export function estimateCost(model, { input = 0, output = 0,
                                      cacheRead = 0, cacheWrite = 0 } = {}) {
  const p = priceFor(model);
  if (p === null) {
    return null;
  }
  return (input * p.input + output * p.output
          + cacheRead * p.cacheRead + cacheWrite * p.cacheWrite) / 1e6;
}

export function contextWindow(model) {
  const p = priceFor(model);
  return p === null ? null : p.window;
}
