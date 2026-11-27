// pricing.js — a table of Claude model prices and context
// windows, with no DOM or network. THE FIGURES ARE HAND-KEPT ESTIMATES (USD per
// MTok, cache writes at the 5-minute TTL, last reconciled 2026-11-23), so the UI
// prefixes costs with "~". An unknown model answers null: tokens show without
// cost. Never guess a price: a wrong "$0.02" reads as fact, a "—" doesn't.

//                            $/MTok in   out   cache-read  cache-write  context
const PRICES = {
  "claude-fable-5-2":         [8,         40,   0.2,        10,          1_000_000],
  "claude-mythos-5-2":        [8,         40,   0.2,        10,          1_000_000],
  "claude-fable-5-1":         [10,        50,   0.25,       12.5,        1_000_000],
  "claude-mythos-5-1":        [10,        50,   0.25,       12.5,        1_000_000],
  "claude-fable-5":           [10,        50,   1,          12.5,        1_000_000],
  "claude-mythos-5":          [10,        50,   1,          12.5,        1_000_000],
  "claude-opus-5-5":          [4,         20,   0.2,        5,           1_000_000],
  "claude-opus-5":            [5,         25,   0.5,        6.25,        1_000_000],
  "claude-sonnet-5-5":        [2,         10,   0.1,        2.5,         1_000_000],
  "claude-sonnet-5":          [2,         10,   0.2,        2.5,         1_000_000],
  // claude-haiku-5-5 has no row: its price rises past a 100k-token prompt,
  // a tier this flat table cannot express, so it answers null.
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

// A model id matches its own row, or a row plus a dated-snapshot suffix:
// "claude-opus-4-5-20251101" finds claude-opus-4-5. Nothing else matches, so a
// new release answers null until it has a row, instead of borrowing a sibling's
// price. Rows are own properties only: "constructor" is not a model.
const SNAPSHOT = /-\d{8}$/;

function row(id) {
  return Object.hasOwn(PRICES, id) ? PRICES[id] : null;
}

export function priceFor(model) {
  if (typeof model !== "string" || !model) {
    return null;
  }
  const found = row(model) ?? (SNAPSHOT.test(model) ? row(model.slice(0, -9)) : null);
  if (!found) {
    return null;
  }
  const [input, output, cacheRead, cacheWrite, window] = found;
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
