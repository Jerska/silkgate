// controls.test.js — the control bar's gating rule: which buttons show for
// which session state. Pure over the state string, so the archived/down
// lockout pins down in node. Never served, never imported by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { controlVisibility } from "./controls.js";

test("archived and downed sessions get no controls at all", () => {
  for (const state of ["archived", "down"]) {
    assert.equal(controlVisibility(state).root, true, state);
  }
});

test("a running session shows freeze, not resume, no badge", () => {
  const v = controlVisibility("running");
  assert.equal(v.root, false);
  assert.equal(v.freeze, false, "freeze visible");
  assert.equal(v.resume, true, "resume hidden");
  assert.equal(v.badge, true, "badge hidden");
});

test("a frozen session swaps freeze for resume plus badge", () => {
  const v = controlVisibility("frozen");
  assert.equal(v.root, false);
  assert.equal(v.freeze, true, "freeze hidden");
  assert.equal(v.resume, false, "resume visible");
  assert.equal(v.badge, false, "badge visible");
});

test("an unknown or absent state keeps the bar up — the backend decides", () => {
  assert.equal(controlVisibility(null).root, false);
  assert.equal(controlVisibility(undefined).root, false);
});
