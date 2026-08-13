// style.test.js — the one cascade fact the UI depends on: the [hidden] reset.
// Scripts hide controls with el.hidden = true, and the UA sheet's
// [hidden] { display: none } loses to any author display rule (.ctl,
// .badge, .exec-pick, the grid sections), so style.css carries its own
// [hidden] { display: none !important; } reset. Node runs no cascade, so
// this pin is static text over the stylesheet. Never served, never
// imported by served files.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const css = readFileSync(fileURLToPath(new URL("./style.css", import.meta.url)),
                         "utf8");

test("style.css resets [hidden] to display: none !important", () => {
  // Comments cite the UA sheet's plain [hidden] rule, so strip them first;
  // the reset itself must carry the !important.
  const rules = css.replace(/\/\*[\s\S]*?\*\//g, "")
    .match(/\[hidden\]\s*\{[^}]*\}/g) ?? [];
  assert.ok(rules.length > 0, "a [hidden] rule exists");
  assert.ok(rules.some((r) => /display\s*:\s*none\s+!important/.test(r)),
            "display: none, pinned above every author display rule");
});
