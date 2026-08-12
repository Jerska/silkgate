// controls.js — the control plane's buttons, shared by the overview cards and
// the session detail: freeze/resume, then down, in escalation order, each
// titled with its blast radius; kill (per exec) uses the same machinery beside
// the exec selector. Every POST here fires on an explicit click and never
// automatically — the server's CSRF guard checks the Origin header that
// same-origin fetch already sends, so the click itself is the whole ceremony.
// A failed POST always surfaces the server's {"error"} text — never a silent
// no-op — and a success shows optimistically until the sessions poll confirms.

import { el } from "./render.js";

// POST one control endpoint. Resolves the body; throws with the server's
// {"error"} text when it gave one, a readable fallback when it did not.
export async function controlPost(url) {
  let resp;
  try {
    resp = await fetch(url, { method: "POST" });
  } catch {
    throw new Error("ui server unreachable");
  }
  let body = null;
  try {
    body = await resp.json();
  } catch {
    // no JSON body — the status alone will have to explain
  }
  if (!resp.ok) {
    throw new Error(body?.error != null ? String(body.error)
                    : resp.status === 429 ? "busy — try again shortly"
                    : `HTTP ${resp.status}`);
  }
  return body;
}

// What the down confirm says about uncommitted work, from one explicit diff
// probe. Never throws: a probe the backend cannot answer (no endpoint yet, no
// git workspace, diff busy) is reported as unanswerable, not skipped over.
export async function uncommittedNote(ident) {
  let d;
  try {
    d = await controlPost(`/api/session/${encodeURIComponent(ident)}/diff`);
  } catch (err) {
    return `could not check for uncommitted work (${err.message}).`;
  }
  const dirty = (typeof d?.diff === "string" && d.diff.trim() !== "")
    || (typeof d?.status === "string" && d.status.trim() !== "");
  return dirty ? "uncommitted work present — down destroys it."
               : "no uncommitted work detected.";
}

// What hides for a given session state: archived and downed sessions have
// nothing left to control (the endpoints reject them), frozen swaps freeze
// for resume plus badge. Pure so the gating pins down in node.
export function controlVisibility(state) {
  return {
    root: state === "archived" || state === "down",
    badge: state !== "frozen",
    freeze: state === "frozen",
    resume: state !== "frozen",
  };
}

// The freeze/resume/down bar. getMeta() supplies the freshest meta each time;
// onChanged() is the caller's poll-nudge after a successful action.
export function newControlBar({ ident, getMeta, onChanged = () => {} }) {
  const badge = el("span", { class: "badge frozen" }, "frozen");
  const freeze = el("button", { type: "button",
    title: "pause the VM — nothing is lost, resume continues it" }, "freeze");
  const resume = el("button", { type: "button",
    title: "continue the frozen VM" }, "resume");
  const down = el("button", { type: "button",
    title: "destroy the VM — uncommitted work inside it is lost" }, "down");
  const confirmBox = el("span", { class: "ctl-confirm" });
  const err = el("span", { class: "ctl-err" });
  const root = el("span", { class: "ctl" },
                  badge, freeze, resume, down, confirmBox, err);

  let override = null;             // optimistic state until the poll catches up
  let overrideBase = null;         // the meta state the override replaced

  function state() {
    const s = getMeta()?.state ?? null;
    if (override !== null && s !== overrideBase) {
      override = null;             // the backend answered — its word wins
    }
    return override ?? s;
  }

  function setBusy(b) {
    freeze.disabled = resume.disabled = down.disabled = b;
  }

  async function act(url, next) {
    err.textContent = "";
    const base = getMeta()?.state ?? null;
    setBusy(true);
    try {
      await controlPost(url);
    } catch (e) {
      err.textContent = e.message;
      setBusy(false);
      sync();
      return;
    }
    override = next;
    overrideBase = base;
    setBusy(false);
    onChanged();
    sync();
  }

  freeze.addEventListener("click", () =>
    act(`/api/session/${encodeURIComponent(ident)}/freeze`, "frozen"));
  resume.addEventListener("click", () =>
    act(`/api/session/${encodeURIComponent(ident)}/resume`, "running"));

  // Down is the destructive end of the escalation, so it confirms — and the
  // confirm leads with what a diff probe says about uncommitted work.
  down.addEventListener("click", async () => {
    err.textContent = "";
    setBusy(true);
    confirmBox.textContent = "checking for uncommitted work…";
    const note = await uncommittedNote(ident);
    const yes = el("button", { type: "button" }, "confirm down");
    const no = el("button", { type: "button" }, "cancel");
    confirmBox.textContent = "";
    confirmBox.append(el("span", { class: "ctl-note" }, note + " "), yes, no);
    yes.addEventListener("click", () => {
      confirmBox.textContent = "";
      act(`/api/session/${encodeURIComponent(ident)}/down`, "down");
    });
    no.addEventListener("click", () => {
      confirmBox.textContent = "";
      setBusy(false);
      sync();
    });
  });

  // Re-derive what shows from the current state.
  function sync() {
    const v = controlVisibility(state());
    root.hidden = v.root;
    badge.hidden = v.badge;
    freeze.hidden = v.freeze;
    resume.hidden = v.resume;
  }

  sync();
  return { root, sync };
}

// The per-exec kill button. getUrl() answers the endpoint for the currently
// selected exec, or null when nothing killable is selected (the caller hides
// the control then anyway).
export function newKillControl({ getUrl, onDone = () => {} }) {
  const kill = el("button", { type: "button",
    title: "end this exec's process — the VM and other execs stay up" },
    "kill exec");
  const confirmBox = el("span", { class: "ctl-confirm" });
  const err = el("span", { class: "ctl-err" });
  const root = el("span", { class: "ctl" }, kill, confirmBox, err);

  kill.addEventListener("click", () => {
    err.textContent = "";
    confirmBox.textContent = "";
    kill.disabled = true;
    const yes = el("button", { type: "button" }, "confirm kill");
    const no = el("button", { type: "button" }, "cancel");
    confirmBox.append(
      el("span", { class: "ctl-note" },
         "ends this exec's process — the VM stays up "), yes, no);
    yes.addEventListener("click", async () => {
      confirmBox.textContent = "";
      const url = getUrl();
      if (url) {
        try {
          await controlPost(url);
          onDone();
        } catch (e) {
          err.textContent = e.message;
        }
      }
      kill.disabled = false;
    });
    no.addEventListener("click", () => {
      confirmBox.textContent = "";
      kill.disabled = false;
    });
  });

  return { root };
}
