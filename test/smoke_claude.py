#!/usr/bin/env python3
"""Smoke-test the claude profile in a real guest: what a user does first.

    python3 test/smoke_claude.py

1. Interactive: `silkgate-claude` under a terminal must reach its prompt, with no
   first-run screen in the way and no request the proxy refuses for policy.
2. With SILKGATE_EGRESS_SECRET_ANTHROPIC set: `silkgate-claude -p` must answer.

Needs what `silkgate run` needs: docker, msb, mitmproxy, and network for the first
image build. Not part of tests.py: it boots real guests. CI runs it in smoke.yml.
"""
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI = [sys.executable, str(REPO / "cli" / "silkgate")]
LOGS = Path.home() / ".silkgate" / "logs"
BUILD_TIMEOUT = 900                  # a cold image build downloads Claude Code
PROMPT_TIMEOUT = 120                 # from a warm image to the prompt

# What the screen shows, with ANSI codes and all whitespace removed: Claude Code's TUI
# moves the cursor instead of printing spaces, so words arrive glued together.
READY = "bypasspermissionson"        # the status line on silkgate-claude's prompt
BLOCKERS = {
    "unabletoconnect": "Claude Code couldn't reach Anthropic (a denied startup request?)",
    "doyouwanttousethisapikey": "the custom-API-key question (customApiKeyResponses seed)",
    "choosethetextstyle": "the theme picker (hasCompletedOnboarding seed)",
    "bypasspermissionsmode": "the bypass-permissions warning (bypassPermissionsModeAccepted seed)",
    "trustthisfolder": "the workspace trust dialog (hasTrustDialogAccepted seed)",
}


def screen_text(raw):
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b.", "", raw)
    return re.sub(r"\s+", "", text).lower()


def cli(*args, **kw):
    return subprocess.run(CLI + list(args), capture_output=True, text=True, **kw)


# Hosts Claude Code reaches that the claude profile denies on purpose.
EXPECTED_DENIES = {
    "downloads.claude.ai": "release downloads: the image pins its version",
}


def denied(session):
    """Unexpected policy denies for `session` in the audit trail. A missing secret counts
    only when one was set: without one, the proxy must deny the requests that need it."""
    secret = os.environ.get("SILKGATE_EGRESS_SECRET_ANTHROPIC")
    found = []
    for f in LOGS.glob("events-*.jsonl"):
        for line in f.read_text(errors="replace").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("session") != session or rec.get("decision") != "deny":
                continue
            if not secret and rec.get("reason", "").startswith("missing secret"):
                continue
            if rec.get("host") in EXPECTED_DENIES:
                continue
            found.append(f"{rec.get('method')} {rec.get('host')}{rec.get('path', '')}: "
                         f"{rec.get('reason')}")
    return found


def interactive(session):
    """Run silkgate-claude on a pty until it shows its prompt, a blocker, or times out."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(CLI[0], CLI + ["run", "--name", session, "--tty", "--with", "claude",
                                "--", "silkgate-claude"])
    raw, verdict = "", None
    deadline = time.monotonic() + PROMPT_TIMEOUT
    try:
        while time.monotonic() < deadline and verdict is None:
            ready, _, _ = select.select([fd], [], [], 1)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:              # the child closed the pty: it exited
                break
            if not chunk:
                break
            raw += chunk.decode(errors="replace")
            text = screen_text(raw)
            if READY in text:
                verdict = "ready"
            for marker, why in BLOCKERS.items():
                if marker in text and READY not in text:
                    verdict = why
    finally:
        stop(pid, fd)
        cli("down", session)                    # no-op once the unwind finished
    return verdict, screen_text(raw)[-400:]


def stop(pid, fd, grace=60):
    """TERM the CLI, which unwinds its session, and drain the pty while it does: an
    undrained pty fills, and the unwind blocks writing to it. KILL after `grace`."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if os.waitpid(pid, os.WNOHANG)[0]:
            return
        if select.select([fd], [], [], 0.5)[0]:
            try:
                os.read(fd, 65536)
            except OSError:
                pass
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


def main():
    failures = []
    build = cli("build", "--with", "claude", timeout=BUILD_TIMEOUT)
    if build.returncode:
        sys.exit(f"FAIL build:\n{build.stderr[-2000:]}")

    session = f"smoke-tty-{os.getpid()}"
    verdict, tail = interactive(session)
    if verdict != "ready":
        failures.append(f"interactive: {verdict or 'no prompt within %ss' % PROMPT_TIMEOUT}"
                        f"\n  screen tail: {tail}")
    failures += [f"interactive: denied {d}" for d in denied(session)]
    print(f"{'PASS' if verdict == 'ready' else 'FAIL'} interactive prompt")

    if os.environ.get("SILKGATE_EGRESS_SECRET_ANTHROPIC"):
        session = f"smoke-p-{os.getpid()}"
        run = cli("run", "--name", session, "--no-tty", "--with", "claude", "--",
                  "silkgate-claude", "-p", "Reply with exactly: PONG", timeout=PROMPT_TIMEOUT * 2)
        ok = "PONG" in run.stdout
        if not ok:
            failures.append(f"-p: no PONG (exit {run.returncode})\n  stdout: "
                            f"{run.stdout[-500:]}\n  stderr: {run.stderr[-500:]}")
        failures += [f"-p: denied {d}" for d in denied(session)]
        print(f"{'PASS' if ok else 'FAIL'} -p answers")
    else:
        print("SKIP -p answers: SILKGATE_EGRESS_SECRET_ANTHROPIC is not set")

    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
