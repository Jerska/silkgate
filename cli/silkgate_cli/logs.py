"""silkgate logs: a session's guest output, and its proxy's audit lines."""
import json
import os
import sys
import time
from pathlib import Path

from . import console, mitm, sessions, vm


# --- logs: per-session observability ----------------------------------------
# msb's exec is RPC-shaped — a parent sees nothing until the guest exits — but the
# sandbox's captured log IS live, and there is no `msb logs --follow`, so -f polls it.

def _emit(lines):
    """Print lines and flush now, so follow is live and a closed pipe surfaces promptly."""
    for ln in lines:
        print(ln)
    sys.stdout.flush()


def _logs_guest(args, meta):
    sandbox = meta["sandbox"]
    if not args.follow:                              # one-shot: pass shaping straight to msb
        lines, err = vm._run_msb_logs(sandbox, args.tail, args.since)
        if err is not None:
            console.die(f"cannot read guest logs for {args.name!r}: {err}")
        _emit(lines)
        return
    # Follow: `printed` starts at the current log's length, and each poll re-fetches the
    # whole append-only log and prints the suffix. --tail and --since shape the first view
    # only. --since needs msb's clock, so msb counts the recent lines, after `full` is
    # fetched, so nothing appended between the calls is lost or doubled.
    full, err = vm._run_msb_logs(sandbox)
    if err is not None:
        console.die(f"cannot read guest logs for {args.name!r}: {err}")
    start = 0
    if args.tail is not None:
        start = max(0, len(full) - args.tail)
    elif args.since is not None:
        win, werr = vm._run_msb_logs(sandbox, since=args.since)
        if werr is None:
            start = max(0, len(full) - len(win))
    _emit(full[start:])
    printed = len(full)
    while True:
        time.sleep(args.interval)
        if not sessions.session_dir(args.name).exists():  # someone ran `silkgate down`
            console.die(f"session {args.name!r} is gone — stopped following")
        lines, err = vm._run_msb_logs(sandbox)
        if err is not None:                          # sandbox removed / msb unhappy
            console.die(f"session {args.name!r}: {err} — stopped following")
        n = len(lines)
        if n < printed:                              # rotation/truncation: resync, don't replay
            console.say(f"guest log for {args.name!r} rotated — resyncing")
            printed = n
        elif n > printed:
            _emit(lines[printed:])
            printed = n


def _audit_match(line, name):
    """True iff `line` is a JSON audit record for session `name`.

    mitmdump stamps every log line with a "[HH:MM:SS.mmm] " prefix and emits its own
    connection chatter, so drop everything before the first brace and require a parse.
    """
    brace = line.find("{")
    if brace < 0:
        return False
    try:
        rec = json.loads(line[brace:])
    except ValueError:
        return False
    return isinstance(rec, dict) and rec.get("session") == name


def _read_from(path, offset):
    """Complete (newline-terminated) lines from byte `offset` -> (lines, new_offset), or
    (None, offset) if the file is unreadable. Advances only past whole lines, so a
    half-written trailing line is re-read on the next poll rather than split."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read()
    except OSError:
        return None, offset
    cut = data.rfind(b"\n")
    if cut == -1:
        return [], offset
    chunk = data[:cut + 1]
    return chunk.decode("utf-8", "replace").splitlines(), offset + len(chunk)


def _logs_audit(args):
    proxy = mitm.read_proxy()
    if not proxy or not proxy.get("log"):
        console.die("shared proxy not running — no audit log (silkgate ls)")
    if args.since is not None:
        console.say("--since applies to the guest log only — --audit starts from the whole "
                    "file (--tail trims it)")
    name = args.name
    path = Path(proxy["log"])
    lines, offset = _read_from(path, 0)              # first view = the whole file's history
    if lines is None:
        console.die(f"cannot read audit log {path}")
    matched = [ln for ln in lines if _audit_match(ln, name)]
    if args.tail is not None:
        matched = matched[-args.tail:] if args.tail > 0 else []
    _emit(matched)
    if not args.follow:
        return
    while True:
        time.sleep(args.interval)
        if not sessions.session_dir(name).exists():
            console.die(f"session {name!r} is gone — stopped following")
        p = mitm.read_proxy()
        # Identity, not pid liveness: after an unclean exit proxy.json survives and its
        # pid may be recycled, so only a proxy answering on the control socket counts.
        if not (p and mitm._proxy_running()):
            console.die("shared proxy is gone — stopped following")
        new_path = Path(p.get("log") or path)
        if new_path != path:                         # proxy restarted onto a fresh log file
            console.say("audit log replaced — resyncing")
            path, offset = new_path, 0
        try:
            size = path.stat().st_size
        except OSError:
            console.die(f"audit log {path} vanished — stopped following")
        if size < offset:                            # truncated/rotated in place
            console.say("audit log rotated — resyncing")
            offset = 0
        new_lines, offset = _read_from(path, offset)  # byte offset: only the new tail is read
        if new_lines is None:
            console.die(f"audit log {path} vanished — stopped following")
        _emit([ln for ln in new_lines if _audit_match(ln, name)])


def cmd_logs(args):
    """Stream one session's guest output, or (--audit) its proxy allow/deny decisions.

    A supervising parent sees nothing until an exec exits (msb's exec is RPC-shaped),
    so -f polls the live captured log (there is no `msb logs --follow`). --audit reads
    the shared audit log and keeps only lines whose "session" field is this session."""
    sessions._validate_name(args.name)
    meta = sessions.read_meta(args.name)
    if not meta:
        console.die(f"no such session: {args.name!r} (silkgate ls)")
    if args.tail is not None and args.tail < 0:
        console.die("--tail must be >= 0")
    if args.interval <= 0:
        console.die("--interval must be > 0")
    try:
        if args.audit:
            _logs_audit(args)
        else:
            _logs_guest(args, meta)
    except KeyboardInterrupt:
        # Ctrl-C out of follow: quiet, status 130. os._exit skips interpreter shutdown, which
        # would otherwise re-surface the pending SIGINT as a traceback on stderr.
        sys.stdout.flush()
        os._exit(130)
    except BrokenPipeError:                          # `silkgate logs -f x | head`: quiet exit
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
