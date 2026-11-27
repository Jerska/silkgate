"""The machinery behind the silkgate commands: profiles, images, sessions, the proxy, guests."""
import hashlib
import json
import os
import posixpath
import re
import shutil
import signal
import subprocess
import sys
import termios
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

GUEST_CONTEXT = "/silkgate/CONTEXT.md"        # what the guest is told about its sandbox
GUEST_BRIEF = "/silkgate/BRIEF.md"            # where --brief lands the operator's task
GUEST_EXECS = "/silkgate/execs"               # one pidfile per exec, <exec_id>.pid
TIER1_PROBE_TARGET = "1.1.1.1:443"   # must be a live public service: the probe passes only
                                     # when a connect that WOULD succeed is denied (tier1_fault)

import rule_engine

from . import console, foreground, git, images, mitm, paths, profile


# --- what the guest is told about itself --------------------------------------
# Generated per session from the profiles, ruleset, and mounts, so it can't drift. It saves a
# cooperating agent wasted turns. It's never a control: a hostile guest ignores it.

def session_context(profiles, ruleset, *, mounts=(), persistent, branch=None, checkout=None,
                    brief=False):
    """The markdown a guest gets about its own sandbox.

    `mounts` is the validated -v list as (host, guest, mode). The workspace text follows
    the active mode: branch, checkout, or a /workspace mount's mode. `brief` means a brief
    landed at GUEST_BRIEF, so the guest is pointed at it first."""
    lines = [
        "# Where you are: a silkgate sandbox",
        "",
        "Read this to learn what's installed here, what you can reach, and what survives",
        "this machine.",
        "",
        "**You're in a disposable VM. Every network request goes through a proxy that allows",
        "only the destinations listed below. Nothing inside this machine can widen that.**",
    ]
    if brief:
        lines += ["", f"Your task brief is at `{GUEST_BRIEF}`. Read it first."]
    lines += [
        "",
        "Launch subagents freely for independent work.",
        "",
        "## What's installed",
        "",
    ]
    if profiles:
        # What is installed, so one entry per (name, version) — instances of a profile
        # that differ only in args install the same tools once.
        for p in images._image_profiles(profiles):
            # Named as packages, not commands, since the two differ (ripgrep ships `rg`).
            extra = f", plus packages {', '.join(p.packages)}" if p.packages else ""
            lines.append(f"- `{p.image_spec}`{extra}")
    else:
        lines.append("- Nothing beyond the base image.")
    lines += [
        "",
        "That's all. git, python, pip, make, and compilers are absent unless listed, and",
        "you can't install more: no package mirror is reachable.",
        "",
        "## What survives",
        "",
    ]
    ws_mode = next((mode for _, dst, mode in mounts if dst == "/workspace"), None)
    others = [(dst, mode) for _, dst, mode in mounts if dst != "/workspace"]
    if branch:
        lines += [
            f"**Commit to branch `{branch}` as you go. Commits are the deliverable.**",
            "",
            "- `/workspace` is a checkout of the project on that branch.",
            "- When the session ends, your commits land in the host repo. Everything",
            "  uncommitted is deleted. The host can also collect commits mid-session.",
            "- Never amend or rewrite a commit you made: the branch only moves forward.",
            "- Don't push: no remote accepts it. `origin` is a read-only copy of the host repo,",
            "  so `git log` and `git fetch origin` work.",
        ]
    elif checkout:
        lines += [
            "**Put your results in printed output. Nothing you write leaves this machine,",
            "commits included.**",
            "",
            f"- `/workspace` is a throwaway checkout of the project at `{checkout}`. Local",
            "  commits are fine.",
            "- `origin` is a read-only copy of the host repo, so `git log` and",
            "  `git fetch origin` work. No remote accepts a push.",
        ]
    elif ws_mode == "ro":
        lines += [
            "**Put your results in printed output.** `/workspace` is host code, read-only.",
            "The rest of the filesystem is scratch that dies with this machine.",
        ]
    elif ws_mode == "rw":
        lines += [
            "**What you leave in `/workspace` is the deliverable.** It's a host directory,",
            "read-write. The rest of the filesystem is scratch that dies with this machine.",
        ]
    elif others:
        lines.append("**`/workspace` is scratch that dies with this machine.** No host"
                     " directory is mounted there.")
    else:
        lines.append("**Nothing you write survives this machine.** No host directory is mounted.")
    if others:
        lines += ["", "Other host directories mounted here:", ""]
        for dst, mode in others:
            lines.append(f"- `{dst}`: " + ("read-only." if mode == "ro" else
                                            "read-write. What you leave there lands on the host."))
    lines += [
        "",
        "This machine " + ("stays up between commands, so what you leave behind persists."
                           if persistent else "is destroyed when this command finishes."),
        "",
        "## What you can reach",
        "",
    ]
    if ruleset.rules:
        lines += [
            "**Only these destinations, with these methods.** http and https both go through",
            "the proxy, and the match ignores the scheme.",
            "",
        ]
        for rule in ruleset.rules:
            methods = " ".join(sorted(rule.methods))
            inject = f", injects `{rule.inject_auth}`" if rule.inject_auth else ""
            lines.append(f"- `{rule.raw.split()[0]}`: {methods}{inject}")
        lines += [
            "",
            "In a host, `*` matches one label. In a path, `*` matches one segment. `**` matches",
            "anything, an empty path included. GET is enough to install from a listed registry.",
        ]
    else:
        # An empty allowlist is the strictest policy silkgate can express, and it is a normal
        # configuration rather than a broken one — so say what it means instead of a bare list.
        lines += [
            "**Nothing. The allowlist is empty, so work from what's on this machine.** No host,",
            "port, or protocol works, and there's no DNS.",
        ]
    lines += [
        "",
        "## When a request is refused",
        "",
        "**A refusal is policy, not a broken network. Retrying can't change it.**",
        "",
        "| You see | It means |",
        "|---|---|",
        "| http: a 403 with body `no matching rule` | the proxy refused it |",
        "| https: `CONNECT tunnel failed, response 403` | the proxy refused it, before TLS |",
        "| a 500 with `X-Silkgate: deny` | the proxy failed internally. Report it, don't retry. |",
        "| an error without `X-Silkgate: deny` | the destination answered: fix the request |",
        "",
        "Every proxy refusal carries the `X-Silkgate: deny` response header. `curl -v` shows",
        "it on a refused CONNECT too. A destination could fake it, so treat it as a strong",
        "hint, not proof.",
        "",
        "If you need an unlisted destination, say so in your answer: the host, path, method,",
        "and why. Your printed output is the only channel to whoever set the task.",
    ]
    # A profile can ship a context.md — guidance that travels with the capability,
    # templated like its rules — appended once per instance, so the guest learns how
    # to use each grant it holds.
    for p in profiles:
        snippet = p.rendered_context().strip()
        if snippet:
            lines += ["", snippet]
    inject_names = sorted({r.inject_auth for r in ruleset.rules if r.inject_auth})
    if inject_names:
        lines += [
            "",
            "## Credentials",
            "",
            "**The key or token in your environment is a placeholder. Use it as if it were",
            "real.** The proxy swaps in the real value, which never enters this machine. It only",
            "replaces a header you send, never adds one. So a request without the header gets a",
            "real 401 from the destination: add the header and resend.",
            "",
            "Status at launch:",
            "",
        ]
        for name in inject_names:
            value = os.environ.get(f"SILKGATE_EGRESS_SECRET_{name.upper()}")
            parsed = rule_engine._parse_secret(value) if value else None
            if parsed is not None:
                # The guest learns the header's name, never any part of its value.
                status = f"available. The proxy fills in the `{parsed[0]}` header."
            else:
                reason = "not set" if not value else "not a valid header line"
                status = (f"missing ({reason}). Requests that need it will be denied. Tell"
                          " whoever set your task: a retry can't fix it.")
            lines.append(f"- `inject_auth={name}`: {status}")
    return "\n".join(lines) + "\n"


# --- persistent sessions: host state ----------------------------------------

def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _write_json(path, obj):
    """Atomic-ish write: temp file then rename, so a reader never sees half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj))
    tmp.replace(path)


def _read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def session_dir(name):
    return paths.SESSIONS_DIR / name


def sandbox_name(name):
    return f"sg-{name}"


_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
# What msb accepts as a sandbox name. meta.json's "sandbox" reaches `msb exec`/`msb rm` argv,
# so it is held to this before it is used — a value msb would read as a flag is not a name.
_SANDBOX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def _name_ok(name):
    return bool(_NAME_RE.fullmatch(name or ""))


def _validate_name(name):
    # Used as a dir name, an msb sandbox name (sg-<name>), and a net-rule component.
    if not _name_ok(name):
        console.die(f"invalid session name {name!r} (letters, digits, '-', '_'; ≤32 chars)")


# A session id outlives the session: it names the archive dir and threads through the
# journal, so it packs chronology (a UTC stamp first, making plain name order time
# order), identity (the session name) and uniqueness (6 random hex) into one string
# that is safe as a path component. Session names can repeat across time; sids cannot.
_SID_RE = re.compile(r"\d{8}T\d{6}Z-[A-Za-z0-9][A-Za-z0-9_-]{0,31}-[0-9a-f]{6}")


def _new_sid(name):
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{name}-{uuid4().hex[:6]}"


# How much argv text one journal record holds. argv carries the whole prompt, and the
# journal has no other cap, so it's cut here with a "..." tail. A few KiB keeps a prompt's
# head readable, and a loop of huge prompts costs megabytes, never gigabytes.
_JOURNAL_ARGV_LIMIT = 8192


def _clip_argv(argv):
    """argv for one journal record: whole elements until the limit, the element that
    crosses it cut with a '...' tail, everything after dropped."""
    out, spent = [], 0
    for arg in argv:
        s = str(arg)
        if spent + len(s) > _JOURNAL_ARGV_LIMIT:
            out.append(s[:_JOURNAL_ARGV_LIMIT - spent] + "...")
            break
        out.append(s)
        spent += len(s)
    return out


def _journal(name, event, **fields):
    """Append one event record to a session's journal (journal.jsonl in its dir).

    Bookkeeping fails open, so this warns and never raises: a teardown must never block on
    it. Each record is one os.write on an O_APPEND descriptor, so concurrent execs
    interleave whole records, never bytes.

    argv holds the operator's prompt, on purpose, bounded by _clip_argv. Env vars appear
    as names only.
    """
    _journal_into(session_dir(name), event, **fields)


def _journal_into(sdir, event, **fields):
    """_journal against an explicit directory — for the one record (`created`) that
    must land in the staging dir, before the rename makes the session appear."""
    try:
        if isinstance(fields.get("argv"), (list, tuple)):
            fields["argv"] = _clip_argv(fields["argv"])
        record = json.dumps({"ts": now_iso(), "event": event, **fields})
        fd = os.open(sdir / "journal.jsonl",
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (record + "\n").encode())
        finally:
            os.close(fd)
    except Exception as e:                     # never raise: bookkeeping, not enforcement
        console.say(f"warning: could not journal {event!r} for {sdir.name}: {e}")


def _end_exec(name, exec_id, rc):
    """Close one exec bracket: the exec_end record, then meta["last_rc"] — the newest
    exec's rc, kept in meta so `ls` and the dashboard can show it without reading the
    journal. Both are bookkeeping: fail-open, never raising. last_rc is written only
    for a known rc; a null rc stays a journal-only fact."""
    _journal(name, "exec_end", exec_id=exec_id, rc=rc)
    if not isinstance(rc, int):
        return
    mpath = session_dir(name) / "meta.json"
    meta = _read_json(mpath)
    if meta is None:                             # torn down mid-exec: nowhere to record
        return
    try:
        _write_json(mpath, {**meta, "last_rc": rc})
    except Exception as e:
        console.say(f"warning: could not record last_rc for {name!r}: {e}")


def _bracketed_exec(name, exec_id, run):
    """run(), with an exec_end journaled even when it's interrupted. An interrupt records
    the shell's rc (130 for Ctrl-C, 128+signo for a signal), or null when unknown. A
    missing exec_end means this process crashed."""
    rc = None
    try:
        rc = run()
        return rc
    except KeyboardInterrupt:
        rc = 130
        raise
    except SystemExit as e:
        if isinstance(e.code, int):
            rc = e.code
        raise
    finally:
        _end_exec(name, exec_id, rc)


def _read_journal(path):
    """Parsed journal records, oldest first. Torn or foreign lines are skipped rather
    than fatal: a crash can cut an append mid-line, and one bad line must not hide the
    history around it."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    records = []
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return records


def _clean_abs_path(value):
    """Whether a meta path is absolute and free of control characters — the bar it must
    clear before reaching git argv, an rmtree decision, or a terminal."""
    s = str(value)
    return s.startswith("/") and not any(ord(c) < 0x20 or ord(c) == 0x7f for c in s)


def _check_meta_fields(meta):
    """Why this meta.json's fields cannot be used, or None — shared by the live registry
    and the archive, because the UI's diff puts archived meta fields into git argv too,
    so they are held to read_meta's bar. Every field is optional on read; only a present
    field with a bad value refuses."""
    sandbox = meta.get("sandbox")
    if sandbox is not None and not _SANDBOX_RE.fullmatch(str(sandbox)):
        return f"its meta.json names sandbox {sandbox!r}"
    # sid becomes a path component of ARCHIVE_DIR at teardown (sdir.rename), where a
    # '..' or absolute value would move the whole session dir — journal included —
    # anywhere the planter names. Same bar the archive read side already holds it to.
    if meta.get("sid") is not None and not _SID_RE.fullmatch(str(meta["sid"])):
        return f"its meta.json names sid {meta['sid']!r}"
    if meta.get("branch") is not None:
        # Branch metas add git argv (branch, base) and an rmtree decision (repo_root via
        # _reap_derived_workspace) — same refusal as sandbox above for a planted meta.
        branch, base = str(meta["branch"]), str(meta.get("base", ""))
        if (not git._BRANCH_RE.fullmatch(branch) or ".." in branch
                or not git._BASE_RE.fullmatch(base)):
            return f"its meta.json names branch {branch!r}"
    elif meta.get("checkout") is not None:
        # A checkout meta carries base into git argv the same way a branch one does.
        if not git._BASE_RE.fullmatch(str(meta.get("base", ""))):
            return f"its meta.json names base {meta.get('base')!r}"
    for field in ("git_dir", "workspace"):
        if meta.get(field) is not None and not _clean_abs_path(meta[field]):
            return f"its meta.json has invalid {field} field"
    return None


def read_meta(name):
    """One session's meta.json, or None when there is no such session.

    Every command that takes a session name comes through here, so this checks it. The
    name is a path component, so '..' would read a meta.json from outside the registry,
    and its fields become msb argv and an rmtree target. A meta that disagrees with its
    directory is refused.
    """
    _validate_name(name)
    meta = _read_json(session_dir(name) / "meta.json")
    if meta is None:
        return None
    if meta.get("name") != name:
        console.die(f"session {name!r}: its meta.json names session {meta.get('name')!r} — "
                    "refusing it")
    bad = _check_meta_fields(meta)
    if bad:
        console.die(f"session {name!r}: {bad} — refusing it")
    return meta


def list_metas():
    if not paths.SESSIONS_DIR.is_dir():
        return []
    metas = []
    for d in sorted(paths.SESSIONS_DIR.iterdir()):
        if d.name.startswith(".") or not _name_ok(d.name):   # not something silkgate created
            continue
        m = read_meta(d.name)
        if m:
            metas.append(m)
    return metas


def read_archived_meta(sid):
    """One archived session's meta.json, or None when no archive holds that sid.

    Read with read_meta's checks: the sid is a path component, the meta must name its own
    directory's sid, and every field is checked, because the UI's diff puts archived meta
    fields into git argv."""
    if not _SID_RE.fullmatch(sid or ""):
        console.die(f"invalid archive sid {sid!r}")
    meta = _read_json(paths.ARCHIVE_DIR / sid / "meta.json")
    if meta is None:
        return None
    if meta.get("sid") != sid:
        console.die(f"archived session {sid!r}: its meta.json names sid {meta.get('sid')!r} — "
                    "refusing it")
    bad = _check_meta_fields(meta)
    if bad:
        console.die(f"archived session {sid!r}: {bad} — refusing it")
    return meta


def list_archived_metas():
    """Every archived session's meta, oldest first — a sid opens with its UTC stamp, so
    the plain name sort is chronological."""
    if not paths.ARCHIVE_DIR.is_dir():
        return []
    metas = []
    for d in sorted(paths.ARCHIVE_DIR.iterdir()):
        if not _SID_RE.fullmatch(d.name):            # not something silkgate archived
            continue
        m = read_archived_meta(d.name)
        if m:
            metas.append(m)
    return metas


# --- msb session guests -----------------------------------------------------

def _msb():
    return console.which("msb", "curl -fsSL https://install.microsandbox.dev | sh")


def msb_argv(image, cmd, port, *, pull_never=True, mounts=()):
    """One-shot `msb run` of a guest locked to one proxy port (the verify path)."""
    argv = [console.which("msb", "curl -fsSL https://install.microsandbox.dev | sh"), "run", image]
    if pull_never:
        argv += ["--pull", "never"]
    for m in mounts:
        argv += ["-v", m]
    url = f"http://{mitm.PROXY_ALIAS}:{port}"
    for var in mitm.PROXY_ENV_VARS:
        argv += ["-e", f"{var}={url}"]
    argv += ["--net-default-egress", "deny", "--net-rule", f"allow@host:tcp:{port}"]
    return argv + ["--"] + list(cmd)


def msb_create_argv(sandbox, image, port, *, mounts=(), env=(), copies=(),
                    memory=None, cpus=None):
    """A backgrounded, idling guest whose only egress is its own proxy port."""
    argv = [_msb(), "create", image, "--name", sandbox, "--pull", "never"]
    if memory:                                          # sized by --memory; else msb's default
        argv += ["-m", memory]
    if cpus:                                            # set by --cpus; else msb's default
        argv += ["-c", cpus]
    for m in mounts:
        argv += ["-v", m]
    for src, dst in copies:                             # into the rootfs, before boot
        argv += ["--copy-file", f"{src}:{dst}"]
    url = f"http://{mitm.PROXY_ALIAS}:{port}"
    for var in mitm.PROXY_ENV_VARS:                     # inherited by every later exec
        argv += ["-e", f"{var}={url}"]
    for pair in env:
        argv += ["-e", pair]
    argv += ["--net-default-egress", "deny", "--net-rule", f"allow@host:tcp:{port}"]
    return argv


def msb_exec_argv(sandbox, cmd, *, tty=False, env=()):
    argv = [_msb(), "exec", "-q"]                       # -q silences msb progress noise
    if tty:
        argv.append("-t")
    for pair in env:
        argv += ["-e", pair]
    return argv + [sandbox, "--"] + list(cmd)


def _run_msb_logs(sandbox, tail_n=None, since=None):
    """`msb logs` for one sandbox -> (lines, None) or (None, error). Non-zero/OSError => gone."""
    argv = [_msb(), "logs", sandbox]
    if tail_n is not None:
        argv += ["--tail", str(tail_n)]
    if since is not None:
        argv += ["--since", since]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True)
    except OSError as e:
        return None, str(e)
    if proc.returncode:
        return None, (proc.stderr.strip() or f"msb logs exited {proc.returncode}")
    return proc.stdout.splitlines(), None


# --- Tier-1 probe -------------------------------------------------------------
# Tier 1 rests on msb's --net-default-egress and --net-rule flags meaning what they did when
# verified. msb is pre-1.0, and an msb that parses the flags but enforces less would leave
# every session open while silkgate reports success. So no session is handed over until a
# probe inside the new guest shows the deny is real. It's a canary, not a boundary: a hostile
# --image controls the shell that prints the verdict, but the caller chose that image.

def tier1_probe_cmd(port):
    """The in-guest probe command: two bounded connects, one verdict token on stdout.

    Both use bash's /dev/tcp, with no DNS (an IP literal and an /etc/hosts alias), so
    `timeout` bounds the one slow path, a dropped SYN:

      - TIER1_PROBE_TARGET, a live public service, must NOT connect, else TIER1_LEAK. A
        refusal and a drop both count as denied.
      - The session's proxy port MUST connect, else TIER1_NOPROXY. That proves the first
        failure was a deny, not a broken probe, and the guest needs a working proxy anyway.

    An image without bash or timeout reports TIER1_UNTESTABLE:<tool>.
    """
    host, _, target_port = TIER1_PROBE_TARGET.partition(":")
    return ["sh", "-c",
            "command -v bash >/dev/null || { echo TIER1_UNTESTABLE:bash; exit 0; }; "
            "command -v timeout >/dev/null || { echo TIER1_UNTESTABLE:timeout; exit 0; }; "
            f"if timeout 1 bash -c 'exec 3<>/dev/tcp/{host}/{target_port}' 2>/dev/null; "
            "then echo TIER1_LEAK; "
            f"elif timeout 1 bash -c 'exec 3<>/dev/tcp/{mitm.PROXY_ALIAS}/{port}' 2>/dev/null; "
            "then echo TIER1_OK; else echo TIER1_NOPROXY; fi"]


def tier1_verdict(stdout, port, *, error=None):
    """Map one probe run to None (hand the session over) or the refusal message.

    Only an explicit TIER1_OK from a clean run passes. Anything else refuses: the caller
    may be an agent that never reads warnings, so "couldn't test" must never look like
    "tested and held".
    """
    if error:
        return (f"could not run the Tier-1 probe ({error}); containment is unproven, and "
                "an unproven session is not handed over. Session torn down.")
    token = next((ln.strip() for ln in stdout.splitlines()
                  if ln.strip().startswith("TIER1_")), "")
    if token == "TIER1_OK":
        return None
    if token == "TIER1_LEAK":
        return ("TIER-1 CONTAINMENT IS NOT IN EFFECT: the guest connected straight to "
                f"{TIER1_PROBE_TARGET}, around the proxy, so nothing silkgate enforces "
                "was going to bind this session. Suspect msb itself — its --net-* flag "
                "grammar is pre-1.0 and unpinned; re-run `silkgate verify` and pin an msb "
                "whose deny holds (README: Installing microsandbox). Session torn down.")
    if token == "TIER1_NOPROXY":
        return (f"Tier-1 probe: direct egress to {TIER1_PROBE_TARGET} is denied, but the "
                f"guest could not reach its own proxy at {mitm.PROXY_ALIAS}:{port}. A denial "
                "cannot be told from a dead guest network, and a session whose proxy is "
                "unreachable could not carry traffic anyway. Session torn down.")
    if token.startswith("TIER1_UNTESTABLE:"):
        return ("cannot test Tier-1 containment: the guest image has no "
                f"{token.partition(':')[2]!r}, which the probe needs (silkgate-built "
                "images carry bash + coreutils; a custom --image must too). An untestable "
                "session is not handed over. Session torn down.")
    return (f"the Tier-1 probe printed {stdout.strip()!r} instead of a verdict; "
            "containment is unproven, and an unproven session is not handed over. "
            "Session torn down.")


def tier1_fault(sandbox, port):
    """Probe a just-created guest; return None if Tier 1 holds, else why it must refuse.

    Callers run this between create and first use and tear the session down on anything
    but None — a hard stop, never a warning above a working prompt, because a silent loss
    of containment is the exact failure mode this exists to close.
    """
    argv = msb_exec_argv(sandbox, tier1_probe_cmd(port))
    # stdin is closed: msb exec waits for stdin EOF, and a detached caller's pipe never
    # closes, so the exec would time out on a healthy guest.
    # In-guest waits cap at 1 s each. 15 s covers msb exec itself stalling, which has one
    # known benign cause: msb 0.5.4 can swallow the FIRST exec after a create, and never
    # answer. Only that first exec loses, so one retry with a new exec process recovers it.
    # A second timeout, a nonzero exit, or a bad verdict is an answer, and isn't retried.
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=15)
    except subprocess.TimeoutExpired:
        try:
            proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=15)
        except subprocess.TimeoutExpired:
            return tier1_verdict("", port, error="msb exec did not return within 15s")
        console.say("note: the first Tier-1 probe exec timed out — the msb relay race (msb 0.5.4 "
                    "swallows the first exec after create); a fresh exec client answered")
    if proc.returncode:
        detail = (proc.stderr.strip() or proc.stdout.strip()).splitlines()
        return tier1_verdict(proc.stdout, port,
                             error=f"msb exec exited {proc.returncode}"
                                   + (f": {detail[-1]}" if detail else ""))
    return tier1_verdict(proc.stdout, port)


# A PTY makes programs emit terminal control: colors, cursor moves, and a reset burst on
# exit. Downstream of the relay stdout is a pipe or a file, so those bytes are never drawn —
# they just corrupt logs and break JSON parsers. Strip them and keep the text.
_ANSI = re.compile(rb"\x1b\[[0-9:;<=>?]*[ -/]*[@-~]"        # CSI: params per ECMA-48, so the
                                                            # "<=>?" private forms match too
                   rb"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)"  # OSC, incl. one cut off at EOL
                   rb"|\x1b[()][A-Za-z0-9]"                # charset selection
                   rb"|\x1b[=>78]"                         # keypad / cursor save-restore
                   rb"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # stray control bytes (keeps \t, \n)


def _plain(line):
    return _ANSI.sub(b"", line.rstrip(b"\r"))


# msb streams output live only when its stdout is a terminal, so a run needs a PTY. But the
# command must not hold it: it would turn interactive (colors, cursor codes) and merge its
# streams. So the command writes to two FIFOs, and two loops relay them into the PTY,
# tagging each line: RS for stderr, US for stdout.
#
# Both streams get a tag, because the leading byte picks the stream: a bare stdout line
# that opened with RS would read as stderr. Tagged, the command's bytes land after column
# zero, where _plain strips any tag, so its output stays data. A guest that bypasses the
# wrapper can still pick a stream, but its text never carries RS, silkgate's own mark.
#
# The shell waits for both loops, so no trailing line is lost, and $? stays the command's.
# Needs POSIX sh and mkfifo. stdin is /dev/null.
#
# SILKGATE_CONTEXT holds the context text, not a path, so a prompt can inline it. It's
# exported here, not passed with `msb -e`, because msb aborts on an env value that holds a
# newline.
_EXPORT_CONTEXT = ('[ -f %s ] && SILKGATE_CONTEXT=$(cat %s) && export SILKGATE_CONTEXT; '
                   % (GUEST_CONTEXT, GUEST_CONTEXT))

# What a journaled exec sets up in the guest, before the wrapper shell:
# - an X-Silkgate-Exec header in ANTHROPIC_CUSTOM_HEADERS, the SDK's hook for extra
#   headers, so the proxy can attribute API traffic to this exec. A caller's existing
#   value keeps its lines, and the marker goes on a new one.
# - a pidfile, which the kill endpoint signals. The wrapper's EXIT trap removes it, so a
#   missing pidfile means "already ended".
# Both are best-effort: the snippet swallows its own errors, and the command still runs.
def _exec_marker_sh(exec_id):
    if not exec_id:
        return ""
    return ('ANTHROPIC_CUSTOM_HEADERS="${ANTHROPIC_CUSTOM_HEADERS:+'
            '${ANTHROPIC_CUSTOM_HEADERS}\n'
            f'}}X-Silkgate-Exec: {exec_id}"; export ANTHROPIC_CUSTOM_HEADERS; '
            f'{{ mkdir -p {GUEST_EXECS} && printf %s "$$" >{GUEST_EXECS}/{exec_id}.pid; }} '
            '2>/dev/null || :; '
            f'trap "rm -f {GUEST_EXECS}/{exec_id}.pid 2>/dev/null" EXIT; ')


_RELAY_SH = (_EXPORT_CONTEXT
             + 'd=$(mktemp -d); mkfifo "$d/o" "$d/e"; '
             f'while IFS= read -r l || [ -n "$l" ]; do printf "\\{ord(console._OUT_TAG):03o}%s\\n" "$l"; done <"$d/o" & po=$!; '
             f'while IFS= read -r l || [ -n "$l" ]; do printf "\\{ord(console._ERR_TAG):03o}%s\\n" "$l"; done <"$d/e" & pe=$!; '
             '"$@" </dev/null >"$d/o" 2>"$d/e"; rc=$?; wait $po $pe; rm -rf "$d"; exit $rc')


def run_guest(build_argv, cmd, *, tty, on_line=None, exec_id=None):
    """Run a guest command and return its exit code.

    Without a TTY, the command gets pipes, and its output still arrives live, on our own
    two streams (_RELAY_SH). With `tty`, it gets a real terminal for a TUI, and draws on the
    screen directly, so it can imitate say(). The voice mark only holds where guest bytes
    pass through this process.

    `exec_id` threads the exec marker into whichever wrapper shell runs (see
    _exec_marker_sh); None runs unmarked, as silkgate's own setup execs do.
    """
    marker = _exec_marker_sh(exec_id)
    if tty:
        # A terminal run gets no relay, so the context export needs its own tiny shell.
        # A marked exec keeps that shell (no exec): its EXIT trap is what removes the
        # pidfile, and the command shares the shell's process group either way, so the
        # kill endpoint's group signal reaches it the same.
        tail = '"$@"' if marker else 'exec "$@"'
        cmd = ["sh", "-c", _EXPORT_CONTEXT + marker + tail, "_"] + list(cmd)
        if sys.stdout.isatty():
            # Inheriting a real terminal is what keeps a TUI fully interactive — and
            # what lets an interrupted TUI leave that terminal in raw mode, so the
            # settings are guarded, and an exit mid-wait (SIGTERM, SIGHUP) stops the
            # child instead of orphaning it against a sandbox about to be removed.
            with foreground._guarded_terminal():
                proc = subprocess.Popen(build_argv(cmd))
                try:
                    return foreground.wait_foreground(proc)
                finally:
                    foreground.stop(proc)
        return _pty_relay(build_argv(cmd), demux=False, on_line=on_line)
    return _pty_relay(build_argv(["sh", "-c", marker + _RELAY_SH, "_"] + list(cmd)),
                      demux=True, on_line=on_line)


def _pty_relay(argv, *, demux, on_line=None):
    """Run argv with a PTY for its stdio and copy what it writes to our own streams.

    `demux` splits the tagged lines back out and drops terminal control bytes. Without it,
    bytes pass through for a TUI, except RS, which say()'s mark relies on.

    SIGINT is ignored while the child runs, as in wait_foreground: Ctrl-C reaches the child
    through the terminal, and the parent stays to relay its last output and return its
    status. A child still running on the way out (SIGTERM, or our stdout closed) is
    stopped, never orphaned against a sandbox about to be removed.
    """
    previous = signal.signal(signal.SIGINT, lambda *a: None)
    ptm, pts = os.openpty()
    proc = None
    try:
        attrs = termios.tcgetattr(pts)                  # no echo: our EOF byte below would
        attrs[3] &= ~termios.ECHO                       # otherwise come back as "^D"
        termios.tcsetattr(pts, termios.TCSANOW, attrs)
        proc = subprocess.Popen(argv, stdin=pts, stdout=pts, stderr=pts)
        os.close(pts)
        if not sys.stdin.isatty():
            os.write(ptm, b"\x04")                      # EOF: nothing will type at this PTY
        buf = b""
        while True:
            try:
                chunk = os.read(ptm, 65536)
            except OSError:                             # slave closed — the child is done
                break
            if not chunk:
                break
            if not demux:
                sys.stdout.buffer.write(chunk.replace(console._ERR_TAG, b""))
                sys.stdout.buffer.flush()
                continue
            buf += chunk
            while b"\n" in buf:                         # a line is the unit for both the
                line, buf = buf.split(b"\n", 1)         # stderr tag and ANSI stripping
                _relay(line, newline=True, on_line=on_line)
        if buf:
            _relay(buf, newline=False, on_line=on_line)
        return foreground.wait_foreground(proc)
    finally:
        os.close(ptm)
        if proc is not None:
            foreground.stop(proc)                       # reaped already on the clean path
        signal.signal(signal.SIGINT, previous)


def _relay(line, *, newline, on_line=None):
    """Write one relayed line to our stdout, or to stderr if the wrapper tagged it so.

    Only the leading byte routes. RS or US anywhere else is guest content, and _plain
    drops it. Untagged lines (msb's noise, a wrapper that died early) go to stdout, which
    claims nothing. `on_line` sees the same cleaned text a reader does.
    """
    tag = line[:1]
    stream = sys.stderr.buffer if tag == console._ERR_TAG else sys.stdout.buffer
    text = _plain(line[1:] if tag in (console._ERR_TAG, console._OUT_TAG) else line)
    stream.write(text + b"\n" if newline else text)
    stream.flush()
    if on_line is not None:
        on_line(text.decode(errors="replace"))


# Mounts are the only host paths a guest ever sees. Even read-only access to home,
# silkgate's own state, or the checkout this CLI runs from exposes credentials and
# configuration — so the guard applies regardless of the mount mode.
# This, _RESERVED_DSTS, and _mount_args are mirrored in README.md (Mounts). Update both.
def _forbidden_mounts():
    return ((Path.home(), "your home directory"),
            (paths.SILK_DIR,
             "silkgate's own state (session rulesets, the control socket, the CA)"),
            (paths.REPO, "the silkgate checkout this CLI runs from"))


def _find_git_dir(root):
    """The first `.git` directory at or under `root`, or None. The walk never follows
    symlinks, so it is bounded by the tree the user chose to mount and cannot leave it."""
    for dirpath, dirnames, _ in os.walk(root):
        if ".git" in dirnames:
            return Path(dirpath) / ".git"
    return None


# Guest paths silkgate populates: /silkgate (context, scripts, base.git), /root/lfsstore, and
# /root/gitdir (a branch session's clone). A -v at or under one would shadow it. One above
# it is as bad: it nests virtiofs, and would put a branch clone's hooks on a host directory.
# So the refusal runs both ways.
_RESERVED_DSTS = ("/silkgate", "/root/lfsstore", "/root/gitdir")


def _split_mount(spec):
    """One -v value, SRC:DST[:MODE] -> (src, dst, mode), or None if malformed. MODE is
    exactly `ro` or `rw` and defaults to `ro` — write access to host files is asked for,
    never implied. The path rules live in _mount_pair; this is syntax alone."""
    parts = spec.split(":")
    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1], "ro"
    if len(parts) == 3 and parts[0] and parts[1] and parts[2] in ("ro", "rw"):
        return parts[0], parts[1], parts[2]
    return None


def _normalize_dst(dst):
    """One comparable form per guest path, so the duplicate/nesting guards cannot be
    dodged by spelling: `.`/`..`/`//` collapse (POSIX's special leading // included —
    it means nothing to the guest)."""
    d = posixpath.normpath(dst)
    return "/" + d.lstrip("/") if d.startswith("/") else d


def _mount_pair(src, dst, mode, *, allow_git_dir=False):
    """One mount, both sides checked -> (resolved host path, normalized guest path).

    Host side:
    - _forbidden_mounts (credentials, configuration) is refused in either mode.
    - An rw mount is refused if it holds a `.git` directory anywhere, not just at its
      root: hooks and config there would become guest-writable. A root-only check would
      be trusted as if it checked everything.
    - A linked worktree passes: its `.git` is a file that points outside the mount.
    - --allow-git-dir skips the walk, so the risk sits on a command line a human
      approved, never in an env var that outlives the decision. An ro mount skips it too.

    Guest side: DST is absolute, isn't `/`, and doesn't touch _RESERVED_DSTS.
    """
    w = Path(src).resolve()
    if not w.is_dir():
        console.die(f"mount source is not a directory: {w}")
    if w.parent == w:
        console.die(f"refusing to mount {w}: that is the whole filesystem")
    for path, what in _forbidden_mounts():
        target = Path(path).resolve()
        if w == target or w in target.parents:
            console.die(f"refusing to mount {w}: it is (or contains) {what} — credentials and "
                        "configuration there must not be exposed to the guest")
    d = _normalize_dst(dst)
    if not d.startswith("/"):
        console.die(f"mount destination {dst!r} is not absolute — guest paths start at /")
    if d == "/":
        console.die(f"refusing to mount {w} over the guest's whole filesystem")
    for reserved in _RESERVED_DSTS:
        if d == reserved or d.startswith(reserved + "/") or reserved.startswith(d + "/"):
            console.die(f"refusing to mount at {d}: it is (or contains) {reserved}, silkgate's "
                        "own path in the guest")
    if mode == "ro":
        if (w / ".git").is_file():
            console.say(f"note: {w} is a linked git worktree — the .git pointer file is in the "
                        "read-only mount, but hooks and config live outside it")
        return str(w), d
    if allow_git_dir:
        console.say(f"note: --allow-git-dir — {w} is mounted without the .git check, so hooks and "
                    "config of any repository inside are guest-writable: host code execution the "
                    "next time a human runs git there")
    else:
        dotgit = _find_git_dir(w)
        if dotgit is not None:
            where = "" if dotgit.parent == w else f" (at {dotgit.parent.relative_to(w)})"
            console.die(f"refusing to mount {w} at {d} read-write: it holds a .git "
                        f"directory{where}, so the guest would get read-write access to hooks and "
                        "config — host code execution the next time you run git there. Mount a "
                        "linked worktree instead (git worktree add), mount it read-only, or "
                        "accept the risk explicitly with --allow-git-dir.")
    if (w / ".git").is_file():
        console.say(f"note: {w} is a linked git worktree — hooks and config live outside the "
                    "mount and are beyond the guest's reach, but the .git pointer file itself is "
                    "not")
    return str(w), d


def _mount_args(specs, *, allow_git_dir=False):
    """Every -v flag validated -> [(host, guest, mode)], in flag order.

    Refused here: two mounts at one DST (the VMM silently keeps the last), a DST nested
    under another (unverified nested virtiofs), and --allow-git-dir with no rw mount,
    since a flag accepted and ignored reads as honored.
    """
    mounts = []
    for spec in specs or ():
        parsed = _split_mount(spec)
        if parsed is None:
            console.die(f"invalid mount {spec!r} — expected SRC:DST[:ro|rw] (MODE defaults to ro)")
        host, guest = _mount_pair(*parsed, allow_git_dir=allow_git_dir)
        for _, other, _ in mounts:
            if guest == other:
                console.die(f"duplicate mount destination {guest} — one guest path takes one "
                            "mount")
            inner, outer = sorted((guest, other), key=len)
            if outer.startswith(inner + "/"):
                console.die(f"mount destinations {inner} and {outer} nest — nested virtiofs "
                            "behavior is unverified, so it is refused rather than trusted")
        mounts.append((host, guest, parsed[2]))
    if allow_git_dir and not any(mode == "rw" for _, _, mode in mounts):
        console.die("--allow-git-dir does nothing here — the .git risk it accepts only exists "
                    "for a read-write -v mount")
    return mounts


def _provision_session(name, image, port, rules_text, ruleset, mounts, ws, env, meta_extra,
                       context=None, context_paths=(), settings=None, settings_paths=(),
                       memory=None, cpus=None, brief=None):
    """Stage the session dir, rename it into the registry, then boot the guest.

    The rename makes the session appear atomically, so the addon never caches a half-written
    one. On failure, undo only what's ours: the staging dir, the renamed dir if we renamed
    it, the port claim, any half-created sandbox, and the proxy if nothing else needs it."""
    sdir = session_dir(name)
    if sdir.exists():
        console.die(f"session already exists: {sdir}")
    tmp = paths.SESSIONS_DIR / f".tmp-{name}"            # dot-prefixed: invisible to registries
    shutil.rmtree(tmp, ignore_errors=True)               # stale leftover from a crash
    tmp.mkdir(parents=True)
    owned = False                                        # whether the rename made sdir ours
    created = False                                      # whether msb create was reached
    try:
        (tmp / "rules.txt").write_text(rules_text)
        if context:
            (tmp / "context.md").write_text(context)
        if settings:
            (tmp / "settings.json").write_text(settings)
        if brief is not None:
            (tmp / "brief.md").write_bytes(brief)
        meta = {"name": name, "sandbox": sandbox_name(name), "sid": _new_sid(name),
                "port": port, "image": image, "workspace": ws,
                "created": now_iso(), **meta_extra}
        _write_json(tmp / "meta.json", meta)
        # Into the staging dir, right after meta.json: the rename below is what makes
        # the session appear, so it appears with its journal already begun.
        _journal_into(tmp, "created", meta=meta)
        try:
            tmp.rename(sdir)                             # atomic claim; fails if name raced us
            owned = True
        except OSError:
            console.die(f"session already exists: {sdir}")
        mitm._push_secrets(ruleset, name)
        # The context goes into the rootfs, never the workspace: it must not appear in the
        # user's project, and a guest rewriting it changes nothing that matters. The
        # projected settings ride the same mechanism to each profile's settings_path,
        # and the brief too, to the one path the guest is told to read.
        copies = [(sdir / "context.md", dst) for dst in context_paths] if context else []
        if settings:
            copies += [(sdir / "settings.json", dst) for dst in settings_paths]
        if brief is not None:
            copies.append((sdir / "brief.md", GUEST_BRIEF))
        created = True
        if subprocess.run(msb_create_argv(sandbox_name(name), image, port, mounts=mounts,
                                          env=env, copies=copies, memory=memory,
                                          cpus=cpus)).returncode:
            console.die(f"msb create failed for session {name!r}")
    except BaseException:                                # incl. SystemExit from die()
        with foreground._deferred_interrupts():          # a Ctrl-C cannot halve the unwind
            if created:                                  # failed or cut short, a create
                _remove_sandbox(sandbox_name(name))      # can still have registered it
            shutil.rmtree(tmp, ignore_errors=True)
            if owned:
                shutil.rmtree(sdir, ignore_errors=True)
            mitm._release_port(name, port)
            _maybe_stop_proxy()                          # a failure that left the registry
        raise                                            # empty leaves no proxy over it


# What each msb call gets during a removal before it is treated as hung. Teardowns run
# under _deferred_interrupts, and a deferral is only honest while the thing it shields
# is bounded: three calls at 30s each is the worst wait, after which the failure is
# reported as a sandbox that could not be confirmed gone — never waited out silently.
_MSB_TIMEOUT = 30


def _remove_sandbox(sandbox):
    """Best-effort `msb stop` then `msb rm`. True only if the sandbox is verifiably gone.

    An rm failure counts as gone when `msb list` no longer shows the name, as for a sandbox
    that never registered. The msb children run in their own sessions, so a Ctrl-C can't
    kill the removal halfway."""
    msb = shutil.which("msb")
    if not msb or not sandbox:
        return False
    quiet = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                 start_new_session=True, timeout=_MSB_TIMEOUT)
    try:
        subprocess.run([msb, "stop", sandbox], **quiet)
    except subprocess.TimeoutExpired:
        pass                                             # stop is courtesy; rm decides
    try:
        if not subprocess.run([msb, "rm", sandbox], **quiet).returncode:
            return True
        listed = subprocess.run([msb, "list"], capture_output=True, text=True,
                                start_new_session=True, timeout=_MSB_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False                                     # a hung msb proves nothing
    if listed.returncode:
        return False                                     # cannot prove it is gone
    return not any(line.split()[:1] == [sandbox] for line in listed.stdout.splitlines()[1:])


# How much guest output an archive keeps: the tail, bounded in lines (asked of msb) and in
# bytes (enforced before the write), so a chatty guest can't balloon it. The defaults hold a
# full agent transcript, and ARCHIVE_RETAIN_COUNT snapshots cost at most ~400 MiB. Each knob
# takes a positive integer. Anything else keeps the default.
# Mirrored in doc/PROXY.md (The archive). Update both.
_SNAPSHOT_TAIL_LINES = 20000     # SILKGATE_SNAPSHOT_TAIL_LINES
_SNAPSHOT_MAX_BYTES = 8 << 20    # SILKGATE_SNAPSHOT_MAX_BYTES


def _snapshot_cap(var, default):
    """One snapshot knob: the env override where it parses positive, the default
    otherwise — _retain_days' pattern, minus the 0-turns-it-off arm."""
    try:
        value = int(os.environ.get(var, "") or default)
    except ValueError:
        return default
    return value if value > 0 else default


def _snapshot_output(sandbox, sdir):
    """Best-effort tail of the guest's output into the session dir, pre-archive.
    Fail-open like all bookkeeping: a guest whose log can no longer be read must not
    block its own teardown."""
    tail = _snapshot_cap("SILKGATE_SNAPSHOT_TAIL_LINES", _SNAPSHOT_TAIL_LINES)
    cap = _snapshot_cap("SILKGATE_SNAPSHOT_MAX_BYTES", _SNAPSHOT_MAX_BYTES)
    lines, err = _run_msb_logs(sandbox, tail_n=tail)
    if err is not None:
        console.say(f"warning: no guest-output snapshot for {sandbox}: {err}")
        return
    data = ("\n".join(lines) + "\n").encode("utf-8", "replace") if lines else b""
    try:
        (sdir / "output.log").write_bytes(data[-cap:])
    except OSError as e:
        console.say(f"warning: could not write the guest-output snapshot: {e}")


# Retention for ~/.silkgate/archive, favouring keeping like the audit logs above: an
# archived session goes only when BOTH older than the age AND beyond the newest
# ARCHIVE_RETAIN_COUNT, every removal is announced, and SILKGATE_ARCHIVE_RETAIN_DAYS=0
# (or less) keeps everything.
ARCHIVE_RETAIN_DAYS = 30
ARCHIVE_RETAIN_COUNT = 50


def _prune_archive():
    """Apply the archive retention policy above; runs where archives are created."""
    days = mitm._retain_days("SILKGATE_ARCHIVE_RETAIN_DAYS", ARCHIVE_RETAIN_DAYS)
    if days <= 0:
        return
    cutoff = time.time() - days * 86400
    stamped = []
    try:
        entries = list(paths.ARCHIVE_DIR.iterdir())
    except OSError:
        return
    for d in entries:
        if not _SID_RE.fullmatch(d.name):            # not something silkgate archived
            continue
        try:
            stamped.append((d.stat().st_mtime, d))
        except OSError:                              # vanished mid-scan: already gone
            continue
    stamped.sort(reverse=True)
    pruned = 0
    for mtime, d in stamped[ARCHIVE_RETAIN_COUNT:]:
        if mtime >= cutoff:
            continue
        shutil.rmtree(d, ignore_errors=True)
        pruned += not d.exists()
    if pruned:
        console.say(f"pruned {pruned} archived session(s) older than {days:g}d from "
                    f"{paths.ARCHIVE_DIR} (the {ARCHIVE_RETAIN_COUNT} newest always stay; "
                    "SILKGATE_ARCHIVE_RETAIN_DAYS=0 keeps everything)")


def _teardown_session(meta, archive=True):
    """Remove the guest, then free its session dir and port, in that order.

    While a guest that can reach the port may exist, the port stays reserved, or the next
    session would inherit a guest policed by the wrong ruleset. So a sandbox that can't be
    removed keeps its session, and this dies.

    With `archive` (the default), the session dir moves to ARCHIVE_DIR/<sid>, after a
    last output snapshot, the `down` journal record, and an `ended` stamp. That
    bookkeeping fails open. archive=False is for a session never handed over (`up`'s
    unwind).

    The teardown that empties the registry stops the shared proxy, whoever started it.
    Every removal runs through here, so the proxy's lifetime follows the registry."""
    name = meta.get("name")
    sandbox = meta.get("sandbox") or (sandbox_name(name) if name else None)
    sdir = session_dir(name) if name else None
    archive = archive and sdir is not None and sdir.is_dir()
    if archive and sandbox:
        _snapshot_output(sandbox, sdir)              # the guest's log dies with the VM
    if sandbox and not _remove_sandbox(sandbox):
        console.die(f"msb rm {sandbox} failed — session {name!r} kept, its proxy port still "
                    f"reserved; remove the sandbox manually, then `silkgate down {name}`")
    if name:
        # The claim goes first, while meta.json still pins the port for pick_port; the
        # rename (or rmtree) is then what genuinely frees it.
        mitm._release_port(name, meta.get("port"))
        if archive:
            _journal(name, "down")
            sid = meta.get("sid") or _new_sid(name)  # pre-feature metas: minted here
            try:
                _write_json(sdir / "meta.json", {**meta, "sid": sid, "ended": now_iso()})
            except OSError as e:
                console.say(f"warning: could not stamp 'ended' into {name!r}'s meta: {e}")
            try:
                paths.ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
                sdir.rename(paths.ARCHIVE_DIR / sid)
            except OSError as e:
                console.say(f"warning: could not archive session {name!r} ({e}) — removing it "
                            "instead")
                shutil.rmtree(sdir, ignore_errors=True)
            _prune_archive()
        else:
            shutil.rmtree(sdir, ignore_errors=True)
    _maybe_stop_proxy()


def _maybe_stop_proxy():
    """Stop the shared proxy once the last session is gone. The check here is a courtesy;
    stop_proxy re-checks sessions and port claims under the lifecycle lock."""
    if list_metas():
        return
    meta = mitm.read_proxy()
    if meta:
        mitm.stop_proxy(meta)


# --- commands ------------------------------------------------------------------

def cmd_build(args):
    profiles = profile.resolve_profiles(args.with_ or [])
    profile.load_ruleset(profile.compose_rules(profiles))  # bad rules fail before a long build
    console.preflight(*console._build_tools())              # every missing tool, pre-docker
    ref = images.build_image(profiles, base=args.base, platform_=args.platform)
    console.say(f"loaded {ref} into msb")
    print(ref)


def cmd_profiles(args):
    specs = getattr(args, "render", None)
    if specs:
        # A parameterized policy stays as auditable as a static one: this is the exact
        # composed text a session launched with the same --with list enforces, parsed
        # first so a defect dies here rather than reads as an allowance.
        text = profile.compose_rules(profile.resolve_profiles(specs))
        profile.load_ruleset(text)
        sys.stdout.write(text)
        return
    width = shutil.get_terminal_size((80, 24)).columns
    blocks = [_profile_block(profile.Profile(d.name), width)
              for d in sorted(p for p in paths.PROFILE_DIR.iterdir() if p.is_dir())]
    print("\n\n".join(blocks))


def _profile_block(prof, width):
    """One `profiles` record: a header naming the profile, its description, then the
    label-aligned installs, reaches, injects, and rules lines. The description and the
    reaches list wrap to `width`, continuations aligned under the first list item."""
    header = [prof.name]
    if prof.version:
        header.append(prof.version)
    if prof.arg_pattern:
        header.append(f"arg: {prof.arg_pattern}")
    if prof.name in profile._VERIFY_ONLY:       # listed like the rest, usable unlike them
        header.append("(silkgate verify only — refused with run/up/build/proxy)")
    lines = [" ".join(header)]
    desc = prof.conf.get("description", "")
    if desc:
        lines += textwrap.wrap(desc, width, initial_indent="  ", subsequent_indent="  ",
                               break_long_words=False, break_on_hyphens=False)
    installs = list(prof.packages) + (["setup.sh"] if prof.setup.strip() else [])
    if installs:
        lines.append("  installs  " + " ".join(installs))
    hosts = sorted({ln.split()[0].split("/")[0]
                    for ln in prof.rules.splitlines()
                    if ln.strip() and not ln.startswith("#")})
    if hosts:
        lines += textwrap.wrap(", ".join(hosts), width,
                               initial_indent="  reaches   ",
                               subsequent_indent=" " * len("  installs  "),
                               break_long_words=False, break_on_hyphens=False)
    secrets = sorted({"SILKGATE_EGRESS_SECRET_" + tok.split("=", 1)[1].upper()
                      for ln in prof.rules.splitlines()
                      if ln.strip() and not ln.startswith("#")
                      for tok in ln.split() if tok.startswith("inject_auth=")})
    if secrets:
        lines.append("  injects   " + " ".join(secrets))
    if prof.rules:
        lines.append("  rules     " + f"profiles/{prof.name}/rules.txt")
    return "\n".join(lines)


def cmd_doctor(args):
    """The whole toolchain's presence in one pass — the command to run (and to name in a
    brief) when a sandbox will not start. Presence means a PATH lookup, never a version
    call: whether containment actually holds is `silkgate verify`'s question."""
    rows = [("TOOL", "STATUS")]
    missing = []
    for binary, hint in console._TOOL_HINTS.items():
        path = shutil.which(binary)
        rows.append((binary, path or f"missing — {hint}"))
        if path is None:
            missing.append(binary)
    _print_table(rows)
    sys.stdout.flush()                    # the verdict goes to stderr; table first, even piped
    if missing:
        console.die(f"missing {len(missing)} of {len(console._TOOL_HINTS)} tools")
    console.say("toolchain complete")


def cmd_proxy(args):
    """One ruleset, one port, in the foreground — for guests silkgate doesn't manage.

    Binds PROXY_BINDS, loopback by default, like every proxy entry point. For a guest on
    another machine, name one routable interface with SILKGATE_PROXY_BIND=<address>.
    """
    profiles = profile.resolve_profiles(args.with_ or [])
    rules_text = profile.compose_rules(profiles, args.rule or [])
    if not rules_text.strip():
        console.die("no rules — pass --with PROFILE and/or --rule 'host/path GET'")
    profile.check_secrets(profile.load_ruleset(rules_text))
    mitmdump = console.which("mitmdump", "pip install mitmproxy")
    paths.LOG_DIR.mkdir(parents=True, exist_ok=True)
    mitm._prune_logs()
    stamp = f"{datetime.now():%Y%m%d-%H%M%S}"
    rules_file = paths.LOG_DIR / f"standalone-{stamp}.rules"
    events_path = paths.LOG_DIR / f"events-{stamp}.jsonl"
    capture_path = paths.LOG_DIR / f"capture-{stamp}.jsonl"
    rules_file.write_text(rules_text)
    env = dict(os.environ, SILKGATE_EGRESS_RULES=str(rules_file),
               SILKGATE_EGRESS_EVENTS_FILE=str(events_path),
               SILKGATE_EGRESS_CAPTURE_FILE=str(capture_path))
    env.pop("SILKGATE_EGRESS_SESSIONS_DIR", None)
    # rawtcp=false: a CONNECT whose payload mitmproxy cannot read as TLS is refused
    # instead of becoming an opaque tunnel around the addon's per-request checks.
    argv = [mitmdump, "-s", str(paths.ADDON), "--set", "rawtcp=false"] + mitm._modes(args.port)
    proc = subprocess.Popen(argv, env=env)
    try:
        sys.exit(foreground.wait_foreground(proc))
    finally:
        foreground.stop(proc)


def _strip_cmd_sep(cmd):
    return cmd[1:] if cmd and cmd[0] == "--" else cmd


def cmd_run(args):
    """One-shot over a persistent session: up (ephemeral) -> exec -> down, all foreground."""
    profile.check_env(args.env)
    git._check_mount_flags(args)
    profiles, rules_text, ruleset = _session_policy(args)
    _read_brief(args.brief)     # per-exec brief: fail on it here, before any host process
    cmd = _strip_cmd_sep(args.cmd) or profile.profile_command(profiles)
    if not cmd:
        console.die("nothing to run — pass a command after -- (or --with a profile that names "
                    "one)")
    name = args.name or uuid4().hex[:6]
    _validate_name(name)
    if session_dir(name).exists():
        console.die(f"session {name!r} already exists")
    # The ask is well-formed; now the whole toolchain shortfall in one report, before any
    # host process. An explicit --image is run as-is, never built, so docker is not its
    # business.
    console.preflight(*(() if args.image else console._build_tools()), "msb", "mitmdump",
                      *(("git",) if args.branch or args.checkout is not None else ()))
    tty = args.tty if args.tty is not None else sys.stdin.isatty()
    if args.branch:
        spec = git._branch_spec(args.branch, profiles, args.env, args.checkout or "HEAD")
    elif args.checkout is not None:
        spec = git._checkout_spec(args.checkout, profiles, args.env)
    else:
        spec = None
    vmounts = _mount_args(args.mount, allow_git_dir=args.allow_git_dir)
    mounts = [f"{host}:{guest}:{mode}" for host, guest, mode in vmounts]
    ws = None
    if args.branch:
        ws, extra = git._branch_workspace(spec, name)
        mounts += extra
    elif spec:
        mounts += git._checkout_workspace(spec)
    image = images.ensure_image(profiles, args.image, base=args.base)
    proxy_was_running = mitm._proxy_running()   # --port is the base port iff WE start it
    rc, provisioned, branch_ready, proxy = 1, False, False, None
    create_env = (mitm._guest_credential_env(profiles) + list(args.env)
                  + (list(git._BRANCH_ENV) if args.branch else []))
    try:
        proxy = mitm.ensure_proxy(args.port)
        port = mitm.pick_port(proxy, name)
        ctx, ctx_paths = _context_for(args, profiles, ruleset, vmounts, persistent=False)
        settings, settings_paths = _settings_for(args, profiles,
                                                 _settings_workspace(spec, vmounts))
        meta_extra = {**_session_meta(profiles, cmd),
                      **_observability_meta(args, rules_text, None), "tty": tty,
                      **(spec or {})}
        if vmounts:
            meta_extra["mounts"] = [f"{h}:{g}:{m}" for h, g, m in vmounts]
        _provision_session(name, image, port, rules_text, ruleset, mounts, ws, create_env,
                           meta_extra, ctx, ctx_paths, settings, settings_paths,
                           memory=args.memory, cpus=args.cpus)
        provisioned = True
        fault = tier1_fault(sandbox_name(name), port)
        if fault:
            console.die(fault)              # the finally below tears the session down
        if args.branch:
            git._setup_branch_guest(sandbox_name(name), args.branch, spec["base"], name)
            branch_ready = True
        elif spec:
            git._setup_checkout_guest(sandbox_name(name), spec["base"], name)
        console.say(f"session {name} · proxy :{port} · audit: tail -f {proxy['log']}")
        exec_id = uuid4().hex[:8]
        brief_fields = _exec_brief_fields(name, sandbox_name(name), exec_id, args.brief)
        _journal(name, "exec_start", exec_id=exec_id, argv=list(cmd), tty=tty,
                 env_names=sorted({p.partition("=")[0] for p in args.env}), via="run",
                 **brief_fields)
        rc = _bracketed_exec(name, exec_id, lambda: run_guest(
            lambda c: msb_exec_argv(sandbox_name(name), c, tty=tty, env=args.env),
            cmd, tty=tty, exec_id=exec_id))
    finally:
        # One-shot means one-shot even interrupted: the unwind runs with the stop
        # signals deferred, so a second Ctrl-C cannot leave the session half-removed.
        with foreground._deferred_interrupts():
            if provisioned:
                meta = read_meta(name) or {"name": name, "sandbox": sandbox_name(name),
                                           **(spec or {}), **({"workspace": ws} if ws else {})}
                # Harvest while the guest is still up — its gitdir dies with the VM. A
                # harvest that could not bank everything keeps the workspace and must not
                # let a green guest run mask it, hence the forced nonzero exit.
                keep = False
                if branch_ready:
                    keep = not git._harvest_branch(meta)
                    if keep and rc == 0:
                        rc = 1
                _teardown_session(meta)
                if spec and not keep:
                    git._reap_derived_workspace(meta)
            else:
                mitm._release_port(name)     # a claim pick_port made, however far it got
                if spec and ws:
                    shutil.rmtree(ws, ignore_errors=True)   # empty: created before the try
            # Only tear down the proxy if this command started it and nothing else
            # needs it.
            if not proxy_was_running and not list_metas():
                mitm.stop_proxy(mitm.read_proxy() or proxy)
    sys.exit(rc)


def _session_policy(args):
    """Profiles -> (profiles, composed rules text, parsed ruleset), failing on bad rules.

    No profile and no --rule composes an empty ruleset, which is legal: it is the strictest
    policy silkgate can express — default-deny with nothing exempted — and the alternative
    of a rule written to match nothing would sit in shell history reading like an allowance.
    """
    profiles = profile.resolve_profiles(args.with_ or [])
    rules_text = profile.compose_rules(profiles, args.rule or [])
    ruleset = profile.load_ruleset(rules_text)
    if not ruleset.rules:
        console.say("empty allowlist — this guest can reach nothing; every request is denied")
    return profiles, rules_text, ruleset


def _session_meta(profiles, cmd):
    """What a session records about how it was asked for, so exec/attach/ls can use it."""
    return {"profiles": [p.spec for p in profiles], "command": cmd}


# --brief is copied into the rootfs like the context, so its size rides msb argv paths
# sized for small files; anything over this is not a brief, and dying beats truncating.
_BRIEF_MAX_BYTES = 1 << 20


def _read_brief(path):
    """The --brief bytes, read host-side before any provisioning — or None without the
    flag. Dying here, on an unreadable or oversized file, costs nothing yet; the same
    failure after a guest boots costs a teardown."""
    if not path:
        return None
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        console.die(f"cannot read --brief {path}: {e.strerror or e}")
    if len(data) > _BRIEF_MAX_BYTES:
        console.die(f"--brief {path} is {len(data)} bytes — over the 1 MiB limit")
    return data


# One in-guest pass to land an exec's brief: the bytes arrive on stdin — argv could
# not carry a megabyte — and the rename makes the swap atomic, so a guest reading
# the brief mid-exec never sees a torn file.
_BRIEF_LAND_SH = ("set -eu\n"
                  f"cat > {GUEST_BRIEF}.tmp\n"
                  f"mv {GUEST_BRIEF}.tmp {GUEST_BRIEF}\n")


def _land_brief_in_guest(sandbox, data):
    """Write `data` to GUEST_BRIEF in a live guest — why it failed, or None. A seam
    the tests stub, like _diff_in_guest."""
    try:
        proc = subprocess.run(msb_exec_argv(sandbox, ["sh", "-c", _BRIEF_LAND_SH]),
                              input=data, capture_output=True,
                              start_new_session=True, timeout=_MSB_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return "the guest did not take the brief in time"
    if proc.returncode:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        return (err or ["guest brief write failed"])[-1]
    return None


def _exec_brief_fields(name, sandbox, exec_id, flag_path):
    """Resolve, store and land one exec's brief; the fields its exec_start record
    carries, or {} when no brief applies.

    The exec's own --brief wins (source "flag"). Otherwise, the session default from
    `up --brief` applies (source "default"), copied in again so an older brief can't
    linger. The bytes are stored at briefs/<exec_id>.md. A failure dies host-side before
    the exec: a command without its brief would succeed at the wrong task."""
    data, source = _read_brief(flag_path), "flag"
    if data is None:
        try:
            data = (session_dir(name) / "brief.md").read_bytes()
        except OSError:                          # no default either: briefless exec
            return {}
        source = "default"
    bdir = session_dir(name) / "briefs"
    try:
        bdir.mkdir(exist_ok=True)
        (bdir / f"{exec_id}.md").write_bytes(data)
    except OSError as e:
        console.die(f"cannot store the exec brief under {bdir}: {e}")
    err = _land_brief_in_guest(sandbox, data)
    if err is not None:
        console.die(f"could not land the brief in the guest: {err}")
    return {"brief_sha256": hashlib.sha256(data).hexdigest(), "brief_source": source}


def _observability_meta(args, rules_text, brief):
    """Meta fields for the record only (journal, archive, UI), never for enforcement.

    env_names holds names, never values. base_ref is the base as typed, for display.
    rules_sha256 ties the session to its exact ruleset. `brief` is up's default brief:
    per-exec briefs go on their exec records."""
    meta = {"env_names": sorted({p.partition("=")[0] for p in args.env}),
            "allow_git_dir": bool(args.allow_git_dir),
            "rules_sha256": hashlib.sha256(rules_text.encode()).hexdigest()}
    if args.branch or args.checkout is not None:
        meta["base_ref"] = args.checkout or "HEAD"
    if brief is not None:
        meta["brief_path"] = str(Path(args.brief).resolve())
        meta["brief_sha256"] = hashlib.sha256(brief).hexdigest()
    return meta


def _context_for(args, profiles, ruleset, mounts, *, persistent):
    """(context text, where to put it in the guest) — or (None, ()) with --no-context.

    Always at GUEST_CONTEXT, plus wherever a harness profile says its own tool looks for
    instructions (`context_path`), which is how this stays harness-agnostic.
    """
    if args.no_context:
        return None, ()
    paths = list(dict.fromkeys(
        [GUEST_CONTEXT] + [p.conf["context_path"] for p in profiles
                           if p.conf.get("context_path")]))
    return session_context(profiles, ruleset, mounts=mounts, persistent=persistent,
                           branch=args.branch, checkout=args.checkout,
                           brief=bool(getattr(args, "brief", None))), paths


# --- the settings projection: the host's model configuration, forwarded ---------
# Claude Code reads three settings files, lowest rank first: user (~/.claude/settings.json),
# project (.claude/settings.json), local (.claude/settings.local.json). An "env" block entry
# in any of them beats every direct key. The host resolves its answer once, and the guest
# gets only that, so it defaults to the host's model and effort.

# The host's user-rank settings file. The project and local files come from the host
# directory that becomes /workspace.
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"

# The only keys that ever leave the host, each with the env var Claude Code maps to it.
# Everything else in a settings file — permissions, hooks, apiKeyHelper, every other env
# entry — stays behind: env entries can carry secrets, and the guest needs none of it.
_SETTINGS_KEYS = (("model", "ANTHROPIC_MODEL"),
                  ("effortLevel", "CLAUDE_CODE_EFFORT_LEVEL"))


def _read_settings(path):
    """One settings file as a dict. Absent is {}; a file that exists but does not hold a
    JSON object warns and counts as absent too — the same contract as a malformed secret:
    the launch continues, and the warning says why the projection lacks the file."""
    try:
        text = path.read_text()
    except OSError:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        console.say(f"warning: {path} is not valid JSON — the settings projection ignores it")
        return {}
    if not isinstance(data, dict):
        console.say(f"warning: {path} is not a JSON object — the settings projection ignores it")
        return {}
    return data


def _resolve_settings(workspace, user_settings):
    """At most {model, effortLevel}: the answer the host's own Claude Code would reach.

    `workspace` is the host directory mounted at /workspace (or None), and `user_settings`
    the user-rank file, both passed in so tests never read the real home. Per key, the
    first match wins: env-block values (local, project, user), then direct keys, same order.
    """
    files = []                                   # highest rank first
    if workspace:
        dot = Path(workspace) / ".claude"
        files += [_read_settings(dot / "settings.local.json"),
                  _read_settings(dot / "settings.json")]
    files.append(_read_settings(Path(user_settings)))
    env_blocks = [f["env"] for f in files if isinstance(f.get("env"), dict)]
    resolved = {}
    for key, env_name in _SETTINGS_KEYS:
        candidates = [b.get(env_name) for b in env_blocks] + [f.get(key) for f in files]
        value = next((v for v in candidates if isinstance(v, str) and v), None)
        if value is not None:
            resolved[key] = value
    return resolved


def _settings_workspace(spec, mounts):
    """The host directory whose project and local settings files apply: the one that
    becomes /workspace. The repository root for --checkout and --branch, else the SRC of
    the mount whose DST is /workspace, else None — the user file alone then decides."""
    if spec:
        return spec["repo_root"]
    return next((host for host, guest, _ in mounts if guest == "/workspace"), None)


def _settings_for(args, profiles, workspace):
    """(settings JSON text, where to put it in the guest) — or (None, ()) with
    --no-settings, with no profile naming a settings_path, or with neither key resolved.

    Nothing is staged unless a profile has a `settings_path` AND a key resolves on the host.
    """
    if args.no_settings:
        return None, ()
    paths = [p.conf["settings_path"] for p in profiles if p.conf.get("settings_path")]
    if not paths:
        return None, ()
    resolved = _resolve_settings(workspace, CLAUDE_SETTINGS)
    if not resolved:
        return None, ()
    return json.dumps(resolved) + "\n", paths


def cmd_up(args):
    profile.check_env(args.env)
    git._check_mount_flags(args)
    profiles, rules_text, ruleset = _session_policy(args)
    brief = _read_brief(args.brief)             # host-side, before any provisioning
    name = args.name or uuid4().hex[:6]
    _validate_name(name)
    if session_dir(name).exists():
        console.die(f"session {name!r} already exists")
    # The ask is well-formed; now the whole toolchain shortfall in one report, before any
    # host process. An explicit --image is run as-is, never built, so docker is not its
    # business.
    console.preflight(*(() if args.image else console._build_tools()), "msb", "mitmdump",
                      *(("git",) if args.branch or args.checkout is not None else ()))
    if args.branch:
        spec = git._branch_spec(args.branch, profiles, args.env, args.checkout or "HEAD")
    elif args.checkout is not None:
        spec = git._checkout_spec(args.checkout, profiles, args.env)
    else:
        spec = None
    vmounts = _mount_args(args.mount, allow_git_dir=args.allow_git_dir)
    mounts = [f"{host}:{guest}:{mode}" for host, guest, mode in vmounts]
    ws = None
    if args.branch:
        ws, extra = git._branch_workspace(spec, name)
        mounts += extra
    elif spec:
        mounts += git._checkout_workspace(spec)
    image = images.ensure_image(profiles, args.image, base=args.base)
    provisioned = False
    create_env = (mitm._guest_credential_env(profiles) + list(args.env)
                  + (list(git._BRANCH_ENV) if args.branch else []))
    try:
        proxy = mitm.ensure_proxy(args.port)
        port = mitm.pick_port(proxy, name)
        ctx, ctx_paths = _context_for(args, profiles, ruleset, vmounts, persistent=True)
        settings, settings_paths = _settings_for(args, profiles,
                                                 _settings_workspace(spec, vmounts))
        meta_extra = {**_session_meta(profiles, profile.profile_command(profiles)),
                      **_observability_meta(args, rules_text, brief),
                      **(spec or {})}
        if vmounts:
            meta_extra["mounts"] = [f"{h}:{g}:{m}" for h, g, m in vmounts]
        _provision_session(name, image, port, rules_text, ruleset, mounts, ws, create_env,
                           meta_extra, ctx, ctx_paths, settings, settings_paths,
                           memory=args.memory, cpus=args.cpus, brief=brief)
        provisioned = True
        fault = tier1_fault(sandbox_name(name), port)
        if fault:
            console.die(fault)
        if args.branch:
            git._setup_branch_guest(sandbox_name(name), args.branch, spec["base"], name)
        elif spec:
            git._setup_checkout_guest(sandbox_name(name), spec["base"], name)
    except BaseException:
        # A session `up` never handed over is removed whole, interrupt included: nothing
        # of the user's is in it yet, and one left behind would hide the failure. Stop
        # signals are deferred, so a second Ctrl-C can't leave it half-removed.
        with foreground._deferred_interrupts():
            if provisioned:
                # A session never handed over leaves nothing worth archiving.
                _teardown_session(read_meta(name) or
                                  {"name": name, "sandbox": sandbox_name(name)},
                                  archive=False)
            else:
                mitm._release_port(name)     # a claim pick_port made, however far it got
            if spec and ws:
                shutil.rmtree(ws, ignore_errors=True)   # no commits can exist yet
            _maybe_stop_proxy()
        raise
    console.say(f"session {name} up · proxy :{port} · audit: tail -f {proxy['log']}")
    print(name)


def cmd_exec(args):
    meta = read_meta(args.name)
    if not meta:
        console.die(f"no such session: {args.name!r} (silkgate ls)")
    profile.check_env(args.env)
    cmd = _strip_cmd_sep(args.cmd) or meta.get("command")
    if not cmd:
        console.die("nothing to run — usage: silkgate exec NAME [-t] [-e K=V]... -- CMD ...")
    tty = args.tty if args.tty is not None else sys.stdin.isatty()
    exec_id = uuid4().hex[:8]
    brief_fields = _exec_brief_fields(args.name, meta["sandbox"], exec_id,
                                      getattr(args, "brief", None))
    _journal(args.name, "exec_start", exec_id=exec_id, argv=list(cmd), tty=tty,
             env_names=sorted({p.partition("=")[0] for p in args.env}), via="exec",
             **brief_fields)
    rc = _bracketed_exec(args.name, exec_id, lambda: run_guest(
        lambda c: msb_exec_argv(meta["sandbox"], c, tty=tty, env=args.env),
        cmd, tty=tty, exec_id=exec_id))
    sys.exit(rc)


def cmd_attach(args):
    meta = read_meta(args.name)
    if not meta:
        console.die(f"no such session: {args.name!r} (silkgate ls)")
    cmd = meta.get("command")
    if not cmd:
        console.die(f"session {args.name!r} has no default command — use: silkgate exec "
                    f"{args.name} -t -- CMD")
    exec_id = uuid4().hex[:8]
    # attach takes no --brief; the session default still covers it, like any exec.
    brief_fields = _exec_brief_fields(args.name, meta["sandbox"], exec_id, None)
    _journal(args.name, "exec_start", exec_id=exec_id, argv=list(cmd), tty=True,
             env_names=[], via="attach", **brief_fields)
    rc = _bracketed_exec(args.name, exec_id, lambda: run_guest(
        lambda c: msb_exec_argv(meta["sandbox"], c, tty=True), cmd, tty=True,
        exec_id=exec_id))
    sys.exit(rc)


def _down_session(meta):
    """End a handed-over session: cmd_down and the UI's down both run this.

    Harvest first, since the guest's gitdir dies with the VM. A retried down harvests
    again, a no-op without new commits. Returns True if a failed harvest kept the
    workspace. Stop signals are deferred during removal (a no-op off the main thread)."""
    with foreground._deferred_interrupts():
        keep = bool(meta.get("branch")) and not git._harvest_branch(meta)
        _teardown_session(meta)
        if meta.get("branch") and not keep:
            git._reap_derived_workspace(meta)
        _maybe_stop_proxy()
    return keep


def cmd_down(args):
    meta = read_meta(args.name)
    if not meta:
        console.die(f"no such session: {args.name!r} (silkgate ls)")
    # Teardown needs msb to stop/rm the guest; without this, its absence surfaces as
    # "msb rm failed — session kept", which reads as a broken sandbox, not a missing tool.
    console.preflight("msb", *(("git",) if meta.get("branch") else ()))
    keep = _down_session(meta)
    console.say(f"session {args.name} down")
    if keep:
        sys.exit(1)


def cmd_harvest(args):
    """Bundle the session's branch out of the live guest and fast-forward the host branch —
    the mid-session save point. No teardown, no workspace reaping."""
    meta = read_meta(args.name)
    if not meta:
        console.die(f"no such session: {args.name!r} (silkgate ls)")
    if not meta.get("branch"):
        console.die(f"session {args.name!r} has no --branch — nothing to harvest")
    console.preflight("msb", "git")
    sys.exit(0 if git._harvest_branch(meta) else 1)


def _age(iso):
    try:
        t = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return "?"
    secs = max(0, int((datetime.now(t.tzinfo) - t).total_seconds()))
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if secs >= size:
            return f"{secs // size}{unit}"
    return f"{secs}s"


def _msb_statuses():
    """sandbox name -> STATUS, parsed from `msb list` (NAME/IMAGE/STATUS columns)."""
    msb = shutil.which("msb")
    if not msb:
        return {}
    try:
        out = subprocess.run([msb, "list"], capture_output=True, text=True).stdout
    except OSError:
        return {}
    statuses = {}
    for line in out.splitlines()[1:]:            # skip the header row
        cols = line.split()
        if len(cols) >= 3:
            statuses[cols[0]] = cols[2]
    return statuses


def _print_table(rows):
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())


def _journal_summary(path):
    """(EXECS, EXIT) table cells from one journal: how many execs the session ran, and
    the newest exec_end's rc — "-" where none closed, or the rc itself is unknown."""
    records = _read_journal(path)
    execs = sum(1 for r in records if r.get("event") == "exec_start")
    last = next((r for r in reversed(records) if r.get("event") == "exec_end"), None)
    rc = None if last is None else last.get("rc")
    return str(execs), "-" if rc is None else str(rc)


def _mounts_cell(meta):
    """One meta's MOUNTS cell: the workspace mode first, then every -v mount."""
    parts = []
    if meta.get("branch"):
        parts.append(f"{meta.get('workspace') or '-'} (branch {meta['branch']})")
    elif meta.get("checkout"):
        parts.append(f"(checkout {meta['checkout']})")
    for entry in meta.get("mounts") or []:
        path, _, mode = str(entry).rpartition(":")
        parts.append(f"{path} ({mode})")
    return ", ".join(parts) or "-"


def cmd_ls(args):
    show_all = bool(getattr(args, "all", False))
    metas = list_metas()
    archived = list_archived_metas() if show_all else []
    if not metas and not archived:
        print("no sessions")
    else:
        statuses = _msb_statuses() if metas else {}
        header = ("NAME", "STATUS", "PORT", "MOUNTS", "AGE", "EXECS", "EXIT")
        rows = [header + ("ID",) if show_all else header]
        for m in metas:
            row = (m["name"], statuses.get(m["sandbox"], "?"),
                   str(m.get("port", "?")), _mounts_cell(m), _age(m.get("created")),
                   *_journal_summary(session_dir(m["name"]) / "journal.jsonl"))
            rows.append(row + ((m.get("sid") or "-",) if show_all else ()))
        for m in archived:
            # The port is history, not a claim, so the cell stays empty; AGE counts
            # from the end, the moment an archived session's clock stopped.
            rows.append((m.get("name") or "-", "archived", "-", _mounts_cell(m),
                         _age(m.get("ended") or m.get("created")),
                         *_journal_summary(paths.ARCHIVE_DIR / m["sid"] / "journal.jsonl"),
                         m["sid"]))
        _print_table(rows)
    proxy = mitm.read_proxy()
    ident = mitm._proxy_ident()          # identity via the control socket, never pid alone:
    if ident is None:                    # after an unclean exit proxy.json survives and its
        print("proxy: not running")      # pid may belong to a recycled, unrelated process
    elif proxy is None:
        print(f"proxy: pid {ident or 'unknown'} answers on {paths.PROXY_SOCK} but "
              f"{paths.PROXY_JSON} is gone — kill that process and retry")
    else:
        pool = proxy["ports"]
        pid = ident or proxy.get("pid")  # 0 = answered, but the kernel could not name it
        print(f"proxy: pid {pid} alive · ports {pool[0]}-{pool[-1]} · {proxy['log']}")


def cmd_secret_set(args):
    """Secrets are scoped per session in the proxy, so a set names the one it is for."""
    name = args.name
    value = os.environ.get(f"SILKGATE_EGRESS_SECRET_{name.upper()}")
    if not value:
        console.die(f'missing secret: SILKGATE_EGRESS_SECRET_{name.upper()}="<header>: <value>"')
    if rule_engine._parse_secret(value) is None:
        console.die(f'SILKGATE_EGRESS_SECRET_{name.upper()} is not a valid "<Header>: <value>" '
                    "line — expected a printable-ASCII header name (not a routing header) and a "
                    "non-empty value")
    if not read_meta(args.session):
        console.die(f"no such session: {args.session!r} (silkgate ls)")
    if not mitm._proxy_running():
        console.die("shared proxy not running — start a session first (silkgate up)")
    mitm._sock_call({"op": "set_secret", "name": name.lower(), "value": value,
                     "session": args.session})
    console.say(f"secret {name.lower()} set for session {args.session}")  # value never printed


def cmd_secret_ls(args):
    if not mitm._proxy_running():
        console.die("shared proxy not running — start a session first (silkgate up)")
    if args.session:
        if not read_meta(args.session):
            console.die(f"no such session: {args.session!r} (silkgate ls)")
        for n in sorted(mitm._sock_call({"op": "list_secrets",
                                         "session": args.session}).get("names", [])):
            print(n)
        return
    by_session = mitm._sock_call({"op": "list_secrets"}).get("sessions", {})
    for s in sorted(by_session):                 # names only, one per line, session-qualified
        for n in sorted(by_session[s]):
            print(f"{s}/{n}")

