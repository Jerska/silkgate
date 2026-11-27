"""Session host state: the registry under ~/.silkgate, its names and ids, the journal, and the
archive."""
import json
import os
import re
from datetime import datetime, timezone
from uuid import uuid4

from . import console, paths


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
_BASE_RE = re.compile(r"[0-9a-f]{40}")
# meta.json's branch reaches git argv (always behind --git-dir, always fully qualified) and,
# with repo_root, an rmtree decision — held to a charset before use, like "sandbox" above.
_BRANCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,200}")


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
        if (not _BRANCH_RE.fullmatch(branch) or ".." in branch
                or not _BASE_RE.fullmatch(base)):
            return f"its meta.json names branch {branch!r}"
    elif meta.get("checkout") is not None:
        # A checkout meta carries base into git argv the same way a branch one does.
        if not _BASE_RE.fullmatch(str(meta.get("base", ""))):
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
