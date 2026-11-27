"""silkgate ui: a local web view over the sessions, their audit events, and their control."""
import hashlib
import json
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from . import core, git, logs, paths


# --- ui: a local web view over the events files -------------------------------------
# `silkgate ui` serves ui/ and its JSON endpoints on 127.0.0.1, with no auth: no guest can
# reach a host port beyond its own proxy port. The server keeps no trail state: history is
# a filtered read of the events files, live is a byte-offset tail, and the client joins
# allow and response on `id`. So a dropped stream resumes from a plain Last-Event-ID.

UI_DIR = paths.REPO / "ui"
DEFAULT_UI_PORT = 8642       # clear of the proxy pool (8090..8105) and common dev ports
UI_EVENTS_LIMIT = 2000       # /api/events default page
UI_EVENTS_LIMIT_MAX = 20000
UI_STREAM_POLL = 0.5         # seconds between tail passes on /api/stream
UI_STREAM_HEARTBEAT = 15.0   # idle seconds before an SSE comment keeps the pipe alive

# Every asset the UI can serve, by exact request path. A map instead of a filesystem
# walk makes traversal structurally impossible: a path outside it resolves to nothing
# — which is also why ui/'s *.test.js files stay unserved: they are not keys here.
# Nested paths are plain dict keys, never re-parsed.
_UI_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/store.js": ("store.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/router.js": ("router.js", "text/javascript; charset=utf-8"),
    "/capture.js": ("capture.js", "text/javascript; charset=utf-8"),
    "/pricing.js": ("pricing.js", "text/javascript; charset=utf-8"),
    "/render.js": ("render.js", "text/javascript; charset=utf-8"),
    "/metrics.js": ("metrics.js", "text/javascript; charset=utf-8"),
    "/search.js": ("search.js", "text/javascript; charset=utf-8"),
    "/timeline.js": ("timeline.js", "text/javascript; charset=utf-8"),
    "/controls.js": ("controls.js", "text/javascript; charset=utf-8"),
    "/views/overview.js": ("views/overview.js", "text/javascript; charset=utf-8"),
    "/views/session.js": ("views/session.js", "text/javascript; charset=utf-8"),
    "/views/calls.js": ("views/calls.js", "text/javascript; charset=utf-8"),
    "/views/search.js": ("views/search.js", "text/javascript; charset=utf-8"),
}


def _events_files(pattern="events-*.jsonl"):
    """The retained files of one trail kind, oldest first — the stamp in the name is
    the order. The audit trail and the capture trail share the layout, so the glob is
    the only parameter."""
    return sorted(paths.LOG_DIR.glob(pattern))


def _event_passes(rec, filters):
    """Whether one parsed record survives the /api/events filters.

    `session` is exact, and "null" selects unattributed records. `host` is a case-folded
    substring, `method` case-folded. `since`/`until` are aware datetimes, and a record
    whose `ts` is unparsable or naive fails a time filter, never slips past it."""
    since, until = filters.get("since"), filters.get("until")
    if since is not None or until is not None:
        try:
            ts = datetime.fromisoformat(rec.get("ts") or "")
        except (TypeError, ValueError):
            return False
        if ts.tzinfo is None:
            return False
        if since is not None and ts < since:
            return False
        if until is not None and ts > until:
            return False
    session = filters.get("session")
    if session is not None:
        if session == "null":
            if rec.get("session") is not None:
                return False
        elif rec.get("session") != session:
            return False
    decision = filters.get("decision")
    if decision is not None and rec.get("decision") != decision:
        return False
    method = filters.get("method")
    if method is not None and (rec.get("method") or "").upper() != method.upper():
        return False
    host = filters.get("host")
    if host is not None and host.lower() not in (rec.get("host") or "").lower():
        return False
    return True


def _events_history(filters, limit, pattern="events-*.jsonl"):
    """The newest `limit` records passing `filters`, oldest first, across every
    retained file of one kind (filename order — the stamp is chronological, and
    records within a file are append-ordered). Unparsable lines are skipped: the live
    file's tail can be half-written mid-read, and history must not die on it."""
    kept = []
    for path in _events_files(pattern):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:                          # pruned mid-scan: already gone
            continue
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict) and _event_passes(rec, filters):
                kept.append(rec)
    return kept[-limit:]


class _EventsTailer:
    """Byte-offset tail of the live events file, one poll at a time.

    This tracks which file is live and how far the client has read, so the stream tests
    without a server. `poll` takes the current proxy.json and yields ("reset"|"record",
    payload, cursor). A cursor, "<file>:<offset>", doubles as the SSE id.

    | Event | Resumes at |
    |---|---|
    | the proxy restarted (new events path) | the new file, from 0 |
    | the file was truncated | the same file, from 0 |
    | a cursor names another file | the live file's EOF. The client refetches history. |
    | no proxy | nothing yet, and a later `up` flows into the same stream |

    `meta_key` picks the proxy.json entry: "events" or "capture"."""

    def __init__(self, cursor=None, meta_key="events"):
        self._path = None                        # nothing live seen yet
        self._offset = 0
        self._start = cursor                     # consumed when a live file first appears
        self._meta_key = meta_key

    @staticmethod
    def _parse_cursor(cursor):
        name, sep, off = (cursor or "").rpartition(":")
        if sep and off.isdigit():
            return name, int(off)
        return None, None

    def poll(self, proxy_meta):
        out = []
        events = (proxy_meta or {}).get(self._meta_key)
        if not events:
            return out
        path = Path(events)
        if self._path is None:                   # first pass that sees a live file
            cursor, self._start = self._start, None
            self._path = path
            name, offset = self._parse_cursor(cursor)
            if name == path.name:
                self._offset = offset            # hand-over from /api/events, or a reconnect
            else:
                try:
                    self._offset = path.stat().st_size
                except OSError:
                    self._offset = 0
                if cursor is not None:           # a cursor was given, but for another file
                    out.append(("reset", None, f"{path.name}:{self._offset}"))
        if path != self._path:                   # proxy restarted onto a fresh file
            self._path, self._offset = path, 0
            out.append(("reset", None, f"{path.name}:0"))
        try:
            size = self._path.stat().st_size
        except OSError:
            size = None
        if size is not None and size < self._offset:     # truncated in place
            self._offset = 0
            out.append(("reset", None, f"{self._path.name}:0"))
        lines, new_offset = logs._read_from(self._path, self._offset)
        if lines is None:                        # unreadable this pass: try again later
            return out
        pos = self._offset
        for i, line in enumerate(lines):
            # json.dumps output is ASCII, so a line's length is its byte length; the
            # final line's cursor is pinned to _read_from's own offset regardless.
            pos = new_offset if i == len(lines) - 1 else pos + len(line.encode()) + 1
            try:
                rec = json.loads(line)
            except ValueError:                   # a torn write that still ended in \n
                continue
            if isinstance(rec, dict):
                out.append(("record", line, f"{self._path.name}:{pos}"))
        self._offset = new_offset
        return out


# --- ui: per-session detail, control and search -------------------------------------
# Module-level (not nested in the handler) for the same reason _bundle_in_guest is:
# every host/guest boundary here is a seam the tests stub, and every cache must be
# one per process, not one per request thread.

UI_BRIEF_MAX_BYTES = 256 << 10   # /api/session serves at most this much brief text
UI_ARCHIVED_LIMIT = 50           # newest archived metas /api/sessions carries
UI_OUTPUT_TAIL = 200             # /api/session/<ident>/output default tail
UI_OUTPUT_TAIL_MAX = 2000
UI_OUTPUT_TTL = 1.0              # seconds one output fetch answers for, per session
UI_METRICS_TTL = 2.0             # seconds one msb metrics run answers for
UI_SEARCH_LIMIT = 200            # /api/search early-exits at this many results
UI_SEARCH_MIN_QUERY = 3
UI_SEARCH_MAX_BYTES = 32 << 20   # /api/search stops scanning past this many bytes

_EXEC_ID_RE = re.compile(r"[0-9a-f]{8}")

_OUTPUT_LOCK = threading.Lock()
_OUTPUT_CACHE = {}               # (name, tail) -> (monotonic stamp, payload, code)
_METRICS_LOCK = threading.Lock()
_METRICS_CACHE = {"at": None, "payload": None}
_DIFF_LOCK = threading.Lock()
_DIFF_BUSY = set()               # idents with a diff in flight: one guest git at a time


def _resolve_ident(ident):
    """(meta, state, session dir) for a live name or an archived sid, or three Nones.

    The ident is checked before it's a path: by read_meta for a name, read_archived_meta
    for a sid. Their die() on a planted meta becomes a not-found here, not a dead thread.
    A name that also parses as a sid resolves live first."""
    if core._NAME_RE.fullmatch(ident or ""):
        try:
            meta = core.read_meta(ident)
        except SystemExit:
            return None, None, None
        if meta:
            return meta, "live", core.session_dir(ident)
    if core._SID_RE.fullmatch(ident or ""):
        try:
            meta = core.read_archived_meta(ident)
        except SystemExit:
            return None, None, None
        if meta:
            return meta, "archived", paths.ARCHIVE_DIR / ident
    return None, None, None


def _brief_entry(path, source):
    """One briefs-map entry read from `path`, or None where no file answers. Text is
    capped at UI_BRIEF_MAX_BYTES and the sha256 covers the bytes served."""
    try:
        with open(path, "rb") as f:
            data = f.read(UI_BRIEF_MAX_BYTES + 1)
    except OSError:
        return None
    truncated = len(data) > UI_BRIEF_MAX_BYTES
    data = data[:UI_BRIEF_MAX_BYTES]
    return {"source": source, "text": data.decode("utf-8", "replace"),
            "sha256": hashlib.sha256(data).hexdigest(), "truncated": truncated}


def _session_briefs(meta, state, sdir):
    """The briefs map for /api/session: per exec_id, plus "default" and "workspace".

    Each exec's source ("flag" or "default") comes from its exec_start record, and a lost
    record reads as "flag". exec_ids are 8 hex chars, so the two reserved keys can't
    collide. "workspace" (<workspace>/BRIEF.md) appears only for a live session with no
    operator brief. It's guest-writable, so its label is the warning, and symlinks aren't
    followed."""
    sources = {}
    for rec in core._read_journal(sdir / "journal.jsonl"):
        if rec.get("event") == "exec_start" and rec.get("brief_source"):
            sources[str(rec.get("exec_id"))] = str(rec["brief_source"])
    briefs = {}
    bdir = sdir / "briefs"
    if bdir.is_dir():
        for p in sorted(bdir.glob("*.md")):
            if not _EXEC_ID_RE.fullmatch(p.stem):    # not something silkgate stored
                continue
            entry = _brief_entry(p, sources.get(p.stem, "flag"))
            if entry:
                briefs[p.stem] = entry
    if (sdir / "brief.md").is_file():
        entry = _brief_entry(sdir / "brief.md", "default")
        if entry:
            briefs["default"] = entry
    if not briefs and state == "live" and meta.get("workspace"):
        path = Path(meta["workspace"]) / "BRIEF.md"
        if not path.is_symlink() and path.is_file():
            entry = _brief_entry(path, "workspace")
            if entry:
                briefs["workspace"] = entry
    return briefs


def _session_output(meta, state, sdir, tail):
    """(payload, status) for /api/session/<ident>/output. Archived sessions read the
    output.log snapshot; live ones ask msb, behind a 1 s TTL cache per (session,
    tail) — N open tabs cost one subprocess per second, and a failure is cached the
    same so a dead sandbox is not re-poked every poll."""
    if state == "archived":
        try:
            text = (sdir / "output.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        lines = text.splitlines()
        return {"source": "archive", "lines": lines[-tail:],
                "truncated": len(lines) > tail}, 200
    key = (meta["name"], tail)
    with _OUTPUT_LOCK:
        hit = _OUTPUT_CACHE.get(key)
        if hit and time.monotonic() - hit[0] < UI_OUTPUT_TTL:
            return hit[1], hit[2]
        lines, err = core._run_msb_logs(meta["sandbox"], tail_n=tail)
        if err is not None:
            payload, code = {"error": f"cannot read guest output: {err}"}, 502
        else:
            # tail lines came back full: there may be more — that is all msb says.
            payload, code = {"source": "live", "lines": lines,
                             "truncated": len(lines) >= tail}, 200
        _OUTPUT_CACHE[key] = (time.monotonic(), payload, code)
        return payload, code


_DIFF_TIMEOUT = 30
_DIFF_MAX_BYTES = 2 << 20

# One in-guest pass for /api/session/<ident>/diff: status, then a patch against $1, split
# by a marker. Both gits run with --no-pager and GIT_PAGER=cat: a pager would block until
# _DIFF_TIMEOUT and draw `(END)` on the guest console, which the output snapshot reads.
_DIFF_SH = """\
set -eu
GIT_PAGER=cat; export GIT_PAGER
{cd}git --no-pager status --porcelain
echo SILKGATE_DIFF_SPLIT
git --no-pager diff "$1"
"""


def _diff_in_guest(meta):
    """(status, diff, error) from a live guest — a branch session diffs through the
    GIT_DIR/GIT_WORK_TREE pair, a checkout session from /workspace where its clone's
    own .git lives."""
    if meta.get("branch"):
        script, env = _DIFF_SH.format(cd=""), git._BRANCH_ENV
    else:
        script, env = _DIFF_SH.format(cd="cd /workspace\n"), ()
    try:
        # stdin closed: the script reads none, and msb exec waits on an inherited
        # stdin for EOF (see tier1_fault) — a detached caller's would never close.
        proc = subprocess.run(core.msb_exec_argv(meta["sandbox"],
                                                 ["sh", "-c", script, "_", meta["base"]],
                                                 env=env),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors="replace", start_new_session=True,
                              timeout=_DIFF_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None, None, "the guest did not answer the diff request in time"
    if proc.returncode:
        return None, None, (proc.stderr.strip().splitlines()
                            or ["guest git diff failed"])[-1]
    status, sep, diff = proc.stdout.partition("SILKGATE_DIFF_SPLIT\n")
    if not sep:
        return None, None, "no diff verdict from the guest"
    return status, diff, None


def _clip_text(text, cap):
    """(text within `cap` utf-8 bytes, whether it was cut)."""
    data = text.encode("utf-8", "replace")
    if len(data) <= cap:
        return text, False
    return data[:cap].decode("utf-8", "replace"), True


def _run_msb_metrics():
    """`msb metrics --format json` parsed, or None on any failure — the seam
    /api/metrics stubs in tests and the TTL cache sits in front of."""
    msb = shutil.which("msb")
    if not msb:
        return None
    try:
        proc = subprocess.run([msb, "metrics", "--format", "json"],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode:
        return None
    try:
        parsed = json.loads(proc.stdout)
    except ValueError:
        return None
    return parsed


def _metrics_snapshot():
    """The /api/metrics payload, behind a 2 s TTL cache under one lock, so N tabs cost one
    msb call per TTL. An empty registry skips msb, and a failure is cached like a success,
    so a hung msb isn't re-poked every poll.

    Each row is msb's entry, with one rename: msb's memory gauge is the VMM's host-side RSS,
    not guest usage, and can exceed the guest cap. So it's `memory_rss_bytes`, never framed
    as a ratio of `memory_limit_bytes`."""
    with _METRICS_LOCK:
        now = time.monotonic()
        if (_METRICS_CACHE["at"] is not None
                and now - _METRICS_CACHE["at"] < UI_METRICS_TTL):
            return _METRICS_CACHE["payload"]
        metrics = []
        metas = core.list_metas()
        if metas:
            raw = _run_msb_metrics()
            by_sandbox = {}
            if isinstance(raw, list):                # msb's native shape: one entry per
                for entry in raw:                    # sandbox, named inside the entry
                    if isinstance(entry, dict) and entry.get("name"):
                        by_sandbox[str(entry["name"])] = entry
            elif isinstance(raw, dict):
                by_sandbox = {k: v for k, v in raw.items() if isinstance(v, dict)}
            for m in metas:
                entry = by_sandbox.get(m["sandbox"])
                if entry is not None:
                    row = {k: v for k, v in entry.items() if k != "name"}
                    if "memory_bytes" in row:
                        row["memory_rss_bytes"] = row.pop("memory_bytes")
                    metrics.append({"session": m["name"], **row})
        payload = {"sampled": core.now_iso(), "ttl": UI_METRICS_TTL, "metrics": metrics}
        _METRICS_CACHE.update(at=now, payload=payload)
        return payload


def _search_files():
    """(path, source) pairs for /api/search, newest file first by mtime across the
    capture trail, the audit trail and every archived journal — so an early exit
    keeps the freshest records."""
    entries = []
    for pattern, source in (("capture-*.jsonl", "capture"), ("events-*.jsonl", "audit")):
        entries += [(p, source) for p in paths.LOG_DIR.glob(pattern)]
    if paths.ARCHIVE_DIR.is_dir():
        entries += [(d / "journal.jsonl", "journal") for d in paths.ARCHIVE_DIR.iterdir()
                    if core._SID_RE.fullmatch(d.name) and (d / "journal.jsonl").is_file()]

    def mtime(entry):
        try:
            return entry[0].stat().st_mtime
        except OSError:
            return 0.0
    return sorted(entries, key=mtime, reverse=True)


def _search_trail(query, session, limit):
    """(results, truncated) for /api/search: a case-folded substring scan of the raw
    JSONL lines, newest file first and newest line first within a file, early-exited
    at `limit` results and at a scanned-bytes ceiling.

    A bounded linear scan fits one operator's trails. If the ceiling starts truncating
    routine queries, add an SQLite index over the same files."""
    needle = query.casefold()
    results, scanned = [], 0
    for path, source in _search_files():
        if len(results) >= limit or scanned >= UI_SEARCH_MAX_BYTES:
            return results, True
        # Journal records carry no session field; the archive's sid names it
        # (<stamp>-<name>-<hex>), so the filter still lands.
        journal_session = path.parent.name[17:-7] if source == "journal" else None
        try:
            data = path.read_bytes()
        except OSError:
            continue
        scanned += len(data)
        for line in reversed(data.decode("utf-8", "replace").splitlines()):
            if needle not in line.casefold():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            if session is not None:
                held = journal_session if source == "journal" else rec.get("session")
                if held != session:
                    continue
            results.append({"source": source, "record": rec})
            if len(results) >= limit:
                return results, True
    return results, False


def _session_state(name):
    """One live session's state as the UI reports it: "frozen" while rules.frozen
    holds the preserved ruleset, else "live". The VM runs either way — frozen is
    about egress, not placement, so archive stays out of this answer."""
    return "frozen" if (core.session_dir(name) / "rules.frozen").exists() else "live"


def _freeze_session(name):
    """Freeze one live session's egress: rules.txt moves to rules.frozen and an empty
    ruleset takes its place — deny-by-default does the rest, since the addon re-reads
    the session's rules on every resolve. Why it failed, or None."""
    sdir = core.session_dir(name)
    if (sdir / "rules.frozen").exists():
        return "already frozen"
    try:
        (sdir / "rules.txt").rename(sdir / "rules.frozen")
        (sdir / "rules.txt").write_text("")
    except OSError as e:
        return f"could not freeze: {e}"
    core._journal(name, "frozen")
    return None


def _resume_session(name):
    """Undo _freeze_session: the preserved ruleset moves back over the empty one (one
    atomic rename). Why it failed, or None."""
    sdir = core.session_dir(name)
    if not (sdir / "rules.frozen").exists():
        return "not frozen"
    try:
        (sdir / "rules.frozen").rename(sdir / "rules.txt")
    except OSError as e:
        return f"could not resume: {e}"
    core._journal(name, "resumed")
    return None


_KILL_GRACE = 5     # seconds between TERM and the KILL escalation, in-guest

# One in-guest pass for the kill endpoint: signal the process group the exec's
# pidfile names, politely first, then hard once the grace runs out. The pidfile is
# guest-written, so its content is held to digits before it reaches kill's argv.
_KILL_SH = ("set -eu\n"
            f'pidfile={core.GUEST_EXECS}/$1.pid\n'
            'if [ ! -f "$pidfile" ]; then echo SILKGATE_NO_PIDFILE; exit 0; fi\n'
            'pgid=$(cat "$pidfile")\n'
            'case "$pgid" in ""|*[!0-9]*) echo SILKGATE_NO_PIDFILE; exit 0;; esac\n'
            'kill -TERM -- -"$pgid" 2>/dev/null || :\n'
            f'i=0; while [ $i -lt {_KILL_GRACE} ] && kill -0 -- -"$pgid" 2>/dev/null; '
            'do sleep 1; i=$((i+1)); done\n'
            'if kill -0 -- -"$pgid" 2>/dev/null; '
            'then kill -KILL -- -"$pgid" 2>/dev/null || :; fi\n'
            'echo SILKGATE_KILLED\n')


def _kill_in_guest(meta, exec_id):
    """(token, detail) from the guest: SILKGATE_KILLED, SILKGATE_NO_PIDFILE (the exec
    already ended — its wrapper's trap removed the pidfile), or SILKGATE_ERROR."""
    try:
        # stdin closed: the script reads none, and msb exec waits on an inherited
        # stdin for EOF (see tier1_fault) — a detached caller's would never close.
        proc = subprocess.run(core.msb_exec_argv(meta["sandbox"],
                                                 ["sh", "-c", _KILL_SH, "_", exec_id]),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              start_new_session=True,
                              timeout=_KILL_GRACE + core._MSB_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return "SILKGATE_ERROR", "the guest did not answer the kill request in time"
    for line in reversed(proc.stdout.splitlines()):
        token = line.strip()
        if token in ("SILKGATE_KILLED", "SILKGATE_NO_PIDFILE"):
            return token, ""
    return "SILKGATE_ERROR", (proc.stderr.strip().splitlines()
                              or ["no verdict from the guest"])[-1]


def _ui_server(port):
    """The bound, threaded HTTP server behind `silkgate ui`; the caller runs it.

    Threaded, because one open SSE stream would block a plain HTTPServer. Daemon threads,
    so Ctrl-C's os._exit reaps open streams. Every response sends nosniff and a self-only
    CSP: even a record that smuggles markup can't send the trail anywhere.

    No auth, by design: the 127.0.0.1 bind is the boundary, and Tier 1 keeps guests off
    every host port. Never bind beyond loopback. Remote use is an SSH tunnel, and a future
    --bind needs token auth first. Against the host's own browsers, every request needs a
    loopback Host (a DNS-rebound page sends its own) and a loopback Origin, if present.
    """
    # Local imports: only this command needs an HTTP server, and every `silkgate exec`
    # would otherwise pay for importing one.
    import urllib.parse
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "silkgate-ui"
        sys_version = ""

        def log_message(self, *a):               # the events files are the record
            pass

        def _security(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'")

        def _reply(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self._security()
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, code=200):
            self._reply(code, "application/json", json.dumps(obj).encode())

        def _guarded(self):
            """Whether this request came from this host's browser, pointed at this server.

            Host must be loopback, which a DNS-rebound page fails. A present Origin must be
            loopback too, and browsers always send it on cross-origin POSTs. That guards
            every endpoint that runs `msb exec` or tears a session down."""
            loopback = ("127.0.0.1", "localhost", "::1")
            try:
                host = urllib.parse.urlsplit("//" + (self.headers.get("Host") or ""))
            except ValueError:
                return False
            if host.hostname not in loopback:
                return False
            origin = self.headers.get("Origin")
            if origin is None:
                return True
            try:
                parts = urllib.parse.urlsplit(origin)
            except ValueError:
                return False
            return parts.scheme in ("http", "https") and parts.hostname in loopback

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            query = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query).items()}
            try:
                if not self._guarded():
                    return self._json({"error": "forbidden"}, 403)
                if url.path == "/api/sessions":
                    self._sessions()
                elif url.path == "/api/events":
                    self._events(query)
                elif url.path == "/api/capture":
                    self._capture(query)
                elif url.path == "/api/stream":
                    self._stream(query)
                elif url.path == "/api/capture/stream":
                    self._stream(query, meta_key="capture")
                elif url.path == "/api/metrics":
                    self._json(_metrics_snapshot())
                elif url.path == "/api/search":
                    self._search(query)
                elif url.path.startswith("/api/session/"):
                    ident, _, sub = url.path[len("/api/session/"):].partition("/")
                    if not sub:
                        self._session(ident)
                    elif sub == "output":
                        self._output(ident, query)
                    else:
                        self._json({"error": "not found"}, 404)
                else:
                    self._static(url.path)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True     # the tab closed; nobody to answer

        def do_POST(self):
            # POSTs are the control plane: freeze/resume/down/kill/diff all reach a
            # guest or the registry, so the guard above is what stands between them
            # and any web page (see _guarded — Origin is always on a cross-site POST).
            self.close_connection = True         # request bodies are never read here
            url = urllib.parse.urlsplit(self.path)
            parts = url.path.split("/")
            try:
                if not self._guarded():
                    return self._json({"error": "forbidden"}, 403)
                if parts[:3] == ["", "api", "session"] and len(parts) == 5 \
                        and parts[4] in ("freeze", "resume", "down", "diff"):
                    if parts[4] == "diff":
                        self._diff(parts[3])
                    else:
                        self._control(parts[3], parts[4])
                elif parts[:3] == ["", "api", "session"] and len(parts) == 7 \
                        and parts[4] == "exec" and parts[6] == "kill":
                    self._kill(parts[3], parts[5])
                else:                            # POST exists for the control plane
                    self._refuse()               # alone; everything else stays 405
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def _refuse(self):
            self.close_connection = True         # keep a HEAD from desyncing keep-alive
            self._json({"error": "method not allowed"}, 405)

        do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _refuse

        def _static(self, path):
            route = _UI_ROUTES.get(path)
            if route is None:
                return self._json({"error": "not found"}, 404)
            name, ctype = route
            try:
                body = (UI_DIR / name).read_bytes()
            except OSError:
                return self._json({"error": f"{name} is missing from {UI_DIR}"}, 404)
            self._reply(200, ctype, body)

        def _sessions(self):
            meta = core.read_proxy() or {}
            ident = core._proxy_ident()               # identity via the control socket, as ever:
            running = ident is not None          # a recycled pid must not read as "running"
            # Archived rows carry the keys a listing needs; /api/session/<sid> has
            # the rest. last_rc rides along only where an exec_end recorded one.
            archived = [{"sid": m["sid"], "name": m.get("name"),
                         "created": m.get("created"),
                         "ended": m.get("ended"),
                         **({"last_rc": m["last_rc"]} if "last_rc" in m else {}),
                         **({"branch": m["branch"]} if m.get("branch") else {})}
                        for m in reversed(core.list_archived_metas()[-UI_ARCHIVED_LIMIT:])]
            self._json({"sessions": [{**m, "state": _session_state(m["name"])}
                                     for m in core.list_metas()],
                        "archived": archived,
                        "proxy": {"running": running,
                                  "pid": (ident or meta.get("pid")) if running else None,
                                  "ports": meta.get("ports"),
                                  "started": meta.get("started"),
                                  "log": meta.get("log"),
                                  "events": meta.get("events")}})

        def _limit(self, query, default, cap):
            """The validated limit parameter, or None after a 400 went out."""
            try:
                limit = int(query.get("limit", default))
            except ValueError:
                self._json({"error": "limit: not an integer"}, 400)
                return None
            if limit < 1:
                self._json({"error": "limit: must be >= 1"}, 400)
                return None
            return min(limit, cap)

        def _page(self, filters, limit, meta_key, pattern):
            """One history page plus the live cursor — /api/events and /api/capture
            differ only in which trail they read. The live file's size is read BEFORE
            the history: a record appended between the two shows up in both history
            and the stream — the client dedupes on (id, decision) — where a size read
            after would show it in neither."""
            cursor = None
            live = (core.read_proxy() or {}).get(meta_key)
            if live:
                try:
                    cursor = f"{Path(live).name}:{Path(live).stat().st_size}"
                except OSError:
                    cursor = f"{Path(live).name}:0"
            self._json({"events": _events_history(filters, limit, pattern),
                        "cursor": cursor})

        def _events(self, query):
            filters = {}
            for key in ("since", "until"):
                if key in query:
                    try:
                        t = datetime.fromisoformat(query[key])
                    except ValueError:
                        return self._json({"error": f"{key}: not an ISO-8601 timestamp"},
                                          400)
                    if t.tzinfo is None:         # records are offset-aware; comparing one
                        return self._json(       # to a naive time raises, so refuse early
                            {"error": f"{key}: needs a UTC offset "
                                      f"(e.g. {query[key]}+00:00)"}, 400)
                    filters[key] = t
            for key in ("session", "decision", "method", "host"):
                if key in query:
                    filters[key] = query[key]
            limit = self._limit(query, UI_EVENTS_LIMIT, UI_EVENTS_LIMIT_MAX)
            if limit is None:
                return
            self._page(filters, limit, "events", "events-*.jsonl")

        def _capture(self, query):
            filters = {}
            if "session" in query:
                filters["session"] = query["session"]
            limit = self._limit(query, UI_EVENTS_LIMIT, UI_EVENTS_LIMIT_MAX)
            if limit is None:
                return
            self._page(filters, limit, "capture", "capture-*.jsonl")

        def _search(self, query):
            q = query.get("q") or ""
            if len(q) < UI_SEARCH_MIN_QUERY:
                return self._json(
                    {"error": f"q: need at least {UI_SEARCH_MIN_QUERY} characters"}, 400)
            limit = self._limit(query, UI_SEARCH_LIMIT, UI_SEARCH_LIMIT)
            if limit is None:
                return
            results, truncated = _search_trail(q, query.get("session"), limit)
            self._json({"results": results, "truncated": truncated})

        def _session(self, ident):
            meta, state, sdir = _resolve_ident(ident)
            if meta is None:
                return self._json({"error": f"no such session: {ident}"}, 404)
            try:
                rules = (sdir / "rules.txt").read_text(encoding="utf-8",
                                                       errors="replace")
            except OSError:
                rules = ""
            proxy = core.read_proxy() or {}
            # A live session can be frozen. Only the reported state says so:
            # `state` is placement (live vs archived) and keeps driving the
            # briefs map — a frozen VM still runs, so it reads as live there.
            reported = _session_state(meta["name"]) if state == "live" else state
            self._json({"session": meta, "state": reported,
                        "journal": core._read_journal(sdir / "journal.jsonl"),
                        "briefs": _session_briefs(meta, state, sdir),
                        "rules": rules,
                        "pointers": {"events": proxy.get("events"),
                                     "captures": [str(p) for p in
                                                  _events_files("capture-*.jsonl")]}})

        def _output(self, ident, query):
            meta, state, sdir = _resolve_ident(ident)
            if meta is None:
                return self._json({"error": f"no such session: {ident}"}, 404)
            try:
                tail = int(query.get("tail", UI_OUTPUT_TAIL))
            except ValueError:
                return self._json({"error": "tail: not an integer"}, 400)
            if tail < 1:
                return self._json({"error": "tail: must be >= 1"}, 400)
            payload, code = _session_output(meta, state, sdir,
                                            min(tail, UI_OUTPUT_TAIL_MAX))
            self._json(payload, code)

        def _diff(self, ident):
            meta, state, sdir = _resolve_ident(ident)
            if meta is None:
                return self._json({"error": f"no such session: {ident}"}, 404)
            with _DIFF_LOCK:
                if ident in _DIFF_BUSY:          # one guest git per session at a time
                    return self._json(
                        {"error": "a diff for this session is already running"}, 429)
                _DIFF_BUSY.add(ident)
            try:
                if state == "live":
                    if not (meta.get("branch") or meta.get("checkout")):
                        return self._json(
                            {"error": "this session has no git checkout to diff"}, 409)
                    status, diff, err = _diff_in_guest(meta)
                    if err is not None:
                        return self._json({"error": err}, 409)
                    diff, truncated = _clip_text(diff, _DIFF_MAX_BYTES)
                    return self._json({"mode": "guest", "status": status,
                                       "diff": diff, "truncated": truncated})
                if not meta.get("branch"):
                    return self._json(
                        {"error": "this session had no branch — nothing came back"}, 409)
                if not meta.get("branch_ingested"):
                    return self._json(
                        {"error": "never harvested — no commits reached the host"}, 409)
                proc = git._git(meta["git_dir"], "diff",
                                f"{meta['base']}..refs/heads/{meta['branch']}")
                if proc is None or proc.returncode:
                    return self._json({"error": "host git diff failed — the branch "
                                                "may be gone from the repository"}, 409)
                diff, truncated = _clip_text(proc.stdout, _DIFF_MAX_BYTES)
                # An archived diff has no worktree, so there is no status to report.
                self._json({"mode": "host", "status": "", "diff": diff,
                            "truncated": truncated})
            finally:
                with _DIFF_LOCK:
                    _DIFF_BUSY.discard(ident)

        # This and _kill are mirrored in README.md (Audit UI). Update both.
        def _control(self, ident, action):
            meta, state, _ = _resolve_ident(ident)
            if meta is None:
                return self._json({"error": f"no such session: {ident}"}, 404)
            if state != "live":
                return self._json(
                    {"error": "an archived session cannot be controlled"}, 409)
            if action == "down":
                try:
                    core._down_session(meta)
                except SystemExit:               # die() inside the teardown: kept whole
                    return self._json({"error": "teardown failed — the session is "
                                                "kept; run `silkgate down` for the "
                                                "full report"}, 409)
                return self._json({"ok": True})
            err = (_freeze_session(meta["name"]) if action == "freeze"
                   else _resume_session(meta["name"]))
            if err is not None:
                return self._json({"error": err}, 409)
            self._json({"ok": True})

        def _kill(self, ident, exec_id):
            if not _EXEC_ID_RE.fullmatch(exec_id or ""):   # before it nears any argv
                return self._json({"error": f"invalid exec id: {exec_id}"}, 400)
            meta, state, _ = _resolve_ident(ident)
            if meta is None:
                return self._json({"error": f"no such session: {ident}"}, 404)
            if state != "live":
                return self._json(
                    {"error": "an archived session has nothing to kill"}, 409)
            token, detail = _kill_in_guest(meta, exec_id)
            if token == "SILKGATE_KILLED":
                core._journal(meta["name"], "killed", exec_id=exec_id)
                return self._json({"ok": True})
            if token == "SILKGATE_NO_PIDFILE":
                return self._json({"error": f"no pidfile for exec {exec_id} — "
                                            "it already ended"}, 409)
            self._json({"error": detail or "kill failed"}, 409)

        def _stream(self, query, meta_key="events"):
            tailer = _EventsTailer(self.headers.get("Last-Event-ID")
                                   or query.get("cursor"), meta_key=meta_key)
            self.close_connection = True         # no Content-Length: the stream is the body
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self._security()
            self.end_headers()
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()                   # BufferedWriter: an unflushed SSE frame
            beat = time.monotonic()              # sits in the buffer, never on the wire
            while True:
                try:
                    for kind, payload, cursor in tailer.poll(core.read_proxy()):
                        if kind == "reset":
                            frame = f"id: {cursor}\nevent: reset\ndata: {{}}\n\n"
                        else:
                            frame = f"id: {cursor}\ndata: {payload}\n\n"
                        self.wfile.write(frame.encode())
                        self.wfile.flush()
                        beat = time.monotonic()
                    if time.monotonic() - beat >= UI_STREAM_HEARTBEAT:
                        self.wfile.write(b": alive\n\n")
                        self.wfile.flush()
                        beat = time.monotonic()
                except (BrokenPipeError, ConnectionResetError):
                    return                       # closed tab: this thread's work is done
                time.sleep(UI_STREAM_POLL)

    class Server(ThreadingHTTPServer):
        daemon_threads = True                    # Ctrl-C must not wait on an open stream

    return Server(("127.0.0.1", port), Handler)


def cmd_ui(args):
    """Serve the local audit UI: static assets from ui/ plus the sessions, history and
    live-stream endpoints. Needs no running proxy — history and session listings work
    on their own, and the stream heartbeats until a proxy appears."""
    if not (UI_DIR / "index.html").is_file():
        core.die(f"ui assets not found at {UI_DIR} — run from a complete checkout "
                 "(the ui/ directory ships with the repo)")
    try:
        server = _ui_server(args.port)
    except OSError:
        core.die(f"cannot bind the ui at 127.0.0.1:{args.port} — "
                 + core._port_in_use_error(args.port))
    host, port = server.server_address[:2]
    core.say(f"silkgate ui at http://{host}:{port}/ — Ctrl-C stops it")
    server.serve_forever()
