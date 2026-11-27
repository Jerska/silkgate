"""The shared mitmdump proxy: its ports, its start and stop, its logs, its CA, and its control
socket."""
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

import rule_engine

from . import console, core, foreground, paths


# Mirrored in doc/PROXY.md (The port pool). Update both.
POOL_SIZE = 16                                 # base_port .. base_port+15
DEFAULT_BASE_PORT = 8090
PROXY_ALIAS = "host.microsandbox.internal"   # resolves via the guest's /etc/hosts
PROXY_ENV_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")


# --- host processes ----------------------------------------------------------

# Where proxy listeners bind. Guests reach host.microsandbox.internal, an address the VMM
# owns, and the VMM delivers that traffic over loopback (observed on macOS/HVF). So loopback
# serves every guest and keeps the pool ports, each an allowlist with credential injection,
# off the LAN. mitmdump's default bind would expose them on every interface.
#
# Both loopback families: the guest's /etc/hosts also maps the alias to IPv6, and
# getaddrinfo prefers it. With a v4-only listener, curl's [::1] connection dies on a reset
# that looks like a proxy deny. If your microsandbox routes guests through a real bridge
# address, name it: SILKGATE_PROXY_BIND=<address>[,<address>] silkgate up ...
PROXY_BINDS = tuple(a.strip() for a in
                    os.environ.get("SILKGATE_PROXY_BIND", "127.0.0.1,::1").split(",")
                    if a.strip())


def _modes(port):
    """`--mode` arguments placing one regular-proxy listener per bind address on `port`.

    One mode per address is the only way to bind several. The spec splits host from port
    at the last colon, so an IPv6 literal goes in bare: brackets would fail to resolve.
    """
    args = []
    for addr in PROXY_BINDS:
        args += ["--mode", f"regular@{addr}:{port}"]
    return args


def _probe_addrs(port):
    """Where readiness checks dial `port`: every bind address, so probe and bind cannot
    drift apart — except a wildcard bind, which is dialed via loopback."""
    addrs = []
    for host in (PROXY_BINDS or ("127.0.0.1",)):
        if host == "0.0.0.0":
            host = "127.0.0.1"
        elif host == "::":
            host = "::1"
        addrs.append((host, port))
    return addrs


def _probe_addr(port):
    """The first probe address — for a check that needs one dialable place, not all."""
    return _probe_addrs(port)[0]


def _port_free(port):
    """Whether `port` can be bound on every bind address, asked by binding, as mitmdump
    will. The readiness probe can't answer this: a squatter answers a connect before a
    fresh mitmdump even binds. SO_REUSEADDR keeps a TIME_WAIT from reading as a squatter."""
    for host in PROXY_BINDS:
        try:
            with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
        except OSError:
            return False
    return True


def _port_in_use_error(port):
    """Why `port` can't be taken, naming the holder when it's the shared proxy (it answers
    its control socket). That's the usual holder: an orphaned proxy keeps all sixteen pool
    ports. Unnamed, the collision surfaces as 403s inside a verify guest, far from its cause."""
    ident = _proxy_ident()
    pool = (read_proxy() or {}).get("ports") or []
    if ident is not None and (not pool or port in pool):
        return (f"port {port} is already in use by pid {ident or 'unknown'} "
                f"(the shared proxy) — silkgate ls")
    return (f"port {port} is already in use — "
            f"lsof -nP -iTCP:{port} -sTCP:LISTEN names the holder")


def _find_free_pool(base_port):
    """The lowest free POOL_SIZE-wide port range at or above base_port.

    Steps one port at a time, so a single occupied port shifts the pool by one, not by
    POOL_SIZE. Scans 5*POOL_SIZE ports, never past 65535, where bind() raises instead of
    reading as busy. Dies naming every blocker if no range is free."""
    if base_port + POOL_SIZE - 1 > 65535:
        console.die(f"base port {base_port} leaves no room for a {POOL_SIZE}-port pool "
                    f"({base_port}..{base_port + POOL_SIZE - 1} runs past port 65535)")
    limit = min(base_port + 5 * POOL_SIZE, 65536)
    start = base_port
    blockers = []
    while start <= limit - POOL_SIZE:
        blocked = next((p for p in range(start, start + POOL_SIZE)
                        if not _port_free(p)), None)
        if blocked is None:
            return list(range(start, start + POOL_SIZE))
        blockers.append(blocked)
        start = blocked + 1
    console.die(f"no {POOL_SIZE}-port range free in {base_port}..{limit - 1} — blocked by "
                f"listeners on {', '.join(str(p) for p in blockers)} "
                f"(lsof -nP -iTCP:<port> -sTCP:LISTEN names each holder)")


# How long a spawned mitmdump gets to answer on every advertised address.
PROXY_READY_TIMEOUT = 15

# What a lost bind looks like in mitmdump's log: EADDRINUSE's strerror, one casing on
# Linux, another on macOS, matched case-folded.
_BIND_FAILURE = b"address already in use"


def _wait_proxy_ready(proc, ports, log_path):
    """Block until the new mitmdump answers on every address, or stop it and die.

    Its output goes only to the log, so the loop watches the log and fails on the first
    EADDRINUSE, with the log's tail, not after a 15 s timeout. poll() catches a child that
    exits. The caller checked the ports free before the spawn, so a listener is ours."""
    deadline = time.monotonic() + PROXY_READY_TIMEOUT
    addr = _probe_addr(ports[0])
    while True:
        if proc.poll() is not None:
            console.die(f"proxy exited at startup — {log_path}:\n{console.tail(log_path)}")
        if _BIND_FAILURE in log_path.read_bytes().lower():
            foreground.stop(proc)
            console.die(f"proxy failed to bind — {log_path}:\n{console.tail(log_path)}")
        try:
            for port in ports:
                for addr in _probe_addrs(port):
                    with socket.create_connection(addr, timeout=0.5):
                        pass
            return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            foreground.stop(proc)
            console.die(f"proxy did not answer at {addr[0]}:{addr[1]} within "
                        f"{PROXY_READY_TIMEOUT}s — {log_path}:\n{console.tail(log_path)}")
        time.sleep(0.2)


# Retention for ~/.silkgate/logs. Each proxy start writes a new proxy-<stamp>.log, plus a
# .rules snapshot on the single-ruleset paths. The audit trail backs incident review, so
# pruning favors keeping: a file goes only when it's BOTH older than the retention age AND
# beyond the newest LOG_RETAIN_COUNT of its kind. Every removal is announced, and
# SILKGATE_LOG_RETAIN_DAYS=0 keeps everything.
# Mirrored with ARCHIVE_RETAIN_* in doc/PROXY.md (Retention). Update both.
LOG_RETAIN_DAYS = 30
LOG_RETAIN_COUNT = 20
# Capture files hold conversation content — bulkier and more sensitive than audit
# metadata — so they get a shorter default: a working week of look-back suffices.
CAPTURE_RETAIN_DAYS = 7
_LOG_PATTERNS = ("proxy-*.log", "proxy-*.rules", "standalone-*.rules", "events-*.jsonl")


def _retain_days(var, default):
    """One retention knob: the env override where it parses, the default otherwise."""
    try:
        return float(os.environ.get(var, "") or default)
    except ValueError:
        return default


def _prune_kind(pattern, cutoff, live):
    """One kind's removals under the policy above: only files BOTH beyond the newest
    LOG_RETAIN_COUNT of the kind AND older than `cutoff`, never one in `live`."""
    stamped = []
    for p in paths.LOG_DIR.glob(pattern):
        try:
            stamped.append((p.stat().st_mtime, p))
        except OSError:                          # vanished mid-scan: already gone
            continue
    stamped.sort(reverse=True)
    pruned = 0
    for mtime, p in stamped[LOG_RETAIN_COUNT:]:
        if p in live or mtime >= cutoff:
            continue
        try:
            p.unlink()
            pruned += 1
        except OSError:
            pass
    return pruned


def _prune_logs():
    """Apply the retention policy above; runs where log files are created.

    A live proxy's log is safe twice: proxy.json names it, and writes keep its mtime fresh,
    which also covers a foreground proxy with no proxy.json. Audit kinds age on
    LOG_RETAIN_DAYS, capture files on CAPTURE_RETAIN_DAYS. A knob at 0 or less turns off
    retention for its own kinds only."""
    _proxy_meta = read_proxy() or {}
    live = {Path(v) for k in ("log", "events", "capture") if (v := _proxy_meta.get(k))}
    pruned = 0
    for patterns, days in (
            (_LOG_PATTERNS, _retain_days("SILKGATE_LOG_RETAIN_DAYS", LOG_RETAIN_DAYS)),
            (("capture-*.jsonl",),
             _retain_days("SILKGATE_CAPTURE_RETAIN_DAYS", CAPTURE_RETAIN_DAYS))):
        if days <= 0:
            continue
        cutoff = time.time() - days * 86400
        for pattern in patterns:
            pruned += _prune_kind(pattern, cutoff, live)
    if pruned:
        console.say(f"pruned {pruned} audit log file(s) past retention from {paths.LOG_DIR} "
                    f"(the {LOG_RETAIN_COUNT} newest of each kind always stay; "
                    "SILKGATE_LOG_RETAIN_DAYS=0 and SILKGATE_CAPTURE_RETAIN_DAYS=0 keep "
                    "everything)")


def start_proxy(rules_text, port):
    """Start a single-ruleset mitmdump in the background; return (proc, audit log path).

    The port is checked free before the spawn, and the child watched after it
    (_port_free, _wait_proxy_ready), because a bare connect can't tell this proxy from a
    squatter. An orphaned proxy would answer while ours died, and a verify guest would run
    under the wrong ruleset."""
    mitmdump = console.which("mitmdump", "pip install mitmproxy")
    if not _port_free(port):
        console.die(_port_in_use_error(port))
    paths.LOG_DIR.mkdir(parents=True, exist_ok=True)
    _prune_logs()
    stamp = f"{datetime.now():%Y%m%d-%H%M%S}"
    log_path = paths.LOG_DIR / f"proxy-{stamp}.log"
    events_path = paths.LOG_DIR / f"events-{stamp}.jsonl"
    capture_path = paths.LOG_DIR / f"capture-{stamp}.jsonl"
    rules_file = paths.LOG_DIR / f"proxy-{stamp}.rules"
    rules_file.write_text(rules_text)
    env = dict(os.environ, SILKGATE_EGRESS_RULES=str(rules_file),
               SILKGATE_EGRESS_EVENTS_FILE=str(events_path),
               SILKGATE_EGRESS_CAPTURE_FILE=str(capture_path))
    env.pop("SILKGATE_EGRESS_SESSIONS_DIR", None)
    # rawtcp=false: a CONNECT whose payload mitmproxy cannot read as TLS is refused
    # instead of becoming an opaque tunnel around the addon's per-request checks.
    argv = [mitmdump, "-s", str(paths.ADDON), "--set", "rawtcp=false"] + _modes(port)
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(argv, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        _wait_proxy_ready(proc, [port], log_path)
    except BaseException:       # incl. a Ctrl-C mid-wait: the caller has no handle on
        foreground.stop(proc)   # the child yet, so an exit here is the last chance to
        raise                   # stop it (stop is a no-op where the wait already did)
    return proc, log_path


def ensure_ca():
    """Return a guest-safe copy of the CA *certificate*, generating the CA on first use.

    ~/.mitmproxy also holds the private key, so that directory is never handed out.
    Callers get a directory with the public cert alone.

    Generation opens no socket: `mitmdump --no-server`, with an addon that exits once
    startup is done, writes the CA and never listens. A listener here would be a proxy
    with no rules.
    """
    if not paths.MITM_CA.is_file():
        mitmdump = console.which("mitmdump", "pip install mitmproxy")
        console.say("generating the mitmproxy CA (first run)…")
        with tempfile.TemporaryDirectory(prefix="silkgate-ca-") as tmp:
            addon = Path(tmp) / "shutdown_after_startup.py"
            addon.write_text("from mitmproxy import ctx\n"
                             "\n"
                             "def running():\n"
                             "    ctx.master.shutdown()\n")
            argv = [mitmdump, "--no-server", "-s", str(addon),
                    "--set", f"confdir={paths.MITM_CA.parent}"]
            try:
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                console.die(f"mitmdump did not finish generating {paths.MITM_CA} within 60s")
        if not paths.MITM_CA.is_file():
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            console.die(f"mitmdump did not create {paths.MITM_CA}"
                        + (f" — {detail[-1]}" if detail else ""))
    paths.CA_DIR.mkdir(parents=True, exist_ok=True)
    cert = paths.CA_DIR / "egress-ca.pem"
    shutil.copyfile(paths.MITM_CA, cert)
    return cert


# --- shared proxy -----------------------------------------------------------

def read_proxy():
    return core._read_json(paths.PROXY_JSON)


def proxy_alive(pid):
    """Whether *some* process holds `pid` — liveness only, never identity: after an
    unclean exit the pid in proxy.json may belong to a recycled, unrelated process.
    Anything that trusts or signals the proxy goes through _proxy_ident() instead."""
    if not pid:
        return False
    try:
        # An exited child of this process that nobody reaped is a zombie, and a zombie
        # still answers kill -0 — stop_proxy would wait its whole grace on the corpse.
        # Reap it if it is ours; ECHILD means it is not, and kill -0 decides below.
        if os.waitpid(pid, os.WNOHANG)[0] == pid:
            return False
    except OSError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True          # exists but not ours — count it alive
    return True


def _peer_pid(sock):
    """The pid on the far end of a connected unix socket, straight from the kernel;
    0 if it cannot say (callers treat that as alive-but-unnamed)."""
    try:
        if hasattr(socket, "SO_PEERCRED"):        # Linux: struct ucred {pid, uid, gid}
            import struct
            cred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                   struct.calcsize("3i"))
            return struct.unpack("3i", cred)[0]
        return sock.getsockopt(0, 0x0002)          # macOS: SOL_LOCAL, LOCAL_PEERPID
    except OSError:
        return 0


def _proxy_ident():
    """The pid of the live shared proxy, or None if nothing is — identity, not liveness.

    Only the process bound to our control socket can answer a ping, and the kernel names
    that peer. proxy.json can outlive or misname its process. Returns 0 for a proxy that
    answered but whose pid the kernel couldn't report."""
    if not paths.PROXY_SOCK.exists():
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(str(paths.PROXY_SOCK))
            f = s.makefile("rw")
            f.write('{"op": "ping"}\n')
            f.flush()
            line = f.readline()
            if not line or not json.loads(line).get("ok"):
                return None
            return _peer_pid(s)
    except (OSError, ValueError):
        return None


def _proxy_running():
    return _proxy_ident() is not None


class _proxy_lock:
    """Exclusive advisory lock over proxy lifecycle and port claims (flock, so the
    kernel drops it with the process — it cannot go stale). Serializing proxy start,
    proxy stop and port claiming is what keeps a `down` that found no sessions from
    killing the proxy between another command's ensure_proxy and its port claim."""

    def __enter__(self):
        import fcntl
        paths.SILK_DIR.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(paths.SILK_DIR / "proxy.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self._fd, fcntl.LOCK_EX)

    def __exit__(self, *exc):
        os.close(self._fd)


def _clear_proxy_files():
    for p in (paths.PROXY_JSON, paths.PROXY_SOCK):
        try:
            p.unlink()
        except OSError:
            pass


def start_shared_proxy(base_port, ports=None):
    """Start the detached multi-session mitmdump; write proxy.json; return its meta.

    Without `ports`, the pool is the first free range at or above base_port
    (_find_free_pool). `ports` is a pool a restart must reuse, because sessions pin it
    (_pinned_pool). Either way, every port is checked free before the spawn, and ready
    means all of them answer, with the child and its log watched (see start_proxy).
    proxy.json appears only then, so it never records a proxy that didn't come up."""
    mitmdump = console.which("mitmdump", "pip install mitmproxy")
    if ports is None:
        ports = _find_free_pool(base_port)
    paths.LOG_DIR.mkdir(parents=True, exist_ok=True)
    paths.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    _prune_logs()
    stamp = f"{datetime.now():%Y%m%d-%H%M%S}"
    log_path = paths.LOG_DIR / f"proxy-{stamp}.log"
    events_path = paths.LOG_DIR / f"events-{stamp}.jsonl"
    capture_path = paths.LOG_DIR / f"capture-{stamp}.jsonl"
    # rawtcp=false: a CONNECT whose payload mitmproxy cannot read as TLS is refused
    # instead of becoming an opaque tunnel around the addon's per-request checks.
    argv = [mitmdump, "-s", str(paths.ADDON), "--set", "rawtcp=false"]
    for p in ports:
        argv += _modes(p)
    # Multi-session mode: SILKGATE_EGRESS_SESSIONS_DIR on, SILKGATE_EGRESS_RULES off (addon needs exactly one).
    env = dict(os.environ, SILKGATE_EGRESS_SESSIONS_DIR=str(paths.SESSIONS_DIR),
               SILKGATE_EGRESS_CONTROL_SOCK=str(paths.PROXY_SOCK),
               SILKGATE_EGRESS_EVENTS_FILE=str(events_path),
               SILKGATE_EGRESS_CAPTURE_FILE=str(capture_path))
    env.pop("SILKGATE_EGRESS_RULES", None)
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(argv, env=env, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    # base_port is the pool that landed, not the one asked for — _find_free_pool may have
    # scanned past a squatter, and pick_port re-reads this record to follow it.
    # "capture" also shields the live capture file from _prune_logs, like "log"/"events".
    meta = {"pid": proc.pid, "base_port": ports[0], "ports": ports,
            "log": str(log_path), "events": str(events_path),
            "capture": str(capture_path),
            "sock": str(paths.PROXY_SOCK), "started": core.now_iso()}
    try:
        _wait_proxy_ready(proc, ports, log_path)
        core._write_json(paths.PROXY_JSON, meta)
    except BaseException:       # incl. a Ctrl-C mid-wait: until proxy.json lands, no
        foreground.stop(proc)   # other command can ever find this mitmdump to stop
        raise                   # it (stop is a no-op where the wait already did)
    return meta


def ensure_proxy(base_port):
    """Return the running shared-proxy meta, starting it (on base_port) if need be."""
    with _proxy_lock():
        return _ensure_proxy_locked(base_port)


def _pinned_pool(meta):
    """The exact port pool a proxy restart must reuse, or None when it may float.

    A guest's proxy port is fixed at creation, in its env and its Tier 1 rule. A moved
    pool would strand it, and whoever binds the old port later gets its traffic. So while
    any session or port claim survives, a restart reuses the recorded pool exactly, and
    dies if a port is taken. The caller holds _proxy_lock and calls this before the old
    proxy record, where the pool is read from, is cleared."""
    owners = {}
    for m in core.list_metas():
        if m.get("port"):
            owners.setdefault(m["port"], m["name"])
    for p in _live_claims():
        owners.setdefault(p, (core._read_json(_claim_path(p)) or {}).get("name"))
    if not owners:
        return None
    pool = (meta or {}).get("ports") or []
    strays = sorted(p for p in owners if p not in pool)
    if strays:
        held = ", ".join(f"{p} (session {owners[p]})" for p in strays)
        console.die(f"sessions hold ports no proxy record names a pool for: {held} — "
                    f"`silkgate down` them before the proxy can start")
    for p in pool:
        if not _port_free(p):
            pin = (f"session {owners[p]} is frozen onto it" if owners.get(p) else
                   f"surviving sessions pin the pool to {pool[0]}..{pool[-1]}")
            console.die(f"port {p} is already in use, but {pin} — "
                        f"lsof -nP -iTCP:{p} -sTCP:LISTEN names the holder")
    return pool


def _ensure_proxy_locked(base_port):
    """ensure_proxy's body, for callers already holding _proxy_lock."""
    meta = read_proxy()
    ident = _proxy_ident()
    if ident is not None:                      # something live answers on our socket path
        if meta is None:
            console.die(f"a proxy (pid {ident or 'unknown'}) holds {paths.PROXY_SOCK} but "
                        f"{paths.PROXY_JSON} is gone — kill that process and retry")
        if ident and meta.get("pid") != ident:
            meta["pid"] = ident                # proxy.json outlived the proxy it described;
            core._write_json(paths.PROXY_JSON, meta)  # the socket's owner is the identity
        return meta
    pinned = _pinned_pool(meta)                # read while the stale record still exists
    if meta:                                   # record of a proxy that no longer answers
        _clear_proxy_files()
    meta = start_shared_proxy(base_port, pinned)
    _wait_control_sock(10, meta["pid"])        # port readiness ≠ socket readiness, and
    return meta                                # the socket must answer as that very pid


def stop_proxy(meta):
    """Stop the shared proxy — unless a session or an in-flight port claim still needs it.

    Identity before force: only the process that answers on the control socket is ever
    signalled, so a stale proxy.json whose pid was recycled cannot draw a SIGKILL onto an
    unrelated process. When nothing answers there is nothing to kill, only files to clear."""
    with _proxy_lock():
        if core.list_metas() or _live_claims():
            return
        ident = _proxy_ident()
        if ident is None:
            _clear_proxy_files()
            return
        pid = ident or (meta or {}).get("pid")  # 0 = alive but unnamed: fall back to record
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and proxy_alive(pid):
                time.sleep(0.1)
            if proxy_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        _clear_proxy_files()


# A pool port is claimed when it's picked, by an O_EXCL marker here, long before the
# session's meta.json exists. Without the claim, two concurrent `up`s could pick one port,
# and the addon would police one guest with the other's ruleset. The dot prefix keeps the
# addon from reading claims as sessions.

def _port_claims_dir():
    return paths.SESSIONS_DIR / ".ports"


def _claim_path(port):
    return _port_claims_dir() / str(port)


def _claim_port(port, name):
    """Claim `port` for session `name`; False if a claim already exists."""
    _port_claims_dir().mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(_claim_path(port), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps({"name": name, "pid": os.getpid(), "created": core.now_iso()}))
    return True


def _claim_stale(port, path):
    """Whether a claim is a crash leftover that may be reaped (caller holds _proxy_lock).

    Not stale while its session dir exists — the guest may still hold L3 access to the
    port even if unhealthy, and only `down` frees that — nor while any session's meta
    names the port, nor while the claiming process is alive (provisioning in flight)."""
    info = core._read_json(path) or {}
    name = info.get("name")
    if name and core.session_dir(name).exists():
        return False
    if any(m.get("port") == port for m in core.list_metas()):
        return False
    return not proxy_alive(info.get("pid"))


def _release_port(name, port=None):
    """Drop `name`'s claim(s); with no port to go by, every claim naming the session.
    Only claims naming `name` are touched, so a port that was reaped and re-claimed by
    a newer session is left alone."""
    try:
        paths = [_claim_path(port)] if port else list(_port_claims_dir().iterdir())
    except OSError:
        return
    for path in paths:
        info = core._read_json(path)
        if info and info.get("name") == name:
            try:
                os.unlink(path)
            except OSError:
                pass


def _live_claims():
    """Claimed ports that are not crash leftovers — sessions in flight or kept alive."""
    try:
        names = os.listdir(_port_claims_dir())
    except OSError:
        return []
    return [int(n) for n in names
            if n.isdigit() and not _claim_stale(int(n), _claim_path(int(n)))]


def pick_port(proxy, name):
    """Claim the lowest free pool port for `name` and return it.

    Existing metas count as claims too, so sessions provisioned before their claim file
    existed keep their ports. A claim whose maker died before its session appeared is a
    crash leftover: reaped and reused. A pool held entirely by live sessions and claims
    is genuinely full, and an error."""
    with _proxy_lock():
        taken = {m.get("port") for m in core.list_metas() if m.get("name") != name}
        for p in proxy["ports"]:
            if p in taken:
                continue
            if not _claim_port(p, name):
                if not _claim_stale(p, _claim_path(p)):
                    continue
                _claim_path(p).unlink(missing_ok=True)   # leftover; reaped under the lock
                if not _claim_port(p, name):
                    continue
            # A `down <last>` may have stopped the proxy since ensure_proxy. stop_proxy sees
            # the claim from here on, so one re-check under the lock closes that window. p
            # is checked against the fresh record, not trusted to _pinned_pool.
            if not _proxy_running():
                fresh = _ensure_proxy_locked(proxy["base_port"])
                if p not in (fresh.get("ports") or ()):
                    _release_port(name, p)
                    console.die(f"the proxy pool moved across a restart: port {p} was claimed "
                                f"from {proxy['ports'][0]}..{proxy['ports'][-1]} but the new "
                                f"pool is {fresh['ports'][0]}..{fresh['ports'][-1]} — retry")
            return p
    console.die(f"no free proxy ports (pool {proxy['ports'][0]}..{proxy['ports'][-1]} is full)")


# --- control socket ---------------------------------------------------------

def _sock_call(req):
    """One line-delimited JSON request/response against the proxy control socket."""
    if not paths.PROXY_SOCK.exists():
        console.die("shared proxy control socket missing — is a session up?")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(paths.PROXY_SOCK))
            f = s.makefile("rw")
            f.write(json.dumps(req) + "\n")
            f.flush()
            line = f.readline()
    except OSError as e:
        console.die(f"control socket error: {e}")
    if not line:
        console.die("control socket closed without a response")
    try:
        resp = json.loads(line)
    except ValueError:
        console.die("control socket sent a non-JSON response")
    if not resp.get("ok"):
        console.die(f"control op {req.get('op')!r} failed: {resp.get('error', 'unknown error')}")
    return resp


def _wait_control_sock(timeout, pid=None):
    """Wait for the control socket to answer — and, given `pid`, to answer AS that
    process: the kernel names the peer (_proxy_ident), so ports coming up says nothing
    about who owns the socket. 0 — answered, but the kernel could not name it — is
    accepted, as everywhere identity is read from the kernel."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ident = _proxy_ident()
        if ident is not None:
            if pid is None or ident in (0, pid):
                return
            console.die(f"control socket {paths.PROXY_SOCK} is answered by pid {ident}, not the "
                        f"proxy just started (pid {pid})")
        time.sleep(0.2)
    console.die("shared proxy control socket did not become ready")


def _push_secrets(ruleset, session):
    """Push every inject_auth secret we hold in the env, scoped to `session`.

    The proxy keeps one store per session, so this environment is its only source. A
    missing or malformed secret warns and is skipped: the session still comes up, and the
    guest context reports the credential's status.
    """
    names = sorted({r.inject_auth for r in ruleset.rules if r.inject_auth})
    for n in names:
        value = os.environ.get(f"SILKGATE_EGRESS_SECRET_{n.upper()}")
        if not value:
            console.say(f"warning: SILKGATE_EGRESS_SECRET_{n.upper()} is not set — "
                        f"requests matching inject_auth={n} will be denied")
            continue
        if rule_engine._parse_secret(value) is None:
            console.say(f"warning: SILKGATE_EGRESS_SECRET_{n.upper()} is set but not a valid "
                        f'"<Header>: <value>" line — requests matching inject_auth={n} will be '
                        "denied")
            continue
        _sock_call({"op": "set_secret", "name": n.lower(), "value": value,
                    "session": session})


def _guest_credential_env(profiles):
    """The dummy credential each profile plants in its guest, as `KEY=VALUE` env pairs.

    The proxy only replaces a header the guest sends, so the guest needs the dummy whose
    client sends the header the host secret names. `guest_credential = <secret>` names the
    secret, and each `guest_credential.<header>` line gives that header's dummy. A missing,
    malformed, or unlisted secret falls back to the first line, so the proxy can still deny
    with the real reason. Only the header's name decides, never the value.
    """
    env = []
    for p in profiles:
        name = p.conf.get("guest_credential")
        if not name:
            continue
        choices = p.guest_credentials
        value = os.environ.get(f"SILKGATE_EGRESS_SECRET_{name.upper()}")
        parsed = rule_engine._parse_secret(value) if value else None
        header = parsed[0].lower() if parsed else None
        env.append(choices.get(header, next(iter(choices.values()))))
    return env
