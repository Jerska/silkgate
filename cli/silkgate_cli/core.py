"""The machinery behind the silkgate commands: profiles, images, sessions, the proxy, guests."""
import hashlib
import json
import os
import platform
import posixpath
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

REPO = Path(__file__).resolve().parents[2]
ADDON = REPO / "mitmaddon" / "proxy_addon.py"
PROFILE_DIR = REPO / "profiles"
MITM_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
SILK_DIR = Path.home() / ".silkgate"
LOG_DIR = SILK_DIR / "logs"
SESSIONS_DIR = SILK_DIR / "sessions"
ARCHIVE_DIR = SILK_DIR / "archive"            # ended sessions, one dir per sid
CA_DIR = SILK_DIR / "ca"                      # public MITM cert only, never the key
DOCKER_CFG_DIR = SILK_DIR / "docker"          # our own DOCKER_CONFIG — see docker_env()
GUEST_CONTEXT = "/silkgate/CONTEXT.md"        # what the guest is told about its sandbox
GUEST_BRIEF = "/silkgate/BRIEF.md"            # where --brief lands the operator's task
GUEST_EXECS = "/silkgate/execs"               # one pidfile per exec, <exec_id>.pid
PROXY_JSON = SILK_DIR / "proxy.json"          # shared-proxy meta (pid/ports/log/sock)
PROXY_SOCK = SILK_DIR / "proxy.sock"          # control socket (line-delimited JSON)
# Mirrored in doc/PROXY.md (The port pool). Update both.
POOL_SIZE = 16                                 # base_port .. base_port+15
DEFAULT_BASE_PORT = 8090
PROXY_ALIAS = "host.microsandbox.internal"   # resolves via the guest's /etc/hosts
PROXY_ENV_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
BASE_IMAGE = "debian:bookworm-slim"   # profiles layer on top of this
IMAGE_NS = "silkgate"                # generated images: silkgate/<slug>:<hash12>
TIER1_PROBE_TARGET = "1.1.1.1:443"   # must be a live public service: the probe passes only
                                     # when a connect that WOULD succeed is denied (tier1_fault)

sys.path.insert(0, str(REPO / "mitmaddon"))
from rule_engine import RuleSet, _parse_secret


def die(msg, code=1):
    say(msg)
    sys.exit(code)


def say(msg):
    # RS opens every line silkgate speaks as itself: it's the one byte relayed guest output
    # can't carry (_relay spends a leading one on routing, _plain strips the rest). So a
    # `silkgate:` line without it is a guest's imitation. Terminals draw nothing for RS.
    # Under --tty the guest writes to the screen directly, and no mark holds.
    mark = _ERR_TAG.decode()
    try:
        print(mark + f"silkgate: {msg}".replace("\n", "\n" + mark), file=sys.stderr)
    except (OSError, ValueError):
        # stderr can be a closed pipe or a vanished terminal by the time a teardown
        # speaks; losing the line is fine, losing the rest of the cleanup is not.
        pass


# Every binary the toolchain can need, with its install hint. preflight() and which() both
# read this table, so they can't name different remedies. A hint passed to which() loses
# to the table for a binary the table knows.
_TOOL_HINTS = {
    "docker": "images are built with docker, then loaded into msb",
    "msb": "curl -fsSL https://install.microsandbox.dev | sh",
    "mitmdump": "pip install mitmproxy",
    "git": "--checkout/--branch drive the host repository with it",
}


def which(binary, hint=None):
    """Resolve one binary or die naming the remedy — the last line of defence, at the
    moment of use, for a tool that vanished after preflight() let the command start."""
    path = shutil.which(binary)
    if path is None:
        die(f"{binary} not found — {_TOOL_HINTS.get(binary, hint)}")
    return path


def preflight(*binaries):
    """Die naming every absent tool at once, before a command does any work.

    which() checks one tool when it's needed, so a user missing several would learn them
    one failed run at a time. This reports them together, for one PATH lookup each.
    Whether containment holds is `silkgate verify`'s question.
    """
    missing = [b for b in dict.fromkeys(binaries) if shutil.which(b) is None]
    if not missing:
        return
    lines = "\n".join(f"  {b} — {_TOOL_HINTS[b]}" for b in missing)
    die(f"missing {len(missing)} of the tools this command needs:\n{lines}")


def _build_tools():
    """What building an image dials: docker and msb (build_image), plus mitmdump while
    the mitmproxy CA does not exist yet — write_build_context runs ensure_ca, which
    shells out to mitmdump only to generate that CA."""
    return ("docker", "msb") + (() if MITM_CA.is_file() else ("mitmdump",))


def tail(path, lines=10):
    return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])


# --- profiles ----------------------------------------------------------------
# A profile is one capability: how to install it (setup.sh, run at build time) and what it
# may reach once running (rules.txt, enforced by the proxy). Both come from the same
# `--with` list, so an image can't end up with a tool whose egress nobody allowed.

# A version and a base image reach the generated Dockerfile verbatim: the version as shell
# text in `RUN VERSION="<v>" sh setup.sh`, the base as `FROM`. `docker build` runs as root on
# the host, outside the proxy, so both are charset-checked at parse time, where the error can
# name the flag.
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_IMAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}")

# `probe` is not a capability a task may hold: its rules open the Debian mirrors so that
# `verify --full` can install its probe tools *through* the proxy (profiles/probe/rules.txt).
# Only that one path resolves it; everywhere else it is refused rather than composed.
_VERIFY_ONLY = frozenset({"probe"})


def _version_error(version):
    """Why `version` cannot be interpolated into a generated Dockerfile, or None."""
    if _VERSION_RE.fullmatch(version):
        return None
    return (f"invalid version {version!r} — letters and digits plus '.', '_', '+', '-', "
            "starting alphanumeric; it becomes shell text at image build time")


def _image_error(ref):
    """Why `ref` cannot be used as an image reference, or None."""
    if _IMAGE_RE.fullmatch(ref):
        return None
    return (f"invalid image reference {ref!r} — registry/name[:tag][@digest] characters only "
            "(letters, digits and '.', '_', '-', ':', '/', '@'); a newline here would be an "
            "extra Dockerfile directive")


def _arg_error(arg):
    """Why `arg` cannot land inside generated rule text, or None. A rule is one
    whitespace-separated line, so whitespace or a control character in an arg is rule
    injection and is refused unconditionally, whatever pattern the profile declares —
    everything finer is the declaring profile's arg_pattern's question."""
    if not arg:
        return "empty argument — drop the ':' or name an argument"
    if any(c.isspace() or not c.isprintable() for c in arg):
        return (f"invalid argument {arg!r} — whitespace and control characters never pass; "
                "the argument lands inside rule syntax")
    return None


def _parse_spec(spec):
    """Split `NAME[@VERSION][:ARG]` into (name, version, arg), or raise ValueError.

    Charset questions only: the name resolves later, against the profiles that exist,
    and the arg's shape against the profile's declared arg_pattern. Neither a name nor
    a version can contain ':', so the first ':' opens the arg — which may itself
    contain more of them."""
    head, sep, arg = spec.partition(":")
    name, vsep, version = head.partition("@")
    if vsep and not version:
        raise ValueError(
            f"{spec!r} pins an empty version — drop the '@' or name a version (an unset shell "
            "variable expands to this, and would quietly install the default instead)")
    bad = _version_error(version) if version else None
    if bad:
        raise ValueError(bad)
    if sep:
        bad = _arg_error(arg)
        if bad:
            raise ValueError(f"{spec!r}: {bad}")
    return name, version or None, arg if sep else None


class Profile:
    """One resolved `--with name[@version][:arg]`: its files, version, arg, metadata."""

    __slots__ = ("name", "version", "arg", "arg_pattern", "dir", "conf", "rules", "setup",
                 "env", "context", "packages", "guest_credentials")

    def __init__(self, name, version=None, arg=None):
        # The keys read here are mirrored in doc/PROFILES.md (profile.conf keys). Update both.
        self.name, self.dir = name, PROFILE_DIR / name
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) or not self.dir.is_dir():
            avail = ", ".join(sorted(p.name for p in PROFILE_DIR.iterdir() if p.is_dir()))
            die(f"unknown profile {name!r} (available: {avail})")
        self.conf = _parse_conf(self.dir / "profile.conf")
        self.rules = _read_if(self.dir / "rules.txt")
        self.setup = _read_if(self.dir / "setup.sh")
        self.env = _read_if(self.dir / "env")
        self.context = _read_if(self.dir / "context.md")
        self.packages = [t for t in re.split(r"[,\s]+", self.conf.get("packages", "")) if t]
        # header -> the `KEY=VALUE` pair whose client sends that header; see
        # _guest_credential_env. Checked at load, so `profiles` lists a defect too.
        self.guest_credentials = {k.partition(".")[2].lower(): v for k, v in self.conf.items()
                                  if k.startswith("guest_credential.")}
        if self.conf.get("guest_credential") and not self.guest_credentials:
            die(f"profile {name!r}: guest_credential names a secret but no "
                "guest_credential.<header> line says what the guest holds")
        for header, pair in self.guest_credentials.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S+", pair):
                die(f"profile {name!r}: guest_credential.{header} must be KEY=VALUE, "
                    f"got {pair!r}")
        default = self.conf.get("default_version")
        if version and not default:
            die(f"profile {name!r} takes no version (it installs nothing versioned)")
        self.version = version or default
        if self.version:
            bad = _version_error(self.version)      # a profile.conf default is checked too
            if bad:
                die(f"profile {name!r}: {bad}")
        # The arg contract, both halves load-checked: a declared arg_pattern must be a
        # usable full-match regex, and a {arg} placeholder without one is a line
        # nothing may ever fill — refused at load so `profiles` lists the defect too.
        self.arg_pattern = self.conf.get("arg_pattern")
        if self.arg_pattern is not None:
            if not self.arg_pattern:
                die(f"profile {name!r}: empty arg_pattern — name a full-match pattern "
                    "or drop the key")
            try:
                re.compile(self.arg_pattern)
            except re.error as e:
                die(f"profile {name!r}: bad arg_pattern {self.arg_pattern!r} — {e}")
        elif "{arg}" in self.rules or "{arg}" in self.context:
            where = "rules.txt" if "{arg}" in self.rules else "context.md"
            die(f"profile {name!r}: {where} uses {{arg}} but profile.conf declares no "
                "arg_pattern — declare one or drop the placeholder")
        if arg is not None:
            bad = _arg_error(arg)       # unconditional, wherever the arg came from
            if bad:
                die(f"profile {name!r}: {bad}")
            if self.arg_pattern is None:
                die(f"profile {name!r} takes no argument "
                    "(its profile.conf declares no arg_pattern)")
            if not re.fullmatch(self.arg_pattern, arg):
                die(f"profile {name!r}: argument {arg!r} does not match its arg_pattern "
                    f"{self.arg_pattern!r}")
        self.arg = arg

    @property
    def spec(self):
        return f"{self.image_spec}:{self.arg}" if self.arg is not None else self.image_spec

    @property
    def image_spec(self):
        """The spec without the arg — everything about this instance that the image
        can see. An arg reaches only composed rules, never setup.sh or env, so image
        identity must exclude it or every arg would force a pointless rebuild."""
        return f"{self.name}@{self.version}" if self.version else self.name

    def env_pairs(self):
        return [ln for ln in self.env.splitlines() if ln.strip() and not ln.startswith("#")]

    def rendered_rules(self):
        """rules.txt with every {arg} replaced by the validated arg. rules.txt and
        context.md are the templated files: setup.sh and env shape the image, which an
        arg must never touch (see image_ref, which hashes the template bytes as
        written)."""
        return self.rules.replace("{arg}", self.arg) if self.arg is not None else self.rules

    def rendered_context(self):
        """context.md with every {arg} replaced by the validated arg — the profile's
        own addition to the guest brief, appended by session_context once per instance.
        Session text only: it never shapes the image, so image_ref excludes it."""
        return self.context.replace("{arg}", self.arg) if self.arg is not None else self.context


def _parse_conf(path):
    """`key = value` lines; blanks and #-comments ignored."""
    conf = {}
    for line in _read_if(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            die(f"{path}: expected 'key = value', got {line!r}")
        conf[key.strip()] = value.strip()
    return conf


def _read_if(path):
    return path.read_text() if path.is_file() else ""


def resolve_profiles(specs, *, allow_verify_only=False):
    """Turn `--with` specs into Profiles, in the order given (which the image hash keeps).

    Each distinct (name, version, arg) instance lands once: exact duplicate specs and
    respellings that resolve the same — `node` beside `node@<its default>` — deduplicate
    silently, and each surviving instance expands its rules once.
    """
    profiles = []
    for spec in specs:
        try:
            name, version, arg = _parse_spec(spec)
        except ValueError as e:
            die(str(e))
        if name in _VERIFY_ONLY and not allow_verify_only:
            die(f"profile {name!r} is for `silkgate verify` only — it opens the Debian mirrors "
                "so the containment check can install its probe tools through the proxy")
        p = Profile(name, version, arg)
        if p.arg_pattern is not None and p.arg is None:
            die(f"profile {name!r} requires an argument — write {name}:ARG, with an ARG "
                f"that fully matches its arg_pattern {p.arg_pattern!r}")
        if all((p.name, p.version, p.arg) != (q.name, q.version, q.arg) for q in profiles):
            profiles.append(p)
    # `supersedes = NAME` in profile.conf: an instance of the declaring profile drops
    # any NAME instance carrying the same arg — the wider grant absorbs the narrower
    # one, announced so the operator sees the list they asked for shrink.
    for p in list(profiles):
        target = p.conf.get("supersedes")
        if not target or p not in profiles:
            continue
        for q in [q for q in profiles if q is not p
                  and q.name == target and q.arg == p.arg]:
            say(f"profile {p.spec} supersedes {q.spec} — dropping {q.spec}")
            profiles.remove(q)
    have = {p.name for p in profiles}
    for p in profiles:
        missing = [r for r in re.split(r"[,\s]+", p.conf.get("requires", "")) if r and r not in have]
        if missing:
            die(f"profile {p.name!r} requires {', '.join(missing)} — add --with for them")
    return profiles


def profile_command(profiles):
    """The default command to run in the guest: the last profile that names one."""
    for p in reversed(profiles):
        if p.conf.get("command"):
            return p.conf["command"].split()
    return None


def compose_rules(profiles, extra_rules=()):
    """The session's ruleset text, in deliberate order: --rule lines first, then
    arg-instance expansions (grants such as github-read:OWNER/REPO), then the rules of
    profiles without args. The proxy is first-match-wins, so earlier rules override
    later ones for the paths they cover — explicit beats a grant, a grant beats the
    profile floor."""
    out = []
    if extra_rules:
        out.append("# --- --rule ---")
        out.extend(extra_rules)
    for p in profiles:
        if p.arg is not None and p.rules.strip():
            out.append(f"# --- profile {p.spec} ---")
            out.append(p.rendered_rules().rstrip("\n"))
    for p in profiles:
        if p.arg is None and p.rules.strip():
            out.append(f"# --- profile {p.spec} ---")
            out.append(p.rules.rstrip("\n"))
    return "\n".join(out) + "\n" if out else ""


def load_ruleset(text, where="rules"):
    """Parse up front so bad rules fail here, not inside mitmdump at startup."""
    try:
        return RuleSet.parse(text)
    except ValueError as e:
        die(f"{where}: {e}")


# The other half of the proxy configuration: NO_PROXY/no_proxy is an exemption list every
# HTTP client honours, and Tier 1 drops the direct connection it sends them to — so it takes
# hosts out of the proxy's reach without taking them out of the policy, which is the same
# footgun as clobbering HTTPS_PROXY and reads like the opposite.
_NO_PROXY_VARS = ("NO_PROXY", "no_proxy")


def check_env(pairs):
    """Validate -e NAME=VALUE pairs; clobbering the proxy config is always an error."""
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            die(f"bad -e argument {pair!r} (expected NAME=VALUE)")
        if name in PROXY_ENV_VARS:
            die(f"-e {name} collides with the proxy configuration silkgate sets")
        if name in _NO_PROXY_VARS:
            die(f"-e {name} tells the guest's clients to bypass the proxy for the hosts it "
                "names, and Tier 1 drops those connections — they fail instead of being "
                "policed, and nothing in it widens the allowlist")
        if "\n" in value:
            # msb aborts the guest (SIGABRT, before the agent relay comes up) on any env
            # value containing a newline, at any size. Fail here with a reason instead.
            die(f"-e {name} value contains a newline, which microsandbox cannot pass; "
                "write it to a file in the workspace instead")


def check_secrets(ruleset):
    """Warn about any inject_auth secret in the ruleset that is absent or malformed.

    Each secret must be set AND pass _parse_secret: "x-api-key: " is set, but the proxy
    rejects its empty value at request time. Launches always warn and continue.
    """
    names = sorted({r.inject_auth for r in ruleset.rules if r.inject_auth})
    for n in names:
        value = os.environ.get(f"SILKGATE_EGRESS_SECRET_{n.upper()}")
        if not value:
            reason = "is not set"
        elif _parse_secret(value) is None:
            reason = 'is set but not a valid "<Header>: <value>" line'
        else:
            continue
        msg = (f"SILKGATE_EGRESS_SECRET_{n.upper()} {reason} — "
               f"requests matching inject_auth={n} will be denied")
        say(f"warning: {msg}")


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
        die(f"base port {base_port} leaves no room for a {POOL_SIZE}-port pool "
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
    die(f"no {POOL_SIZE}-port range free in {base_port}..{limit - 1} — blocked by "
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
            die(f"proxy exited at startup — {log_path}:\n{tail(log_path)}")
        if _BIND_FAILURE in log_path.read_bytes().lower():
            stop(proc)
            die(f"proxy failed to bind — {log_path}:\n{tail(log_path)}")
        try:
            for port in ports:
                for addr in _probe_addrs(port):
                    with socket.create_connection(addr, timeout=0.5):
                        pass
            return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            stop(proc)
            die(f"proxy did not answer at {addr[0]}:{addr[1]} within "
                f"{PROXY_READY_TIMEOUT}s — {log_path}:\n{tail(log_path)}")
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
    for p in LOG_DIR.glob(pattern):
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
        say(f"pruned {pruned} audit log file(s) past retention from {LOG_DIR} "
            f"(the {LOG_RETAIN_COUNT} newest of each kind always stay; "
            "SILKGATE_LOG_RETAIN_DAYS=0 and SILKGATE_CAPTURE_RETAIN_DAYS=0 keep "
            "everything)")


def start_proxy(rules_text, port):
    """Start a single-ruleset mitmdump in the background; return (proc, audit log path).

    The port is checked free before the spawn, and the child watched after it
    (_port_free, _wait_proxy_ready), because a bare connect can't tell this proxy from a
    squatter. An orphaned proxy would answer while ours died, and a verify guest would run
    under the wrong ruleset."""
    mitmdump = which("mitmdump", "pip install mitmproxy")
    if not _port_free(port):
        die(_port_in_use_error(port))
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _prune_logs()
    stamp = f"{datetime.now():%Y%m%d-%H%M%S}"
    log_path = LOG_DIR / f"proxy-{stamp}.log"
    events_path = LOG_DIR / f"events-{stamp}.jsonl"
    capture_path = LOG_DIR / f"capture-{stamp}.jsonl"
    rules_file = LOG_DIR / f"proxy-{stamp}.rules"
    rules_file.write_text(rules_text)
    env = dict(os.environ, SILKGATE_EGRESS_RULES=str(rules_file),
               SILKGATE_EGRESS_EVENTS_FILE=str(events_path),
               SILKGATE_EGRESS_CAPTURE_FILE=str(capture_path))
    env.pop("SILKGATE_EGRESS_SESSIONS_DIR", None)
    # rawtcp=false: a CONNECT whose payload mitmproxy cannot read as TLS is refused
    # instead of becoming an opaque tunnel around the addon's per-request checks.
    argv = [mitmdump, "-s", str(ADDON), "--set", "rawtcp=false"] + _modes(port)
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(argv, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        _wait_proxy_ready(proc, [port], log_path)
    except BaseException:       # incl. a Ctrl-C mid-wait: the caller has no handle on
        stop(proc)              # the child yet, so an exit here is the last chance to
        raise                   # stop it (stop is a no-op where the wait already did)
    return proc, log_path


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


class _guarded_terminal:
    """Restore this terminal's settings afterwards, whatever the child did to them.

    A child may put the terminal in raw mode (msb does), and one that dies without restoring
    it leaves the shell mangled until `stty sane`. So: snapshot before, restore after. Does
    nothing when stdout isn't a terminal.
    """

    def __enter__(self):
        self.saved = None
        try:
            if sys.stdout.isatty():
                self.saved = termios.tcgetattr(sys.stdout)
        except (OSError, termios.error):
            pass
        return self

    def __exit__(self, *exc):
        if self.saved is not None:
            try:
                termios.tcsetattr(sys.stdout, termios.TCSADRAIN, self.saved)
            except (OSError, termios.error):
                pass
        return False


def wait_foreground(proc):
    """Wait for a child that owns the terminal. Ctrl-C reaches it directly, so the parent
    survives SIGINT to clean up. A Python handler isn't inherited across exec, so the child's
    SIGINT behavior is untouched. A signal death returns 128 plus the signal, as a shell
    would, since sys.exit mangles proc.wait()'s negative code."""
    previous = signal.signal(signal.SIGINT, lambda *a: None)
    try:
        rc = proc.wait()
        return rc if rc >= 0 else 128 - rc
    finally:
        signal.signal(signal.SIGINT, previous)


class _deferred_interrupts:
    """Hold SIGINT/SIGTERM/SIGHUP while an unwind runs, restoring them after.

    A second Ctrl-C mid-teardown would leave a session half-removed, worse than up or
    gone. So stop signals are acknowledged once on stderr and dropped: the unwind already
    does what they ask. That's safe only because everything under it is bounded: the msb
    calls in _remove_sandbox time out and run outside the terminal's process group, and
    stop_proxy escalates to SIGKILL after 5 s. The note uses os.write, because print into a
    buffer mid-flush raises."""

    _SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)

    def __enter__(self):
        self._noted = False
        self._prev = []

        def hold(signum, frame):
            if not self._noted:
                self._noted = True
                try:
                    os.write(2, _ERR_TAG + b"silkgate: interrupt noted "
                                b"- finishing cleanup first (it is bounded)\n")
                except OSError:
                    pass
        try:
            for s in self._SIGNALS:
                self._prev.append((s, signal.signal(s, hold)))
        except ValueError:           # not the main thread: nothing can be deferred
            pass
        return self

    def __exit__(self, *exc):
        for s, previous in self._prev:
            signal.signal(s, previous)
        return False


def msb_argv(image, cmd, port, *, pull_never=True, mounts=()):
    """One-shot `msb run` of a guest locked to one proxy port (the verify path)."""
    argv = [which("msb", "curl -fsSL https://install.microsandbox.dev | sh"), "run", image]
    if pull_never:
        argv += ["--pull", "never"]
    for m in mounts:
        argv += ["-v", m]
    url = f"http://{PROXY_ALIAS}:{port}"
    for var in PROXY_ENV_VARS:
        argv += ["-e", f"{var}={url}"]
    argv += ["--net-default-egress", "deny", "--net-rule", f"allow@host:tcp:{port}"]
    return argv + ["--"] + list(cmd)


def ensure_ca():
    """Return a guest-safe copy of the CA *certificate*, generating the CA on first use.

    ~/.mitmproxy also holds the private key, so that directory is never handed out.
    Callers get a directory with the public cert alone.

    Generation opens no socket: `mitmdump --no-server`, with an addon that exits once
    startup is done, writes the CA and never listens. A listener here would be a proxy
    with no rules.
    """
    if not MITM_CA.is_file():
        mitmdump = which("mitmdump", "pip install mitmproxy")
        say("generating the mitmproxy CA (first run)…")
        with tempfile.TemporaryDirectory(prefix="silkgate-ca-") as tmp:
            addon = Path(tmp) / "shutdown_after_startup.py"
            addon.write_text("from mitmproxy import ctx\n"
                             "\n"
                             "def running():\n"
                             "    ctx.master.shutdown()\n")
            argv = [mitmdump, "--no-server", "-s", str(addon),
                    "--set", f"confdir={MITM_CA.parent}"]
            try:
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                die(f"mitmdump did not finish generating {MITM_CA} within 60s")
        if not MITM_CA.is_file():
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            die(f"mitmdump did not create {MITM_CA}"
                + (f" — {detail[-1]}" if detail else ""))
    CA_DIR.mkdir(parents=True, exist_ok=True)
    cert = CA_DIR / "egress-ca.pem"
    shutil.copyfile(MITM_CA, cert)
    return cert


# --- generated images --------------------------------------------------------
# There is no Dockerfile in this repo: an image is the base plus one layer per profile,
# synthesized here. The tag carries a hash of everything that shapes the result, so a
# session can ask for an image by profile list and get a cache hit or an honest rebuild.

_DOCKER_PLATFORMS = {"arm64": "linux/arm64", "aarch64": "linux/arm64",
                     "x86_64": "linux/amd64", "amd64": "linux/amd64"}

# What silkgate needs of any guest: its CA in the trust store and in the env vars runtimes
# read, a shell plus mkfifo/mktemp for the output relay, and /workspace.
#
# NODE_EXTRA_CA_CERTS adds to the defaults, so it names our CA alone. The others replace
# the root store (OpenSSL, rustls, Go), so they name the regenerated system bundle: Debian's
# roots and ours. The bare CA would break every later layer's setup.sh, which downloads
# from the real internet, outside the proxy.
_BASE_LAYER = """FROM {base}
RUN apt-get update \\
    && apt-get install -y --no-install-recommends ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
COPY egress-ca.pem /usr/local/share/ca-certificates/egress.crt
RUN update-ca-certificates
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/egress.crt \\
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \\
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \\
    PATH=/root/.local/bin:$PATH
WORKDIR /workspace
"""


def _image_profiles(profiles):
    """The unique (name, version) instances, in order: an arg never shapes the image,
    so several instances of one profile contribute one layer set — two sessions whose
    specs differ only in args reuse one image."""
    unique = {}
    for p in profiles:
        unique.setdefault((p.name, p.version), p)
    return list(unique.values())


def image_ref(profiles, base=BASE_IMAGE):
    """`silkgate/<slug>:<hash12>` — slug to read, hash to be exact.

    The hash covers the base, _BASE_LAYER, and per profile, in order: its name, version,
    packages, and the bytes of setup.sh, rules.txt (as templates, so args don't count),
    and env. Any edit or reorder makes a new image, so a cache hit is never stale.
    """
    profiles = _image_profiles(profiles)
    h = hashlib.sha256(base.encode())
    h.update(b"\0" + _BASE_LAYER.encode())
    for p in profiles:
        h.update(b"\0" + p.image_spec.encode())
        h.update(b"\0" + " ".join(p.packages).encode())
        for text in (p.setup, p.rules, p.env):
            h.update(b"\0" + text.encode())
    slug = "-".join(dict.fromkeys(p.name for p in profiles)) or "base"
    return f"{IMAGE_NS}/{slug[:60]}:{h.hexdigest()[:12]}"


def image_in_msb(ref):
    msb = shutil.which("msb")
    if not msb:
        return False
    out = subprocess.run([msb, "image", "ls"], capture_output=True, text=True).stdout
    return any(line.split()[:1] == [ref] for line in out.splitlines()[1:])


def write_build_context(directory, profiles, base):
    """The synthesized Dockerfile plus everything it COPYs."""
    profiles = _image_profiles(profiles)        # one layer set per profile, args aside
    shutil.copyfile(ensure_ca(), directory / "egress-ca.pem")
    lines = [_BASE_LAYER.format(base=base)]
    # Every profile's `packages` in one transaction: apt resolves them together, shared
    # dependencies land once, and no setup.sh has to carry update/clean boilerplate. A
    # profile that needs a package from outside the distro's repos adds the source and
    # installs it in its own setup.sh instead.
    packages = sorted({pkg for p in profiles for pkg in p.packages})
    if packages:
        lines.append("RUN apt-get update \\\n"
                     "    && apt-get install -y --no-install-recommends \\\n        "
                     + " \\\n        ".join(packages)
                     + " \\\n    && rm -rf /var/lib/apt/lists/*")
    for p in profiles:
        if p.setup.strip():
            (directory / f"setup-{p.name}.sh").write_text(p.setup)
            # One COPY+RUN per profile, so editing the last one rebuilds only its layer.
            lines.append(f"COPY setup-{p.name}.sh /silkgate/setup-{p.name}.sh")
            lines.append(f'RUN VERSION="{p.version or ""}" sh /silkgate/setup-{p.name}.sh')
        if p.env_pairs():
            lines.append("ENV " + " \\\n    ".join(p.env_pairs()))
    (directory / "Dockerfile").write_text("\n".join(lines) + "\n")


def docker_env():
    """Env for our docker calls, with a config that has no credential helper.

    Builds use public images only, but a `credsStore` in the user's config still calls its
    helper, which on macOS prompts for access on every build. So DOCKER_CONFIG points at our
    own directory, with the user's CLI plugins linked in, or buildx disappears. An explicit
    DOCKER_CONFIG is left alone.
    """
    if os.environ.get("DOCKER_CONFIG"):
        return None
    DOCKER_CFG_DIR.mkdir(parents=True, exist_ok=True)
    config = DOCKER_CFG_DIR / "config.json"
    if not config.is_file():
        config.write_text("{}\n")
    plugins = DOCKER_CFG_DIR / "cli-plugins"
    user_plugins = Path.home() / ".docker" / "cli-plugins"
    if user_plugins.is_dir() and not plugins.exists():
        plugins.symlink_to(user_plugins)
    return dict(os.environ, DOCKER_CONFIG=str(DOCKER_CFG_DIR))


def build_image(profiles, *, base=BASE_IMAGE, platform_=None):
    """Build (and load into msb) the image these profiles describe; return its ref."""
    docker = which("docker", "images are built with docker, then loaded into msb")
    msb = which("msb", "curl -fsSL https://install.microsandbox.dev | sh")
    plat = platform_ or _DOCKER_PLATFORMS.get(platform.machine().lower())
    if plat is None:
        die(f"unknown host arch {platform.machine()!r} — pass --platform (e.g. linux/amd64)")
    ref = image_ref(profiles, base)
    env = docker_env()
    with tempfile.TemporaryDirectory(prefix="silkgate-build-") as tmp:
        context = Path(tmp)
        write_build_context(context, profiles, base)
        say(f"building {ref} "
            f"({', '.join(p.image_spec for p in _image_profiles(profiles)) or 'base only'})")
        if subprocess.run([docker, "build", "--platform", plat, "-t", ref, str(context)],
                          env=env).returncode:
            die(f"docker build failed for {ref}")
    save = subprocess.Popen([docker, "save", ref], env=env, stdout=subprocess.PIPE)
    load = subprocess.run([msb, "load"], stdin=save.stdout)
    save.stdout.close()
    if save.wait() or load.returncode:
        die(f"docker save | msb load failed for {ref}")
    return ref


def ensure_image(profiles, image, *, base=BASE_IMAGE):
    """An explicit --image wins; otherwise build the profiles' image unless msb has it.

    --image beside a non-default --base is refused rather than resolved: the image is
    already chosen, so nothing is built and the base would change nothing — and a flag
    that is accepted and then ignored reads as honoured."""
    if image:
        if base != BASE_IMAGE:
            die("--image and --base together are contradictory: --image names the exact "
                "image to run, so nothing is built for --base to shape — drop one")
        return image
    ref = image_ref(profiles, base)
    if image_in_msb(ref):
        return ref
    return build_image(profiles, base=base)


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
        for p in _image_profiles(profiles):
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
            parsed = _parse_secret(value) if value else None
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
    return SESSIONS_DIR / name


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
        die(f"invalid session name {name!r} (letters, digits, '-', '_'; ≤32 chars)")


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
        say(f"warning: could not journal {event!r} for {sdir.name}: {e}")


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
        say(f"warning: could not record last_rc for {name!r}: {e}")


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
        if not _BRANCH_RE.fullmatch(branch) or ".." in branch or not _BASE_RE.fullmatch(base):
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
        die(f"session {name!r}: its meta.json names session {meta.get('name')!r} — refusing it")
    bad = _check_meta_fields(meta)
    if bad:
        die(f"session {name!r}: {bad} — refusing it")
    return meta


def list_metas():
    if not SESSIONS_DIR.is_dir():
        return []
    metas = []
    for d in sorted(SESSIONS_DIR.iterdir()):
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
        die(f"invalid archive sid {sid!r}")
    meta = _read_json(ARCHIVE_DIR / sid / "meta.json")
    if meta is None:
        return None
    if meta.get("sid") != sid:
        die(f"archived session {sid!r}: its meta.json names sid {meta.get('sid')!r} — "
            "refusing it")
    bad = _check_meta_fields(meta)
    if bad:
        die(f"archived session {sid!r}: {bad} — refusing it")
    return meta


def list_archived_metas():
    """Every archived session's meta, oldest first — a sid opens with its UTC stamp, so
    the plain name sort is chronological."""
    if not ARCHIVE_DIR.is_dir():
        return []
    metas = []
    for d in sorted(ARCHIVE_DIR.iterdir()):
        if not _SID_RE.fullmatch(d.name):            # not something silkgate archived
            continue
        m = read_archived_meta(d.name)
        if m:
            metas.append(m)
    return metas


# --- shared proxy -----------------------------------------------------------

def read_proxy():
    return _read_json(PROXY_JSON)


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
    if not PROXY_SOCK.exists():
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(str(PROXY_SOCK))
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
        SILK_DIR.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(SILK_DIR / "proxy.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self._fd, fcntl.LOCK_EX)

    def __exit__(self, *exc):
        os.close(self._fd)


def _clear_proxy_files():
    for p in (PROXY_JSON, PROXY_SOCK):
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
    mitmdump = which("mitmdump", "pip install mitmproxy")
    if ports is None:
        ports = _find_free_pool(base_port)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    _prune_logs()
    stamp = f"{datetime.now():%Y%m%d-%H%M%S}"
    log_path = LOG_DIR / f"proxy-{stamp}.log"
    events_path = LOG_DIR / f"events-{stamp}.jsonl"
    capture_path = LOG_DIR / f"capture-{stamp}.jsonl"
    # rawtcp=false: a CONNECT whose payload mitmproxy cannot read as TLS is refused
    # instead of becoming an opaque tunnel around the addon's per-request checks.
    argv = [mitmdump, "-s", str(ADDON), "--set", "rawtcp=false"]
    for p in ports:
        argv += _modes(p)
    # Multi-session mode: SILKGATE_EGRESS_SESSIONS_DIR on, SILKGATE_EGRESS_RULES off (addon needs exactly one).
    env = dict(os.environ, SILKGATE_EGRESS_SESSIONS_DIR=str(SESSIONS_DIR),
               SILKGATE_EGRESS_CONTROL_SOCK=str(PROXY_SOCK),
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
            "sock": str(PROXY_SOCK), "started": now_iso()}
    try:
        _wait_proxy_ready(proc, ports, log_path)
        _write_json(PROXY_JSON, meta)
    except BaseException:       # incl. a Ctrl-C mid-wait: until proxy.json lands, no
        stop(proc)              # other command can ever find this mitmdump to stop
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
    for m in list_metas():
        if m.get("port"):
            owners.setdefault(m["port"], m["name"])
    for p in _live_claims():
        owners.setdefault(p, (_read_json(_claim_path(p)) or {}).get("name"))
    if not owners:
        return None
    pool = (meta or {}).get("ports") or []
    strays = sorted(p for p in owners if p not in pool)
    if strays:
        held = ", ".join(f"{p} (session {owners[p]})" for p in strays)
        die(f"sessions hold ports no proxy record names a pool for: {held} — "
            f"`silkgate down` them before the proxy can start")
    for p in pool:
        if not _port_free(p):
            pin = (f"session {owners[p]} is frozen onto it" if owners.get(p) else
                   f"surviving sessions pin the pool to {pool[0]}..{pool[-1]}")
            die(f"port {p} is already in use, but {pin} — "
                f"lsof -nP -iTCP:{p} -sTCP:LISTEN names the holder")
    return pool


def _ensure_proxy_locked(base_port):
    """ensure_proxy's body, for callers already holding _proxy_lock."""
    meta = read_proxy()
    ident = _proxy_ident()
    if ident is not None:                      # something live answers on our socket path
        if meta is None:
            die(f"a proxy (pid {ident or 'unknown'}) holds {PROXY_SOCK} but {PROXY_JSON} "
                "is gone — kill that process and retry")
        if ident and meta.get("pid") != ident:
            meta["pid"] = ident                # proxy.json outlived the proxy it described;
            _write_json(PROXY_JSON, meta)      # the socket's owner is the identity
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
        if list_metas() or _live_claims():
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
    return SESSIONS_DIR / ".ports"


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
        fh.write(json.dumps({"name": name, "pid": os.getpid(), "created": now_iso()}))
    return True


def _claim_stale(port, path):
    """Whether a claim is a crash leftover that may be reaped (caller holds _proxy_lock).

    Not stale while its session dir exists — the guest may still hold L3 access to the
    port even if unhealthy, and only `down` frees that — nor while any session's meta
    names the port, nor while the claiming process is alive (provisioning in flight)."""
    info = _read_json(path) or {}
    name = info.get("name")
    if name and session_dir(name).exists():
        return False
    if any(m.get("port") == port for m in list_metas()):
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
        info = _read_json(path)
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
        taken = {m.get("port") for m in list_metas() if m.get("name") != name}
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
                    die(f"the proxy pool moved across a restart: port {p} was claimed "
                        f"from {proxy['ports'][0]}..{proxy['ports'][-1]} but the new "
                        f"pool is {fresh['ports'][0]}..{fresh['ports'][-1]} — retry")
            return p
    die(f"no free proxy ports (pool {proxy['ports'][0]}..{proxy['ports'][-1]} is full)")


# --- control socket ---------------------------------------------------------

def _sock_call(req):
    """One line-delimited JSON request/response against the proxy control socket."""
    if not PROXY_SOCK.exists():
        die("shared proxy control socket missing — is a session up?")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(PROXY_SOCK))
            f = s.makefile("rw")
            f.write(json.dumps(req) + "\n")
            f.flush()
            line = f.readline()
    except OSError as e:
        die(f"control socket error: {e}")
    if not line:
        die("control socket closed without a response")
    try:
        resp = json.loads(line)
    except ValueError:
        die("control socket sent a non-JSON response")
    if not resp.get("ok"):
        die(f"control op {req.get('op')!r} failed: {resp.get('error', 'unknown error')}")
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
            die(f"control socket {PROXY_SOCK} is answered by pid {ident}, not the "
                f"proxy just started (pid {pid})")
        time.sleep(0.2)
    die("shared proxy control socket did not become ready")


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
            say(f"warning: SILKGATE_EGRESS_SECRET_{n.upper()} is not set — "
                f"requests matching inject_auth={n} will be denied")
            continue
        if _parse_secret(value) is None:
            say(f"warning: SILKGATE_EGRESS_SECRET_{n.upper()} is set but not a valid "
                f'"<Header>: <value>" line — requests matching inject_auth={n} will be denied')
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
        parsed = _parse_secret(value) if value else None
        header = parsed[0].lower() if parsed else None
        env.append(choices.get(header, next(iter(choices.values()))))
    return env


# --- msb session guests -----------------------------------------------------

def _msb():
    return which("msb", "curl -fsSL https://install.microsandbox.dev | sh")


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
    url = f"http://{PROXY_ALIAS}:{port}"
    for var in PROXY_ENV_VARS:                          # inherited by every later exec
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
            f"elif timeout 1 bash -c 'exec 3<>/dev/tcp/{PROXY_ALIAS}/{port}' 2>/dev/null; "
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
                f"guest could not reach its own proxy at {PROXY_ALIAS}:{port}. A denial "
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
        say("note: the first Tier-1 probe exec timed out — the msb relay race (msb 0.5.4 "
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


_ERR_TAG = b"\x1e"          # RS: a stderr line, and the mark on silkgate's own voice (say)
_OUT_TAG = b"\x1f"          # US: a stdout line

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
             f'while IFS= read -r l || [ -n "$l" ]; do printf "\\{ord(_OUT_TAG):03o}%s\\n" "$l"; done <"$d/o" & po=$!; '
             f'while IFS= read -r l || [ -n "$l" ]; do printf "\\{ord(_ERR_TAG):03o}%s\\n" "$l"; done <"$d/e" & pe=$!; '
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
            with _guarded_terminal():
                proc = subprocess.Popen(build_argv(cmd))
                try:
                    return wait_foreground(proc)
                finally:
                    stop(proc)
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
                sys.stdout.buffer.write(chunk.replace(_ERR_TAG, b""))
                sys.stdout.buffer.flush()
                continue
            buf += chunk
            while b"\n" in buf:                         # a line is the unit for both the
                line, buf = buf.split(b"\n", 1)         # stderr tag and ANSI stripping
                _relay(line, newline=True, on_line=on_line)
        if buf:
            _relay(buf, newline=False, on_line=on_line)
        return wait_foreground(proc)
    finally:
        os.close(ptm)
        if proc is not None:
            stop(proc)                                  # reaped already on the clean path
        signal.signal(signal.SIGINT, previous)


def _relay(line, *, newline, on_line=None):
    """Write one relayed line to our stdout, or to stderr if the wrapper tagged it so.

    Only the leading byte routes. RS or US anywhere else is guest content, and _plain
    drops it. Untagged lines (msb's noise, a wrapper that died early) go to stdout, which
    claims nothing. `on_line` sees the same cleaned text a reader does.
    """
    tag = line[:1]
    stream = sys.stderr.buffer if tag == _ERR_TAG else sys.stdout.buffer
    text = _plain(line[1:] if tag in (_ERR_TAG, _OUT_TAG) else line)
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
            (SILK_DIR, "silkgate's own state (session rulesets, the control socket, the CA)"),
            (REPO, "the silkgate checkout this CLI runs from"))


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
        die(f"mount source is not a directory: {w}")
    if w.parent == w:
        die(f"refusing to mount {w}: that is the whole filesystem")
    for path, what in _forbidden_mounts():
        target = Path(path).resolve()
        if w == target or w in target.parents:
            die(f"refusing to mount {w}: it is (or contains) {what} — credentials and "
                "configuration there must not be exposed to the guest")
    d = _normalize_dst(dst)
    if not d.startswith("/"):
        die(f"mount destination {dst!r} is not absolute — guest paths start at /")
    if d == "/":
        die(f"refusing to mount {w} over the guest's whole filesystem")
    for reserved in _RESERVED_DSTS:
        if d == reserved or d.startswith(reserved + "/") or reserved.startswith(d + "/"):
            die(f"refusing to mount at {d}: it is (or contains) {reserved}, silkgate's own "
                "path in the guest")
    if mode == "ro":
        if (w / ".git").is_file():
            say(f"note: {w} is a linked git worktree — the .git pointer file is in the "
                "read-only mount, but hooks and config live outside it")
        return str(w), d
    if allow_git_dir:
        say(f"note: --allow-git-dir — {w} is mounted without the .git check, so hooks and "
            "config of any repository inside are guest-writable: host code execution the "
            "next time a human runs git there")
    else:
        dotgit = _find_git_dir(w)
        if dotgit is not None:
            where = "" if dotgit.parent == w else f" (at {dotgit.parent.relative_to(w)})"
            die(f"refusing to mount {w} at {d} read-write: it holds a .git directory{where}, "
                "so the guest would get read-write access to hooks and config — host code "
                "execution the next time you run git there. Mount a linked worktree instead "
                "(git worktree add), mount it read-only, or accept the risk explicitly with "
                "--allow-git-dir.")
    if (w / ".git").is_file():
        say(f"note: {w} is a linked git worktree — hooks and config live outside the mount and "
            "are beyond the guest's reach, but the .git pointer file itself is not")
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
            die(f"invalid mount {spec!r} — expected SRC:DST[:ro|rw] (MODE defaults to ro)")
        host, guest = _mount_pair(*parsed, allow_git_dir=allow_git_dir)
        for _, other, _ in mounts:
            if guest == other:
                die(f"duplicate mount destination {guest} — one guest path takes one mount")
            inner, outer = sorted((guest, other), key=len)
            if outer.startswith(inner + "/"):
                die(f"mount destinations {inner} and {outer} nest — nested virtiofs "
                    "behavior is unverified, so it is refused rather than trusted")
        mounts.append((host, guest, parsed[2]))
    if allow_git_dir and not any(mode == "rw" for _, _, mode in mounts):
        die("--allow-git-dir does nothing here — the .git risk it accepts only exists "
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
        die(f"session already exists: {sdir}")
    tmp = SESSIONS_DIR / f".tmp-{name}"                  # dot-prefixed: invisible to registries
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
            die(f"session already exists: {sdir}")
        _push_secrets(ruleset, name)
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
            die(f"msb create failed for session {name!r}")
    except BaseException:                                # incl. SystemExit from die()
        with _deferred_interrupts():                     # a Ctrl-C cannot halve the unwind
            if created:                                  # failed or cut short, a create
                _remove_sandbox(sandbox_name(name))      # can still have registered it
            shutil.rmtree(tmp, ignore_errors=True)
            if owned:
                shutil.rmtree(sdir, ignore_errors=True)
            _release_port(name, port)
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
        say(f"warning: no guest-output snapshot for {sandbox}: {err}")
        return
    data = ("\n".join(lines) + "\n").encode("utf-8", "replace") if lines else b""
    try:
        (sdir / "output.log").write_bytes(data[-cap:])
    except OSError as e:
        say(f"warning: could not write the guest-output snapshot: {e}")


# Retention for ~/.silkgate/archive, favouring keeping like the audit logs above: an
# archived session goes only when BOTH older than the age AND beyond the newest
# ARCHIVE_RETAIN_COUNT, every removal is announced, and SILKGATE_ARCHIVE_RETAIN_DAYS=0
# (or less) keeps everything.
ARCHIVE_RETAIN_DAYS = 30
ARCHIVE_RETAIN_COUNT = 50


def _prune_archive():
    """Apply the archive retention policy above; runs where archives are created."""
    days = _retain_days("SILKGATE_ARCHIVE_RETAIN_DAYS", ARCHIVE_RETAIN_DAYS)
    if days <= 0:
        return
    cutoff = time.time() - days * 86400
    stamped = []
    try:
        entries = list(ARCHIVE_DIR.iterdir())
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
        say(f"pruned {pruned} archived session(s) older than {days:g}d from {ARCHIVE_DIR} "
            f"(the {ARCHIVE_RETAIN_COUNT} newest always stay; SILKGATE_ARCHIVE_RETAIN_DAYS=0 "
            "keeps everything)")


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
        die(f"msb rm {sandbox} failed — session {name!r} kept, its proxy port still "
            f"reserved; remove the sandbox manually, then `silkgate down {name}`")
    if name:
        # The claim goes first, while meta.json still pins the port for pick_port; the
        # rename (or rmtree) is then what genuinely frees it.
        _release_port(name, meta.get("port"))
        if archive:
            _journal(name, "down")
            sid = meta.get("sid") or _new_sid(name)  # pre-feature metas: minted here
            try:
                _write_json(sdir / "meta.json", {**meta, "sid": sid, "ended": now_iso()})
            except OSError as e:
                say(f"warning: could not stamp 'ended' into {name!r}'s meta: {e}")
            try:
                ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
                sdir.rename(ARCHIVE_DIR / sid)
            except OSError as e:
                say(f"warning: could not archive session {name!r} ({e}) — removing it "
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
    meta = read_proxy()
    if meta:
        stop_proxy(meta)


# --- checkout/branch sessions: a clone in the guest, from the host repo ---------
# The guest clones from a read-only mount of the host repo's gitdir.
# - --checkout: the clone lives in the guest's rootfs, detached at REF, and dies with the VM.
# - --branch: a named branch in a host-derived workspace. Commits return as a bundle the host
#   fetches under fsck and fast-forwards. The workspace mount holds no git metadata, so a
#   guest has nothing there to rewrite.
# The one writable piece of host git state is `.git/lfs`, which is SHA-checked on read: a
# hostile guest can force a re-download, never swap content.

_BRANCH_ENV = ("GIT_DIR=/root/gitdir/.git", "GIT_WORK_TREE=/workspace")
_GIT_TIMEOUT = 120                 # host git during harvest: bounded, per the deferral contract
# Every repo-location override git(1) honors from the environment. Host git here must act
# on the repository named by cwd or --git-dir, never one a parent process exported — run
# silkgate from inside a silkgate --branch guest, for instance, and GIT_DIR/GIT_WORK_TREE
# point at that session's clone, not the repo under the caller's feet.
_GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                      "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
                      "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
                      "GIT_INDEX_VERSION", "GIT_SHALLOW_FILE", "GIT_GRAFT_FILE")


def _host_git_env():
    """os.environ minus git's repo-location overrides, for every host-side git call."""
    return {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_VARS}
_BASE_RE = re.compile(r"[0-9a-f]{40}")
# meta.json's branch reaches git argv (always behind --git-dir, always fully qualified) and,
# with repo_root, an rmtree decision — held to a charset before use, like "sandbox" above.
_BRANCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,200}")


def _git(git_dir, *argv):
    """One bounded host-git call, or None on timeout. Its own session: harvest runs inside
    _deferred_interrupts after a Ctrl-C already hit the foreground group."""
    try:
        return subprocess.run([which("git"), "--git-dir", str(git_dir), *argv],
                              capture_output=True, text=True, start_new_session=True,
                              timeout=_GIT_TIMEOUT, env=_host_git_env())
    except subprocess.TimeoutExpired:
        return None


def _check_mount_flags(args):
    """--checkout/--branch own /workspace, so a -v mount at or under it is refused with
    them — under it too, because that would be nested virtiofs on a branch workspace and
    a directory the checkout clone needs empty."""
    if getattr(args, "branch", None):
        owner = "--branch"
    elif getattr(args, "checkout", None) is not None:
        owner = "--checkout"
    else:
        return
    for spec in args.mount or ():
        parsed = _split_mount(spec)
        if parsed is None:
            continue                        # argparse already refused it; _mount_args re-dies
        dst = _normalize_dst(parsed[1])
        if dst == "/workspace" or dst.startswith("/workspace/"):
            die(f"-v {spec} collides with {owner}, which owns /workspace in the guest")


def _checkout_repo(flag, ref, profiles, env):
    """The validation --checkout and --branch share -> (git_dir, repo_root, base sha).

    Dies before any host process starts unless: git is in the image, a repo encloses the
    cwd, and REF names a commit. `-e GIT_DIR` or `GIT_WORK_TREE` is refused in both modes:
    it would point every guest git call away from the checkout.
    """
    if not any(p.name == "git" for p in profiles):
        die(f"{flag} needs git in the guest — add --with git")
    for pair in env:
        if pair.partition("=")[0] in ("GIT_DIR", "GIT_WORK_TREE"):
            die(f"-e {pair.partition('=')[0]} conflicts with {flag}, which owns the guest's "
                "git environment")
    if ref.startswith("-") or any(c.isspace() or ord(c) < 0x20 for c in ref):
        die(f"invalid ref {ref!r}")
    probe = subprocess.run([which("git"), "rev-parse", "--path-format=absolute",
                            "--git-common-dir", "--show-toplevel"],
                           capture_output=True, text=True, env=_host_git_env())
    if probe.returncode:
        die(f"{flag} needs the current directory to be inside a git work tree — cd into "
            "the repo this session should check out")
    git_dir, repo_root = probe.stdout.splitlines()[:2]
    base = subprocess.run([which("git"), "rev-parse", "--verify", f"{ref}^{{commit}}"],
                          capture_output=True, text=True, env=_host_git_env())
    if base.returncode:
        die(f"cannot resolve {ref!r} to a commit in this repository — {flag} needs a "
            "base commit")
    return git_dir, repo_root, base.stdout.strip()


def _checkout_spec(ref, profiles, env):
    """Validate --checkout against the enclosing repo; the meta extras a plain-checkout
    session records. No branch parts and no host directory is created: the checkout lives
    and dies in the guest's own rootfs."""
    git_dir, repo_root, base = _checkout_repo("--checkout", ref, profiles, env)
    return {"checkout": ref, "git_dir": git_dir, "base": base, "repo_root": repo_root}


def _branch_spec(branch, profiles, env, ref="HEAD"):
    """Validate --branch against the enclosing repo; the meta extras a branch session records.

    _checkout_repo checks the repo and base. `ref` is the branch base (--checkout REF, or
    HEAD). The name must be a legal ref, and an existing branch is refused, never moved:
    the branch is the deliverable.
    """
    if branch.startswith("-") or any(c.isspace() or ord(c) < 0x20 for c in branch):
        die(f"invalid branch name {branch!r}")
    git_dir, repo_root, base = _checkout_repo("--branch", ref, profiles, env)
    if subprocess.run([which("git"), "check-ref-format", "--branch", branch],
                      capture_output=True, env=_host_git_env()).returncode:
        die(f"invalid branch name {branch!r} (git check-ref-format refused it)")
    if not subprocess.run([which("git"), "--git-dir", git_dir, "show-ref", "--verify",
                           "--quiet", f"refs/heads/{branch}"], capture_output=True,
                          env=_host_git_env()).returncode:
        die(f"branch {branch!r} already exists — the branch is this session's deliverable; "
            "pick a new name")
    _exclude_silkgate(Path(git_dir))
    return {"branch": branch, "git_dir": git_dir, "base": base,
            "repo_root": repo_root, "workspace_derived": True}


def _exclude_silkgate(git_dir):
    """One idempotent `.silkgate/` line in info/exclude, so derived workspaces never show up
    in the repo's own status. info/exclude over .gitignore: host-side, nothing to commit."""
    exclude = git_dir / "info" / "exclude"
    text = exclude.read_text() if exclude.is_file() else ""
    if ".silkgate/" in text.splitlines():
        return
    exclude.parent.mkdir(exist_ok=True)
    exclude.write_text(text + ("" if not text or text.endswith("\n") else "\n") + ".silkgate/\n")


def _branch_workspace(spec, name):
    """The derived workspace and the mounts of a branch session.

    The workspace is a fresh directory nested inside the repo — inside, so the guard's refusal
    of the repo root itself keeps holding for everyone else — and it is silkgate's to delete at
    teardown, which is why a user-named -v mount can never reach this path."""
    ws_dir = Path(spec["repo_root"]) / ".silkgate" / "sandboxes" / name
    silk = Path(SILK_DIR).resolve()
    if silk == ws_dir.resolve() or silk in ws_dir.resolve().parents:
        die(f"refusing to keep branch workspaces under {ws_dir}: that is inside silkgate's "
            "own state — a repository rooted at your home directory cannot use --branch")
    if ws_dir.exists():
        die(f"leftover workspace {ws_dir} already exists — a previous session kept it; "
            "review and remove it first")
    ws_dir.mkdir(parents=True)
    ws, dst = _mount_pair(str(ws_dir), "/workspace", "rw")
    mounts = [f"{ws}:{dst}:rw"]
    mounts.append(f"{spec['git_dir']}:/silkgate/base.git:ro")
    # The whole of .git/lfs, not objects/ alone: git-lfs stages under <storage>/tmp and
    # renames into <storage>/objects, and a rename across two virtiofs mounts is EXDEV
    # (measured, git-lfs 3.3.0 has no copy fallback). One mount = one filesystem, and the
    # guest-side storage layout matches the host's byte for byte.
    if (Path(spec["git_dir"]) / "lfs").is_dir():
        mounts.append(f"{spec['git_dir']}/lfs:/root/lfsstore:rw")
    return ws, mounts


def _checkout_workspace(spec):
    """The mounts of a plain-checkout session: _branch_workspace minus the derived dir.

    No /workspace mount at all — /workspace already exists in the rootfs (WORKDIR) as a
    writable guest-local directory, so the checkout dies with the VM and nothing the guest
    writes there can reach the host."""
    mounts = [f"{spec['git_dir']}:/silkgate/base.git:ro"]
    # The whole of .git/lfs, for the same EXDEV reason as _branch_workspace above.
    if (Path(spec["git_dir"]) / "lfs").is_dir():
        mounts.append(f"{spec['git_dir']}/lfs:/root/lfsstore:rw")
    return mounts


# Runs once per branch session, between the Tier-1 gate and the handover, with GIT_DIR unset
# for the clone: the create-time -e pair is inherited by every exec, this one included, and
# would point the clone at its own destination. lfs.storage is set before the checkout so the
# smudge of an LFS-tracked tree reads the mounted store.
_BRANCH_SETUP_SH = """\
set -eu
branch=$1; base=$2; session=$3
unset GIT_DIR GIT_WORK_TREE
git clone --quiet --no-checkout /silkgate/base.git /root/gitdir
if [ -d /silkgate/base.git/hooks ]; then cp -a /silkgate/base.git/hooks/. /root/gitdir/.git/hooks/; fi
if [ -d /silkgate/base.git/logs ]; then mkdir -p /root/gitdir/.git/logs && cp -a /silkgate/base.git/logs/. /root/gitdir/.git/logs/; fi
git -C /root/gitdir config lfs.storage /root/lfsstore
if command -v git-lfs >/dev/null 2>&1; then git -C /root/gitdir lfs install --skip-repo >/dev/null; fi
git -C /root/gitdir config user.name "Claude (silkgate/$session)"
git -C /root/gitdir config user.email "claude-$session@silkgate.invalid"
export GIT_DIR=/root/gitdir/.git GIT_WORK_TREE=/workspace
git checkout -b "$branch" "$base"
"""


def _setup_branch_guest(sandbox, branch, base, session):
    """Clone + checkout in the guest, streamed (a big repo's clone must show progress)."""
    rc = run_guest(lambda c: msb_exec_argv(sandbox, c),
                   ["sh", "-c", _BRANCH_SETUP_SH, "_", branch, base, session], tty=False)
    if rc:
        die("guest git setup failed — session torn down")


# Runs once per --checkout session, after the Tier 1 probe. /workspace isn't a mount here, so
# it's a normal clone with .git inside. An identity lets local commits work. The detached
# HEAD makes "no deliverable branch" structural. lfs.storage is set before the checkout, so
# LFS smudge reads the mounted store.
_CHECKOUT_SETUP_SH = """\
set -eu
base=$1; session=$2
git clone --quiet --no-checkout /silkgate/base.git /workspace
if [ -d /silkgate/base.git/hooks ]; then cp -a /silkgate/base.git/hooks/. /workspace/.git/hooks/; fi
if [ -d /silkgate/base.git/logs ]; then mkdir -p /workspace/.git/logs && cp -a /silkgate/base.git/logs/. /workspace/.git/logs/; fi
git -C /workspace config lfs.storage /root/lfsstore
if command -v git-lfs >/dev/null 2>&1; then git -C /workspace lfs install --skip-repo >/dev/null; fi
git -C /workspace config user.name "Claude (silkgate/$session)"
git -C /workspace config user.email "claude-$session@silkgate.invalid"
git -C /workspace checkout --detach --quiet "$base"
"""


def _setup_checkout_guest(sandbox, base, session):
    """Clone + detached checkout in the guest, streamed like _setup_branch_guest."""
    rc = run_guest(lambda c: msb_exec_argv(sandbox, c),
                   ["sh", "-c", _CHECKOUT_SETUP_SH, "_", base, session], tty=False)
    if rc:
        die("guest git setup failed — session torn down")


# The bundle range is always base..branch; only the nothing-new check moves with harvests.
# rev-list --count, not a tip comparison: a guest reset to an ancestor of the base would
# otherwise reach `bundle create`, which refuses an empty range with an error this protocol
# would misread as a broken guest.
_BUNDLE_SH = """\
set -eu
if ! tip=$(git rev-parse --verify "refs/heads/$1^{commit}" 2>/dev/null); then
  echo SILKGATE_NO_BRANCH; exit 0
fi
if [ "$(git rev-list --count "$2..refs/heads/$1")" -eq 0 ]; then
  echo SILKGATE_NO_COMMITS; exit 0
fi
rm -f /workspace/.silkgate.bundle
git bundle create --quiet /workspace/.silkgate.bundle "$3..refs/heads/$1"
echo "SILKGATE_BUNDLED $tip"
"""


def _bundle_in_guest(meta):
    """(token, detail) from the guest: NO_BRANCH, NO_COMMITS, BUNDLED <tip>, or ERROR <why>."""
    since = meta.get("branch_ingested") or meta["base"]
    try:
        # stdin closed: the script reads none, and msb exec waits on an inherited
        # stdin for EOF (see tier1_fault) — a detached caller's would never close.
        proc = subprocess.run(msb_exec_argv(meta["sandbox"],
                                            ["sh", "-c", _BUNDLE_SH, "_", meta["branch"],
                                             since, meta["base"]]),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              start_new_session=True, timeout=_GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        return "SILKGATE_ERROR", "the guest did not answer the bundle request in time"
    for line in reversed(proc.stdout.splitlines()):
        token, _, detail = line.strip().partition(" ")
        if token in ("SILKGATE_NO_BRANCH", "SILKGATE_NO_COMMITS", "SILKGATE_BUNDLED"):
            return token, detail
    return "SILKGATE_ERROR", (proc.stderr.strip().splitlines() or ["no verdict from the guest"])[-1]


def _ingest_bundle(meta, bundle, tip):
    """Fetch the guest's bundle under fsck and fast-forward the branch, or say why not.

    The promote is one compare-and-swap against what the last harvest ingested (or
    must-not-exist, the first time). It refuses a branch someone else moved and rewritten
    history. Refused commits stay at the staging ref."""
    name, branch, git_dir = meta["name"], meta["branch"], meta["git_dir"]
    staging = f"refs/silkgate/{name}/{branch}"
    kept = f"the bundle stays at {bundle}; the workspace is kept"

    def refuse(why):
        say(f"branch {branch!r} not updated: {why} — {kept}")
        return False

    if not bundle.is_file():
        return refuse("the guest reported a bundle that never landed in the workspace")
    proc = _git(git_dir, "bundle", "verify", str(bundle))
    if proc is None or proc.returncode:
        return refuse("the bundle does not verify against this repository")
    proc = _git(git_dir, "-c", "fetch.fsckObjects=true", "fetch", "--no-write-fetch-head",
                str(bundle), f"+refs/heads/{branch}:{staging}")
    if proc is None or proc.returncode:
        return refuse("fetching the bundle failed fsck")
    proc = _git(git_dir, "rev-parse", "--verify", f"{staging}^{{commit}}")
    if proc is None or proc.returncode:
        return refuse("the staging ref did not materialise")
    staged = proc.stdout.strip()
    if staged != tip:
        return refuse("the fetched tip is not what the guest bundled")
    # Ancestry against the last harvested tip, not the base: descent from the base alone
    # would let a guest that rewrote already-harvested history move the branch sideways
    # with a clean CAS (the old value still matches). Fast-forward-only means each harvest
    # descends from the previous one; the first descends from the base.
    old = meta.get("branch_ingested", "")
    proc = _git(git_dir, "merge-base", "--is-ancestor", old or meta["base"], staged)
    if proc is None or proc.returncode:
        what = "fast-forward the last harvested tip" if old else "descend from the base commit"
        return refuse(f"the branch does not {what} — commits staged at {staging}")
    proc = _git(git_dir, "update-ref", f"refs/heads/{branch}", staged, old)
    if proc is None or proc.returncode:
        return refuse(f"refs/heads/{branch} moved since the last harvest — commits staged "
                      f"at {staging}")
    _git(git_dir, "update-ref", "-d", staging, staged)          # best-effort tidy-up
    count = _git(git_dir, "rev-list", "--count", f"{meta['base']}..{staged}")
    n = count.stdout.strip() if count and not count.returncode else "?"
    say(f"branch {branch}: {n} commit(s) since base, tip {staged[:12]}")
    mpath = session_dir(name) / "meta.json"
    if mpath.is_file():
        _write_json(mpath, {**meta, "branch_ingested": staged})
        meta["branch_ingested"] = staged
    return True


def _harvest_branch(meta):
    """Bundle out of the guest and ingest; True iff the workspace holds nothing durable."""
    token, detail = _bundle_in_guest(meta)
    tip = detail if token == "SILKGATE_BUNDLED" else None
    if token == "SILKGATE_NO_COMMITS":
        since = "the last harvest" if meta.get("branch_ingested") else "the base commit"
        say(f"no commits since {since} — nothing to ingest")
        ok, result = True, "no_commits"
    elif token == "SILKGATE_NO_BRANCH":
        say(f"the guest deleted branch {meta['branch']!r} — nothing to ingest")
        ok, result = True, "no_branch"
    elif token == "SILKGATE_BUNDLED":
        ok = _ingest_bundle(meta, Path(meta["workspace"]) / ".silkgate.bundle", tip)
        result = "ingested" if ok else "failed"
    else:
        if meta.get("branch_ingested"):
            say(f"could not reach the guest ({detail}); refs/heads/{meta['branch']} holds "
                f"the last harvested state — the workspace is kept")
        else:
            say(f"could not harvest branch {meta['branch']!r}: {detail} — the workspace "
                "is kept")
        ok, result = False, "failed"
    # The verdict is settled before the record is cut, and _journal never raises, so a
    # journal failure cannot change what this harvest reports.
    _journal(meta["name"], "harvest", result=result, tip=tip,
             detail=None if token == "SILKGATE_BUNDLED" else detail or None)
    return ok


def _reap_derived_workspace(meta):
    """Delete a branch session's workspace — and only that. meta is data from disk, and this
    is an rmtree, so both locks must hold: the flag, and the path resolving to exactly the
    directory a branch session derives. A user-named -v mount never carries the flag."""
    if not meta.get("workspace_derived") or not meta.get("workspace"):
        return
    ws = Path(meta["workspace"])
    expected = Path(meta.get("repo_root", "")) / ".silkgate" / "sandboxes" / meta["name"]
    if not ws.exists():
        return
    if ws.resolve() != expected.resolve():
        say(f"not deleting {ws}: it is not this session's derived workspace")
        return
    shutil.rmtree(ws, ignore_errors=True)


# --- commands ------------------------------------------------------------------

def cmd_build(args):
    profiles = resolve_profiles(args.with_ or [])
    load_ruleset(compose_rules(profiles))            # bad rules fail before a long build
    preflight(*_build_tools())                       # every missing tool at once, pre-docker
    ref = build_image(profiles, base=args.base, platform_=args.platform)
    say(f"loaded {ref} into msb")
    print(ref)


def cmd_profiles(args):
    specs = getattr(args, "render", None)
    if specs:
        # A parameterized policy stays as auditable as a static one: this is the exact
        # composed text a session launched with the same --with list enforces, parsed
        # first so a defect dies here rather than reads as an allowance.
        text = compose_rules(resolve_profiles(specs))
        load_ruleset(text)
        sys.stdout.write(text)
        return
    width = shutil.get_terminal_size((80, 24)).columns
    blocks = [_profile_block(Profile(d.name), width)
              for d in sorted(p for p in PROFILE_DIR.iterdir() if p.is_dir())]
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
    if prof.name in _VERIFY_ONLY:               # listed like the rest, usable unlike them
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
    for binary, hint in _TOOL_HINTS.items():
        path = shutil.which(binary)
        rows.append((binary, path or f"missing — {hint}"))
        if path is None:
            missing.append(binary)
    _print_table(rows)
    sys.stdout.flush()                    # the verdict goes to stderr; table first, even piped
    if missing:
        die(f"missing {len(missing)} of {len(_TOOL_HINTS)} tools")
    say("toolchain complete")


def cmd_proxy(args):
    """One ruleset, one port, in the foreground — for guests silkgate doesn't manage.

    Binds PROXY_BINDS, loopback by default, like every proxy entry point. For a guest on
    another machine, name one routable interface with SILKGATE_PROXY_BIND=<address>.
    """
    profiles = resolve_profiles(args.with_ or [])
    rules_text = compose_rules(profiles, args.rule or [])
    if not rules_text.strip():
        die("no rules — pass --with PROFILE and/or --rule 'host/path GET'")
    check_secrets(load_ruleset(rules_text))
    mitmdump = which("mitmdump", "pip install mitmproxy")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _prune_logs()
    stamp = f"{datetime.now():%Y%m%d-%H%M%S}"
    rules_file = LOG_DIR / f"standalone-{stamp}.rules"
    events_path = LOG_DIR / f"events-{stamp}.jsonl"
    capture_path = LOG_DIR / f"capture-{stamp}.jsonl"
    rules_file.write_text(rules_text)
    env = dict(os.environ, SILKGATE_EGRESS_RULES=str(rules_file),
               SILKGATE_EGRESS_EVENTS_FILE=str(events_path),
               SILKGATE_EGRESS_CAPTURE_FILE=str(capture_path))
    env.pop("SILKGATE_EGRESS_SESSIONS_DIR", None)
    # rawtcp=false: a CONNECT whose payload mitmproxy cannot read as TLS is refused
    # instead of becoming an opaque tunnel around the addon's per-request checks.
    argv = [mitmdump, "-s", str(ADDON), "--set", "rawtcp=false"] + _modes(args.port)
    proc = subprocess.Popen(argv, env=env)
    try:
        sys.exit(wait_foreground(proc))
    finally:
        stop(proc)


def _strip_cmd_sep(cmd):
    return cmd[1:] if cmd and cmd[0] == "--" else cmd


def cmd_run(args):
    """One-shot over a persistent session: up (ephemeral) -> exec -> down, all foreground."""
    check_env(args.env)
    _check_mount_flags(args)
    profiles, rules_text, ruleset = _session_policy(args)
    _read_brief(args.brief)     # per-exec brief: fail on it here, before any host process
    cmd = _strip_cmd_sep(args.cmd) or profile_command(profiles)
    if not cmd:
        die("nothing to run — pass a command after -- (or --with a profile that names one)")
    name = args.name or uuid4().hex[:6]
    _validate_name(name)
    if session_dir(name).exists():
        die(f"session {name!r} already exists")
    # The ask is well-formed; now the whole toolchain shortfall in one report, before any
    # host process. An explicit --image is run as-is, never built, so docker is not its
    # business.
    preflight(*(() if args.image else _build_tools()), "msb", "mitmdump",
              *(("git",) if args.branch or args.checkout is not None else ()))
    tty = args.tty if args.tty is not None else sys.stdin.isatty()
    if args.branch:
        spec = _branch_spec(args.branch, profiles, args.env, args.checkout or "HEAD")
    elif args.checkout is not None:
        spec = _checkout_spec(args.checkout, profiles, args.env)
    else:
        spec = None
    vmounts = _mount_args(args.mount, allow_git_dir=args.allow_git_dir)
    mounts = [f"{host}:{guest}:{mode}" for host, guest, mode in vmounts]
    ws = None
    if args.branch:
        ws, extra = _branch_workspace(spec, name)
        mounts += extra
    elif spec:
        mounts += _checkout_workspace(spec)
    image = ensure_image(profiles, args.image, base=args.base)
    proxy_was_running = _proxy_running()        # --port is the base port iff WE start it
    rc, provisioned, branch_ready, proxy = 1, False, False, None
    create_env = (_guest_credential_env(profiles) + list(args.env)
                  + (list(_BRANCH_ENV) if args.branch else []))
    try:
        proxy = ensure_proxy(args.port)
        port = pick_port(proxy, name)
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
            die(fault)                      # the finally below tears the session down
        if args.branch:
            _setup_branch_guest(sandbox_name(name), args.branch, spec["base"], name)
            branch_ready = True
        elif spec:
            _setup_checkout_guest(sandbox_name(name), spec["base"], name)
        say(f"session {name} · proxy :{port} · audit: tail -f {proxy['log']}")
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
        with _deferred_interrupts():
            if provisioned:
                meta = read_meta(name) or {"name": name, "sandbox": sandbox_name(name),
                                           **(spec or {}), **({"workspace": ws} if ws else {})}
                # Harvest while the guest is still up — its gitdir dies with the VM. A
                # harvest that could not bank everything keeps the workspace and must not
                # let a green guest run mask it, hence the forced nonzero exit.
                keep = False
                if branch_ready:
                    keep = not _harvest_branch(meta)
                    if keep and rc == 0:
                        rc = 1
                _teardown_session(meta)
                if spec and not keep:
                    _reap_derived_workspace(meta)
            else:
                _release_port(name)     # a claim pick_port made, however far it got
                if spec and ws:
                    shutil.rmtree(ws, ignore_errors=True)   # empty: created before the try
            # Only tear down the proxy if this command started it and nothing else
            # needs it.
            if not proxy_was_running and not list_metas():
                stop_proxy(read_proxy() or proxy)
    sys.exit(rc)


def _session_policy(args):
    """Profiles -> (profiles, composed rules text, parsed ruleset), failing on bad rules.

    No profile and no --rule composes an empty ruleset, which is legal: it is the strictest
    policy silkgate can express — default-deny with nothing exempted — and the alternative
    of a rule written to match nothing would sit in shell history reading like an allowance.
    """
    profiles = resolve_profiles(args.with_ or [])
    rules_text = compose_rules(profiles, args.rule or [])
    ruleset = load_ruleset(rules_text)
    if not ruleset.rules:
        say("empty allowlist — this guest can reach nothing; every request is denied")
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
        die(f"cannot read --brief {path}: {e.strerror or e}")
    if len(data) > _BRIEF_MAX_BYTES:
        die(f"--brief {path} is {len(data)} bytes — over the 1 MiB limit")
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
        die(f"cannot store the exec brief under {bdir}: {e}")
    err = _land_brief_in_guest(sandbox, data)
    if err is not None:
        die(f"could not land the brief in the guest: {err}")
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
        say(f"warning: {path} is not valid JSON — the settings projection ignores it")
        return {}
    if not isinstance(data, dict):
        say(f"warning: {path} is not a JSON object — the settings projection ignores it")
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
    check_env(args.env)
    _check_mount_flags(args)
    profiles, rules_text, ruleset = _session_policy(args)
    brief = _read_brief(args.brief)             # host-side, before any provisioning
    name = args.name or uuid4().hex[:6]
    _validate_name(name)
    if session_dir(name).exists():
        die(f"session {name!r} already exists")
    # The ask is well-formed; now the whole toolchain shortfall in one report, before any
    # host process. An explicit --image is run as-is, never built, so docker is not its
    # business.
    preflight(*(() if args.image else _build_tools()), "msb", "mitmdump",
              *(("git",) if args.branch or args.checkout is not None else ()))
    if args.branch:
        spec = _branch_spec(args.branch, profiles, args.env, args.checkout or "HEAD")
    elif args.checkout is not None:
        spec = _checkout_spec(args.checkout, profiles, args.env)
    else:
        spec = None
    vmounts = _mount_args(args.mount, allow_git_dir=args.allow_git_dir)
    mounts = [f"{host}:{guest}:{mode}" for host, guest, mode in vmounts]
    ws = None
    if args.branch:
        ws, extra = _branch_workspace(spec, name)
        mounts += extra
    elif spec:
        mounts += _checkout_workspace(spec)
    image = ensure_image(profiles, args.image, base=args.base)
    provisioned = False
    create_env = (_guest_credential_env(profiles) + list(args.env)
                  + (list(_BRANCH_ENV) if args.branch else []))
    try:
        proxy = ensure_proxy(args.port)
        port = pick_port(proxy, name)
        ctx, ctx_paths = _context_for(args, profiles, ruleset, vmounts, persistent=True)
        settings, settings_paths = _settings_for(args, profiles,
                                                 _settings_workspace(spec, vmounts))
        meta_extra = {**_session_meta(profiles, profile_command(profiles)),
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
            die(fault)
        if args.branch:
            _setup_branch_guest(sandbox_name(name), args.branch, spec["base"], name)
        elif spec:
            _setup_checkout_guest(sandbox_name(name), spec["base"], name)
    except BaseException:
        # A session `up` never handed over is removed whole, interrupt included: nothing
        # of the user's is in it yet, and one left behind would hide the failure. Stop
        # signals are deferred, so a second Ctrl-C can't leave it half-removed.
        with _deferred_interrupts():
            if provisioned:
                # A session never handed over leaves nothing worth archiving.
                _teardown_session(read_meta(name) or
                                  {"name": name, "sandbox": sandbox_name(name)},
                                  archive=False)
            else:
                _release_port(name)     # a claim pick_port made, however far it got
            if spec and ws:
                shutil.rmtree(ws, ignore_errors=True)   # no commits can exist yet
            _maybe_stop_proxy()
        raise
    say(f"session {name} up · proxy :{port} · audit: tail -f {proxy['log']}")
    print(name)


def cmd_exec(args):
    meta = read_meta(args.name)
    if not meta:
        die(f"no such session: {args.name!r} (silkgate ls)")
    check_env(args.env)
    cmd = _strip_cmd_sep(args.cmd) or meta.get("command")
    if not cmd:
        die("nothing to run — usage: silkgate exec NAME [-t] [-e K=V]... -- CMD ...")
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
        die(f"no such session: {args.name!r} (silkgate ls)")
    cmd = meta.get("command")
    if not cmd:
        die(f"session {args.name!r} has no default command — use: silkgate exec {args.name} -t -- CMD")
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
    with _deferred_interrupts():
        keep = bool(meta.get("branch")) and not _harvest_branch(meta)
        _teardown_session(meta)
        if meta.get("branch") and not keep:
            _reap_derived_workspace(meta)
        _maybe_stop_proxy()
    return keep


def cmd_down(args):
    meta = read_meta(args.name)
    if not meta:
        die(f"no such session: {args.name!r} (silkgate ls)")
    # Teardown needs msb to stop/rm the guest; without this, its absence surfaces as
    # "msb rm failed — session kept", which reads as a broken sandbox, not a missing tool.
    preflight("msb", *(("git",) if meta.get("branch") else ()))
    keep = _down_session(meta)
    say(f"session {args.name} down")
    if keep:
        sys.exit(1)


def cmd_harvest(args):
    """Bundle the session's branch out of the live guest and fast-forward the host branch —
    the mid-session save point. No teardown, no workspace reaping."""
    meta = read_meta(args.name)
    if not meta:
        die(f"no such session: {args.name!r} (silkgate ls)")
    if not meta.get("branch"):
        die(f"session {args.name!r} has no --branch — nothing to harvest")
    preflight("msb", "git")
    sys.exit(0 if _harvest_branch(meta) else 1)


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
                         *_journal_summary(ARCHIVE_DIR / m["sid"] / "journal.jsonl"),
                         m["sid"]))
        _print_table(rows)
    proxy = read_proxy()
    ident = _proxy_ident()               # identity via the control socket, never pid alone:
    if ident is None:                    # after an unclean exit proxy.json survives and its
        print("proxy: not running")      # pid may belong to a recycled, unrelated process
    elif proxy is None:
        print(f"proxy: pid {ident or 'unknown'} answers on {PROXY_SOCK} but {PROXY_JSON} "
              "is gone — kill that process and retry")
    else:
        pool = proxy["ports"]
        pid = ident or proxy.get("pid")  # 0 = answered, but the kernel could not name it
        print(f"proxy: pid {pid} alive · ports {pool[0]}-{pool[-1]} · {proxy['log']}")


def cmd_secret_set(args):
    """Secrets are scoped per session in the proxy, so a set names the one it is for."""
    name = args.name
    value = os.environ.get(f"SILKGATE_EGRESS_SECRET_{name.upper()}")
    if not value:
        die(f'missing secret: SILKGATE_EGRESS_SECRET_{name.upper()}="<header>: <value>"')
    if _parse_secret(value) is None:
        die(f'SILKGATE_EGRESS_SECRET_{name.upper()} is not a valid "<Header>: <value>" line — '
            "expected a printable-ASCII header name (not a routing header) and a non-empty value")
    if not read_meta(args.session):
        die(f"no such session: {args.session!r} (silkgate ls)")
    if not _proxy_running():
        die("shared proxy not running — start a session first (silkgate up)")
    _sock_call({"op": "set_secret", "name": name.lower(), "value": value,
                "session": args.session})
    say(f"secret {name.lower()} set for session {args.session}")   # value never printed


def cmd_secret_ls(args):
    if not _proxy_running():
        die("shared proxy not running — start a session first (silkgate up)")
    if args.session:
        if not read_meta(args.session):
            die(f"no such session: {args.session!r} (silkgate ls)")
        for n in sorted(_sock_call({"op": "list_secrets",
                                    "session": args.session}).get("names", [])):
            print(n)
        return
    by_session = _sock_call({"op": "list_secrets"}).get("sessions", {})
    for s in sorted(by_session):                 # names only, one per line, session-qualified
        for n in sorted(by_session[s]):
            print(f"{s}/{n}")

