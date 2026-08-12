"""mitmproxy addon — Tier 2 egress enforcement over rule_engine.

Every request is resolved the same way: the listener port it arrived on picks a ruleset.
Which registry answers that question is the only difference between the two ways to run:

    export SILKGATE_EGRESS_RULES=/path/to/rules.txt                   # colon-separate to combine files
    export SILKGATE_EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-..."   # injected; never in the guest
    mitmdump -s mitmaddon/proxy_addon.py --listen-port 8090
        one ruleset, every port — for guests silkgate doesn't manage

    export SILKGATE_EGRESS_SESSIONS_DIR=~/.silkgate/sessions          # <name>/meta.json + <name>/rules.txt
    export SILKGATE_EGRESS_CONTROL_SOCK=~/.silkgate/proxy.sock        # unix control socket (secrets)
    mitmdump -s mitmaddon/proxy_addon.py --mode regular@8090 --mode regular@8091 ...
        one proxy serving many sessions, each on its own port

Exactly one of SILKGATE_EGRESS_RULES / SILKGATE_EGRESS_SESSIONS_DIR must be set (die at load otherwise).

Two hooks decide: `http_connect` gates the authority of a CONNECT before its tunnel exists,
`request` decides every request — including the ones decrypted out of such a tunnel. Both
match on the destination mitmproxy will actually dial, never on what the client claims.
`response` and `error` decide nothing: they finish the audit trail, recording what an
allowed flow actually moved.

Tier 1 (forcing all guest traffic here, enforced outside the guest) is microsandbox's own
host-side network policy — see ../README.md. This addon assumes the guest can only reach this
proxy, and — with a session registry — only its own listener port, so the accepted port is
spoof-proof session identity.
"""
import asyncio
import json
import logging
import os
import re
import socket
import tempfile
import time
from datetime import datetime

from mitmproxy import ctx, exceptions, http

from rule_engine import (RuleSet, normalize_host,
                         _parse_secret, _MAX_SECRET, _HEADER_TOKEN, _ROUTING_HEADERS)

logger = logging.getLogger("egress")

# --- configuration: exactly one of SILKGATE_EGRESS_RULES / SILKGATE_EGRESS_SESSIONS_DIR ---------
_RULES_PATH = os.environ.get("SILKGATE_EGRESS_RULES")
_SESSIONS_DIR = os.environ.get("SILKGATE_EGRESS_SESSIONS_DIR")
_CONTROL_SOCK = os.environ.get("SILKGATE_EGRESS_CONTROL_SOCK")
if bool(_RULES_PATH) == bool(_SESSIONS_DIR):
    raise RuntimeError("set exactly one of SILKGATE_EGRESS_RULES (one ruleset, colon-separated rule "
                       "files) or SILKGATE_EGRESS_SESSIONS_DIR (a session per listener port)")


class _EventsFile:
    """Append-mode secondary sink for machine-readable event records.

    Each write appends one JSON line and flushes — no fsync. A None path disables
    the sink; control and stream records are never written here.
    """

    def __init__(self, path):
        self._fh = open(path, "a") if path is not None else None

    def write(self, line):
        if self._fh is None:
            return
        self._fh.write(line + "\n")
        self._fh.flush()


EVENTS = _EventsFile(os.environ.get("SILKGATE_EGRESS_EVENTS_FILE"))


class _CaptureFile:
    """Append-mode sink for LLM capture records — the deliberate contrast with _EventsFile.

    A failed EVENTS write propagates and fails the flow closed, because the audit trail is
    enforcement's own record. Capture is observability layered on top of flows the audit
    already covers, so losing it must never cost traffic: the first failure disables the
    sink for good and logs one control line, and `write` never raises.
    """

    def __init__(self, path):
        self._fh = None
        if path is None:
            return
        try:
            self._fh = open(path, "a")
        except Exception as e:
            self._disable(f"capture sink disabled: {e}")

    def _disable(self, reason):
        self._fh = None
        logger.info(json.dumps({"decision": "control", "reason": reason}))

    def write(self, line):
        if self._fh is None:
            return
        try:
            self._fh.write(line + "\n")
            self._fh.flush()
        except Exception as e:
            self._disable(f"capture sink disabled: {e}")


CAPTURE = _CaptureFile(os.environ.get("SILKGATE_EGRESS_CAPTURE_FILE"))


def configure(updates):
    """Refuse the one mitmproxy option that would route requests around this addon.

    If stream_large_bodies is ever set, mitmproxy sends any over-threshold request's headers
    upstream *before* the request hook fires — the host match, the credential injection, the
    header hygiene and max_body are all skipped and the request is already on the wire.
    Nothing sets it; raising here turns that from a convention into a control: OptionsError
    refuses startup outright, and rolls back a runtime change. body_size_limit is the
    opposite knob — it aborts an oversized body before it is buffered — but the same number
    caps responses too, and package downloads are legitimately huge, so requiring it would
    deny the proxy's main use; it stays the operator's call.
    """
    if "stream_large_bodies" in updates and ctx.options.stream_large_bodies:
        raise exceptions.OptionsError(
            "stream_large_bodies bypasses egress enforcement: a request over the threshold "
            "is sent upstream before the addon can match, strip or deny it — refusing to run")


# --- secrets: "<Header>: <value>", in memory, scoped by session -----------------
# _parse_secret, _MAX_SECRET, _HEADER_TOKEN and _ROUTING_HEADERS live in rule_engine
# so cli/silkgate can reuse the same parser for launch-time validation without taking
# a mitmproxy dependency.  _SECRET_NAME is proxy-internal (control-socket op names).
_SECRET_NAME = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}")


class SecretStore:
    """Named secrets ("<Header>: <value>") for inject_auth, scoped by session.

    A scope is a session name, or None for the standalone single-ruleset proxy. A session's
    secrets arrive over the control socket, already naming their scope, from the `up` that
    provisioned it — so a session spends only the credentials its own creator could show.
    SILKGATE_EGRESS_SECRET_* env vars are read for the None scope only: the process environment is
    one bag shared by every session, and honouring it per session would be exactly the
    cross-session grant this scoping exists to remove. Values never leave this object: they
    are not logged, not returned by list, not echoed by any control op — only spent by
    injection.
    """

    def __init__(self):
        self._store = {}                         # session|None -> {lower-name: "Header: value"}

    def get(self, session, name):
        scope = self._store.get(session, {})
        key = name.lower()
        if key in scope:
            return scope[key]
        if session is None:
            return os.environ.get("SILKGATE_EGRESS_SECRET_" + name.upper())
        return None

    def set(self, session, name, value):
        self._store.setdefault(session, {})[name.lower()] = value

    def names(self, session):
        env = ({k[len("SILKGATE_EGRESS_SECRET_"):].lower()
                for k in os.environ if k.startswith("SILKGATE_EGRESS_SECRET_")}
               if session is None else set())
        return sorted(env | set(self._store.get(session, {})))

    def by_session(self):
        """Session -> its secret names (names only), for the operator's `secret ls`."""
        return {s: sorted(scope) for s, scope in self._store.items() if s is not None}

    def prune(self, live):
        """Forget sessions no longer in `live`, so a later session reusing a name does not
        inherit the dead one's credentials. The None scope has no session to outlive."""
        for stale in [s for s in self._store if s is not None and s not in live]:
            del self._store[stale]


SECRETS = SecretStore()


# --- registries: a listener port resolves to a ruleset (and maybe a session) ---
class SessionError(Exception):
    """Fail-closed session-resolution failure; the message is the audit deny reason."""


class FixedRegistry:
    """One ruleset, whatever port a request arrives on. Sessions are simply absent."""

    def __init__(self, paths):
        texts = []
        for path in paths:
            with open(path) as fh:
                texts.append(fh.read())
        self._ruleset = RuleSet.parse("\n".join(texts))

    def resolve(self, port):
        return None, self._ruleset

    def has_session(self, name):
        return False                             # no named sessions; only the None scope


class SessionRegistry:
    """Resolve a listener port to (session name, RuleSet) from SILKGATE_EGRESS_SESSIONS_DIR.

    Layout: <dir>/<name>/meta.json (carries "port") and <dir>/<name>/rules.txt (the composed
    ruleset snapshot). Both layers are re-read from disk on every resolve: sessions appear by
    rename out of a staging directory, so their files keep whatever mtimes staging gave them,
    and a name-and-port recycle can land inside one filesystem timestamp tick — no timestamp
    can tell a session from the one it replaced, so none is consulted. A scan is a listdir
    plus a small JSON read per session (tens of µs, against a proxied request's milliseconds);
    only the rule parse is worth avoiding (~0.2ms for a composed profile, pure Python under
    the GIL of the one proxy every session shares), and its cache is keyed on the rule text
    itself: byte-identical text is byte-identical policy, so the key cannot serve one
    session's rules to another. Any ambiguity fails closed (raises).
    """

    def __init__(self, sessions_dir):
        self._dir = sessions_dir
        self._rules = {}                         # name -> (rules bytes, RuleSet|None, reason|None)

    def _scan(self):
        """(port -> name, live names), read fresh; empty when the dir is unreadable.

        A successful scan is also the moment per-session state is dropped: a session it no
        longer shows is down for good, and the pool recycles both its name and its port — so
        its secrets and cached rules go with it, or the next session called the same thing
        starts life holding the dead one's credentials. A failed scan proves nothing about
        which sessions are live and prunes nothing: denying every port until the directory
        is readable again is recoverable, an emptied secret store is not — secrets arrive
        once, at provision.
        """
        try:
            names = os.listdir(self._dir)
        except OSError:
            return {}, frozenset()
        ports, live = {}, set()
        for name in names:
            if name.startswith("."):             # CLI staging dirs are not sessions
                continue
            try:                                 # skip half-written / malformed sessions
                with open(os.path.join(self._dir, name, "meta.json")) as fh:
                    port = int(json.load(fh)["port"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
            live.add(name)
            # A port two sessions claim is marked ambiguous, not given to whichever name
            # listdir yielded last: the loser's guest would run under the winner's ruleset.
            ports[port] = name if port not in ports else None
        SECRETS.prune(live)
        for stale in [n for n in self._rules if n not in live]:
            del self._rules[stale]
        return ports, live

    def _ruleset(self, name):
        # Parse a session's rules.txt, re-reading the bytes every time: they are the cache
        # key, so a recreated session is told apart from its predecessor by the only thing
        # that matters here — what the rules say. A failure to decode or parse is cached
        # under the same key, so a session recreated with usable rules is picked up at once.
        path = os.path.join(self._dir, name, "rules.txt")
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            raise SessionError("no session for port")     # snapshot vanished under us
        cached = self._rules.get(name)
        if cached is None or cached[0] != data:
            try:                                 # UnicodeDecodeError is a ValueError
                cached = (data, RuleSet.parse(data.decode()), None)
            except ValueError as e:
                cached = (data, None, f"rules parse error: {e}")
            self._rules[name] = cached
        if cached[1] is None:
            raise SessionError(cached[2])
        return cached[1]

    def resolve(self, port):
        """Return (name, RuleSet) for a listener port, or raise SessionError (fail closed)."""
        ports, _ = self._scan()
        name = ports.get(port)
        if name is None:
            raise SessionError("two sessions claim this port" if port in ports
                               else "no session for port")
        return name, self._ruleset(name)

    def has_session(self, name):
        """Whether `name` is a live session — the scan is fresh, so a set_secret racing the
        session's first appearance sees it as soon as the rename lands."""
        return name in self._scan()[1]


REGISTRY = (SessionRegistry(_SESSIONS_DIR) if _SESSIONS_DIR
            else FixedRegistry(_RULES_PATH.split(":")))


# --- control socket: line-delimited JSON, ping / set_secret / list_secrets ----
def _control_dispatch(line):
    """Handle one control request line (bytes/str) -> a JSON-able reply dict.

    Pure and unit-testable. Never includes secret values in any reply. Unknown op is an error.
    """
    try:
        req = json.loads(line)
    except ValueError:
        return {"ok": False, "error": "bad json"}
    if not isinstance(req, dict):
        return {"ok": False, "error": "bad request"}
    op = req.get("op")
    if op == "ping":
        return {"ok": True}
    if op == "set_secret":
        name, value, session = req.get("name"), req.get("value"), req.get("session")
        if not isinstance(name, str) or not _SECRET_NAME.fullmatch(name):
            return {"ok": False, "error": "name must match [0-9A-Za-z][0-9A-Za-z._-]{0,63}"}
        if _parse_secret(value) is None:
            return {"ok": False, "error": "value must be '<Header>: <value>', printable ASCII, "
                                          f"under {_MAX_SECRET} chars, and not a routing header"}
        # The store is scoped, so the op must name a scope that can spend the secret: a live
        # session, or — with a fixed ruleset, where sessions do not exist — no session at all.
        if session is None:
            if _SESSIONS_DIR:
                return {"ok": False, "error": "set_secret needs a session: this proxy scopes "
                                              "secrets per session"}
        elif not isinstance(session, str) or not REGISTRY.has_session(session):
            return {"ok": False, "error": f"unknown session: {session!r}"}
        SECRETS.set(session, name, value)
        return {"ok": True}
    if op == "list_secrets":
        session = req.get("session")
        if session is None and _SESSIONS_DIR:
            return {"ok": True, "sessions": SECRETS.by_session()}
        if session is not None and (not isinstance(session, str)
                                    or not REGISTRY.has_session(session)):
            return {"ok": False, "error": f"unknown session: {session!r}"}
        return {"ok": True, "names": SECRETS.names(session)}
    return {"ok": False, "error": f"unknown op: {op!r}"}


async def _control_client(reader, writer):
    try:
        while True:
            line = await reader.readline()
            if not line:                          # EOF
                break
            writer.write((json.dumps(_control_dispatch(line)) + "\n").encode())
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


def _control_log(reason):
    logger.info(json.dumps({"decision": "control", "reason": reason}))


async def _control_server(path):
    # A unix socket is created with the umask's permissions, so chmod-after-bind leaves a
    # window in which anyone on the host could connect and push a secret. Bind inside a
    # private directory instead (mkdtemp is 0700 from creation, in the same filesystem) and
    # rename the finished socket into place: the advertised path never exists world-writable,
    # and the socket keeps serving under its new name because the bound inode is unchanged.
    staging = tempfile.mkdtemp(prefix=".control-", dir=os.path.dirname(path) or ".")
    bound = os.path.join(staging, "sock")
    try:
        server = await asyncio.start_unix_server(_control_client, path=bound)
        os.chmod(bound, 0o600)
        os.rename(bound, path)
    finally:
        try:
            os.unlink(bound)                      # still there only if bind or rename failed
        except OSError:
            pass
        try:
            os.rmdir(staging)
        except OSError:
            pass
    _control_log(f"listening on {path}")
    async with server:
        await server.serve_forever()


def _control_sock_live(path):
    """True if something is accepting on `path` — another proxy owns that control channel.

    A socket file left behind by a dead proxy refuses the connection, so it is safe to replace.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(0.5)
        sock.connect(path)
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _shutdown(reason):
    logger.error(json.dumps({"decision": "control", "reason": reason}))
    try:
        ctx.master.shutdown()
    except Exception:                             # already tearing down; the log is the point
        pass


def _control_stopped(task):
    # asyncio.ensure_future swallows what the task raises, so a failed bind would otherwise
    # leave the proxy serving traffic with no control channel and no sign of it. A proxy that
    # cannot be given secrets cannot honour an inject_auth rule, so stop rather than limp.
    if task.cancelled():                          # ordinary shutdown cancels serve_forever
        return
    exc = task.exception()
    if exc is not None:
        _shutdown(f"control socket failed: {exc!r}")


def running():
    """mitmproxy lifecycle hook — start the control socket once the loop is up."""
    if not _CONTROL_SOCK:
        return
    if _control_sock_live(_CONTROL_SOCK):
        # Unlinking a live socket would take over another proxy's control channel and leave it
        # unable to receive secrets, silently. Refuse to run: exiting is loud (the CLI reports
        # a proxy that died at startup) and leaves the proxy that got there first intact.
        _shutdown(f"control socket {_CONTROL_SOCK} is already served by another proxy")
        return
    try:
        os.unlink(_CONTROL_SOCK)                  # a stale socket from a dead proxy
    except FileNotFoundError:
        pass
    except OSError as e:
        _shutdown(f"cannot replace stale control socket {_CONTROL_SOCK}: {e}")
        return
    asyncio.ensure_future(_control_server(_CONTROL_SOCK)).add_done_callback(_control_stopped)


# --- request enforcement -----------------------------------------------------
_FAILSAFE = "denied"                              # body of a block we could not describe


def _clip(text, limit=128):
    """Guest-supplied text, truncated so a hostile header cannot bloat a body or a log line."""
    return text if len(text) <= limit else text[:limit] + "..."


def _blocked(code, text):
    """The response a blocked request gets.

    The body is ASCII-armoured: guest-supplied text arrives decoded with surrogateescape, and
    encoding one raw would raise here — inside the deny path, which mitmproxy answers by
    logging the exception and forwarding the request unfiltered.

    The X-Silkgate header marks the refusal as ours, so a cooperating guest can tell a policy
    denial from a destination's own error — a refused CONNECT shows the guest headers but no
    body, so the body cannot carry the mark. Every refusal this addon issues comes through
    here, the fail-closed 500s included. The value is a constant so this stays throw-free,
    and the mark is a diagnostic, not a boundary: a destination could imitate it, and nothing
    may treat its presence as proof.
    """
    return http.Response.make(code, (text + "\n").encode("ascii", "backslashreplace"),
                              {"Content-Type": "text/plain", "X-Silkgate": "deny"})


def _ts():
    """Local wall clock with date and UTC offset. mitmdump's own line prefix is a bare time
    of day, so the record carries its date itself — a log spanning midnight stays ordered,
    and `logs --since` has something to parse."""
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _listen_port(flow):
    """The local TCP port this flow arrived on, or None if the socket info is absent."""
    try:
        return flow.client_conn.sockname[1]
    except Exception:
        return None


def _audit(decision, flow, reason="", session=None, **extra):
    """One JSON object per line.

    `host` and `port` are the destination mitmproxy dials, never the client's claim about it;
    a claim that contradicted the destination is recorded as `claimed`, since a guest naming
    one host and connecting to another is the interesting signal. `session` is what
    `silkgate logs --audit` filters on. json.dumps escapes what it cannot represent, so a
    hostile path or header cannot break the line.

    A request tells its story in at most two lines, joined by `id` (mitmproxy's flow id):
    the decision when it is made, and — for an allow — a "response" record once the flow
    concludes, carrying what actually moved. `status` on a deny is the code this addon
    answered, and the deny line is the whole story: nothing went upstream, so there is no
    second line. `status` on a "response" record is the destination's answer, or null if it
    never gave one.

    What enforcement did on the way through rides the allow line as names, never values:
    `injected` or `inject_skipped` (the secret's name — exclusive, by whether the guest sent
    the header) and `stripped_query` / `stripped_headers` (sorted names that lost at least
    one (name, value) pair). `path` is post-strip — the record describes what went upstream —
    so a name in `stripped_query` can still appear in `path` with an allowed value:
    q:beta=true keeps beta=true while dropping beta=false.
    """
    line = json.dumps({
        "ts": _ts(),
        "decision": decision,
        "id": flow.id,
        "method": flow.request.method,
        "host": flow.request.host,
        "port": flow.request.port,
        "path": flow.request.path,
        "reason": reason,
        "session": session,
        "listen_port": _listen_port(flow),
        **extra,
    })
    logger.info(line)
    EVENTS.write(line)


def _deny(flow, reason, code=403, session=None, shown=None, **extra):
    """Block the request and record why.

    `reason` goes to the audit log; `shown` overrides what the guest is told, so a deny can
    stay uninformative — the guest reads this body — without the audit losing the detail.
    """
    flow.response = _blocked(code, reason if shown is None else shown)
    _audit("deny", flow, reason, session, status=code, **extra)


def _fail_closed(flow, session, exc):
    """Last resort for an exception on the enforcement path.

    mitmproxy logs an exception escaping a hook and then proceeds as if the hook had never
    run — forwarding the request, or establishing the tunnel. So block first, with a response
    built from constants, and only then try to describe it: describing can throw too.
    """
    try:
        flow.response = _blocked(500, _FAILSAFE)
    except Exception:
        pass
    try:
        _audit("deny", flow, f"internal error: {exc.__class__.__name__}", session, status=500)
    except Exception:
        pass


def _authority_rule(ruleset, host, port):
    """First rule whose host and port admit `host:port`, ignoring path and method.

    For CONNECT, where those two do not exist yet. RuleSet.match demands both, and inventing
    either is wrong in a different direction, so this reads the two dimensions that do exist
    straight off the compiled rules.
    """
    for rule in ruleset.rules:
        if rule.host_re.match(host) and (rule.ports is None or port in rule.ports):
            return rule
    return None


# --- capture: decode LLM responses into records --------------------------------
# Capture is observability, not enforcement: the decoder reads a copy of each chunk,
# its records go to CAPTURE, and the wire is never modified. Every failure on this
# path is contained fail-open — the flow, its byte counts and its audit pair are
# worth more than the transcript.

# Each bound protects the one proxy every session shares from a degenerate or
# hostile stream, and each names its failure mode:
_CAPTURE_LINE_MAX = 64 * 1024        # one SSE line; over = the decoder dies (fail open),
                                     # because a real Anthropic event line is a few KiB
                                     # and anything bigger is not the grammar we parse
_CAPTURE_BLOCK_MAX = 256 * 1024      # stored chars per content block; over = stop
                                     # appending, keep counting, mark truncated — long
                                     # completions are legitimate, so capture degrades
                                     # instead of dying
_CAPTURE_TOTAL_MAX = 2 * 1024 * 1024 # bytes fed per SSE response; over = the decoder
                                     # dies — an unbounded stream must not grow open-
                                     # block state forever
_CAPTURE_JSON_MAX = 2 * 1024 * 1024  # buffered stream=false body; over = the decoder
                                     # dies — this is the one place capture buffers,
                                     # so it is the one place a cap guards memory
                                     # directly

# High-confidence PREFIXED token shapes only, from the gitleaks default set: every
# pattern is anchored to a literal vendor prefix. Deliberately no entropy or generic
# hex/base64 rules — coding transcripts are full of SHAs, digests and randomish ids,
# and a sighting channel that cries wolf gets filtered instead of read. The host
# cross-checks this list against gitleaks upstream.
_SECRET_PATTERNS = [(name, re.compile(pattern)) for name, pattern in (
    ("anthropic-api-key",       r"\bsk-ant-[A-Za-z0-9_-]{16,}"),
    ("openai-api-key",          r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
    ("github-pat",              r"\bghp_[A-Za-z0-9]{36}"),
    ("github-oauth",            r"\bgho_[A-Za-z0-9]{36}"),
    ("github-app-token",        r"\bgh[us]_[A-Za-z0-9]{36}"),
    ("github-fine-grained-pat", r"\bgithub_pat_[A-Za-z0-9_]{82}"),
    ("gitlab-pat",              r"\bglpat-[A-Za-z0-9_-]{20}"),
    ("aws-access-key-id",       r"\bAKIA[0-9A-Z]{16}\b"),
    ("slack-bot-token",         r"\bxoxb-[0-9A-Za-z-]{20,}"),
    ("slack-user-token",        r"\bxoxp-[0-9A-Za-z-]{20,}"),
    ("slack-webhook-url",       r"https://hooks\.slack\.com/services/"
                                r"T[A-Za-z0-9_]{5,}/B[A-Za-z0-9_]{5,}/[A-Za-z0-9_]{10,}"),
    ("stripe-live-key",         r"\b[sr]k_live_[A-Za-z0-9]{16,}"),
    ("google-api-key",          r"\bAIza[A-Za-z0-9_-]{35}"),
    ("sendgrid-api-key",        r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}"),
    ("twilio-api-key",          r"\bSK[0-9a-fA-F]{32}\b"),
    ("npm-token",               r"\bnpm_[A-Za-z0-9]{36}"),
    ("pypi-token",              r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}"),
    ("huggingface-token",       r"\bhf_[A-Za-z0-9]{34}"),
    ("private-key-pem",         r"-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----"),
    ("jwt",                     r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\."
                                r"[A-Za-z0-9_-]{8,}"),
)]

# The guest environment deliberately holds dummy credentials the proxy swaps at the
# boundary (profiles/claude/env), and agents echo their env — so the dummy would light
# up the anthropic pattern on every transcript. Exact matched-text only, never a
# prefix: a real key that merely starts like a dummy must still be sighted.
_SECRET_ALLOWLIST = frozenset({"sk-ant-DUMMY-replaced-by-egress-proxy"})


def _redact(text):
    """(text with secret spans replaced, names of the patterns that hit).

    Runs on a complete block at content_block_stop, so no secret can straddle a chunk
    boundary. Only what the capture file stores is rewritten; the sighting record
    carries the pattern name and never the matched value.
    """
    seen = []
    for name, pattern in _SECRET_PATTERNS:
        replaced = pattern.sub(
            lambda m, _n=name: m.group(0) if m.group(0) in _SECRET_ALLOWLIST
            else f"[redacted:{_n}]", text)
        if replaced != text:
            seen.append(name)
            text = replaced
    return text, seen


class _AnthropicCapture:
    """Anthropic Messages response -> capture records. Pure: bytes in through feed(),
    dicts out, no mitmproxy and no I/O, so the whole grammar is unit-testable directly.

    feed(chunk) returns the records the chunk completed; b"" is mitmproxy's
    end-of-message marker. flush() is the abort path, for a flow that died before the
    marker: it closes open blocks and marks the turn incomplete. summary() is what the
    audit response record can be enriched with, whenever it is asked. Any parse
    surprise raises out of feed — containment is the tap's job, not this class's,
    because the tap is the only layer that knows what a dead decoder must not take
    down with it.
    """

    def __init__(self, mode):
        if mode not in ("sse", "json"):
            raise ValueError(f"unknown capture mode: {mode!r}")
        self._sse = mode == "sse"
        self._buf = b""                  # partial SSE line / the whole stream=false body
        self._total = 0                  # bytes fed, for the caps
        self._event = None               # pending SSE event type
        self._data = []                  # accumulated data: lines for the pending event
        self._blocks = {}                # index -> open block accumulator
        self._model = None
        self._message_id = None
        self._usage = {}
        self._stop_reason = None
        self._output_tokens = None
        self._ended = False              # a turn_end went out; emit nothing further

    # --- accumulators ---------------------------------------------------------
    @staticmethod
    def _rec(kind, **fields):
        """A record with its known fields only: absent upstream data is omitted, not null."""
        rec = {"kind": kind}
        rec.update((k, v) for k, v in fields.items() if v is not None)
        return rec

    @staticmethod
    def _new_block(btype, tool_name=None, tool_id=None):
        return {"type": btype, "parts": [], "chars": 0, "stored": 0,
                "truncated": False, "tool_name": tool_name, "tool_id": tool_id}

    @staticmethod
    def _append(block, text):
        """chars counts the true length; storage stops at the cap and marks it."""
        if not block["truncated"]:
            room = _CAPTURE_BLOCK_MAX - block["stored"]
            if len(text) > room:
                block["parts"].append(text[:room])
                block["stored"] = _CAPTURE_BLOCK_MAX
                block["truncated"] = True
            else:
                block["parts"].append(text)
                block["stored"] += len(text)
        block["chars"] += len(text)

    def _close_block(self, index, block):
        """The content_block record (plus sightings), scanned and redacted here —
        the one moment the text is both complete and still unwritten."""
        rec = {"kind": "content_block", "index": index, "type": block["type"],
               "chars": block["chars"]}
        if block["truncated"]:
            rec["truncated"] = True
        if block["type"] not in ("text", "tool_use"):
            # thinking, and any type this decoder does not know: the length is
            # recorded, the content never is — unknown content has unknown
            # sensitivity, so it gets thinking's treatment, not text's.
            return [rec]
        text, seen = _redact("".join(block["parts"]))
        out = [{"kind": "secret_sighting", "pattern": name, "index": index}
               for name in seen]
        if block["type"] == "text":
            rec["text"] = text
        else:
            rec["tool_name"] = block["tool_name"]
            rec["tool_id"] = block["tool_id"]
            try:                         # truncated or partial JSON: keep the raw string
                rec["tool_input"] = json.loads(text)
            except ValueError:
                rec["tool_input"] = text
        out.append(rec)
        return out

    # --- input ----------------------------------------------------------------
    def feed(self, chunk):
        if not chunk:
            return self._finish() if self._sse else self._finish_json()
        self._total += len(chunk)
        self._buf += chunk
        if not self._sse:
            if self._total > _CAPTURE_JSON_MAX:
                raise ValueError("stream=false body exceeds _CAPTURE_JSON_MAX")
            return []
        if self._total > _CAPTURE_TOTAL_MAX:
            raise ValueError("SSE stream exceeds _CAPTURE_TOTAL_MAX")
        out = []
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                if len(self._buf) > _CAPTURE_LINE_MAX:
                    raise ValueError("SSE line exceeds _CAPTURE_LINE_MAX")
                break
            line, self._buf = self._buf[:nl], self._buf[nl + 1:]
            if len(line) > _CAPTURE_LINE_MAX:
                raise ValueError("SSE line exceeds _CAPTURE_LINE_MAX")
            # Split on \n before decoding: a complete line is valid UTF-8 on its own
            # (multi-byte sequences never contain 0x0A), so only chunk-torn sequences
            # inside one line could ever need errors="replace".
            out.extend(self._line(line.decode("utf-8", "replace").rstrip("\r")))
        return out

    def flush(self):
        """Abort path: whatever is open, then a turn_end marked incomplete."""
        return self._finish()

    def summary(self):
        out = {}
        if self._model is not None:
            out["model"] = self._model
        if self._usage.get("input_tokens") is not None:
            out["tokens_in"] = self._usage["input_tokens"]
        if self._output_tokens is not None:
            out["tokens_out"] = self._output_tokens
        if self._stop_reason is not None:
            out["stop_reason"] = self._stop_reason
        return out

    # --- SSE grammar ------------------------------------------------------------
    def _line(self, line):
        if line == "":
            return self._dispatch()
        if line.startswith(":"):         # SSE comment (Anthropic sends keepalives)
            return []
        field, _, value = line.partition(":")
        if value.startswith(" "):        # the grammar strips one leading space
            value = value[1:]
        if field == "event":
            self._event = value
        elif field == "data":
            self._data.append(value)
        # unknown fields (id:, retry:) are ignored, per the grammar
        return []

    def _dispatch(self):
        event, data = self._event, "\n".join(self._data)
        self._event, self._data = None, []
        if not data or self._ended:
            return []
        payload = json.loads(data)
        etype = event or payload.get("type")
        if etype == "message_start":
            msg = payload["message"]
            self._model = msg.get("model")
            self._message_id = msg.get("id")
            self._usage = msg.get("usage") or {}
            self._output_tokens = self._usage.get("output_tokens")
            return [self._turn_start()]
        if etype == "content_block_start":
            block = payload["content_block"]
            acc = self._new_block(block.get("type"), tool_name=block.get("name"),
                                  tool_id=block.get("id"))
            if acc["type"] == "text" and block.get("text"):
                self._append(acc, block["text"])
            elif acc["type"] == "thinking" and block.get("thinking"):
                acc["chars"] += len(block["thinking"])
            self._blocks[payload["index"]] = acc
            return []
        if etype == "content_block_delta":
            acc = self._blocks[payload["index"]]
            delta = payload["delta"]
            dtype = delta.get("type")
            if dtype == "text_delta":
                self._append(acc, delta["text"])
            elif dtype == "input_json_delta":
                self._append(acc, delta["partial_json"])
            elif dtype == "thinking_delta":
                acc["chars"] += len(delta["thinking"])   # chars only, never the text
            # unknown delta types (signature_delta among them) are ignored
            return []
        if etype == "content_block_stop":
            index = payload["index"]
            return self._close_block(index, self._blocks.pop(index))
        if etype == "message_delta":
            delta = payload.get("delta") or {}
            if delta.get("stop_reason") is not None:
                self._stop_reason = delta["stop_reason"]
            usage = payload.get("usage") or {}
            if usage.get("output_tokens") is not None:
                self._output_tokens = usage["output_tokens"]   # cumulative; keep latest
            return []
        if etype == "message_stop":
            self._ended = True
            return [self._rec("turn_end", stop_reason=self._stop_reason,
                              output_tokens=self._output_tokens)]
        if etype == "error":
            # The upstream ended the turn itself; open blocks still hold real content,
            # so they are closed and kept rather than lost with the stream.
            self._ended = True
            self._stop_reason = "error"
            err = payload.get("error") or {}
            out = []
            for index in sorted(self._blocks):
                out.extend(self._close_block(index, self._blocks[index]))
            self._blocks.clear()
            rec = self._rec("turn_end", stop_reason="error",
                            output_tokens=self._output_tokens)
            rec["error"] = {"type": err.get("type"), "message": err.get("message")}
            out.append(rec)
            return out
        return []                        # ping, and event types newer than this decoder

    # --- endings ----------------------------------------------------------------
    def _turn_start(self):
        return self._rec("turn_start", model=self._model, message_id=self._message_id,
                         input_tokens=self._usage.get("input_tokens"),
                         cache_creation_input_tokens=self._usage.get(
                             "cache_creation_input_tokens"),
                         cache_read_input_tokens=self._usage.get(
                             "cache_read_input_tokens"))

    def _finish(self):
        """End of input before the grammar ended the turn: close and mark incomplete."""
        if self._ended:
            return []
        self._ended = True
        out = []
        for index in sorted(self._blocks):
            out.extend(self._close_block(index, self._blocks[index]))
        self._blocks.clear()
        rec = self._rec("turn_end", stop_reason=self._stop_reason,
                        output_tokens=self._output_tokens)
        rec["incomplete"] = True
        out.append(rec)
        return out

    def _finish_json(self):
        """The whole stream=false body at once -> the identical record sequence SSE
        would have produced, through the same block accumulators — so the caps, the
        chars counting and the redaction cannot drift between the two modes."""
        if self._ended:
            return []
        self._ended = True
        msg = json.loads(self._buf.decode("utf-8", "replace"))
        self._model = msg.get("model")
        self._message_id = msg.get("id")
        self._usage = msg.get("usage") or {}
        self._stop_reason = msg.get("stop_reason")
        self._output_tokens = self._usage.get("output_tokens")
        out = [self._turn_start()]
        for index, block in enumerate(msg["content"]):
            acc = self._new_block(block.get("type"), tool_name=block.get("name"),
                                  tool_id=block.get("id"))
            if acc["type"] == "text":
                self._append(acc, block.get("text") or "")
            elif acc["type"] == "tool_use":
                self._append(acc, json.dumps(block.get("input"), ensure_ascii=False,
                                             separators=(",", ":")))
            elif acc["type"] == "thinking":
                acc["chars"] = len(block.get("thinking") or "")
            out.extend(self._close_block(index, acc))
        out.append(self._rec("turn_end", stop_reason=self._stop_reason,
                             output_tokens=self._output_tokens))
        return out


def _capture_write(flow, state, rec):
    """One capture record as a JSON line: the envelope that joins it to the flow's
    audit pair, then the decoder's fields. The timing fields are added here because
    the decoder is pure and has no clock to relate to the request. Wrapped so it can
    never throw into the tap — a capture failure must not touch forwarding."""
    try:
        record = {"ts": _ts(), "kind": rec["kind"], "id": flow.id,
                  "session": state["session"], "host": flow.request.host}
        if state.get("exec") is not None:
            record["exec"] = state["exec"]
        start = getattr(flow.request, "timestamp_start", None)
        if start is not None:
            if rec["kind"] == "turn_start" and state.get("first_chunk_ts") is not None:
                record["ttfb_ms"] = int(round((state["first_chunk_ts"] - start) * 1000))
            elif rec["kind"] == "turn_end":
                record["duration_ms"] = int(round((time.time() - start) * 1000))
        record.update((k, v) for k, v in rec.items() if k != "kind")
        CAPTURE.write(json.dumps(record))
    except Exception as e:
        try:
            logger.info(json.dumps({"decision": "control", "reason":
                                    f"capture record dropped: {e.__class__.__name__}"}))
        except Exception:
            pass


def responseheaders(flow: http.HTTPFlow) -> None:
    # Forward response bytes as they arrive. mitmproxy's default buffers the whole body
    # before sending anything, which starves streaming consumers: an SSE completion that
    # generates longer than the client's ~60s timeout can never be delivered, and the
    # client retries into the same wall. Enforcement is request-side only, so nothing
    # here needs the assembled response body — and failing to stream only costs latency,
    # which is why this is the one hook that swallows its error instead of blocking.
    #
    # For a flow request() allowed, streaming, counting and capture are one act:
    # mitmproxy hands the tap each chunk (and b"" at end of message) and forwards
    # whatever it returns, so nothing here costs buffering. Flows without the marker —
    # this addon's own deny responses, mostly — just stream.
    try:
        state = flow.metadata.get("egress")
        if state is None:
            flow.response.stream = True
            return

        def tap(chunk, _flow=flow, _state=state):
            # Counting, first-chunk timestamping and `return chunk` sit outside the
            # capture try: no capture failure may corrupt forwarding or the audit's
            # byte counts.
            _state["response_bytes"] += len(chunk)
            if _state.get("first_chunk_ts") is None:
                _state["first_chunk_ts"] = time.time()
            decoder = _flow.metadata.get("capture")
            if decoder is not None:
                try:
                    for rec in decoder.feed(chunk):
                        _capture_write(_flow, _state, rec)
                except Exception as e:
                    # The decoder is dead; the flow is not. Pop it so later chunks
                    # skip it, say why once, and keep counting.
                    _flow.metadata.pop("capture", None)
                    _capture_write(_flow, _state, {"kind": "capture_error", "reason":
                                                   f"decoder died: {e.__class__.__name__}"})
            return chunk

        # The stream assignment comes before decoder attachment: a capture setup bug
        # must never leave the response buffered (the SSE-starvation failure this
        # hook exists to prevent) — it may only leave it unobserved.
        flow.response.stream = tap

        try:
            if state.get("capture") and flow.response.status_code == 200:
                encoding = flow.response.headers.get("content-encoding", "identity")
                media = (flow.response.headers.get("content-type") or "")
                media = media.split(";", 1)[0].strip().lower()
                # Streamed chunks arrive still content-encoded, and growing a
                # decompressor here would hand the guest a zip-bomb lever; Anthropic
                # answers identity-encoded, so metadata-only is the honest fallback.
                if encoding.lower() not in ("", "identity"):
                    _capture_write(flow, state, {"kind": "capture_error", "reason":
                                                 f"content-encoding {_clip(encoding)}: "
                                                 "not decoded"})
                elif media == "text/event-stream":
                    flow.metadata["capture"] = _AnthropicCapture("sse")
                elif media == "application/json":
                    flow.metadata["capture"] = _AnthropicCapture("json")
                else:
                    _capture_write(flow, state, {"kind": "capture_error", "reason":
                                                 f"unexpected content-type: {_clip(media)}"})
        except Exception as e:
            _capture_write(flow, state, {"kind": "capture_error", "reason":
                                         f"decoder setup failed: {e.__class__.__name__}"})
    except Exception as e:
        logger.info(json.dumps({"decision": "stream", "reason":
                                f"not streaming: {e.__class__.__name__}"}))


def _conclude(flow, reason=""):
    """The "response" record for a flow request() allowed: what actually moved, and how the
    flow ended. Pops the marker, so whichever of response()/error() runs emits exactly one
    record — and a flow this addon denied, which mitmproxy also routes through response(),
    has no marker and already told its whole story on the deny line.

    Capture teardown happens here too, each step wrapped on its own: a decoder still
    attached means the stream never reached its own end, so its open blocks are flushed
    as an incomplete turn, and whatever it learned (model, tokens, stop_reason) enriches
    this record — but none of that may cost the record itself."""
    state = flow.metadata.pop("egress", None)
    if state is None:
        return
    extras = {}
    if state.get("exec") is not None:
        extras["exec"] = state["exec"]
    decoder = flow.metadata.pop("capture", None)
    if decoder is not None:
        try:
            for rec in decoder.flush():
                _capture_write(flow, state, rec)
        except Exception as e:
            _capture_write(flow, state, {"kind": "capture_error", "reason":
                                         f"flush failed: {e.__class__.__name__}"})
        try:
            extras.update(decoder.summary())
        except Exception:
            pass
    start = getattr(flow.request, "timestamp_start", None)
    if start is not None and state.get("first_chunk_ts") is not None:
        extras["ttfb_ms"] = int(round((state["first_chunk_ts"] - start) * 1000))
    if start is not None:
        end = (getattr(flow.response, "timestamp_end", None)
               or getattr(flow.error, "timestamp", None)
               or time.time())
        duration_ms = int(round((end - start) * 1000))
    else:
        duration_ms = None
    _audit("response", flow, reason, state["session"],
           status=flow.response.status_code if flow.response else None,
           request_bytes=state["request_bytes"],
           response_bytes=state["response_bytes"],
           duration_ms=duration_ms, **extras)


def response(flow: http.HTTPFlow) -> None:
    # Fires once the response has been fully forwarded — for a streamed body, after the
    # last chunk went through the counter — so the byte counts are final here.
    try:
        _conclude(flow)
    except Exception as e:
        logger.info(json.dumps({"decision": "response", "reason":
                                f"unrecorded: {e.__class__.__name__}"}))


def error(flow: http.HTTPFlow) -> None:
    # Fires instead of response() when the flow dies — the upstream unreachable, or the
    # client hanging up mid-stream — so an aborted transfer still gets its record, with the
    # bytes counted up to the break and mitmproxy's description of it as the reason.
    try:
        _conclude(flow, reason=_clip(flow.error.msg) if flow.error else "aborted")
    except Exception as e:
        logger.info(json.dumps({"decision": "response", "reason":
                                f"unrecorded: {e.__class__.__name__}"}))


def http_connect(flow: http.HTTPFlow) -> None:
    """CONNECT: decide the tunnel's authority before the tunnel exists.

    mitmproxy dispatches CONNECT here and nowhere else — `request` never sees one — so without
    this hook every HTTPS authority is tunnelled unevaluated and unlogged. A non-2xx response
    set here is how the tunnel is refused: mitmproxy answers it, skips the upstream connection
    and never switches to passthrough.

    A CONNECT carries an authority and nothing else. Two of a rule's four dimensions do not
    exist yet, so this matches host and port only and leaves path and method to the requests
    decrypted out of the tunnel, which reach `request` with all four. Guessing the missing two
    fails in both directions: a path of "/" would deny the CONNECT under a rule like
    `api.anthropic.com/v1/messages POST` and break every HTTPS request to it, while treating
    the authority as if the rules were path-agnostic would grant tunnels no request-level
    match would allow. Bytes the tunnel then carries are only re-examined because mitmproxy
    parses them; a raw passthrough would escape this hook's decision, which is what
    `--set rawtcp=false` is for.
    """
    session = None
    try:
        flow.response = _blocked(500, _FAILSAFE)  # fail closed before anything can throw
        req = flow.request

        try:
            session, ruleset = REGISTRY.resolve(flow.client_conn.sockname[1])
        except SessionError as e:
            _deny(flow, str(e), session=session)
            return

        host = normalize_host(req.host)
        if host is None:
            _deny(flow, f"invalid host: {_clip(req.host)}", session=session)
            return

        rule = _authority_rule(ruleset, host, req.port)
        if rule is None:
            _deny(flow, "no matching rule", session=session)
            return

        # A CONNECT's Host: header decides nothing — mitmproxy tunnels to the request line's
        # authority and never reads the header — so a disagreement is recorded, not refused.
        claimed = req.host_header
        mismatch = ({"claimed": _clip(claimed)}
                    if claimed and normalize_host(claimed) != host else {})
        _audit("allow", flow, rule.raw, session=session, **mismatch)
        flow.response = None                      # nothing threw — let the tunnel open
    except Exception as e:
        _fail_closed(flow, session, e)


def request(flow: http.HTTPFlow) -> None:
    session = None
    try:
        # 0. Fail closed before any enforcement runs. mitmproxy logs an exception escaping this
        #    hook and then forwards the request unfiltered, so the block has to be in place
        #    from the start: each deny below replaces this response, and the allow path clears
        #    it as its last act, once nothing is left that can throw.
        flow.response = _blocked(500, _FAILSAFE)
        req = flow.request

        # 1. Which ruleset applies: the accepted listener port decides. With sessions that
        #    port is spoof-proof identity (Tier-1 lets a guest reach only its own), and an
        #    unknown port, a missing session, or unparsable rules fail closed rather than
        #    fall through to somebody else's ruleset.
        try:
            session, ruleset = REGISTRY.resolve(flow.client_conn.sockname[1])
        except SessionError as e:
            _deny(flow, str(e), session=session)
            return

        # 2. The destination, normalized (null-byte / homograph / IP guard) the same way the
        #    engine normalizes patterns. req.host and req.port are what mitmproxy will dial:
        #    the URL for an absolute-form request line, otherwise the authority it resolved
        #    the connection from. req.pretty_host must not be used here — it prefers the
        #    client's Host: header, so policy would be decided about one host and the
        #    connection made to another. Rejecting here is also what makes the engine's
        #    IP-literal guard bite: an IP destination can match no pattern anyway.
        host = normalize_host(req.host)
        if host is None:
            _deny(flow, f"invalid host: {_clip(req.host)}", session=session)
            return

        # 3. The claimed authority must agree with the destination — domain fronting, and the
        #    guest naming an allowlisted host while dialling its own. This subsumes the SNI
        #    check, which is only enforceable when the guest speaks TLS to the proxy: a
        #    plaintext absolute-form request has no SNI to compare, and that is the normal
        #    case. Hostnames only: a Host: header legitimately carries or omits the port
        #    ("h" and "h:443" name one destination), and the port that decides policy is
        #    req.port in step 5, the one actually dialled. No Host: header at all is not a
        #    disagreement — the request line named the destination unambiguously.
        claimed = req.host_header
        if claimed and normalize_host(claimed) != host:
            _deny(flow, f"Host/destination mismatch: {_clip(claimed)} != {host}",
                  session=session, claimed=_clip(claimed))
            return
        sni = flow.client_conn.sni
        if sni and normalize_host(sni) != host:
            _deny(flow, f"SNI/destination mismatch: {_clip(sni)} != {host}",
                  session=session, claimed=_clip(sni))
            return

        # 4. Protocol upgrades (WebSocket): deny — a bidirectional tunnel over an allowed host.
        if req.headers.get("upgrade"):
            _deny(flow, "upgrade not allowed", session=session)
            return

        # 5. Allowlist match (host + port + normalized path + method); default-deny.
        rule = ruleset.match(host, req.path, req.method, req.port)
        if rule is None:
            _deny(flow, "no matching rule", session=session)
            return

        # 6. Query params: keep only those the rule allows (deny-by-default per param, like
        #    headers) and STRIP the rest — the request proceeds without them, not a 403.
        #    The audit line carries the dropped names (semantics: _audit's docstring).
        stripped_query = []
        if req.query:
            items = list(req.query.items(multi=True))
            kept, dropped_names = [], set()
            for k, v in items:
                if rule.query_ok(k, v):
                    kept.append((k, v))
                else:
                    dropped_names.add(k)
            if dropped_names:
                req.query = kept
                stripped_query = sorted(dropped_names)

        # 7. Request body capped (default 0 = no body).
        body_len = len(req.raw_content or b"")
        if body_len > rule.max_body:
            _deny(flow, f"body {body_len}B > max_body {rule.max_body}B", code=413,
                  session=session)
            return

        # 8. The exec marker: the CLI stamps X-Silkgate-Exec on requests it issues on a
        #    run's behalf, so capture and audit records can be joined to that run.
        #    Popped here, unconditionally — h:* rules skip the hygiene in step 10, and
        #    an internal id must never reach the destination. Clipped like any other
        #    guest-supplied text; a request without the header simply records no exec.
        exec_id = req.headers.pop("x-silkgate-exec", None)
        if exec_id is not None:
            exec_id = _clip(exec_id)

        # 9. Auth secret: replace the named header's value with the real secret (held on the
        #    host) ONLY if the request already carries that header — the guest signals intent by
        #    sending it. We never force the header onto a request that didn't use it.
        secret_header = None
        injected = None
        inject_skipped = None
        if rule.inject_auth:
            secret = SECRETS.get(session, rule.inject_auth)
            parsed = _parse_secret(secret) if secret is not None else None
            if parsed is None:
                # Deny exactly as an unmatched request is denied, status and body alike: which
                # secrets the host holds is not the guest's to learn. The audit line keeps the
                # real reason, so `silkgate logs --audit` still explains the failure.
                state = "missing" if secret is None else "unusable"
                _deny(flow, f"{state} secret for inject_auth={rule.inject_auth}",
                      session=session, shown="no matching rule")
                return
            hname, hval = parsed
            secret_header = hname.lower()
            if req.headers.get(hname) is not None:        # only override when the header is used
                req.headers[hname] = hval
                injected = rule.inject_auth
            else:
                inject_skipped = rule.inject_auth

        # 10. Header hygiene: unless the rule allows all headers (h:*), drop any header failing the
        #    value constraint (deny-by-default) — keeping the auth header we just replaced.
        stripped_headers = []
        if not rule.allow_all_headers:
            removed = []
            for name in {k for k in req.headers.keys()}:
                if name.lower() == secret_header:
                    continue
                if not rule.header_ok(name, req.headers.get(name)):
                    del req.headers[name]
                    removed.append(name.lower())
            stripped_headers = sorted(removed)

        extras = {}
        if injected is not None:
            extras["injected"] = injected
        if inject_skipped is not None:
            extras["inject_skipped"] = inject_skipped
        if stripped_query:
            extras["stripped_query"] = stripped_query
        if stripped_headers:
            extras["stripped_headers"] = stripped_headers
        if exec_id is not None:
            extras["exec"] = exec_id
        _audit("allow", flow, rule.raw, session=session, **extras)
        # The allow line says what was asked; what actually moved — status and byte counts —
        # is the "response" record _conclude emits, and this marker is what earns one.
        # rule.capture and exec ride along for the tap; first_chunk_ts is stamped there.
        flow.metadata["egress"] = {"session": session, "request_bytes": body_len,
                                   "response_bytes": 0, "capture": rule.capture,
                                   "exec": exec_id, "first_chunk_ts": None}
        flow.response = None                      # nothing threw — let the request through
    except Exception as e:
        _fail_closed(flow, session, e)
