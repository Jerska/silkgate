"""mitmproxy addon — Tier 2 egress enforcement over rule_engine.

Every request is resolved the same way: the listener port it arrived on picks a ruleset.
Which registry answers that question is the only difference between the two ways to run:

    export EGRESS_RULES=/path/to/rules.txt                   # colon-separate to combine files
    export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-..."   # injected; never in the guest
    mitmdump -s mitmaddon/proxy_addon.py --listen-port 8090
        one ruleset, every port — for guests silkgate doesn't manage

    export EGRESS_SESSIONS_DIR=~/.silkgate/sessions          # <name>/meta.json + <name>/rules.txt
    export EGRESS_CONTROL_SOCK=~/.silkgate/proxy.sock        # unix control socket (secrets)
    mitmdump -s mitmaddon/proxy_addon.py --mode regular@8090 --mode regular@8091 ...
        one proxy serving many sessions, each on its own port

Exactly one of EGRESS_RULES / EGRESS_SESSIONS_DIR must be set (die at load otherwise).

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
from datetime import datetime

from mitmproxy import ctx, exceptions, http

from rule_engine import RuleSet, normalize_host

logger = logging.getLogger("egress")

# --- configuration: exactly one of EGRESS_RULES / EGRESS_SESSIONS_DIR ---------
_RULES_PATH = os.environ.get("EGRESS_RULES")
_SESSIONS_DIR = os.environ.get("EGRESS_SESSIONS_DIR")
_CONTROL_SOCK = os.environ.get("EGRESS_CONTROL_SOCK")
if bool(_RULES_PATH) == bool(_SESSIONS_DIR):
    raise RuntimeError("set exactly one of EGRESS_RULES (one ruleset, colon-separated rule "
                       "files) or EGRESS_SESSIONS_DIR (a session per listener port)")


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
# A secret names the header whose value it replaces, so that name has to be a real header name
# (RFC 9110 token) and never one that decides where the request goes or how it is framed:
# rewriting Host would front another vhost behind an allowlisted destination — defeating the
# destination agreement `request` enforces — and rewriting the framing headers is smuggling.
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_SECRET_NAME = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}")
_ROUTING_HEADERS = frozenset({"host", "content-length", "transfer-encoding",
                              "connection", "upgrade"})
_MAX_SECRET = 4096


def _parse_secret(value):
    """Split a "<Header>: <value>" secret into (header, value), or None if it is unusable.

    Rejected: a header name outside the token charset or naming a routing/framing header, a
    value that is empty or carries anything but printable ASCII (a CR/LF would inject a header
    of the guest's choosing into the upstream request), and anything over _MAX_SECRET.
    """
    if not isinstance(value, str) or not value or len(value) > _MAX_SECRET:
        return None
    name, sep, val = value.partition(":")
    if not sep:
        return None
    name, val = name.strip(), val.strip()
    if not _HEADER_TOKEN.fullmatch(name) or name.lower() in _ROUTING_HEADERS:
        return None
    if not val or not all(0x20 <= ord(c) <= 0x7e for c in val):
        return None
    return name, val


class SecretStore:
    """Named secrets ("<Header>: <value>") for inject_auth, scoped by session.

    A scope is a session name, or None for the standalone single-ruleset proxy. A session's
    secrets arrive over the control socket, already naming their scope, from the `up` that
    provisioned it — so a session spends only the credentials its own creator could show.
    EGRESS_SECRET_* env vars are read for the None scope only: the process environment is
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
            return os.environ.get("EGRESS_SECRET_" + name.upper())
        return None

    def set(self, session, name, value):
        self._store.setdefault(session, {})[name.lower()] = value

    def names(self, session):
        env = ({k[len("EGRESS_SECRET_"):].lower()
                for k in os.environ if k.startswith("EGRESS_SECRET_")}
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
    """Resolve a listener port to (session name, RuleSet) from EGRESS_SESSIONS_DIR.

    Layout: <dir>/<name>/meta.json (carries "port") and <dir>/<name>/rules.txt (the composed
    ruleset snapshot). The proxy is long-lived and looks up per request, so both layers are
    cached and re-read only when an mtime moves: the sessions-dir mtime for add/remove, each
    session's rules.txt mtime for content changes. Any ambiguity fails closed (raises).
    """

    def __init__(self, sessions_dir):
        self._dir = sessions_dir
        self._dir_mtime = None
        self._ports = {}                         # port -> name
        self._rules = {}                         # name -> (rules_mtime, RuleSet|None, reason|None)

    def _refresh_ports(self):
        # Re-scan meta.json only when the sessions dir mtime changes (session add/remove).
        try:
            mtime = os.stat(self._dir).st_mtime
        except OSError:
            self._ports, self._dir_mtime = {}, None
            return
        if mtime == self._dir_mtime:
            return
        ports = {}
        try:
            names = os.listdir(self._dir)
        except OSError:
            names = []
        for name in names:
            if name.startswith("."):             # CLI staging dirs are not sessions
                continue
            try:                                 # skip half-written / malformed sessions
                with open(os.path.join(self._dir, name, "meta.json")) as fh:
                    port = int(json.load(fh)["port"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
            ports[port] = name
        self._ports, self._dir_mtime = ports, mtime
        # A session that a successful scan no longer shows is down for good, and the pool
        # recycles both its name and its port — so its secrets go with it, or the next
        # session called the same thing starts life holding the dead one's credentials.
        SECRETS.prune(set(ports.values()))

    def _ruleset(self, name):
        # Parse (and cache) a session's rules.txt; invalidate on its own mtime.
        path = os.path.join(self._dir, name, "rules.txt")
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            raise SessionError("no session for port")     # snapshot vanished under us
        cached = self._rules.get(name)
        if cached and cached[0] == mtime:
            if cached[1] is None:
                raise SessionError(cached[2])
            return cached[1]
        try:
            with open(path) as fh:
                ruleset = RuleSet.parse(fh.read())
        except (OSError, ValueError) as e:                 # cache the failure by mtime too
            reason = f"rules parse error: {e}"
            self._rules[name] = (mtime, None, reason)
            raise SessionError(reason)
        self._rules[name] = (mtime, ruleset, None)
        return ruleset

    def resolve(self, port):
        """Return (name, RuleSet) for a listener port, or raise SessionError (fail closed)."""
        self._refresh_ports()
        name = self._ports.get(port)
        if name is None:
            self._dir_mtime = None               # a miss may be a scan that raced a session's
            self._refresh_ports()                # appearance — rescan once before denying
            name = self._ports.get(port)
        if name is None:
            raise SessionError("no session for port")
        return name, self._ruleset(name)

    def has_session(self, name):
        """Whether `name` is a live session — the same rescan-once as resolve, because the
        usual caller is a set_secret racing the session's first appearance."""
        self._refresh_ports()
        if name not in self._ports.values():
            self._dir_mtime = None
            self._refresh_ports()
        return name in self._ports.values()


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
    """
    logger.info(json.dumps({
        "ts": _ts(),
        "decision": decision,
        "id": flow.id,
        "method": flow.request.method,
        "host": flow.request.host,
        "port": flow.request.port,
        "path": flow.request.path,
        "reason": reason,
        "session": session,
        **extra,
    }))


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


def responseheaders(flow: http.HTTPFlow) -> None:
    # Forward response bytes as they arrive. mitmproxy's default buffers the whole body
    # before sending anything, which starves streaming consumers: an SSE completion that
    # generates longer than the client's ~60s timeout can never be delivered, and the
    # client retries into the same wall. Enforcement is request-side only, so nothing
    # here needs the assembled response body — and failing to stream only costs latency,
    # which is why this is the one hook that swallows its error instead of blocking.
    #
    # For a flow request() allowed, streaming and counting are one act: mitmproxy hands a
    # callable each chunk (and b"" at end of message) and forwards whatever it returns, so
    # the count costs no buffering. Flows without the marker — this addon's own deny
    # responses, mostly — just stream.
    try:
        state = flow.metadata.get("egress")
        if state is None:
            flow.response.stream = True
            return

        def count(chunk, _state=state):
            _state["response_bytes"] += len(chunk)
            return chunk

        flow.response.stream = count
    except Exception as e:
        logger.info(json.dumps({"decision": "stream", "reason":
                                f"not streaming: {e.__class__.__name__}"}))


def _conclude(flow, reason=""):
    """The "response" record for a flow request() allowed: what actually moved, and how the
    flow ended. Pops the marker, so whichever of response()/error() runs emits exactly one
    record — and a flow this addon denied, which mitmproxy also routes through response(),
    has no marker and already told its whole story on the deny line."""
    state = flow.metadata.pop("egress", None)
    if state is None:
        return
    _audit("response", flow, reason, state["session"],
           status=flow.response.status_code if flow.response else None,
           request_bytes=state["request_bytes"],
           response_bytes=state["response_bytes"])


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
        if req.query:
            items = list(req.query.items(multi=True))
            kept = [(k, v) for (k, v) in items if rule.query_ok(k, v)]
            if len(kept) != len(items):
                req.query = kept

        # 7. Request body capped (default 0 = no body).
        body_len = len(req.raw_content or b"")
        if body_len > rule.max_body:
            _deny(flow, f"body {body_len}B > max_body {rule.max_body}B", code=413,
                  session=session)
            return

        # 8. Auth secret: replace the named header's value with the real secret (held on the
        #    host) ONLY if the request already carries that header — the guest signals intent by
        #    sending it. We never force the header onto a request that didn't use it.
        secret_header = None
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

        # 9. Header hygiene: unless the rule allows all headers (h:*), drop any header failing the
        #    value constraint (deny-by-default) — keeping the auth header we just replaced.
        if not rule.allow_all_headers:
            for name in {k for k in req.headers.keys()}:
                if name.lower() == secret_header:
                    continue
                if not rule.header_ok(name, req.headers.get(name)):
                    del req.headers[name]

        _audit("allow", flow, rule.raw, session=session)
        # The allow line says what was asked; what actually moved — status and byte counts —
        # is the "response" record _conclude emits, and this marker is what earns one.
        flow.metadata["egress"] = {"session": session, "request_bytes": body_len,
                                   "response_bytes": 0}
        flow.response = None                      # nothing threw — let the request through
    except Exception as e:
        _fail_closed(flow, session, e)
