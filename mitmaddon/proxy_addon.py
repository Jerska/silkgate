"""mitmproxy addon — Tier 2 egress enforcement over rule_engine.

Single-tenant (one shared ruleset, one listener):
    pip install mitmproxy
    export EGRESS_RULES=mitmaddon/presets/claude.txt         # colon-separate to combine presets
    export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-..."   # injected; never in the guest
    mitmdump -s mitmaddon/proxy_addon.py --listen-port 8090

Multi-session (one shared proxy serves every session; identity == listener port):
    export EGRESS_SESSIONS_DIR=~/.silkgate/sessions          # <name>/meta.json + <name>/rules.txt
    export EGRESS_CONTROL_SOCK=~/.silkgate/proxy.sock        # unix control socket (secrets)
    mitmdump -s mitmaddon/proxy_addon.py --mode regular@8090 --mode regular@8091 ...
Exactly one of EGRESS_RULES / EGRESS_SESSIONS_DIR must be set (die at load otherwise).

Tier 1 (forcing all guest traffic here, enforced outside the guest) is microsandbox's own
host-side network policy — see ../doc/THREAT-MODEL.md and ../README.md. This addon assumes the
guest can only reach this proxy, and — in multi-session mode — only its own listener port, so
the accepted port is spoof-proof session identity.
"""
import asyncio
import json
import logging
import os

from mitmproxy import http

from rule_engine import RuleSet, normalize_host

logger = logging.getLogger("egress")

# --- mode selection: exactly one of EGRESS_RULES / EGRESS_SESSIONS_DIR --------
_RULES_PATH = os.environ.get("EGRESS_RULES")
_SESSIONS_DIR = os.environ.get("EGRESS_SESSIONS_DIR")
_CONTROL_SOCK = os.environ.get("EGRESS_CONTROL_SOCK")
if bool(_RULES_PATH) == bool(_SESSIONS_DIR):
    raise RuntimeError("set exactly one of EGRESS_RULES (single-tenant, colon-separated rule "
                       "files) or EGRESS_SESSIONS_DIR (multi-session registry)")
_MULTI = _SESSIONS_DIR is not None

# Single-tenant: one ruleset for the life of the process (the DSL is line-based, so files are
# concatenated). Multi-session builds rulesets per-port via the registry below.
RULES = None
if not _MULTI:
    _texts = []
    for _p in _RULES_PATH.split(":"):
        with open(_p) as _fh:
            _texts.append(_fh.read())
    RULES = RuleSet.parse("\n".join(_texts))


# --- secret store: in-memory (set over the control socket) layered over env ---
class SecretStore:
    """Named secrets ("<Header>: <value>") for inject_auth, socket-set over EGRESS_SECRET_* env.

    The socket store wins on the same name. Values never leave this object: they are not
    logged, not returned by list, not echoed by any control op — only spent by injection.
    """

    def __init__(self):
        self._store = {}                         # lower-name -> "Header: value"

    def get(self, name):
        key = name.lower()
        if key in self._store:
            return self._store[key]
        return os.environ.get("EGRESS_SECRET_" + name.upper())

    def set(self, name, value):
        self._store[name.lower()] = value

    def names(self):
        env = {k[len("EGRESS_SECRET_"):].lower()
               for k in os.environ if k.startswith("EGRESS_SECRET_")}
        return sorted(env | set(self._store))


SECRETS = SecretStore()


def _secret(name):
    return SECRETS.get(name)


# --- multi-session registry: port -> RuleSet, cached, mtime-invalidated -------
class SessionError(Exception):
    """Fail-closed session-resolution failure; the message is the audit deny reason."""


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
            try:                                 # skip half-written / malformed sessions
                with open(os.path.join(self._dir, name, "meta.json")) as fh:
                    port = int(json.load(fh)["port"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
            ports[port] = name
        self._ports, self._dir_mtime = ports, mtime

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
            raise SessionError("no session for port")
        return name, self._ruleset(name)


REGISTRY = SessionRegistry(_SESSIONS_DIR) if _MULTI else None


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
        name, value = req.get("name"), req.get("value")
        if not isinstance(name, str) or not name:
            return {"ok": False, "error": "missing name"}
        if not isinstance(value, str) or ":" not in value:
            return {"ok": False, "error": "value must be '<Header>: <value>'"}
        SECRETS.set(name, value)
        return {"ok": True}
    if op == "list_secrets":
        return {"ok": True, "names": SECRETS.names()}
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


async def _control_server(path):
    server = await asyncio.start_unix_server(_control_client, path=path)
    os.chmod(path, 0o600)                          # host-only socket; no secrets to the world
    logger.info(json.dumps({"decision": "control", "reason": f"listening on {path}"}))
    async with server:
        await server.serve_forever()


def running():
    """mitmproxy lifecycle hook — start the control socket once the loop is up."""
    if not _CONTROL_SOCK:
        return
    try:
        os.unlink(_CONTROL_SOCK)                   # unlink a stale socket before binding
    except FileNotFoundError:
        pass
    asyncio.ensure_future(_control_server(_CONTROL_SOCK))


# --- request enforcement -----------------------------------------------------
def _audit(decision, flow, reason="", session=None):
    rec = {
        "decision": decision,
        "method": flow.request.method,
        "host": flow.request.pretty_host,
        "path": flow.request.path,
        "reason": reason,
    }
    if _MULTI:
        rec["session"] = session
    logger.info(json.dumps(rec))


def _deny(flow, reason, code=403, session=None):
    flow.response = http.Response.make(code, (reason + "\n").encode(),
                                       {"Content-Type": "text/plain"})
    _audit("deny", flow, reason, session)


def responseheaders(flow: http.HTTPFlow) -> None:
    # Forward response bytes as they arrive. mitmproxy's default buffers the whole body
    # before sending anything, which starves streaming consumers: an SSE completion that
    # generates longer than the client's ~60s timeout can never be delivered, and the
    # client retries into the same wall. Enforcement is request-side only, so nothing
    # here needs the assembled response body.
    flow.response.stream = True


def request(flow: http.HTTPFlow) -> None:
    session = None
    try:
        req = flow.request

        # 0. Session resolution (multi-session mode): the accepted listener port is spoof-proof
        #    identity (Tier-1 lets a guest reach only its own port). Unknown port / missing
        #    session / unparsable rules fail closed — never fall through to another's ruleset.
        if _MULTI:
            try:
                session, ruleset = REGISTRY.resolve(flow.client_conn.sockname[1])
            except SessionError as e:
                _deny(flow, str(e), session=session)
                return
        else:
            ruleset = RULES

        # 1. Host normalization (null-byte / homograph / IP guard) — same path as the engine.
        host = normalize_host(req.pretty_host)
        if host is None:
            _deny(flow, "invalid host", session=session)
            return

        # 2. SNI == Host (kills domain fronting). Only enforceable on TLS connections.
        sni = flow.client_conn.sni
        if sni and normalize_host(sni) != host:
            _deny(flow, f"SNI/Host mismatch: {sni} != {req.pretty_host}", session=session)
            return

        # 3. Protocol upgrades (WebSocket): deny — a bidirectional tunnel over an allowed host.
        if req.headers.get("upgrade"):
            _deny(flow, "upgrade not allowed", session=session)
            return

        # 4. Allowlist match (host + port + normalized path + method); default-deny.
        rule = ruleset.match(host, req.path, req.method, req.port)
        if rule is None:
            _deny(flow, "no matching rule", session=session)
            return

        # 5. Query params: keep only those the rule allows (deny-by-default per param, like
        #    headers) and STRIP the rest — the request proceeds without them, not a 403.
        if req.query:
            items = list(req.query.items(multi=True))
            kept = [(k, v) for (k, v) in items if rule.query_ok(k, v)]
            if len(kept) != len(items):
                req.query = kept

        # 6. Request body capped (default 0 = no body).
        body_len = len(req.raw_content or b"")
        if body_len > rule.max_body:
            _deny(flow, f"body {body_len}B > max_body {rule.max_body}B", code=413,
                  session=session)
            return

        # 7. Auth secret: replace the named header's value with the real secret (held on the
        #    host) ONLY if the request already carries that header — the guest signals intent by
        #    sending it. We never force the header onto a request that didn't use it.
        secret_header = None
        if rule.inject_auth:
            secret = _secret(rule.inject_auth)
            if secret is None:
                _deny(flow, f"missing secret for inject_auth={rule.inject_auth}", code=500,
                      session=session)
                return
            hname, _, hval = secret.partition(":")
            hname, secret_header = hname.strip(), hname.strip().lower()
            if req.headers.get(hname) is not None:        # only override when the header is used
                req.headers[hname] = hval.strip()

        # 8. Header hygiene: unless the rule allows all headers (h:*), drop any header failing the
        #    value constraint (deny-by-default) — keeping the auth header we just replaced.
        if not rule.allow_all_headers:
            for name in {k for k in req.headers.keys()}:
                if name.lower() == secret_header:
                    continue
                if not rule.header_ok(name, req.headers.get(name)):
                    del req.headers[name]

        _audit("allow", flow, rule.raw, session=session)
    except Exception as e:  # fail-closed: never forward on an enforcement error
        _deny(flow, f"internal error: {e.__class__.__name__}", code=500, session=session)
