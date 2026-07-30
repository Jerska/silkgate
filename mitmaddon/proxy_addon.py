"""mitmproxy addon — Tier 2 egress enforcement over rule_engine.

Run on the HOST:
    pip install mitmproxy
    export EGRESS_RULES=rules.txt
    export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-..."   # injected; never in the guest
    mitmdump -s proxy_addon.py --listen-port 8090

Tier 1 (forcing all guest traffic here, enforced outside the guest) is microsandbox's own
host-side network policy — see ../THREAT-MODEL.md and README.md. This addon assumes the guest
can only reach this proxy.
"""
import json
import logging
import os

from mitmproxy import http

from rule_engine import RuleSet, normalize_host

logger = logging.getLogger("egress")

_RULES_PATH = os.environ.get("EGRESS_RULES", "rules.txt")
with open(_RULES_PATH) as _fh:
    RULES = RuleSet.parse(_fh.read())


def _secret(name):
    return os.environ.get("EGRESS_SECRET_" + name.upper())


def _audit(decision, flow, reason=""):
    logger.info(json.dumps({
        "decision": decision,
        "method": flow.request.method,
        "host": flow.request.pretty_host,
        "path": flow.request.path,
        "reason": reason,
    }))


def _deny(flow, reason, code=403):
    flow.response = http.Response.make(code, (reason + "\n").encode(),
                                       {"Content-Type": "text/plain"})
    _audit("deny", flow, reason)


def request(flow: http.HTTPFlow) -> None:
    try:
        req = flow.request

        # 1. Host normalization (null-byte / homograph / IP guard) — same path as the engine.
        host = normalize_host(req.pretty_host)
        if host is None:
            _deny(flow, "invalid host")
            return

        # 2. SNI == Host (kills domain fronting). Only enforceable on TLS connections.
        sni = flow.client_conn.sni
        if sni and normalize_host(sni) != host:
            _deny(flow, f"SNI/Host mismatch: {sni} != {req.pretty_host}")
            return

        # 3. Protocol upgrades (WebSocket): deny — a bidirectional tunnel over an allowed host.
        if req.headers.get("upgrade"):
            _deny(flow, "upgrade not allowed")
            return

        # 4. Allowlist match (host + port + normalized path + method); default-deny.
        rule = RULES.match(host, req.path, req.method, req.port)
        if rule is None:
            _deny(flow, "no matching rule")
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
            _deny(flow, f"body {body_len}B > max_body {rule.max_body}B", code=413)
            return

        # 7. Auth secret: replace the named header's value with the real secret (held on the
        #    host) ONLY if the request already carries that header — the guest signals intent by
        #    sending it. We never force the header onto a request that didn't use it.
        secret_header = None
        if rule.inject_auth:
            secret = _secret(rule.inject_auth)
            if secret is None:
                _deny(flow, f"missing secret for inject_auth={rule.inject_auth}", code=500)
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

        _audit("allow", flow, rule.raw)
    except Exception as e:  # fail-closed: never forward on an enforcement error
        _deny(flow, f"internal error: {e.__class__.__name__}", code=500)
