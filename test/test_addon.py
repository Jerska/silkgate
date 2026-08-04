#!/usr/bin/env python3
"""Enforcement tests for mitmaddon/proxy_addon.py — in-process, no network, no proxy.

    python3 test/test_addon.py

Needs mitmproxy importable (the addon imports it); nothing else, and nothing listens.

Grown from test/repro/addon_host_spoof.py, which found finding 1: policy was decided from
`flow.request.pretty_host` — the client's `Host:` header — while mitmproxy connects to
`flow.request.host`, so a guest could name an allowlisted host in a header and have the
request, and the host-held credential, delivered anywhere it liked. Nothing in this file had
ever been executed by a test, which is why that survived.

Every case asserts on the audit record as well as on the response, because the same bug made
the audit trail forgeable: a line naming a host the request never reached is worse than no
line. The record must stay one JSON object per line and must keep `session`, which is what
`silkgate logs --audit` filters on.
"""
import asyncio
import json
import logging
import os
import pathlib
import socket
import sys
import tempfile
import unittest

SENTINEL_VALUE = "SENTINEL-NOT-A-REAL-KEY"
REPO = pathlib.Path(__file__).resolve().parents[1]

# One ruleset covering every dimension under test: a credential-injecting rule with query and
# body limits and no `h:*` (so header hygiene is live), a plain GET rule, an `h:*` rule, a
# port-scoped rule, and two rules whose secret is unusable or absent.
RULES = """\
api.anthropic.com/v1/** GET POST q:beta=true max_body=1k inject_auth=anthropic
registry.npmjs.org/** GET
files.pythonhosted.org/** GET h:*
internal.example:8080/** GET
pypi.org/** GET inject_auth=badhost
example.test/** GET inject_auth=absent
"""

_rules_file = pathlib.Path(tempfile.mkdtemp()) / "rules.txt"
_rules_file.write_text(RULES)
os.environ["EGRESS_RULES"] = str(_rules_file)
os.environ["EGRESS_SECRET_ANTHROPIC"] = f"x-api-key: {SENTINEL_VALUE}"
os.environ["EGRESS_SECRET_BADHOST"] = "Host: evil.example"     # must never be honoured
os.environ.pop("EGRESS_SESSIONS_DIR", None)
os.environ.pop("EGRESS_CONTROL_SOCK", None)

sys.path.insert(0, str(REPO / "mitmaddon"))
import proxy_addon                                             # noqa: E402
from mitmproxy.test import tflow, tutils                       # noqa: E402

LISTEN_PORT = 8090


class AuditCapture(logging.Handler):
    """Collect the addon's log lines verbatim, so a malformed one fails a test loudly."""

    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())

    def records(self):
        return [json.loads(line) for line in self.lines]


class AddonCase(unittest.TestCase):
    """Drive one hook against one synthetic flow and assert on both of its outputs."""

    def setUp(self):
        self.audit = AuditCapture()
        self.logger = logging.getLogger("egress")
        self.logger.addHandler(self.audit)
        self.logger.setLevel(logging.INFO)
        self.addCleanup(self.logger.removeHandler, self.audit)

    # --- building flows ------------------------------------------------------
    def flow(self, *, host, port=443, method="GET", path="/v1/messages", claimed=None,
             sni=None, body=b"", headers=(), connect=False):
        """A flow as the addon sees it.

        `host`/`port` are the destination mitmproxy will dial; `claimed` is the `Host:` header.
        The two are independent here for the same reason they are independent in the wild: for
        an absolute-form request line the destination comes from the URL and the header is just
        a claim. In a CONNECT tunnel, or for an origin-form request line, mitmproxy derives the
        destination from that header instead — pass the same value for both to model those.
        """
        fields = list(headers)
        if claimed is not None:
            fields.insert(0, (b"Host", claimed if isinstance(claimed, bytes)
                              else claimed.encode()))
        if connect:
            req = tutils.treq(host=host, port=port, method=b"CONNECT", scheme=b"",
                              authority=f"{host}:{port}".encode(), path=b"",
                              headers=tuple(fields), content=b"")
        else:
            req = tutils.treq(host=host, port=port, method=method.encode(),
                              path=path.encode(), headers=tuple(fields), content=body)
        f = tflow.tflow(req=req)
        f.client_conn.sockname = ("127.0.0.1", LISTEN_PORT)
        f.client_conn.sni = sni                    # None = the guest spoke plaintext to us
        return f

    def run_request(self, **kw):
        f = self.flow(**kw)
        proxy_addon.request(f)
        return f

    def run_connect(self, **kw):
        f = self.flow(connect=True, **kw)
        proxy_addon.http_connect(f)
        return f

    # --- assertions ----------------------------------------------------------
    def record(self):
        """The single audit record the hook emitted."""
        records = self.audit.records()
        self.assertEqual(len(records), 1, f"expected one audit line, got {self.audit.lines}")
        rec = records[0]
        self.assertIn("session", rec, "silkgate logs --audit filters on 'session'")
        return rec

    def assertAllowed(self, flow, *, host, port=443):
        """No response set means mitmproxy forwards — and dials exactly what we audited."""
        self.assertIsNone(flow.response, f"expected allow, got {self.body(flow)!r}")
        rec = self.record()
        self.assertEqual(rec["decision"], "allow")
        self.assertEqual((rec["host"], rec["port"]), (host, port))
        return rec

    def assertDenied(self, flow, *, code=403, host=None, port=None, reason=None):
        self.assertIsNotNone(flow.response, "expected a deny, the request was forwarded")
        self.assertEqual(flow.response.status_code, code)
        rec = self.record()
        self.assertEqual(rec["decision"], "deny")
        if host is not None:
            self.assertEqual(rec["host"], host, "the audit must name the host actually dialled")
        if port is not None:
            self.assertEqual(rec["port"], port)
        if reason is not None:
            self.assertIn(reason, rec["reason"])
        return rec

    def assertNoSecret(self, flow):
        """The sentinel must not have reached the request in any form."""
        for name, value in flow.request.headers.items():
            self.assertNotIn(SENTINEL_VALUE, value, f"secret leaked into {name}")
        self.assertNotIn(SENTINEL_VALUE.encode(), flow.request.raw_content or b"")

    @staticmethod
    def body(flow):
        if flow.response is None:
            return None
        return flow.response.content.decode("ascii", "replace").strip()


# --- the four cases from the reproduction ------------------------------------
class HostSpoof(AddonCase):

    def test_honest_allow(self):
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com",
                             method="POST", body=b"prompt",
                             headers=[(b"x-api-key", b"guest-dummy")])
        rec = self.assertAllowed(f, host="api.anthropic.com")
        self.assertTrue(rec["reason"].startswith("api.anthropic.com/v1/**"))
        self.assertEqual(f.request.headers["x-api-key"], SENTINEL_VALUE)

    def test_honest_deny(self):
        f = self.run_request(host="evil.example", port=80, claimed="evil.example")
        self.assertDenied(f, host="evil.example", port=80, reason="no matching rule")

    def test_spoofed_host_header_is_denied(self):
        f = self.run_request(host="evil.example", port=80, claimed="registry.npmjs.org")
        rec = self.assertDenied(f, host="evil.example", port=80,
                                reason="Host/destination mismatch")
        self.assertEqual(rec["claimed"], "registry.npmjs.org")

    def test_spoof_against_injecting_rule_carries_no_secret(self):
        f = self.run_request(host="evil.example", port=80, method="POST", body=b"exfil",
                             claimed="api.anthropic.com",
                             headers=[(b"x-api-key", b"guest-dummy")])
        self.assertDenied(f, host="evil.example", port=80,
                          reason="Host/destination mismatch")
        self.assertEqual(f.request.headers["x-api-key"], "guest-dummy")
        self.assertNoSecret(f)

    def test_sni_mismatch_is_denied(self):
        """Case 5 of the reproduction: the one spoof the old code did catch."""
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com",
                            sni="evil.example")
        rec = self.assertDenied(f, host="api.anthropic.com",
                                reason="SNI/destination mismatch")
        self.assertEqual(rec["claimed"], "evil.example")


# --- where a naive Host-agreement check goes wrong ---------------------------
class ClaimedAuthority(AddonCase):

    def test_no_host_header_is_not_a_disagreement(self):
        """An absolute-form request line names its destination; there is nothing to disagree."""
        f = self.run_request(host="registry.npmjs.org", path="/lodash")
        rec = self.assertAllowed(f, host="registry.npmjs.org")
        self.assertNotIn("claimed", rec)

    def test_no_host_header_still_needs_a_rule(self):
        f = self.run_request(host="evil.example", port=80, path="/")
        self.assertDenied(f, host="evil.example", reason="no matching rule")

    def test_claimed_port_is_ignored(self):
        """"h" and "h:443" name one destination; the port that decides policy is the dialled one."""
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com:443")
        self.assertAllowed(f, host="api.anthropic.com")

    def test_destination_port_without_a_claimed_port(self):
        f = self.run_request(host="api.anthropic.com", port=80, claimed="api.anthropic.com")
        self.assertAllowed(f, host="api.anthropic.com", port=80)

    def test_claimed_case_and_trailing_dot_agree(self):
        for claimed in ("API.Anthropic.COM", "api.anthropic.com.", "API.ANTHROPIC.COM.:443"):
            with self.subTest(claimed=claimed):
                self.audit.lines.clear()
                f = self.run_request(host="api.anthropic.com", claimed=claimed)
                self.assertAllowed(f, host="api.anthropic.com")

    def test_ip_literal_destination_is_denied(self):
        """The engine's IP-literal guard only bites now that it sees the real destination."""
        f = self.run_request(host="127.0.0.1", port=80, claimed="api.anthropic.com")
        self.assertDenied(f, host="127.0.0.1", port=80, reason="invalid host")

    def test_ip_literal_destination_with_matching_claim_is_denied(self):
        f = self.run_request(host="127.0.0.1", port=80, claimed="127.0.0.1")
        self.assertDenied(f, host="127.0.0.1", reason="invalid host")

    def test_ip_literal_claim_against_a_named_destination_is_denied(self):
        f = self.run_request(host="api.anthropic.com", claimed="1.2.3.4")
        self.assertDenied(f, host="api.anthropic.com", reason="Host/destination mismatch")

    def test_unparsable_claimed_authority_is_denied(self):
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com:notaport")
        self.assertDenied(f, host="api.anthropic.com", reason="Host/destination mismatch")

    def test_undecodable_claimed_authority_does_not_crash_the_deny(self):
        """A header value reaches us surrogate-escaped; encoding one raw would throw in _deny,
        and an exception escaping the hook forwards the request unfiltered."""
        f = self.run_request(host="api.anthropic.com", claimed=b"ev\xffil.example")
        self.assertDenied(f, host="api.anthropic.com", reason="Host/destination mismatch")
        self.assertIn("claimed", self.record())        # the line still parsed as JSON

    def test_port_takes_part_in_the_match(self):
        cases = [("internal.example", 8080, True), ("internal.example", 443, False),
                 ("registry.npmjs.org", 8443, False), ("registry.npmjs.org", 80, True)]
        for host, port, allowed in cases:
            with self.subTest(host=host, port=port):
                self.audit.lines.clear()
                f = self.run_request(host=host, port=port, claimed=host, path="/x")
                if allowed:
                    self.assertAllowed(f, host=host, port=port)
                else:
                    self.assertDenied(f, host=host, port=port, reason="no matching rule")


# --- flows that came through a CONNECT ---------------------------------------
class Tunnelled(AddonCase):
    """After a CONNECT, mitmproxy derives an origin-form request's destination from its `Host:`
    header, so the two agree by construction and the SNI from the tunnel's TLS is what pins the
    request to the authority the tunnel was opened for."""

    def test_ordinary_https_is_untouched(self):
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com",
                             sni="api.anthropic.com", method="POST", body=b"prompt",
                             headers=[(b"x-api-key", b"guest-dummy")])
        self.assertAllowed(f, host="api.anthropic.com")
        self.assertEqual(f.request.headers["x-api-key"], SENTINEL_VALUE)

    def test_hopping_to_another_host_inside_the_tunnel_is_denied(self):
        """A second, allowlisted authority in the inner `Host:` retargets the connection —
        mitmproxy dials it — but the tunnel's SNI still names the first one."""
        f = self.run_request(host="registry.npmjs.org", claimed="registry.npmjs.org",
                             sni="api.anthropic.com", path="/lodash")
        self.assertDenied(f, host="registry.npmjs.org", reason="SNI/destination mismatch")

    def test_absolute_form_inside_the_tunnel_is_denied(self):
        f = self.run_request(host="evil.example", port=80, claimed="api.anthropic.com",
                             sni="api.anthropic.com")
        self.assertDenied(f, host="evil.example", reason="Host/destination mismatch")


class Connect(AddonCase):

    def test_path_scoped_rule_still_permits_the_tunnel(self):
        """The strict direction of the CONNECT decision: `api.anthropic.com/v1/**` carries a
        path a CONNECT does not have, and guessing one would break every HTTPS request."""
        f = self.run_connect(host="api.anthropic.com", claimed="api.anthropic.com:443")
        rec = self.assertAllowed(f, host="api.anthropic.com")
        self.assertEqual(rec["method"], "CONNECT")
        self.assertTrue(rec["reason"].startswith("api.anthropic.com/v1/**"))

    def test_unlisted_authority_is_denied_and_logged(self):
        """Finding 2: this used to be answered `200 Connection established`, unaudited."""
        f = self.run_connect(host="evil.example", port=443, claimed="evil.example:443")
        self.assertDenied(f, host="evil.example", port=443, reason="no matching rule")

    def test_port_is_matched(self):
        allowed = self.run_connect(host="internal.example", port=8080)
        self.assertAllowed(allowed, host="internal.example", port=8080)
        self.audit.lines.clear()
        denied = self.run_connect(host="internal.example", port=443)
        self.assertDenied(denied, host="internal.example", port=443, reason="no matching rule")

    def test_non_default_port_on_an_allowed_host_is_denied(self):
        f = self.run_connect(host="registry.npmjs.org", port=8443)
        self.assertDenied(f, host="registry.npmjs.org", port=8443, reason="no matching rule")

    def test_ip_literal_authority_is_denied(self):
        f = self.run_connect(host="127.0.0.1", port=9099)
        self.assertDenied(f, host="127.0.0.1", port=9099, reason="invalid host")

    def test_disagreeing_host_header_is_recorded_not_refused(self):
        """mitmproxy tunnels to the request line's authority and never reads the header."""
        f = self.run_connect(host="api.anthropic.com", claimed="evil.example")
        rec = self.assertAllowed(f, host="api.anthropic.com")
        self.assertEqual(rec["claimed"], "evil.example")


# --- the rest of the enforcement path ---------------------------------------
class Enforcement(AddonCase):

    def test_oversized_body_is_rejected(self):
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com",
                             method="POST", body=b"x" * 2000)
        self.assertDenied(f, code=413, host="api.anthropic.com", reason="max_body")

    def test_body_at_the_cap_is_allowed(self):
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com",
                             method="POST", body=b"x" * 1024)
        self.assertAllowed(f, host="api.anthropic.com")

    def test_disallowed_headers_are_stripped(self):
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com",
                             method="POST", body=b"prompt",
                             headers=[(b"content-type", b"application/json"),
                                      (b"x-exfil", b"stolen"),
                                      (b"user-agent", b"curl/8"),
                                      (b"x-api-key", b"guest-dummy")])
        self.assertAllowed(f, host="api.anthropic.com")
        self.assertEqual(f.request.headers["content-type"], "application/json")
        self.assertEqual(f.request.headers["Host"], "api.anthropic.com")
        self.assertEqual(f.request.headers["x-api-key"], SENTINEL_VALUE)
        self.assertNotIn("x-exfil", f.request.headers)
        self.assertNotIn("user-agent", f.request.headers)

    def test_allow_all_headers_rule_keeps_them(self):
        f = self.run_request(host="files.pythonhosted.org", claimed="files.pythonhosted.org",
                             path="/packages/x.whl", headers=[(b"x-exfil", b"stolen")])
        self.assertAllowed(f, host="files.pythonhosted.org")
        self.assertEqual(f.request.headers["x-exfil"], "stolen")

    def test_disallowed_query_params_are_stripped(self):
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com",
                             path="/v1/messages?beta=true&evil=data&beta=false")
        self.assertAllowed(f, host="api.anthropic.com")
        self.assertEqual(list(f.request.query.items(multi=True)), [("beta", "true")])

    def test_upgrade_is_denied(self):
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com",
                             headers=[(b"upgrade", b"websocket")])
        self.assertDenied(f, host="api.anthropic.com", reason="upgrade not allowed")

    def test_session_name_reaches_the_audit_record(self):
        """`silkgate logs --audit` keeps only lines whose session field is the session's name."""
        _, ruleset = proxy_addon.REGISTRY.resolve(LISTEN_PORT)

        class Stub:
            def resolve(self, port):
                return "demo", ruleset

        real, proxy_addon.REGISTRY = proxy_addon.REGISTRY, Stub()
        self.addCleanup(setattr, proxy_addon, "REGISTRY", real)
        f = self.run_request(host="registry.npmjs.org", claimed="registry.npmjs.org",
                             path="/lodash")
        self.assertEqual(self.assertAllowed(f, host="registry.npmjs.org")["session"], "demo")

    def test_unresolvable_session_fails_closed(self):
        class Stub:
            def resolve(self, port):
                raise proxy_addon.SessionError("no session for port")

        real, proxy_addon.REGISTRY = proxy_addon.REGISTRY, Stub()
        self.addCleanup(setattr, proxy_addon, "REGISTRY", real)
        f = self.run_request(host="api.anthropic.com", claimed="api.anthropic.com")
        self.assertDenied(f, reason="no session for port")


class Secrets(AddonCase):

    def test_missing_secret_is_indistinguishable_from_a_policy_miss(self):
        """Finding 8: a 500 here told the guest which secrets the host holds."""
        missing = self.run_request(host="example.test", claimed="example.test", path="/x")
        self.assertDenied(missing, host="example.test", reason="missing secret")
        self.audit.lines.clear()
        unmatched = self.run_request(host="evil.example", port=80, claimed="evil.example")
        self.assertDenied(unmatched, host="evil.example")
        self.assertEqual((missing.response.status_code, self.body(missing)),
                         (unmatched.response.status_code, self.body(unmatched)))

    def test_secret_may_not_rewrite_the_routing_header(self):
        """EGRESS_SECRET_BADHOST is "Host: evil.example" — honouring it would front another
        vhost behind an allowlisted destination, undoing the check in step 3."""
        f = self.run_request(host="pypi.org", claimed="pypi.org", path="/simple/")
        self.assertDenied(f, host="pypi.org", reason="unusable secret")
        self.assertEqual(f.request.headers["Host"], "pypi.org")

    def test_parse_secret_rejects_unusable_values(self):
        good = [("x-api-key: sk-ant-123", ("x-api-key", "sk-ant-123")),
                ("Authorization:Bearer abc", ("Authorization", "Bearer abc"))]
        for value, expected in good:
            with self.subTest(value=value):
                self.assertEqual(proxy_addon._parse_secret(value), expected)
        bad = ["no-colon",                              # not "<Header>: <value>"
               "x-api-key: ",                           # empty value
               "Host: evil.example",                    # decides the destination
               "Content-Length: 0",                     # decides the framing
               "Transfer-Encoding: chunked",
               "Upgrade: websocket",                    # step 4 denies these
               "x api key: v",                          # space is not a token character
               "x-api-key: a\r\nx-exfil: b",            # header injection upstream
               "x-api-key: a\x00b",
               "x-api-key: kéy",                        # non-ASCII field value
               "x-api-key: " + "x" * proxy_addon._MAX_SECRET,
               None, 42]
        for value in bad:
            with self.subTest(value=value):
                self.assertIsNone(proxy_addon._parse_secret(value))


class FailClosed(AddonCase):
    """mitmproxy logs an exception escaping a hook and then proceeds as if the hook had never
    run — forwarding the request, or opening the tunnel. Nothing may escape, and the block must
    be in place before the addon tries to describe it, because describing can throw too."""

    def explode(self):
        def boom(*a, **kw):
            raise RuntimeError("audit is broken")

        real = proxy_addon._audit
        proxy_addon._audit = boom
        self.addCleanup(setattr, proxy_addon, "_audit", real)

    def test_broken_audit_blocks_an_otherwise_allowed_request(self):
        self.explode()
        f = self.run_request(host="registry.npmjs.org", claimed="registry.npmjs.org",
                             path="/lodash")
        self.assertIsNotNone(f.response, "an unloggable allow must not be forwarded")
        self.assertEqual(f.response.status_code, 500)

    def test_broken_audit_blocks_a_connect(self):
        self.explode()
        f = self.run_connect(host="api.anthropic.com")
        self.assertIsNotNone(f.response, "an unloggable CONNECT must not open a tunnel")
        self.assertEqual(f.response.status_code, 500)

    def test_an_exception_before_any_decision_still_blocks(self):
        class Stub:
            def resolve(self, port):
                raise RuntimeError("registry is broken")

        real, proxy_addon.REGISTRY = proxy_addon.REGISTRY, Stub()
        self.addCleanup(setattr, proxy_addon, "REGISTRY", real)
        for hook, kw in ((self.run_request, {}), (self.run_connect, {})):
            with self.subTest(hook=hook.__name__):
                self.audit.lines.clear()
                f = hook(host="api.anthropic.com", **kw)
                self.assertDenied(f, code=500, reason="internal error: RuntimeError")

    def test_responseheaders_never_raises(self):
        f = self.flow(host="api.anthropic.com")
        f.response = None                            # not reachable in mitmproxy; a bug would be
        proxy_addon.responseheaders(f)
        self.assertEqual(len(self.audit.records()), 1)

    def test_responseheaders_streams(self):
        f = tflow.tflow(resp=True)
        proxy_addon.responseheaders(f)
        self.assertTrue(f.response.stream)


class Control(AddonCase):
    """_control_dispatch is pure: one line in, one JSON-able reply out, never a secret value."""

    def test_ping(self):
        self.assertEqual(proxy_addon._control_dispatch('{"op": "ping"}'), {"ok": True})

    def test_malformed_requests(self):
        for line in (b"not json", "[]", '"s"', "{}", '{"op": "nope"}'):
            with self.subTest(line=line):
                self.assertFalse(proxy_addon._control_dispatch(line)["ok"])

    def test_set_secret_round_trip(self):
        reply = proxy_addon._control_dispatch(
            json.dumps({"op": "set_secret", "name": "demo", "value": "x-token: abc123"}))
        self.assertEqual(reply, {"ok": True})
        self.assertEqual(proxy_addon.SECRETS.get("DEMO"), "x-token: abc123")

    def test_set_secret_rejects_bad_names(self):
        for name in ("", "-lead", "a b", "x" * 65, "a/b", None, 7):
            with self.subTest(name=name):
                reply = proxy_addon._control_dispatch(
                    json.dumps({"op": "set_secret", "name": name, "value": "x-t: v"}))
                self.assertFalse(reply["ok"])

    def test_set_secret_rejects_routing_headers_and_long_values(self):
        for value in ("Host: evil.example", "no-colon", "x-t: a\r\nx-u: b",
                      "x-t: " + "x" * proxy_addon._MAX_SECRET, None):
            with self.subTest(value=value):
                reply = proxy_addon._control_dispatch(
                    json.dumps({"op": "set_secret", "name": "probe", "value": value}))
                self.assertFalse(reply["ok"])
        self.assertNotIn("probe", proxy_addon.SECRETS.names())

    def test_list_secrets_never_echoes_a_value(self):
        reply = proxy_addon._control_dispatch('{"op": "list_secrets"}')
        self.assertIn("anthropic", reply["names"])
        self.assertNotIn(SENTINEL_VALUE, json.dumps(reply))


class ControlSocket(AddonCase):
    """The control channel is how the host hands over its credentials, so the socket must never
    exist with loose permissions and a second proxy must not take over a live one's channel.
    A unix socket in a temp directory; still nothing on the network."""

    def setUp(self):
        super().setUp()
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.dir.chmod(0o755)                      # an ordinary directory, as ~/.silkgate is
        self.path = str(self.dir / "proxy.sock")
        self.addCleanup(os.umask, os.umask(0))     # the widest umask a host could be running

    @staticmethod
    async def until(predicate, timeout=2.0):
        for _ in range(int(timeout / 0.01)):
            if predicate():
                return True
            await asyncio.sleep(0.01)
        return False

    def test_socket_is_never_exposed_at_the_advertised_path(self):
        """A socket is created with the umask's permissions, so chmod-after-bind leaves a window
        — and a window is a race no single stat can observe. Assert the mechanism instead: the
        bind lands on a private path inside a directory nobody else can enter, and only the
        finished 0600 socket is renamed to the path the host connects to.
        """
        bound = []
        start_unix_server = asyncio.start_unix_server

        async def spy(handler, *, path, **kw):
            server = await start_unix_server(handler, path=path, **kw)
            bound.append((path, os.stat(os.path.dirname(path)).st_mode & 0o777))
            return server

        async def scenario():
            asyncio.start_unix_server = spy
            try:
                task = asyncio.ensure_future(proxy_addon._control_server(self.path))
                self.assertTrue(await self.until(lambda: os.path.exists(self.path)))
            finally:
                asyncio.start_unix_server = start_unix_server

            self.assertEqual(len(bound), 1)
            bind_path, parent_mode = bound[0]
            self.assertNotEqual(bind_path, self.path,
                                "the path the host connects to must never be the one bound")
            self.assertEqual(parent_mode, 0o700, "bound where others could reach it")
            self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
            self.assertEqual([p.name for p in self.dir.iterdir() if p.is_dir()], [],
                             "the staging directory must not outlive the bind")

            reader, writer = await asyncio.open_unix_connection(self.path)
            writer.write(b'{"op": "ping"}\n')
            await writer.drain()
            self.assertEqual(json.loads(await reader.readline()), {"ok": True},
                             "the renamed socket must still serve")
            writer.close()
            task.cancel()

        asyncio.run(scenario())

    def test_a_live_channel_is_never_taken_over(self):
        real, proxy_addon._CONTROL_SOCK = proxy_addon._CONTROL_SOCK, self.path
        self.addCleanup(setattr, proxy_addon, "_CONTROL_SOCK", real)

        async def scenario():
            # A socket file left by a dead proxy is bound but unlistened: connect() refuses it,
            # which is what tells a stale path apart from one that is still being served.
            stale = socket.socket(socket.AF_UNIX)
            stale.bind(self.path)
            stale.close()
            self.assertFalse(proxy_addon._control_sock_live(self.path))

            proxy_addon.running()
            self.assertTrue(await self.until(lambda: proxy_addon._control_sock_live(self.path)))
            inode = os.stat(self.path).st_ino

            proxy_addon.running()                  # a second proxy on the same control socket
            self.assertTrue(await self.until(
                lambda: any("already served" in line for line in self.audit.lines)))
            self.assertEqual(os.stat(self.path).st_ino, inode)
            self.assertTrue(proxy_addon._control_sock_live(self.path))

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main(verbosity=2)
