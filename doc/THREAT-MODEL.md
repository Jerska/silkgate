# Threat model

Read this to understand what an adversarial guest can attempt and which layer stops each
attempt. Tier 1 and Tier 2 are defined here in full. The glossary in
[ARCHITECTURE.md](./ARCHITECTURE.md) gives the one-line versions.

The scenario: an adversarial coding agent, equal to arbitrary code execution, runs inside a
microVM, and the proxy is its only egress. The attacker wants to exfiltrate data — source,
the mounted workspace, reachable secrets — and to reach attacker-controlled infrastructure.

## The reframe that drives everything

**An allowlist bounds who the agent talks to, not what it says.** Every allowed destination
is a potential exfiltration carrier. Two distinct axes are often conflated:

- Exfiltration bandwidth is bounded only by whether the destination stores or echoes
  attacker-readable data, by request volume, and by content caps and inspection. It is never
  bounded by glob breadth. Of the caps, this design ships the size half only, per request: a
  rule's `max_body` caps the request body. Nothing inspects content, nothing caps responses,
  and nothing rate-limits.
- Capability and blast radius are bounded by path and method scope.

A correction worth a record: `*` (one segment) is not safer than `**` for exfiltration. A
single path segment carries an arbitrary-length base64 blob. Glob granularity bounds the
shape of a URL, not the bytes through it. `POST github.com/<org>/<repo>` and `github.com/**`
leak identically as exfiltration channels. The first only restricts what the agent can do:
write one repo, not open gists or issues on others. Do not mistake a scoped path for stopped
exfiltration.

There are three problems. The proxy owns only the middle one.

## Tier 1 — network-layer prerequisites

**Tier 1 forces all guest egress to the session's proxy port, enforced outside the guest. If
any part of it leaks, the proxy is theater: the agent goes around it.** The guest is
root-compromised by assumption, so enforcement must live outside it. Any iptables, route, or
resolver configuration inside the guest is flushable by guest-root and is not a boundary.
Tier 1 is host-side policy on the guest's interface.

| Channel | Attack | Required property |
|---|---|---|
| DNS (port 53) | `<data>.attacker.com` queries tunnel data past any HTTP proxy | The guest resolves no external names. Port 53 terminates in the VMM. |
| QUIC / HTTP3 (UDP 443) | Bypasses an HTTP proxy entirely | Default-deny covers all UDP. |
| IPv6 | A v4-only deny leaves v6 wide open — a classic miss | Default-deny covers both address families. |
| Raw sockets, ICMP, other IP protocols | Channels below TCP | Only TCP to the proxy port leaves the VMM. |

### How microsandbox enforces it

**microsandbox terminates the guest's network in its own host-side userspace TCP/IP stack
(smoltcp), where a default-deny policy engine runs before any real socket opens.** It does
not use libkrun's TSI mode: it attaches a virtio-net device and ends it in that stack, native
on HVF and KVM. The guest's only egress path is `eth0`, then the host-side stack, then the
policy check, then a real socket opened by the host process. Guest-root can reconfigure
`eth0`, add routes, run its own resolver, or craft raw frames — every frame still terminates
in the host stack. Only a hypervisor escape bypasses it. This is the enforce-outside-the-guest
property Tier 1 needs, with no nested VM, no `pf`, and no `nft`.

The configuration is `msb run … --net-default-egress deny --net-rule
"allow@host:tcp:<proxyport>"`, with `HTTPS_PROXY=host.microsandbox.internal:<proxyport>` in
the guest.

Port 53 is not an egress channel in either protocol. microsandbox's gateway intercepts
all UDP/53, and its forwarder applies the egress policy per query, so with no DNS allow rule
the default-deny yields NXDOMAIN — no explicit DNS deny is needed. Its stub answers `REFUSED`
for TCP/53 to every destination. The proxy alias resolves through the guest's `/etc/hosts`,
so nothing breaks. Do not add `allow@host:udp:53` to a session. That rule reopens DNS.

### Verified live

**A root guest reached nothing except its own proxy port: 15 of 15 checks passed, and three
oracles outside the guest agree.** The guest reached nothing by TCP, UDP, DNS over either
transport, IPv6, or ICMP. It did not escape through a new route, a new address, or any of the
host's other ports. The addon allowed the allowlisted host and refused an unlisted one. Each
denial was an answer from the boundary, not a silence.

The three oracles sat outside the guest. A listener the allowlist omits heard nothing from
the guest. A recorder endpoint saw the proxy replace a credential the guest sent, and never
add one the guest did not send. The run's audit log holds the decisions the checks provoked. With
`--negative-control`, a deliberately leaky guest fails six of the checks — the only proof
that the checks can fail at all.

Platforms: macOS (Apple Silicon, HVF, msb 0.5.4/0.5.7) by hand, and Linux (x86_64, KVM,
msb 0.6.8, in the `test/linux/` container) by CI on every push. Coverage differs. The Linux
guest has no working IPv6 and maps the proxy alias to v4 only, so a check whose subject is
a v6 path reports that it had nothing to probe.

The checks live in `test/verify_guest.sh`, run as root inside a guest by `silkgate verify`.
`test/test_verify_checks.py` and `test/test_verify_oracles.py` pin the harness. Pin your
`msb --version` — rule-grammar scope names drift pre-1.0.

### Fallbacks

**If microsandbox's policy proves insufficient, three fallbacks exist, ranked.**

1. A `VZFileHandleNetworkDeviceAttachment` userspace gateway (fork gvproxy). Strongest, but
   Virtualization.framework-only, so it drops libkrun.
2. No NIC plus a vsock-to-host relay. Equal containment, but macOS has no host `AF_VSOCK`,
   so it needs a custom host relay and an in-guest TCP-to-vsock shim.
3. Host `pf` on `bridge100`, keyed by VM subnet. Fragile — it races Apple's InternetSharing
   daemon — and defense-in-depth only.

The Linux fallback is a tap device plus an `nft` ruleset in the `inet` family on that
interface. The rules: allow `ct state established,related`, allow new TCP to the proxy
address and port only, and drop everything else. That covers all UDP, ICMP, IPv6, and other
TCP, with no resolver in the guest. It is not needed while microsandbox's stack holds.

## Tier 2 — what the proxy enforces (and the traps)

**Tier 2 is per-request enforcement at the proxy: the mitmproxy addon plus the rule engine
in [DSL.md](./DSL.md).** Each trap below names the failure it guards against.

- Domain fronting. The proxy rejects any request whose SNI and Host disagree.
- Host-parsing discrepancies — the null-byte bug class (see the Claude Code SOCKS5 bypass in
  [SOTA.md](./SOTA.md)). The matcher must normalize the host identically to how the
  connection layer resolves it. Reject null bytes, `%`, CR-LF, whitespace, `user@host`,
  brackets, and raw IP literals. Strip the trailing dot, lowercase, and force punycode to
  kill homographs. If the pattern is laxer than the resolver, the difference is a bypass.
  This is the most likely place this proxy gets broken, so normalization lives in the rule
  engine, applied to pattern and request host by the same function
  ([DSL.md](./DSL.md), host normalization).
- Path scope is only as strong as path normalization. Decode `%2e%2e` and resolve `..` and
  `.` before the match, or the pattern and the upstream server disagree.
- Headers are micro-channels, not just names. `User-Agent`, `Range`, and `Accept-Language`
  carry attacker bytes to a host that logs them. To allow a name is not enough: constrain the
  value (exact or regex plus a length cap) and keep the baseline minimal. This design ships a
  three-header, length-capped baseline — `host`, `content-type`, `content-length` — and
  everything else, `User-Agent` included, is opt-in per rule. A constrained value is still a
  residual low-bandwidth channel. Pin exact values for a stricter posture.
- A WebSocket `Upgrade` to an allowed host is a bidirectional command channel that looks like
  one allowed request. Deny `Upgrade` by default.
- Fail closed on anything undecryptable. Cert-pinned tools, non-HTTP-over-TLS, and raw
  CONNECT tunnels must break, not get an exception: whatever the proxy passes through
  uninspected is the exfiltration channel. Two halves enforce it, and neither is sufficient
  alone. The `http_connect` hook matches the tunnel's authority before the tunnel exists, and
  `--set rawtcp=false` removes the passthrough a CONNECT falls back to when its payload is
  not TLS. One visible consequence: a denied HTTPS destination is refused before the tunnel
  exists, so the guest sees a rejected CONNECT that names 403 rather than a 403 response
  body.
- Non-standard ports. A host allowlist that ignores the port lets `allowed.com:1234` reach an
  attacker service on a co-opted host. The rules gate it: no port means 80 and 443 only, and
  any other port needs an explicit `:port` or `:*` ([DSL.md](./DSL.md), ports).

## Tier 3 — the irreducible residual (no proxy fixes these)

**Tier 3 is what remains after Tiers 1 and 2 hold. It is bounded by rule discipline and
operations, not by code.**

- Exfiltration through a legitimately allowed path and body. `registry.npmjs.org/**` with an
  unbounded `**` is an open channel, and the LLM API body is attacker-influenced by
  definition. You cannot both use these and prove nothing leaves. The levers: minimize the
  allowlist, cap request bodies with `max_body`, and prefer destinations that neither store
  nor relay attacker-readable data. `api.anthropic.com` is low-risk because the response
  comes from Anthropic, not the attacker. Never allowlist an endpoint that reflects headers
  or bodies, such as an `httpbin`-style service.
- Injected-credential abuse. The agent cannot read the injected key but can spend it: run up
  cost, hit your account. And if any allowed endpoint reflects request headers, the agent
  reads the key back. Scope and rate-limit the key, and never allowlist a reflector.
- Subdomain as data. `**` in the host, and the `**.` apex matcher, let `<data>.allowed.com`
  carry bytes in the SNI itself. Reach for `**` in hosts deliberately.
- Timing and size side channels. Low bandwidth, out of scope, named here for honesty.
- Inbound prompt injection. The allowed content the agent fetches is what turns it
  adversarial. The proxy controls where the agent fetches, not the semantics of what comes
  back. Egress control limits damage. It does not prevent the turn.

## Scope summary

**Each tier has one owner, and only the first two are code.**

| Tier | Owner | In this design |
|---|---|---|
| 1 — network-layer prerequisites | Host and VMM, outside the guest | Implemented and verified: `test/verify_guest.sh` 15/15 plus three host-side oracles, macOS by hand, Linux in CI on every push, `nft` as the Linux fallback |
| 2 — request-level enforcement | The proxy plus the rule engine | Implemented: [`mitmaddon/`](../mitmaddon/), operations in [PROXY.md](./PROXY.md) |
| 3 — irreducible residual | Rule discipline plus operations | Accepted and documented, not code |
