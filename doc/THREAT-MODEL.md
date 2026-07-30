# Threat Model — egress control for an adversarial agent sandbox

> Scenario: an adversarial coding agent (≈ arbitrary code execution) runs inside a microVM;
> the [TLS-terminating proxy](./ARCHITECTURE.md) is its only egress. Attacker goals:
> exfiltrate data (source, mounted workspace, reachable secrets) and/or reach
> attacker-controlled infra (C2, payloads).

## The reframe that drives everything

An allowlist bounds **who the agent talks to, not what it says**. Every allowed destination
is a potential exfil carrier. Two distinct axes, often conflated:

- **Exfil bandwidth** is bounded only by (a) whether the destination stores/echoes
  attacker-readable data, (b) request volume/rate, (c) content length caps + inspection.
  **Never by glob breadth.**
- **Capability / blast radius** *is* bounded by path+method scoping.

> **Correction worth recording:** `*` (one segment) is *not* meaningfully safer than `**` for
> exfil — a single path segment swallows an arbitrary-length base64 blob. Glob granularity
> bounds the *shape* of a URL, not the *bytes* through it. `POST github.com/<org>/<repo>` vs
> `github.com/**` leak identically as exfil channels; the first only restricts what the agent
> can **do** (write one repo, not open gists/issues/API on others). Path+method scoping is
> blast-radius control, not exfil control. Don't conflate "I scoped the path" with "I stopped
> exfil."

There are three problems; the proxy only owns the middle one.

## Tier 1 — Network-layer prerequisites (the proxy is moot if these leak)

Not the proxy's job, but if any is missing the proxy is theater — the agent goes around it.

**Key constraint: the guest is root-compromised, so enforcement MUST live outside it.** Any
iptables/route/resolver config *inside* the guest is flushable by guest-root — not a
boundary. Tier 1 is host/VMM-side policy on the guest's interface.

- **DNS exfiltration.** Raw UDP/53 to any resolver = `<data>.attacker.com` tunnel,
  independent of the HTTP proxy. Structural fix: with an *explicit* HTTP proxy the **guest
  does no DNS at all** (proxy resolves). Block 53.
- **QUIC / HTTP3.** UDP/443; bypasses an HTTP proxy entirely. Block UDP/443.
- **IPv6.** If L3 default-deny only covers v4, v6 egress is wide open. Classic miss.
- **Raw sockets / ICMP / other IP protocols.** L3 default-deny must be "only TCP to the proxy
  port," not "block some ports."

**macOS implementation (primary): microsandbox's own host-side stack.** microsandbox does not
use libkrun's TSI mode — it attaches a virtio-net device and terminates it in a host-side
userspace TCP/IP stack (smoltcp) with a **default-deny egress policy engine**. The guest's
only egress is `eth0` → that host stack → policy → a real socket opened by the host process.
Root-in-guest can reconfigure `eth0` / add routes / craft raw frames, but every frame
terminates in the host stack; **only a hypervisor escape bypasses it.** Config:
`--net-default-egress deny --net-rule "allow@host:tcp:<proxyport>"`;
guest `HTTPS_PROXY=host.microsandbox.internal:<proxyport>`. DNS: microsandbox intercepts all
UDP/53 at its gateway but applies the egress policy per query, so with no DNS allow rule the
default-deny yields NXDOMAIN — no explicit DNS deny needed; the proxy alias resolves via
`/etc/hosts`, so nothing breaks. Native on
HVF — no nested VM, no `pf`. *(Verified live on macOS/Apple Silicon: a root guest had no direct
TCP/DNS/IPv6/ICMP egress and couldn't escape by re-routing — `verify_guest.sh` 7/7. Pin your `msb --version`; scope names drift pre-1.0.)*

**Linux alternative / CI:** microVM tap device + an `nft` ruleset in the `inet` family on that
interface — allow `ct state established,related`, allow new TCP to `proxy_ip . proxy_port`
only, `drop` everything else (covers all UDP, ICMP, IPv6, other TCP). Guest has no resolver.

**Fallbacks** if microsandbox's policy is insufficient: `VZFileHandleNetworkDeviceAttachment`
userspace gateway (strongest, but Virtualization.framework-only → off libkrun); no-NIC + vsock
(equal containment, needs host relay + in-guest shim); host `pf` keyed by VM subnet (fragile,
races Apple daemons — defense-in-depth only).

**Verification (run as root inside the guest):** `curl --proxy … https://registry.npmjs.org`
→ ok; `curl https://1.1.1.1` → blocked; `dig @1.1.1.1` → fail; `nc -u host 53` → fail; IPv6
→ fail; reconfiguring the guest's own `eth0`/routes changes nothing.

## Tier 2 — What the proxy enforces (and the traps)

- **Domain fronting** → SNI==Host. Cheap, handled.
- **Host-parsing discrepancies — the null-byte bug class** (cf. Claude Code SOCKS5 bypass).
  The matcher must normalize the host *identically to how the connection layer resolves it*:
  reject null/`%`/CR-LF/whitespace, strip trailing dot, lowercase, force punycode (reject raw
  Unicode → homographs), reject `user@host`/brackets/ports, reject raw IP literals. If the
  regex is laxer than the resolver, you get a bypass. **This is the most likely place this
  proxy gets broken.** Lives in the rule engine so it can't be skipped; same function applied
  to pattern and request host. (See [DSL.md](./DSL.md) → normalization.)
- **Path scoping is only as strong as path normalization.** Decode (`%2e%2e`) and resolve
  `..`/`.` *before* matching, or the regex and the upstream server disagree.
- **Headers are micro-channels, not just names.** `User-Agent`, `Range`, `Accept-Language`, etc.
  carry attacker bytes to a logging host. Allowing the *name* isn't enough — constrain the *value*
  (exact or regex + length cap) and keep the baseline minimal. (This design ships a 3-header,
  length-capped baseline — `host`/`content-type`/`content-length`; everything else, incl.
  `User-Agent`, is opt-in per rule.) A constrained value is still a residual low-bandwidth channel;
  pin exact for stricter posture.
- **WebSocket `Upgrade`** to an allowed host = a bidirectional C2 tunnel that looks like one
  allowed request. Deny `Upgrade` by default.
- **Fail-closed on anything undecryptable.** Cert-pinned tools, non-HTTP-over-TLS, raw CONNECT
  tunnels — if the proxy ever *passes through* what it can't inspect, that's the exfil
  channel. Pinned tools should break, not get an exception.
- **Non-standard ports.** A host allowlist that ignores port lets `allowed.com:1234` reach an
  attacker service on a co-opted host/port. Gate it: default to 80/443, require explicit
  `:port`/`:*` otherwise.

## Tier 3 — The irreducible residual (no proxy fixes these)

- **Exfil through a legitimately-allowed path/body.** `registry.npmjs.org/**` with unbounded
  `**` is an open channel; the LLM API body is attacker-influenced by definition. You can't
  both use these and prove nothing leaves. Levers: **minimize the allowlist**, and prefer
  destinations that don't store/relay attacker-readable data (`api.anthropic.com` is low-risk
  because the response comes from Anthropic, not the attacker; **never allowlist a
  header/body-reflecting endpoint** like an `httpbin`-style service).
- **Injected-credential abuse.** The agent can't *read* the injected key but can *use* it (run
  up cost, hit your account) — and if any allowed endpoint reflects request headers, it reads
  the key back. Scope/rate-limit the key; never allowlist a reflector.
- **Subdomain-as-data.** `**` in the *host* (and the `**.` apex matcher) lets
  `<data>.allowed.com` carry bytes in the SNI itself. Reason to reach for `**` in hosts
  deliberately.
- **Timing / size side channels** — low bandwidth, generally out of scope; name them.
- **Inbound prompt-injection** — the allowed *content* the agent fetches is what turns it
  adversarial. The proxy controls *where* it fetches, not the semantics of what comes back.
  Egress control limits damage; it doesn't prevent the agent from being turned.

## Scope summary

| Tier | Owner | In this design |
|---|---|---|
| 1 — network-layer prerequisites | Host/VMM (outside guest) | **Implemented & verified** (macOS via microsandbox, `verify_guest.sh` 7/7; Linux nft) |
| 2 — request-level enforcement | The proxy + rule engine | **Implemented** |
| 3 — irreducible residual | Rule discipline + operations | **Accepted & documented**, not code |
