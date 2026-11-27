# Threat model

Read this to see what a hostile guest can try, and which tier stops it.

The scenario: a hostile agent, equal to arbitrary code execution, runs in the microVM, and
the proxy is its only way out. It wants to send data out (source, the workspace, any secret
it can reach) or to reach the attacker's servers.

## Allowlists bound who, not what

**An allowlist limits who the agent talks to, not what it says.**

| Axis | Bounded by | In silkgate |
|---|---|---|
| What the agent can do | path and method scope | rules |
| How much it can leak | whether the destination stores or echoes data, volume, content limits | `max_body` per request only. No content inspection, no response cap, no rate limit. |

A narrow glob isn't safer for leaks. One `*` path segment carries any base64 blob, so
`POST github.com/acme/app` and `github.com/**` leak the same. The narrow rule only limits
what the agent can do: write one repo, not open gists elsewhere.

## Tier 1: the network boundary

**Tier 1 forces all guest egress to the session's proxy port, from outside the guest. If it
leaks, the agent just goes around the proxy.**

The guest is root by assumption, so anything configured inside it (iptables, routes, a
resolver) isn't a boundary.

| Channel | Attack | Required |
|---|---|---|
| DNS (port 53) | `<data>.attacker.com` queries tunnel past any HTTP proxy | No external names resolve. Port 53 ends in the VMM. |
| QUIC, HTTP/3 (UDP 443) | bypasses an HTTP proxy | Default-deny covers all UDP. |
| IPv6 | a v4-only deny leaves v6 open | Default-deny covers both families. |
| Raw sockets, ICMP, other protocols | channels below TCP | Only TCP to the proxy port leaves. |

### How microsandbox enforces it

**microsandbox ends the guest's network in its own host-side TCP/IP stack, where a
default-deny policy runs before any real socket opens.**

```text
guest eth0 ─▶ virtio-net ─▶ host-side stack (smoltcp) ─▶ policy ─▶ real socket
```

Guest root can reconfigure `eth0`, add routes, or craft raw frames. Every frame still ends
in that stack. Only a hypervisor escape bypasses it. Silkgate starts each guest with:

```text
msb run … --net-default-egress deny --net-rule "allow@host:tcp:<port>"
HTTPS_PROXY=host.microsandbox.internal:<port>
```

DNS needs no extra rule:

- All UDP/53 goes to microsandbox's gateway. With no DNS allow rule, every query gets
  NXDOMAIN.
- TCP/53 to any destination gets `REFUSED` from microsandbox's own stub.
- The proxy alias resolves through the guest's `/etc/hosts`.

Don't add `allow@host:udp:53` to a session. That rule reopens DNS.

### Verified live

**From a root guest, nothing but the guest's own proxy port answered. All 15 checks passed,
and three observers outside the guest agreed.**

```sh
silkgate verify                              # bare guest
silkgate verify --full                       # also installs probe tools through the proxy
silkgate verify --full --negative-control    # adds a leaky guest that must fail
```

- No TCP, UDP, DNS over either transport, IPv6, or ICMP got out. Neither did a new route, a
  new address, or the host's other ports.
- A blocked probe passes only on an answer from the boundary, never on silence. A refusal
  counts. An unreachable means the probe never left, and proves nothing. Silence is graded
  against a control that measures how this boundary denies.
- Check 0 tests the probe itself: it needs the proxy to refuse a request no rule allows. A
  bare TCP connect proves nothing, because microsandbox's NAT completes the handshake with
  no listener.
- Check 3 runs as root with no direct route. Check 7 re-adds a default route as root and is
  still blocked: enforcement sits below the guest NIC. If any of checks 3 to 7 succeeds, the
  boundary leaks.
- `--full` checks which checks ran (the guest's `CHECKS:` line), not just the count. A skip
  fails it.
- Three observers outside the guest:
  - a listener the allowlist omits, which must hear nothing, while its own control token
    must arrive
  - a recorder that must see the proxy replace a credential the guest sent, and never add
    one
  - the run's audit log, which must hold the decisions the checks provoked
- `--negative-control` must fail six checks on a deliberately leaky guest. It's the only
  proof the checks can fail.
- Every `up` and `run` re-runs check 3 before handing over the guest.

| Platform | msb | How |
|---|---|---|
| macOS, Apple Silicon (HVF) | 0.5.4, 0.5.7 | by hand |
| Linux x86_64 (KVM), in `test/linux/` | 0.6.8 | CI, every push |

The Linux guest has no working IPv6, so the v6 checks report nothing to probe there. Pin
your `msb --version`: rule names drift before 1.0.

Pinned by: `test/verify_guest.sh` (the checks), `test/test_verify_checks.py` and
`test/test_verify_oracles.py` (the harness).

### Fallbacks

**If microsandbox's policy ever proves insufficient, three fallbacks exist, best first.**

1. A userspace gateway on `VZFileHandleNetworkDeviceAttachment` (a gvproxy fork). Strongest,
   but Virtualization.framework only, so it drops libkrun.
2. No NIC, plus a vsock relay to the host. Same containment, but macOS has no host
   `AF_VSOCK`, so it needs a custom relay and an in-guest shim.
3. Host `pf` on `bridge100`. Fragile, because it races Apple's InternetSharing: defense in
   depth only.

On Linux: a tap device plus an `nft` ruleset in the `inet` family. Allow established
traffic and new TCP to the proxy port, and drop the rest.

## Tier 2: what the proxy enforces

**Tier 2 is per-request enforcement: the mitmproxy addon plus the rule engine
([DSL.md](./DSL.md)).**

| Trap | Defense |
|---|---|
| Domain fronting | reject SNI ≠ Host |
| Host-parsing tricks: null bytes, `user@host`, homographs | normalize the pattern and the request host with the same function, and reject anything odd ([DSL.md](./DSL.md#normalization)). The most likely place for a bypass. |
| `..` and `%2e%2e` in paths | decode once and resolve before matching |
| Headers as side channels (`User-Agent`, `Range`) | strip all but a 4-header baseline. Every other header is opt-in, value-constrained. |
| WebSocket `Upgrade` | always denied |
| Undecryptable traffic: pinned certs, raw CONNECT, non-TLS | refused, never passed through. `http_connect` checks the tunnel's target before it opens, and `rawtcp=false` removes the fallback. |
| Non-standard ports | no port means 80 and 443 only |

A denied HTTPS destination is refused at CONNECT, before any TLS. The client sees a failed
CONNECT that names 403, not a 403 body.

## Tier 3: what no proxy fixes

**Tier 3 is what's left when Tiers 1 and 2 hold. Rule discipline bounds it, not code.**

- Leaks through an allowed path. `registry.npmjs.org/**` is an open channel, and the LLM
  request body is attacker-influenced by definition. Keep rules minimal, cap bodies, and
  prefer destinations that don't store or relay what you send. Never allow an endpoint that
  echoes headers or bodies.
- Spending the injected credential. The agent can't read the key, but can spend it. If an
  allowed endpoint echoes headers, it reads the key back. Scope and rate-limit keys.
- Subdomains as data. `**` in a host lets `<data>.allowed.com` carry bytes in the SNI.
- Timing and size side channels: low bandwidth, out of scope.
- Inbound prompt injection. The proxy controls where the agent fetches from, not what
  comes back. It limits the damage, but can't prevent the turn.

## Summary

| Tier | Owner | Status |
|---|---|---|
| 1, network | host and VMM, outside the guest | implemented and verified, 15 of 15 checks |
| 2, requests | the proxy and the rule engine | implemented ([PROXY.md](./PROXY.md)) |
| 3, residual | rule discipline and operations | documented, not code |
