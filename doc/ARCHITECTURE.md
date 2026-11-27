# Architecture

Read this to understand why silkgate pairs a microVM with a TLS-terminating proxy, and what
each boundary guarantees.

The target is a developer laptop. The workload is a coding agent treated as hostile: assume
prompt injection turns it into arbitrary code execution. [SOTA.md](./SOTA.md) covers what
other tools ship.

## Principles

**Treat the agent itself as the threat: run all of it in the VM, and make inspected network
requests the only thing it can do.**

1. The whole agent runs in the guest. Its tools are attacker-controlled, so they never run
   on the host. There's no `~/.ssh` in the guest to read.
2. Two independent boundaries. The VM contains code execution, and the proxy contains data
   movement. A VM escape still meets the proxy. A proxy bypass still meets the VM.
3. Default-deny below the guest, not just at the proxy. `HTTPS_PROXY` serves tools that
   cooperate. Tier 1 stops the ones that don't.
4. Every allowed destination can carry data out. The allowlist bounds what the agent can
   do, not how much it can leak.

## Glossary

**Every doc uses these terms with these meanings.**

| Term | Meaning |
|---|---|
| host | your machine. It runs only the CLI and the proxy. |
| guest | the Linux system inside the microVM. The agent and everything it touches run here. |
| session | one warm microVM, the proxy port it claims, and its composed ruleset. `up` creates it, `down` ends it. |
| profile | one capability under [`profiles/`](../profiles/): an install step and the rules it needs ([PROFILES.md](./PROFILES.md)) |
| proxy | the one shared mitmproxy process on the host, every guest's only route out ([PROXY.md](./PROXY.md)) |
| Tier 1 | the network boundary outside the guest: microsandbox forces all egress to the session's proxy port ([THREAT-MODEL.md](./THREAT-MODEL.md#tier-1-the-network-boundary)) |
| Tier 2 | per-request enforcement at the proxy: allowlist, header, body and query limits, secret injection ([THREAT-MODEL.md](./THREAT-MODEL.md#tier-2-what-the-proxy-enforces)) |

## At a glance

**One diagram shows both boundaries and the only way out.**

```text
┌──────────────────────── host (trusted) ─────────────────────────────────────┐
│  you ──▶ silkgate CLI                                                        │
│                                                                              │
│  ┌──────── microVM: own kernel (KVM on Linux, HVF on macOS) ──────────────┐  │
│  │  the agent and its whole process tree, plus node, python, git, …        │  │
│  │  trusts the proxy's CA cert · HTTPS_PROXY=<session port>                │  │
│  │  mounts: only the ones you chose, read-only by default                  │  │
│  │  no ~/.ssh, no ~/.aws, no dotfiles, no real credentials                 │  │
│  └───────────────────────────────┬─────────────────────────────────────────┘  │
│   Tier 1: everything is denied, except TCP to the session's own proxy port;    │
│   port 53 is answered inside the VMM and never forwarded                       │
│                                  ▼                                             │
│  ┌─────────────── proxy (mitmproxy + silkgate addon) ──────────┐  ┌─────────┐ │
│  │  terminates TLS with the private CA                          │◀─│ secrets │ │
│  │  rejects SNI ≠ Host · checks method, path, headers, body     │  └─────────┘ │
│  │  swaps dummy credentials for real ones · writes the audit log│              │
│  └───────────────────────────────┬──────────────────────────────┘              │
└──────────────────────────────────┼────────────────────────────────────────────┘
                                   ▼  only allowed, inspected requests leave
            api.anthropic.com   registry.npmjs.org (GET)   github.com/acme/app
```

## Boundary A: the microVM

**The VM contains code execution: the agent runs behind its own guest kernel.**

| | macOS (Apple Silicon) | Linux |
|---|---|---|
| Hypervisor | Hypervisor.framework | KVM |
| Runtime | microsandbox (libkrun) | microsandbox (libkrun) |
| File sharing | virtiofs | virtiofs |
| Guest image | the same Debian-based image on both | |

- A session keeps one VM warm, so clones, `node_modules`, and `claude --resume` survive
  between commands. `run` gives a fresh VM per command.
- Mounts are your choice, read-only by default, and the risky ones are refused (README,
  [Mounts](../README.md#mounts)).
- The git modes bring their own mounts ([GIT.md](./GIT.md)).

## Boundary B: the proxy

**The proxy contains data movement: it runs on the host, as the guest's only gateway.**

1. It terminates TLS. The guest trusts a private CA whose key never leaves the host. So
   the proxy sees each request, rejects SNI ≠ Host (domain fronting), and can allow
   `GET github.com/acme/…` while it blocks pushes and gists.
2. It allows per request, not per domain:

   | Upstream | Allowed | Blocked |
   |---|---|---|
   | `api.anthropic.com` | `POST /v1/messages`, key injected | everything else |
   | `registry.npmjs.org`, `pypi.org` | GET (download) | PUT, POST (publish) |
   | `github.com` | clone and fetch your repos | pushes, gists, other repos |
   | anything else | — | denied and logged |

3. It holds the secrets. The guest sends a dummy, and the proxy swaps in the real value.
   Code execution in the guest can't steal a key that isn't there. The proxy picks the
   route from the address it dials, never from headers the guest controls.
4. It resolves DNS. The guest sends hostnames, and port 53 never leaves the VMM.
5. It logs every decision, never bodies or credential values ([PROXY.md](./PROXY.md#the-audit-trail)).

## Four flows

**Four flows show how the two boundaries combine.**

| Flow | Path | What contains it |
|---|---|---|
| LLM call | guest → proxy → `api.anthropic.com` | The guest sends a dummy key. The real key survives full guest compromise. |
| `npm install` | guest → proxy → `GET registry.npmjs.org` | A malicious postinstall runs inside the VM and reaches only the proxy. |
| Exfiltration attempt | guest → proxy → denied | No host secrets in the guest. A POST to `evil.com` isn't allowed. A POST to `github.com` hits method, size, or SNI checks. Both boundaries must fail. |
| Git push | guest commits → you review → you push | Or `github-write:OWNER/REPO` allows push to one repo, token injected, body capped. |

## The channel back to you

**A guest command's stdout and stderr reach you over a process pipe, not the network, so
they never touch the proxy.**

- `silkgate attach` gives you the TUI.
- A parent agent runs `silkgate exec <name> -- claude -p --output-format stream-json`, and
  parses the stream.
- stdout and stderr stay apart, but that split is a convenience. The guest can forge it.

## Sessions

**All sessions share one proxy. Each session's port is its identity.**

A guest can reach only its own port, so the port a request arrives on proves which session
sent it. The proxy maps the port to that session's ruleset and fails closed on any gap
([PROXY.md](./PROXY.md#port-as-session-identity)).

## The audit UI

**`silkgate ui` has no auth, by design: the loopback bind is the boundary.**

- Only host processes can connect, and no guest can reach a host port beyond its own
  proxy port.
- It must never bind beyond loopback. For remote use, tunnel over SSH. A future `--bind`
  needs token auth first.
- It refuses what a hostile web page could send through your browser: the `Host` header
  must be loopback, a present `Origin` must be too, and every control action (freeze,
  resume, down, kill, diff) is POST-only.

Pinned by: `test/test_ui.py`.

## The stack

**Nothing security-critical is hand-rolled.**

- Proxy: mitmproxy plus a small addon. The rule engine is stdlib-only
  ([DSL.md](./DSL.md)).
- microVM: microsandbox, on both OSes.
- Guest image: a Debian base plus one layer per profile, generated at build time. Agents
  are profiles too: nothing agent-specific is in the base.

## Hardening checklist

**A hardened setup meets every line.**

- [ ] The whole agent runs in the guest. The host runs only the CLI and the proxy.
- [ ] Only chosen mounts, read-only by default, or a `--checkout` guest. No credentials or
      dotfiles mounted.
- [ ] Guest egress is default-deny outside the guest, DNS included: only the proxy port.
- [ ] The CA cert is in the guest trust store and env vars. The key stays on the host.
- [ ] The proxy enforces SNI = Host and the per-request limits, and writes the audit log.
- [ ] LLM and git secrets are injected by the proxy, never written into the guest.
- [ ] Package registries are download-only.
- [ ] Git push waits for review, or is scoped to one repo and size-capped.
- [ ] The hypervisor and guest kernel are patched.

## Residual risks

**Six risks survive both boundaries.**

| Risk | Status |
|---|---|
| Hypervisor escape | A KVM, HVF, or virtio bug breaks Boundary A. Patch, and accept it. |
| Exfiltration through an allowed channel | `max_body` caps each request. Nothing inspects content, caps responses, or limits rates. Keep the allowlist tight. |
| DNS tunneling | Closed: the VMM answers port 53 itself ([THREAT-MODEL.md](./THREAT-MODEL.md#tier-1-the-network-boundary)). |
| Mount tampering | Code can corrupt a read-write mount. Mounts are read-only by default, and you review diffs before pushing. |
| LFS store on the host | Writable from git-mode guests. A re-download risk, never content substitution ([GIT.md](./GIT.md#lfs)). |
| The shared CA | The proxy reads all guest TLS. Don't reuse that CA anywhere else. |
