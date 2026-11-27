# Agent sandboxing: state of the art

Read this to see what other tools ship for agent sandboxes, and which gap silkgate fills.

Last verified: June 2026. This is a research snapshot: 20 sources, 25 key claims
cross-checked, 23 confirmed and 2 refuted. The field moves fast, so check versions before
you rely on one. Managed cloud sandboxes (E2B, Modal, Daytona, Cloudflare, Fly.io) are out of
scope.

## One axis: isolation against overhead

**Every approach trades isolation strength against overhead and compatibility.**

| Tier | Isolates with | An attacker must beat | Start time | Shares the host kernel |
|---|---|---|---|---|
| microVMs: Firecracker, Kata, libkrun | a guest kernel behind KVM | the guest kernel and the hypervisor | ~100–300 ms | no |
| userspace kernel: gVisor (`runsc`) | a Sentry that intercepts syscalls | the Sentry, which still makes some host syscalls | ~50–100 ms in practice | partly |
| OS sandboxes: Seatbelt, bubblewrap, namespaces, seccomp, Landlock | a restricted view of the host kernel | one host-kernel bug | instant | yes |

The consensus (NVIDIA, and others): run untrusted or LLM-written code under full
virtualization, not in a kernel-sharing sandbox. A 200 ms boot is noise next to an LLM
call.

| Approach | Isolation | Egress control | OS | Maturity |
|---|---|---|---|---|
| Firecracker | very high | add your own proxy | Linux | high (Lambda, Fargate) |
| Kata Containers | very high | add your own | Linux | high |
| libkrun, microsandbox | high | add your own | Linux KVM, macOS HVF | medium |
| gVisor | medium-high | add your own | Linux | high (GKE) |
| Sysbox | medium: a hardened shared kernel | add your own | Linux | medium-high |
| bubblewrap, seccomp, Landlock | low-medium | none built in | Linux | high |
| Seatbelt (`sandbox-exec`) | low-medium | none built in | macOS | high, API nominally deprecated |

## Self-hostable tools

| Tool | How | License | Best for |
|---|---|---|---|
| microsandbox | libkrun microVMs on KVM and HVF, SDKs in Python, JS, Rust, Go | Apache 2.0 | untrusted code on a laptop or on-prem |
| Sysbox | user namespaces, seccomp on 300+ syscalls, virtual procfs. Rootless Docker-in-Docker without `--privileged`. | OSS | shared-kernel multi-tenancy without a VM |
| Firecracker, Kata | a microVM per workload | OSS | strong isolation at scale |
| gVisor | a userspace kernel | OSS | stronger than Docker, lighter than a VM |
| bubblewrap, nsjail | namespace and seccomp wrappers | OSS | the primitives frameworks build on |

Refuted in verification, so don't rely on them:

- microsandbox's "sub-100 ms boot" claim.
- "Docker Desktop's `docker sandbox` uses plain `runc` while ECI uses `sysbox-runc`".

## Framework built-ins

**Codex CLI and Claude Code converged: an OS-native sandbox, plus a default-deny egress
allowlist.**

Codex CLI:

- macOS: Seatbelt, with a generated default-deny profile.
- Linux: bubblewrap and seccomp. Landlock is a legacy fallback.
- Three modes: read-only, workspace-write, `danger-full-access`. Network is off in
  workspace-write. In allowlists, deny beats allow.

Claude Code, built on Anthropic's open-source `sandbox-runtime` (`srt`):

| Platform | Enforcement |
|---|---|
| macOS | Seatbelt, with generated profiles |
| Linux, WSL2 | bubblewrap, a network namespace, seccomp blocking `AF_UNIX`, socat to a host proxy |
| Windows | not supported: use WSL2 |

- Writes: the working directory and the session's `$TMPDIR`.
- Reads: the whole machine, `~/.ssh` and `~/.aws` included, unless you add them to
  `denyRead`.
- Egress: a host-side allowlist proxy that matches the client's hostname, and doesn't
  inspect TLS. So it's open to domain fronting and to leaks through broad domains like
  `github.com`. Its docs recommend a TLS-terminating proxy for stronger threat models.
- A patched bypass: `attacker.com\x00.google.com` passed an `endsWith('.google.com')` check,
  then libc dialed `attacker.com`. Affected 2.0.24 to 2.1.89, fixed in 2.1.90.

To harden a Claude Code setup:

1. Add `~/.aws`, `~/.ssh`, `~/.config/gh`, and `.env` files to `denyRead`.
2. Keep the egress allowlist narrow.
3. Put a TLS-terminating proxy in front ([ARCHITECTURE.md](./ARCHITECTURE.md)).
4. Stay on 2.1.90 or later.
5. For untrusted repos or MCP servers, run it all in a microVM.

## The gap

**Everyone says you need a microVM plus a TLS-terminating egress proxy. Nobody shipped the
combination.**

| Threat | What works |
|---|---|
| untrusted code execution | only full virtualization contains a kernel exploit |
| prompt injection, exfiltration | default-deny egress with explicit allowlists, ideally TLS-inspecting |
| multi-tenancy | a microVM per tenant, or Sysbox as the shared-kernel compromise |

Silkgate is that combination: microsandbox as Boundary A, mitmproxy as Boundary B
([ARCHITECTURE.md](./ARCHITECTURE.md)). An OS sandbox inside the VM is a cheap third layer.

Still open:

1. Steady-state overhead (compilers, `npm install`, test suites) of gVisor, Kata, and
   Firecracker. Only boot time is documented.
2. Multi-tenancy at scale: side channels, noisy neighbors, host-kernel CVE exposure.
3. GPU passthrough for microVMs, and whether it reintroduces host-kernel exposure.

## Sources

Primary:

- Anthropic `sandbox-runtime`: https://github.com/anthropic-experimental/sandbox-runtime
- Claude Code sandboxing: https://code.claude.com/docs/en/sandboxing
- Codex agent approvals and security: https://developers.openai.com/codex/agent-approvals-security
- Codex sandboxing concepts: https://developers.openai.com/codex/concepts/sandboxing
- NVIDIA, sandboxing agentic workflows: https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/
- microsandbox: https://github.com/microsandbox/microsandbox
- ContainAI security comparison (also the source of one refuted claim): https://github.com/novotnyllc/ContainAI/blob/main/docs/security-comparison.md
- Firecracker: https://github.com/firecracker-microvm/firecracker
- gVisor: https://gvisor.dev/docs/
- Sysbox: https://github.com/nestybox/sysbox
- libkrun: https://github.com/containers/libkrun

Secondary:

- SecurityWeek, the Claude Code sandbox bypass: https://www.securityweek.com/anthropic-silently-patches-claude-code-sandbox-bypass/
- DeepWiki, Codex sandboxing: https://deepwiki.com/openai/codex/5.6-sandboxing-implementation

Comparisons:

- https://northflank.com/blog/kata-containers-vs-firecracker-vs-gvisor
- https://edera.dev/stories/kata-vs-firecracker-vs-gvisor-isolation-compared
- https://oddguan.com/blog/claude-code-sandbox-2/
- https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/
- https://www.innoq.com/en/blog/2026/03/dev-sandbox-network/
- https://www.loginradius.com/blog/engineering/enforce-outbound-http-allowlists-ai-agents
- https://www.shayon.dev/post/2026/52/lets-discuss-sandbox-isolation/
- https://multikernel.io/2026/03/14/introducing-sandlock/
- https://www.softwareseni.com/firecracker-gvisor-containers-and-webassembly-comparing-isolation-technologies-for-ai-agents/
- https://onidel.com/blog/gvisor-kata-firecracker-2025
- https://emirb.github.io/blog/microvm-2026/
- https://codex.danielvaughan.com/2026/04/08/codex-sandbox-platform-implementation/
- https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/
