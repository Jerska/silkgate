# Agent Sandboxing — State of the Art

Read this to see what the field ships for agent sandboxes, and which gap this repo fills.

Last verified: June 2026.

> Snapshot from a deep-research pass (20 sources fetched, 25 key claims adversarially
> verified: 23 confirmed, 2 killed). Anchored to **late 2025 / 2026** — a fast-moving area,
> so verify version specifics before you act. Managed cloud sandboxes (E2B, Modal, Daytona,
> Cloudflare, Fly.io) were intentionally **out of scope**.

## TL;DR — one isolation hierarchy

Everything sorts onto a single axis: **isolation strength traded against overhead and
compatibility.**

| Tier | What isolates the workload | Attacker must defeat | Boot/start | Host kernel exposed? |
|---|---|---|---|---|
| **Hardware-virtualized microVMs** (Firecracker, Kata, libkrun) | Own guest kernel behind KVM-enforced memory | Guest kernel **and** hypervisor (+ jailer) | ~100–300 ms | No |
| **Userspace kernel** (gVisor / `runsc`) | Sentry intercepts syscalls in user space | Sentry, but it still makes *some* host syscalls | Milliseconds (no VM boot)* | Partially |
| **Kernel-sharing OS sandboxes** (Seatbelt, bubblewrap, namespaces, seccomp, Landlock) | Restricted view of the *shared* host kernel | A single host-kernel bug | ~instant | **Yes** |

Consensus (NVIDIA + corroborating sources): for **untrusted / LLM-generated code, use full
virtualization** (VMs, unikernels, Kata) — not kernel-sharing sandboxes. gVisor is
"preferable to fully shared solutions but offers potentially weaker guarantees than full
virtualization." (verified 3-0)

\* *gVisor "milliseconds" is the marketing framing — real `runsc` spawn is often 50–100 ms.
The "no VM boot" claim is unambiguously true. The absolute number is optimistic.*

## Summary comparison

| Approach | Isolation | Perf overhead | Egress control | OS | Maturity |
|---|---|---|---|---|---|
| **Firecracker** (microVM) | Very high (own kernel + KVM) | ~100–200 ms boot | External (add a proxy) | Linux/KVM | High (AWS Lambda/Fargate) |
| **Kata Containers** | Very high | ~150–300 ms boot | External | Linux/KVM | High |
| **libkrun / microsandbox** | High (microVM) | Fast boot | External | Linux KVM, macOS HVF | Medium (younger) |
| **gVisor (`runsc`)** | Medium-high (userspace kernel) | No VM boot; real syscall overhead | External | Linux | High (Google/GKE) |
| **Sysbox** | Medium (hardened shared kernel) | Low | External | Linux | Medium-high |
| **bubblewrap / namespaces / seccomp / Landlock** | Low-medium (shared kernel) | Minimal | None built-in | Linux | High (primitives) |
| **macOS Seatbelt (`sandbox-exec`)** | Low-medium (shared kernel) | Minimal | None built-in | macOS | High (API nominally deprecated) |

---

## Layer 1 — Kernel / isolation primitives

- **Firecracker** — minimal-device microVM VMM (KVM). Each workload = dedicated guest
  kernel; escape path is guest→VMM then VMM→host, with the `jailer` as a second line of
  defense. Strongest + fastest microVM; minimal device model (weak GPU story).
- **Kata Containers** — OCI-compatible microVMs; drop-in-ish for container workflows,
  slightly heavier boot, most "container-native" of the strong-isolation options.
- **gVisor (`runsc`)** — the Sentry is "an application kernel" that does *not* pass
  syscalls to the host. Intermediate tier: stronger than namespaces, weaker than a VM,
  with real (unquantified here) steady-state syscall overhead.
- **Kernel-sharing primitives** — namespaces, seccomp-bpf, cgroups, Landlock,
  AppArmor/SELinux, capabilities on Linux; **Seatbelt/`sandbox-exec`** on macOS. The
  building blocks agent frameworks actually ship on. Cheap and ubiquitous, but a single
  host-kernel CVE defeats the whole layer.

**Overhead is modest where it matters:** NVIDIA's point is VM startup is "modest compared
to LLM calls" — a 200 ms microVM boot is noise next to per-inference latency. This is what
makes strong isolation practical for agents specifically.

## Layer 2 — Self-hostable OSS tooling

| Tool | Mechanism | License | Best for |
|---|---|---|---|
| **microsandbox** | libkrun microVMs (KVM/Linux, HVF/macOS-ARM64); Py/JS/Rust/Go SDKs; self-hosted | Apache 2.0 | Strong isolation for untrusted code on laptop/VPC/on-prem (verified 3-0) |
| **Sysbox** (Nestybox) | Auto user-namespaces (container root → unprivileged host UID), seccomp on 300+ syscalls, FUSE-virtualized procfs/sysfs; rootless **Docker-in-Docker + systemd** without `--privileged` | OSS | Hardened *shared-kernel* multi-tenancy without the VM tax (verified 3-0) |
| **Firecracker / Kata runners** | microVM per workload | OSS | Production strong isolation at scale |
| **gVisor** | userspace kernel | OSS | "Stronger than Docker, lighter than a VM" default |
| **bubblewrap / nsjail** | namespace + seccomp wrappers | OSS | The DIY primitives the frameworks build on |

⚠️ **Killed in verification — do not rely on these:**
- microsandbox's "sub-100 ms microVM boot" marketing claim (vote 1-2).
- "Docker Desktop `docker sandbox` uses plain `runc` while ECI uses `sysbox-runc`" (vote 0-3) — the runtime details are wrong.

## Layer 3 — Agent-framework built-ins

**OpenAI Codex CLI** is the closest parallel to Claude Code, and the two converged:
- macOS: Seatbelt via `/usr/bin/sandbox-exec` + dynamically generated default-deny SBPL
  (path hardcoded to prevent `PATH` injection).
- Linux: **bubblewrap + seccomp** by default (`--unshare-user/-pid/-net`); Landlock is a
  *legacy fallback*, not a co-running layer.
- Three modes: **read-only → workspace-write → `danger-full-access` (`--yolo`)**. Network
  **off by default** in workspace-write; allowlists support `*.example.com` vs
  `**.example.com`, **deny always wins over allow**, `*` valid only for allow rules.
  (verified 3-0)

The vendor convergence — OS-native sandbox + default-deny egress allowlist — *is* the
current state of the art for framework built-ins.

---

## Claude Code specifically (2025–2026)

Built on Anthropic's OSS **`sandbox-runtime` (`srt`)** primitives (also adopted by
Microsoft's `vscode-sandbox-runtime`).

| Platform | Enforcement |
|---|---|
| **macOS** | Seatbelt via `sandbox-exec` + dynamically generated profiles |
| **Linux / WSL2** | **bubblewrap** (filesystem) + network-namespace isolation (`--unshare-net`) + seccomp-BPF blocking `AF_UNIX` socket creation; **socat** relays to the host proxy |
| **Native Windows** | ❌ Not supported — run inside WSL2 (WSL1 also unsupported) |

**Filesystem default (the biggest risk):**
- **Write:** working dir + subdirs + session `$TMPDIR` only.
- **Read:** the **entire computer** — docs warn this "still allows reading credential files
  such as `~/.aws/credentials` and `~/.ssh/`." Must add to **`denyRead`** to block the Bash
  route. (verified 3-0)

**Network egress:** host-side allowlist **proxy** (nothing pre-allowed, default-deny).
Critical self-documented limitation: it **enforces the allowlist by client-supplied hostname
only and does NOT terminate or inspect TLS**, so it is open to **domain fronting** and to
exfiltration via broadly-allowed domains (for example `github.com`). Docs recommend a custom
**TLS-terminating proxy** for stronger threat models. (verified 3-0)

**Known exploited weakness (patched):** SOCKS5 hostname null-byte injection —
`attacker-host.com\x00.google.com` — JS `endsWith('.google.com')` passes but libc
`getaddrinfo()` truncates at the null byte and dials the attacker host. Affected
**v2.0.24–2.1.89, fixed in 2.1.90** (`isValidHost()` now rejects `\x00`, `%`, CRLF). Lesson:
hostname-only allowlisting without TLS inspection is architecturally fragile. (verified 3-0)

**Hardening a Claude Code deployment:**
1. Add `~/.aws`, `~/.ssh`, `~/.config/gh`, `.env` files to **`denyRead`**.
2. Keep the **egress allowlist narrow** — avoid broad domains like `github.com`.
3. Put a **TLS-terminating egress proxy** in front for any real exfiltration threat model —
   the layer this repo builds ([ARCHITECTURE.md](./ARCHITECTURE.md)).
4. Stay on **≥ 2.1.90**.
5. For untrusted repos/MCP servers, run the whole thing inside a **microVM/Kata** — the
   built-in sandbox shares the host kernel.

---

## The three threat models, cross-cut

- **Untrusted code execution** → only **full virtualization** contains a kernel exploit.
  Everything kernel-sharing is best-effort.
- **Prompt-injection / data exfiltration** → **default-deny egress with explicit
  allowlists** is the universal answer (srt, Codex, NVIDIA). NVIDIA's prescription: a
  **"default-ask posture + enterprise denylists that cannot be overridden by local users."**
  Weak spot everywhere: hostname-only filtering — you want TLS-terminating inspection.
- **Multi-tenancy / blast radius** → per-tenant **microVMs** are clean; **Sysbox** is the
  hardened shared-kernel compromise. (Behavior at true scale — side channels, noisy
  neighbors, host-kernel CVE exposure like the 2025 `runc` CVEs — was *not* quantified.)

## Recommendation for self-hosting

Defense-in-depth, ranked by what does the heavy lifting:

1. **Strong isolation foundation** — a **microVM** per agent session. `microsandbox`
   (Apache 2.0, libkrun, SDKs) for batteries-included self-hosted; **Kata** if
   container/K8s-native; **Firecracker** for own orchestration at scale. Adopted here as
   Boundary A ([ARCHITECTURE.md](./ARCHITECTURE.md)).
2. **Default-deny egress with a TLS-terminating proxy** — the capability *none* of the
   built-in framework proxies ship. This is what actually stops exfiltration. Adopted here
   as Boundary B ([ARCHITECTURE.md](./ARCHITECTURE.md)), with operations in
   [PROXY.md](./PROXY.md).
3. **OS-level sandbox inside the VM** — `sandbox-runtime`, Codex's bwrap/Seatbelt, or Sysbox
   — cheap second layer and for credential-file `denyRead`.
4. **Do not rely on a single layer** — the Claude Code SOCKS5 bypass is the lesson. It
   drives the host normalization in [DSL.md](./DSL.md).

**Two gaps you must solve yourself** (no shipped product covers them):
- A **microVM runtime + TLS-terminating egress proxy** combined into one reference
  architecture — everyone says you need it, and nobody ships it. This repo is that
  combination ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- **Steady-state runtime overhead** (compilers, `npm install`, test suites) of gVisor vs
  Kata vs Firecracker — only *boot* latency is well-documented. Benchmark your own workload.

## Caveats & confidence

- Sourcing is mostly primary (vendor docs, repos, source code). Boot-time numbers and the
  gVisor "shares host resources" framing lean partly on the Northflank blog (corroborated by
  primary docs).
- Two Codex implementation claims came via the DeepWiki secondary source (2-1 votes), though
  both were verified against Codex source.
- Time-sensitive: the SOCKS5 null byte was patched in v2.1.90, and new hostname-allowlist
  bypasses are plausible because the proxy does not inspect TLS (architectural, not a
  one-off bug).

## Open questions (unresolved by the research)

1. Measured **steady-state** CPU/IO/syscall overhead of gVisor vs Kata vs Firecracker for
   coding-agent workloads (only boot latency is documented).
2. A concrete reference architecture that combines a **microVM/Kata runtime +
   TLS-terminating egress proxy** (the layer everyone says you need but nobody ships).
   Answered since by this repo ([ARCHITECTURE.md](./ARCHITECTURE.md)).
3. True multi-tenancy at scale: per-tenant blast-radius, side-channel/noisy-neighbor risk,
   host-kernel CVE exposure.
4. GPU/accelerator passthrough story for microVM sandboxes — and whether it reintroduces
   host-kernel exposure.

---

## Sources

### Primary — vendor docs & official repos
- Anthropic `sandbox-runtime` (srt) — https://github.com/anthropic-experimental/sandbox-runtime
- Claude Code sandboxing docs — https://code.claude.com/docs/en/sandboxing
- OpenAI Codex — agent approvals & security — https://developers.openai.com/codex/agent-approvals-security
- OpenAI Codex — sandboxing concepts — https://developers.openai.com/codex/concepts/sandboxing
- NVIDIA — Practical security guidance for sandboxing agentic workflows — https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/
- microsandbox — https://github.com/microsandbox/microsandbox
- ContainAI security comparison (Sysbox details; also source of one *refuted* claim) — https://github.com/novotnyllc/ContainAI/blob/main/docs/security-comparison.md
- Firecracker — https://github.com/firecracker-microvm/firecracker
- gVisor docs — https://gvisor.dev/docs/
- Sysbox — https://github.com/nestybox/sysbox
- libkrun — https://github.com/containers/libkrun

### Secondary
- SecurityWeek — "Anthropic silently patches Claude Code sandbox bypass" — https://www.securityweek.com/anthropic-silently-patches-claude-code-sandbox-bypass/
- DeepWiki — Codex sandboxing implementation — https://deepwiki.com/openai/codex/5.6-sandboxing-implementation

### Blogs — comparison framing & corroboration
- Northflank — Kata vs Firecracker vs gVisor — https://northflank.com/blog/kata-containers-vs-firecracker-vs-gvisor
- Edera — Kata vs Firecracker vs gVisor isolation compared — https://edera.dev/stories/kata-vs-firecracker-vs-gvisor-isolation-compared
- oddguan.com — Claude Code network allowlist bypass / exfiltration — https://oddguan.com/blog/claude-code-sandbox-2/ · https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/
- INNOQ — dev sandbox network — https://www.innoq.com/en/blog/2026/03/dev-sandbox-network/
- LoginRadius — enforce outbound HTTP allowlists for AI agents — https://www.loginradius.com/blog/engineering/enforce-outbound-http-allowlists-ai-agents
- Additional isolation-comparison blogs: https://www.shayon.dev/post/2026/52/lets-discuss-sandbox-isolation/ · https://multikernel.io/2026/03/14/introducing-sandlock/ · https://www.softwareseni.com/firecracker-gvisor-containers-and-webassembly-comparing-isolation-technologies-for-ai-agents/ · https://onidel.com/blog/gvisor-kata-firecracker-2025 · https://emirb.github.io/blog/microvm-2026/ · https://codex.danielvaughan.com/2026/04/08/codex-sandbox-platform-implementation/ · https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/
