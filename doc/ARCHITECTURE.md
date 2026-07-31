# Reference Architecture — microVM + TLS-terminating egress proxy

> Target: **developer laptops**. Workload: **coding agents (Claude Code / Codex) treated as
> adversarial** — assume prompt injection turns the agent into ≈ arbitrary code execution.
> This is the architecture the [SOTA](./SOTA.md) flagged as the gap nobody ships: strong
> isolation + real egress control, combined.

## Driving principle

Treat the agent process itself as the threat. So **put the whole agent inside the VM**, and
make the network the only thing it can do — under inspection.

1. **The agent runs *inside* the VM, not on the host.** Its `Read`/`Bash`/MCP tools are
   attacker-controlled. The agent binary, toolchain, and everything it touches live in the
   guest. The host runs only the control CLI and the proxy. (This also dissolves Claude
   Code's "reads the whole filesystem" problem — there is no `~/.ssh` on the guest.)
2. **Two independent boundaries.** The **microVM** contains code execution (guest kernel +
   hypervisor); the **TLS-terminating proxy** contains data movement. Neither trusts the
   other. A VM escape still hits the proxy; a proxy bypass still hits the VM.
3. **Default-deny at L3, not just at the proxy.** The guest has no route to the internet
   except the proxy port. Env-var proxying is for cooperating tools; the L3 drop is for the
   malware that ignores env vars. (See [THREAT-MODEL.md](./THREAT-MODEL.md) Tier 1.)
4. **Every allowed destination is an exfil channel until proven otherwise.** The allowlist
   bounds *capability/blast-radius*, not exfil bandwidth.

## At a glance

```
┌──────────────────────── Developer laptop (host / trusted) ────────────────────────┐
│                                                                                    │
│  Human ──terminal──▶ control CLI (start/stop session, attach)                      │
│                                                                                    │
│  ┌─────────────── microVM  (own guest kernel · KVM on Linux / HVF on macOS) ─────┐ │
│  │  Coding agent (Claude Code / Codex CLI) runs HERE — the whole process tree    │ │
│  │  toolchain: node, python, git, build tools                                    │ │
│  │  trust store + NODE_EXTRA_CA_CERTS/REQUESTS_CA_BUNDLE ➜ private CA cert        │ │
│  │  HTTPS_PROXY=10.0.2.2:8090   ·   NO direct internet route                      │ │
│  │  mount (virtiofs):  /workspace ⇄ ~/projects/foo   (rw, the ONLY host path)    │ │
│  │                     ✗ no ~/.ssh  ✗ no ~/.aws  ✗ no dotfiles  ✗ no host creds  │ │
│  └──────────────────────────────┬─────────────────────────────────────────────┘  │
│      all egress default-DROP ────┘  except TCP→ proxy port ; DNS→ host resolver    │
│                                  ▼                                                 │
│   ┌──────────────────────────────────────────────────┐   ┌──────────────────────┐│
│   │  TLS-terminating egress proxy (mitmproxy)          │◀──│ host secrets vault   ││
│   │   • terminates TLS with the private CA             │   │ LLM API key, git PAT ││
│   │   • SNI == Host enforcement  → kills domain front  │   └──────────────────────┘│
│   │   • allowlist + per-request method/path/size       │                          │
│   │   • injects Authorization for LLM / API upstreams  │                          │
│   │   • DLP regex · upload-size cap · full audit log   │                          │
│   └───────────────────────────┬────────────────────────┘                          │
└───────────────────────────────┼────────────────────────────────────────────────────┘
                                 ▼  only allowlisted + inspected requests leave
        api.anthropic.com   registry.npmjs.org (GET only)   github.com/your-org/*
```

## Boundary A — the microVM

**Runtime, per OS** (the cross-platform reality on laptops):

| | macOS (Apple Silicon) | Linux |
|---|---|---|
| Hypervisor | Hypervisor.framework (HVF) | KVM |
| microVM runtime | microsandbox (libkrun/HVF), or Lima / Tart / Apple `container` | Firecracker / Cloud Hypervisor / Kata; or microsandbox (libkrun/KVM) |
| FS share | virtiofs | virtiofs / 9p |
| Guest image | one minimal Linux image, **identical on both OSes** | same |

**Two realistic shapes:**
- **Persistent hardened VM (recommended for coding agents).** One warm Linux VM per
  project/session — coding agents have stateful workspaces (cloned repo, `node_modules`,
  build cache). Keep warm for the session, tear down after.
- **Ephemeral microVM per task** — only for code-interpreter semantics (fresh VM per run);
  worse DX for iterative coding.

**Mounts:** exactly one — the project dir, read-write, via virtiofs. Nothing else.

## Boundary B — the TLS-terminating egress proxy

Runs **on the host, outside the VM**, and is the guest's only gateway. The piece neither
Claude Code nor Codex ships, and the whole reason for the exercise.

1. **Terminates TLS.** Private CA generated once. The **CA cert (public)** goes into the
   guest's trust store + `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`,
   `GIT_SSL_CAINFO`, `PIP_CERT`. The **CA private key never leaves the host.** Now the proxy
   decrypts everything — defeating the hostname-only weakness:
   - **Domain fronting dies:** proxy sees both TLS SNI and decrypted `Host` and rejects
     `SNI != Host`. (Claude Code's proxy never decrypts, so it can't.)
   - **Broad-domain exfil shrinks:** sees the payload, so it can allow `github.com` for
     `GET /your-org/...` while blocking pushes/gists/large POSTs.
2. **Allowlist is per-request, not per-domain.** Example for a coding agent:

| Upstream | Allowed | Blocked |
|---|---|---|
| `api.anthropic.com` | POST `/v1/messages` (key injected) | everything else |
| `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org` | `GET` (download) | `PUT`/`POST` (publish) |
| `github.com` / `*.github.com` | clone/fetch your org's repos | pushes, gists, arbitrary repos, large uploads |
| everything else | — | dropped + logged |

3. **Injects secrets the guest never holds.** Guest LLM client points `base_url` at the
   proxy with a *dummy* key; the proxy attaches the real `Authorization`/`x-api-key` from the
   host vault for the allowlisted route. **Full code execution in the guest cannot steal the
   API key — it isn't there.**
4. **DNS is the proxy's, not the guest's.** With an explicit `HTTPS_PROXY`, the guest sends
   hostnames and the *proxy* resolves; drop raw UDP/TCP 53 from the guest.
5. **Logs everything (redacted)** — full audit trail for post-incident review.

## How four flows play out

- **LLM call:** guest → proxy (dummy key) → proxy injects real key → `api.anthropic.com`.
  Key safe even under full compromise.
- **`npm install`:** guest → proxy → `GET registry.npmjs.org`. A malicious postinstall runs
  *inside the VM* (contained) and can't phone home (no egress except inspected proxy).
- **Exfil attempt via prompt injection:** no `~/.ssh` in the guest (not mounted); and
  reading `/workspace/.env` then POSTing to `evil.com` is dropped at the proxy (not
  allowlisted) and to `github.com` is blocked (size/method/SNI≠Host). Two independent
  failures required.
- **Git push:** safest default — agent commits to a branch *inside the VM*; the **human
  pushes from the host** after reviewing the diff. For autonomy, allow push to one repo only
  with the PAT injected by the proxy and upload-size capped. No SSH keys in the guest.

## Driving the agent — interactive vs programmatic

The `msb run` process's **stdio is the channel** back to the parent — a process pipe, not network
egress, so it never touches the proxy boundary:
- **Human (interactive TUI):** `msb run -t … -- claude` attaches Claude Code's TUI to the terminal.
- **Parent agent (programmatic):** `msb run … -- claude -p --output-format stream-json` emits a
  structured event stream the parent reads (`--resume <id>` to continue across turns).

With an Anthropic **Console/org API key** (injected at the proxy) *both* work — but interactive
additionally probes `platform.claude.com/v1/oauth/hello` at startup and fails only if that host is
**blocked**, so interactive runs allowlist `platform.claude.com/v1/oauth/**`. (No OAuth
`setup-token` — that's Max/Pro-gated and unrelated to API-key auth.)

## Concrete starter stack

- **Proxy:** mitmproxy with a small addon (allowlist rule engine, SNI==Host, header/body/
  query enforcement, secret injection, audit log). See [DSL.md](./DSL.md) and the
  [`mitmaddon/`](../mitmaddon/) code. (Hand-rolling TLS MITM is the wrong place to be minimal — reuse
  mitmproxy; keep the rule engine dependency-free and portable.)
- **microVM:** microsandbox for "one tool, both OSes" (Apache 2.0, libkrun); or Lima +
  Firecracker for maturity.
- **Guest image:** minimal Debian/Alpine + Node/Python/git + agent CLI + CA cert + proxy
  env vars in `/etc/environment`.

## Hardening checklist

- [ ] Agent process tree runs entirely inside the guest; host runs only control CLI + proxy.
- [ ] Exactly one virtiofs mount (project dir, rw). No creds/dotfiles mounted.
- [ ] Guest default route = drop; only proxy port + host DNS reachable (enforced **outside**
      the guest — see Tier 1).
- [ ] Private CA: cert in guest trust store + all language env vars; **private key host-only**.
- [ ] Proxy enforces SNI==Host, per-request method/path, header/body/query constraints, audit log.
- [ ] LLM/git secrets injected by proxy; never written into the guest.
- [ ] Package registries: download-only; publish blocked.
- [ ] Git push gated on human review (or repo-scoped + size-capped).
- [ ] Hypervisor and guest kernel patched (this is your residual escape surface).

## Residual risks (be honest)

- **Hypervisor escape** — a KVM/HVF/virtio CVE breaks Boundary A. Mitigate by patching +
  minimal device model; can't eliminate.
- **Exfil within an allowed, inspected channel** — size caps + DLP + logging raise cost,
  don't zero it. Tightening the allowlist is the strongest lever.
- **DNS tunneling** — closed only if resolution is forced through the proxy and raw 53 dropped.
- **Workspace tampering** — malicious code can corrupt mounted project files; human reviews
  diffs before push.
- **Shared MITM CA** — by design you can read all guest TLS. Fine (you own both ends); don't
  reuse that CA elsewhere.

## Tier 1 enforcement (resolved — verified on macOS and Linux)

Forcing *all* egress through the proxy on macOS+microsandbox **does not need a nested Linux
VM, `pf`, or vsock plumbing.** microsandbox does not use libkrun's default TSI mode — it
attaches a virtio-net device and terminates it in its **own host-side userspace TCP/IP stack
(smoltcp) with a default-deny egress policy engine**, running natively on HVF.

- The guest's only egress path is `eth0` → microsandbox's host-side stack → policy check →
  a real socket opened *by the host process*. Root in the guest can reconfigure `eth0`, add
  routes, run its own resolver, or craft raw frames — every frame still terminates in the
  host stack, where policy is evaluated before any real socket opens. **Only a hypervisor
  escape bypasses it.** This is the "enforce outside the guest" property Tier 1 needs.
- Config: `msb run … --net-default-egress deny --net-rule "allow@host:tcp:<proxyport>"`.
  Guest `HTTPS_PROXY=host.microsandbox.internal:<proxyport>`. DNS: microsandbox's gateway
  intercepts all UDP/53, and the forwarder applies the egress policy per query, so with no DNS
  allow rule the default-deny yields NXDOMAIN — no explicit DNS deny is needed. The proxy alias
  resolves via the guest's `/etc/hosts`.

So on both OSes, **microsandbox's stack is Tier 1; the mitmproxy + DSL is Tier 2.** No separate
L3 firewall is built. (Linux fallback if that ever changes: tap + `nft` — see THREAT-MODEL.md.)

**Fallbacks if microsandbox's policy proves insufficient** (ranked): (a)
`VZFileHandleNetworkDeviceAttachment` userspace gateway (fork gvproxy) — strongest, but
Virtualization.framework-only → drops libkrun; (b) no-NIC + vsock-to-host-proxy — equal
containment, but needs a custom host relay (no host `AF_VSOCK` on macOS) + an in-guest
TCP→vsock shim; (c) host `pf` on `bridge100` keyed by VM subnet — fragile (races Apple's
InternetSharing daemon), belt-and-suspenders only.

**Verified live (macOS/Apple Silicon · Linux/x86_64):** a root guest had no direct TCP, DNS,
IPv6, or ICMP egress — only the proxy was reachable; a root guest re-adding its default route
still couldn't egress; and the addon allowed the allowlisted host while 403'ing an unlisted one
(`verify_guest.sh`, 7/7 on both — macOS on HVF with msb 0.5.4/0.5.7, Linux on KVM with msb
0.6.8 via the `test/linux/` container, same flags unchanged). Caveat: **pin your
`msb --version`** — rule-grammar scope names drift pre-1.0.
