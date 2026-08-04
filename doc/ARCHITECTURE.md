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
│  │  HTTPS_PROXY=<session port>  ·   NO direct internet route                      │ │
│  │  mount (virtiofs):  /workspace ⇄ ~/projects/foo   (rw, the ONLY host path)    │ │
│  │                     ✗ no ~/.ssh  ✗ no ~/.aws  ✗ no dotfiles  ✗ no host creds  │ │
│  └──────────────────────────────┬─────────────────────────────────────────────┘  │
│      all egress default-DROP ────┘  except TCP→ proxy port ; DNS intercepted in VMM│
│                                  ▼                                                 │
│   ┌──────────────────────────────────────────────────┐   ┌──────────────────────┐│
│   │  TLS-terminating egress proxy (mitmproxy)          │◀──│ host secrets vault   ││
│   │   • terminates TLS with the private CA             │   │ LLM API key, git PAT ││
│   │   • SNI == Host enforcement  → kills domain front  │   └──────────────────────┘│
│   │   • allowlist + per-request method/path/size       │                          │
│   │   • injects Authorization for LLM / API upstreams  │                          │
│   │   • request-body cap (max_body) · audit log        │                          │
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

**Mounts:** exactly one — the project dir, read-write, via virtiofs. Nothing else. The CLI
refuses mounts that would hand the guest the host itself: `/`, `$HOME`, silkgate's own checkout
and state, and any directory whose root holds a `.git` **directory** — hooks and
`core.fsmonitor` there are host code execution the next time a human runs git in it. A linked
worktree's `.git` **file** is allowed, with a printed note; only the mount root is examined.

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
   That guarantee rests entirely on the proxy deciding the route from the address it will dial,
   never from anything the guest writes into the request. It once did the latter, and a request to
   any host carrying an allowlisted `Host:` header was answered with the credential attached — so
   the guest did not need to steal the key, only to ask for it to be spent. `test/test_addon.py`
   is what keeps that closed; treat the destination check as the load-bearing part of this claim.
4. **DNS is the proxy's, not the guest's.** With an explicit `HTTPS_PROXY`, the guest sends
   hostnames and the *proxy* resolves; raw port 53 from the guest never leaves the VMM
   (see Tier 1 — microsandbox intercepts UDP and TCP 53 alike).
5. **Logs every decision** — one allow/deny line per request, for post-incident review;
   never bodies, and never the injected credential.

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
  pushes from the host** after reviewing the diff. For autonomy, allow push to one repo only,
  with the PAT injected by the proxy and the request body capped (`max_body`). No SSH keys in
  the guest.

## Driving the agent — interactive vs programmatic

The guest process's **stdio is the channel** back to the parent — a process pipe, not network
egress, so it never touches the proxy boundary. The CLI relays that channel line by line as the
guest writes it, keeping stdout and stderr apart and leaving the command non-interactive, so a
parent can supervise a run and parse its output at the same time. The split is a convenience,
not a property: the relay tags stderr lines in-band with a byte the guest can write itself, so
everything on either stream — stderr included — is the guest's own report:
- **Human (interactive TUI):** `silkgate attach <name>` (`msb exec -t … -- claude`) attaches
  Claude Code's TUI to the terminal.
- **Parent agent (programmatic):** `silkgate exec <name> -- claude -p --output-format stream-json`
  emits a structured event stream the parent reads.

**One `msb run` is one turn.** It boots and tears down the VM per command, so session state under
`/root/.claude` dies with it and `--resume <id>` fails across runs. **Persistent sessions are the
fix:** `silkgate up` creates the VM once in the background (`msb create`) and each turn is an
`msb exec` into that live VM, so `/root/.claude` — and the cloned repo, `node_modules`, build
cache — survive between turns, and `claude -p --resume <id>` works across execs. The one-shot
`silkgate run` remains: it is now just `up` → `exec` → `down` in a finally block, keeping the
per-command lifecycle (and the per-turn VM boot) on purpose, for scripts that want no residue.

With an Anthropic **Console/org API key** (injected at the proxy) *both* work — but interactive
additionally probes `platform.claude.com/v1/oauth/hello` at startup and fails only if that host is
**blocked**, so interactive runs allowlist `platform.claude.com/v1/oauth/**`. (No OAuth
`setup-token` — that's Max/Pro-gated and unrelated to API-key auth.)

## The shared-proxy session model

Sessions share **one** mitmproxy process — not one proxy per VM. A single `mitmdump` listens on a
**pool of ports** (base `8090`, 16 consecutive, `8090..8105`) via repeated
`--mode regular@<addr>:<port>` args — bound to loopback only, both address families, never the
LAN (`SILKGATE_PROXY_BIND` overrides it for a platform that routes guests through a real bridge
address) — and each session claims one port from the pool. `silkgate up` starts this proxy the first
time it's needed (detached, `start_new_session=True`), waits for the base port to accept, and
records it in `~/.silkgate/proxy.json`; `silkgate down` terminates it once the last session goes
away.

**The listener port *is* the session identity — and it's spoof-proof.** Each sandbox's Tier-1
net-rule allows egress to *only its own* session's port (`--net-rule "allow@host:tcp:<port>"`,
default-deny otherwise), enforced in microsandbox's host-side stack **below** the guest (see Tier 1
enforcement). So the port a request arrives on cannot be forged by guest-root: reaching another
session's port is dropped before a real socket ever opens. The addon reads the accepted port from
`flow.client_conn.sockname[1]`, maps port → session → that session's RuleSet, and enforces it.
That ruleset is a **per-session snapshot** composed at `up` time into
`~/.silkgate/sessions/<name>/rules.txt` (cached per port; invalidated by the sessions-dir mtime and
the per-session `rules.txt` mtime). Unknown port, missing session, or unparsable rules **fail
closed** — deny with reason `"no session for port"`, never falling through to another session's
rules. Audit lines gain a `"session"` field. No per-request tokens are needed or used: the network
layer already proves identity, once, below the guest.

**Control plane: a unix socket, not an in-band HTTP endpoint.** The proxy also needs a channel for
the host to push secrets and query health. It must **not** be a network endpoint on a proxy port:
every guest can reach its proxy port (that is the whole point), so any in-band HTTP control plane
would be reachable by an adversarial guest and would need its own authentication to be safe.
Instead the addon serves a line-delimited-JSON protocol on a **unix socket**
(`~/.silkgate/proxy.sock`, mode `0600`, started in its `running()` hook; a stale socket file is
unlinked at start). A unix socket in the host filesystem is **unreachable from every guest by
construction** — no host path is mounted into the guests and there is no network route to it —
so it needs no auth. Ops: `ping`, `set_secret`, `list_secrets`; unknown ops and malformed lines are
errors.

**Secrets flow: env → CLI → socket → proxy memory.** The credential lives on the host only as
`EGRESS_SECRET_<NAME>`. `silkgate up` (and `silkgate secret set <name>`) reads it from the local
environment and pushes it over the control socket with `set_secret`; the addon holds it in an
**in-memory** dict, layered over any `EGRESS_SECRET_*` env it was launched with (the socket wins on
the same name). `inject_auth=<name>` resolves against that store. The value is **never** passed as
an argv (so it never shows in `ps`), **never** written to disk, and **never** logged or echoed back
— `list_secrets` returns names only. After pushing, `up` calls `list_secrets` and dies listing any
`inject_auth` name in the session ruleset still missing, so a session never starts
believing it holds a key it doesn't.

## Concrete starter stack

- **Proxy:** mitmproxy with a small addon (allowlist rule engine, SNI==Host, header/body/
  query enforcement, secret injection, audit log). See [DSL.md](./DSL.md) and the
  [`mitmaddon/`](../mitmaddon/) code. (Hand-rolling TLS MITM is the wrong place to be minimal — reuse
  mitmproxy; keep the rule engine dependency-free and portable.)
- **microVM:** microsandbox for "one tool, both OSes" (Apache 2.0, libkrun); or Lima +
  Firecracker for maturity.
- **Guest image:** nothing hand-written. A base distro image plus one layer per **profile**,
  synthesized at build time and cached by a hash of what went into it. A profile pairs the
  install step for a capability with the egress rules that capability needs, so the image and
  the policy are declared once, together — see [`profiles/`](../profiles/) and the README.
  Runtimes and the agent harness are both just profiles: nothing about a particular agent is
  baked into the base.

## Hardening checklist

- [ ] Agent process tree runs entirely inside the guest; host runs only control CLI + proxy.
- [ ] Exactly one virtiofs mount (project dir, rw). No creds/dotfiles mounted.
- [ ] Guest default route = drop; only the session's proxy port reachable — DNS included:
      port 53 is intercepted in the VMM (enforced **outside** the guest — see Tier 1).
- [ ] Private CA: cert in guest trust store + all language env vars; **private key host-only**.
- [ ] Proxy enforces SNI==Host, per-request method/path, header/body/query constraints, audit log.
- [ ] LLM/git secrets injected by proxy; never written into the guest.
- [ ] Package registries: download-only; publish blocked.
- [ ] Git push gated on human review (or repo-scoped + size-capped).
- [ ] Hypervisor and guest kernel patched (this is your residual escape surface).

## Residual risks (be honest)

- **Hypervisor escape** — a KVM/HVF/virtio CVE breaks Boundary A. Mitigate by patching +
  minimal device model; can't eliminate.
- **Exfil within an allowed channel** — what bounds it today is per-request: a rule's
  `max_body` caps each request body, and every decision is logged. There is **no content
  inspection** (no DLP), no cap on response size, and no budget across requests — a guest can
  leak through any allowed POST one capped body at a time. Tightening the allowlist is the
  strongest lever.
- **DNS tunneling** — closed: the guest does no external DNS (the proxy resolves), and
  microsandbox intercepts port 53 in the VMM — UDP queries fail under default-deny, TCP/53
  answers `REFUSED` from its stub.
- **Workspace tampering** — malicious code can corrupt mounted project files; human reviews
  diffs before push.
- **Shared MITM CA** — by design you can read all guest TLS. Fine (you own both ends); don't
  reuse that CA elsewhere.

## Tier 1 enforcement (resolved — verified live; see the platform note at the end)

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
  allow rule the default-deny yields NXDOMAIN — no explicit DNS deny is needed. TCP/53 is
  intercepted too: msb's own stub answers `REFUSED` for every destination, so port 53 is not an
  egress channel in either protocol. The proxy alias resolves via the guest's `/etc/hosts`.

So on both OSes, **microsandbox's stack is Tier 1; the mitmproxy + DSL is Tier 2.** No separate
L3 firewall is built. (Linux fallback if that ever changes: tap + `nft` — see THREAT-MODEL.md.)

**Fallbacks if microsandbox's policy proves insufficient** (ranked): (a)
`VZFileHandleNetworkDeviceAttachment` userspace gateway (fork gvproxy) — strongest, but
Virtualization.framework-only → drops libkrun; (b) no-NIC + vsock-to-host-proxy — equal
containment, but needs a custom host relay (no host `AF_VSOCK` on macOS) + an in-guest
TCP→vsock shim; (c) host `pf` on `bridge100` keyed by VM subnet — fragile (races Apple's
InternetSharing daemon), belt-and-suspenders only.

**Verified live:** a root guest had no direct TCP, DNS, IPv6, or ICMP egress — only the proxy
was reachable; a root guest re-adding its default route still couldn't egress; and the addon
allowed the allowlisted host while 403'ing an unlisted one (`verify_guest.sh`, 7/7). On macOS
(Apple Silicon/HVF, msb 0.5.4/0.5.7) that result was re-verified after the latest round of
fixes; on Linux (x86_64/KVM, msb 0.6.8, via the `test/linux/` container) it dates from before
them and has not been re-run since — the `--net-*` flags are unchanged, but treat the Linux
claim as stale until it is. Caveat: **pin your `msb --version`** — rule-grammar scope names
drift pre-1.0.
