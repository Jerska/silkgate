# Architecture — microVM + TLS-terminating egress proxy

Read this to understand why silkgate pairs a microVM with a TLS-terminating proxy, and what
each boundary guarantees.

The target is developer laptops. The workload is coding agents (Claude Code, Codex) treated
as adversarial: assume prompt injection turns the agent into arbitrary code execution. This
is the architecture [SOTA.md](./SOTA.md) flagged as the gap nobody ships — strong isolation
and real egress control, combined.

## Driving principle

**Treat the agent process itself as the threat: put the whole agent inside the VM, and make
the network the only thing it can do — under inspection.**

1. The agent runs inside the VM, not on the host. Its Read, Bash, and MCP tools are
   attacker-controlled, so the agent binary and toolchain live in the guest. This also
   dissolves Claude Code's read-the-whole-filesystem problem: there is no `~/.ssh` there.
2. Two independent boundaries. The microVM contains code execution. The proxy contains
   data movement. Neither trusts the other: a VM escape still hits the proxy, and a proxy
   bypass still hits the VM.
3. Default-deny below the guest, not just at the proxy. The guest has no route to the
   internet except the proxy port. `HTTPS_PROXY` serves the tools that cooperate, and
   Tier 1 stops the malware that ignores it.
4. Every allowed destination is an exfiltration channel until proven otherwise. The
   allowlist bounds capability and blast radius, not exfiltration bandwidth.

## Glossary

**These terms are introduced here once, and no document uses a synonym for them.**

| Term | Definition |
|---|---|
| guest | The Linux system inside the microVM. The agent, its toolchain, and everything they touch run here. |
| host | The developer's machine. It runs only the control CLI and the proxy. |
| session | One warm microVM plus the proxy port it claims and the ruleset composed for it. `silkgate up` creates it, `silkgate down` ends it. |
| profile | One capability under [`profiles/`](../profiles/): the install step and the egress rules that capability needs, declared together. |
| proxy | The TLS-terminating egress proxy on the host: one shared mitmproxy process that is every guest's only route to the network. |
| Tier 1 | The network boundary outside the guest: microsandbox's host-side stack forces all guest egress to the session's own proxy port. The full definition is in [THREAT-MODEL.md](./THREAT-MODEL.md). |
| Tier 2 | Per-request enforcement at the proxy: allowlist, header, body, and query constraints, secret injection. The full definition is in [THREAT-MODEL.md](./THREAT-MODEL.md). |

## At a glance

**One diagram shows both boundaries and the only path out.**

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
│  │  mounts (virtiofs): user-chosen, ro default (/workspace ⇄ ~/projects/foo rw)  │ │
│  │                     ✗ no ~/.ssh  ✗ no ~/.aws  ✗ no dotfiles  ✗ no host creds  │ │
│  └──────────────────────────────┬─────────────────────────────────────────────┘  │
│     all egress default-deny ─────┘ except TCP to the session's own proxy port;     │
│     port 53 (UDP and TCP) is answered inside the VMM and never forwarded           │
│                                  ▼                                                 │
│   ┌──────────────────────────────────────────────────┐   ┌──────────────────────┐│
│   │  TLS-terminating egress proxy (mitmproxy)          │◀──│ host secrets vault   ││
│   │   • terminates TLS with the private CA             │   │ LLM API key, git PAT ││
│   │   • rejects SNI != Host (kills domain fronting)    │   └──────────────────────┘│
│   │   • allowlist + per-request method/path/size       │                          │
│   │   • injects Authorization for allowlisted routes   │                          │
│   │   • request-body cap (max_body) · audit log        │                          │
│   └───────────────────────────┬────────────────────────┘                          │
└───────────────────────────────┼────────────────────────────────────────────────────┘
                                 ▼  only allowlisted + inspected requests leave
        api.anthropic.com   registry.npmjs.org (GET only)   github.com/your-org/*
```

## Boundary A — the microVM

**The microVM contains code execution: the whole agent process tree runs behind its own
guest kernel.** The cross-platform runtime, per OS:

| | macOS (Apple Silicon) | Linux |
|---|---|---|
| Hypervisor | Hypervisor.framework (HVF) | KVM |
| microVM runtime | microsandbox (libkrun/HVF), or Lima / Tart / Apple `container` | Firecracker / Cloud Hypervisor / Kata, or microsandbox (libkrun/KVM) |
| FS share | virtiofs | virtiofs / 9p |
| Guest image | one minimal Linux image, identical on both OSes | same |

A session keeps one warm VM, because agent workspaces are stateful. The cloned repo,
`node_modules`, and build caches survive between turns, and `claude --resume` works. An
ephemeral VM per command suits code-interpreter semantics only, so the one-shot
`silkgate run` keeps that shape for scripts that want no residue.

Mounts are user-chosen, each guarded, and read-only by default. `-v SRC:DST[:ro|rw]`
(repeatable) mounts host directory SRC at guest DST via virtiofs, read-only unless the spec
says `:rw`. The git modes shape their own mounts: `--checkout` mounts just the host gitdir,
read-only at `/silkgate/base.git` — the guest's worktree is its own rootfs, holds committed
content only, and dies with the VM — and `--branch` adds a workspace derived under the
repo's `.silkgate/sandboxes/`, mounted read-write. With LFS in use, the host LFS store is
writable in either mode. The CLI refuses any mount that hands the guest the host itself
(`/`, `$HOME`, silkgate's own checkout and state), and refuses a read-write mount that
holds a `.git` directory — hooks and `core.fsmonitor` there are host code execution the
next time a human runs git in it. A linked worktree's `.git` file is allowed, with a
printed note. Guest-side, a DST is refused when it is relative, when it is `/`, when it
sits at, under, or above silkgate's own guest paths (`/silkgate`, `/root/lfsstore`,
`/root/gitdir`), and when it duplicates or nests under another mount's DST. Nested
virtiofs behavior is unverified, so it is refused rather than trusted. The full mount
rules live in the [README](../README.md).

## Boundary B — the proxy

**The proxy contains data movement: it runs on the host, outside the VM, as the guest's only
gateway.** This is the piece neither Claude Code nor Codex ships.

1. It terminates TLS. A private CA is generated once. The certificate (public) goes into the
   guest trust store and the language env vars (`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
   `SSL_CERT_FILE`, `GIT_SSL_CAINFO`, `PIP_CERT`). The private key never leaves the host.
   Because the proxy decrypts, domain fronting dies — it rejects any request whose SNI and
   Host disagree — and broad-domain exfiltration shrinks, because the proxy can allow
   `GET github.com/your-org/…` while it blocks pushes, gists, and large POSTs.
2. The allowlist is per request, not per domain. An example policy for a coding agent:

   | Upstream | Allowed | Blocked |
   |---|---|---|
   | `api.anthropic.com` | POST `/v1/messages` (key injected) | everything else |
   | `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org` | `GET` (download) | `PUT`/`POST` (publish) |
   | `github.com` / `*.github.com` | clone and fetch your org's repos | pushes, gists, arbitrary repos, large uploads |
   | everything else | — | denied and logged |

3. It injects secrets the guest never holds. The guest's LLM client points at the proxy with
   a dummy key, and the proxy attaches the real credential from the host for the allowlisted
   route. Full code execution in the guest cannot steal the API key, because the key is not
   there. One rule carries this guarantee: the proxy decides the route from the address it
   will dial, never from request contents that the guest controls. An earlier version
   matched on the guest's `Host:` header, and any request that named an allowlisted host
   received the credential. `test/test_addon.py` covers the destination check.
4. DNS is the proxy's, not the guest's. With an explicit `HTTPS_PROXY`, the guest sends
   hostnames and the proxy resolves them. Port 53 traffic never leaves the VMM — see
   [THREAT-MODEL.md](./THREAT-MODEL.md), Tier 1.
5. It logs every decision: one allow or deny line per request, never bodies, never a
   credential value. Each record is mirrored into a machine-only events file, and
   `silkgate ui` serves a live view over those files. [PROXY.md](./PROXY.md) specifies the
   record fields, the events-file contract, and retention.

## The four flows

**Four flows show how the two boundaries compose.**

| Flow | Path | What contains it |
|---|---|---|
| LLM call | guest → proxy → `api.anthropic.com` | The guest sends a dummy key and the proxy injects the real one. The key survives full guest compromise, because the guest never holds it. |
| `npm install` | guest → proxy → `GET registry.npmjs.org` | A malicious postinstall runs inside the VM, contained, and reaches nothing except the inspected proxy. |
| Exfiltration under prompt injection | guest → proxy → denied | There is no `~/.ssh` in the guest — the only host paths are the mounts the user chose, each guarded and read-only by default, and a `--checkout` guest holds committed content only, so an untracked `/workspace/.env` never entered it. A POST of a secret that was handed in to `evil.com` is denied (not allowlisted), and to `github.com` is blocked on method, size, or SNI-Host mismatch. Two independent failures are required. |
| Git push | guest commits → human reviews → host pushes | The safest default: the agent commits inside the VM and the human pushes after review. For autonomy, the `github-write:OWNER/REPO` profile grants push to that one repository, with the PAT injected and the body capped (`max_body`). No SSH keys exist in the guest. |

## The agent's channel back to the parent

**A guest command's stdio is the channel to whoever drives it: a process pipe, not network
egress, so it never touches the proxy boundary.** The CLI relays it live with stdout and
stderr apart — a convenience, not a property, because the split rides an in-band tag the
guest can write itself. A human attaches the TUI with `silkgate attach`. A parent agent runs
`silkgate exec <name> -- claude -p --output-format stream-json` and parses the stream
([README](../README.md#persistent-sessions)). With a Console API key injected at the proxy,
both modes work. Interactive Claude Code also probes `platform.claude.com/v1/oauth/hello` at
startup and fails only if that host is blocked, so interactive runs allowlist
`platform.claude.com/v1/oauth/**`.

## The session model

**Sessions share one proxy process, and each session's listener port is its spoof-proof
identity.** Each guest's Tier-1 rule allows only its own port, so the port a request arrives
on proves which session sent it, below the guest. The proxy maps that port to the session's
ruleset snapshot and fails closed on any gap. [PROXY.md](./PROXY.md) specifies the port
pool, the control socket, the secrets flow, and the on-disk layout.

## The capture trail

**Capture is observability, never enforcement: a rule that opts in gets its response
bodies decoded and recorded, and no capture failure can change a flow.** A
`capture=<format>` option on a rule ([DSL.md](./DSL.md)) feeds a decoder from the proxy's
response tap. The decoder writes `turn_start`, `content_block` and `turn_end` records to
the file named by `SILKGATE_EGRESS_CAPTURE_FILE`, joined to the audit trail by flow id.
The CLI stamps `X-Silkgate-Exec` on an exec's API traffic, and the proxy strips it at the
boundary. Each captured turn therefore names the exec that sent it. Thinking blocks are
recorded as lengths only. A secret match is stored redacted, with a `secret_sighting`
record that names the pattern and never the value. Every capture failure is fail-open:
the flow, its byte counts and its audit record are unchanged. A captured flow enriches
the audit response record with model, token counts and stop reason, and every allowed
flow carries `ttfb_ms`. Proof: `test/test_cli_journal.py` pins the capture-file wiring
and its retention, and the addon's own tests pin the decoder.

## The session archive

**A session that silkgate hands over ends in the archive, never in silent deletion.** At
teardown the CLI snapshots the guest's last output, journals the `down` event, stamps
`ended` into `meta.json`, and renames the session directory to
`~/.silkgate/archive/<sid>/`. The rename is atomic because the archive and the session
registry share one filesystem. The sid packs a UTC stamp, the session name and six random
hex characters, so a plain name sort is a time sort. An archived session holds these
files:

| File | Content |
|---|---|
| `meta.json` | the session's meta, plus `sid`, `ended` and `last_rc` when an exec recorded one |
| `rules.txt` | the composed ruleset text the proxy enforced |
| `journal.jsonl` | one JSON record per event: `created`, `exec_start`, `exec_end`, `harvest`, `frozen`, `resumed`, `killed`, `down` |
| `output.log` | the last 20000 lines of guest output, at most 8 MiB; `SILKGATE_SNAPSHOT_TAIL_LINES` and `SILKGATE_SNAPSHOT_MAX_BYTES` override the two bounds |
| `brief.md` | the session-default brief (`up --brief`), when one was given |
| `briefs/<exec_id>.md` | the brief each exec ran under (its own `--brief`, or the session default), at most 1 MiB each |

The archive is bookkeeping and therefore fail-open: a failed snapshot or rename warns and
the teardown completes. Sandbox removal stays fail-closed: an unremovable sandbox keeps
its session and the command dies. `silkgate ls -a` lists archives, and the audit UI reads
them. Proof: `test/test_cli_journal.py` pins the layout, the record order and both
failure rules.

## What the journal records

**The journal records what the operator asked for and never a secret's value.** An exec's
`argv` contains the operator's prompt, and that record is the feature: the journal exists
to reconstruct a session after it ends. Environment variables appear as names only,
because values can hold credentials. The journal file carries mode 0600. The guest cannot
read the journal or the archive: both live under `~/.silkgate` on the host, and silkgate
refuses every mount of that directory. Proof: `test/test_cli_journal.py` pins the
names-only rule and the file mode.

## Retention

**Silkgate removes an old file only when it is both beyond the newest-count guard and
older than its age knob.** One rule covers audit logs, capture files and archived
sessions. A knob at 0 or less turns retention off for its own kind alone. Silkgate
announces every removal.

| Kind | Age default | Count guard | Knob |
|---|---|---|---|
| `proxy-*.log`, `proxy-*.rules`, `standalone-*.rules`, `events-*.jsonl` | 30 days | newest 20 per kind | `SILKGATE_LOG_RETAIN_DAYS` |
| `capture-*.jsonl` | 7 days | newest 20 | `SILKGATE_CAPTURE_RETAIN_DAYS` |
| `archive/<sid>/` | 30 days | newest 50 | `SILKGATE_ARCHIVE_RETAIN_DAYS` |

The files a live proxy writes never go: `proxy.json` names them and the prune checks it.
Capture files keep a shorter default because they hold conversation content, which is
bulkier and more sensitive than audit metadata. Proof: `test/test_cli_journal.py` and
`test/test_cli_logs.py` pin both halves of the rule.

## The audit UI

**The `silkgate ui` server carries no auth, by decision: the 127.0.0.1 bind is the
boundary.** Only processes on the host can connect, and a guest's Tier-1 rules allow only
its own proxy port, so no guest reaches it. The server must never bind beyond loopback.
For remote use, open an SSH tunnel to the loopback port. A future `--bind` flag requires
token auth first. Inside the boundary, the server still refuses what a hostile web page
can send through the operator's own browser: every request must carry a loopback `Host`
header, and a present `Origin` header must be loopback too. Browsers always send `Origin`
on a cross-origin POST. Every control endpoint (freeze, resume, down, kill, diff) is
POST-only, so a cross-site page cannot drive one. Proof: `test/test_ui.py` pins the
matrix.

## Tier 1 enforcement

**Tier 1 needs no nested VM, no `pf`, and no `nft`: microsandbox terminates the guest's
network in its own host-side stack, under a default-deny policy.** Every frame the guest
emits ends in that stack, whatever guest-root does, and policy runs before any real socket
opens. Only a hypervisor escape bypasses it. [THREAT-MODEL.md](./THREAT-MODEL.md) holds the
full mechanism, the DNS story, the ranked fallbacks, and the live-verification record
(15/15 checks on both OSes, three outside oracles, a negative control).

## Concrete stack

**Every part is reused or synthesized — nothing security-critical is hand-rolled.**

- Proxy: mitmproxy plus a small addon ([DSL.md](./DSL.md), [`mitmaddon/`](../mitmaddon/)).
  Do not hand-roll TLS interception. Reuse mitmproxy, and keep the rule engine
  dependency-free.
- microVM: microsandbox for one tool on both OSes (Apache 2.0, libkrun), or Lima plus
  Firecracker for maturity.
- Guest image: nothing hand-written. A base distro image plus one layer per profile,
  synthesized at build time and cached by a hash of its inputs, so image and policy are
  declared once, together. Agent harnesses are profiles too: nothing agent-specific is
  baked into the base ([README](../README.md#profiles)).

## Hardening checklist

**A hardened deployment satisfies every line below.**

- [ ] The whole agent process tree runs inside the guest. The host runs only the CLI and
      the proxy.
- [ ] Only user-chosen virtiofs mounts, each guarded, read-only by default — or a
      `--checkout` guest whose worktree is guest-local, committed content only. No
      credentials or dotfiles mounted.
- [ ] Guest egress is default-deny with only the session's proxy port reachable, DNS
      included, enforced outside the guest (Tier 1).
- [ ] Private CA: certificate in the guest trust store and all language env vars. The
      private key stays host-only.
- [ ] The proxy enforces SNI==Host and the per-request method, path, header, body, and
      query constraints, and writes the audit log.
- [ ] LLM and git secrets are injected by the proxy, never written into the guest.
- [ ] Package registries are download-only. Publish is blocked.
- [ ] Git push is gated on human review, or repo-scoped and size-capped.
- [ ] Hypervisor and guest kernel are patched. This is the residual escape surface.

## Residual risks

**Six risks survive both boundaries. Name them, and do not pretend the design closes them.**

- Hypervisor escape. A KVM, HVF, or virtio CVE breaks Boundary A. Patch, keep the device
  model minimal, and accept that this cannot be eliminated.
- Exfiltration within an allowed channel. `max_body` caps each request body, and every
  decision is logged. Nothing inspects content, caps responses, or budgets across requests,
  so a guest can leak through any allowed POST one capped body at a time. The strongest
  lever is a tighter allowlist.
- DNS tunneling. Closed: the guest does no external DNS, and the VMM answers port 53 itself
  ([THREAT-MODEL.md](./THREAT-MODEL.md)).
- Mount tampering. Malicious code can corrupt files on a read-write mount. Mounts are
  read-only unless asked otherwise, a `--checkout` guest touches no host file at all, and a
  human reviews diffs before push.
- LFS store bytes on the host. With LFS in use, `.git/lfs` is host-writable from `--branch`
  and `--checkout` guests, and `.git/lfs/logs` is not content-addressed — `git lfs logs
  last` renders guest-written bytes in a host terminal. An availability and
  terminal-rendering risk, never content substitution: SHA-256 verifies objects on read.
- Shared MITM CA. By design the proxy reads all guest TLS. That is fine — you own both
  ends — but do not reuse that CA anywhere else.
