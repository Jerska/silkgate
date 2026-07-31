# Silkgate

TLS-terminating egress proxy for a sandboxed, adversarial coding agent. Verified live on
**macOS (Apple Silicon)** and **Linux (x86_64/KVM)**. Two enforcement layers:

- **Tier 1 — force all egress to the proxy (outside the guest):** microsandbox's own
  host-side network policy. No nft, no pf, no nested VM.
- **Tier 2 — per-request inspection:** the mitmproxy addon + the DSL rule engine.

Design docs: [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) · [doc/THREAT-MODEL.md](doc/THREAT-MODEL.md) · [doc/DSL.md](doc/DSL.md)

## Quickstart (CLI)

The CLI automates Steps 1–5 below (prereqs: `pip install mitmproxy`, docker, msb — Step 3):
```sh
./cli/silkgate build                     # guest image + mitmproxy CA, loaded into msb
./cli/silkgate verify                    # Tier-1 containment check (add --full for the proxy path)
export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"    # host-only; never enters the guest or argv
./cli/silkgate run                       # interactive Claude Code, egress-locked (one-shot)
./cli/silkgate run --workspace ~/projects/foo -- claude --bare -p "task…"
```
The proxy audit log path is printed at startup (`tail -f` it to watch allow/deny decisions).
`--preset`/`--rules` compose allowlists; `silkgate proxy` runs just the proxy for manual setups.

### Persistent sessions (multi-turn agents)

`run` is **one-shot**: it boots a microVM, runs one command, tears it down. So each turn pays a VM
boot and `claude --resume` can't work across turns — the VM, and `/root/.claude` with it, is gone.
A **session** is a warm background microVM plus a dedicated proxy port; every turn is an `exec` into
the *same* VM, so its state (cloned repo, `node_modules`, `/root/.claude`) persists and `--resume`
works. One shared proxy serves all sessions, one port each.

```sh
export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"   # host-only; pushed to the proxy over a socket
./cli/silkgate up --name foo --workspace ~/projects/foo   # warm VM + a proxy port; starts the
                                                          # shared proxy if it isn't running yet
./cli/silkgate exec foo -- claude -p "scaffold a Flask app" --output-format json
# ↑ prints a session_id; the VM persists, so resume that conversation on the next turn:
./cli/silkgate exec foo -- claude -p --resume <id> "add a /health route and a test"
./cli/silkgate attach foo                    # same VM, interactive TUI (defaults to claude)
./cli/silkgate ls                            # sessions (status/port/workspace/age) + proxy health
./cli/silkgate down foo                      # stop + rm the VM, free the port; last out stops the proxy
```

A guest command's output arrives **live**, with its stdout and stderr on separate streams, so a
parent can watch a task and still parse a captured `stream-json` — `run` and `exec` relay it out
of the microVM as it is written. `-t` instead hands the command a real terminal, which changes how
it behaves (colors, cursor control, both streams merged into the terminal), so keep it for a TUI
and leave it off for anything you intend to parse. To watch a session you did not start in the
foreground, or to see only its egress decisions:
```sh
./cli/silkgate logs foo -f            # the guest's output, live
./cli/silkgate logs foo --audit -f    # just this session's allow/deny lines
```

`up` pushes every `EGRESS_SECRET_<NAME>` a session's `inject_auth` rules need, and refuses to start
if one is neither in your environment nor already held by the running proxy — so a secret pushed
once serves later sessions started from a shell that never had it. Add or rotate a secret on the running shared proxy with `silkgate secret set
anthropic` — it reads `EGRESS_SECRET_ANTHROPIC` from the environment; the value is **never** an
argument. `silkgate secret ls` lists names only, never values. `silkgate run` is now just `up` →
`exec` → `down` around an ephemeral auto-named session (so its `--port` sets the shared-proxy base
port when it's the command that starts the proxy).

## Layout
- `mitmaddon/rule_engine.py` — dependency-free DSL parser + host/path normalizer + matcher (`python3 mitmaddon/rule_engine.py` self-tests)
- `mitmaddon/proxy_addon.py` — mitmproxy addon: SNI==Host, allowlist, header/body/query enforcement, secret injection, fail-closed, audit log; single-tenant (`EGRESS_RULES`) or multi-session (`EGRESS_SESSIONS_DIR` + the unix control socket)
- `mitmaddon/presets/` — composable allowlists; colon-separate paths in `EGRESS_RULES` to combine them.
  `claude.txt` covers both headless and interactive Claude Code (it includes the TUI's
  `platform.claude.com` startup probe); `debian.txt` is for the "full check" only
- `test/verify_guest.sh` — Tier-1 verification, run as root inside the guest
- `image/Dockerfile` — Step 5: a Claude Code guest image
- `cli/silkgate` — host control CLI (`build` / `verify` / `proxy` / `run` / `up` / `exec` / `attach` / `logs` / `down` / `ls` / `secret`), stdlib-only Python

Host state lives under `~/.silkgate/` (created on first `run`/`up`):
- `~/.silkgate/proxy.json` — shared-proxy metadata: pid, base port, the port pool, log path, socket path, start time
- `~/.silkgate/proxy.sock` — unix control socket (mode 0600) the CLI uses to push secrets and check health; unreachable from any guest
- `~/.silkgate/sessions/<name>/` — per-session state: `meta.json` (sandbox `sg-<name>`, assigned port, image, workspace, created) + `rules.txt` (the composed ruleset snapshot for that session)
- `~/.silkgate/logs/proxy-*.log` — proxy audit log (allow/deny decisions), existing location/format

All commands below run from the repo root.

> ⚠️ microsandbox is pre-1.0 (verified against **v0.5.4/v0.5.7 on macOS** and **v0.6.8 on
> Linux**, repo `superradcompany/microsandbox`, formerly `microsandbox/microsandbox`; the
> `--net-*` flags were identical across all three). Flags can shift — confirm with `msb run --help`.

## Step 1 — engine tests (no deps)
```sh
python3 mitmaddon/rule_engine.py        # -> "54/54 passed"
```

## Step 2 — run the proxy (host)
```sh
pip install mitmproxy
cp ~/.mitmproxy/mitmproxy-ca-cert.pem image/egress-ca.pem    # CA the guest will trust (created on first mitmproxy run)
export EGRESS_RULES=mitmaddon/presets/npm.txt                # what verify_guest.sh probes; no real LLM key needed
mitmdump -s mitmaddon/proxy_addon.py --listen-port 8090
```

## Step 3 — install & start microsandbox (host)
```sh
curl -fsSL https://install.microsandbox.dev | sh       # or: brew install superradcompany/tap/microsandbox
msb server start --dev                                 # required for the server-backed path; harmless otherwise
```

**Linux:** you need rw access to `/dev/kvm` (usually membership in the `kvm` group), and the
msb release binaries need **glibc ≥ 2.39** (check `ldd --version`; they're built on Ubuntu
24.04). On older hosts, run the proxy + msb inside the `test/linux/` container instead —
`/dev/kvm` is passed through, so the microVM boundary is the host kernel's KVM either way:
```sh
docker build -t silkgate-verify test/linux/
docker run --rm --device /dev/kvm -v "$PWD:/silkgate" silkgate-verify \
  /silkgate/cli/silkgate verify --full
```
(Add `--network=host` to both commands if DNS fails inside containers — common when the host's
`resolv.conf` points at a localhost stub resolver.)

## Step 4 — launch the Debian guest with Tier 1, then verify
microsandbox runs standard OCI images, so `debian` is pulled from Docker Hub on first use.
Mount this dir (`-v`), set the proxy env (`-e`), and lock egress to the proxy only.

### Quick containment check — one command, no tools needed in the guest
The bash `/dev/tcp` checks (3 & 7) prove a root guest has no direct egress; they need nothing
installed. (curl/dig/ping checks SKIP on a bare image — that's expected here.)
```sh
msb run debian \
  -v "$PWD:/mnt/poc:ro" \
  -e HTTPS_PROXY=http://host.microsandbox.internal:8090 \
  -e HTTP_PROXY=http://host.microsandbox.internal:8090 \
  --net-default-egress deny \
  --net-rule "allow@host:tcp:8090" \
  -- bash /mnt/poc/test/verify_guest.sh
```
Expect: `3. direct TCP egress blocked` (and `7. still blocked after root route change` if
`ip` is present). DNS is already denied: `--net-default-egress deny` grants no UDP/53, and
microsandbox intercepts all UDP/53 at its gateway, so external names can't resolve; the proxy
alias resolves via the guest's `/etc/hosts`. So do **not** add `allow@host:udp:53` (it would
re-open DNS). An explicit `deny@any:udp:53,…` is a no-op here — only worth it under default-allow.

### Full check — also exercises the proxy path (checks 1 & 2)
Run the proxy with the Debian mirrors allowed so `apt` can fetch test tools **through** the proxy:
```sh
# host: restart the proxy with mirrors allowed
EGRESS_RULES=mitmaddon/presets/npm.txt:mitmaddon/presets/debian.txt \
  mitmdump -s mitmaddon/proxy_addon.py --listen-port 8090
```
```sh
# host: open an interactive root shell in the guest
msb run debian -t --shell /bin/bash \
  -v "$PWD:/mnt/poc:ro" \
  -e HTTPS_PROXY=http://host.microsandbox.internal:8090 -e HTTP_PROXY=http://host.microsandbox.internal:8090 \
  -e https_proxy=http://host.microsandbox.internal:8090 -e http_proxy=http://host.microsandbox.internal:8090 \
  --net-default-egress deny --net-rule "allow@host:tcp:8090"
```
```sh
# inside the guest (apt reaches the mirrors via the proxy; then trust the MITM CA):
apt-get update && apt-get install -y curl ca-certificates dnsutils iputils-ping
cp /mnt/poc/image/egress-ca.pem /usr/local/share/ca-certificates/egress.crt && update-ca-certificates
bash /mnt/poc/test/verify_guest.sh
```
(If `apt` fails on a TLS/cert error, the image's sources use https before the CA is trusted —
switch them to `http://deb.debian.org` or pre-trust the CA. Default Debian 12 uses http.)

### Reading the result
- **Pass = checks 1 & 2 succeed (when run) and 3–7 are all blocked.** `RESULT: N passed, 0 failed`.
- #3 runs as root (no direct egress) and #7 confirms a root guest re-adding its default route
  still can't get out — enforcement sits in the host stack below the guest NIC. If any of 3–7
  succeed, the boundary leaks → fall back per doc/ARCHITECTURE.md.
- **Verified 7/7 on macOS (Apple Silicon) and on Linux (x86_64/KVM, via `test/linux/`)**
  (`iproute2` installed for #7). Now **pin your `msb --version`** and the exact flags here.

## Step 5 — run Claude Code inside the guest (real agent + key injection)
Build a guest image with Node + Claude Code + the CA, load it into msb, and run it egress-locked.
The agent reaches **only** `api.anthropic.com`; the real key lives on the host and is injected by
the proxy, so the guest holds only a dummy.

```sh
# host: build for Apple Silicon and load into the msb cache (no registry needed)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem image/egress-ca.pem
docker build --platform linux/arm64 -t claude-sandbox:poc image/
docker save claude-sandbox:poc | msb load
```
```sh
# host: run the proxy with the claude preset + the REAL key (key exists only here)
export EGRESS_RULES=mitmaddon/presets/claude.txt
export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"     # your real Anthropic key
mitmdump -s mitmaddon/proxy_addon.py --listen-port 8090
```
```sh
# host: run Claude Code in the guest, egress locked to the proxy
msb run claude-sandbox:poc --pull never \
  -e HTTPS_PROXY=http://host.microsandbox.internal:8090 \
  -e HTTP_PROXY=http://host.microsandbox.internal:8090 \
  --net-default-egress deny \
  --net-rule "allow@host:tcp:8090" \
  -- claude --bare -p "Say hello in exactly five words."
```

### What a pass looks like
- Claude Code prints a real five-word answer → the call succeeded **even though the guest holds
  only a dummy key**: the proxy injected the real `x-api-key`. That's the inject_auth proof.
- The proxy audit log shows `allow … api.anthropic.com /v1/messages`. Confirm the guest has no
  real key: `msb run claude-sandbox:poc --pull never -- printenv ANTHROPIC_API_KEY` → the dummy.
- To *see* the deny path, drop `DISABLE_TELEMETRY=1` from `image/Dockerfile` and rebuild: statsig/
  sentry requests show up as `deny … no matching rule` while the agent still works.
- For real work, mount a project: add `-v "$PWD/project:/workspace:rw"` and use a task prompt
  with `--permission-mode acceptEdits`.

> Verify against your build: `--bare` / `--permission-mode` flags and the disable-traffic env
> vars are current per Claude Code docs (2026-06) but pre-confirm with `claude --help`. Claude
> Code honors `HTTPS_PROXY`; if a call instead fails closed, that's the L3 lock working — check
> the proxy is reachable on `host.microsandbox.internal:8090`.

### Interactive mode (TUI) — same key, same preset
The interactive TUI works with the **same org/Console API key** — no `setup-token`/OAuth (that's
Max/Pro-gated and unneeded). It only adds a startup probe to `platform.claude.com/v1/oauth/hello`
(a Console account check) that must *reach* the host — the `claude.txt` preset already allowlists
`platform.claude.com/v1/oauth/**`. Run with a PTY (`-t`), no `-p`:
```sh
EGRESS_RULES=mitmaddon/presets/claude.txt EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…" \
  mitmdump -s mitmaddon/proxy_addon.py --listen-port 8090
msb run claude-sandbox:poc --pull never -t \
  -e HTTPS_PROXY=http://host.microsandbox.internal:8090 -e HTTP_PROXY=http://host.microsandbox.internal:8090 \
  --net-default-egress deny --net-rule "allow@host:tcp:8090" \
  -- claude
```
`msb run`'s stdio is the channel back to the parent: `-t` gives you the TUI; a parent **agent**
instead drops `-t` and drives `claude -p --output-format stream-json`, reading the structured
event stream. One `msb run` is one turn — session state dies with the VM, so `--resume` fails
across runs; multi-turn needs a long-lived guest — which is exactly what sessions provide
(see [Persistent sessions](#persistent-sessions-multi-turn-agents) above).

## Notes / residual (see doc/THREAT-MODEL.md Tier 3)
- The proxy decrypts via a private CA you own; don't reuse that CA elsewhere.
- Allowlisted destinations remain exfil carriers — keep the combined ruleset minimal, never
  allowlist a header/body-reflecting endpoint, prefer download-only (GET). Drop
  `presets/debian.txt` from `EGRESS_RULES` once verification is done.
