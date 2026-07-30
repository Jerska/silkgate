# Egress proxy POC

TLS-terminating egress proxy for a sandboxed, adversarial coding agent, **macOS-first**
(Apple Silicon). Two enforcement layers:

- **Tier 1 — force all egress to the proxy (outside the guest):** microsandbox's own
  host-side network policy. No nft, no pf, no nested VM.
- **Tier 2 — per-request inspection:** the mitmproxy addon + the DSL rule engine.

Design docs: [../ARCHITECTURE.md](../ARCHITECTURE.md) · [../THREAT-MODEL.md](../THREAT-MODEL.md) · [../DSL.md](../DSL.md)

## Files
- `rule_engine.py` — dependency-free DSL parser + host/path normalizer + matcher (`python3 rule_engine.py` self-tests)
- `proxy_addon.py` — mitmproxy addon: SNI==Host, allowlist, header/body/query enforcement, secret injection, fail-closed, audit log
- `rules.txt` — the allowlist · `rules.verify.txt` — allowlist + Debian mirrors, for the "full check" only
- `verify_guest.sh` — Tier-1 verification, run as root inside the guest
- `Dockerfile` + `rules.agent.txt` — Step 5: a Claude Code guest image + its headless allowlist
- `rules.interactive.txt` — Step 5 (interactive): adds `platform.claude.com` for the TUI's startup probe

> ⚠️ microsandbox is pre-1.0 (verified against **v0.5.7**, repo `superradcompany/microsandbox`,
> formerly `microsandbox/microsandbox`). Flags can shift — confirm with `msb run --help`.

## Step 1 — engine tests (no deps)
```sh
python3 rule_engine.py        # -> "54/54 passed"
```

## Step 2 — run the proxy (host)
```sh
pip install mitmproxy
cp ~/.mitmproxy/mitmproxy-ca-cert.pem egress-ca.pem    # CA the guest will trust (created on first mitmproxy run)
export EGRESS_RULES=rules.txt                          # no real LLM key needed for the verification
mitmdump -s proxy_addon.py --listen-port 8090
```

## Step 3 — install & start microsandbox (host, Apple Silicon only)
```sh
curl -fsSL https://install.microsandbox.dev | sh       # or: brew install superradcompany/tap/microsandbox
msb server start --dev                                 # required for the server-backed path; harmless otherwise
```

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
  -- bash /mnt/poc/verify_guest.sh
```
Expect: `3. direct TCP egress blocked` (and `7. still blocked after root route change` if
`ip` is present). DNS is already denied: `--net-default-egress deny` grants no UDP/53, and
microsandbox intercepts all UDP/53 at its gateway, so external names can't resolve; the proxy
alias resolves via the guest's `/etc/hosts`. So do **not** add `allow@host:udp:53` (it would
re-open DNS). An explicit `deny@any:udp:53,…` is a no-op here — only worth it under default-allow.

### Full check — also exercises the proxy path (checks 1 & 2)
Run the proxy with the verify ruleset so `apt` can fetch test tools **through** the proxy:
```sh
# host: restart the proxy with mirrors allowed
EGRESS_RULES=rules.verify.txt mitmdump -s proxy_addon.py --listen-port 8090
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
cp /mnt/poc/egress-ca.pem /usr/local/share/ca-certificates/egress.crt && update-ca-certificates
bash /mnt/poc/verify_guest.sh
```
(If `apt` fails on a TLS/cert error, the image's sources use https before the CA is trusted —
switch them to `http://deb.debian.org` or pre-trust the CA. Default Debian 12 uses http.)

### Reading the result
- **Pass = checks 1 & 2 succeed (when run) and 3–7 are all blocked.** `RESULT: N passed, 0 failed`.
- #3 runs as root (no direct egress) and #7 confirms a root guest re-adding its default route
  still can't get out — enforcement sits in the host stack below the guest NIC. If any of 3–7
  succeed, the boundary leaks → fall back per ARCHITECTURE.md.
- **Verified 7/7 on macOS (Apple Silicon)** (`iproute2` installed for #7). Now **pin your `msb --version`** and the exact flags here.

## Step 5 — run Claude Code inside the guest (real agent + key injection)
Build a guest image with Node + Claude Code + the CA, load it into msb, and run it egress-locked.
The agent reaches **only** `api.anthropic.com`; the real key lives on the host and is injected by
the proxy, so the guest holds only a dummy.

```sh
# host: build for Apple Silicon and load into the msb cache (no registry needed)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem egress-ca.pem
docker build --platform linux/arm64 -t claude-sandbox:poc .
docker save claude-sandbox:poc | msb load
```
```sh
# host: run the proxy with the agent ruleset + the REAL key (key exists only here)
export EGRESS_RULES=rules.agent.txt
export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"     # your real Anthropic key
mitmdump -s proxy_addon.py --listen-port 8090
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
- To *see* the deny path, drop `DISABLE_TELEMETRY=1` from the `Dockerfile` and rebuild: statsig/
  sentry requests show up as `deny … no matching rule` while the agent still works.
- For real work, mount a project: add `-v "$PWD/project:/workspace:rw"` and use a task prompt
  with `--permission-mode acceptEdits`.

> Verify against your build: `--bare` / `--permission-mode` flags and the disable-traffic env
> vars are current per Claude Code docs (2026-06) but pre-confirm with `claude --help`. Claude
> Code honors `HTTPS_PROXY`; if a call instead fails closed, that's the L3 lock working — check
> the proxy is reachable on `host.microsandbox.internal:8090`.

### Interactive mode (TUI) — same key, one extra host
The interactive TUI works with the **same org/Console API key** — no `setup-token`/OAuth (that's
Max/Pro-gated and unneeded). It only adds a startup probe to `platform.claude.com/v1/oauth/hello`
(a Console account check) that must *reach* the host, so run with `rules.interactive.txt` (which
allowlists `platform.claude.com/v1/oauth/**`) and a PTY (`-t`), no `-p`:
```sh
EGRESS_RULES=rules.interactive.txt EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…" \
  mitmdump -s proxy_addon.py --listen-port 8090
msb run claude-sandbox:poc --pull never -t \
  -e HTTPS_PROXY=http://host.microsandbox.internal:8090 -e HTTP_PROXY=http://host.microsandbox.internal:8090 \
  --net-default-egress deny --net-rule "allow@host:tcp:8090" \
  -- claude
```
`msb run`'s stdio is the channel back to the parent: `-t` gives you the TUI; a parent **agent**
instead drops `-t` and drives `claude -p --output-format stream-json` (one-shot per turn,
`--resume <id>` to continue), reading the structured event stream.

## Notes / residual (see THREAT-MODEL.md Tier 3)
- The proxy decrypts via a private CA you own; don't reuse that CA elsewhere.
- Allowlisted destinations remain exfil carriers — keep `rules.txt` minimal, never allowlist a
  header/body-reflecting endpoint, prefer download-only (GET). Remove the mirror lines from
  `rules.verify.txt` use once verification is done.
