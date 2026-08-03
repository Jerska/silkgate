# Silkgate

Run an untrusted coding agent — or any untrusted command — in a microVM whose **only** route to
the network is a TLS-terminating proxy that allowlists per request. Verified live on **macOS
(Apple Silicon)** and **Linux (x86_64/KVM)**. Two enforcement layers, both outside the guest:

- **Tier 1 — force all egress to the proxy:** microsandbox's own host-side network policy. No
  nft, no pf, no nested VM.
- **Tier 2 — per-request inspection:** the mitmproxy addon + the DSL rule engine.

Design docs: [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) · [doc/THREAT-MODEL.md](doc/THREAT-MODEL.md) · [doc/DSL.md](doc/DSL.md)

## Quickstart

Prereqs: `pip install mitmproxy`, docker, and msb (see [Installing microsandbox](#installing-microsandbox)).

```sh
./cli/silkgate profiles                    # what capabilities are available
./cli/silkgate verify                      # Tier-1 containment check (--full for the proxy path)
export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"   # host-only; never enters the guest or argv
./cli/silkgate run --with claude --workspace ~/projects/foo -- \
  claude --bare -p "task…" --permission-mode bypassPermissions
```

That single `--with claude` decides two things: the **image** (built on first use, then cached)
and the **egress policy** (only `api.anthropic.com` and the Console probe, with the real key
injected at the proxy). The audit log path is printed at startup — `tail -f` it, or use
`silkgate logs`, to watch allow/deny decisions.

## Profiles

A profile is one capability, and it owns both halves of that capability:

```
profiles/node/
  profile.conf     description, default_version, packages, requires, command
  setup.sh         how to install it — runs at image build time, as root, with $VERSION
  rules.txt        what it may reach at run time — enforced by the proxy
  env              optional KEY=VALUE lines baked into the image
```

`packages` are distro packages, and every profile's are installed in **one** transaction
before any `setup.sh` runs: apt resolves them together, shared dependencies land once, and no
profile carries update/clean boilerplate. `setup.sh` is then only the interesting part — often
a single pinned download, and `git` and `probe` need no script at all. A profile that wants a
package from outside the distro's repos adds that source and installs it in its own `setup.sh`.

Because one `--with` list drives both, an image cannot end up holding a tool whose traffic
nobody allowed. Compose them freely, and pin versions where it matters:

```sh
./cli/silkgate build --with node@22.11.0 --with claude@2.1.89
# -> silkgate/node-claude:f357122f17de
```

The tag's hash covers the base image, every profile's name and resolved version, and the bytes
of its `setup.sh`/`rules.txt`/`env`. Change any of them and you get a different image; change
nothing and `run`/`up` reuse the cached one. Each profile is its own docker layer, so editing
the last one in a list rebuilds only that layer.

**There is no Dockerfile in this repo.** An image is `debian:bookworm-slim` plus a silkgate
layer (the MITM CA in the trust store, the CA env vars runtimes read, `/workspace`) plus one
layer per profile — all synthesized at build time. Nothing is baked in for a particular agent,
so a different harness is just a different profile. Setup steps run inside `docker build` on
the host, which has its own network, so installing a compiler or hitting apt mirrors never
touches the proxy or the policy the session will run under.

## Persistent sessions (multi-turn agents)

`run` is one-shot: it creates a microVM, runs one command, tears it down. Boot is ~0.3s, so
that stays cheap — but `claude --resume` can't work across turns, because the VM and
`/root/.claude` are gone. A **session** keeps the VM warm and gives it a dedicated proxy port:

```sh
./cli/silkgate up --name foo --with claude --workspace ~/projects/foo
./cli/silkgate exec foo -- claude -p "scaffold a Flask app" --output-format json
# ↑ prints a session_id; the VM persists, so resume that conversation next turn:
./cli/silkgate exec foo -- claude -p --resume <id> "add a /health route and a test"
./cli/silkgate attach foo                 # same VM, interactive, runs the profile's command
./cli/silkgate ls                         # sessions (status/port/workspace/age) + proxy health
./cli/silkgate down foo                   # frees the port; last one out stops the proxy
```

One shared proxy serves every session, each on its own port out of a 16-port pool, and each
guest's Tier-1 rule allows **only its own port** — so a guest cannot reach another session's
listener, and that makes the port spoof-proof session identity. Audit lines carry the session
that produced them.

A guest command's output arrives **live**, with stdout and stderr on separate streams, so a
parent can supervise a task and still parse a captured `stream-json`. `-t` instead gives the
command a real terminal, which changes how it behaves (colors, cursor control, both streams
merged), so keep it for a TUI and leave it off for anything you intend to parse. To watch a
session you did not start in the foreground, or to see only its egress decisions:

```sh
./cli/silkgate logs foo -f            # the guest's output, live
./cli/silkgate logs foo --audit -f    # just this session's allow/deny lines
```

`up` pushes every `EGRESS_SECRET_<NAME>` the session's `inject_auth` rules need, and refuses to
start if one is neither in your environment nor already held by the running proxy — so a secret
pushed once serves later sessions started from a shell that never had it. Add or rotate one with
`silkgate secret set anthropic`, which reads `EGRESS_SECRET_ANTHROPIC` from the environment; the
value is **never** an argument. `silkgate secret ls` lists names only.

## Layout

- `profiles/<name>/` — the capabilities: setup + rules + env, as above
- `mitmaddon/rule_engine.py` — dependency-free DSL parser + host/path normalizer + matcher
  (`python3 mitmaddon/rule_engine.py` self-tests)
- `mitmaddon/proxy_addon.py` — the addon: SNI==Host, allowlist, header/body/query enforcement,
  secret injection, fail-closed, audit log. A listener port always resolves to a ruleset, either
  from a session registry (`EGRESS_SESSIONS_DIR`) or from one fixed ruleset (`EGRESS_RULES`)
- `cli/silkgate` — the host CLI (`profiles` / `build` / `verify` / `proxy` / `run` / `up` /
  `exec` / `attach` / `logs` / `down` / `ls` / `secret`), stdlib-only Python
- `test/verify_guest.sh` — the Tier-1 checks, run as root inside a guest by `silkgate verify`
- `test/linux/` — a container to run the whole thing on Linux hosts too old for the msb binaries

Host state lives under `~/.silkgate/` (created on first `run`/`up`):

- `proxy.json` — shared-proxy metadata: pid, base port, the port pool, log path, socket path
- `proxy.sock` — unix control socket (mode 0600) used to push secrets; unreachable from any guest
- `sessions/<name>/` — `meta.json` (sandbox, port, image, profiles, command, workspace) +
  `rules.txt` (the composed ruleset snapshot the proxy reads for that session)
- `ca/egress-ca.pem` — the MITM **certificate** (never the key) that images and guests trust
- `logs/proxy-*.log` — the audit log

## Installing microsandbox

```sh
curl -fsSL https://install.microsandbox.dev | sh   # or: brew install superradcompany/tap/microsandbox
```

> ⚠️ microsandbox is pre-1.0 (verified against **v0.5.4/v0.5.7 on macOS** and **v0.6.8 on
> Linux**, repo `superradcompany/microsandbox`; the `--net-*` flags were identical across all
> three). Flags can shift — confirm with `msb run --help` and pin the version you verified.

**Linux:** you need rw access to `/dev/kvm` (usually membership in the `kvm` group), and the msb
release binaries need **glibc ≥ 2.39** (check `ldd --version`; they're built on Ubuntu 24.04). On
older hosts, run the proxy + msb inside the `test/linux/` container instead — `/dev/kvm` is
passed through, so the microVM boundary is the host kernel's KVM either way:

```sh
docker build -t silkgate-verify test/linux/
docker run --rm --device /dev/kvm -v "$PWD:/silkgate" silkgate-verify \
  /silkgate/cli/silkgate verify --full
```

(Add `--network=host` to both commands if DNS fails inside containers — common when the host's
`resolv.conf` points at a localhost stub resolver.)

## Verifying containment

```sh
./cli/silkgate verify           # bare debian guest; the /dev/tcp probes need nothing installed
./cli/silkgate verify --full    # also installs probe tools *through* the proxy, then trusts the CA
```

- **Pass = the proxy-path checks succeed when run, and every direct-egress check is blocked**
  (`RESULT: N passed, 0 failed`). The quick form reports 2 passed and skips what a bare image
  can't probe; `--full` reports 7.
- Check 3 runs as root with no direct egress; check 7 re-adds a default route as root and is
  *still* blocked, which is the point — enforcement sits in the host stack below the guest NIC.
  If any of 3–7 succeed, the boundary leaks.
- DNS is denied without any extra rule: `--net-default-egress deny` grants no UDP/53, and
  microsandbox intercepts UDP/53 at its gateway, so external names can't resolve; the proxy's
  alias resolves via the guest's `/etc/hosts`. Do **not** add `allow@host:udp:53` — it would
  re-open DNS.
- **Verified 7/7 on macOS (Apple Silicon) and on Linux (x86_64/KVM, via `test/linux/`).**

## Using the proxy on its own

For a guest silkgate doesn't manage (a container, a remote VM), run one ruleset on one port:

```sh
./cli/silkgate proxy --with claude --port 8090
```

Point the workload at it with `HTTPS_PROXY`/`HTTP_PROXY`, and install `~/.silkgate/ca/egress-ca.pem`
in its trust store. Enforcement is identical; what you lose is Tier 1, so the workload must be
unable to reach the network any other way — otherwise the proxy is advisory.

## Notes / residual

- The proxy decrypts via a private CA you own; the **private key never leaves the host**, and
  nothing in silkgate hands a guest more than the certificate. Don't reuse that CA elsewhere.
- Allowlisted destinations remain exfil carriers — keep each profile's rules minimal, never
  allowlist a header- or body-reflecting endpoint, and prefer download-only (GET).
- The `probe` profile exists for `verify` only; it opens the Debian mirrors, so don't compose it
  into a real task.
