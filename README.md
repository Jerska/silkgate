# Silkgate

Run an untrusted coding agent — or any untrusted command — in a microVM whose only route to
the network is a TLS-terminating proxy that allowlists per request. Two layers enforce that,
both outside the guest:

- Tier 1 forces all egress to the proxy: microsandbox's own host-side network policy. No
  `nft`, no `pf`, no nested VM.
- Tier 2 inspects per request: the mitmproxy addon plus the rule engine.

Containment is verified live on macOS (Apple Silicon) by hand, and on Linux (x86_64/KVM,
msb 0.6.8) by CI on every push. The CI workflow runs all fifteen checks inside the
`test/linux/` container, plus three oracles outside the guest, and fails if any check merely
skipped (see [Verify containment](#verify-containment)).

## Quickstart

**Install the three prerequisites: `pip install mitmproxy`, docker, and msb** (see
[Install microsandbox](#install-microsandbox)). `./cli/silkgate doctor` names whichever are
missing, and how to install each.

```sh
./cli/silkgate profiles                    # what capabilities are available
./cli/silkgate verify                      # Tier-1 containment check (--full for the proxy path)
export SILKGATE_EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"   # host-only; never enters the guest or argv
./cli/silkgate run --with claude --workspace ~/projects/foo -- \
  claude --bare -p "task…" --permission-mode bypassPermissions
```

That single `--with claude` decides two things: the image (built on first use, then cached)
and the egress policy (only `api.anthropic.com` and the Console probe, with the real key
injected at the proxy). The audit log path prints at startup. Watch the allow and deny
decisions with `tail -f`, or with `silkgate logs`.

No `--with` and no `--rule` is legal too. The policy is then empty — the tightest sandbox
silkgate can express — and the guest can reach nothing at all.

## Documentation map

**Each document answers one question.**

- [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) — why a microVM plus a TLS-terminating proxy,
  and what each boundary guarantees. Its glossary defines guest, session, profile, Tier 1,
  and Tier 2.
- [doc/THREAT-MODEL.md](doc/THREAT-MODEL.md) — what an adversarial guest can attempt, and
  which tier stops it.
- [doc/PROXY.md](doc/PROXY.md) — how the shared proxy operates: ports, the control socket,
  secrets, the audit trail, and the layout of `~/.silkgate/`.
- [doc/DSL.md](doc/DSL.md) — how to write egress rules.
- [doc/SOTA.md](doc/SOTA.md) — what the field ships and where the gaps are (a dated research
  snapshot).
- [doc/PLUGIN.md](doc/PLUGIN.md) — how silkgate packages as a Claude Code plugin.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to set up, test, commit, and write documentation
  here.
- [AGENTS.md](AGENTS.md) — the additional instructions for agent contributors.

## Profiles

**A profile is one capability, and it owns both halves of that capability: the install step
and the egress rules.**

```
profiles/node/
  profile.conf     description, default_version, packages, requires, command
  setup.sh         how to install it — runs at image build time, as root, with $VERSION
  rules.txt        what it may reach at run time — enforced by the proxy
  env              optional KEY=VALUE lines baked into the image
```

`packages` lists distro packages, and every profile's are installed in one transaction
before any `setup.sh` runs: apt resolves them together, shared dependencies land once, and
no profile carries update or clean boilerplate. `setup.sh` is then only the part specific to
the capability — often a single pinned download, and `git` and `probe` need no script at
all. A profile that wants a package from outside the distro's repos adds that source and
installs it in its own `setup.sh`.

Because one `--with` list drives both halves, an image cannot end up with a tool whose
traffic nobody allowed. Compose profiles freely, and pin versions where it matters:

```sh
./cli/silkgate build --with node@22.11.0 --with claude@2.1.226
# -> silkgate/node-claude:f357122f17de
```

The tag's hash covers the base image, every profile's name and resolved version, and the
bytes of its `setup.sh`, `rules.txt`, and `env`. Change any of them and you get a different
image. Change nothing and `run`/`up` reuse the cached one. Each profile is its own docker
layer, so an edit to the last profile in a list rebuilds only that layer.

There is no Dockerfile in this repo. An image is `debian:bookworm-slim`, plus a silkgate
layer, plus one layer per profile — all synthesized at build time. The silkgate layer holds
the MITM CA in the trust store, the CA env vars runtimes read, and `/workspace`. Nothing is
baked in for a particular agent, so a different harness is just a different profile. Setup
steps run inside `docker build` on the host, which has its own network. A compiler install
or an apt mirror therefore never touches the proxy or the policy the session will run
under.

## The guest context

**Each session describes itself to the guest, so a cooperative agent wastes no turns on
discovery.** Without it, the agent reaches for a runtime that is not installed, or retries a
host that policy never allows. The description is generated from the session's own profiles,
ruleset, and mount, and reaches the guest two ways:

```sh
# inline, for any harness — the variable holds the text itself, not a path
./cli/silkgate exec foo -- sh -c 'claude -p "$SILKGATE_CONTEXT

Now: <task>"'
# or as a file, which Claude Code accepts even under --bare
./cli/silkgate exec foo -- claude --bare -p "<task>" --append-system-prompt-file /silkgate/CONTEXT.md
```

The file lands at `/silkgate/CONTEXT.md` in the rootfs — never in `/workspace`, so it cannot
appear in the project — plus wherever a profile's `context_path` says its harness looks for
instructions. `--no-context` skips the whole thing.

This is a courtesy, not a control. An adversarial guest ignores every word of it, so nothing
is allowed to rely on it. What it buys is fewer wasted turns, and denials reported as
requests ("I need `pypi.org` for X") instead of retried in a loop.

## Persistent sessions

**`run` is one-shot, and a session instead keeps the VM warm on a dedicated proxy port.**
`run` creates a microVM, runs one command, and tears the VM down. Boot is ~0.3 s, so that
stays cheap — but `claude --resume` cannot work across turns, because the VM and
`/root/.claude` die with the command. A session persists both:

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
guest's Tier-1 rule allows only its own port. A guest therefore cannot reach another
session's listener, which makes the port spoof-proof session identity. Audit lines carry the
session that produced them. [doc/PROXY.md](doc/PROXY.md) specifies the pool and the
identity mechanism.

A guest command's output arrives live, with stdout and stderr on separate streams, so a
parent can supervise a task and still parse a captured `stream-json`. The separation is a
convenience, not a property: it rides an in-band tag the guest can write itself, and
everything on both streams is the guest's own report. `-t` instead gives the command a real
terminal, which changes how it behaves (colors, cursor control, both streams merged). Keep
`-t` for a TUI, and leave it off for anything you intend to parse. To watch a session you
did not start in the foreground, or to see only its egress decisions:

```sh
./cli/silkgate logs foo -f            # the guest's output, live
./cli/silkgate logs foo --audit -f    # just this session's allow/deny lines
```

## Secrets

**`up` pushes every secret the session's rules need, and a missing secret warns rather than
blocks.** `up` reads each `SILKGATE_EGRESS_SECRET_<NAME>` that the session's `inject_auth`
rules name, and pushes it to the proxy, scoped to this session. A missing or malformed
secret is a warning, not a startup error: the session comes up, and the guest sees the
credential status in `/silkgate/CONTEXT.md`. How those variables reach the environment —
shell profile, a per-launch prefix on the command, a password-manager wrapper — is the
operator's choice.

Secrets are held per session, so one shared proxy never lets a later session spend a key an
earlier session pushed. The cost: each `up` needs the variable in its own environment,
because a session never inherits one already in the proxy. Add or rotate one with
`silkgate secret set anthropic --session foo`, which reads
`SILKGATE_EGRESS_SECRET_ANTHROPIC` from the environment — the value is never an argument.
`silkgate secret ls` lists names only, and `--session` narrows it to one session.
[doc/PROXY.md](doc/PROXY.md) specifies the full flow and its tests.

## The audit UI: `silkgate ui`

**`silkgate ui` serves a live, filterable table over the whole audit trail at
`http://127.0.0.1:8642/`.** `--port` overrides. The UI is loopback only with no auth. It is
safe for the same reason the control socket is: a guest's Tier-1 rule allows only its own
proxy port, so no guest can ever reach it. It needs no live proxy, because history and the
session list stand on their own. The live stream heartbeats until a proxy appears, then
adopts a restarted proxy's new file without a reload.

One row is one request: the allow line joined with its conclusion (a deny is the whole
story, and a CONNECT allow renders as a tunnel). Filters — session, decision, method, host,
time window — live in the URL hash, so a view is shareable. The ACTIONS column shows what
the proxy did to each request. `inj:<name>` or `skip:<name>` marks the credential swap, with
the secret's name and never its value. `q:<n>` and `h:<n>` count stripped query params and
headers, with the stripped names in the tooltip.

The UI reads only the machine-readable `events-*.jsonl` files ([doc/PROXY.md](doc/PROXY.md)).
It never parses the older mixed-format `proxy-*.log` files, so its history starts with the
first proxy that wrote an events file.

## Real git for a guest: `--branch`

**With `--with git --branch <new-name>`, the guest gets a working checkout at `/workspace`,
cloned inside the VM from a read-only mount of the repo's `.git`.** Run `run` or `up` from
inside a repository. The workspace mount holds no git metadata at all, so there is nothing
on it for a guest to rewrite. Commits are the deliverable, and file modes ride in them.

```sh
cd ~/projects/foo
silkgate run --with git --with claude --branch agent/fix-flaky-test -- \
  silkgate-claude -p "fix the flaky test in tests/test_sync.py, commit as you go"
```

A persistent session works the same way (`up --branch … --name bar`), and
`silkgate harvest bar` banks its commits mid-session without a stop.

At `down`, and on every `harvest`, the guest's commits come out as a bundle. The host
fetches it under `fetch.fsckObjects`, then promotes fast-forward-only with one
compare-and-swap: a branch that already exists, that someone else moved, or whose harvested
history the guest rewrote is refused, and the refused commits stay reachable at
`refs/silkgate/<session>/<branch>`. The derived workspace under `<repo>/.silkgate/sandboxes/`
is deleted at teardown — uncommitted files die with it, and the guest's brief says so —
except when a harvest was unable to bank everything, in which case it is kept and named.
Commits made after the last harvest live only in the VM, so `harvest` long sessions at
milestones.

With LFS in use, `.git/lfs` is mounted read-write — the one piece of host git state a guest
can touch. That is an availability risk only, accepted by design: objects are
content-addressed and git-lfs verifies SHA-256 on read, so a hostile guest can force a
re-download, never substitute content. It can also read any LFS object in the store, so
treat the store as visible to the guest. Hooks are copied into the clone verbatim and run in
the guest. A hook that references host paths fails there (`--no-verify`, or fix the hook).

## Layout

**The repository maps one directory per concern.**

- `profiles/<name>/` — the capabilities: setup plus rules plus env, as above
- `mitmaddon/rule_engine.py` — dependency-free DSL parser, host and path normalizer, and
  matcher (`python3 mitmaddon/rule_engine.py` self-tests)
- `mitmaddon/proxy_addon.py` — the addon: SNI==Host, allowlist, header/body/query
  enforcement, secret injection, fail-closed resolution, audit log. A listener port always
  resolves to a ruleset, either from a session registry (`SILKGATE_EGRESS_SESSIONS_DIR`) or
  from one fixed ruleset (`SILKGATE_EGRESS_RULES`)
- `cli/silkgate` — the host CLI (`profiles` / `build` / `verify` / `proxy` / `run` / `up` /
  `exec` / `attach` / `logs` / `ui` / `harvest` / `down` / `ls` / `secret`), stdlib-only
  Python
- `ui/` — the audit UI `silkgate ui` serves: four static files, vanilla ES modules, no
  framework, no build step
- `test/verify_guest.sh` — the Tier-1 checks, run as root inside a guest by `silkgate verify`
- `test/linux/` — a container that runs the whole thing on Linux hosts too old for the msb
  binaries

Host state lives under `~/.silkgate/`, created on the first `run` or `up`. The short
version: `sessions/<name>/` holds each session's ruleset snapshot and metadata,
`ca/egress-ca.pem` is the MITM certificate (never the key), and `logs/` holds the audit logs
and their machine-only `events-*.jsonl` mirrors. The full table — every path, plus retention
— is in [doc/PROXY.md](doc/PROXY.md).

## Install microsandbox

**One script, or brew, installs msb — then pin the version you verified.**

```sh
curl -fsSL https://install.microsandbox.dev | sh   # or: brew install superradcompany/tap/microsandbox
```

> ⚠️ microsandbox is pre-1.0, verified against v0.5.4/v0.5.7 on macOS and v0.6.8 on Linux
> (repo `superradcompany/microsandbox` — the `--net-*` flags were identical across all
> three). Flags can shift. Confirm with `msb run --help`, and pin the version you verified.

Linux needs two things: read-write access to `/dev/kvm` (usually membership in the `kvm`
group), and glibc ≥ 2.39 for the msb release binaries (check `ldd --version` — the binaries
are built on Ubuntu 24.04). On older hosts, run the proxy and msb inside the `test/linux/`
container instead. `/dev/kvm` is passed through, so the microVM boundary is the host
kernel's KVM either way:

```sh
docker build -t silkgate-verify test/linux/
docker run --rm --device /dev/kvm -v "$PWD:/silkgate" silkgate-verify \
  /silkgate/cli/silkgate verify --full
```

If DNS fails inside the containers, add `--network=host` to both commands. That failure is
common when the host's `resolv.conf` points at a localhost stub resolver.

## Verify containment

**A pass proves containment: the expected checks ran, every direct-egress probe was blocked
with an answer, and three oracles outside the guest agree.**

```sh
./cli/silkgate verify           # bare debian guest; the /dev/tcp probes need nothing installed
./cli/silkgate verify --full    # also installs probe tools *through* the proxy, then trusts the CA
```

- A count is not enough — most checks skipped and two passed is not containment — so
  `--full` asserts the set that ran, and a skip fails it. The guest's `CHECKS:` line beside
  `RESULT: N passed, 0 failed` names which checks ran.
- A blocked-direction check passes on an answer, not an absence. The errno is kept and
  classified: a refusal means the boundary answered, an unreachable means the probe never
  left and proves nothing, and silence is graded against a control that measures how this
  boundary actually denies — both drop and refusal are plausible, and neither is assumed.
- The three oracles sit outside the guest, so not every verdict rests on the guest's own
  report: an arrival observer on a port the allowlist omits (its own token must arrive, so a
  deaf listener cannot pass by silence), a recorder endpoint that proves the proxy replaces
  a credential the guest sent and never adds one it did not, and an assertion that this
  run's audit log holds the decisions the checks provoked. `--negative-control` adds a
  second, deliberately leaky guest and requires the checks to fail there — the only way to
  know they can fail.
- Check 0 is a control for the probe mechanism itself: it requires the proxy's own refusal
  of a request no rule allows. A bare TCP connect proves nothing, because microsandbox's
  guest-to-host NAT completes the handshake inside the VMM and reports success with no
  listener at all.
- Check 3 runs as root with no direct egress. Check 7 re-adds a default route as root and is
  still blocked, which is the point: enforcement sits in the host stack below the guest NIC.
  If any of checks 3–7 succeed, the boundary leaks.
- DNS is denied without any extra rule: `--net-default-egress deny` grants no UDP/53, and
  microsandbox intercepts UDP/53 at its gateway, so external names cannot resolve. The
  proxy's alias resolves via the guest's `/etc/hosts`. Do not add `allow@host:udp:53` — that
  rule reopens DNS. TCP/53 is intercepted too: every destination on that port answers
  `REFUSED` from msb's own stub, so it is not a way out either.
- Every `up` and `run` re-runs one check from inside the guest before handover — that a host
  outside the allowlist is unreachable — and refuses the session otherwise. Check 3 is that
  assertion. The rest of `verify` is what the always-on probe deliberately does not pay for.
- The score is 15/15 on macOS (Apple Silicon) by hand, with all three oracles in agreement,
  and on Linux (x86_64/KVM, msb 0.6.8) by CI on every push. Coverage differs by platform:
  the Linux guest has no working IPv6 and maps the proxy alias to v4 only, so the checks
  whose subject is a v6 path report that they had nothing to probe rather than a claim of
  coverage.

## The standalone proxy

**For a guest silkgate does not manage — a container, a remote VM — run one ruleset on one
port.**

```sh
./cli/silkgate proxy --with claude --port 8090
```

Point the workload at it with `HTTPS_PROXY`/`HTTP_PROXY`, and install
`~/.silkgate/ca/egress-ca.pem` in its trust store. Enforcement is identical. What you lose
is Tier 1, so the workload must be unable to reach the network any other way — otherwise the
proxy is advisory.

## Notes

**The residual risk lives in what you allowlist and what you mount.**

- The proxy decrypts via a private CA you own. The private key never leaves the host, and
  nothing in silkgate hands a guest more than the certificate. Do not reuse that CA
  elsewhere.
- Allowlisted destinations remain exfiltration carriers. Keep each profile's rules minimal,
  never allowlist an endpoint that reflects headers or bodies, and prefer download-only
  (GET).
- `--workspace DIR` mounts DIR read-write. `--workspace-ro DIR` mounts the same path
  read-only: `/workspace` is then browsable, but writes to it fail. The read-only form skips
  the `.git`-directory refusal (a whole repository is mountable), so an agent that only
  reads code can be pointed directly at the repo. Read-only still exposes everything under
  the mount, `.git/config` included, where a remote URL can embed a token. Both forms are
  refused for `/`, your home directory, and silkgate's own checkout and state — credentials
  and configuration there must not be exposed even read-only. A linked worktree's `.git`
  file passes either form, with a printed note. `--workspace-ro` is exclusive with
  `--workspace`, `--allow-git-dir`, and `--branch`. For a repository where the guest must
  also commit, use `--branch` instead.
- The `probe` profile exists for `verify` only: it opens the Debian mirrors, so every other
  command refuses to compose it.
