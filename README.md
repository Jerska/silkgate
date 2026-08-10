# Silkgate

Run an untrusted coding agent — or any untrusted command — in a microVM whose **only** route to
the network is a TLS-terminating proxy that allowlists per request. Verified live on **macOS
(Apple Silicon)**, by hand, and on **Linux (x86_64/KVM, msb 0.6.8)** by CI on every push — the
containment workflow runs all fifteen checks inside the `test/linux/` container, plus three
assertions made from outside the guest, and fails if any check merely skipped (see
[Verifying containment](#verifying-containment)). Two enforcement layers, both outside the guest:

- **Tier 1 — force all egress to the proxy:** microsandbox's own host-side network policy. No
  nft, no pf, no nested VM.
- **Tier 2 — per-request inspection:** the mitmproxy addon + the DSL rule engine.

Design docs: [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) · [doc/THREAT-MODEL.md](doc/THREAT-MODEL.md) · [doc/DSL.md](doc/DSL.md)

## Quickstart

Prereqs: `pip install mitmproxy`, docker, and msb (see [Installing microsandbox](#installing-microsandbox)).
`./cli/silkgate doctor` names whichever of the three are missing, and how to install each.

```sh
./cli/silkgate profiles                    # what capabilities are available
./cli/silkgate verify                      # Tier-1 containment check (--full for the proxy path)
export SILKGATE_EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"   # host-only; never enters the guest or argv
./cli/silkgate run --with claude --workspace ~/projects/foo -- \
  claude --bare -p "task…" --permission-mode bypassPermissions
```

That single `--with claude` decides two things: the **image** (built on first use, then cached)
and the **egress policy** (only `api.anthropic.com` and the Console probe, with the real key
injected at the proxy). The audit log path is printed at startup — `tail -f` it, or use
`silkgate logs`, to watch allow/deny decisions.

No `--with` and no `--rule` is legal too: the policy is then empty — the tightest sandbox
silkgate can express — and the guest can reach nothing at all.

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

## Telling the guest where it is

A cooperating agent wastes turns discovering the sandbox the hard way — reaching for a runtime
that isn't installed, retrying a host that policy will never allow. So each session generates a
description of itself from its own profiles, ruleset and mount, and puts it in the guest two
ways:

```sh
# inline, for any harness — the variable holds the text itself, not a path
./cli/silkgate exec foo -- sh -c 'claude -p "$SILKGATE_CONTEXT

Now: <task>"'
# or as a file, which Claude Code accepts even under --bare
./cli/silkgate exec foo -- claude --bare -p "<task>" --append-system-prompt-file /silkgate/CONTEXT.md
```

It lands at `/silkgate/CONTEXT.md` in the rootfs — never in `/workspace`, so it cannot appear in
the project — plus wherever a profile's `context_path` says its harness looks for instructions.
`--no-context` skips the whole thing.

This is a courtesy, not a control. An adversarial guest ignores every word of it, so nothing may
rely on it; what it buys is fewer wasted turns, and denials reported as requests ("I need
`pypi.org` for X") instead of retried in a loop.

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
parent can supervise a task and still parse a captured `stream-json` — though the separation
is a convenience, not a property: it rides an in-band tag the guest can write itself, and
everything on both streams is the guest's own report. `-t` instead gives the
command a real terminal, which changes how it behaves (colors, cursor control, both streams
merged), so keep it for a TUI and leave it off for anything you intend to parse. To watch a
session you did not start in the foreground, or to see only its egress decisions:

```sh
./cli/silkgate logs foo -f            # the guest's output, live
./cli/silkgate logs foo --audit -f    # just this session's allow/deny lines
```

## Handing a guest real git: `--branch`

Run `run` or `up` from inside a repository with `--with git --branch <new-name>` and the guest
gets a working checkout on that branch at `/workspace`, cloned inside the VM from a **read-only**
mount of the repo's `.git`. The workspace mount holds no git metadata at all, so there is nothing
on it for a guest to rewrite; commits are the deliverable, and file modes ride in them.

```sh
cd ~/projects/foo
silkgate run --with git --with claude --branch agent/fix-flaky-test -- \
  silkgate-claude -p "fix the flaky test in tests/test_sync.py, commit as you go"
```

A persistent session works the same way (`up --branch … --name bar`), and
`silkgate harvest bar` banks its commits mid-session without stopping it.

At `down` (and on every `harvest`) the guest's commits come out as a bundle the host fetches
under `fetch.fsckObjects`, then promotes **fast-forward-only** with one compare-and-swap: a
branch that already exists, was moved by someone else, or whose harvested history the guest
rewrote is refused, and the refused commits stay reachable at `refs/silkgate/<session>/<branch>`.
The derived workspace under `<repo>/.silkgate/sandboxes/` is deleted at teardown — uncommitted
files die with it, and the guest's brief says so — except when a harvest could not bank
everything, in which case it is kept and named. Commits made after the last harvest live only in
the VM, so `harvest` long sessions at milestones.

With LFS in use, `.git/lfs` is mounted **read-write** — the one piece of host git state a guest
can touch. That is an availability risk only, accepted by design: objects are content-addressed
and git-lfs verifies SHA-256 on read, so a hostile guest can force a re-download, never
substitute content. It can also read any LFS object in the store, so treat the store as visible
to the guest. Hooks are copied into the clone verbatim and run in the guest; a hook that
references host paths fails there (`--no-verify`, or fix the hook).

`up` pushes every `SILKGATE_EGRESS_SECRET_<NAME>` the session's `inject_auth` rules need, and refuses to
start if one is missing from your environment. Secrets are held **per session**, so one shared
proxy never lets a later session spend a key an earlier one pushed — which means each `up` needs
the variable in its own environment rather than inheriting one already in the proxy. Add or rotate
one with `silkgate secret set anthropic --session foo`, which reads `SILKGATE_EGRESS_SECRET_ANTHROPIC` from
the environment; the value is **never** an argument. `silkgate secret ls` lists names only, and
`--session` narrows it to one.

## Layout

- `profiles/<name>/` — the capabilities: setup + rules + env, as above
- `mitmaddon/rule_engine.py` — dependency-free DSL parser + host/path normalizer + matcher
  (`python3 mitmaddon/rule_engine.py` self-tests)
- `mitmaddon/proxy_addon.py` — the addon: SNI==Host, allowlist, header/body/query enforcement,
  secret injection, fail-closed, audit log. A listener port always resolves to a ruleset, either
  from a session registry (`SILKGATE_EGRESS_SESSIONS_DIR`) or from one fixed ruleset (`SILKGATE_EGRESS_RULES`)
- `cli/silkgate` — the host CLI (`profiles` / `build` / `verify` / `proxy` / `run` / `up` /
  `exec` / `attach` / `logs` / `harvest` / `down` / `ls` / `secret`), stdlib-only Python
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

- **Pass = the expected checks ran, the proxy-path ones succeeded, every direct-egress check was
  blocked, and three assertions made outside the guest agree.** A count is not enough — most checks
  skipped and two passed is not containment — so `--full` asserts the set that ran, and a skip fails
  it. Which checks ran is on the guest's `CHECKS:` line beside `RESULT: N passed, 0 failed`.
- **A blocked-direction check passes on an answer, not an absence.** The errno is kept and
  classified: a refusal means the boundary answered, an unreachable means the probe never left and
  proves nothing, and silence is graded against a control that measures how this boundary actually
  denies — because dropping and refusing are both plausible and neither is assumed.
- **Three oracles sit outside the guest**, so not every verdict rests on the guest's own report: an
  arrival observer on a port the allowlist omits (its own token must arrive, so a deaf listener
  cannot pass by staying silent), a recording endpoint proving the proxy *replaces* a credential the
  guest sent and never *adds* one it did not, and an assertion that this run's audit log holds the
  decisions the checks provoked. `--negative-control` adds a second, deliberately leaking guest and
  requires the checks to fail there — the only way to know they can.
- Check 0 is a control for the probe mechanism itself: it requires the proxy's own refusal of a
  request no rule allows. A bare TCP connect would not do, because microsandbox's guest→host NAT
  completes the handshake inside the VMM and so reports success with nothing listening at all.
- Check 3 runs as root with no direct egress; check 7 re-adds a default route as root and is
  *still* blocked, which is the point — enforcement sits in the host stack below the guest NIC.
  If any of 3–7 succeed, the boundary leaks.
- DNS is denied without any extra rule: `--net-default-egress deny` grants no UDP/53, and
  microsandbox intercepts UDP/53 at its gateway, so external names can't resolve; the proxy's
  alias resolves via the guest's `/etc/hosts`. Do **not** add `allow@host:udp:53` — it would
  re-open DNS. TCP/53 is intercepted too: every destination on that port answers `REFUSED` from
  msb's own stub, so it is not a way out either.
- Every `up` and `run` re-checks one thing from inside the guest before handing it over — that a
  host outside the allowlist is unreachable — and refuses the session otherwise. Check 3 *is* that
  assertion; the rest of `verify` is what the always-on probe deliberately does not pay for.
- **Verified 15/15 on macOS (Apple Silicon), by hand, with all three oracles agreeing, and on
  Linux (x86_64/KVM, msb 0.6.8) by CI on every push.** Coverage differs by platform: that Linux
  guest has no working IPv6 and maps the proxy alias to v4 only, so the checks whose subject is a
  v6 path report that they had nothing to probe rather than claiming to have covered it.

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
- `--workspace` is refused where the mount itself would hand over the host: `/`, your home
  directory, silkgate's own checkout and state, and any directory holding a `.git`
  **directory** anywhere under it — hooks and `core.fsmonitor` there are host code execution
  the next time you run git in it. A linked worktree's `.git` **file** is allowed, with a
  printed note. For a repository, use `--branch` instead of a mount.
- The `probe` profile exists for `verify` only: it opens the Debian mirrors, so every other
  command refuses to compose it.
