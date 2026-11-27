# Silkgate

Run an untrusted coding agent, or any untrusted command, in a microVM whose only way out is
a proxy you control.

```text
guest (microVM) ──▶ proxy on your host ──▶ only the requests your rules allow
```

- Tier 1: microsandbox's host-side network policy sends all guest traffic to the proxy.
  Nothing else leaves: no DNS, no UDP, no IPv6, no other port.
- Tier 2: the proxy terminates TLS and checks each request against an allowlist: host,
  path, method, headers, body size. It swaps the guest's dummy credentials for real ones.

Both tiers run outside the guest, so even a root guest can't turn them off. CI verifies
containment on Linux on every push. macOS is verified by hand.

## Quickstart

**Install three tools, check containment, then hand an agent a branch.**

```sh
pip install mitmproxy                  # plus docker and msb: see Install microsandbox
export PATH="$PWD/cli:$PATH"           # from this checkout
silkgate doctor                        # names anything missing, with its install command
silkgate verify                        # proves Tier 1 holds on this machine

export SILKGATE_EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"   # stays on the host
cd ~/projects/foo
silkgate run --name fix --with git --with claude --branch agent/fix-test -- \
  silkgate-claude -p "fix the failing test, commit as you go"
```

- `--with claude` picks the image (built once, then cached) and the rules (Anthropic's API
  only).
- Add what your tests need to run, for example `--with python` or `--with node`.
- The agent's commits land on `agent/fix-test` in your repo when the run ends.
- The startup line prints the audit log path. `tail -f` it to watch each allow and deny.
- On a Team or Enterprise plan, use a token instead of a key:
  [A Claude subscription](#a-claude-subscription).

## Documentation

| Read | To |
|---|---|
| [doc/PROFILES.md](doc/PROFILES.md) | write a profile, pass arguments, see what the guest is told |
| [doc/DSL.md](doc/DSL.md) | write egress rules |
| [doc/GIT.md](doc/GIT.md) | give a guest a repo, get commits back, reach GitHub |
| [doc/PROXY.md](doc/PROXY.md) | operate and debug the proxy, read the audit trail, find host state |
| [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) | understand the design and the glossary |
| [doc/THREAT-MODEL.md](doc/THREAT-MODEL.md) | see what an attacker can try, and what stops it |
| [doc/SOTA.md](doc/SOTA.md) | compare with other sandboxes (dated research) |
| [doc/PLUGIN.md](doc/PLUGIN.md) | ship silkgate as a Claude Code plugin |
| [doc/REFRESH.md](doc/REFRESH.md) | find the facts here that go stale, and how to check each |
| [CONTRIBUTING.md](CONTRIBUTING.md) | set up, test, commit, write docs |

## Profiles

**A profile is one capability: what to install, and what it may reach.**

```sh
silkgate profiles                                  # list them, with pinned versions
silkgate run --with node@20.18.1 --with python -- node --test
silkgate run --with claude --rule 'pypi.org/simple/** GET' -- …   # add one rule
silkgate profiles --render github-read:acme/app    # the exact rules a spec enforces
```

- No `--with` gives an empty policy: the guest reaches nothing.
- Rules can only be added, never removed, so pick the smallest profile set.
- Write your own: [doc/PROFILES.md](doc/PROFILES.md). Rule syntax: [doc/DSL.md](doc/DSL.md).

## Sessions

**`run` is one-shot. `up` keeps the VM warm across commands.**

```sh
silkgate up --name foo --with claude -v ~/notes:/workspace
silkgate exec foo -- silkgate-claude -p "summarize the notes" --output-format json
silkgate exec foo -- silkgate-claude -p --resume <session_id> "now list open questions"
silkgate attach foo              # interactive: runs the profile's command
silkgate logs foo -f             # guest output, live
silkgate logs foo --audit -f     # this session's allow and deny lines
silkgate ls                      # sessions and proxy health (-a adds archives)
silkgate down foo                # the last session out stops the proxy
```

- Use `run` unless a later command needs the same VM, for example `--resume`.
- Each session gets its own proxy port, and its guest can reach only that port. The port
  is how the proxy knows which session sent a request.
- Output streams live, with stdout and stderr apart, so a parent can parse `stream-json`.
- A command gets a terminal when your stdin is one, which merges both streams. Pass
  `--no-tty` when you parse the output.
- Each guest gets 1G of memory and half the host's CPUs. Change it with `--memory 2G` and
  `--cpus 4`.
- Hand over a long task as a file: `--brief task.md` lands it at `/silkgate/BRIEF.md`.

## Secrets

**The real credential stays on the host. The guest holds a dummy.**

```sh
export SILKGATE_EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"
silkgate up --name foo --with claude              # pushes the secret, for foo only
silkgate secret set anthropic --session foo       # rotate it later
silkgate secret ls                                # names only, never values
```

- A rule's `inject_auth=anthropic` names `SILKGATE_EGRESS_SECRET_ANTHROPIC`. The variable
  holds a full header line, not a bare key.
- Each session gets its own copy. A later session can't spend an earlier one's secret.
- A missing secret doesn't block `up`. Requests that need it get denied, and
  `/silkgate/CONTEXT.md` tells the guest why.

Details: [doc/PROXY.md](doc/PROXY.md#secrets).

### A Claude subscription

**On a Team or Enterprise plan, put a `claude setup-token` token in the same variable, as
an `Authorization` header.**

```sh
claude setup-token                    # prints a one-year token
export SILKGATE_EGRESS_SECRET_ANTHROPIC="Authorization: Bearer sk-ant-oat01-…"
silkgate run --name task --with claude -- silkgate-claude -p "task…"
```

| Secret header | The guest holds |
|---|---|
| `x-api-key` | a dummy `ANTHROPIC_API_KEY` |
| `Authorization` | a dummy `CLAUDE_CODE_OAUTH_TOKEN` |

Don't pass `--bare` with a subscription token. Claude Code ignores the token under `--bare`
and stops with `Not logged in`.

## Git and GitHub

**`--checkout` gives the guest a throwaway clone. `--branch` also brings its commits back.**

```sh
cd ~/projects/foo
silkgate run --name ask --with git --with claude --checkout -- \
  silkgate-claude -p "why does auth reject refreshable tokens? cite files"
silkgate run --name fix --with git --with claude --branch agent/fix-flaky -- \
  silkgate-claude -p "fix tests/test_sync.py, commit as you go"
```

| Profile | Grants |
|---|---|
| `github` | anonymous clone and fetch of any public repo |
| `github-read:OWNER/REPO` | one repo, read, with an injected token |
| `github-write:OWNER/REPO` | one repo, read and push, with an injected token |

Details: [doc/GIT.md](doc/GIT.md).

## Mounts

**Mounts are read-only unless you add `:rw`, and silkgate refuses the dangerous ones.**

```sh
-v ~/data:/data              # read-only
-v ~/scratch:/scratch:rw     # read-write
```

| Refused | Why |
|---|---|
| `/`, your home, this checkout, `~/.silkgate` | they hold credentials and config |
| a read-write mount with a `.git` directory inside | its hooks would run on your host. `--allow-git-dir` overrides. |
| a guest path that's relative or `/`, that touches `/silkgate`, `/root/lfsstore` or `/root/gitdir`, or that nests in another mount | it would shadow silkgate's files or another mount |

- A read-only mount still exposes all of it, `.git/config` included. Remote URLs there can
  hold tokens.
- For a writable repo, use `--checkout` or `--branch`, not `-v`.

## More flags

**`run` and `up` take these too. `exec` takes `-e` and `--tty`.**

| Flag | Does |
|---|---|
| `-e NAME=VALUE` | sets an env var in the guest. The journal keeps the name only. Proxy variables (`HTTPS_PROXY`, `NO_PROXY`, …) are refused. Secrets belong in `SILKGATE_EGRESS_SECRET_*`. |
| `--tty`, `--no-tty` | gives the command a terminal, or not. The default follows your stdin. `exec` also takes `-t`. |
| `--image REF` | runs that image as-is: nothing is built, and rules still come from `--with`. It needs `sh` and `mkfifo`, and must trust `~/.silkgate/ca/egress-ca.pem` for HTTPS. |
| `--base IMAGE` | builds the profiles on another base than `debian:bookworm-slim`. Not with `--image`. |
| `--port N` | where the proxy's 16-port pool starts, if this command starts the proxy (default 8090) |
| `--memory SIZE`, `--cpus N` | guest resources: default 1G, and half the host's CPUs |
| `--no-context`, `--no-settings` | skip the [guest context](doc/PROFILES.md#the-guest-context), or the [model settings](doc/PROFILES.md#model-settings) copy |

## Audit UI

**`silkgate ui` serves a live table of every request at <http://127.0.0.1:8642/>.**

- One row per request. Filter by session, decision, method, host, or time. Filters live in
  the URL, so you can share a view.
- The ACTIONS column shows what the proxy did: `inj:<name>` swapped a credential,
  `q:<n>` and `h:<n>` stripped query params and headers.
- A session's page shows its activity, tool calls, and files, and can act on it:

  | Action | Effect |
  |---|---|
  | freeze | swaps in an empty ruleset: every request is denied, and the guest keeps running |
  | resume | restores the ruleset |
  | kill | stops one exec: TERM, then KILL after 5 s |
  | diff | a live git session's working diff, or a harvested branch's diff on the host |
  | down | tears the session down, like `silkgate down` |

  The journal records freeze, resume, and kill.
- It binds loopback only and has no auth. No guest can reach it.
- `--port` changes the port.

## Install microsandbox

**Install msb with one script, then pin the version you verified.**

```sh
curl -fsSL https://install.microsandbox.dev | sh   # or: brew install superradcompany/tap/microsandbox
```

microsandbox is pre-1.0. Silkgate is verified against 0.5.4 and 0.5.7 on macOS and 0.6.8
on Linux. Run `silkgate verify --full` after any upgrade.

Linux needs:

- read-write `/dev/kvm` (usually: be in the `kvm` group)
- glibc ≥ 2.39 (`ldd --version`)

On an older host, run everything inside the test container. KVM still provides the VM
boundary:

```sh
docker build -t silkgate-verify test/linux/
docker run --rm --device /dev/kvm -v "$PWD:/silkgate" silkgate-verify \
  /silkgate/cli/silkgate verify --full
```

If DNS fails inside the container, add `--network=host` to both commands.

## Verify containment

**`verify` proves, from inside a root guest, that nothing leaves except through the proxy.**

```sh
silkgate verify                              # bare guest, no tools needed
silkgate verify --full                       # also installs probe tools through the proxy
silkgate verify --full --negative-control    # adds a leaky guest the checks must catch
```

- A pass means all 15 checks ran and passed, and three observers outside the guest agree.
  Under `--full`, a skipped check fails the run.
- Every `up` and `run` also re-checks that an unlisted host is unreachable before it hands
  over the guest.

What each check proves: [doc/THREAT-MODEL.md](doc/THREAT-MODEL.md#verified-live).

## The standalone proxy

**For a guest silkgate doesn't manage, such as a container or a remote VM, run one ruleset
on one port.**

```sh
silkgate proxy --with claude --port 8090
```

Point the workload at it with `HTTPS_PROXY`, and trust `~/.silkgate/ca/egress-ca.pem`.
Tier 2 is identical, but there's no Tier 1. Block the workload's other routes yourself, or
the proxy is only advisory.

## Limits

**Silkgate bounds where a guest can send data, not how much or what.**

- Every allowed destination can carry data out. Keep rules minimal, prefer GET, and never
  allow an endpoint that echoes headers or bodies back.
- Nothing bounds a runaway agent: no timeout, no cost ceiling. Wrap the command in
  `timeout 600 …` if that matters.
- Host sleep kills every guest's API stream. A `-p` run exits and loses its unwritten
  work. Run long batches on a machine that stays awake, or in a session you can resume.
- The proxy reads all guest TLS with a private CA. Its key never leaves the host. Don't
  reuse that CA anywhere else.

## Layout

| Path | Holds |
|---|---|
| `cli/silkgate` | the host CLI, stdlib-only Python |
| `mitmaddon/` | the proxy addon and the rule engine |
| `profiles/<name>/` | one capability each: install step, rules, env |
| `ui/` | the audit UI: static ES modules, no build step |
| `test/` | the suites, and `verify_guest.sh`, the in-guest containment checks |
| `~/.silkgate/` | host state: sessions, logs, the CA ([doc/PROXY.md](doc/PROXY.md#host-state)) |
