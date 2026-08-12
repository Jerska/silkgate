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
./cli/silkgate run --with claude -v ~/projects/foo:/workspace:rw -- \
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
- [doc/REFRESH.md](doc/REFRESH.md) — which facts in this tree rot with time (pins, prices,
  static lists, observed upstream behavior), and the check that catches each.
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

## Profile arguments

**A profile can take an argument — `--with NAME[@VERSION][:ARG]` — and the argument
reaches only the composed rules, never the image.** A profile that takes an argument
declares `arg_pattern` in its `profile.conf`: a regex the whole argument must match. A
profile with a pattern requires an argument, and a profile without one refuses any. The
argument lands inside rule syntax, so a malformed argument is rule injection. The spec
parser refuses whitespace and control characters unconditionally, and the declared
pattern decides the rest. Each refusal names the profile and its pattern.

`rules.txt` and `context.md` are the templated files. Every `{arg}` in them becomes
the validated argument — in the session's composed ruleset and in the guest context. A
`{arg}` placeholder in a profile with no declared pattern is a load error. `setup.sh`
and `env` are never templated, so an argument can never affect the image. The tag's hash covers the template bytes as
written, and the slug carries each profile name once. Two sessions with different
arguments for one profile therefore reuse one image.

The same name repeats with different arguments to grant several instances. Each
distinct name, version, and argument combination expands its rules once, and exact
duplicates deduplicate silently. When a profile's conf declares `supersedes = NAME`,
its instance drops any NAME instance with the same argument, and silkgate prints one
line per drop. The dependency key is `requires = NAME`: a listed profile that is
absent from the `--with` list is refused, never added silently.

The composed ruleset is ordered, and the order is the override mechanism. The proxy is
first-match-wins, so an earlier rule decides every request it covers. Composition puts
`--rule` lines first, then the argument expansions, then the rules of profiles without
arguments. Explicit therefore beats a grant, and a grant beats the profile floor.
`test/test_cli_validation.py` pins the validation, the image identity, and the order.
Audit a composed policy before a launch:

```sh
./cli/silkgate profiles                              # the ARG column lists each pattern
./cli/silkgate profiles --render some-profile:myarg  # the exact rules a session enforces
```

## The guest context

**Each session describes itself to the guest, so a cooperative agent wastes no turns on
discovery.** Without it, the agent reaches for a runtime that is not installed, or retries a
host that policy never allows. The description is generated from the session's own profiles,
ruleset, and mounts, and reaches the guest two ways:

```sh
# inline, for any harness — the variable holds the text itself, not a path
./cli/silkgate exec foo -- sh -c 'claude -p "$SILKGATE_CONTEXT

Now: <task>"'
# or as a file, which Claude Code accepts even under --bare
./cli/silkgate exec foo -- claude --bare -p "<task>" --append-system-prompt-file /silkgate/CONTEXT.md
```

The file lands at `/silkgate/CONTEXT.md` in the rootfs — never in `/workspace`, so it cannot
appear in the project — plus wherever a profile's `context_path` says its harness looks for
instructions. A profile can add its own passage: a `context.md` beside its rules, templated
with `{arg}` the same way, appended once per instance. `--no-context` skips the whole thing.

This is a courtesy, not a control. An adversarial guest ignores every word of it, so nothing
is allowed to rely on it. What it buys is fewer wasted turns, and denials reported as
requests ("I need `pypi.org` for X") instead of retried in a loop.

## The settings projection

**Each launch forwards the host's Claude Code model configuration, so a guest agent
defaults to the same model and reasoning effort as the host.** Silkgate resolves exactly
two keys, `model` and `effortLevel`, from the host's settings files. Per key, an env-block
value (`ANTHROPIC_MODEL`, `CLAUDE_CODE_EFFORT_LEVEL`) outranks every direct key, and local
outranks project outranks user. The project and local files come from the host directory
that becomes `/workspace`. The result lands at each profile's `settings_path` —
`/root/.claude/settings.json` for the claude profile. Nothing else in a settings file ever
leaves the host. Permissions, hooks, and env entries can carry secrets, so the projection
is an allowlist, not a copy. If neither key resolves, nothing is staged. A settings file
that is not valid JSON warns on stderr and counts as absent. `--no-settings` skips the
projection. `test/test_cli_settings.py` pins the resolution order and the allowlist.

## Persistent sessions

**`run` is one-shot, and a session instead keeps the VM warm on a dedicated proxy port.**
`run` creates a microVM, runs one command, and tears the VM down. Boot is ~0.3 s, so that
stays cheap — but `claude --resume` cannot work across turns, because the VM and
`/root/.claude` die with the command. A session persists both:

```sh
./cli/silkgate up --name foo --with claude -v ~/projects/foo:/workspace:rw
./cli/silkgate exec foo -- claude -p "scaffold a Flask app" --output-format json
# ↑ prints a session_id; the VM persists, so resume that conversation next turn:
./cli/silkgate exec foo -- claude -p --resume <id> "add a /health route and a test"
./cli/silkgate attach foo                 # same VM, interactive, runs the profile's command
./cli/silkgate ls                         # sessions (status/port/mounts/age) + proxy health
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

## Real git for a guest: `--checkout` and `--branch`

**The git story is two layers: `--checkout [REF]` is the primitive, and `--branch NAME`
layers the return path on it.** Both need `--with git`, both run from inside a repository,
and both own `/workspace` in the guest, so no `-v` mount can target it.

Run `run` or `up` with `--with git --checkout` and the guest gets a disposable, writable
checkout of the repo at REF (default `HEAD`) at `/workspace`. The checkout holds committed
content only, so untracked files such as `.env` never enter the guest. The repo's `.git` is mounted read-only
at `/silkgate/base.git`, and the guest clones from it: a normal clone with its own `.git`
inside `/workspace`. Hooks and reflogs are copied into the clone, the LFS store is mounted
when the repo uses one, and a commit identity is set so local commits do not fail. The
checkout is detached at REF, so "no deliverable branch" is structural. Nothing written in
the guest returns to the host, commits included: the worktree lives in the guest's own
rootfs and dies with the VM, so printed output is the deliverable. It works from the
silkgate repo itself.

```sh
cd ~/projects/foo
silkgate run --with git --with claude --checkout -- \
  silkgate-claude -p "why does auth reject expired-but-refreshable tokens? cite files"
```

`--branch NAME` builds on that and changes exactly this: the worktree moves from a
guest-only folder to a writable host-derived mount (`.silkgate/sandboxes/<name>` under the
repo root). A named branch is created at the base — `HEAD`, or REF when `--checkout REF` is
given beside it — and its commits return to the host fast-forward-only at harvest.
`GIT_DIR` and `GIT_WORK_TREE` are exported into every exec, and teardown harvests the
branch and reaps the derived workspace. The workspace mount holds no git metadata at all,
so there is nothing on it for a guest to rewrite. Commits are the deliverable, and file
modes ride in them.

```sh
cd ~/projects/foo
silkgate run --with git --with claude --branch agent/fix-flaky-test -- \
  silkgate-claude -p "fix the flaky test in tests/test_sync.py, commit as you go"
```

A persistent session works the same way (`up --branch … --name bar`), and
`silkgate harvest bar` banks its commits mid-session without a stop. `harvest` also works
against a `run` session — `run` prints its session name at startup.

At `run` teardown, at `down`, and on every `harvest`, the guest's commits come out as a
bundle. The host fetches it under `fetch.fsckObjects`, then promotes fast-forward-only with
one compare-and-swap: a branch that already exists, that someone else moved, or whose
harvested history the guest rewrote is refused, and the refused commits stay reachable at
`refs/silkgate/<session>/<branch>`. The derived workspace under `<repo>/.silkgate/sandboxes/`
is deleted at teardown — uncommitted files die with it, and the guest's brief says so —
except when a harvest was unable to bank everything, in which case it is kept and named.
That failed harvest also makes `run` and `down` exit 1, even when the guest command exited
0. Commits made after the last harvest live only in the VM, so `harvest` long sessions at
milestones.

With LFS in use, `.git/lfs` is mounted read-write in either mode — the one piece of host
git state a guest can touch. That is an availability and terminal-rendering risk, never
content substitution: objects are content-addressed and git-lfs verifies SHA-256 on read,
so a hostile guest can force a re-download, never swap content. The guest can also read any
LFS object in the store, so treat the store as visible to the guest. And `.git/lfs/logs` is
not content-addressed — `git lfs logs last` renders guest-written bytes in a host terminal,
so treat that output as untrusted. Hooks are copied into the clone verbatim and run in the
guest. A hook that references host paths fails there (`--no-verify`, or fix the hook).

## GitHub egress: `github`, `github-read`, `github-write`

**GitHub egress is three profiles: `github` is the anonymous public-read floor, and
`github-read:OWNER/REPO` and `github-write:OWNER/REPO` each grant one repository with a
PAT the proxy injects.** The `git` profile installs git and git-lfs and opens nothing.
Compose the pieces a task needs:

```sh
silkgate run --with git --with github -- git clone https://github.com/octocat/Hello-World
silkgate run --with git --with github-read:your-org/app -- git clone https://github.com/your-org/app
silkgate up --name bot --with git --with github-write:your-org/app
```

The floor allows anonymous clone and fetch of any public repository, with no credential
anywhere. It holds four rules: the ref advertisement pinned to
`?service=git-upload-pack`, the capped `git-upload-pack` POST, and GET on
`raw.githubusercontent.com` and `codeload.github.com`. The grants take one `OWNER/REPO`
argument each and repeat per repository. Their rules compose before the floor, so the
granted repository rides the credential and every other one stays anonymous.
`github-write` supersedes `github-read` for the same argument. Neither grant requires
`git`: a `github-read`-only guest is a supported REST-only shape. The table below lists
what each grant allows for its repository:

| Leg | `github-read:OWNER/REPO` | `github-write:OWNER/REPO` |
|---|---|---|
| ref advertisement (`info/refs`, bare and `.git` path forms) | GET, `?service=git-upload-pack` only | GET, upload-pack and receive-pack |
| fetch negotiation (`git-upload-pack`) | POST, 1 MiB cap | POST, 1 MiB cap |
| push (`git-receive-pack`) | — | POST, 64 MiB cap |
| LFS batch API on `github.com` | `info/lfs/objects/batch` POST, 1 MiB cap | `info/lfs/**` GET and POST, 1 MiB cap |
| LFS batch API on `lfs.github.com` (`objects/batch`) | POST, 1 MiB cap | POST, 1 MiB cap |
| LFS action hrefs on `lfs.github.com` (every other path) | GET and POST, 1 MiB cap, no injection | GET and POST, 1 MiB cap, no injection |
| REST API (`api.github.com/repos/OWNER/REPO`) | GET | GET, POST, PUT, PATCH, DELETE, 1 MiB cap |
| `raw.githubusercontent.com`, `codeload.github.com` | GET, anonymous | GET, anonymous |
| LFS object download (`github-cloud.githubusercontent.com`, presigned query) | GET, no injection | GET, no injection |
| LFS object upload (`github-cloud.s3.amazonaws.com`, SigV4 header) | — | PUT, 1 GiB cap, no injection |

Every `github.com` and `api.github.com` row carries `inject_auth=github`, and so does
the `lfs.github.com` batch row. The action hrefs authorize themselves: each carries a
short-lived `Authorization` token that the batch response issued, and the proxy
forwards it verbatim. The PAT injected over that token makes GitHub answer 403 on
upload-verify, so the action-href row carries no injection. The secret is
`SILKGATE_EGRESS_SECRET_GITHUB`, one full header
line: `Authorization: Basic base64(x-access-token:<PAT>)`. Build the line with
`base64 | tr -d '\n'`: `base64` wraps output past 76 characters, and a value that
spans lines is malformed. As with every secret, a missing or malformed value warns at
launch, and the guest sees the credential status in its context file.

A PAT for a repository in an organization that enforces SAML SSO needs one extra step:
authorize the token for that organization before the launch. A classic PAT is
authorized after creation, in the token's own settings. A fine-grained PAT is
authorized at creation, and the organization can require an approval. The
authorization is a browser flow, so complete it on the host. Inside a guest, an
unauthorized PAT answers GitHub's own 403 or 404 with an `X-GitHub-SSO` response
header. The audit log shows that request allowed: GitHub refused it, not the proxy. A
personal account's repository never needs this step.

The storage hosts authorize themselves (presigned URL or SigV4), so those rules
carry no `inject_auth` — a second `Authorization` header there makes S3 answer 501. The
upload's SigV4 signature rides in request headers, so the S3 rule forwards all headers
(`h:*`), while the presigned download host stays query-only. Each
grant's `setup.sh` bakes URL-scoped `Authorization` stubs into the image for the three
control hosts, never a global one, for the same reason.

Two gaps remain. `gh` is not installed and GraphQL is not reachable. The grants steer
the guest to the REST API instead, through their context snippets. Call
`api.github.com/repos/OWNER/REPO/...` with any `Authorization` value, and the proxy
replaces that value with the real credential. GitHub REST refuses a request that
carries no `User-Agent` header, so the API rules forward `user-agent` and `accept`.
The `accept` header selects the API media type. The `raw.githubusercontent.com` and
`codeload.github.com` lines stay anonymous even inside a grant, so a private file there
answers 404. Fetch private content over git or the REST API instead.

Migration from the removed flags: `--github-read OWNER/REPO` is now
`--with github-read:OWNER/REPO`, `--github-write OWNER/REPO` is now
`--with github-write:OWNER/REPO`, and the anonymous GitHub reach `--with git` once
carried is now `--with github`. `test/test_cli_validation.py` (TestGithubProfiles) pins
the read grant's push denial, the body caps, and the composition order.

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
version: `sessions/<name>/` holds each session's ruleset snapshot and metadata (mounts
included),
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
- `-v SRC:DST[:ro|rw]` (repeatable) mounts host directory SRC at DST in the guest,
  read-only unless the spec says `:rw`. Read-only skips the `.git`-directory refusal (a
  whole repository is mountable), so an agent that only reads code can be pointed directly
  at the repo. Read-only still exposes everything under the mount, `.git/config` included,
  where a remote URL can embed a token. Either mode is refused for `/`, your home
  directory, and silkgate's own checkout and state — credentials and configuration there
  must not be exposed even read-only.
- Guest-side, a DST is refused in five cases: it is relative, it is `/`, it sits at,
  under, or above `/silkgate`, `/root/lfsstore`, or `/root/gitdir` (silkgate's own guest
  paths), it duplicates another mount's DST, or it nests under one. Nested virtiofs
  behavior is unverified, so it is refused rather than trusted.
- A read-write mount that holds a `.git` directory anywhere under it is refused — hooks and
  config become guest-writable there, which is host code execution the next time a human
  runs git in it — unless `--allow-git-dir` accepts that risk explicitly. A linked
  worktree's `.git` file passes either mode, with a printed note.
- Steer by what the guest needs. A read-only shelf of host files: `-v DIR:DST` (read-only
  is the default). A writable scratch checkout with printed output as the deliverable:
  `--checkout`. Commits as the deliverable: `--branch`.
- The `probe` profile exists for `verify` only: it opens the Debian mirrors, so every other
  command refuses to compose it.
