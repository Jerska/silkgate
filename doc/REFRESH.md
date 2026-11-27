# Refresh registry

Read this to find the facts here that go stale on someone else's schedule, and the check
for each.

Each row is a fact an outside party owns: a version, a price, a URL, another system's
behavior. When a check fails, fix the fact, and every copy [Cross-file
pairs](#cross-file-pairs) lists. Rows name files and identifiers, never line numbers.

## Profile pins

**Each profile pins one upstream version.**

| Pin | Where | Check |
|---|---|---|
| Claude Code `2.1.330` | `profiles/claude/profile.conf` | `npm view @anthropic-ai/claude-code version`. It releases almost daily. |
| node `22.23.5` | `profiles/node/profile.conf` | the latest 22.x. Node 22 reaches end of life in 2027. |
| python `3.12.16` | `profiles/python/profile.conf` | the latest 3.12.x security release |
| uv `0.13.9` | `UV_VERSION` in `profiles/python/setup.sh` | the latest uv release |

Every `setup.sh` fails the build when the installed version misses its pin.

**A bump can also break what surrounds the pin.**

| Contract | Where | Check on a bump |
|---|---|---|
| `install.sh` takes a version argument | `profiles/claude/setup.sh` | the build's version check |
| `curl libgcc-s1 libstdc++6 ripgrep` are the binary's runtime needs | `profiles/claude/profile.conf` | `ldd` on the binary in a fresh image |
| a plain `claude -p` reads `context_path`, `--bare` doesn't | `profiles/claude/profile.conf` | ask a guest `claude -p` about its context, then `--bare` |
| `/root/.claude.json` keys `hasCompletedOnboarding`, `lastOnboardingVersion`, `bypassPermissionsModeAccepted`, `customApiKeyResponses`, and `projects./workspace.hasTrustDialogAccepted` skip first-run prompts | `profiles/claude/setup.sh` | `test/smoke_claude.py` |
| `IS_SANDBOX=1` lets root use `bypassPermissions` | `profiles/claude/setup.sh` | run `silkgate-claude` in a guest: no refusal. Plain `claude --permission-mode bypassPermissions` refuses. |
| the switches in the env file (`DISABLE_AUTOUPDATER`, …) | `profiles/claude/env` | check each name in the settings docs, and watch the audit log for new hosts |
| the `nodejs.org/dist` tarball layout | `profiles/node/setup.sh` | the build's version check |
| `deb.debian.org`, `security.debian.org` | `profiles/probe/rules.txt` | `silkgate verify --full` installs the probe tools |

## Egress rules

**Each rules file encodes what a service needs today. A path it adds later shows up as an
audit-log deny.**

| List | Where | Check |
|---|---|---|
| Claude Code's endpoints | `profiles/claude/rules.txt` | grep fresh audit logs for denies on `api.anthropic.com` and `platform.claude.com` |
| `max_body=10m` on the two Anthropic POSTs, `64k` on oauth | `profiles/claude/rules.txt` | grep audit logs for 413s |
| interactive startup probes `api.anthropic.com/api/hello` and `platform.claude.com/v1/oauth/hello`, and refuses to start on a deny | `profiles/claude/rules.txt` | `test/smoke_claude.py` (CI, weekly) |
| GitHub smart HTTP: `?service=`, protocol v2, 1 MiB negotiation | `profiles/github/rules.txt` | clone and fetch a public repo: no denies, no 413 |
| `raw.githubusercontent.com`, `codeload.github.com` | `profiles/github/rules.txt` | fetch a raw file and a tarball |
| LFS hosts (`lfs.github.com`, `github-cloud.*`), and S3's 501 on a second `Authorization` | `profiles/github-{read,write}/rules.txt` | an LFS clone and push on a scratch repo: no denies |
| SAML SSO: GitHub's 403 or 404 with `X-GitHub-SSO` | `doc/GIT.md` | one grant with an unauthorized PAT on an SSO org |
| npm needs only `registry.npmjs.org/**` GET | `profiles/node/rules.txt` | install a package: no denies |
| pip needs only `pypi.org/simple/**`, `files.pythonhosted.org/**` GET | `profiles/python/rules.txt` | install a package: no denies |

Known debt: at 2.1.330, subscription-token runs confirmed three of Claude Code's paths. The
rest date from API-key runs before 2.1.226. Re-check them with a working API key, rather
than widen a rule.

## Toolchain and CI pins

| Pin | Where | Check |
|---|---|---|
| mitmproxy `12.3.1` | `.github/workflows/ci.yml`, `test/linux/Dockerfile`, `test/test_proxy_lifecycle.py` | the `addon-mitmproxy-latest` canary job, and PyPI |
| msb `0.6.8` in CI, `0.5.4` and `0.5.7` by hand | `README.md`, `doc/THREAT-MODEL.md`, `test/linux/Dockerfile` | `silkgate verify --full` per platform |
| `debian:bookworm-slim` | `BASE_IMAGE` in `cli/silkgate_cli/images.py`, `doc/PROFILES.md` | Debian's current stable |
| `ubuntu:24.04`, glibc 2.39 | `test/linux/Dockerfile`, `README.md` | `ldd` on the current msb binary |
| action SHAs, tags in comments | `.github/workflows/ci.yml` | resolve each SHA. The comment can drift from it. |
| python 3.12 and 3.13 in CI | `.github/workflows/ci.yml` | the Ubuntu LTS python3, and the latest CPython |
| `ubuntu-24.04` runners expose `/dev/kvm` | `.github/workflows/containment.yml` | the workflow's own KVM probe warns |

## Tables in code

**These hand-kept tables mirror outside facts, and drift silently.**

| Table | Where | Check |
|---|---|---|
| `PRICES` and its "last reconciled" date | `ui/pricing.js` | diff against Anthropic's price and model lists. Every model in recent capture files must get a non-null `priceFor()`. |
| `_SECRET_PATTERNS`: 20 regexes from gitleaks | `mitmaddon/proxy_addon.py` | diff against gitleaks' `config/gitleaks.toml` |
| the Anthropic key shape `sk-ant-[A-Za-z0-9_-]{16,}` | `mitmaddon/proxy_addon.py` | a fresh Console key still matches |
| `CAPTURE_FORMATS` (only `anthropic`) | `mitmaddon/rule_engine.py` | when a decoder changes, grep `doc/DSL.md` and the profiles |
| capture caps: 64 KiB line, 256 KiB block, 2 MiB total | `mitmaddon/proxy_addon.py` | the largest SSE line in fresh capture files. One over-cap line ends capture for that flow. |
| the SSE grammar (`:` keepalives, unknown deltas ignored) | `_AnthropicCapture` in `mitmaddon/proxy_addon.py` | replay a fresh transcript and diff record kinds |
| Anthropic answers uncompressed | `mitmaddon/proxy_addon.py` | count `capture_error: content-encoding` records |
| the client's ~60 s stream timeout | `mitmaddon/proxy_addon.py` | the SDK's stream timeout, on a Claude Code bump |
| Claude Code tool names (`Bash`, `Write`, `Agent`, …) and their key fields | `toolCallView` in `ui/views/session.js` | grep fresh capture files for unmapped tool names |

## Observed microsandbox behavior

**msb is pre-1.0. Re-check each observation on every bump.**

| Observation | Where | Check |
|---|---|---|
| guest traffic arrives on loopback (macOS) | `cli/silkgate_cli/mitm.py` | the peer address of a guest connection |
| the first exec after a create can vanish, so the CLI retries once | `cli/silkgate_cli/vm.py` | 20 fresh creates: count first-exec timeouts |
| rule grammar and scope names | `cli/silkgate_cli/` | release notes, then `silkgate verify` |
| `--tail` honors `_SNAPSHOT_TAIL_LINES` (20000) | `cli/silkgate_cli/lifecycle.py` | snapshot a guest that printed more |
| `host.microsandbox.internal` resolves in a guest | `test/verify_guest.sh` | the guest's `/etc/hosts` |
| the installer URL, the brew tap, the repo owner, `--net-*` flags | `cli/silkgate_cli/`, `README.md` | HEAD the installer, resolve the tap, diff `msb run --help` |
| a rename across two virtiofs mounts is EXDEV, and git-lfs 3.3.0 has no fallback | `cli/silkgate_cli/git.py` | an LFS checkout across the mount |
| boot takes ~0.3 s | the skill | time `silkgate run -- true` |

## Observed Claude Code behavior

**Silkgate leans on Claude Code internals no contract guarantees.**

| Observation | Where | Check on a bump |
|---|---|---|
| `ANTHROPIC_CUSTOM_HEADERS` carries `X-Silkgate-Exec` | `cli/silkgate_cli/vm.py` | an exec's allow lines carry `exec` |
| `claude -p` waits at most 600 s for background subagents, and one env var lifts it | the skill | run one background subagent, and grep the binary for the variable |
| `CLAUDE_CODE_OAUTH_TOKEN` works for `claude -p` but not `--bare`, and `ANTHROPIC_API_KEY` outranks it | `profiles/claude/profile.conf`, `README.md` | under an `Authorization` secret: `silkgate-claude -p` answers, `claude --bare -p` says `Not logged in` |
| the default model needs the subscription to have it | `profiles/claude/profile.conf` | a `claude -p` with no settings answers |
| plugin cache rules, version floors, every claim from the docs mirror | `doc/PLUGIN.md` | re-read each cited page, and try one `--plugin-dir` install |
| the manifests' `$schema` URLs | `.claude-plugin/*.json` | `claude plugin validate .`, and HEAD both URLs |
| `anthropic-version=2023-06-01` in an example | `doc/DSL.md` | the current API docs |

## Dated documents

**Two documents are research snapshots. Each goes stale as a whole.**

| Snapshot | Check |
|---|---|
| [`doc/SOTA.md`](./SOTA.md), "Last verified: June 2026" | redo the research pass. HEAD every URL. Re-check the 2.1.90 patch floor. |
| the verified-platform table in [`doc/THREAT-MODEL.md`](./THREAT-MODEL.md) | `silkgate verify --full` per platform, on the current msb |

## Test fixtures and outside oracles

| Fact | Where | Check |
|---|---|---|
| fixture model ids and the SSE event set | `test/test_capture_decoder.py`, `test/test_capture_tap.py`, `ui/capture.test.js`, `ui/fixtures.test.js` | record one live streamed response, diff its events |
| fixture `pattern` values match `_SECRET_PATTERNS` names | `ui/fixtures.test.js` | grep them against the producer |
| the log scan matches mitmdump 12.3.1's line format | `test/test_proxy_lifecycle.py` | the canary job |
| `--full` fetches `https://registry.npmjs.org/lodash` | `test/verify_guest.sh` | fetch it from an open host |
| `evil.com` is never allowed | `test/verify_guest.sh` | grep every rules file |
| `1.1.1.1` answers TCP 443, ICMP, DNS. `192.0.2.1` never routes. | `test/verify_guest.sh`, `TIER1_PROBE_TARGET` in `cli/silkgate_cli/vm.py` | `curl -sv --connect-timeout 3 https://1.1.1.1/` from an open host |

## Cross-file pairs

**These facts live in more than one place. Move every copy together.**

| Fact | Copies | Check |
|---|---|---|
| the dummy key and dummy OAuth token | `guest_credential.*` in `profiles/claude/profile.conf`, `_SECRET_ALLOWLIST` in `mitmaddon/proxy_addon.py`, the dummy key's last 20 characters in `profiles/claude/setup.sh` | `grep -F DUMMY-replaced` both. A mismatch flags every transcript. |
| the Claude Code pin and its rules note | `profiles/claude/profile.conf`, the comment in `profiles/claude/rules.txt` | grep both for `2.1.` |
| mitmproxy `12.3.1` | see Toolchain | `rg -n '12\.3\.1'` |
| msb `0.6.8` | see Toolchain | `rg -n '0\.6\.8'` |
| model prices and windows | `ui/pricing.js`, `ui/pricing.test.js` | grep the test for every figure |
| secret pattern names | `_SECRET_PATTERNS`, `ui/fixtures.test.js` | grep the fixture patterns |
| file-path keys: `file_path` for read, edit, write, multiedit, and `notebook_path` | the salient map in `ui/views/session.js`, `FILE_KEYS` in `ui/timeline.js` | diff the shared entries |
