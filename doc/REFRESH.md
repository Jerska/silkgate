# Refresh registry

Read this to find the facts in this tree that rot with time, and the check that catches
each one.

Every entry is a fact an external party owns: a version, a price, a model id, a URL, a
measurement, or another system's behavior. None of them is a defect.
Each goes stale on somebody else's schedule, and its check is how this repository finds
out. When a check fails, fix the fact and every copy that [Cross-file
pairs](#cross-file-pairs) names for it. This registry names files and identifiers, not
line numbers — line numbers rot faster than the facts they point at.

## Profile pins

**Each profile pins one upstream version, and the pin ages on that upstream's release
schedule.** The pins, and the check for each:

| Pin | Where | Check |
|---|---|---|
| Claude Code `2.1.226` | `default_version` in [`profiles/claude/profile.conf`](../profiles/claude/profile.conf) | Compare `npm view @anthropic-ai/claude-code version` to the pin. Claude Code releases near-daily, so this pin ages fastest. |
| node `22.11.0` | `default_version` in [`profiles/node/profile.conf`](../profiles/node/profile.conf), echoed by examples in the sandboxed-agent skill | Compare to the latest 22.x on the Node release schedule. Diff every `@x.y.z` in the skill against the profile. Node 22 reaches end of life in 2027. |
| python `3.12.7` | `default_version` in [`profiles/python/profile.conf`](../profiles/python/profile.conf) | Compare to the latest 3.12.x security release. |
| uv `0.5.14` | `UV_VERSION` in [`profiles/python/setup.sh`](../profiles/python/setup.sh) | Compare to the latest uv release. The image build asserts `uv --version`. |

**A pin bump can also break the install contract around the pin, so each contract has
its own check.** These facts belong to the upstream vendor, not to this repository:

| Contract | Where | Check |
|---|---|---|
| The installer at `https://claude.ai/install.sh` accepts a pinned version argument | `profiles/claude/setup.sh` | Build the image and assert `claude --version` equals the pin. |
| `packages = curl libgcc-s1 libstdc++6 ripgrep` are the native binary's runtime needs | `profiles/claude/profile.conf` | After a bump, run `ldd` on the binary in a fresh image. |
| `context_path` is read on a plain `claude -p` and not under `--bare` | `profiles/claude/profile.conf` | On a bump, check that a guest `claude -p` reads the file and `--bare` does not. |
| `--permission-mode bypassPermissions` exists, and `IS_SANDBOX=1` lifts the refusal to bypass permissions as root | `profiles/claude/setup.sh` | On a bump, run the wrapper as root in a guest and expect no refusal. |
| The Claude Code switches in the env file (`DISABLE_AUTOUPDATER`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, …) | `profiles/claude/env` | On a bump, check each name against the settings documentation, and watch the audit log for new hosts. |
| The node tarball URL layout under `nodejs.org/dist` | `profiles/node/setup.sh` | The build asserts `node --version` against the pin. |
| The Debian mirrors `deb.debian.org` and `security.debian.org` | `profiles/probe/rules.txt` | Run `silkgate verify --full` and check that the probe tools install through the proxy. |

## Egress rule lists

**Each rules file encodes what an external service needs today, and the service moves
first.** A path the service adds later fails as a 403 the guest reports as silkgate
policy, so audit-log denies are the staleness signal.

| List | Where | Check |
|---|---|---|
| The Claude Code endpoint list: `/v1/messages` and `count_tokens`, `/v1/models`, the `claude_code` paths, `domain_info`, the Console oauth prefix | [`profiles/claude/rules.txt`](../profiles/claude/rules.txt) | Re-derive the list from fresh audit logs at the pinned version. Grep audit logs for denies on `api.anthropic.com` and `platform.claude.com`. |
| `max_body=10m` on the two POSTed Anthropic paths, `64k` on oauth | `profiles/claude/rules.txt` | Grep audit logs for 413 answers. Request bodies grow with new tool shapes. |
| GitHub smart-HTTP facts: the `?service=` requirement, protocol v2 with a v0 fallback, `max_body=1m` for negotiation | [`profiles/github/rules.txt`](../profiles/github/rules.txt) | Clone and fetch a public repository through the profile, and assert zero denies and no 413. |
| The GitHub content hosts `raw.githubusercontent.com` and `codeload.github.com` | `profiles/github/rules.txt` | Fetch a raw file and a tarball through the profile. |
| GitHub LFS infrastructure by name (`lfs.github.com`, `github-cloud.*`), the no-redirect path forms, and the S3 501 on a doubled Authorization header | `profiles/github-read/rules.txt` and `profiles/github-write/rules.txt` | Run a live LFS clone and push against a scratch repository, and assert zero denies. |
| The SAML SSO shape: an unauthorized PAT answers GitHub's own 403 or 404 with an `X-GitHub-SSO` response header | `README.md` (GitHub egress) | Run one grant with a deliberately unauthorized PAT against an SSO organization, and check the header beside the audit allow line. |
| npm needs only `registry.npmjs.org/**` GET | `profiles/node/rules.txt` | Install a package in a guest and grep the audit log for denies. |
| pip needs only `pypi.org/simple/**` and `files.pythonhosted.org/**` GET | `profiles/python/rules.txt` | Install a package in a guest and grep the audit log for denies. |

The Claude Code list carries a known debt: it was derived from audit logs before the pin
moved to 2.1.226. The file's own comment says so. Re-derive it at the current pin rather
than widen a rule.

## Toolchain and CI pins

**CI and the Linux test image pin the toolchain, and several pins have copies that must
move in lockstep.**

| Pin | Where | Check |
|---|---|---|
| mitmproxy `12.2.3`, the version the addon is verified against | `.github/workflows/ci.yml`, `test/linux/Dockerfile`, a comment in `test/test_proxy_lifecycle.py` | Run `rg -n '12\.2\.3'` and check that all three sites agree. Watch the `addon-mitmproxy-latest` canary job, and compare the pin to the PyPI latest. |
| msb `0.6.8` in CI, `0.5.4` and `0.5.7` by hand | `README.md`, `doc/THREAT-MODEL.md`, `test/linux/Dockerfile` | On a bump, run `silkgate verify --full` per platform and update every citation. |
| `BASE_IMAGE = "debian:bookworm-slim"` | `cli/silkgate` | Compare to the current Debian stable codename and its release schedule. |
| `FROM ubuntu:24.04` and the glibc `2.39` floor for msb release binaries | `test/linux/Dockerfile`, `README.md` | Run `ldd` on the current msb release binary and read the required GLIBC symbols. Bump the base image when noble ages out. |
| `actions/checkout` and `actions/setup-python` pinned to commit shas, with release tags in comments | `.github/workflows/ci.yml` | Resolve each sha and compare it to the action's latest release tag. The comment can drift from the sha. |
| The Python test matrix, 3.12 and 3.13 | `.github/workflows/ci.yml` | Compare the matrix to the current Ubuntu LTS python3 and the latest stable CPython. |
| GitHub's `ubuntu-24.04` runners expose `/dev/kvm` | `.github/workflows/containment.yml` | The workflow's own KVM probe warns. Read the runner-image notes when the label ages out. |

## Static tables in code

**Three hand-kept tables answer for outside facts — prices, secret shapes, and capture
formats — and each drifts silently unless its check runs.**

| Table | Where | Check |
|---|---|---|
| `PRICES`: model-id prefixes, dollars per MTok, cache multipliers, context windows, and a "last reconciled" date | [`ui/pricing.js`](../ui/pricing.js) | Diff every row against the published price list and the models list, then move the reconciled date. For every model in recent capture files, assert `priceFor()` is not null — a new model id answers null and hides its cost. |
| The Sonnet 5 row holds an introductory rate that ends 2026-08-31 and reverts to `[3, 15, 0.3, 3.75]` | `ui/pricing.js` | Replace the row after that date. The row's own comment carries the deadline. |
| `_SECRET_PATTERNS`: 20 vendor-prefixed regexes from the gitleaks default set, with `_SECRET_TRIGGERS` literals beside them | [`mitmaddon/proxy_addon.py`](../mitmaddon/proxy_addon.py) | Diff each regex against `config/gitleaks.toml` at the gitleaks HEAD. Vendors rotate token prefixes and lengths. |
| The Anthropic key shape `sk-ant-[A-Za-z0-9_-]{16,}` | `mitmaddon/proxy_addon.py` | Check that a fresh Console key still matches, and cross-check the gitleaks anthropic rule. |
| `CAPTURE_FORMATS`, the decoder names a `capture=` rule can cite (today only `anthropic`) | [`mitmaddon/rule_engine.py`](../mitmaddon/rule_engine.py) | When a decoder lands or retires, run the rule-engine self-tests and grep `doc/DSL.md` and the profiles for the format names. |
| The capture caps: `_CAPTURE_LINE_MAX` at 64 KiB, block at 256 KiB, total and JSON at 2 MiB — sized from real Anthropic event lines | `mitmaddon/proxy_addon.py` | Measure the largest observed SSE line and body in live capture files after each API or model change. One over-cap line kills capture for that flow. |
| The SSE grammar: keepalives as `:` comments, unknown delta types ignored, `ping` and newer event types pass silently | `mitmaddon/proxy_addon.py` (`_AnthropicCapture`) | Replay a fresh live transcript through `_AnthropicCapture` and diff the record kinds against the response content. A new content kind is lost without a sign. |
| The identity-encoding assumption: Anthropic answers uncompressed, so metadata-only is the fallback | `mitmaddon/proxy_addon.py` | Count `capture_error: content-encoding` records in live capture files and alert above zero. |
| The stream-vs-buffer rationale cites the client's rough 60-second timeout | `mitmaddon/proxy_addon.py` | Read the current SDK stream timeout on a Claude Code pin bump. |

## Observed microsandbox behavior

**Code and docs record what msb 0.5.4 through 0.6.8 does, and msb is pre-1.0 — re-check
each observation on every bump.**

| Observation | Where | Check |
|---|---|---|
| Guest traffic arrives on loopback (observed on macOS/HVF) | `cli/silkgate` | Re-observe the peer address of a guest connection. |
| msb can swallow the first exec after a create, so the code retries once | `cli/silkgate` | Run the Tier-1 probe 20 times after fresh creates and count first-exec timeouts. An upstream fix makes the retry wrong. |
| The msb rule grammar and scope names are pre-1.0 and unpinned | `cli/silkgate` | Read the msb release notes, then run `silkgate verify`. |
| `--tail` limits a snapshot to `_SNAPSHOT_TAIL_LINES` (5000) — the flag is msb's to honor | `cli/silkgate` | Snapshot a guest that printed more than 5000 lines and count what arrives. |
| The gateway alias `host.microsandbox.internal` resolves in a guest | `test/verify_guest.sh` | Check the alias in `/etc/hosts` inside a guest. |
| The installer at `install.microsandbox.dev`, the brew tap, the repository owner, and `--net-*` flag stability | `cli/silkgate`, `README.md` | Send a HEAD request to the installer URL, check that the tap and the repository resolve, and diff `msb run --help`. |
| A rename across two virtiofs mounts is EXDEV, and git-lfs 3.3.0 has no copy fallback | `cli/silkgate` | Retest an LFS checkout across the mount with the git-lfs the base image ships. |
| Boot is ~0.3 s | `README.md` | Re-time `silkgate run -- true` on an msb bump. |

## Observed Claude Code behavior

**The sandbox leans on Claude Code internals that no contract guarantees, so each pin
bump re-tests them.**

| Observation | Where | Check |
|---|---|---|
| `ANTHROPIC_CUSTOM_HEADERS` is the SDK's escape hatch for extra headers and carries `X-Silkgate-Exec` | `cli/silkgate` | Run one journaled exec and assert `exec` appears on the audit allow line. A rename silently ends exec attribution. |
| Interactive Claude Code probes `platform.claude.com/v1/oauth/hello` at startup | `doc/ARCHITECTURE.md` | Run interactive claude in a guest and diff the probed hosts in the audit log. |
| An in-guest `claude -p` waits at most 600 seconds for background subagents, and one env var overrides the ceiling | the sandboxed-agent skill | On a pin bump, run one background subagent and grep the new binary for the variable name. |
| Plugin cache semantics, feature version floors, and every claim cited from the docs mirror | `doc/PLUGIN.md` | Re-fetch each cited page from `code.claude.com`, diff every claim, and run one `--plugin-dir` install on current Claude Code. |
| The plugin manifest `$schema` URLs at `json.schemastore.org` | `.claude-plugin/plugin.json` | Run `claude plugin validate . --strict`, plus a HEAD request on both schema URLs. |
| The example rule pins `h:anthropic-version=2023-06-01` | `doc/DSL.md` | Compare to the `anthropic-version` in the current API documentation. |

## Documentation snapshots

**Two documents are dated research, and each rots as a whole rather than row by row.**

| Snapshot | Where | Check |
|---|---|---|
| "Last verified: June 2026", the boot and overhead figures, the Claude Code sandbox internals with their 2.1.90 patch floor, and about 25 source URLs | [`doc/SOTA.md`](./SOTA.md) | Re-run the research pass and move the verified date. Send a HEAD request to every URL and replace each 404. Re-read the srt repository and check the patch floor is still the relevant one. |
| The verified-platform list and the no-IPv6 note for Linux guests | [`doc/THREAT-MODEL.md`](./THREAT-MODEL.md) | Run `silkgate verify --full` on the current msb per platform and update the version list. |
| The README measurements: "all fifteen checks", "15/15 on macOS by hand", the msb version list | [`README.md`](../README.md) | Cross-check against `verify` output and `containment.yml` on every change to either. |

## Test fixtures and external oracles

**The suite freezes today's wire shapes and leans on services nobody here controls.**

| Fact | Where | Check |
|---|---|---|
| Fixture model ids (`claude-sonnet-4-5`, dated snapshot ids) and the frozen SSE event vocabulary | `test/test_capture_decoder.py`, `test/test_capture_tap.py`, `ui/capture.test.js`, `ui/fixtures.test.js` | Record one live streamed response per API change, diff its event set against the fixture builders, and refresh the ids. |
| The fixture `pattern` values must be spelled as `_SECRET_PATTERNS` names them | `ui/fixtures.test.js` | Grep the fixture patterns against the producer's name list. |
| The log scan matches the real line format mitmdump 12.2.3 writes | `test/test_proxy_lifecycle.py` | The `addon-mitmproxy-latest` canary job. Update the scan when the pin moves. |
| The full check fetches `https://registry.npmjs.org/lodash` | `test/verify_guest.sh` | Fetch the URL from an unrestricted host in CI. |
| `https://evil.com` is the guaranteed-unlisted host | `test/verify_guest.sh` | Grep every rules file for `evil.com`. Keep the header-discrimination check green. |
| The external oracles: `1.1.1.1` answers TCP 443, ICMP and DNS (also `TIER1_PROBE_TARGET` in `cli/silkgate`), and TEST-NET-1 `192.0.2.1` never routes | `test/verify_guest.sh` | From an unrestricted host, run `curl -sv --connect-timeout 3 https://1.1.1.1/`, and send one ICMP echo from CI. |

## Cross-file pairs

**The highest-risk facts live in more than one place, and every copy must move
together.**

| Fact | Copies | Check |
|---|---|---|
| The Anthropic dummy key | `profiles/claude/env`, `_SECRET_ALLOWLIST` in `mitmaddon/proxy_addon.py` | `grep -F sk-ant-DUMMY-` both files and compare the literals byte for byte. A mismatch raises a false sighting on every transcript. |
| The Claude Code pin against the rules derivation | `profiles/claude/profile.conf`, the comment in `profiles/claude/rules.txt` | Grep both for `2.1.` and check the versions agree. On a bump, re-derive the endpoint list, then update the comment. |
| mitmproxy `12.2.3` | `.github/workflows/ci.yml`, `test/linux/Dockerfile`, `test/test_proxy_lifecycle.py` | `rg -n '12\.2\.3'` — all three sites must agree. |
| msb `0.6.8` | `README.md` (three sites), `doc/THREAT-MODEL.md`, `test/linux/Dockerfile` | `rg -n '0\.6\.8'` and update every citation on a bump. |
| `node@22.11.0` | `profiles/node/profile.conf`, the sandboxed-agent skill examples | Diff every `@x.y.z` in the skill against the profile's `default_version`. |
| Model prices and context windows | `ui/pricing.js`, re-hardcoded in `ui/pricing.test.js` | When `PRICES` changes, grep `pricing.test.js` for every dollar figure and every window. |
| The sighting pattern names | `_SECRET_PATTERNS` in `mitmaddon/proxy_addon.py`, `ui/fixtures.test.js` | Grep each fixture `pattern` value against the producer's names. |
