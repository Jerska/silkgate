# Packaging silkgate as a Claude Code plugin

Read this to decide how to ship silkgate as a Claude Code plugin, and what to verify first.

**The verdict: yes, and in one specific shape — the whole repo is the plugin, and the same
repo carries its own one-entry marketplace.** A teammate then runs two slash commands and
has the skill, the CLI, the addon, and the profiles, pinned to a commit, available in every
project. What no plugin can deliver is the host stack (docker, mitmproxy, msb, KVM/HVF). The
honest fix for that is a prerequisite check that fails at first use with the exact install
command, not a stack trace.

## How to read the claims in this document

**Every "the docs say" claim below was read from a mirror, because this investigation's
sandbox had no route to the canonical docs.** The canonical Claude Code docs live at
`code.claude.com`, and both `docs.claude.com` and `docs.anthropic.com` answer `301` to
`code.claude.com` for every Claude Code page. Each claim was therefore read from
[ericbuess/claude-code-docs](https://github.com/ericbuess/claude-code-docs), last synced the
day of this investigation (2026-08-05), and cross-checked where possible against manifests
Anthropic itself ships. The labels:

- **doc** — stated on an official docs page (cited by its canonical URL, read via the
  mirror).
- **observed** — read from a file in an Anthropic-owned GitHub repo (`anthropics/claude-code`,
  `anthropics/claude-plugins-official`), so the format as Anthropic actually uses it.
- **inferred** — follows from the above but is not stated anywhere.
- **untested** — nothing in this sandbox can install a plugin, so every end-to-end claim is
  untested. The label marks the ones where the docs also leave room for doubt.

Whoever spends the day on this must budget the first half hour for `claude --plugin-dir .`
against a real Claude Code, which converts most of the **untested** labels into facts.

## The plugin format, as documented

### What a plugin is on disk

**A plugin is a directory, and even its manifest is optional.** The only reserved location
is `.claude-plugin/plugin.json`. Without it, components are auto-discovered in default
locations and the plugin takes its directory's name
([plugins-reference § Plugin manifest schema](https://code.claude.com/docs/en/plugins-reference)).
If a manifest exists, `name` is the only required field (**doc**). Everything else —
`version`, `description`, `author`, component-path overrides — is optional. Unrecognized
top-level fields are ignored at load time and reported as warnings by
`claude plugin validate` (**doc**), so a manifest cannot easily be *invalid*, only wrong.

Components live at fixed paths under the plugin root, all optional (**doc**,
[plugins-reference § Plugin directory structure](https://code.claude.com/docs/en/plugins-reference)):

| Path | Component |
|---|---|
| `skills/<name>/SKILL.md` | Skills — first-class and distributable. This is the crux the brief asked about, and the answer is plainly yes. |
| `commands/*.md` | Skills as flat files (the legacy spelling — the docs say use `skills/` for new plugins) |
| `agents/*.md` | Subagents |
| `hooks/hooks.json` | Hooks (also inline in plugin.json) |
| `.mcp.json` | MCP servers (also inline) |
| `bin/` | Executables added to the Bash tool's `PATH` — "invokable as bare commands in any Bash tool call while the plugin is enabled" |
| `.lsp.json`, `output-styles/`, `workflows/`, `monitors/`, `themes/` | The rest — not relevant here |

Anthropic ships skills inside plugins itself: `anthropics/claude-code` carries
`plugins/claude-opus-4-5-migration/skills/claude-opus-4-5-migration/SKILL.md` with
supporting `references/` files (**observed**,
[repo tree](https://api.github.com/repos/anthropics/claude-code/git/trees/HEAD)). A plugin
skill is namespaced `plugin-name:skill-name`, so it cannot collide with a project or
personal skill ([skills doc](https://code.claude.com/docs/en/skills), **doc**).

Component paths can be redirected in the manifest. The one that matters for silkgate:
`"skills"` takes directories that contain `<name>/SKILL.md`, must be relative to the plugin
root and start with `./`, and adds to the default `skills/` scan rather than a replacement
of it (**doc**,
[plugins-reference § Component path fields](https://code.claude.com/docs/en/plugins-reference)).
So `"skills": ["./.claude/skills/"]` exposes the skill this repo already ships, without a
file move. Whether the scanner accepts a dot-directory in that path is stated nowhere
(**untested** — see the list at the end). The fallback is a one-line
`skills/sandboxed-agent → ../.claude/skills/sandboxed-agent` symlink, because symlinks that
resolve inside the plugin are preserved on install (**doc**).

### Versions, and what actually pins an install

**The version is the cache key, and this repo must omit it, so every commit is a new
version.** A plugin's version resolves in order: `version` in plugin.json, then `version` in
its marketplace entry, then the git commit SHA of its source, then `"unknown"` (**doc**,
[plugins-reference § Version management](https://code.claude.com/docs/en/plugins-reference)).
Same version, no update. The docs warn that a `version` field nobody bumps silently freezes
users on old code. Omit it entirely and every commit is a new version — for a security tool
the honest mode, and the recommendation below.

### Marketplaces, and installs from a plain GitHub repo

**Plugins install through marketplaces, and the marketplace and the plugin can be the same
repository.** A marketplace is a repo (or directory) whose `.claude-plugin/marketplace.json`
lists plugins and where to fetch them
([plugin-marketplaces](https://code.claude.com/docs/en/plugin-marketplaces), **doc**). The
required fields: `name`, `owner.name`, `plugins[]`, and each entry needs `name` and
`source`. A plain GitHub repo *is* a marketplace source — `/plugin marketplace add
owner/repo` — but only if it contains that file. A bare repo with no `marketplace.json`
cannot be installed from directly. Session-scoped sideload (`claude --plugin-dir <dir>`) is
the only marketplace-free path, and it does not persist (**doc**).

One repository serves as both in two documented ways:

- An entry with a relative `source: "./plugins/foo"` resolves against the marketplace root.
  Anthropic's own `anthropics/claude-code` and `anthropics/claude-plugins-official` are both
  built this way (**observed**).
- `source: "./"` — the marketplace root itself is the plugin — is explicitly discussed,
  with a special rule for how `skills` paths behave in that case (**doc**,
  [plugin-marketplaces § Advanced plugin entries](https://code.claude.com/docs/en/plugin-marketplaces)).
  This is silkgate's shape: one repo, one plugin, one entry.

### Install, pinning, updates

**An installed plugin runs from a versioned local cache, not from the marketplace clone.**
`/plugin marketplace add owner/repo` clones the marketplace, and
`/plugin install name@marketplace` copies the plugin into `~/.claude/plugins/cache`, one
immutable directory per installed version (**doc**,
[plugins-reference § Plugin caching](https://code.claude.com/docs/en/plugins-reference)).
Three consequences matter:

- Paths that traverse above the plugin root (`../`) are dead after install. Symlinks are
  kept if they resolve inside the plugin, dereferenced if they resolve elsewhere in the
  marketplace, and dropped if they point outside it (**doc**).
- Pinning: a marketplace *source* takes a `ref` (branch or tag — `#v1.0.0` appended to a
  git URL at add time), and a plugin *source* inside marketplace.json additionally takes a
  full 40-character `sha` (**doc**). With `source: "./"` the plugin rides the marketplace
  clone, so the pin is whatever ref the user added the marketplace at.
- Updates: `/plugin marketplace update` refreshes the catalog, and `/plugin update` moves
  the cache to the new version. Background auto-update exists but is disabled by default
  for third-party marketplaces (**doc**,
  [discover-plugins § Configure auto-updates](https://code.claude.com/docs/en/discover-plugins)).
  For a security tool that default is exactly right: nothing changes under the user without
  an explicit command.

A team can also push the whole thing through settings: a project's `.claude/settings.json`
can declare `extraKnownMarketplaces` and `enabledPlugins`, and collaborators are prompted to
install when they trust the folder (**doc**,
[plugin-marketplaces § Require marketplaces for your team](https://code.claude.com/docs/en/plugin-marketplaces)).
That is the zero-command path for a team that already trusts a repo.

## The hard part: silkgate is code, not prose

### Can a plugin ship and execute code? Yes, three documented ways

**A skill can learn its own plugin's path: `${CLAUDE_PLUGIN_ROOT}` resolves to the
installation directory.** The substitution table says where it applies (**doc**,
[plugins-reference § Environment variables](https://code.claude.com/docs/en/plugins-reference)):

| Component | Where `${CLAUDE_PLUGIN_ROOT}` resolves |
|---|---|
| Skill and agent content | "Anywhere the placeholder appears" |
| Hook and monitor commands | Anywhere |
| MCP/LSP server configs | command/args/env fields |

So the skill can say `"${CLAUDE_PLUGIN_ROOT}"/cli/silkgate run …` and the path is real at
the moment Claude reads it. Second, `bin/` puts executables on the Bash tool's `PATH`
(**doc**) — a relative symlink `bin/silkgate → ../cli/silkgate` makes the invocation just
`silkgate` (**inferred + untested**: the combination of `bin/` with a symlink, and exec-bit
preservation through the cache copy, are both undocumented — `bin/`'s existence implies that
executables survive install, and `python3 "${CLAUDE_PLUGIN_ROOT}/cli/silkgate"` sidesteps
the exec bit entirely, because the CLI is stdlib-only with a `#!/usr/bin/env python3`
shebang).
Third, hooks execute arbitrary commands against the same root.

And silkgate is already built for this. `cli/silkgate` locates everything it needs relative
to itself — `REPO = Path(__file__).resolve().parent.parent`, then `mitmaddon/` and
`profiles/` under it (cli/silkgate:51–53) — and never writes into its own tree: host state
lives in `~/.silkgate/`, and image identity is a content hash over profile bytes, not a
path. Even the mount-refusal list tracks `REPO` dynamically (cli/silkgate:1844), so an
installed copy correctly refuses to mount its own cache directory. Two path-related caveats,
both minor: `.resolve()` follows the `bin/` symlink to the right root (**inferred**), and
`${CLAUDE_PLUGIN_ROOT}` changes on every update — the old directory lingers ~14 days for
live sessions, and nothing must store that path (**doc**). Silkgate stores no such path, and
cached docker images survive updates untouched because their tags hash content, not
location.

One real edit is required, and it is not this document's to make: the skill's invocations
say `./cli/silkgate`, relative to a checkout that a plugin user does not have. The skill
already hedges ("from the repo root … or by absolute path"). Shipped as a plugin it needs
one added sentence — *when installed as the silkgate plugin, the CLI is
`"${CLAUDE_PLUGIN_ROOT}"/cli/silkgate`* — phrased as prose, because the same SKILL.md still
serves repo checkouts as a project skill, where no substitution happens and the placeholder
stays literal. The skill is under rewrite as this is written. This is a coordination note
for that rewrite, not a patch.

### Prerequisites the plugin system cannot install

**Nothing in the plugin system installs host software, so docker, mitmproxy, msb, and
KVM/HVF stay manual.** The `dependencies` manifest field is plugin-to-plugin only (**doc**,
[plugin-dependencies](https://code.claude.com/docs/en/plugin-dependencies)), and
`userConfig` prompts for *values*, not capabilities. A plugin that installs cleanly and then
dies on first `run` is the bad artifact the brief warns about. What the system does offer:

- `SessionStart` hooks run on every session. Their stdout is added to Claude's context, and
  the docs say to keep them fast (**doc**,
  [hooks § SessionStart](https://code.claude.com/docs/en/hooks)).
- A `Setup` hook fires only under `--init-only` / `-p --init` — CI territory, not the
  interactive first-run path.

**The plugin must ship no hook.** A `SessionStart` hook works, and it was the obvious
answer, but it is the wrong one: it charges every session in the project for a tool most
sessions never invoke, and it puts the check as far as possible from the thing it checks.
The docs' own advice to keep SessionStart fast is a hint that this is not what it is for.

The check belongs where silkgate is invoked, which is also where it already partly lives.
`which()` (cli/silkgate:110) takes the binary and the install command and dies with both
named — *"`mitmdump` not found — pip install mitmproxy"* — at the moment the tool is needed.
A hook duplicates that and runs whether or not anyone reaches for a sandbox.

What the lazy version does cost is round trips. Each tool is looked up only when first
needed, so a user with none of the stack learns about it one command at a time: `docker`
when the image builds, `mitmdump` when the proxy starts, `msb` when the guest is created.
Three installs, three failed runs, and no way to see the whole list up front. The fix is a
preflight at the start of any command that needs the toolchain, which reports *every*
absent tool together with its install command — three `shutil.which` calls, microseconds,
paid only by people who run silkgate. `silkgate verify` stays the deep check: preflight
answers "is the toolchain here", and verify answers "does containment actually hold".

That leaves the plugin with no auto-executed content at all, which is the right posture for
a security tool: an install adds a skill and a CLI to the machine and changes nothing about
how sessions start.

### Which shape

**Shape 1 — the whole repo is the plugin — and it quietly subsumes the other two.**

- *Against rot:* with `source: "./"` nothing is duplicated anywhere. The plugin **is** this
  repo at a commit, and the cache copy is made by Claude Code at install time, versioned by
  SHA. There is no second copy of `cli/silkgate` for anyone to forget to update. (The
  brief's rot worry applies to shape 2, where the skill documents a CLI at whatever commit
  the user's separate clone happens to sit.)
- *Against the security question:* "where did this executable come from and what pins it"
  has a crisp answer — the marketplace clone's commit SHA, visible in the cache path and in
  `/plugin` details, with auto-update off by default and updates only via explicit
  `/plugin marketplace update` plus `/plugin update`. An organization that wants more can
  run its own one-file marketplace that lists silkgate with a hard 40-character `sha` pin
  (**doc**) — strictly stronger than what `git clone` habits give most users. The docs' own
  caveat applies and belongs in anything told to users: Anthropic does not vet third-party
  plugins, and trust is between the user and this repo.
- *Weight:* the whole repo — `test/` and `doc/` included — rides into the cache. It is
  540 KB. Context cost is only the skill's frontmatter description (`claude plugin details`
  shows the always-on figure, **doc**). Docs beside the tool are a feature for a security
  tool, not bloat.
- *Shape 2 (thin plugin plus separate clone)* is strictly worse: two artifacts that skew, a
  `userConfig` directory prompt where shape 1 needs nothing, and no answer to pinning at
  all. *Shape 3* is shape 2's maintenance bill paid twice. And the constituency shape 2
  serves — people who already have the clone — is served by shape 1's own machinery:
  `/plugin marketplace add ~/src/silkgate` installs from their audited local clone
  (local-path marketplaces, **doc**), and `claude --plugin-dir ~/src/silkgate` sideloads it
  in place for development. One artifact, three consumption modes.

The repo needs exactly two new files (scaffolded, see below), one skill sentence (owned by
the skill rewrite), and optionally the `bin/` symlink. No hook, and no file moves.

### A user's first five minutes

**Two slash commands install everything the repo can deliver.**

```text
/plugin marketplace add <owner>/silkgate         # or the git URL; append #v0.X to pin a tag
/plugin install silkgate@silkgate                # scope: user → available in every project
```
*(`<owner>` is wherever this repo lives on GitHub)*

Install reports "Plugin is now active", and nothing else changes — no hook runs, and
sessions start exactly as before. The user learns what is absent the first time they ask
for a sandbox: the CLI's preflight names every absent tool with its install command at
once, for example `mitmdump not found — pip install mitmproxy` beside `msb not found —
curl -fsSL https://install.microsandbox.dev | sh`. Two installs later, they export
`SILKGATE_EGRESS_SECRET_ANTHROPIC="x-api-key: …"` in their shell profile, per the README.
Then, in any project: *"run the failing tests in a sandbox and fix them"* — the skill fires
as `silkgate:sandboxed-agent`, invokes the CLI out of the plugin root, builds the first
image (about a minute, once), and the audit log path prints. `silkgate verify` on request.
Total new concepts for the user: two slash commands and three host installs they needed
anyway.

## What was not determinable from here

**Nothing below blocks the recommendation. Each is a checkbox for the first `--plugin-dir`
session.**

1. The canonical docs themselves. `code.claude.com` is not on this sandbox's allowlist and
   both permitted docs hosts 301 to it (`GET code.claude.com/docs/**` is the access a
   future investigation must request). Every **doc** citation was read from a mirror synced
   2026-08-05 and spot-checked against Anthropic-owned manifests. Exact canonical wording
   can differ.
2. The dot-directory skills path. `"skills": ["./.claude/skills/"]` is legal per the path
   rules, but no doc mentions a scan inside a dot-directory. Verify, or fall back to the
   in-plugin symlink.
3. Exec-bit preservation through the cache copy, and `bin/` symlinks specifically.
   `python3 "${CLAUDE_PLUGIN_ROOT}/cli/silkgate"` is the spelling that needs neither.
4. `#ref` pinning with the `owner/repo` shorthand at `marketplace add` — documented for git
   URLs, unstated for the shorthand.
5. Whether `${CLAUDE_PLUGIN_ROOT}` substitutes in a skill's auxiliary files
   (`references/*.md`) or only SKILL.md. "Skill content, anywhere" probably covers both,
   but it is one word in a table.
6. Whether an installed plugin's own `.claude/` directory is inert in the cache. No doc
   assigns it meaning there. Presumed harmless.
7. The minimum Claude Code version. Several cited niceties are gated (`displayName`
   ≥2.1.143, `defaultEnabled` ≥2.1.154, same-session activation ≥2.1.221). The core
   install flow predates all of them, but no floor version was determinable.

## Scaffold

**`.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` exist as of this
investigation — minimal, and untested**, because no plugin can be installed from inside the
sandbox this was written in. They omit `version` deliberately (commit-SHA versions, per the
recommendation above) and carry the dot-directory skills path from caveat 2. Validate with
`claude plugin validate . --strict`, then `claude --plugin-dir .`, before anyone is told to
install.
