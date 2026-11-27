# Silkgate as a Claude Code plugin

Read this to ship silkgate as a Claude Code plugin, or to finish testing that it works.

## The shape

**The whole repo is the plugin, and the same repo is its own one-entry marketplace.**

```text
/plugin marketplace add <owner>/silkgate      # append #<tag> to pin
/plugin install silkgate@silkgate
```

That gives every project the skill, the CLI, the addon, and the profiles, pinned to a
commit. No plugin can install the host stack (docker, mitmproxy, msb, KVM or HVF). The CLI
names what's missing at first use, with install commands.

## Status

**The scaffold is in place, and it validates. Nobody has installed it end to end yet.**

| Item | State |
|---|---|
| `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | present |
| `claude plugin validate .` | passes, with one warning: no `version`, on purpose (below) |
| `claude plugin validate . --strict` | fails on that same warning, by design |
| an install through `/plugin install` | untested |
| the skill's CLI path under a plugin install | not written yet (below) |

Test it in this order:

```sh
claude plugin validate .
claude --plugin-dir .           # then ask for a sandbox, and check the skill fires
```

## Decisions

**No `version`, no hook, no file moves.**

- No `version` field. A plugin's version is its cache key. Without one, Claude Code uses the
  commit SHA, so every commit is a new version. A `version` nobody bumps freezes users on
  old code.
- The marketplace entry is `"source": "./"`: the marketplace root is the plugin. Nothing is
  copied, so nothing can drift.
- `"skills": ["./.claude/skills/"]` exposes the skill this repo already has. If the loader
  skips dot-directories, add a `skills/sandboxed-agent` symlink to it instead.
- No hook. A `SessionStart` hook would charge every session for a tool most never use. The
  CLI's own preflight (`silkgate doctor`, and each command's startup) lists every missing
  tool at once.
- Updates are explicit: auto-update is off by default for third-party marketplaces. An org
  that wants a hard pin can run its own marketplace with a 40-character `sha`.

The whole repo, docs and tests included, rides into the cache: about 540 KB. Only the
skill's description costs context.

## How the CLI finds itself

**`cli/silkgate` finds everything relative to its own file, so an installed copy works from
the plugin cache.**

- It resolves `mitmaddon/` and `profiles/` from its own path, and keeps state in
  `~/.silkgate/`, never in its tree.
- Image tags hash content, not paths, so cached images survive plugin updates.
- Its mount refusal covers its own directory, the plugin cache included.

The skill still says `./cli/silkgate`, which only works from a checkout. Under a plugin
install the path is `"${CLAUDE_PLUGIN_ROOT}"/cli/silkgate`. The skill needs one sentence
that says so, in prose, because the same file still serves checkouts, where the placeholder
stays literal. A `bin/silkgate → ../cli/silkgate` symlink would put `silkgate` on the Bash
tool's `PATH`. Whether `bin/` symlinks and exec bits survive the cache copy is undocumented,
and `python3 "${CLAUDE_PLUGIN_ROOT}/cli/silkgate"` needs neither.

## Open checks

**None of these blocks shipping. Each is a checkbox for the first `--plugin-dir` session.**

1. Does the skill scan accept a dot-directory (`./.claude/skills/`)?
2. Do exec bits and `bin/` symlinks survive the cache copy?
3. Does `#ref` pinning work with the `owner/repo` shorthand, or only with a git URL?
4. Does `${CLAUDE_PLUGIN_ROOT}` substitute in a skill's extra files, or only in `SKILL.md`?
5. Is the plugin's own `.claude/` directory inert in the cache?
6. What's the minimum Claude Code version? `displayName` needs 2.1.143, `defaultEnabled`
   2.1.154, same-session activation 2.1.221.

## Sources

Read on 2026-08-05 from a docs mirror,
[ericbuess/claude-code-docs](https://github.com/ericbuess/claude-code-docs), and checked
against Anthropic's own plugin repos (`anthropics/claude-code`,
`anthropics/claude-plugins-official`):

- [Plugins reference](https://code.claude.com/docs/en/plugins-reference): manifest, layout,
  versions, caching, `${CLAUDE_PLUGIN_ROOT}`
- [Plugin marketplaces](https://code.claude.com/docs/en/plugin-marketplaces): `source: "./"`,
  pinning, team settings
- [Discover plugins](https://code.claude.com/docs/en/discover-plugins): auto-updates
- [Hooks](https://code.claude.com/docs/en/hooks), [Skills](https://code.claude.com/docs/en/skills),
  [Plugin dependencies](https://code.claude.com/docs/en/plugin-dependencies)
