# Profiles

Read this to write a profile, pass it an argument, and see what a guest is told.

## What a profile is

**A profile is one directory under `profiles/`. It declares what to install and what that
install may reach, together.**

```text
profiles/node/
  profile.conf   metadata (keys below)
  setup.sh       installs it: runs at image build, as root, with $VERSION set
  rules.txt      what it may reach: enforced by the proxy (syntax: DSL.md)
  env            KEY=VALUE lines baked into the image
  context.md     guidance appended to the guest context
```

Every file is optional. `git` and `probe` have no `setup.sh`, and `github` installs nothing.
One `--with` list drives both the image and the policy, so a guest never holds a tool whose
traffic nobody allowed.

```sh
silkgate profiles                     # every profile, its pinned version, its hosts
silkgate build --with node --with claude
# silkgate/node-claude:5ef1fc362586   (the hash covers every input)
```

The skill keeps a committed copy of that listing in
[PROFILES.txt](../.claude/skills/sandboxed-agent/PROFILES.txt). Regenerate it with
`COLUMNS=80 silkgate profiles > .claude/skills/sandboxed-agent/PROFILES.txt`.

Pinned by: `test/test_scripts.py` (the copy matches `profiles/`).

## `profile.conf` keys

**`profile.conf` is `key = value` lines. `#` starts a comment.**

<!-- Mirrors the keys Profile.__init__ reads in cli/silkgate_cli/. Update both. -->
| Key | Meaning | Example |
|---|---|---|
| `description` | one line for `silkgate profiles` | `Node.js, from the official pinned tarball` |
| `default_version` | what `--with NAME` installs. Without it, `@VERSION` is refused. | `22.23.5` |
| `packages` | Debian packages, installed before any `setup.sh` | `curl xz-utils` |
| `command` | what `attach` runs, and `run` when given no command | `silkgate-claude` |
| `requires` | a profile that must also be in `--with`. It's never added for you. | `git` |
| `supersedes` | drops that profile's instance with the same argument | `github-read` |
| `arg_pattern` | full-match regex for `:ARG`. If set, an argument is required. | `[A-Za-z0-9._-]+/[A-Za-z0-9._-]+` |
| `context_path` | another guest path for the context, where the harness reads instructions | `/root/.claude/CLAUDE.md` |
| `settings_path` | guest path for the [model settings](#model-settings) | `/root/.claude/settings.json` |
| `guest_credential` | the secret whose header picks the guest's dummy | `anthropic` |
| `guest_credential.<header>` | the `KEY=VALUE` dummy for that header. The first line is the fallback. | `x-api-key = ANTHROPIC_API_KEY=sk-ant-DUMMY-…` |

All profiles' `packages` install in one apt transaction, so a `setup.sh` holds only what's
specific to the capability. A package from outside Debian's repos belongs in `setup.sh`,
with its source.

## Versions

**`--with NAME` installs the pinned version. `--with NAME@VERSION` installs exactly that
one.**

```sh
silkgate run --with node -- node --version           # the pinned version
silkgate run --with node@20.18.1 -- node --version   # any release upstream has
silkgate run --with node@22 -- node --version        # fails: no prefix matching
```

Each `setup.sh` fails the build when the installed version doesn't match.

## Images

**An image is the base, plus one silkgate layer, plus one layer per profile. Its tag hashes
every input.**

- The base is `debian:bookworm-slim`. `--base` picks another.
- The silkgate layer adds the proxy's CA to the trust store and to the env vars runtimes
  read, and creates `/workspace`.
- The tag hashes the base, each profile's name and version, and the bytes of its
  `setup.sh`, `rules.txt` and `env`. Change any of them, and you get a new image.
- Each profile is its own docker layer, so editing the last one rebuilds only that layer.
- Builds run in `docker build` on the host network, not through the proxy. A build's
  downloads never touch the session's policy.

There's no Dockerfile in the repo: `silkgate build` writes one per build.

## Arguments

**`--with NAME:ARG` fills `{arg}` in a profile's rules and context. It never changes the
image.**

```sh
silkgate profiles --render github-read:acme/app      # the rules a session would enforce
silkgate run --with git --with github-read:acme/app --with github-read:acme/lib -- …
```

- A profile with `arg_pattern` requires an argument, and the whole argument must match.
  A profile without one refuses any argument.
- Whitespace and control characters are always refused: an argument lands inside rule
  syntax.
- Only `rules.txt` and `context.md` are templated. A `{arg}` in a profile without
  `arg_pattern` is a load error.
- Repeat a profile with different arguments for several grants. Exact duplicates collapse.
- Two sessions that differ only in arguments share one image.

Pinned by: `test/test_cli_validation.py`.

## Rule order

**The first matching rule decides, and composition puts the most specific rules first.**

```text
1. --rule lines, in the order given
2. argument expansions (github-read:acme/app, …)
3. rules of profiles without arguments
```

So an explicit `--rule` beats a grant, and a grant beats the profile floor. For example,
`github-read:acme/app` injects a token for `acme/app`, while `github` keeps every other
repo anonymous.

Pinned by: `test/test_cli_validation.py`.

## The guest context

**Each session writes `/silkgate/CONTEXT.md`, which describes the sandbox to the guest. It's
a courtesy, never a control: an adversarial guest ignores it.**

It lists the profiles, the allowlist, the mounts, and each credential's status. With it,
the guest wastes fewer turns and reports blocked requests instead of retrying them.

| Command in the guest | Sees the context |
|---|---|
| `silkgate-claude -p "…"` | yes, passed for you |
| `claude -p "…"` | yes, from `/root/.claude/CLAUDE.md` (the claude profile's `context_path`) |
| `claude --bare -p "…"` | only with `--append-system-prompt-file /silkgate/CONTEXT.md` |
| any other harness | only if the prompt includes `$SILKGATE_CONTEXT` (the text, not a path) |

```sh
silkgate exec foo -- sh -c 'my-agent "$SILKGATE_CONTEXT

Now: <task>"'
```

- A profile's `context.md` is appended once per instance, with `{arg}` filled.
- The context lives in the guest's root filesystem, never in `/workspace`, so it can't land
  in your project.
- `--no-context` skips it.

## Model settings

**Each launch copies your Claude Code `model` and `effortLevel` into the guest. Nothing else
from your settings leaves the host.**

| Order | Source |
|---|---|
| 1 | `ANTHROPIC_MODEL` or `CLAUDE_CODE_EFFORT_LEVEL` in a settings file's `env` block |
| 2 | the direct `model` or `effortLevel` key |

Within each, local beats project beats user. The project and local files come from the host
directory mounted at `/workspace`.

- The result lands at each profile's `settings_path`.
- A settings file that isn't valid JSON warns and counts as absent.
- `--no-settings` skips the copy.

Pinned by: `test/test_cli_settings.py` (the order and the two-key allowlist).

## The `probe` profile

**`probe` exists for `silkgate verify` only.** It opens the Debian mirrors, so every other
command refuses it.
