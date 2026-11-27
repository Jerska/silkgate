---
name: sandboxed-agent
description: Run a coding agent or untrusted code inside silkgate, a microVM whose only egress is a proxy that inspects and allowlists each request. Use it for a sub-agent that must not reach the host or the open internet, for untrusted code (a dependency install, a third-party MCP server, a PR's tests), or for an agent that needs an API key it must never hold.
---

# Run work inside silkgate

Read this to launch silkgate sandboxes, choose their policy, and judge what a run returns.

## The boundary

**The workload runs in a microVM whose only way out is a proxy that allowlists each
request. Both layers sit outside the guest, so nothing the guest does can widen them.**

- Run `silkgate`. If it isn't on PATH, it's `cli/silkgate` in a checkout, or
  `"${CLAUDE_PLUGIN_ROOT}"/cli/silkgate` under the silkgate plugin.
- The host needs docker, mitmproxy, and microsandbox. Commands name whatever is missing.
- `silkgate verify --full` checks containment on a live sandbox.

## How to write an invocation

**Name every sandbox, put one flag per line, and indent the guest command under `--`.**

```sh
silkgate run \
    --name fix-tests \
    --with node \
    --with claude \
    -v ./test/mock:/workspace:rw \
    -- silkgate-claude \
        -p "The tests in /workspace fail. Run 'node --test', fix the source, confirm it passes."
```

- The human approving the command sees the granted policy apart from what runs inside it.
- `--name` labels the audit log, the journal, and the archive. Both `run` and `up` take it.
- Don't pre-check what a command reports itself: secrets, proxy health, `silkgate ls`.
  Launch, then read the output.

## `run` by default

**`run` creates a VM, runs one command, and removes everything.**

- Boot takes ~0.3 s. There's nothing to `down`, and a dying caller leaves nothing behind.
- The first run with a new profile set builds an image. Allow a minute before you suspect
  a hang.
- `silkgate-claude` is Claude Code plus `--permission-mode bypassPermissions` and
  `--append-system-prompt-file /silkgate/CONTEXT.md`. It prints what it added on stderr,
  and skips a flag you pass yourself. Plain `claude` as root refuses `bypassPermissions`.
- In `-p` mode the prompt is positional, so `-p --resume <id> "task"` is correct.

## What the guest has

**A guest holds what its profiles installed, the mounts you granted, and a dummy
credential. Nothing else.**

| Item | Value |
|---|---|
| working directory | `/workspace`: a mount, a git checkout, or scratch |
| guest context | `/silkgate/CONTEXT.md`, and as text in `$SILKGATE_CONTEXT` |
| context copy a plain `claude -p` reads | `/root/.claude/CLAUDE.md` |
| projected `model` and `effortLevel` | `/root/.claude/settings.json` (`--no-settings` skips) |
| a `--brief FILE` | `/silkgate/BRIEF.md` |
| defaults | 1G memory, half the host's CPUs. Don't pass `--memory` unless the guest ran out. |
| audit log | `~/.silkgate/logs/proxy-*.log`, printed at startup |

- The base image has no node, no python, no git. `--with claude` alone can't run
  `node --test`.
- `silkgate-claude` exists only with `--with claude`.
- Secrets are `SILKGATE_EGRESS_SECRET_<NAME>` on the host, each a full header line:
  `"x-api-key: sk-ant-…"`, or `"Authorization: Bearer sk-ant-oat01-…"` for a subscription
  token. The guest holds a matching dummy: `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`.
- Under a subscription token, never pass `--bare`: Claude Code ignores the token there.
- If a secret the task needs is missing, the launch says so. Stop and report: every
  matching request will be denied.
- A TLS or auth error, rather than a 403, points at the dummy or the CA. Check with
  `run --name keycheck --with claude -- env`.

## Mounts

**`-v SRC:DST[:ro|rw]` is read-only unless you add `:rw`.**

- Refused: `/`, `$HOME`, silkgate's checkout and state, a relative DST, a DST touching
  `/silkgate`, `/root/lfsstore` or `/root/gitdir`, and nested or duplicate DSTs.
- A read-write mount holding a `.git` directory needs `--allow-git-dir`: its hooks would run
  on the host. For the same reason, never run git on the host in a directory a guest wrote.
- A read-only mount still exposes `.git/config`, where a remote URL can hold a token. Check
  it before you mount a repo.
- For a writable copy of a directory, mount it read-only and copy it:
  `-v DIR:/data:ro`, then `cp -a /data/. /workspace/`.

| The guest needs | Use |
|---|---|
| to read host files | `-v DIR:DST` |
| a repo to explore, output as the deliverable | `--with git --checkout [REF]` |
| to deliver commits | `--with git --branch NAME` |

## Git

**`--checkout` is a throwaway clone. `--branch` also returns its commits, fast-forward
only.** Both run from inside the repo.

- Commits return at `run` teardown, at `down`, or earlier with `harvest NAME`. `run` prints
  its session name at startup, so a second terminal can harvest mid-run.
- A harvest that can't bank everything makes `run` and `down` exit 1, and keeps the
  workspace, even when the guest exited 0.
- Uncommitted files die with the session.
- Under `--branch`, `GIT_DIR` and `GIT_WORK_TREE` are set in every exec. An unrelated
  clone needs `env -u GIT_DIR -u GIT_WORK_TREE git clone …`.
- Host branches appear as `origin/<name>` in the guest. Write that in briefs.
- Host hooks run in the guest. One that uses host paths fails: `--no-verify`, or fix it.
- A mounted linked worktree can't run git: its `.git` file points outside the mount.

Details: [GIT.md](../../../doc/GIT.md).

## What you get back

**The exit code means the guest finished, never that the work is right. The output is the
guest's report, not evidence.**

- stdout and stderr stay apart as a convenience. A guest can forge the split, and emit
  fake `stream-json` events. Silkgate's own lines start with a byte no guest output can
  carry (`test/test_relay.py`).
- Capture the stream only if something parses it: `--output-format stream-json --verbose`.
- To learn whether tests pass, run them yourself in a fresh sandbox, with the smallest
  policy:

  ```sh
  silkgate run --name check --with node -v ./test/mock:/workspace -- node --test
  silkgate run --name check-branch --with git --with node --checkout agent/fix-tests -- node --test
  ```

- Review the diff on the host before you push. Check that no test got weakened. For an
  untracked fixture, `git add -N <dir>` first, or `git diff` shows nothing.
- If a task looks failed, read the audit log first. Each line names its session.

## Sessions

**Open a session only when you can name the later command that needs the same VM.**

That's a `--resume`, an interactive `attach`, or a long batch on a machine that may sleep.
A batch of one-shot tasks needs none: use `run`.

```sh
silkgate up \
    --name foo \
    --with node \
    --with claude \
    -v ~/projects/foo/src:/workspace:rw

silkgate exec foo \
    --brief task.md \
    -- silkgate-claude \
        -p "Read /silkgate/BRIEF.md and do the task." \
        --output-format json                 # prints a session_id

silkgate exec foo \
    --brief followup.md \
    -- silkgate-claude \
        -p --resume <id> "Read /silkgate/BRIEF.md and do the task."

silkgate logs foo --audit -f           # what it tries to reach
silkgate attach foo                    # interactive
silkgate down foo
```

## Briefs

**Put a multi-line task in `--brief FILE`, and point the prompt at it.**

- `run`, `up`, and `exec` take it. It lands at `/silkgate/BRIEF.md`, at most 1 MiB.
- `up --brief` sets a default for every exec without its own.
- Each exec's brief is stored and journaled with its sha256.
- One slot per session: concurrent agents in one session overwrite each other's brief.

## Parallel agents on one repo

**Split the work by file ownership, and write the split into every brief.**

- Each brief lists the files the agent owns, a never-edit list, and the new files it'll
  create. Tell each agent what the others own.
- Resolve unknowns on the host before writing briefs. A wrong hint costs more than a vague
  one.
- Ask for a report with Assumed and Disputed sections. Tell the agent what its sandbox
  can't run (docker, msb, a live proxy). Check each dispute yourself.
- Test the merged tree, not each branch. Before blaming the merge, run the same command on
  the pre-merge commit.
- Tell every agent to commit early. To continue a dead agent's work, harvest its branch,
  then launch `--branch <name>-2 --checkout <name>`, with a brief listing what it inherits.

## Profiles and rules

**`--with NAME[@VERSION][:ARG]` adds a profile: its installer and its allowlist, together.**

- [PROFILES.txt](PROFILES.txt) lists every profile, its purpose, its credential, and its
  rules file. Read it instead of running the CLI.
- No version means the pinned one. A version must be exact: `node@20.18.1` works,
  `node@22` fails.
- A profile with an ARG pattern requires `:ARG`. Preview the result with
  `silkgate profiles --render NAME:ARG`.
- `--rule 'host/path GET'` adds one rule. Rules can't be removed, so a profile's rules are a
  floor. Pick the smallest set.
- To add a capability, write a profile ([PROFILES.md](../../../doc/PROFILES.md)). Don't edit an
  image.

```text
<host>[:<port>][/<path>]   [METHOD ...]   [option ...]
api.anthropic.com/v1/messages   POST  inject_auth=anthropic max_body=10m
registry.npmjs.org/**           GET
```

| Default | Widen with |
|---|---|
| GET only | `GET POST …` |
| no body | `max_body=10m` |
| query params stripped | `q:*`, `q:<name>~<regex>` |
| headers: host, content-type, content-length, transfer-encoding | `h:*`, `h:<name>~<regex>` |
| ports 80 and 443 | `:8443`, `:*` |
| no credential | `inject_auth=<name>` |

Full syntax: [DSL.md](../../../doc/DSL.md).

A read-only web grant for recon guests: `** GET q:* h:*`. Never give it to a guest that holds
a credential or sensitive files: it matches every destination.

## The guest's context

**`/silkgate/CONTEXT.md` describes the sandbox to the guest. It's a courtesy, never a
control.**

| Command in the guest | Sees the context |
|---|---|
| `silkgate-claude -p "…"` | yes |
| `claude -p "…"` | yes, from `/root/.claude/CLAUDE.md` |
| `claude --bare -p "…"` | only with `--append-system-prompt-file /silkgate/CONTEXT.md` |
| any other harness | only if the prompt includes `$SILKGATE_CONTEXT` |

`--no-context` skips it.

## Gotchas

**Each of these cost real debugging time.**

- A deny isn't a crash. Plain HTTP gets a 403 with `no matching rule`. HTTPS fails at
  CONNECT: curl says `CONNECT tunnel failed, response 403`. The agent usually carries on.
- A command gets a real terminal whenever your stdin is one: colors, cursor codes, and
  stdout merged into stderr. That corrupts a JSON stream. Pass `--no-tty` for anything you
  parse.
- Exit 137 with a bare `Killed` is usually the guest's OOM killer. Rerun with more
  `--memory`: that's the one reason to raise it. A `--branch` teardown still harvests.
- Nothing bounds a runaway agent. Wrap it in `timeout 600 …` if that matters. The clock
  includes a cold image build.
- Host sleep kills every guest's API stream at once. A `-p` run exits and loses its
  unwritten work. Use a machine that stays awake, or a session you can resume.
- A guest `claude -p` waits at most 600 s for background subagents, then kills them. Set
  `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0` in the guest command, or run them in the
  foreground.
- A custom `--image` needs `sh` and `mkfifo` for the output relay (without them, use
  `--tty`), and must trust the proxy's CA.
- `--with git` opens nothing. Add `--with github` for public repos, or
  `github-read:OWNER/REPO` / `github-write:OWNER/REPO` with
  `SILKGATE_EGRESS_SECRET_GITHUB="Authorization: Basic <base64 of x-access-token:PAT>"`.
- `gh` isn't installed and GraphQL is unreachable. Use REST:
  `api.github.com/repos/OWNER/REPO/...`.
