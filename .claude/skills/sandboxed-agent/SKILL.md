---
name: sandboxed-agent
description: Run a coding agent or untrusted code inside silkgate — a microVM whose only egress is an inspecting proxy. Use when spawning a sub-agent that must not reach the host or the open internet, running untrusted code (a dependency install, a third-party MCP server, a PR's tests), or when an agent needs an API key it must never hold.
---

# Running work inside silkgate

The workload runs in a microVM whose only route out is a TLS-terminating proxy that allowlists
per request and injects secrets the guest never holds. Both enforcement layers sit outside the
guest: microsandbox's host-side network policy (Tier 1) and the mitmproxy addon (Tier 2).

## Setup (once per machine)

```sh
./cli/silkgate profiles                                  # what capabilities exist
export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"     # host-only, injected at the proxy
```
Images are built from the profiles you name, on first use, then cached — so there is no separate
setup step. The guest holds a dummy key; confirm the real one never lands there with
`./cli/silkgate run --with claude -- printenv ANTHROPIC_API_KEY`.

## One-shot: a single task, then gone

```sh
./cli/silkgate run --with claude --workspace ~/projects/foo -- \
  claude --bare -p "task…" --permission-mode bypassPermissions \
  --output-format stream-json --verbose
```
`bypassPermissions` is right here: the microVM is the boundary, so in-guest tool prompts add
nothing (the claude profile sets `IS_SANDBOX=1`, which is what lets it run as root). Output streams live
as the agent works, with the guest's stdout and stderr kept on separate streams — so redirect
stdout to a file and parse the `result` event for the answer, `session_id`, and cost. The real
deliverables are the **workspace diff** (review it on the host before pushing) and the **audit
log** whose path is printed at startup.

## Sessions: multi-turn, warm VM

`run` boots and destroys a VM per command, so each turn pays the boot and `--resume` cannot
work. A session keeps the VM and `/root/.claude` alive:

```sh
./cli/silkgate up --name foo --with claude --workspace ~/projects/foo
./cli/silkgate exec foo -- claude -p "first turn" --output-format json   # prints session_id
./cli/silkgate exec foo -- claude -p --resume <id> "second turn"         # same VM, so it works
./cli/silkgate attach foo             # interactive TUI in the same VM
./cli/silkgate ls                     # sessions + shared-proxy health
./cli/silkgate down foo               # frees the port; last one out stops the proxy
```
One shared proxy serves every session on its own port, and each guest's Tier-1 rule allows only
that port — so a guest cannot reach another session's listener, and every audit line carries the
session that produced it.

To watch a session you did not launch in the foreground, or to see its egress decisions:
```sh
./cli/silkgate logs foo -f            # guest output, live
./cli/silkgate logs foo --audit -f    # this session's allow/deny decisions
```

## Profiles: the image and the policy are one declaration

`--with NAME[@VERSION]` (repeatable) picks capabilities from `profiles/`. A profile carries both
how to install itself (`setup.sh`, at image build time) and what it may reach (`rules.txt`,
enforced by the proxy), so a guest never holds a tool whose traffic nobody allowed. `--with
node@22.11.0 --with claude` builds and caches its own image, keyed by a hash of those inputs;
`--rule 'host/path GET'` adds a one-off rule without a profile.

Anything unlisted is denied, with a reason in the audit log. Grant the minimum: every allowed
destination is an exfil channel, so prefer download-only (GET) and never allowlist an endpoint
that reflects headers or bodies back. Adding a capability means writing a profile — a directory
with those two files — not editing an image.

## Tell the guest agent where it is

Each session generates a description of its own sandbox — installed profiles, the allowlist, the
mount, that the API key is a dummy — and puts it at `/silkgate/CONTEXT.md` and in
`$SILKGATE_CONTEXT` (the text itself, not a path). Pass it along or the agent will rediscover
the limits by trial and error:

```sh
./cli/silkgate exec foo -- claude --bare -p "<task>" --append-system-prompt-file /silkgate/CONTEXT.md
```
`--bare` skips CLAUDE.md discovery entirely, so that flag is the only thing that works with it.
Without `--bare`, a plain `claude -p` also picks it up from `/root/.claude/CLAUDE.md`.

## Gotchas (each cost real debugging time)

- **A denied request is not a crash.** The agent sees `no matching rule`, usually reports it,
  and carries on. Read the audit log before concluding the task failed.
- **`--resume` only works inside one session.** Across `run` invocations the VM is gone.
- **`-t` changes how the command behaves**, not just how it looks: it hands the guest a real
  terminal, so programs colorize, emit cursor control, and merge stdout into stderr. Leave it
  off (the default when stdin is not a TTY) for anything you intend to parse.
- **git does not work in a mounted worktree** — its `.git` file points at a host path outside
  the mount. Mounting the whole repo instead would hand the guest rw access to `.git`, which is
  host code execution via hooks or `core.fsmonitor`. For agents that need history, give each one
  a full clone and `git fetch <clone> branch:branch` from the host afterwards; fetch copies
  objects without executing anything from the remote.
- **The guest has only what its profiles installed.** The base carries no runtimes at all, so a
  `--with claude` guest has no node, python3, or git. Add `--with node@22`, `--with python`, or
  `--with git` when the task needs them, or expect the agent to report it could not run anything.
- **Guest rewrites can drop the exec bit** — `chmod +x` after an agent edits a script.
- **A custom `--image` needs `sh` and `mkfifo`** for the live-output relay. An image too minimal
  for those can still run under `-t`, which needs neither — at the cost of merged streams.
