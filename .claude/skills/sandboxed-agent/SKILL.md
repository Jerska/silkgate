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
./cli/silkgate build                                     # guest image + CA, loaded into msb
export EGRESS_SECRET_ANTHROPIC="x-api-key: sk-ant-…"     # host-only, injected at the proxy
```
The guest holds a dummy key. Confirm the real one never lands there:
`./cli/silkgate run -- printenv ANTHROPIC_API_KEY` prints the dummy.

## One-shot: a single task, then gone

```sh
./cli/silkgate run --workspace ~/projects/foo -- \
  claude --bare -p "task…" --permission-mode bypassPermissions \
  --output-format stream-json --verbose
```
`bypassPermissions` is right here: the microVM is the boundary, so in-guest tool prompts add
nothing (the image sets `IS_SANDBOX=1`, which is what lets it run as root). Output streams live
as the agent works, with the guest's stdout and stderr kept on separate streams — so redirect
stdout to a file and parse the `result` event for the answer, `session_id`, and cost. The real
deliverables are the **workspace diff** (review it on the host before pushing) and the **audit
log** whose path is printed at startup.

## Sessions: multi-turn, warm VM

`run` boots and destroys a VM per command, so each turn pays the boot and `--resume` cannot
work. A session keeps the VM and `/root/.claude` alive:

```sh
./cli/silkgate up --name foo --workspace ~/projects/foo
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

## Egress rules

`--preset NAME` (repeatable) and `--rules FILE` compose the allowlist; the default is `claude`.
Anything unlisted is denied, with a reason in the audit log. Grant the minimum: every allowed
destination is an exfil channel, so prefer download-only (GET) and never allowlist an endpoint
that reflects headers or bodies back.

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
- **The guest has node, not python3** — a sandboxed agent cannot run Python self-tests. Verify
  Python work on the host, and expect the agent to say it could not check its own output.
- **Guest rewrites can drop the exec bit** — `chmod +x` after an agent edits a script.
- **A custom image needs `sh` and `mkfifo`** for the live-output relay. An image too minimal for
  those can still run under `-t`, which needs neither — at the cost of merged streams.
