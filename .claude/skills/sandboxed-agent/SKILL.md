---
name: sandboxed-agent
description: Run a coding agent or untrusted code inside silkgate — a microVM whose only egress is an inspecting proxy. Use when spawning a sub-agent that must not reach the host or the open internet, running untrusted code (a dependency install, a third-party MCP server, a PR's tests), or when an agent needs an API key it must never hold.
---

# Running work inside silkgate

The workload runs in a microVM whose only route out is a TLS-terminating proxy that allowlists
each request. Both layers are enforced outside the guest — microsandbox's host-side network
policy, and the proxy — so nothing the guest does can widen them.

Run the CLI from the repo root (`./cli/silkgate`, as below) or by absolute path; `--workspace`
takes either kind of path.

**Write these invocations across multiple lines, one flag per line, with the guest's command
indented under `--`.** They are long, and they are what a human sees in the approval prompt: the
split makes the granted policy (which profiles, which workspace) readable apart from whatever
runs inside. A short command that already fits on one line can stay there.

Prereqs are the README's: docker, mitmproxy, and microsandbox. `run` starts and stops the proxy
itself, and builds the image it needs on first use — allow a minute for that before assuming a
hang; later runs with the same profiles reuse it and start in under a second.

## What the guest looks like

- `--workspace DIR` mounts DIR at **`/workspace`, read-write**, and that is the working
  directory. It is the only host path present; everything else the guest writes dies with it.
  `--workspace-ro DIR` mounts the same path **read-only** — writes to `/workspace` fail, so
  the host code is protected. The `.git`-directory check is skipped for read-only mounts, so
  a whole repository can be mounted directly. `--workspace-ro` is exclusive with `--workspace`,
  `--allow-git-dir`, and `--branch`.
- The base image has **no language runtimes** — no node, no python, no git. A guest has exactly
  what its profiles installed, so `--with claude` alone cannot run `node --test`.
- **Secrets:** `inject_auth=<name>` in a rules file maps to `SILKGATE_EGRESS_SECRET_<NAME>` in
  the host environment, holding the **complete header line the proxy sends upstream**
  (`"x-api-key: sk-ant-…"`, not a bare key). How those variables reach the environment — shell
  profile, a per-launch prefix on the command, a password-manager wrapper — is the choice and
  the responsibility of the operator. A missing or malformed secret is **a warning, not a startup
  error**: the session comes up and the guest sees the credential status in `/silkgate/CONTEXT.md`.
  An agent that sees a missing-secret or malformed-secret warning for a secret its task needs must
  **stop and report**, not launch into a task where every matching request will be denied.
- `/silkgate/CONTEXT.md` tells the guest which injected credentials are available at launch time
  and which are missing or malformed.
- The guest's own `ANTHROPIC_API_KEY` is a dummy the claude profile bakes in, and the proxy's CA
  is in the guest's trust store — that combination is what makes the interception work. Check it
  yourself with `run --with claude -- printenv ANTHROPIC_API_KEY`. If a run dies on a TLS or auth
  error rather than a 403, suspect that layer.
- The audit log records the proxy's decisions about requests — never request bodies, and never
  the injected credential, which is spent upstream, not written.
- `silkgate-claude` (below) exists in the guest only when `--with claude` is among the profiles.

## `run`: the default — a single task, then gone

`run` creates a microVM, runs one command, and tears everything down. Use it unless you can
name the session trigger below: it is one command where a session is three, there is nothing
to `down` afterwards, and it cannot leave a session or a sandbox behind if the caller dies
mid-task. Boot is ~0.3s, so the fresh VM per command costs almost nothing.

```sh
./cli/silkgate run \
    --with node@22.11.0 \
    --with claude \
    --workspace ./test/mock \
    -- silkgate-claude \
        -p "The tests in /workspace fail. Run 'node --test', fix the source, confirm it passes."
```

`silkgate-claude` is Claude Code plus the flags that are always right in here: it adds
`--permission-mode bypassPermissions` (the VM is the boundary, and an in-guest prompt would hang
a non-interactive run) and `--append-system-prompt-file /silkgate/CONTEXT.md`, printing on stderr
what it added, and skipping either one you pass yourself. In `-p` mode the prompt is positional —
`-p` is a mode flag, not one that takes the prompt — which is why `-p --resume <id> "task"` is
also correct.

## What you get back

- **Output streams live**, stdout and stderr kept apart — as a convenience, not a property:
  the relay tags stderr with an in-band byte the guest can write itself, so a guest can put
  lines on your stderr, or emit well-formed `stream-json` events that never came from the
  harness. Capture the stream only when something will *parse* it
  (`--output-format stream-json --verbose`, then pipe or redirect), and treat what it parses
  as the guest's report, not as evidence.
- **The exit code is the guest command's** — so an agent run exiting 0 means *the agent finished*,
  never that its work is right. To learn whether the tests actually pass, run them yourself in a
  fresh sandbox and read that exit code:
  ```sh
  ./cli/silkgate run --with node@22.11.0 --workspace ./test/mock -- node --test
  ```
  No claude profile and no secret needed for that — the smallest policy that can answer it.
- **The workspace diff** is the deliverable — review it on the host before pushing, and check
  that only what you expected changed, not that a test got weakened to pass. An untracked fixture
  needs `git add -N <dir>` first or `git diff` shows nothing.
- **The audit log** path is printed at startup, and the files are `~/.silkgate/logs/proxy-*.log`
  if you lose it. It is shared across sessions; each line names the session that produced it.

## Sessions: the exception — a later turn needs the same VM

A session keeps the VM warm between commands, and that matters in three cases: a multi-turn
conversation, where a later `--resume` must find the same `/root/.claude` (`run` destroys the
VM, and that directory with it); an interactive `attach`; or **a long batch on a machine that
might sleep**. Neither of the first two applies to a batch of one-shot tasks — parallel agents
have been run as sessions before, and none of them used `--resume` or `silkgate logs`; the
machinery returned nothing and cost a `down` per sandbox. The session that did earn itself was
a reconciliation, where a finished agent could be asked a follow-up question. If you cannot
name the follow-up, use `run`. When you can:

```sh
./cli/silkgate up \
    --name foo \
    --with node@22.11.0 \
    --with claude \
    --workspace ~/projects/foo

./cli/silkgate exec foo \
    -- silkgate-claude \
        -p "first turn" \
        --output-format json                 # prints a session_id

./cli/silkgate exec foo \
    -- silkgate-claude \
        -p --resume <id> "second turn"       # same VM, so this resumes

./cli/silkgate logs foo --audit -f           # watch what it tries to reach
./cli/silkgate attach foo                    # interactive, runs the profile's command
./cli/silkgate down foo                      # frees the port; last one out stops the proxy
```

One shared proxy serves every session on its own port, and each guest's network policy allows
only that port — so a guest cannot reach another session's listener.

## Profiles: the image and the policy are one declaration

`--with NAME[@VERSION]` (repeatable) picks capabilities from `profiles/`. A profile carries both
how to install itself (`setup.sh`, at image build time) and what it may reach (`rules.txt`,
enforced by the proxy), so a guest never holds a tool whose traffic nobody allowed. The image is
built on first use and cached under a hash of those inputs.

**Omit the version** (`--with node`) to get the one that profile pins. Naming a version installs
that exact release — anything the profile's installer can fetch upstream, so `node@20.18.1` works
as well as the default — but it must be exact: `node@22` is not a prefix match and fails the
build. `./cli/silkgate profiles` lists the names and their pinned defaults.

`--rule 'host/path GET'` adds a one-off rule. There is no way to *subtract* one, so a profile's
rules are a floor: `--with node` grants `registry.npmjs.org` even to a task with no dependencies.
Prefer the smallest profile set, prefer download-only (GET), and never allowlist an endpoint that
reflects headers or bodies back. Adding a capability means writing a profile, not editing an image.

**Rule grammar** (one rule per line in a `rules.txt` or after `--rule`):

```
<host>[:<port>][/<path>]   [METHOD ...]   [option ...]
```

- **Host** globs: `*` matches one label (`api.github.com`, not `a.b.github.com`); `**` matches
  any number of labels; `**.` matches zero or more labels (apex variant). A host pattern that is
  all wildcards (`**`, `*.*`) is legal but warns on stderr — it matches every destination.
- **Path** globs: `*` matches one path segment; `**` matches any path. A pattern with no `/`
  matches any path.
- **Port**: omitting it allows 80 and 443 only; `:*` allows any port; `:N[,M…]` pins exact ports.
- **Defaults** (when not overridden): GET only, no request body, query params stripped, baseline
  headers only (host, content-type, content-length, transfer-encoding).
- **Options** (space-separated after the pattern):
  - `GET POST …` — allowed methods
  - `max_body=<size>` — permit a request body up to `<size>` (bytes, `k`/`m` suffix)
  - `q:*` — allow all query params; `q:<name>=<value>` / `q:<name>~<regex>` — keep matching
    param only, strip the rest
  - `h:*` — allow all request headers; `h:<name>=<value>` / `h:<name>~<regex>` — forward header
    only if it matches, drop it otherwise
  - `inject_auth=<name>` — replace the matching header's value with `SILKGATE_EGRESS_SECRET_<NAME>`
    from the host environment

A wildcard-only read-only web grant — intended for recon guests that hold nothing worth
exfiltrating — looks like:

```
** GET q:* h:*
```

Use it only when the guest has no credentials or sensitive workspace content.

**`--port N`** (on `run` and `up`) sets the proxy's listen port (default: 8090); use it when
8090 is already taken on the host.

## Telling the guest where it is

Each session generates a description of its own sandbox — installed profiles, the allowlist, the
mount, that the key is a dummy, and the launch-time status of every injected credential — at
`/silkgate/CONTEXT.md` and in `$SILKGATE_CONTEXT` (the text itself, not a path). `silkgate-claude`
passes it for you, and does not pass `--bare`.

If you invoke `claude` directly: the claude profile also writes the context to
`/root/.claude/CLAUDE.md`, which a plain `claude -p` reads. Adding Claude Code's own `--bare`
turns off that discovery — along with skills, hooks and MCP — so under `--bare` the
`--append-system-prompt-file` flag is the only route left. For a harness with neither, compose it
into the prompt:

```sh
./cli/silkgate exec foo \
    -- \
    sh -c 'claude -p "$SILKGATE_CONTEXT

Now: <task>"'
```

`--no-context` skips all of it. It is a courtesy, not a control: an adversarial guest ignores
every word, so nothing may rely on it. What it buys is fewer wasted turns, and blocked requests
reported as requests instead of retried in a loop.

## Gotchas (each cost real debugging time)

- **A denied request is not a crash.** Plain HTTP gets a 403 body saying `no matching rule`;
  a denied HTTPS destination is refused earlier, at CONNECT, so the client reports a failed
  CONNECT naming 403 (curl calls it `CONNECT tunnel failed, response 403`). The agent usually
  reports either one and carries on. Read the audit log before concluding the task failed.
- **`-t` changes how the command behaves**, not just how it looks: it hands the guest a real
  terminal, so programs colorize, emit cursor control, and merge stdout into stderr — which
  corrupts a JSON stream. Leave it off for anything you intend to parse.
- **An agent that needs git gets `--branch`, not a repo mount.** `run`/`up` from inside the
  repo with `--with git --branch <new-name>` hands the guest a real clone checked out on that
  branch at `/workspace`; its commits land in the host repo as that branch at `down` (or on
  demand with `silkgate harvest NAME`), fast-forward-only, fetched under fsck. Commits are the
  deliverable: uncommitted files are deleted with the session, and file modes ride in the
  commits, so the old exec-bit ritual is gone. The host repo's `.git` is mounted read-only;
  with LFS in use, `.git/lfs` is the one host-writable piece — a hostile guest can cost you a
  re-download there, never content substitution (SHA-256 verifies on read). Two guest-side
  surprises: host hooks are copied into the clone verbatim, so a hook referencing host paths
  fails in the guest (`--no-verify`, or fix the hook); and `GIT_DIR`/`GIT_WORK_TREE` are in
  every exec's environment, so an unrelated clone inside the guest needs
  `env -u GIT_DIR -u GIT_WORK_TREE git clone …`.
- **git does not work in a mounted worktree** — its `.git` file points at a host path outside
  the mount. Mounting the whole repo would hand the guest rw access to `.git` — host code
  execution via hooks or `core.fsmonitor` the next time a human runs git there — so silkgate
  refuses any workspace holding a `.git` directory anywhere under it (and `/`, `$HOME`, its
  own checkout and state); a linked worktree's `.git` file passes, with a printed note. For
  git-free work, mount the subdirectory that holds it, as the example does. The pre-`--branch`
  fallback still works: `--with git`, clone inside the guest, and on the host
  `git fetch <dir> branch:branch` — never run git in a directory a guest wrote.
- **Nothing bounds a runaway agent** — silkgate has no timeout or cost ceiling. Wrap the
  invocation in `timeout 600 …` if that matters to you; it tears down cleanly, but its clock
  includes the image build, so a cold profile set spends part of the budget on docker.
- **Host sleep kills every guest at once.** Suspending the machine freezes the VMs and the
  proxy together; on wake every upstream connection is dead, so each guest's API stream idles
  out. Interactively that is recoverable — you resume and it retries. Under `-p` it is not:
  the process exits and everything since its last file write is gone. Three parallel agents
  were lost that way mid-batch, about seventeen turns each, having written nothing. For a long
  unattended batch, prefer a machine that does not sleep, or a session whose conversation can
  be resumed rather than a `run` whose task must be restarted.
- **A custom `--image` needs `sh` and `mkfifo`** for the live-output relay. An image too minimal
  for those can still run under `-t`, which needs neither — at the cost of merged streams.
