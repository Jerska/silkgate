---
name: sandboxed-agent
description: Run a coding agent or untrusted code inside silkgate, a microVM whose only egress is a proxy that inspects and allowlists each request. Use it for a sub-agent that must not reach the host or the open internet, for untrusted code (a dependency install, a third-party MCP server, a PR's tests), or for an agent that needs an API key it must never hold.
---

# Run work inside silkgate

Read this to launch silkgate sandboxes, choose their policy, and judge what a run returns.

## The boundary

**Both containment layers sit outside the guest, so nothing the guest does can widen them.**
The workload runs in a microVM. Its only route out is a proxy that terminates TLS and
matches each request against an allowlist. microsandbox's host-side network policy pins
the VM to that proxy. `./cli/silkgate verify --full` checks this containment on a live
sandbox.

Run the CLI from the repo root (`./cli/silkgate`, as below) or by absolute path. A
`-v` mount's SRC takes either kind of path. The prerequisites are the README's:
docker, mitmproxy, and microsandbox.

## Write invocations across multiple lines

**Write each invocation across multiple lines, one flag per line, with the guest's command
indented under `--`.** The invocation is what a human sees in the approval prompt. The
split shows the granted policy — which profiles, which mounts — apart from whatever
runs inside. If a short command fits on one line, keep it there.

## Let commands report their own preconditions

**Do not pre-check what a command reports itself.** Silkgate commands surface their own
preconditions. For example, a launch pushes each secret and then names anything missing
or malformed in its own output, before any exec. A host-side probe of
`SILKGATE_EGRESS_SECRET_*` presence, a `silkgate ls`, or a probe of proxy health before a
launch duplicates that report and adds noise. Launch, then read what the tool said.

## What the guest looks like

**A guest holds exactly what its profiles installed, the mounts you granted, and a dummy
key.**

- `-v SRC:DST[:ro|rw]` (repeatable) mounts host directory SRC at DST in the guest,
  read-only unless the spec says `:rw`. The mounts are the only host paths in the
  guest. Everything else the guest writes dies with the machine. `/workspace` is the
  working directory. Mount something there (`-v DIR:/workspace:rw` for a writable
  workbench), or leave it as guest-local scratch.
- Silkgate refuses a DST that is relative, `/`, at, under, or above `/silkgate`,
  `/root/lfsstore`, or `/root/gitdir`, duplicated, or nested under another mount. If a
  read-write mount holds a `.git` directory, the launch needs `--allow-git-dir`.
- The `.git`-directory check is skipped for read-only mounts, so a whole repository
  can be mounted directly. The guest then reads all of `.git`, `.git/config` included,
  and a remote URL there can embed a token. Check `.git/config` before you mount a
  repository.
- There is no writable-copy flag. For a writable copy of a plain directory, mount it
  read-only and copy it in the guest: `-v DIR:/data:ro`, then `cp -a /data/. /workspace/`.
- Pick the mode by what the guest needs. A read-only shelf of host files takes
  `-v DIR:DST` — read-only is the default. A scratch checkout, with printed output as
  the deliverable, takes `--checkout [REF]` and needs `--with git`. Deliverable commits
  take `--branch NAME`.
- `--branch` is `--checkout` plus a return path. The worktree moves from a guest-only
  folder to a host-derived mount, and a named branch is created at the base. Commits
  return fast-forward only at `down` or `harvest`. `--branch X --checkout REF` sets the
  branch base to REF.
- A plain `--checkout` guest holds committed content only — untracked files such as
  `.env` never enter it. Nothing a `--checkout` guest writes returns, commits included.
  `--checkout` works from the silkgate repo itself: only the repository's `.git` is
  mounted, read-only, the same shape `--branch` always used.
- The base image has no language runtimes: no node, no python, no git. A guest has
  exactly what its profiles installed, so `--with claude` alone cannot run `node --test`.
- `inject_auth=<name>` in a rules file maps to `SILKGATE_EGRESS_SECRET_<NAME>` in the
  host environment. That variable holds the complete header line the proxy sends upstream
  (`"x-api-key: sk-ant-…"`, not a bare key). The operator chooses how the variable
  reaches the environment: a shell profile, a per-launch prefix, a password-manager
  wrapper. That choice is the operator's responsibility.
- A missing or malformed secret is a warning, not a startup error. The session comes up,
  the launch output names the defect, and `/silkgate/CONTEXT.md` shows the guest the
  credential status. If a secret your task needs is missing or malformed, stop and
  report. Do not launch a task whose matching requests will all be denied.
- The guest's own `ANTHROPIC_API_KEY` is a dummy that the claude profile bakes in. The
  proxy's CA is in the guest's trust store. That combination is what makes the
  interception work. Check it with `run --with claude -- printenv ANTHROPIC_API_KEY`. If
  a run dies on a TLS or auth error rather than a 403, suspect that layer.
- The audit log records the proxy's decisions about requests. It never records request
  bodies, and never the injected credential, which is spent upstream, not written.
- `silkgate-claude` (below) exists in the guest only when `--with claude` is among the
  profiles.

## Paths and ports

**Every fixed path and port lives in this table.**

| Item | Value |
|---|---|
| Guest working directory | `/workspace` |
| Guest context, as a file | `/silkgate/CONTEXT.md` |
| Guest context, as text in the environment | `$SILKGATE_CONTEXT` |
| Context copy that a plain `claude -p` reads | `/root/.claude/CLAUDE.md` |
| Audit log files | `~/.silkgate/logs/proxy-*.log` |
| Host-side secret variables | `SILKGATE_EGRESS_SECRET_<NAME>` |
| Proxy listen port | 8090, or `--port N` on `run` and `up` when 8090 is taken |

## `run`: one task, then gone

**Use `run` by default: it creates a microVM, runs one command, and removes everything.**
It is one command where a session is three. There is nothing to `down` afterward. A
caller that dies mid-task cannot leave a session or a sandbox behind. Boot takes about
0.3 seconds, so a fresh VM per command costs almost nothing.

`run` starts and stops the proxy itself, and it builds the image it needs on first use.
If the first run with a new profile set stalls, allow a minute for that build before you
suspect a hang. Later runs with the same profiles reuse the image and start in under a
second.

```sh
./cli/silkgate run \
    --with node@22.11.0 \
    --with claude \
    -v ./test/mock:/workspace:rw \
    -- silkgate-claude \
        -p "The tests in /workspace fail. Run 'node --test', fix the source, confirm it passes."
```

`silkgate-claude` is Claude Code plus the flags that are always right here. It adds
`--permission-mode bypassPermissions`, because the VM is the boundary and an in-guest
permission prompt hangs a non-interactive run. It adds
`--append-system-prompt-file /silkgate/CONTEXT.md`. It prints on stderr what it added,
and it skips either flag you pass yourself. In `-p` mode the prompt is positional: `-p`
is a mode flag and does not take the prompt. That is why `-p --resume <id> "task"` is
also correct.

## What you get back

**The exit code means the guest finished, never that the work is right — the output is
the guest's report, not evidence.**

- Output streams live, stdout and stderr kept apart, as a convenience and not a property.
  The relay tags stderr with an in-band byte, and a guest can write that byte itself. A
  guest can therefore put lines on your stderr, or emit well-formed `stream-json` events
  that never came from the harness. `test/test_relay.py` pins the attribution that does
  hold: silkgate's own lines open with a byte no relayed guest output can carry. Capture
  the stream only when something will parse it (`--output-format stream-json --verbose`,
  then pipe or redirect). Treat what it parses as the guest's report, not as evidence.
- The exit code is the guest command's. An agent run that exits 0 means the agent
  finished, never that its work is right. To learn whether the tests pass, run them
  yourself in a fresh sandbox and read that exit code:

  ```sh
  ./cli/silkgate run --with node@22.11.0 -v ./test/mock:/workspace:rw -- node --test
  ```

  That run needs no claude profile and no secret — the smallest policy that can answer
  the question.
- The workspace diff is the deliverable. Review it on the host before you push. Check
  that only what you expected changed, and that no test got weakened to pass. If a
  fixture is untracked, run `git add -N <dir>` first, or `git diff` shows nothing.
- The startup output prints the audit log path, and the files are
  `~/.silkgate/logs/proxy-*.log` if you lose it. The log is shared across sessions, and
  each line names the session that produced it. If a task looks failed, read the audit
  log before you conclude anything.

## Sessions: a later turn needs the same VM

**Open a session only when you can name the later turn that must find the same VM.** A
session keeps the VM warm between commands, and that matters in three cases. A multi-turn
conversation is the first: a later `--resume` must find the same `/root/.claude`, and
`run` destroys the VM and that directory with it. An interactive `attach` is the second.
A long batch on a machine that can sleep is the third.

A batch of one-shot tasks is none of those. One earlier batch ran its parallel agents as
sessions, and none of them used `--resume` or `silkgate logs`. The machinery returned
nothing and cost a `down` per sandbox. The one session that earned itself was a
reconciliation, where a finished agent was still there for a follow-up question. If you
cannot name the follow-up, use `run`. When you can:

```sh
./cli/silkgate up \
    --name foo \
    --with node@22.11.0 \
    --with claude \
    -v ~/projects/foo:/workspace:rw

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

One shared proxy serves every session on its own port. Each guest's network policy admits
only its own port, so a guest cannot reach another session's listener.

## Profiles: the image and the policy are one declaration

**Pick capabilities with `--with NAME[@VERSION]`, repeatable: a profile carries both its
installer and its allowlist.** A profile holds how to install itself (`setup.sh`, at
image build time) and what it can reach (`rules.txt`, enforced by the proxy). A guest
therefore never holds a tool whose traffic nobody allowed. The image builds on first use
and is cached under a hash of those inputs.

Omit the version (`--with node`) to get the one the profile pins. A named version
installs that exact release. Anything the profile's installer can fetch upstream works,
so `node@20.18.1` succeeds as well as the default. The version must be exact: `node@22`
is not a prefix match and fails the build. `./cli/silkgate profiles` lists the names and
their pinned defaults.

`--rule 'host/path GET'` adds a one-off rule. No rule can be subtracted, so a profile's
rules are a floor: `--with node` grants `registry.npmjs.org` even to a task with no
dependencies. Prefer the smallest profile set. Prefer download-only rules (GET). Never
allowlist an endpoint that reflects headers or bodies back — a reflected response is an
exfiltration channel. To add a capability, write a profile. Do not edit an image.

The rule grammar, one rule per line in a `rules.txt` or after `--rule`:

```
<host>[:<port>][/<path>]   [METHOD ...]   [option ...]
```

- Host globs: `*` matches one label (`api.github.com`, not `a.b.github.com`). `**`
  matches any number of labels. `**.` matches zero or more labels, the apex variant. A
  pattern that is all wildcards (`**`, `*.*`) is legal but warns on stderr, because it
  matches every destination.
- Path globs: `*` matches one path segment. `**` matches any path. A pattern with no `/`
  matches any path.
- Ports: an omitted port allows 80 and 443 only. `:*` allows any port. `:N[,M…]` pins
  exact ports.
- The defaults, when no option overrides them, are GET only, no request body, stripped
  query params, and baseline headers only (host, content-type, content-length,
  transfer-encoding).

These options go space-separated after the pattern:

- `GET POST …` names the allowed methods.
- `max_body=<size>` permits a request body up to `<size>` (bytes, with a `k` or `m`
  suffix).
- `q:*` allows all query params. `q:<name>=<value>` and `q:<name>~<regex>` keep the
  matched param and strip the rest.
- `h:*` allows all request headers. `h:<name>=<value>` and `h:<name>~<regex>` forward a
  header that matches and drop one that does not.
- `inject_auth=<name>` replaces the matched header's value with
  `SILKGATE_EGRESS_SECRET_<NAME>` from the host environment.

A wildcard-only, read-only web grant exists for recon guests:

```
** GET q:* h:*
```

Do not give this grant to a guest that holds a credential or sensitive workspace content.
The pattern matches every destination, so anything the guest holds can leave.

## The guest's own context

**The generated context is a courtesy to the guest, never a control — an adversarial
guest ignores every word.** Each session writes a description of its own sandbox. It
names the installed profiles, the allowlist, the mounts, the dummy key, and the
launch-time status of each injected credential. It lands at `/silkgate/CONTEXT.md` and in
`$SILKGATE_CONTEXT`, which holds the text itself, not a path. `silkgate-claude` passes it
for you and does not pass `--bare`.

The claude profile also writes the context to `/root/.claude/CLAUDE.md`, and a plain
`claude -p` reads that copy. Claude Code's own `--bare` turns that discovery off, and
skills, hooks, and MCP with it. Under `--bare`, the `--append-system-prompt-file` flag is
the only route left. If your harness has neither, compose the text into the prompt:

```sh
./cli/silkgate exec foo \
    -- \
    sh -c 'claude -p "$SILKGATE_CONTEXT

Now: <task>"'
```

`--no-context` skips all of it. Rely on the context for nothing. What it buys is fewer
wasted turns, and blocked requests reported as requests instead of retried in a loop.

## Gotchas

**Each item below cost real debugging time, so read the list before your first launch.**

- A denied request is not a crash. Plain http gets a 403 whose body says
  `no matching rule`. A denied https destination is refused earlier, at CONNECT, and the
  client reports a failed CONNECT that names 403 (curl says
  `CONNECT tunnel failed, response 403`). The agent usually reports either one and
  carries on. Read the audit log before you conclude the task failed.
- `-t` changes how the command behaves, not just how it looks. It hands the guest a real
  terminal, so programs colorize, emit cursor control, and merge stdout into stderr. That
  merge corrupts a JSON stream. If you intend to parse the output, leave `-t` off.
- An agent that needs git gets `--checkout` or `--branch`, not a repository mount. Both
  run from inside the repository with `--with git` and hand the guest a real clone at
  `/workspace`. A plain `--checkout [REF]` guest is disposable: read the code, run the
  tests, commit locally, and nothing returns. `--branch <new-name>` is for deliverable
  commits. They land in the host repository as that branch at `down`, or earlier with
  `silkgate harvest NAME`. The ingest fast-forwards only and fetches under fsck
  (`test/test_cli_branch_ingest.py` pins that rule). Uncommitted files die with the
  session. File modes ride in the commits, so the old exec-bit ritual is gone. In both
  modes, the host repository's `.git` is mounted read-only. With LFS in use, `.git/lfs`
  is the one host-writable piece. A hostile guest can cost you a re-download there,
  never content substitution, because content is checked against SHA-256 on read. Host
  hooks are copied into the clone verbatim, so a hook that references host paths fails
  in the guest. Pass `--no-verify`, or fix the hook. One surprise is `--branch`-only:
  `GIT_DIR` and `GIT_WORK_TREE` are in every exec's environment there, so an unrelated
  clone inside that guest needs `env -u GIT_DIR -u GIT_WORK_TREE git clone …`. A
  `--checkout` clone is a normal clone, with `.git` inside `/workspace` and no env pair.
- git does not work in a mounted worktree: its `.git` file points at a host path outside
  the mount. A read-write mount of the whole repository is not the fix. Write access to
  `.git` is host code execution, via hooks or `core.fsmonitor`, the next time a human
  runs git there. So silkgate refuses a read-write mount that holds a `.git` directory
  anywhere under it, unless you pass `--allow-git-dir`. It also refuses `/`, `$HOME`,
  and its own checkout and state, in either mode. A read-only mount skips the `.git`
  refusal, because the hook risk needs guest writes. A linked worktree's `.git` file
  passes either mode, with a printed note. For git-free work under a read-write mount,
  mount the subdirectory that holds the work, as the `run` example does. The fallback
  from before `--branch` still works: `--with git`, clone inside the guest, then on the
  host `git fetch <dir> branch:branch`. Never run git in a directory a guest wrote — the
  hook risk applies in full.
- Nothing bounds a runaway agent: silkgate has no timeout and no cost ceiling. If that
  matters, wrap the invocation in `timeout 600 …`. The teardown is clean, but the clock
  includes the image build, so a cold profile set spends part of the budget on docker.
- Host sleep kills every guest at once. Suspend freezes the VMs and the proxy together,
  and on wake every upstream connection is dead, so each guest's API stream idles out. An
  interactive session recovers: you resume, and it retries. A `-p` run does not recover:
  the process exits, and everything since its last file write is gone. Three parallel
  agents were lost that way mid-batch, about seventeen turns each, with nothing written.
  For a long unattended batch, prefer a machine that does not sleep. Otherwise, use a
  session: its conversation can be resumed, while a `run` must be restarted.
- A custom `--image` needs `sh` and `mkfifo` for the live-output relay. An image too
  minimal for those can still run under `-t`, which needs neither, at the cost of merged
  streams.
- An in-guest `claude -p` run waits at most 600 seconds for background subagents, then
  terminates them. Set `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0` in the guest command,
  or run subagents in the foreground.
- Guest clones see host branches as `origin/<name>`. If a brief names a bare branch,
  write `origin/<name>` in it, or create the branch on the host first.
- `--github-read OWNER/REPO` and `--github-write OWNER/REPO` grant GitHub access
  (repeatable, and both need `--with git`). The secret `SILKGATE_EGRESS_SECRET_GITHUB`
  holds the full header line (`Authorization: Basic base64(x-access-token:<PAT>)`). A
  missing secret warns at launch and shows in the guest context.
