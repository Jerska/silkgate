# Git and GitHub

Read this to give a guest a repository, get its commits back, and let it reach GitHub.

## Two modes

**`--checkout` gives the guest a throwaway clone. `--branch` also brings its commits back.**

Both need `--with git`, run from inside a repository, and own `/workspace`, so no `-v` can
target it.

```sh
cd ~/projects/foo
silkgate run --name ask --with git --with claude --checkout -- \
  silkgate-claude -p "why does auth reject refreshable tokens? cite files"
silkgate run --name fix --with git --with claude --branch agent/fix-flaky -- \
  silkgate-claude -p "fix tests/test_sync.py, commit as you go"
```

| | `--checkout [REF]` | `--branch NAME` |
|---|---|---|
| The guest gets | a clone of REF (default `HEAD`), committed files only | the same, on a new branch `NAME` |
| What comes back | nothing: the printed output is the deliverable | the commits on `NAME`, fast-forward only |
| Where the worktree lives | the guest's own disk, gone with the VM | `<repo>/.silkgate/sandboxes/<session>`, deleted at teardown |

- Untracked files, such as `.env`, never enter the guest.
- `--branch NAME --checkout REF` starts the branch at REF instead of `HEAD`.
- Both work from the silkgate repo itself.

## Getting commits back

**Commits come back at `run` teardown, at `down`, and on each `harvest`.**

```sh
silkgate up --name bar --with git --with claude --branch agent/refactor
silkgate exec bar -- silkgate-claude -p "split utils.py, commit each step"
silkgate harvest bar          # bank the commits so far, without stopping
silkgate down bar             # final harvest, then teardown
```

`run` prints its session name at startup, so a second terminal can `harvest` a `run` too.

| Case | What happens |
|---|---|
| a clean fast-forward | the branch moves |
| the branch already exists, someone moved it, or the guest rewrote harvested history | refused. The commits stay at `refs/silkgate/<session>/<branch>`. |
| a harvest that can't bank everything | `run` and `down` exit 1, and the workspace is kept |

- Uncommitted files die with the session. Commit early: agents die mid-run.
- File modes ride in the commits.
- The host fetches under `fetch.fsckObjects`.

Pinned by: `test/test_cli_branch_ingest.py`.

## Inside the guest

**The clone is a normal git repo, with a few differences.**

- Host branches show up as `origin/<name>`. Write `origin/<name>` in a brief, or create the
  branch on the host first.
- Host hooks are copied in and run in the guest. A hook that uses host paths fails there:
  pass `--no-verify`, or fix the hook.
- Under `--branch` only, every exec has `GIT_DIR` and `GIT_WORK_TREE` set. An unrelated clone
  there needs `env -u GIT_DIR -u GIT_WORK_TREE git clone …`.
- The repo's `.git` is mounted read-only at `/silkgate/base.git`. The guest clones from it.

To check a harvested branch, test it in a fresh checkout:

```sh
silkgate run --name check --with git --with node --checkout agent/fix-flaky -- node --test
```

## LFS

**With LFS in use, `.git/lfs` is mounted read-write in both modes. It's the one piece of
host git state a guest can touch.**

- A hostile guest can force a re-download, never swap content: git-lfs checks SHA-256 on
  read.
- The guest can read every LFS object in the store.
- `.git/lfs/logs` isn't content-addressed. Treat `git lfs logs last` output as untrusted.

## Why not mount the repo

**A read-write repo mount hands the guest your hooks, which is code execution on your host.**

Silkgate refuses a read-write mount with a `.git` directory inside, unless you pass
`--allow-git-dir`. A mounted linked worktree doesn't work either: its `.git` file points at
a host path outside the mount. Use `--checkout` or `--branch`.

## GitHub

**GitHub access is three profiles: an anonymous floor, and a read or write grant per repo.**

```sh
silkgate run --with git --with github -- git clone https://github.com/octocat/Hello-World
silkgate run --with git --with github-read:acme/app -- git clone https://github.com/acme/app
silkgate up --name bot --with git --with github-write:acme/app
```

`git` itself opens nothing. A grant needs a PAT in one full header line:

```sh
export SILKGATE_EGRESS_SECRET_GITHUB="Authorization: Basic $(printf 'x-access-token:%s' "$PAT" | base64 | tr -d '\n')"
```

`tr -d '\n'` matters: `base64` wraps long output, and a value over two lines is refused.

| For `OWNER/REPO` | `github` | `github-read` | `github-write` |
|---|---|---|---|
| clone, fetch | public repos, anonymous | yes | yes |
| push | — | — | yes, 64 MiB cap |
| LFS download | — | yes | yes |
| LFS upload | — | — | yes, 1 GiB cap |
| REST `api.github.com/repos/OWNER/REPO/…` | — | GET | GET, POST, PUT, PATCH, DELETE |
| `raw.githubusercontent.com`, `codeload.github.com` | anonymous | anonymous | anonymous |

- Grants repeat per repo. Their rules come first, so the granted repo uses the token and
  every other repo stays anonymous.
- `github-write` supersedes `github-read` for the same repo.
- `gh` isn't installed and GraphQL is unreachable. The guest calls the REST API with any
  `Authorization` value, and the proxy swaps in the real one.
- A private file on `raw.githubusercontent.com` answers 404, because that host stays
  anonymous. Fetch it over git or REST instead.
- The exact rules, with body caps: `silkgate profiles --render github-write:acme/app`.

Pinned by: `TestGithubProfiles` in `test/test_cli_validation.py`.

### SAML SSO

**A PAT for an org that enforces SAML SSO must be authorized for that org first.**

- A classic PAT: authorize it in the token's settings, after creation.
- A fine-grained PAT: pick the org at creation. The org may require approval.

An unauthorized PAT gets GitHub's own 403 or 404, with an `X-GitHub-SSO` response header.
The audit log shows the request allowed: GitHub refused it, not the proxy.

### Why some hosts carry no token

**The LFS storage hosts authorize themselves, so the proxy injects nothing there.**

- LFS action URLs on `lfs.github.com` carry a short-lived token from the batch response. A
  PAT on top makes GitHub answer 403.
- Uploads to `github-cloud.s3.amazonaws.com` are SigV4-signed in headers, so that rule
  forwards all headers. A second `Authorization` makes S3 answer 501.
- Downloads from `github-cloud.githubusercontent.com` use a presigned query.

## Migrating from the old flags

| Old | New |
|---|---|
| `--github-read OWNER/REPO` | `--with github-read:OWNER/REPO` |
| `--github-write OWNER/REPO` | `--with github-write:OWNER/REPO` |
| `--with git` (reached GitHub anonymously) | `--with git --with github` |
