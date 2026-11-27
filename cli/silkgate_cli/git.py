"""Checkout and branch sessions: a clone of the host repository in the guest, and its way back."""
import os
import shutil
import subprocess
from pathlib import Path

from . import console, mount, paths, sessions, vm


# --- checkout/branch sessions: a clone in the guest, from the host repo ---------
# The guest clones from a read-only mount of the host repo's gitdir.
# - --checkout: the clone lives in the guest's rootfs, detached at REF, and dies with the VM.
# - --branch: a named branch in a host-derived workspace. Commits return as a bundle the host
#   fetches under fsck and fast-forwards. The workspace mount holds no git metadata, so a
#   guest has nothing there to rewrite.
# The one writable piece of host git state is `.git/lfs`, which is SHA-checked on read: a
# hostile guest can force a re-download, never swap content.

_BRANCH_ENV = ("GIT_DIR=/root/gitdir/.git", "GIT_WORK_TREE=/workspace")
_GIT_TIMEOUT = 120                 # host git during harvest: bounded, per the deferral contract
# Every repo-location override git(1) honors from the environment. Host git here must act
# on the repository named by cwd or --git-dir, never one a parent process exported — run
# silkgate from inside a silkgate --branch guest, for instance, and GIT_DIR/GIT_WORK_TREE
# point at that session's clone, not the repo under the caller's feet.
_GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                      "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
                      "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
                      "GIT_INDEX_VERSION", "GIT_SHALLOW_FILE", "GIT_GRAFT_FILE")


def _host_git_env():
    """os.environ minus git's repo-location overrides, for every host-side git call."""
    return {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_VARS}


def _git(git_dir, *argv):
    """One bounded host-git call, or None on timeout. Its own session: harvest runs inside
    _deferred_interrupts after a Ctrl-C already hit the foreground group."""
    try:
        return subprocess.run([console.which("git"), "--git-dir", str(git_dir), *argv],
                              capture_output=True, text=True, start_new_session=True,
                              timeout=_GIT_TIMEOUT, env=_host_git_env())
    except subprocess.TimeoutExpired:
        return None


def _check_mount_flags(args):
    """--checkout/--branch own /workspace, so a -v mount at or under it is refused with
    them — under it too, because that would be nested virtiofs on a branch workspace and
    a directory the checkout clone needs empty."""
    if getattr(args, "branch", None):
        owner = "--branch"
    elif getattr(args, "checkout", None) is not None:
        owner = "--checkout"
    else:
        return
    for spec in args.mount or ():
        parsed = mount._split_mount(spec)
        if parsed is None:
            continue                        # argparse already refused it; _mount_args re-dies
        dst = mount._normalize_dst(parsed[1])
        if dst == "/workspace" or dst.startswith("/workspace/"):
            console.die(f"-v {spec} collides with {owner}, which owns /workspace in the guest")


def _checkout_repo(flag, ref, profiles, env):
    """The validation --checkout and --branch share -> (git_dir, repo_root, base sha).

    Dies before any host process starts unless: git is in the image, a repo encloses the
    cwd, and REF names a commit. `-e GIT_DIR` or `GIT_WORK_TREE` is refused in both modes:
    it would point every guest git call away from the checkout.
    """
    if not any(p.name == "git" for p in profiles):
        console.die(f"{flag} needs git in the guest — add --with git")
    for pair in env:
        if pair.partition("=")[0] in ("GIT_DIR", "GIT_WORK_TREE"):
            console.die(f"-e {pair.partition('=')[0]} conflicts with {flag}, which owns the "
                        "guest's "
                        "git environment")
    if ref.startswith("-") or any(c.isspace() or ord(c) < 0x20 for c in ref):
        console.die(f"invalid ref {ref!r}")
    probe = subprocess.run([console.which("git"), "rev-parse", "--path-format=absolute",
                            "--git-common-dir", "--show-toplevel"],
                           capture_output=True, text=True, env=_host_git_env())
    if probe.returncode:
        console.die(f"{flag} needs the current directory to be inside a git work tree — cd into "
                    "the repo this session should check out")
    git_dir, repo_root = probe.stdout.splitlines()[:2]
    base = subprocess.run([console.which("git"), "rev-parse", "--verify", f"{ref}^{{commit}}"],
                          capture_output=True, text=True, env=_host_git_env())
    if base.returncode:
        console.die(f"cannot resolve {ref!r} to a commit in this repository — {flag} needs a "
                    "base commit")
    return git_dir, repo_root, base.stdout.strip()


def _checkout_spec(ref, profiles, env):
    """Validate --checkout against the enclosing repo; the meta extras a plain-checkout
    session records. No branch parts and no host directory is created: the checkout lives
    and dies in the guest's own rootfs."""
    git_dir, repo_root, base = _checkout_repo("--checkout", ref, profiles, env)
    return {"checkout": ref, "git_dir": git_dir, "base": base, "repo_root": repo_root}


def _branch_spec(branch, profiles, env, ref="HEAD"):
    """Validate --branch against the enclosing repo; the meta extras a branch session records.

    _checkout_repo checks the repo and base. `ref` is the branch base (--checkout REF, or
    HEAD). The name must be a legal ref, and an existing branch is refused, never moved:
    the branch is the deliverable.
    """
    if branch.startswith("-") or any(c.isspace() or ord(c) < 0x20 for c in branch):
        console.die(f"invalid branch name {branch!r}")
    git_dir, repo_root, base = _checkout_repo("--branch", ref, profiles, env)
    if subprocess.run([console.which("git"), "check-ref-format", "--branch", branch],
                      capture_output=True, env=_host_git_env()).returncode:
        console.die(f"invalid branch name {branch!r} (git check-ref-format refused it)")
    if not subprocess.run([console.which("git"), "--git-dir", git_dir, "show-ref", "--verify",
                           "--quiet", f"refs/heads/{branch}"], capture_output=True,
                          env=_host_git_env()).returncode:
        console.die(f"branch {branch!r} already exists — the branch is this session's "
                    "deliverable; "
                    "pick a new name")
    _exclude_silkgate(Path(git_dir))
    return {"branch": branch, "git_dir": git_dir, "base": base,
            "repo_root": repo_root, "workspace_derived": True}


def _exclude_silkgate(git_dir):
    """One idempotent `.silkgate/` line in info/exclude, so derived workspaces never show up
    in the repo's own status. info/exclude over .gitignore: host-side, nothing to commit."""
    exclude = git_dir / "info" / "exclude"
    text = exclude.read_text() if exclude.is_file() else ""
    if ".silkgate/" in text.splitlines():
        return
    exclude.parent.mkdir(exist_ok=True)
    exclude.write_text(text + ("" if not text or text.endswith("\n") else "\n") + ".silkgate/\n")


def _branch_workspace(spec, name):
    """The derived workspace and the mounts of a branch session.

    The workspace is a fresh directory nested inside the repo — inside, so the guard's refusal
    of the repo root itself keeps holding for everyone else — and it is silkgate's to delete at
    teardown, which is why a user-named -v mount can never reach this path."""
    ws_dir = Path(spec["repo_root"]) / ".silkgate" / "sandboxes" / name
    silk = Path(paths.SILK_DIR).resolve()
    if silk == ws_dir.resolve() or silk in ws_dir.resolve().parents:
        console.die(f"refusing to keep branch workspaces under {ws_dir}: that is inside "
                    "silkgate's "
                    "own state — a repository rooted at your home directory cannot use --branch")
    if ws_dir.exists():
        console.die(f"leftover workspace {ws_dir} already exists — a previous session kept it; "
                    "review and remove it first")
    ws_dir.mkdir(parents=True)
    ws, dst = mount._mount_pair(str(ws_dir), "/workspace", "rw")
    mounts = [f"{ws}:{dst}:rw"]
    mounts.append(f"{spec['git_dir']}:/silkgate/base.git:ro")
    # The whole of .git/lfs, not objects/ alone: git-lfs stages under <storage>/tmp and
    # renames into <storage>/objects, and a rename across two virtiofs mounts is EXDEV
    # (measured, git-lfs 3.3.0 has no copy fallback). One mount = one filesystem, and the
    # guest-side storage layout matches the host's byte for byte.
    if (Path(spec["git_dir"]) / "lfs").is_dir():
        mounts.append(f"{spec['git_dir']}/lfs:/root/lfsstore:rw")
    return ws, mounts


def _checkout_workspace(spec):
    """The mounts of a plain-checkout session: _branch_workspace minus the derived dir.

    No /workspace mount at all — /workspace already exists in the rootfs (WORKDIR) as a
    writable guest-local directory, so the checkout dies with the VM and nothing the guest
    writes there can reach the host."""
    mounts = [f"{spec['git_dir']}:/silkgate/base.git:ro"]
    # The whole of .git/lfs, for the same EXDEV reason as _branch_workspace above.
    if (Path(spec["git_dir"]) / "lfs").is_dir():
        mounts.append(f"{spec['git_dir']}/lfs:/root/lfsstore:rw")
    return mounts


# Runs once per branch session, between the Tier-1 gate and the handover, with GIT_DIR unset
# for the clone: the create-time -e pair is inherited by every exec, this one included, and
# would point the clone at its own destination. lfs.storage is set before the checkout so the
# smudge of an LFS-tracked tree reads the mounted store.
_BRANCH_SETUP_SH = """\
set -eu
branch=$1; base=$2; session=$3
unset GIT_DIR GIT_WORK_TREE
git clone --quiet --no-checkout /silkgate/base.git /root/gitdir
if [ -d /silkgate/base.git/hooks ]; then cp -a /silkgate/base.git/hooks/. /root/gitdir/.git/hooks/; fi
if [ -d /silkgate/base.git/logs ]; then mkdir -p /root/gitdir/.git/logs && cp -a /silkgate/base.git/logs/. /root/gitdir/.git/logs/; fi
git -C /root/gitdir config lfs.storage /root/lfsstore
if command -v git-lfs >/dev/null 2>&1; then git -C /root/gitdir lfs install --skip-repo >/dev/null; fi
git -C /root/gitdir config user.name "Claude (silkgate/$session)"
git -C /root/gitdir config user.email "claude-$session@silkgate.invalid"
export GIT_DIR=/root/gitdir/.git GIT_WORK_TREE=/workspace
git checkout -b "$branch" "$base"
"""


def _setup_branch_guest(sandbox, branch, base, session):
    """Clone + checkout in the guest, streamed (a big repo's clone must show progress)."""
    rc = vm.run_guest(lambda c: vm.msb_exec_argv(sandbox, c),
                      ["sh", "-c", _BRANCH_SETUP_SH, "_", branch, base, session], tty=False)
    if rc:
        console.die("guest git setup failed — session torn down")


# Runs once per --checkout session, after the Tier 1 probe. /workspace isn't a mount here, so
# it's a normal clone with .git inside. An identity lets local commits work. The detached
# HEAD makes "no deliverable branch" structural. lfs.storage is set before the checkout, so
# LFS smudge reads the mounted store.
_CHECKOUT_SETUP_SH = """\
set -eu
base=$1; session=$2
git clone --quiet --no-checkout /silkgate/base.git /workspace
if [ -d /silkgate/base.git/hooks ]; then cp -a /silkgate/base.git/hooks/. /workspace/.git/hooks/; fi
if [ -d /silkgate/base.git/logs ]; then mkdir -p /workspace/.git/logs && cp -a /silkgate/base.git/logs/. /workspace/.git/logs/; fi
git -C /workspace config lfs.storage /root/lfsstore
if command -v git-lfs >/dev/null 2>&1; then git -C /workspace lfs install --skip-repo >/dev/null; fi
git -C /workspace config user.name "Claude (silkgate/$session)"
git -C /workspace config user.email "claude-$session@silkgate.invalid"
git -C /workspace checkout --detach --quiet "$base"
"""


def _setup_checkout_guest(sandbox, base, session):
    """Clone + detached checkout in the guest, streamed like _setup_branch_guest."""
    rc = vm.run_guest(lambda c: vm.msb_exec_argv(sandbox, c),
                      ["sh", "-c", _CHECKOUT_SETUP_SH, "_", base, session], tty=False)
    if rc:
        console.die("guest git setup failed — session torn down")


# The bundle range is always base..branch; only the nothing-new check moves with harvests.
# rev-list --count, not a tip comparison: a guest reset to an ancestor of the base would
# otherwise reach `bundle create`, which refuses an empty range with an error this protocol
# would misread as a broken guest.
_BUNDLE_SH = """\
set -eu
if ! tip=$(git rev-parse --verify "refs/heads/$1^{commit}" 2>/dev/null); then
  echo SILKGATE_NO_BRANCH; exit 0
fi
if [ "$(git rev-list --count "$2..refs/heads/$1")" -eq 0 ]; then
  echo SILKGATE_NO_COMMITS; exit 0
fi
rm -f /workspace/.silkgate.bundle
git bundle create --quiet /workspace/.silkgate.bundle "$3..refs/heads/$1"
echo "SILKGATE_BUNDLED $tip"
"""


def _bundle_in_guest(meta):
    """(token, detail) from the guest: NO_BRANCH, NO_COMMITS, BUNDLED <tip>, or ERROR <why>."""
    since = meta.get("branch_ingested") or meta["base"]
    try:
        # stdin closed: the script reads none, and msb exec waits on an inherited
        # stdin for EOF (see tier1_fault) — a detached caller's would never close.
        proc = subprocess.run(vm.msb_exec_argv(meta["sandbox"],
                                               ["sh", "-c", _BUNDLE_SH, "_", meta["branch"],
                                                since, meta["base"]]),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              start_new_session=True, timeout=_GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        return "SILKGATE_ERROR", "the guest did not answer the bundle request in time"
    for line in reversed(proc.stdout.splitlines()):
        token, _, detail = line.strip().partition(" ")
        if token in ("SILKGATE_NO_BRANCH", "SILKGATE_NO_COMMITS", "SILKGATE_BUNDLED"):
            return token, detail
    return "SILKGATE_ERROR", (proc.stderr.strip().splitlines() or ["no verdict from the guest"])[-1]


def _ingest_bundle(meta, bundle, tip):
    """Fetch the guest's bundle under fsck and fast-forward the branch, or say why not.

    The promote is one compare-and-swap against what the last harvest ingested (or
    must-not-exist, the first time). It refuses a branch someone else moved and rewritten
    history. Refused commits stay at the staging ref."""
    name, branch, git_dir = meta["name"], meta["branch"], meta["git_dir"]
    staging = f"refs/silkgate/{name}/{branch}"
    kept = f"the bundle stays at {bundle}; the workspace is kept"

    def refuse(why):
        console.say(f"branch {branch!r} not updated: {why} — {kept}")
        return False

    if not bundle.is_file():
        return refuse("the guest reported a bundle that never landed in the workspace")
    proc = _git(git_dir, "bundle", "verify", str(bundle))
    if proc is None or proc.returncode:
        return refuse("the bundle does not verify against this repository")
    proc = _git(git_dir, "-c", "fetch.fsckObjects=true", "fetch", "--no-write-fetch-head",
                str(bundle), f"+refs/heads/{branch}:{staging}")
    if proc is None or proc.returncode:
        return refuse("fetching the bundle failed fsck")
    proc = _git(git_dir, "rev-parse", "--verify", f"{staging}^{{commit}}")
    if proc is None or proc.returncode:
        return refuse("the staging ref did not materialise")
    staged = proc.stdout.strip()
    if staged != tip:
        return refuse("the fetched tip is not what the guest bundled")
    # Ancestry against the last harvested tip, not the base: descent from the base alone
    # would let a guest that rewrote already-harvested history move the branch sideways
    # with a clean CAS (the old value still matches). Fast-forward-only means each harvest
    # descends from the previous one; the first descends from the base.
    old = meta.get("branch_ingested", "")
    proc = _git(git_dir, "merge-base", "--is-ancestor", old or meta["base"], staged)
    if proc is None or proc.returncode:
        what = "fast-forward the last harvested tip" if old else "descend from the base commit"
        return refuse(f"the branch does not {what} — commits staged at {staging}")
    proc = _git(git_dir, "update-ref", f"refs/heads/{branch}", staged, old)
    if proc is None or proc.returncode:
        return refuse(f"refs/heads/{branch} moved since the last harvest — commits staged "
                      f"at {staging}")
    _git(git_dir, "update-ref", "-d", staging, staged)          # best-effort tidy-up
    count = _git(git_dir, "rev-list", "--count", f"{meta['base']}..{staged}")
    n = count.stdout.strip() if count and not count.returncode else "?"
    console.say(f"branch {branch}: {n} commit(s) since base, tip {staged[:12]}")
    mpath = sessions.session_dir(name) / "meta.json"
    if mpath.is_file():
        sessions._write_json(mpath, {**meta, "branch_ingested": staged})
        meta["branch_ingested"] = staged
    return True


def _harvest_branch(meta):
    """Bundle out of the guest and ingest; True iff the workspace holds nothing durable."""
    token, detail = _bundle_in_guest(meta)
    tip = detail if token == "SILKGATE_BUNDLED" else None
    if token == "SILKGATE_NO_COMMITS":
        since = "the last harvest" if meta.get("branch_ingested") else "the base commit"
        console.say(f"no commits since {since} — nothing to ingest")
        ok, result = True, "no_commits"
    elif token == "SILKGATE_NO_BRANCH":
        console.say(f"the guest deleted branch {meta['branch']!r} — nothing to ingest")
        ok, result = True, "no_branch"
    elif token == "SILKGATE_BUNDLED":
        ok = _ingest_bundle(meta, Path(meta["workspace"]) / ".silkgate.bundle", tip)
        result = "ingested" if ok else "failed"
    else:
        if meta.get("branch_ingested"):
            console.say(f"could not reach the guest ({detail}); refs/heads/{meta['branch']} holds "
                        f"the last harvested state — the workspace is kept")
        else:
            console.say(f"could not harvest branch {meta['branch']!r}: {detail} — the workspace "
                        "is kept")
        ok, result = False, "failed"
    # The verdict is settled before the record is cut, and _journal never raises, so a
    # journal failure cannot change what this harvest reports.
    sessions._journal(meta["name"], "harvest", result=result, tip=tip,
                      detail=None if token == "SILKGATE_BUNDLED" else detail or None)
    return ok


def _reap_derived_workspace(meta):
    """Delete a branch session's workspace — and only that. meta is data from disk, and this
    is an rmtree, so both locks must hold: the flag, and the path resolving to exactly the
    directory a branch session derives. A user-named -v mount never carries the flag."""
    if not meta.get("workspace_derived") or not meta.get("workspace"):
        return
    ws = Path(meta["workspace"])
    expected = Path(meta.get("repo_root", "")) / ".silkgate" / "sandboxes" / meta["name"]
    if not ws.exists():
        return
    if ws.resolve() != expected.resolve():
        console.say(f"not deleting {ws}: it is not this session's derived workspace")
        return
    shutil.rmtree(ws, ignore_errors=True)
