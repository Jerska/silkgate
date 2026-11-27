"""Mounts: which host paths a guest may see, and where in the guest they may land."""
import os
import posixpath
from pathlib import Path

from . import console, paths


# Mounts are the only host paths a guest ever sees. Even read-only access to home,
# silkgate's own state, or the checkout this CLI runs from exposes credentials and
# configuration — so the guard applies regardless of the mount mode.
# This, _RESERVED_DSTS, and _mount_args are mirrored in README.md (Mounts). Update both.
def _forbidden_mounts():
    return ((Path.home(), "your home directory"),
            (paths.SILK_DIR,
             "silkgate's own state (session rulesets, the control socket, the CA)"),
            (paths.REPO, "the silkgate checkout this CLI runs from"))


def _find_git_dir(root):
    """The first `.git` directory at or under `root`, or None. The walk never follows
    symlinks, so it is bounded by the tree the user chose to mount and cannot leave it."""
    for dirpath, dirnames, _ in os.walk(root):
        if ".git" in dirnames:
            return Path(dirpath) / ".git"
    return None


# Guest paths silkgate populates: /silkgate (context, scripts, base.git), /root/lfsstore, and
# /root/gitdir (a branch session's clone). A -v at or under one would shadow it. One above
# it is as bad: it nests virtiofs, and would put a branch clone's hooks on a host directory.
# So the refusal runs both ways.
_RESERVED_DSTS = ("/silkgate", "/root/lfsstore", "/root/gitdir")


def _split_mount(spec):
    """One -v value, SRC:DST[:MODE] -> (src, dst, mode), or None if malformed. MODE is
    exactly `ro` or `rw` and defaults to `ro` — write access to host files is asked for,
    never implied. The path rules live in _mount_pair; this is syntax alone."""
    parts = spec.split(":")
    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1], "ro"
    if len(parts) == 3 and parts[0] and parts[1] and parts[2] in ("ro", "rw"):
        return parts[0], parts[1], parts[2]
    return None


def _normalize_dst(dst):
    """One comparable form per guest path, so the duplicate/nesting guards cannot be
    dodged by spelling: `.`/`..`/`//` collapse (POSIX's special leading // included —
    it means nothing to the guest)."""
    d = posixpath.normpath(dst)
    return "/" + d.lstrip("/") if d.startswith("/") else d


def _mount_pair(src, dst, mode, *, allow_git_dir=False):
    """One mount, both sides checked -> (resolved host path, normalized guest path).

    Host side:
    - _forbidden_mounts (credentials, configuration) is refused in either mode.
    - An rw mount is refused if it holds a `.git` directory anywhere, not just at its
      root: hooks and config there would become guest-writable. A root-only check would
      be trusted as if it checked everything.
    - A linked worktree passes: its `.git` is a file that points outside the mount.
    - --allow-git-dir skips the walk, so the risk sits on a command line a human
      approved, never in an env var that outlives the decision. An ro mount skips it too.

    Guest side: DST is absolute, isn't `/`, and doesn't touch _RESERVED_DSTS.
    """
    w = Path(src).resolve()
    if not w.is_dir():
        console.die(f"mount source is not a directory: {w}")
    if w.parent == w:
        console.die(f"refusing to mount {w}: that is the whole filesystem")
    for path, what in _forbidden_mounts():
        target = Path(path).resolve()
        if w == target or w in target.parents:
            console.die(f"refusing to mount {w}: it is (or contains) {what} — credentials and "
                        "configuration there must not be exposed to the guest")
    d = _normalize_dst(dst)
    if not d.startswith("/"):
        console.die(f"mount destination {dst!r} is not absolute — guest paths start at /")
    if d == "/":
        console.die(f"refusing to mount {w} over the guest's whole filesystem")
    for reserved in _RESERVED_DSTS:
        if d == reserved or d.startswith(reserved + "/") or reserved.startswith(d + "/"):
            console.die(f"refusing to mount at {d}: it is (or contains) {reserved}, silkgate's "
                        "own path in the guest")
    if mode == "ro":
        if (w / ".git").is_file():
            console.say(f"note: {w} is a linked git worktree — the .git pointer file is in the "
                        "read-only mount, but hooks and config live outside it")
        return str(w), d
    if allow_git_dir:
        console.say(f"note: --allow-git-dir — {w} is mounted without the .git check, so hooks and "
                    "config of any repository inside are guest-writable: host code execution the "
                    "next time a human runs git there")
    else:
        dotgit = _find_git_dir(w)
        if dotgit is not None:
            where = "" if dotgit.parent == w else f" (at {dotgit.parent.relative_to(w)})"
            console.die(f"refusing to mount {w} at {d} read-write: it holds a .git "
                        f"directory{where}, so the guest would get read-write access to hooks and "
                        "config — host code execution the next time you run git there. Mount a "
                        "linked worktree instead (git worktree add), mount it read-only, or "
                        "accept the risk explicitly with --allow-git-dir.")
    if (w / ".git").is_file():
        console.say(f"note: {w} is a linked git worktree — hooks and config live outside the "
                    "mount and are beyond the guest's reach, but the .git pointer file itself is "
                    "not")
    return str(w), d


def _mount_args(specs, *, allow_git_dir=False):
    """Every -v flag validated -> [(host, guest, mode)], in flag order.

    Refused here: two mounts at one DST (the VMM silently keeps the last), a DST nested
    under another (unverified nested virtiofs), and --allow-git-dir with no rw mount,
    since a flag accepted and ignored reads as honored.
    """
    mounts = []
    for spec in specs or ():
        parsed = _split_mount(spec)
        if parsed is None:
            console.die(f"invalid mount {spec!r} — expected SRC:DST[:ro|rw] (MODE defaults to ro)")
        host, guest = _mount_pair(*parsed, allow_git_dir=allow_git_dir)
        for _, other, _ in mounts:
            if guest == other:
                console.die(f"duplicate mount destination {guest} — one guest path takes one "
                            "mount")
            inner, outer = sorted((guest, other), key=len)
            if outer.startswith(inner + "/"):
                console.die(f"mount destinations {inner} and {outer} nest — nested virtiofs "
                            "behavior is unverified, so it is refused rather than trusted")
        mounts.append((host, guest, parsed[2]))
    if allow_git_dir and not any(mode == "rw" for _, _, mode in mounts):
        console.die("--allow-git-dir does nothing here — the .git risk it accepts only exists "
                    "for a read-write -v mount")
    return mounts
