"""A session's life on the host: provisioning its guest, tearing it down, and archiving what
it leaves."""
import os
import shutil
import subprocess
import time

from . import briefing, console, foreground, mitm, paths, sessions, vm


def _provision_session(name, image, port, rules_text, ruleset, mounts, ws, env, meta_extra,
                       context=None, context_paths=(), settings=None, settings_paths=(),
                       memory=None, cpus=None, brief=None):
    """Stage the session dir, rename it into the registry, then boot the guest.

    The rename makes the session appear atomically, so the addon never caches a half-written
    one. On failure, undo only what's ours: the staging dir, the renamed dir if we renamed
    it, the port claim, any half-created sandbox, and the proxy if nothing else needs it."""
    sdir = sessions.session_dir(name)
    if sdir.exists():
        console.die(f"session already exists: {sdir}")
    tmp = paths.SESSIONS_DIR / f".tmp-{name}"            # dot-prefixed: invisible to registries
    shutil.rmtree(tmp, ignore_errors=True)               # stale leftover from a crash
    tmp.mkdir(parents=True)
    owned = False                                        # whether the rename made sdir ours
    created = False                                      # whether msb create was reached
    try:
        (tmp / "rules.txt").write_text(rules_text)
        if context:
            (tmp / "context.md").write_text(context)
        if settings:
            (tmp / "settings.json").write_text(settings)
        if brief is not None:
            (tmp / "brief.md").write_bytes(brief)
        meta = {"name": name, "sandbox": sessions.sandbox_name(name),
                "sid": sessions._new_sid(name), "port": port, "image": image, "workspace": ws,
                "created": sessions.now_iso(), **meta_extra}
        sessions._write_json(tmp / "meta.json", meta)
        # Into the staging dir, right after meta.json: the rename below is what makes
        # the session appear, so it appears with its journal already begun.
        sessions._journal_into(tmp, "created", meta=meta)
        try:
            tmp.rename(sdir)                             # atomic claim; fails if name raced us
            owned = True
        except OSError:
            console.die(f"session already exists: {sdir}")
        mitm._push_secrets(ruleset, name)
        # The context goes into the rootfs, never the workspace: it must not appear in the
        # user's project, and a guest rewriting it changes nothing that matters. The
        # projected settings ride the same mechanism to each profile's settings_path,
        # and the brief too, to the one path the guest is told to read.
        copies = [(sdir / "context.md", dst) for dst in context_paths] if context else []
        if settings:
            copies += [(sdir / "settings.json", dst) for dst in settings_paths]
        if brief is not None:
            copies.append((sdir / "brief.md", briefing.GUEST_BRIEF))
        created = True
        if subprocess.run(vm.msb_create_argv(sessions.sandbox_name(name), image, port,
                                             mounts=mounts, env=env, copies=copies,
                                             memory=memory, cpus=cpus)).returncode:
            console.die(f"msb create failed for session {name!r}")
    except BaseException:                                # incl. SystemExit from die()
        with foreground._deferred_interrupts():          # a Ctrl-C cannot halve the unwind
            if created:                                  # failed or cut short, a create
                _remove_sandbox(sessions.sandbox_name(name))  # can still have registered it
            shutil.rmtree(tmp, ignore_errors=True)
            if owned:
                shutil.rmtree(sdir, ignore_errors=True)
            mitm._release_port(name, port)
            _maybe_stop_proxy()                          # a failure that left the registry
        raise                                            # empty leaves no proxy over it


# What each msb call gets during a removal before it is treated as hung. Teardowns run
# under _deferred_interrupts, and a deferral is only honest while the thing it shields
# is bounded: three calls at 30s each is the worst wait, after which the failure is
# reported as a sandbox that could not be confirmed gone — never waited out silently.
_MSB_TIMEOUT = 30


def _remove_sandbox(sandbox):
    """Best-effort `msb stop` then `msb rm`. True only if the sandbox is verifiably gone.

    An rm failure counts as gone when `msb list` no longer shows the name, as for a sandbox
    that never registered. The msb children run in their own sessions, so a Ctrl-C can't
    kill the removal halfway."""
    msb = shutil.which("msb")
    if not msb or not sandbox:
        return False
    quiet = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                 start_new_session=True, timeout=_MSB_TIMEOUT)
    try:
        subprocess.run([msb, "stop", sandbox], **quiet)
    except subprocess.TimeoutExpired:
        pass                                             # stop is courtesy; rm decides
    try:
        if not subprocess.run([msb, "rm", sandbox], **quiet).returncode:
            return True
        listed = subprocess.run([msb, "list"], capture_output=True, text=True,
                                start_new_session=True, timeout=_MSB_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False                                     # a hung msb proves nothing
    if listed.returncode:
        return False                                     # cannot prove it is gone
    return not any(line.split()[:1] == [sandbox] for line in listed.stdout.splitlines()[1:])


# How much guest output an archive keeps: the tail, bounded in lines (asked of msb) and in
# bytes (enforced before the write), so a chatty guest can't balloon it. The defaults hold a
# full agent transcript, and ARCHIVE_RETAIN_COUNT snapshots cost at most ~400 MiB. Each knob
# takes a positive integer. Anything else keeps the default.
# Mirrored in doc/PROXY.md (The archive). Update both.
_SNAPSHOT_TAIL_LINES = 20000     # SILKGATE_SNAPSHOT_TAIL_LINES
_SNAPSHOT_MAX_BYTES = 8 << 20    # SILKGATE_SNAPSHOT_MAX_BYTES


def _snapshot_cap(var, default):
    """One snapshot knob: the env override where it parses positive, the default
    otherwise — _retain_days' pattern, minus the 0-turns-it-off arm."""
    try:
        value = int(os.environ.get(var, "") or default)
    except ValueError:
        return default
    return value if value > 0 else default


def _snapshot_output(sandbox, sdir):
    """Best-effort tail of the guest's output into the session dir, pre-archive.
    Fail-open like all bookkeeping: a guest whose log can no longer be read must not
    block its own teardown."""
    tail = _snapshot_cap("SILKGATE_SNAPSHOT_TAIL_LINES", _SNAPSHOT_TAIL_LINES)
    cap = _snapshot_cap("SILKGATE_SNAPSHOT_MAX_BYTES", _SNAPSHOT_MAX_BYTES)
    lines, err = vm._run_msb_logs(sandbox, tail_n=tail)
    if err is not None:
        console.say(f"warning: no guest-output snapshot for {sandbox}: {err}")
        return
    data = ("\n".join(lines) + "\n").encode("utf-8", "replace") if lines else b""
    try:
        (sdir / "output.log").write_bytes(data[-cap:])
    except OSError as e:
        console.say(f"warning: could not write the guest-output snapshot: {e}")


# Retention for ~/.silkgate/archive, favouring keeping like the audit logs (mitm.py): an
# archived session goes only when BOTH older than the age AND beyond the newest
# ARCHIVE_RETAIN_COUNT, every removal is announced, and SILKGATE_ARCHIVE_RETAIN_DAYS=0
# (or less) keeps everything.
# Mirrored with LOG_RETAIN_* in doc/PROXY.md (Retention). Update both.
ARCHIVE_RETAIN_DAYS = 30
ARCHIVE_RETAIN_COUNT = 50


def _prune_archive():
    """Apply the archive retention policy above; runs where archives are created."""
    days = mitm._retain_days("SILKGATE_ARCHIVE_RETAIN_DAYS", ARCHIVE_RETAIN_DAYS)
    if days <= 0:
        return
    cutoff = time.time() - days * 86400
    stamped = []
    try:
        entries = list(paths.ARCHIVE_DIR.iterdir())
    except OSError:
        return
    for d in entries:
        if not sessions._SID_RE.fullmatch(d.name):            # not something silkgate archived
            continue
        try:
            stamped.append((d.stat().st_mtime, d))
        except OSError:                              # vanished mid-scan: already gone
            continue
    stamped.sort(reverse=True)
    pruned = 0
    for mtime, d in stamped[ARCHIVE_RETAIN_COUNT:]:
        if mtime >= cutoff:
            continue
        shutil.rmtree(d, ignore_errors=True)
        pruned += not d.exists()
    if pruned:
        console.say(f"pruned {pruned} archived session(s) older than {days:g}d from "
                    f"{paths.ARCHIVE_DIR} (the {ARCHIVE_RETAIN_COUNT} newest always stay; "
                    "SILKGATE_ARCHIVE_RETAIN_DAYS=0 keeps everything)")


def _teardown_session(meta, archive=True):
    """Remove the guest, then free its session dir and port, in that order.

    While a guest that can reach the port may exist, the port stays reserved, or the next
    session would inherit a guest policed by the wrong ruleset. So a sandbox that can't be
    removed keeps its session, and this dies.

    With `archive` (the default), the session dir moves to ARCHIVE_DIR/<sid>, after a
    last output snapshot, the `down` journal record, and an `ended` stamp. That
    bookkeeping fails open. archive=False is for a session never handed over (`up`'s
    unwind).

    The teardown that empties the registry stops the shared proxy, whoever started it.
    Every removal runs through here, so the proxy's lifetime follows the registry."""
    name = meta.get("name")
    sandbox = meta.get("sandbox") or (sessions.sandbox_name(name) if name else None)
    sdir = sessions.session_dir(name) if name else None
    archive = archive and sdir is not None and sdir.is_dir()
    if archive and sandbox:
        _snapshot_output(sandbox, sdir)              # the guest's log dies with the VM
    if sandbox and not _remove_sandbox(sandbox):
        console.die(f"msb rm {sandbox} failed — session {name!r} kept, its proxy port still "
                    f"reserved; remove the sandbox manually, then `silkgate down {name}`")
    if name:
        # The claim goes first, while meta.json still pins the port for pick_port; the
        # rename (or rmtree) is then what genuinely frees it.
        mitm._release_port(name, meta.get("port"))
        if archive:
            sessions._journal(name, "down")
            sid = meta.get("sid") or sessions._new_sid(name)  # pre-feature metas: minted here
            try:
                sessions._write_json(sdir / "meta.json",
                                     {**meta, "sid": sid, "ended": sessions.now_iso()})
            except OSError as e:
                console.say(f"warning: could not stamp 'ended' into {name!r}'s meta: {e}")
            try:
                paths.ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
                sdir.rename(paths.ARCHIVE_DIR / sid)
            except OSError as e:
                console.say(f"warning: could not archive session {name!r} ({e}) — removing it "
                            "instead")
                shutil.rmtree(sdir, ignore_errors=True)
            _prune_archive()
        else:
            shutil.rmtree(sdir, ignore_errors=True)
    _maybe_stop_proxy()


def _maybe_stop_proxy():
    """Stop the shared proxy once the last session is gone. The check here is a courtesy;
    stop_proxy re-checks sessions and port claims under the lifecycle lock."""
    if sessions.list_metas():
        return
    meta = mitm.read_proxy()
    if meta:
        mitm.stop_proxy(meta)
