"""The msb microVM: the argv that creates and enters a guest, the Tier-1 probe, and the relay
that carries its output."""
import os
import re
import signal
import subprocess
import sys
import termios

from . import briefing, console, foreground, mitm


GUEST_EXECS = "/silkgate/execs"               # one pidfile per exec, <exec_id>.pid
TIER1_PROBE_TARGET = "1.1.1.1:443"   # must be a live public service: the probe passes only
                                     # when a connect that WOULD succeed is denied (tier1_fault)


# --- msb session guests -----------------------------------------------------

def _msb():
    return console.which("msb", "curl -fsSL https://install.microsandbox.dev | sh")


def msb_argv(image, cmd, port, *, pull_never=True, mounts=()):
    """One-shot `msb run` of a guest locked to one proxy port (the verify path)."""
    argv = [console.which("msb", "curl -fsSL https://install.microsandbox.dev | sh"), "run", image]
    if pull_never:
        argv += ["--pull", "never"]
    for m in mounts:
        argv += ["-v", m]
    url = f"http://{mitm.PROXY_ALIAS}:{port}"
    for var in mitm.PROXY_ENV_VARS:
        argv += ["-e", f"{var}={url}"]
    argv += ["--net-default-egress", "deny", "--net-rule", f"allow@host:tcp:{port}"]
    return argv + ["--"] + list(cmd)


def msb_create_argv(sandbox, image, port, *, mounts=(), env=(), copies=(),
                    memory=None, cpus=None):
    """A backgrounded, idling guest whose only egress is its own proxy port."""
    argv = [_msb(), "create", image, "--name", sandbox, "--pull", "never"]
    if memory:                                          # sized by --memory; else msb's default
        argv += ["-m", memory]
    if cpus:                                            # set by --cpus; else msb's default
        argv += ["-c", cpus]
    for m in mounts:
        argv += ["-v", m]
    for src, dst in copies:                             # into the rootfs, before boot
        argv += ["--copy-file", f"{src}:{dst}"]
    url = f"http://{mitm.PROXY_ALIAS}:{port}"
    for var in mitm.PROXY_ENV_VARS:                     # inherited by every later exec
        argv += ["-e", f"{var}={url}"]
    for pair in env:
        argv += ["-e", pair]
    argv += ["--net-default-egress", "deny", "--net-rule", f"allow@host:tcp:{port}"]
    return argv


def msb_exec_argv(sandbox, cmd, *, tty=False, env=()):
    argv = [_msb(), "exec", "-q"]                       # -q silences msb progress noise
    if tty:
        argv.append("-t")
    for pair in env:
        argv += ["-e", pair]
    return argv + [sandbox, "--"] + list(cmd)


def _run_msb_logs(sandbox, tail_n=None, since=None):
    """`msb logs` for one sandbox -> (lines, None) or (None, error). Non-zero/OSError => gone."""
    argv = [_msb(), "logs", sandbox]
    if tail_n is not None:
        argv += ["--tail", str(tail_n)]
    if since is not None:
        argv += ["--since", since]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True)
    except OSError as e:
        return None, str(e)
    if proc.returncode:
        return None, (proc.stderr.strip() or f"msb logs exited {proc.returncode}")
    return proc.stdout.splitlines(), None


# --- Tier-1 probe -------------------------------------------------------------
# Tier 1 rests on msb's --net-default-egress and --net-rule flags meaning what they did when
# verified. msb is pre-1.0, and an msb that parses the flags but enforces less would leave
# every session open while silkgate reports success. So no session is handed over until a
# probe inside the new guest shows the deny is real. It's a canary, not a boundary: a hostile
# --image controls the shell that prints the verdict, but the caller chose that image.

def tier1_probe_cmd(port):
    """The in-guest probe command: two bounded connects, one verdict token on stdout.

    Both use bash's /dev/tcp, with no DNS (an IP literal and an /etc/hosts alias), so
    `timeout` bounds the one slow path, a dropped SYN:

      - TIER1_PROBE_TARGET, a live public service, must NOT connect, else TIER1_LEAK. A
        refusal and a drop both count as denied.
      - The session's proxy port MUST connect, else TIER1_NOPROXY. That proves the first
        failure was a deny, not a broken probe, and the guest needs a working proxy anyway.

    An image without bash or timeout reports TIER1_UNTESTABLE:<tool>.
    """
    host, _, target_port = TIER1_PROBE_TARGET.partition(":")
    return ["sh", "-c",
            "command -v bash >/dev/null || { echo TIER1_UNTESTABLE:bash; exit 0; }; "
            "command -v timeout >/dev/null || { echo TIER1_UNTESTABLE:timeout; exit 0; }; "
            f"if timeout 1 bash -c 'exec 3<>/dev/tcp/{host}/{target_port}' 2>/dev/null; "
            "then echo TIER1_LEAK; "
            f"elif timeout 1 bash -c 'exec 3<>/dev/tcp/{mitm.PROXY_ALIAS}/{port}' 2>/dev/null; "
            "then echo TIER1_OK; else echo TIER1_NOPROXY; fi"]


def tier1_verdict(stdout, port, *, error=None):
    """Map one probe run to None (hand the session over) or the refusal message.

    Only an explicit TIER1_OK from a clean run passes. Anything else refuses: the caller
    may be an agent that never reads warnings, so "couldn't test" must never look like
    "tested and held".
    """
    if error:
        return (f"could not run the Tier-1 probe ({error}); containment is unproven, and "
                "an unproven session is not handed over. Session torn down.")
    token = next((ln.strip() for ln in stdout.splitlines()
                  if ln.strip().startswith("TIER1_")), "")
    if token == "TIER1_OK":
        return None
    if token == "TIER1_LEAK":
        return ("TIER-1 CONTAINMENT IS NOT IN EFFECT: the guest connected straight to "
                f"{TIER1_PROBE_TARGET}, around the proxy, so nothing silkgate enforces "
                "was going to bind this session. Suspect msb itself — its --net-* flag "
                "grammar is pre-1.0 and unpinned; re-run `silkgate verify` and pin an msb "
                "whose deny holds (README: Installing microsandbox). Session torn down.")
    if token == "TIER1_NOPROXY":
        return (f"Tier-1 probe: direct egress to {TIER1_PROBE_TARGET} is denied, but the "
                f"guest could not reach its own proxy at {mitm.PROXY_ALIAS}:{port}. A denial "
                "cannot be told from a dead guest network, and a session whose proxy is "
                "unreachable could not carry traffic anyway. Session torn down.")
    if token.startswith("TIER1_UNTESTABLE:"):
        return ("cannot test Tier-1 containment: the guest image has no "
                f"{token.partition(':')[2]!r}, which the probe needs (silkgate-built "
                "images carry bash + coreutils; a custom --image must too). An untestable "
                "session is not handed over. Session torn down.")
    return (f"the Tier-1 probe printed {stdout.strip()!r} instead of a verdict; "
            "containment is unproven, and an unproven session is not handed over. "
            "Session torn down.")


def tier1_fault(sandbox, port):
    """Probe a just-created guest; return None if Tier 1 holds, else why it must refuse.

    Callers run this between create and first use and tear the session down on anything
    but None — a hard stop, never a warning above a working prompt, because a silent loss
    of containment is the exact failure mode this exists to close.
    """
    argv = msb_exec_argv(sandbox, tier1_probe_cmd(port))
    # stdin is closed: msb exec waits for stdin EOF, and a detached caller's pipe never
    # closes, so the exec would time out on a healthy guest.
    # In-guest waits cap at 1 s each. 15 s covers msb exec itself stalling, which has one
    # known benign cause: msb 0.5.4 can swallow the FIRST exec after a create, and never
    # answer. Only that first exec loses, so one retry with a new exec process recovers it.
    # A second timeout, a nonzero exit, or a bad verdict is an answer, and isn't retried.
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=15)
    except subprocess.TimeoutExpired:
        try:
            proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=15)
        except subprocess.TimeoutExpired:
            return tier1_verdict("", port, error="msb exec did not return within 15s")
        console.say("note: the first Tier-1 probe exec timed out — the msb relay race (msb 0.5.4 "
                    "swallows the first exec after create); a fresh exec client answered")
    if proc.returncode:
        detail = (proc.stderr.strip() or proc.stdout.strip()).splitlines()
        return tier1_verdict(proc.stdout, port,
                             error=f"msb exec exited {proc.returncode}"
                                   + (f": {detail[-1]}" if detail else ""))
    return tier1_verdict(proc.stdout, port)


# A PTY makes programs emit terminal control: colors, cursor moves, and a reset burst on
# exit. Downstream of the relay stdout is a pipe or a file, so those bytes are never drawn —
# they just corrupt logs and break JSON parsers. Strip them and keep the text.
_ANSI = re.compile(rb"\x1b\[[0-9:;<=>?]*[ -/]*[@-~]"        # CSI: params per ECMA-48, so the
                                                            # "<=>?" private forms match too
                   rb"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)"  # OSC, incl. one cut off at EOL
                   rb"|\x1b[()][A-Za-z0-9]"                # charset selection
                   rb"|\x1b[=>78]"                         # keypad / cursor save-restore
                   rb"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # stray control bytes (keeps \t, \n)


def _plain(line):
    return _ANSI.sub(b"", line.rstrip(b"\r"))


# msb streams output live only when its stdout is a terminal, so a run needs a PTY. But the
# command must not hold it: it would turn interactive (colors, cursor codes) and merge its
# streams. So the command writes to two FIFOs, and two loops relay them into the PTY,
# tagging each line: RS for stderr, US for stdout.
#
# Both streams get a tag, because the leading byte picks the stream: a bare stdout line
# that opened with RS would read as stderr. Tagged, the command's bytes land after column
# zero, where _plain strips any tag, so its output stays data. A guest that bypasses the
# wrapper can still pick a stream, but its text never carries RS, silkgate's own mark.
#
# The shell waits for both loops, so no trailing line is lost, and $? stays the command's.
# Needs POSIX sh and mkfifo. stdin is /dev/null.
#
# SILKGATE_CONTEXT holds the context text, not a path, so a prompt can inline it. It's
# exported here, not passed with `msb -e`, because msb aborts on an env value that holds a
# newline.
_EXPORT_CONTEXT = ('[ -f %s ] && SILKGATE_CONTEXT=$(cat %s) && export SILKGATE_CONTEXT; '
                   % (briefing.GUEST_CONTEXT, briefing.GUEST_CONTEXT))

# What a journaled exec sets up in the guest, before the wrapper shell:
# - an X-Silkgate-Exec header in ANTHROPIC_CUSTOM_HEADERS, the SDK's hook for extra
#   headers, so the proxy can attribute API traffic to this exec. A caller's existing
#   value keeps its lines, and the marker goes on a new one.
# - a pidfile, which the kill endpoint signals. The wrapper's EXIT trap removes it, so a
#   missing pidfile means "already ended".
# Both are best-effort: the snippet swallows its own errors, and the command still runs.
def _exec_marker_sh(exec_id):
    if not exec_id:
        return ""
    return ('ANTHROPIC_CUSTOM_HEADERS="${ANTHROPIC_CUSTOM_HEADERS:+'
            '${ANTHROPIC_CUSTOM_HEADERS}\n'
            f'}}X-Silkgate-Exec: {exec_id}"; export ANTHROPIC_CUSTOM_HEADERS; '
            f'{{ mkdir -p {GUEST_EXECS} && printf %s "$$" >{GUEST_EXECS}/{exec_id}.pid; }} '
            '2>/dev/null || :; '
            f'trap "rm -f {GUEST_EXECS}/{exec_id}.pid 2>/dev/null" EXIT; ')


_RELAY_SH = (_EXPORT_CONTEXT
             + 'd=$(mktemp -d); mkfifo "$d/o" "$d/e"; '
             f'while IFS= read -r l || [ -n "$l" ]; do printf "\\{ord(console._OUT_TAG):03o}%s\\n" "$l"; done <"$d/o" & po=$!; '
             f'while IFS= read -r l || [ -n "$l" ]; do printf "\\{ord(console._ERR_TAG):03o}%s\\n" "$l"; done <"$d/e" & pe=$!; '
             '"$@" </dev/null >"$d/o" 2>"$d/e"; rc=$?; wait $po $pe; rm -rf "$d"; exit $rc')


def run_guest(build_argv, cmd, *, tty, on_line=None, exec_id=None):
    """Run a guest command and return its exit code.

    Without a TTY, the command gets pipes, and its output still arrives live, on our own
    two streams (_RELAY_SH). With `tty`, it gets a real terminal for a TUI, and draws on the
    screen directly, so it can imitate say(). The voice mark only holds where guest bytes
    pass through this process.

    `exec_id` threads the exec marker into whichever wrapper shell runs (see
    _exec_marker_sh); None runs unmarked, as silkgate's own setup execs do.
    """
    marker = _exec_marker_sh(exec_id)
    if tty:
        # A terminal run gets no relay, so the context export needs its own tiny shell.
        # A marked exec keeps that shell (no exec): its EXIT trap is what removes the
        # pidfile, and the command shares the shell's process group either way, so the
        # kill endpoint's group signal reaches it the same.
        tail = '"$@"' if marker else 'exec "$@"'
        cmd = ["sh", "-c", _EXPORT_CONTEXT + marker + tail, "_"] + list(cmd)
        if sys.stdout.isatty():
            # Inheriting a real terminal is what keeps a TUI fully interactive — and
            # what lets an interrupted TUI leave that terminal in raw mode, so the
            # settings are guarded, and an exit mid-wait (SIGTERM, SIGHUP) stops the
            # child instead of orphaning it against a sandbox about to be removed.
            with foreground._guarded_terminal():
                proc = subprocess.Popen(build_argv(cmd))
                try:
                    return foreground.wait_foreground(proc)
                finally:
                    foreground.stop(proc)
        return _pty_relay(build_argv(cmd), demux=False, on_line=on_line)
    return _pty_relay(build_argv(["sh", "-c", marker + _RELAY_SH, "_"] + list(cmd)),
                      demux=True, on_line=on_line)


def _pty_relay(argv, *, demux, on_line=None):
    """Run argv with a PTY for its stdio and copy what it writes to our own streams.

    `demux` splits the tagged lines back out and drops terminal control bytes. Without it,
    bytes pass through for a TUI, except RS, which say()'s mark relies on.

    SIGINT is ignored while the child runs, as in wait_foreground: Ctrl-C reaches the child
    through the terminal, and the parent stays to relay its last output and return its
    status. A child still running on the way out (SIGTERM, or our stdout closed) is
    stopped, never orphaned against a sandbox about to be removed.
    """
    previous = signal.signal(signal.SIGINT, lambda *a: None)
    ptm, pts = os.openpty()
    proc = None
    try:
        attrs = termios.tcgetattr(pts)                  # no echo: our EOF byte below would
        attrs[3] &= ~termios.ECHO                       # otherwise come back as "^D"
        termios.tcsetattr(pts, termios.TCSANOW, attrs)
        proc = subprocess.Popen(argv, stdin=pts, stdout=pts, stderr=pts)
        os.close(pts)
        if not sys.stdin.isatty():
            os.write(ptm, b"\x04")                      # EOF: nothing will type at this PTY
        buf = b""
        while True:
            try:
                chunk = os.read(ptm, 65536)
            except OSError:                             # slave closed — the child is done
                break
            if not chunk:
                break
            if not demux:
                sys.stdout.buffer.write(chunk.replace(console._ERR_TAG, b""))
                sys.stdout.buffer.flush()
                continue
            buf += chunk
            while b"\n" in buf:                         # a line is the unit for both the
                line, buf = buf.split(b"\n", 1)         # stderr tag and ANSI stripping
                _relay(line, newline=True, on_line=on_line)
        if buf:
            _relay(buf, newline=False, on_line=on_line)
        return foreground.wait_foreground(proc)
    finally:
        os.close(ptm)
        if proc is not None:
            foreground.stop(proc)                       # reaped already on the clean path
        signal.signal(signal.SIGINT, previous)


def _relay(line, *, newline, on_line=None):
    """Write one relayed line to our stdout, or to stderr if the wrapper tagged it so.

    Only the leading byte routes. RS or US anywhere else is guest content, and _plain
    drops it. Untagged lines (msb's noise, a wrapper that died early) go to stdout, which
    claims nothing. `on_line` sees the same cleaned text a reader does.
    """
    tag = line[:1]
    stream = sys.stderr.buffer if tag == console._ERR_TAG else sys.stdout.buffer
    text = _plain(line[1:] if tag in (console._ERR_TAG, console._OUT_TAG) else line)
    stream.write(text + b"\n" if newline else text)
    stream.flush()
    if on_line is not None:
        on_line(text.decode(errors="replace"))
