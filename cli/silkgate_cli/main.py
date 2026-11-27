"""silkgate: run an untrusted agent in a microVM whose only way out is an allowlisting proxy.

  silkgate run --name fix --with git --with claude --branch agent/fix -- \\
      silkgate-claude -p "fix the failing test, commit as you go"
  silkgate up --name foo --with claude -v ~/notes:/workspace
  silkgate exec foo -- silkgate-claude -p "summarize the notes"
  silkgate down foo

Each --with profile decides both what's installed and what it may reach. Secrets stay on
the host as SILKGATE_EGRESS_SECRET_<NAME>="<Header>: <value>". State lives in ~/.silkgate.
Docs: README.md, and doc/ beside it.
"""
import argparse
import os
import re
import signal
import sys

from . import core, logs, ui_server, verify


# The two argument types that reach a generated Dockerfile or an msb argv are checked by
# argparse itself, so a rejection names the flag it came from: `--with node@22.11.0` is
# exactly the token a reviewer's eye slides over on a command line composed for approval.

def _mount_arg(spec):
    """argparse type for -v/--mount: SRC:DST[:MODE] syntax alone — the path guards run at
    dispatch, where the mount list is checked as a whole (_mount_args)."""
    if core._split_mount(spec) is None:
        raise argparse.ArgumentTypeError(
            f"invalid mount {spec!r} — expected SRC:DST[:ro|rw] (MODE defaults to ro)")
    return spec


def _with_arg(spec):
    """argparse type for --with: `name[@version][:arg]`. The name is resolved later,
    against the profiles that exist; the version and arg charsets are asked here."""
    try:
        core._parse_spec(spec)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))
    return spec


def _image_arg(ref):
    """argparse type for --base and --image."""
    bad = core._image_error(ref)
    if bad:
        raise argparse.ArgumentTypeError(bad)
    return ref


def _memory_arg(value):
    """argparse type for --memory: the shape msb documents for -m, digits then M or G."""
    if not re.fullmatch(r"[0-9]+[MG]", value):
        raise argparse.ArgumentTypeError(
            f"invalid memory size {value!r} — expected digits then M or G, "
            "for example 512M or 1G")
    return value


def _cpus_arg(value):
    """argparse type for --cpus: the shape msb documents for -c, a positive integer."""
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise argparse.ArgumentTypeError(
            f"invalid cpu count {value!r} — expected a positive integer, "
            "for example 2 or 4")
    return value


class _MarkedParser(argparse.ArgumentParser):
    """argparse whose stderr lines carry silkgate's voice mark.

    argparse's `usage:` and `error:` lines are host voice, so they get say()'s mark. The
    status and text stay argparse's own. error() and exit() are argparse's override points,
    and add_subparsers() reuses this class, so every subcommand is covered. Help goes to
    stdout, bare.
    """

    def exit(self, status=0, message=None):
        # argparse passes a message here only on the error path; help and version print
        # to stdout elsewhere and call this bare.
        if message:
            mark = core._ERR_TAG.decode()
            sys.stderr.write("".join(mark + ln for ln in message.splitlines(keepends=True)))
            sys.stderr.flush()
        sys.exit(status)

    def error(self, message):
        # Exactly what stock error() prints — usage, then "prog: error: message" — folded
        # into one exit() message so every line passes through the marking above.
        self.exit(2, f"{self.format_usage()}{self.prog}: error: {message}\n")


# The run, up, and exec options are mirrored in README.md (More flags). Update both.
def main():
    ap = _MarkedParser(prog="silkgate", description=__doc__,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    def profile_opts(p, *, rules_only=False):
        p.add_argument("-w", "--with", dest="with_", action="append",
                       metavar="PROFILE[@VER][:ARG]", type=_with_arg,
                       help="add a profile: what to install and what it may reach "
                            "(repeatable; see `silkgate profiles`)")
        if not rules_only:
            p.add_argument("--base", default=core.BASE_IMAGE, type=_image_arg,
                           help=f"base image under the profiles (default: {core.BASE_IMAGE})")
        p.add_argument("--rule", action="append", metavar="RULE",
                       help="add one rule, e.g. 'example.com/** GET' (repeatable)")

    def env_opt(p):
        p.add_argument("-e", "--env", action="append", default=[], metavar="NAME=VALUE",
                       help="set an env var in the guest (repeatable). Secrets go in "
                            "SILKGATE_EGRESS_SECRET_<NAME> instead.")
        p.add_argument("--no-context", action="store_true",
                       help=f"don't write {core.GUEST_CONTEXT} or $SILKGATE_CONTEXT")
        p.add_argument("--no-settings", action="store_true",
                       help="don't copy your Claude Code model and effortLevel into the guest")

    def brief_opt(p, scope):
        p.add_argument("--brief", metavar="FILE",
                       help=f"{scope} task brief, copied to {core.GUEST_BRIEF} (max 1 MiB)")

    # Session guests default to 1G and half the host's CPUs — msb's own 512M / 1 vCPU
    # OOM-kills a guest that runs an agent beside a test suite. Both are limits the
    # host scheduler shares, not reservations, so oversubscription across guests is safe.
    default_cpus = str(max(1, (os.cpu_count() or 2) // 2))

    def guest_opts(p):
        """The options `run` and `up` share: the guest's image, resources, and workspace."""
        p.add_argument("--name", metavar="N", help="session name (default: a random 6-char id)")
        profile_opts(p)
        p.add_argument("--image", metavar="REF", type=_image_arg,
                       help="run this image as-is instead of building one. It must trust "
                            "the proxy's CA.")
        p.add_argument("--memory", metavar="SIZE", type=_memory_arg, default="1G",
                       help="guest memory, e.g. 512M or 2G (default: %(default)s)")
        p.add_argument("--cpus", metavar="COUNT", type=_cpus_arg, default=default_cpus,
                       help="guest CPUs (default: %(default)s, half the host's)")
        p.add_argument("--port", type=int, default=core.DEFAULT_BASE_PORT,
                       help="where the proxy's 16-port pool starts, if this command starts "
                            "the proxy (default: %(default)s)")
        p.add_argument("-v", "--mount", action="append", default=[], metavar="SRC:DST[:ro|rw]",
                       type=_mount_arg,
                       help="mount host directory SRC at DST, read-only unless :rw "
                            "(repeatable). $HOME, /, and silkgate's own files are refused.")
        p.add_argument("--allow-git-dir", action="store_true",
                       help="allow an rw mount that holds a .git directory. Its hooks then "
                            "run on your host the next time you use git there.")
        p.add_argument("--checkout", nargs="?", const="HEAD", default=None, metavar="REF",
                       help="give the guest a throwaway clone of this repo at REF (default "
                            "HEAD) in /workspace. Nothing comes back. Needs --with git.")
        p.add_argument("--branch", metavar="NAME",
                       help="like --checkout, on a new branch NAME whose commits come back "
                            "when the session ends. --checkout REF sets its base.")
        env_opt(p)

    p = sub.add_parser("profiles", help="list the profiles, or print the rules a spec composes")
    p.add_argument("--render", action="append", metavar="PROFILE[@VER][:ARG]",
                   type=_with_arg,
                   help="print the rules a session with these --with specs enforces "
                        "(repeatable)")
    p.set_defaults(fn=core.cmd_profiles)

    p = sub.add_parser("doctor", help="list missing tools (docker, msb, mitmdump), with "
                                      "install commands")
    p.set_defaults(fn=core.cmd_doctor)

    p = sub.add_parser("build", help="build the image for a profile list, into msb")
    profile_opts(p)
    p.add_argument("--platform", metavar="P", help="docker platform (default: the host's)")
    p.set_defaults(fn=core.cmd_build)

    p = sub.add_parser("proxy", help="run one ruleset on one port, in the foreground")
    profile_opts(p, rules_only=True)
    p.add_argument("--port", type=int, default=8090, help="listen port (default: 8090)")
    p.set_defaults(fn=core.cmd_proxy)

    p = sub.add_parser("verify", help="prove containment from inside a root guest")
    p.add_argument("--full", action="store_true",
                   help="also install probe tools through the proxy, and trust its CA")
    p.add_argument("--port", type=int, default=None,
                   help="proxy port (default: the first free 16-port range from 8090). "
                        "An explicit port fails if taken.")
    p.add_argument("--oracles", action=argparse.BooleanOptionalAction, default=True,
                   help="also check from outside the guest: the audit log, a listener that "
                        "must hear nothing, and a recorder that must see the credential "
                        "swapped (default: on)")
    p.add_argument("--negative-control", action="store_true",
                   help="also run a guest with egress open, which must fail check 3: the "
                        "proof the checks can fail")
    p.set_defaults(fn=verify.cmd_verify)

    p = sub.add_parser("run", help="run one command in a fresh guest, then remove it")
    guest_opts(p)
    brief_opt(p, "this run's")
    p.add_argument("-t", "--tty", action=argparse.BooleanOptionalAction,
                   help="give the command a terminal (default: if stdin is one). "
                        "--no-tty keeps stdout and stderr apart.")
    p.add_argument("cmd", nargs=argparse.REMAINDER, metavar="-- CMD ...",
                   help="guest command (default: the profile's command)")
    p.set_defaults(fn=core.cmd_run)

    p = sub.add_parser("up", help="start a session: a guest that stays up between commands")
    guest_opts(p)
    brief_opt(p, "the default")
    p.set_defaults(fn=core.cmd_up)

    p = sub.add_parser("exec", help="run a command in a session's guest")
    p.add_argument("name", metavar="NAME", help="session name")
    p.add_argument("-t", "--tty", action=argparse.BooleanOptionalAction,
                   help="give the command a terminal (default: if stdin is one). "
                        "--no-tty keeps stdout and stderr apart.")
    brief_opt(p, "this exec's")
    env_opt(p)
    # nargs='*' (not REMAINDER): with a positional NAME first, REMAINDER would swallow
    # -t/-e that follow NAME. '*' lets them parse; use `--` to pass flags on to CMD.
    p.add_argument("cmd", nargs="*", metavar="-- CMD ...",
                   help="guest command (put -- before one with flags)")
    p.set_defaults(fn=core.cmd_exec)

    p = sub.add_parser("attach", help="open a terminal on a session, running its profile's "
                                      "command")
    p.add_argument("name", metavar="NAME", help="session name")
    p.set_defaults(fn=core.cmd_attach)

    p = sub.add_parser("logs", help="print a session's guest output, or its proxy decisions")
    p.add_argument("name", metavar="NAME", help="session name")
    p.add_argument("-f", "--follow", action="store_true", help="keep printing new lines")
    p.add_argument("--tail", type=int, metavar="N", help="start from the last N lines")
    p.add_argument("--since", metavar="DUR",
                   help="only lines newer than DUR, e.g. 30s or 5m (guest output only)")
    p.add_argument("--audit", action="store_true",
                   help="print this session's allow and deny decisions")
    p.add_argument("--interval", type=float, default=1.0, metavar="SECS",
                   help="poll interval for -f (default: 1.0)")
    p.set_defaults(fn=logs.cmd_logs)

    p = sub.add_parser("ui", help="serve the audit UI on 127.0.0.1")
    p.add_argument("--port", type=int, default=ui_server.DEFAULT_UI_PORT,
                   help=f"listen port (default: {ui_server.DEFAULT_UI_PORT})")
    p.set_defaults(fn=ui_server.cmd_ui)

    p = sub.add_parser("harvest", help="bring a --branch session's commits back now, "
                                       "without stopping it")
    p.add_argument("name", metavar="NAME", help="session name")
    p.set_defaults(fn=core.cmd_harvest)

    p = sub.add_parser("down", help="stop and remove a session. The last one stops the proxy.")
    p.add_argument("name", metavar="NAME", help="session name")
    p.set_defaults(fn=core.cmd_down)

    p = sub.add_parser("ls", help="list sessions and proxy health")
    p.add_argument("-a", "--all", action="store_true",
                   help="include archived sessions. ID is the archive's sid.")
    p.set_defaults(fn=core.cmd_ls)

    p = sub.add_parser("secret", help="push or list the secrets the proxy holds")
    ssub = p.add_subparsers(dest="secret_cmd", required=True)
    q = ssub.add_parser("set", help="push SILKGATE_EGRESS_SECRET_<NAME> to one session. "
                                    "The value never touches argv.")
    q.add_argument("name", metavar="NAME", help="secret name: reads SILKGATE_EGRESS_SECRET_<NAME>")
    q.add_argument("--session", required=True, metavar="SESSION",
                   help="the session that may spend it")
    q.set_defaults(fn=core.cmd_secret_set)
    q = ssub.add_parser("ls", help="list secret names, never values")
    q.add_argument("--session", metavar="SESSION",
                   help="one session only (default: all, by session)")
    q.set_defaults(fn=core.cmd_secret_ls)

    # SIGTERM must run the finally-blocks that stop mitmdump/msb, not kill us outright.
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(143))
    # SIGHUP — the terminal going away over a live run — gets the same treatment and
    # the same 128+signo status, or every session and proxy this process holds would
    # outlive it. An inherited SIG_IGN (nohup) is the caller declaring hangups
    # expected, and stays.
    if signal.getsignal(signal.SIGHUP) != signal.SIG_IGN:
        signal.signal(signal.SIGHUP, lambda *a: sys.exit(129))
    args = ap.parse_args()
    try:
        args.fn(args)
    except KeyboardInterrupt:
        # An interrupt isn't an error: the finally-blocks already unwound, so just exit 130.
        # os._exit skips shutdown, which would print a pending SIGINT as a traceback.
        # SIGINT is ignored first, so a late Ctrl-C can't land in this handler.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            sys.stdout.flush()
        except (OSError, ValueError):
            pass
        os._exit(130)
    except BrokenPipeError:
        # The reader went away (`silkgate ... | head -3`) and the unwind has already
        # run. 141 is how a shell reports a pipe death; os._exit skips interpreter
        # shutdown, whose flush of the dead stream would print "Exception ignored"
        # noise over the quiet exit.
        os._exit(141)
