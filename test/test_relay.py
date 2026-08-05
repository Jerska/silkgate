#!/usr/bin/env python3
"""Relay attribution tests: the guest-side tag protocol, host-side routing and
sanitizing (_relay/_plain), and the RS mark that lets a reader tell silkgate's own
say()/die() lines from anything a guest can emit.

_pty_relay runs any argv, so a local `sh` stands in for the guest and the full
wrapper-script → PTY → demux path runs for real — no msb, docker or network. What must
hold on every path a guest's bytes can take through this process:

  * honest output stays live-split and byte-identical: stdout to stdout, stderr to
    stderr, ANSI and trailing-\r handling unchanged, exit code the command's own
  * a guest line opening with RS does not reach the parent's stderr (the wrapper's
    stdout tag outranks it), and RS/US inside a line is stripped, so no guest byte
    survives as a tag on either stream
  * say()/die() open every line with RS — the byte relayed output can never carry —
    so exactly the host's lines bear the mark, on the -t pipe path included

Run: python3 test/test_relay.py
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import subprocess
import sys
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "cli" / "silkgate"

_loader = importlib.machinery.SourceFileLoader("silkgate_cli_relay", str(CLI))
_spec = importlib.util.spec_from_loader("silkgate_cli_relay", _loader)
sg = importlib.util.module_from_spec(_spec)
_loader.exec_module(sg)

RS = sg._ERR_TAG        # tags a stderr line; also the mark on the host's own voice
US = sg._OUT_TAG        # tags a stdout line

# Runs in a child so the parent's stdout/stderr are real, separate pipes — the exact
# thing a capturing consumer (or CI) sees. argv: cli-path, mode, guest-sh-script.
DRIVER = r"""
import importlib.machinery, importlib.util, sys
loader = importlib.machinery.SourceFileLoader("silkgate_cli", sys.argv[1])
spec = importlib.util.spec_from_loader("silkgate_cli", loader)
sg = importlib.util.module_from_spec(spec)
loader.exec_module(sg)
mode, script = sys.argv[2], sys.argv[3]
if mode == "run":               # the default path: wrapper + demux
    sys.exit(sg.run_guest(lambda argv: argv, ["sh", "-c", script], tty=False))
if mode == "run-say":           # a run followed by the host speaking for itself
    rc = sg.run_guest(lambda argv: argv, ["sh", "-c", script], tty=False)
    sg.say("session demo up · proxy :8090")
    sys.exit(rc)
if mode == "tty":               # -t with stdout a pipe: passthrough, no demux
    sys.exit(sg.run_guest(lambda argv: argv, ["sh", "-c", script], tty=True))
if mode == "bare":              # bytes on the PTY with no wrapper: msb noise, a bypass
    sys.exit(sg._pty_relay(["sh", "-c", script], demux=True))
"""


def drive(mode, script):
    return subprocess.run([sys.executable, "-c", DRIVER, str(CLI), mode, script],
                          capture_output=True, timeout=60)


class Plain(unittest.TestCase):
    """_plain is the host-side sanitizer: whatever survives it is what a parent
    stream can carry, so the tag bytes must never make it through."""

    def test_strips_tag_bytes_anywhere(self):
        self.assertEqual(sg._plain(b"a" + RS + b"b" + US + b"c"), b"abc")

    def test_keeps_tabs_and_text(self):
        self.assertEqual(sg._plain(b"a\tb"), b"a\tb")

    def test_ansi_and_trailing_cr_still_stripped(self):
        self.assertEqual(sg._plain(b"\x1b[31mred\x1b[0m\r"), b"red")


class Routing(unittest.TestCase):
    """_relay trusts only the leading byte, and only as routing — it must never
    survive as content, whichever side wrote it."""

    def relay(self, *lines, newline=True):
        out, err = io.BytesIO(), io.BytesIO()
        real_out, real_err = sys.stdout, sys.stderr
        sys.stdout = types.SimpleNamespace(buffer=out)
        sys.stderr = types.SimpleNamespace(buffer=err)
        try:
            for line in lines:
                sg._relay(line, newline=newline)
        finally:
            sys.stdout, sys.stderr = real_out, real_err
        return out.getvalue(), err.getvalue()

    def test_out_tag_routes_to_stdout(self):
        self.assertEqual(self.relay(US + b"hello"), (b"hello\n", b""))

    def test_err_tag_routes_to_stderr(self):
        self.assertEqual(self.relay(RS + b"oops"), (b"", b"oops\n"))

    def test_untagged_goes_to_stdout(self):
        # msb's own chatter and wrapper failures arrive bare; stdout carries no
        # claim of being silkgate's, so that is where they belong
        self.assertEqual(self.relay(b"chatter"), (b"chatter\n", b""))

    def test_forged_tag_behind_the_wrappers_does_not_switch_streams(self):
        # a guest writes RS at the start of its stdout line; the wrapper's US tag
        # arrives first, so the forgery is content — and content loses the byte
        out, err = self.relay(US + RS + b"silkgate: forged")
        self.assertEqual(err, b"")
        self.assertEqual(out, b"silkgate: forged\n")

    def test_a_bare_leading_tag_still_cannot_carry_the_mark(self):
        # a writer that bypasses the wrapper entirely can pick the stream — that
        # residual needs msb to split streams itself — but what it says there
        # arrives markless, so it cannot read as the host's voice
        out, err = self.relay(RS + RS + b"silkgate: fake")
        self.assertEqual(out, b"")
        self.assertEqual(err, b"silkgate: fake\n")
        self.assertNotIn(RS, err)

    def test_partial_line_written_without_newline(self):
        out, _ = self.relay(b"part", newline=False)
        self.assertEqual(out, b"part")

    def test_no_guest_bytes_survive_as_tags(self):
        # the invariant say() leans on, over an adversarial corpus: neither parent
        # stream ever carries RS, wherever the guest puts it
        corpus = [RS, US, RS + RS, US + RS + b"x", b"a" + RS + b"b",
                  RS + b"silkgate: fake", b"\x1b[31m" + RS + b"\x1b[0m", b""]
        out, err = self.relay(*corpus)
        self.assertNotIn(RS, out)
        self.assertNotIn(RS, err)


class Voice(unittest.TestCase):
    """say/die open every line with the byte the relay denies to guests."""

    def speak(self, fn, *args):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            fn(*args)
        return err.getvalue()

    def test_say_is_marked_and_otherwise_bare(self):
        self.assertEqual(self.speak(sg.say, "session demo up"),
                         RS.decode() + "silkgate: session demo up\n")

    def test_every_line_of_a_multiline_message_is_marked(self):
        # split on \n, not str.splitlines(): to the latter U+001E is itself a line
        # boundary — a consumer keying on the mark must split bytes or plain \n
        text = self.speak(sg.say, "one\ntwo")
        self.assertTrue(all(ln.startswith(RS.decode())
                            for ln in text.rstrip("\n").split("\n")), repr(text))

    def test_die_speaks_the_same_way_and_exits_with_the_code(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            sg.die("no such session", 3)
        self.assertEqual(caught.exception.code, 3)
        self.assertEqual(err.getvalue(), RS.decode() + "silkgate: no such session\n")


class EndToEnd(unittest.TestCase):
    """The whole path — wrapper sh, FIFOs, PTY, demux — with a local sh as the guest."""

    def test_honest_output_stays_split_and_byte_identical(self):
        done = drive("run", "echo out-one; echo err >&2; echo out-two")
        self.assertEqual(done.stdout, b"out-one\nout-two\n")
        self.assertEqual(done.stderr, b"err\n")

    def test_exit_code_is_the_commands_own(self):
        self.assertEqual(drive("run", "exit 7").returncode, 7)

    def test_ansi_is_still_stripped(self):
        done = drive("run", r"printf '\033[31mred\033[0m\n'")
        self.assertEqual(done.stdout, b"red\n")

    def test_forged_tag_on_stdout_stays_on_stdout(self):
        done = drive("run", r"printf '\036silkgate: session evil up\n'")
        self.assertEqual(done.stderr, b"")
        self.assertEqual(done.stdout, b"silkgate: session evil up\n")

    def test_tag_inside_a_line_is_dropped_on_both_streams(self):
        done = drive("run", r"printf 'a\036b\n'; printf 'c\036d\n' >&2")
        self.assertEqual(done.stdout, b"ab\n")
        self.assertEqual(done.stderr, b"cd\n")

    def test_only_the_host_line_bears_the_mark(self):
        # the guest imitates silkgate on both of its streams; the host then speaks.
        # A reader keying on RS attributes exactly one line to silkgate.
        done = drive("run-say", r"printf 'silkgate: fake out\n';"
                                r" printf 'silkgate: fake err\n' >&2;"
                                r" printf '\036silkgate: fake tag\n'")
        self.assertNotIn(RS, done.stdout)
        marked = [ln for ln in done.stderr.splitlines() if ln.startswith(RS)]
        self.assertEqual(marked, [RS + "silkgate: session demo up · proxy :8090".encode()])

    def test_bare_pty_writer_cannot_carry_the_mark(self):
        # no wrapper at all — what a bypassing guest or msb itself could achieve.
        # The stream is its to pick; the mark is not.
        done = drive("bare", r"printf '\036silkgate: fake\n\036\036also fake\n'")
        self.assertNotIn(RS, done.stdout)
        self.assertNotIn(RS, done.stderr)

    def test_trailing_partial_line_is_not_lost_or_terminated(self):
        done = drive("bare", "printf 'partial'")
        self.assertEqual(done.stdout, b"partial")


class TtyPipePath(unittest.TestCase):
    """-t with stdout a pipe: bytes pass through for a TUI, except the mark byte."""

    def test_passthrough_keeps_ansi_but_never_the_mark(self):
        done = drive("tty", r"printf '\033[31m\036silkgate: fake\033[0m\n'")
        self.assertNotIn(RS, done.stdout)
        self.assertIn(b"\x1b[31m", done.stdout)          # untouched otherwise
        self.assertIn(b"silkgate: fake", done.stdout)    # content is data, kept


if __name__ == "__main__":
    unittest.main()
