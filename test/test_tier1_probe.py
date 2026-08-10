#!/usr/bin/env python3
"""Tier-1 probe tests: the guest command silkgate builds, the probe script's own branching
(run under a real sh with a stub bash/timeout, so no msb, docker or network is needed), and
the decision taken on every probe outcome.

Run: python3 test/test_tier1_probe.py
"""
import importlib.machinery
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

_loader = importlib.machinery.SourceFileLoader("silkgate_cli", str(REPO / "cli" / "silkgate"))
_spec = importlib.util.spec_from_loader("silkgate_cli", _loader)
sg = importlib.util.module_from_spec(_spec)
_loader.exec_module(sg)

TARGET_HOST = sg.TIER1_PROBE_TARGET.partition(":")[0]


class ProbeCmd(unittest.TestCase):
    def test_posix_sh_with_both_connects_bounded(self):
        cmd = sg.tier1_probe_cmd(8093)
        self.assertEqual(cmd[:2], ["sh", "-c"])
        script = cmd[2]
        host, _, port = sg.TIER1_PROBE_TARGET.partition(":")
        self.assertIn(f"/dev/tcp/{host}/{port}", script)
        self.assertIn(f"/dev/tcp/{sg.PROXY_ALIAS}/8093", script)
        # every connect is timeout-bounded: this runs on the hot path of every up/run
        self.assertEqual(script.count("timeout 1 bash"), 2)


class ProbeScript(unittest.TestCase):
    """The script's branching, under a real sh, with stubs deciding each connect."""

    def probe(self, *, outside, proxy, bash=True, timeout=True):
        """Run the probe script with PATH holding only stubs: a no-op `bash` (found, never
        run) and a `timeout` whose exit code fakes each connect by peeking at its argv."""
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp)
            if bash:
                (stub / "bash").write_text("#!/bin/sh\nexit 0\n")
                (stub / "bash").chmod(0o755)
            if timeout:
                (stub / "timeout").write_text(
                    "#!/bin/sh\n"
                    f'case "$*" in *"{TARGET_HOST}"*) exit {outside};; esac\n'
                    f"exit {proxy}\n")
                (stub / "timeout").chmod(0o755)
            script = sg.tier1_probe_cmd(8093)[2]
            done = subprocess.run(["/bin/sh", "-c", script], capture_output=True,
                                  text=True, env=dict(os.environ, PATH=str(stub)))
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout.strip()

    def test_denied_outside_reachable_proxy_is_ok(self):
        self.assertEqual(self.probe(outside=1, proxy=0), "TIER1_OK")

    def test_dropped_outside_reads_as_denied_too(self):
        self.assertEqual(self.probe(outside=124, proxy=0), "TIER1_OK")  # 124 = timed out

    def test_outside_connect_is_a_leak(self):
        self.assertEqual(self.probe(outside=0, proxy=0), "TIER1_LEAK")

    def test_leak_reported_even_when_proxy_is_dead(self):
        self.assertEqual(self.probe(outside=0, proxy=1), "TIER1_LEAK")

    def test_unreachable_proxy_is_not_containment(self):
        self.assertEqual(self.probe(outside=1, proxy=1), "TIER1_NOPROXY")

    def test_missing_bash_is_untestable_not_denied(self):
        self.assertEqual(self.probe(outside=1, proxy=0, bash=False),
                         "TIER1_UNTESTABLE:bash")

    def test_missing_timeout_is_untestable_not_denied(self):
        self.assertEqual(self.probe(outside=1, proxy=0, timeout=False),
                         "TIER1_UNTESTABLE:timeout")


class Verdict(unittest.TestCase):
    """Which outcomes hand the session over: exactly one, TIER1_OK from a clean run."""

    def test_ok_hands_over(self):
        self.assertIsNone(sg.tier1_verdict("TIER1_OK\n", 8093))

    def test_ok_amid_other_output_still_hands_over(self):
        self.assertIsNone(sg.tier1_verdict("some chatter\nTIER1_OK\n", 8093))

    def test_leak_refuses_and_names_the_target(self):
        msg = sg.tier1_verdict("TIER1_LEAK\n", 8093)
        self.assertIn(sg.TIER1_PROBE_TARGET, msg)

    def test_noproxy_refuses_and_names_the_proxy(self):
        msg = sg.tier1_verdict("TIER1_NOPROXY\n", 8093)
        self.assertIn(f"{sg.PROXY_ALIAS}:8093", msg)

    def test_untestable_refuses_and_names_the_missing_tool(self):
        msg = sg.tier1_verdict("TIER1_UNTESTABLE:bash\n", 8093)
        self.assertIn("'bash'", msg)

    def test_no_verdict_refuses(self):
        self.assertIsNotNone(sg.tier1_verdict("", 8093))
        self.assertIsNotNone(sg.tier1_verdict("sh: 1: not found\n", 8093))

    def test_unknown_token_refuses(self):
        self.assertIsNotNone(sg.tier1_verdict("TIER1_BOGUS\n", 8093))

    def test_exec_error_refuses_and_is_reported(self):
        msg = sg.tier1_verdict("", 8093, error="msb exec exited 7: boom")
        self.assertIn("msb exec exited 7: boom", msg)

    def test_exec_error_outranks_a_verdict_token(self):
        # a token from a run msb itself reports as failed proves nothing — fail closed
        self.assertIsNotNone(sg.tier1_verdict("TIER1_OK\n", 8093, error="msb exec exited 1"))


class Fault(unittest.TestCase):
    """tier1_fault's exec handling: one fresh-client retry for a swallowed exec
    (the msb 0.5.4 relay race), and no retry for anything that is an answer."""

    def setUp(self):
        self.runs, self.notes = [], []
        self._orig = (subprocess.run, sg._msb, sg.say)
        sg._msb = lambda: "msb"
        sg.say = self.notes.append
        self.addCleanup(self._restore)

    def _restore(self):
        subprocess.run, sg._msb, sg.say = self._orig

    def fault(self, outcomes):
        """Run tier1_fault with subprocess.run scripted: each entry is either an
        exception to raise or a CompletedProcess to return, one per call."""
        it = iter(outcomes)
        def run(argv, **kw):
            self.runs.append(argv)
            out = next(it)
            if isinstance(out, BaseException):
                raise out
            return out
        subprocess.run = run
        return sg.tier1_fault("sb", 8093)

    @staticmethod
    def timeout():
        return subprocess.TimeoutExpired("msb", 15)

    @staticmethod
    def done(returncode=0, stdout="TIER1_OK\n", stderr=""):
        return subprocess.CompletedProcess("msb", returncode, stdout, stderr)

    def test_timeout_then_ok_hands_over_and_notes_the_race(self):
        self.assertIsNone(self.fault([self.timeout(), self.done()]))
        self.assertEqual(len(self.runs), 2)
        self.assertEqual(self.runs[0], self.runs[1])  # same probe, fresh exec client
        self.assertEqual(len(self.notes), 1)
        self.assertIn("relay race", self.notes[0])

    def test_two_timeouts_refuse_with_the_unchanged_message(self):
        msg = self.fault([self.timeout(), self.timeout()])
        self.assertEqual(msg, sg.tier1_verdict(
            "", 8093, error="msb exec did not return within 15s"))
        self.assertEqual(len(self.runs), 2)
        self.assertEqual(self.notes, [])

    def test_nonzero_exit_is_an_answer_not_retried(self):
        msg = self.fault([self.done(returncode=7, stderr="boom\n")])
        self.assertIsNotNone(msg)
        self.assertEqual(len(self.runs), 1)
        self.assertEqual(self.notes, [])

    def test_clean_first_run_needs_no_retry_and_no_note(self):
        self.assertIsNone(self.fault([self.done()]))
        self.assertEqual(len(self.runs), 1)
        self.assertEqual(self.notes, [])


if __name__ == "__main__":
    unittest.main()
