#!/usr/bin/env python3
"""The host-runnable checks that are not unittest files, driven as subprocesses — so that

    python3 -m unittest discover -s test

is the entire host suite: these plus every test/test_*.py, in one command with one verdict.

Each target keeps its own entry point, because each is deliberately a different genre. The
rule engine's self-tests stay in `mitmaddon/rule_engine.py` — that in-file suite is why the
engine was the one component with tests and the one that worked — and `python3
mitmaddon/rule_engine.py` remains the contract; this file only drives it. `test/repro/` is
reproductions of documented findings, and inclusion here is a per-file decision, never a
glob: `engine_claims.py` and `build_injection.py` render verdicts and need only the host,
`git_profile_clone.sh` renders one in its `--static` half, while `addon_host_spoof.py`
(superseded by test_addon.py, prints without asserting), `connect_probe.sh` and
`host_spoof_live.sh` (both need a live proxy on :8099) stay out.

Every subprocess runs its file exactly as its own docstring documents, in a fresh
interpreter, so nothing here can be broken by — or break — the module-level state of the
other test files.

    python3 test/test_scripts.py [-v]
"""
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def run(*argv, env=None):
    return subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                          timeout=120, cwd=REPO, env=env)


class ScriptCase(unittest.TestCase):
    def assertExitsZero(self, done):
        self.assertEqual(done.returncode, 0,
                         f"\n--- stdout ---\n{done.stdout}--- stderr ---\n{done.stderr}")


class EngineSelfTests(ScriptCase):
    def test_rule_engine_module_runs_green(self):
        done = run(sys.executable, REPO / "mitmaddon" / "rule_engine.py")
        self.assertExitsZero(done)
        # exit 0 without a verdict line would mean the self-tests did not run at all
        self.assertRegex(done.stdout + done.stderr, r"\bpassed\b")


class ReproVerdicts(ScriptCase):
    def test_engine_findings_stay_fixed(self):
        """Exits non-zero if any documented rule-engine fix (FEEDBACK §7) regresses."""
        self.assertExitsZero(run(sys.executable, REPO / "test" / "repro" / "engine_claims.py"))

    def test_build_injection_stays_refused(self):
        """Drives the real CLI in subprocesses; exit 0 means every `--with`/`--base`
        injection attempt (FEEDBACK §5) is still refused at parse time."""
        self.assertExitsZero(run(sys.executable, REPO / "test" / "repro" / "build_injection.py"))

    def test_git_profile_rules_hold(self):
        """The static half of the §6 repro: profiles/git/rules.txt must parse to zero
        rules, and the composed github floor plus a github-read grant must match both
        smart-HTTP fetch phases and deny push. The live half needs msb and the network."""
        self.assertExitsZero(run("sh", REPO / "test" / "repro" / "git_profile_clone.sh",
                                 "--static"))


class ProfilesSnapshot(ScriptCase):
    """The sandboxed-agent skill ships PROFILES.txt, a committed copy of the `profiles`
    listing, so a planner reads it instead of shelling out to the CLI. This pins the
    copy: any byte of drift between the listing and the snapshot fails here."""

    SNAPSHOT = REPO / ".claude" / "skills" / "sandboxed-agent" / "PROFILES.txt"
    REGEN = "COLUMNS=80 ./cli/silkgate profiles > .claude/skills/sandboxed-agent/PROFILES.txt"

    def test_snapshot_matches_cli_listing(self):
        # COLUMNS pins the wrap width; without it the listing follows the terminal.
        done = run(sys.executable, REPO / "cli" / "silkgate", "profiles",
                   env={**os.environ, "COLUMNS": "80"})
        self.assertExitsZero(done)
        self.assertMultiLineEqual(
            done.stdout, self.SNAPSHOT.read_text(),
            f"PROFILES.txt drifted from the live listing — regenerate it:\n  {self.REGEN}")


class SyntaxGates(ScriptCase):
    """The in-guest script cannot execute on the host, but a file that does not even parse
    must fail here, not in a guest."""

    @unittest.skipUnless(shutil.which("bash"), "no bash on PATH")
    def test_verify_guest_parses(self):
        self.assertExitsZero(run("bash", "-n", REPO / "test" / "verify_guest.sh"))


if __name__ == "__main__":
    unittest.main()
