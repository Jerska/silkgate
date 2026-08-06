#!/usr/bin/env python3
"""Unit tests for the verify contract: the pure logic in cli/silkgate, and the two things in
test/verify_guest.sh that decide what that logic is asked about.

    python3 test/test_verify_checks.py [-v]

`cmd_verify` renders its verdict from two guest-printed lines — `CHECKS: ran=… skipped=…`
and `RESULT: N passed, M failed` — through two pure functions: `_parse_checks` and
`_verify_shortfall`. CI's containment job and the README both lean on that contract, so the
parsing and the expected-set decision are pinned here, host-side, with no proxy, no guest and
no msb.

What is new here is that the *expected set itself* is now under test rather than restated.
`_VERIFY_CHECKS` and `_VERIFY_TOOL_FREE` are read out of `verify_guest.sh`'s `# CHECK n
tools:…` declarations, so the tests below check three joints instead of one:

  * the CLI parses those declarations the way the script writes them,
  * each declaration agrees with the `have <tool>` gates in its own check's block — a check
    that says `tools:none` and then skips without `dig` is the exact defect that shipped a
    documented `silkgate verify` which could not pass, and
  * the scoring decisions hold *for the derived sets*, whatever they currently are.

`ClassifyDiscriminator` goes one step further and executes shell: the deny half of the guest
script turns entirely on one function, `classify RC TEXT`, and a discriminator nobody has
seen make a distinction is not known to make one. The function is lifted out of the script by
regex and run under bash against errno strings measured in a real microsandbox guest, so this
file can fail when the classification is wrong without needing a second, deliberately-leaking
sandbox to point it at.

`cli/silkgate` has no .py suffix, so it is loaded through a SourceFileLoader. Importing it has
no side effects on disk, and these tests touch none of its state paths.
"""
import importlib.machinery
import importlib.util
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "test" / "verify_guest.sh"


def _load_cli():
    loader = importlib.machinery.SourceFileLoader("silkgate_cli", str(REPO / "cli" / "silkgate"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


sg = _load_cli()
TEXT = SCRIPT.read_text()

ALL = frozenset(sg._VERIFY_CHECKS)
FREE = frozenset(sg._VERIFY_TOOL_FREE)
NEEDS_TOOLS = ALL - FREE

# Each check's block: its declaration line through to the next declaration (or EOF). Shell
# that belongs to no check lives above the first declaration and is not attributed to one.
_DECL = re.compile(r"^#\s*CHECK\s+(\d+)\s+tools:(\S+)", re.M)

# `have <tool>` in command position — after a line start, a `;`/`|`/`&`/`!`, or one of the
# keywords that opens a command. Anchoring it matters: this script's prose says "would have
# been" and "can only have been", and a gate is code, not English.
_GATE = re.compile(r"(?m)(?:^[ \t]*|[;&|!][ \t]*|\b(?:if|elif|then|else|do)[ \t]+)"
                   r"(?:!\s*)?have[ \t]+([A-Za-z0-9_.+-]+)")


def _gates(block):
    """The tools a block actually refuses to run without."""
    code = "\n".join(l for l in block.splitlines() if not l.lstrip().startswith("#"))
    return set(_GATE.findall(code))


def _blocks():
    marks = [(m.start(), int(m[1]), m[2]) for m in _DECL.finditer(TEXT)]
    out = {}
    for i, (start, num, tools) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(TEXT)
        out[num] = (tools, TEXT[start:end])
    return out


BLOCKS = _blocks()


class ParseChecks(unittest.TestCase):
    def test_ran_and_skipped(self):
        self.assertEqual(sg._parse_checks("CHECKS: ran=3,7 skipped=1,2"), ({3, 7}, {1, 2}))

    def test_empty_skipped(self):
        ran = ",".join(str(i) for i in sorted(ALL))
        self.assertEqual(sg._parse_checks(f"CHECKS: ran={ran} skipped="), (set(ALL), set()))

    def test_empty_both(self):
        self.assertEqual(sg._parse_checks("CHECKS: ran= skipped="), (set(), set()))

    def test_order_is_immaterial(self):
        # the guest runs the two checks that reconfigure it last, so `ran` is not the run order
        ran, _ = sg._parse_checks("CHECKS: ran=10,3,7 skipped=")
        self.assertEqual(ran, {3, 7, 10})

    def test_two_digit_ids_are_not_split(self):
        ran, skipped = sg._parse_checks("CHECKS: ran=1,12,15 skipped=13")
        self.assertEqual((ran, skipped), ({1, 12, 15}, {13}))


class DerivedFromTheScript(unittest.TestCase):
    """The expected sets come out of verify_guest.sh, so this is where they are checked."""

    def test_the_cli_reads_every_declaration_in_the_script(self):
        self.assertEqual(ALL, frozenset(BLOCKS))
        self.assertEqual(FREE, frozenset(n for n, (tools, _) in BLOCKS.items()
                                        if tools == "none"))

    def test_ids_are_contiguous_from_one(self):
        self.assertEqual(sorted(ALL), list(range(1, len(ALL) + 1)),
                         "a gap or a duplicate in the CHECK declarations")

    def test_both_sets_are_non_empty_and_nest(self):
        self.assertTrue(FREE, "no check runs on a bare image, so `silkgate verify` cannot pass")
        self.assertTrue(NEEDS_TOOLS, "--full would then be indistinguishable from a bare run")
        self.assertLessEqual(FREE, ALL)

    def test_declared_tools_are_exactly_the_gates_in_the_block(self):
        """`tools:` is the single source of truth, so it must match the code it describes.

        This is the assertion that would have caught the shipped regression: check 7 was
        called tool-free in the CLI while its block began `if ! have ip; then S 7 …`.
        """
        for num, (tools, block) in sorted(BLOCKS.items()):
            declared = set() if tools == "none" else set(tools.split(","))
            gated = _gates(block)
            self.assertEqual(declared, gated,
                             f"check {num} declares tools:{tools} but gates on {sorted(gated)}")

    def test_a_tool_free_check_never_gates_on_an_installed_tool(self):
        """Said the other way round, because this is the direction that breaks `verify`: a
        check the CLI will demand of a bare debian image must not be able to skip on one."""
        for num in sorted(FREE):
            self.assertEqual(_gates(BLOCKS[num][1]), set(),
                             f"check {num} is in the bare run but tests for a tool")

    def test_every_declared_check_scores_itself_in_its_own_block(self):
        for num, (_, block) in sorted(BLOCKS.items()):
            self.assertRegex(block, rf"[\s;)][PFS] {num} ",
                             f"check {num} declares itself but never calls P/F/S {num}")

    def test_nothing_scores_a_check_that_was_never_declared(self):
        scored = {int(n) for n in re.findall(r"[\s;)][PFS] (\d+) ", TEXT)}
        self.assertEqual(scored, set(ALL))

    def test_an_unreadable_script_leaves_no_expected_set(self):
        self.assertEqual(sg._declared_checks(Path("/nonexistent/verify_guest.sh")),
                         (frozenset(), frozenset()))

    def test_declarations_are_read_from_the_file_handed_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "fake.sh"
            fake.write_text("# CHECK 1 tools:none — a\n"
                            "# CHECK 2 tools:curl,dig — b\n"
                            "#CHECK 3 tools:none\n"
                            "# CHECK 4 tools: none — a space makes the tools field empty\n")
            every, free = sg._declared_checks(fake)
        self.assertEqual(sorted(every), [1, 2, 3])
        self.assertEqual(sorted(free), [1, 3])


class ExpectedSets(unittest.TestCase):
    """The decision `--full` and bare runs are held to, as behavior, not as constants."""

    def test_full_run_of_every_check_is_clean(self):
        self.assertIsNone(sg._verify_shortfall(len(ALL), 0, set(ALL), set(), full=True))

    def test_bare_run_of_the_tool_free_checks_is_clean(self):
        self.assertIsNone(sg._verify_shortfall(len(FREE), 0, set(FREE), set(NEEDS_TOOLS),
                                              full=False))

    def test_a_bare_run_missing_one_tool_free_check_names_it(self):
        one = min(FREE)
        bad = sg._verify_shortfall(len(FREE) - 1, 0, FREE - {one}, NEEDS_TOOLS | {one},
                                   full=False)
        self.assertIsNotNone(bad)
        self.assertIn(f"check(s) {one}", bad)
        self.assertIn("never ran", bad)

    def test_a_bare_run_of_only_the_tool_gated_checks_is_not_enough(self):
        bad = sg._verify_shortfall(len(NEEDS_TOOLS), 0, set(NEEDS_TOOLS), set(FREE), full=False)
        self.assertIsNotNone(bad)
        for missing in FREE:
            self.assertIn(str(missing), bad)

    def test_full_run_missing_one_check_names_it(self):
        one = max(ALL)
        bad = sg._verify_shortfall(len(ALL) - 1, 0, ALL - {one}, {one}, full=True)
        self.assertIsNotNone(bad)
        self.assertIn(f"check(s) {one}", bad)
        self.assertIn("never ran", bad)

    def test_full_run_where_only_passes_were_counted_is_not_containment(self):
        # the original defect: mostly skips and a couple of passes, zero failures
        two = set(sorted(ALL)[:2])
        bad = sg._verify_shortfall(2, 0, two, ALL - two, full=True)
        self.assertIsNotNone(bad)
        self.assertIn("never ran", bad)

    def test_a_bare_run_that_skipped_a_tool_free_check_does_not_blame_a_tool(self):
        """The wrong hint sent a reader looking for a missing package for a whole release."""
        one = min(FREE)
        bad = sg._verify_shortfall(len(FREE) - 1, 0, FREE - {one}, {one}, full=False)
        self.assertIn("tools:none", bad)
        self.assertNotIn("--full installs", bad)

    def test_tool_free_is_a_subset_of_the_full_set(self):
        self.assertLessEqual(sg._VERIFY_TOOL_FREE, sg._VERIFY_CHECKS)


class NoExpectedSetAtAll(unittest.TestCase):
    """If the declarations cannot be read, the run is refused rather than blessed."""

    def setUp(self):
        self.saved = (sg._VERIFY_CHECKS, sg._VERIFY_TOOL_FREE)
        sg._VERIFY_CHECKS = sg._VERIFY_TOOL_FREE = frozenset()

    def tearDown(self):
        sg._VERIFY_CHECKS, sg._VERIFY_TOOL_FREE = self.saved

    def test_a_perfect_looking_run_is_still_refused(self):
        for full in (False, True):
            bad = sg._verify_shortfall(11, 0, set(range(1, 12)), set(), full=full)
            self.assertIsNotNone(bad)
            self.assertIn("CHECK", bad)

    def test_a_failure_is_still_reported_as_a_failure(self):
        self.assertIn("FAILED", sg._verify_shortfall(10, 1, set(range(1, 12)), set(), full=True))


class Shortfall(unittest.TestCase):
    def test_any_failure_wins_over_everything(self):
        bad = sg._verify_shortfall(len(ALL) - 1, 1, set(ALL), set(), full=True)
        self.assertIsNotNone(bad)
        self.assertIn("FAILED", bad)

    def test_pass_count_must_match_the_ran_set(self):
        bad = sg._verify_shortfall(len(ALL) - 1, 0, set(ALL), set(), full=True)
        self.assertIsNotNone(bad)
        self.assertIn("disagrees", bad)

    def test_extra_checks_beyond_the_expected_set_are_fine(self):
        # a bare run where the image happened to carry every tool
        self.assertIsNone(sg._verify_shortfall(len(ALL), 0, set(ALL), set(), full=False))


@unittest.skipUnless(shutil.which("bash"), "no bash on PATH")
class ClassifyDiscriminator(unittest.TestCase):
    """`classify RC TEXT`, lifted out of the guest script and run for real.

    Every blocked-direction check reads its verdict from this function, so the strings below
    are the ones measured inside a microsandbox guest (msb 0.5.4, arm64, bash 5.2, LC_ALL=C):
    a policy denial arrives as `Connection refused` in about a millisecond, while a guest
    whose own stack has nowhere to send the packet gets `Network is unreachable` — and before
    this function existed both were exit 1 and both scored PASS.
    """

    @classmethod
    def setUpClass(cls):
        m = re.search(r"^classify\(\)\{\n.*?^\}$", TEXT, re.M | re.S)
        assert m, "classify() is not in verify_guest.sh in a form this test can lift out"
        cls.fn = m[0]

    def classify(self, rc, text):
        out = subprocess.run(["bash", "-c", f'{self.fn}\nclassify "$1" "$2"', "_", str(rc), text],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def test_a_policy_refusal_is_evidence(self):
        for text in ("bash: connect: Connection refused\n"
                     "bash: line 1: /dev/tcp/1.1.1.1/443: Connection refused",
                     "bash: connect: Connection reset by peer",
                     "* connect to 1.1.1.1 port 443 failed: Connection refused"):
            self.assertEqual(self.classify(1, text), "refused", text)

    def test_the_guests_own_dead_end_is_not_evidence(self):
        for text in ("bash: connect: Network is unreachable",              # 255.255.255.255
                     "bash: line 1: /dev/tcp/fe80::1/80: Invalid argument",  # v6 link-local, no scope
                     "bash: line 1: no-such.invalid: Temporary failure in name resolution",
                     "curl: (45) bind failed with errno 99: Cannot assign requested address",
                     "bash: connect: Permission denied",
                     "bash: connect: No route to host"):
            self.assertEqual(self.classify(1, text), "dead", text)

    def test_a_completed_handshake_is_never_talked_down(self):
        self.assertEqual(self.classify(0, ""), "connected")
        # a future bash that chattered about a refusal on a *successful* connect must not turn
        # a leak into a pass — the exit code decides this one, before any text is read
        self.assertEqual(self.classify(0, "bash: connect: Connection refused"), "connected")

    def test_a_name_resolving_to_two_families_needs_only_one_policy_answer(self):
        """/dev/tcp walks every getaddrinfo result and prints a line per attempt, so a sweep of
        the host by name gets one message per family. A family the guest cannot reach is not a
        channel; a family the boundary refused is the answer. So a refusal anywhere outranks a
        dead end, whichever order the two arrived in."""
        for text in ("bash: connect: Network is unreachable\n"
                     "bash: connect: Connection refused\n"
                     "bash: line 1: /dev/tcp/host.microsandbox.internal/22: Connection refused",
                     "bash: connect: Connection refused\n"
                     "bash: connect: Network is unreachable\n"
                     "bash: line 1: /dev/tcp/host.microsandbox.internal/22: Network is unreachable"):
            self.assertEqual(self.classify(1, text), "refused", text)

    def test_a_timeout_is_silence_and_nothing_more(self):
        self.assertEqual(self.classify(124, ""), "silent")

    def test_an_unrecognized_failure_is_not_quietly_a_refusal(self):
        for rc, text in ((1, ""), (1, "bash: connect: Some errno from 2031"),
                         (124, "half a message"), (2, "usage: bash [options]")):
            self.assertEqual(self.classify(rc, text), "unknown", text)


@unittest.skipUnless(shutil.which("bash"), "no bash on PATH")
class GradeVerdicts(unittest.TestCase):
    """`grade`, the other half of the deny side: classification -> PASS / FAIL / SKIP.

    The `silent` row is why this is tested here rather than in a guest. Its verdict depends on
    control 0b — whether this boundary was seen to REFUSE a TEST-NET destination or to drop it
    — and a guest whose boundary refuses cannot produce the dropping case to check. So the
    table is exercised directly, with $manner set both ways.
    """

    @classmethod
    def setUpClass(cls):
        cls.fn = re.search(r"^grade\(\)\{\n.*?^\}$", TEXT, re.M | re.S)[0]

    def grade(self, how, manner):
        script = (f'{self.fn}\ntcp_how={how}; tcp_ms=1; tcp_errno=probe; manner={manner}; T=5\n'
                  'grade "a probe"; printf "%s|%s" "$dv" "$dw"')
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        verdict, _, why = out.stdout.partition("|")
        return verdict, why

    def test_a_completed_handshake_always_fails_the_check(self):
        for manner in ("refuse", "drop", "open", "unknown"):
            self.assertEqual(self.grade("connected", manner)[0], "f", manner)

    def test_a_refusal_always_passes_it(self):
        for manner in ("refuse", "drop", "open", "unknown"):
            self.assertEqual(self.grade("refused", manner)[0], "p", manner)

    def test_silence_passes_only_where_this_boundary_was_seen_to_drop(self):
        self.assertEqual(self.grade("silent", "drop")[0], "p")
        for manner in ("refuse", "open", "unknown"):
            verdict, why = self.grade("silent", manner)
            self.assertEqual(verdict, "s", manner)
            self.assertIn("proves nothing", why)

    def test_a_probe_that_never_left_the_guest_can_never_pass(self):
        for how in ("dead", "unknown", "something_new"):
            for manner in ("refuse", "drop"):
                self.assertEqual(self.grade(how, manner)[0], "s", (how, manner))


@unittest.skipUnless(shutil.which("bash"), "no bash on PATH")
class ScriptShape(unittest.TestCase):
    def test_it_parses(self):
        out = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_the_two_lines_the_host_parses_are_emitted_unconditionally(self):
        """Neither may sit inside a conditional: a guest that prints no RESULT line makes
        `cmd_verify` die, which is right, but it must not be reachable by a check failing."""
        for literal in ('echo "CHECKS: ran=', 'echo "RESULT: $pass passed, $fail failed"'):
            self.assertIn(literal, TEXT)
        tail = TEXT[TEXT.index('echo "CHECKS: ran='):]
        self.assertNotIn("\nfi", tail.split('echo "RESULT:')[0])

    def test_port_53_is_never_swept_as_a_host_port(self):
        """msb's stub answers on 53 for every destination, so a sweep containing it reports a
        leak on a healthy guest — `verify --port 52` computed alt=53 and did exactly that."""
        self.assertIn('[ "$alt" = 53 ] && alt=$((pport - 1))', TEXT)
        self.assertIn('[ "$n" != 53 ]', TEXT)


if __name__ == "__main__":
    unittest.main()
