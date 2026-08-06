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
SUBJECTS = dict(sg._VERIFY_SUBJECTS)         # {id: the capability a guest may lack}
MAY_LACK = frozenset(SUBJECTS)

# Each check's block: its declaration line through to the next declaration (or EOF). Shell
# that belongs to no check lives above the first declaration and is not attributed to one.
_DECL = re.compile(r"^#\s*CHECK\s+(\d+)\s+tools:(\S+)", re.M)

# The subject declarations, read independently of the CLI so the two parses check each other.
_SUBJ = re.compile(r"^#\s*CHECK\s+(\d+)\s+tools:\S+\s+subject:(\S+)", re.M)
DECLARED_SUBJECTS = {int(n): s for n, s in _SUBJ.findall(TEXT)}

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
    def test_ran_skipped_and_unavailable(self):
        self.assertEqual(sg._parse_checks("CHECKS: ran=3,7 skipped=1,2 unavailable=5,11"),
                         ({3, 7}, {1, 2}, {5, 11}))

    def test_empty_fields(self):
        ran = ",".join(str(i) for i in sorted(ALL))
        self.assertEqual(sg._parse_checks(f"CHECKS: ran={ran} skipped= unavailable="),
                         (set(ALL), set(), set()))

    def test_empty_all_three(self):
        self.assertEqual(sg._parse_checks("CHECKS: ran= skipped= unavailable="),
                         (set(), set(), set()))

    def test_a_line_from_before_the_unavailable_field_still_parses(self):
        # older guests do not print the third field; they simply claimed nothing unavailable
        self.assertEqual(sg._parse_checks("CHECKS: ran=3,7 skipped=1,2"),
                         ({3, 7}, {1, 2}, set()))

    def test_order_is_immaterial(self):
        # the guest runs the two checks that reconfigure it last, so `ran` is not the run order
        ran, _, _ = sg._parse_checks("CHECKS: ran=10,3,7 skipped=")
        self.assertEqual(ran, {3, 7, 10})

    def test_two_digit_ids_are_not_split(self):
        ran, skipped, unavailable = sg._parse_checks("CHECKS: ran=1,12,15 skipped=13 "
                                                     "unavailable=11")
        self.assertEqual((ran, skipped, unavailable), ({1, 12, 15}, {13}, {11}))


class DerivedFromTheScript(unittest.TestCase):
    """The expected sets come out of verify_guest.sh, so this is where they are checked."""

    def test_the_cli_reads_every_declaration_in_the_script(self):
        self.assertEqual(ALL, frozenset(BLOCKS))
        self.assertEqual(FREE, frozenset(n for n, (tools, _) in BLOCKS.items()
                                        if tools == "none"))
        self.assertEqual(SUBJECTS, DECLARED_SUBJECTS)

    def test_a_subject_declaration_rides_a_known_check_and_names_something(self):
        self.assertLessEqual(MAY_LACK, ALL)
        for num, subject in sorted(SUBJECTS.items()):
            self.assertTrue(subject, f"check {num} declares an empty subject")

    def test_only_a_check_that_declares_a_subject_scores_unavailable(self):
        """The guest-side twin of _verify_shortfall's refusal: a U call appearing in a block
        whose declaration names no subject is the widening the host would reject at run
        time, so it fails here first."""
        scored_u = {int(n) for n in re.findall(r"[\s;)]U (\d+) ", TEXT)}
        self.assertEqual(scored_u, set(MAY_LACK))

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
                         (frozenset(), frozenset(), {}))

    def test_declarations_are_read_from_the_file_handed_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "fake.sh"
            fake.write_text("# CHECK 1 tools:none — a\n"
                            "# CHECK 2 tools:curl,dig — b\n"
                            "#CHECK 3 tools:none\n"
                            "# CHECK 4 tools: none — a space makes the tools field empty\n"
                            "# CHECK 5 tools:none subject:ipv6 — may find no subject\n"
                            "# CHECK 6 tools:none subject: — a space empties this one too\n")
            every, free, subjects = sg._declared_checks(fake)
        self.assertEqual(sorted(every), [1, 2, 3, 5, 6])
        self.assertEqual(sorted(free), [1, 3, 5, 6])
        self.assertEqual(subjects, {5: "ipv6"})


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


class UnavailableScoring(unittest.TestCase):
    """The fourth verdict as the host accepts it — and, mostly, as it refuses it.

    An unavailable check is excused from the expected set, so this is the easiest verdict in
    the contract to abuse: taken wholesale, `unavailable=1..15` from a guest that ran nothing
    would read as containment. It is therefore honoured only from the checks whose
    declarations say their subject can be absent, and everything else about the run is still
    demanded.
    """

    def test_a_full_run_whose_declared_subjects_are_absent_is_clean(self):
        ran = ALL - MAY_LACK
        self.assertIsNone(sg._verify_shortfall(len(ran), 0, set(ran), set(), set(MAY_LACK),
                                               full=True))

    def test_a_bare_run_whose_declared_subjects_are_absent_is_clean(self):
        ran = FREE - MAY_LACK
        self.assertIsNone(sg._verify_shortfall(len(ran), 0, set(ran), set(NEEDS_TOOLS),
                                               set(MAY_LACK), full=False))

    def test_the_linux_kvm_run_this_exists_for(self):
        """A --full run on a guest with a ::/0 route and no v6 source: 5 and 11 report their
        subject absent, 15 passes on its v4 sweep, nothing skips — and the run holds."""
        self.assertEqual({5, 11} & MAY_LACK, {5, 11},
                         "checks 5 and 11 must declare a subject a guest may lack")
        ran = ALL - {5, 11}
        self.assertIsNone(sg._verify_shortfall(len(ran), 0, set(ran), set(), {5, 11},
                                               full=True))

    def test_a_check_that_declares_no_subject_cannot_be_waved_off(self):
        one = min(ALL - MAY_LACK)
        bad = sg._verify_shortfall(len(ALL) - 1, 0, set(ALL) - {one}, set(), {one}, full=True)
        self.assertIsNotNone(bad)
        self.assertIn(f"check(s) {one}", bad)
        self.assertIn("could have run", bad)

    def test_a_run_that_excuses_everything_proves_nothing(self):
        # the wholesale abuse: nothing ran, nothing failed, everything "had no subject"
        bad = sg._verify_shortfall(0, 0, set(), set(), set(ALL), full=True)
        self.assertIsNotNone(bad)

    def test_a_check_cannot_both_run_and_have_had_no_subject(self):
        one = min(MAY_LACK)
        bad = sg._verify_shortfall(len(ALL), 0, set(ALL), set(), {one}, full=True)
        self.assertIsNotNone(bad)
        self.assertIn("disagrees", bad)

    def test_a_tool_absent_skip_under_full_still_fails(self):
        """Unavailability excuses nothing beyond itself: a --full run where a tool-gated
        check skipped is still refused, however honestly the v6 checks bowed out."""
        gated = min(NEEDS_TOOLS)
        ran = ALL - MAY_LACK - {gated}
        bad = sg._verify_shortfall(len(ran), 0, set(ran), {gated}, set(MAY_LACK), full=True)
        self.assertIsNotNone(bad)
        self.assertIn(f"check(s) {gated}", bad)
        self.assertIn("never ran", bad)

    def test_a_failure_still_wins_over_an_absent_subject(self):
        bad = sg._verify_shortfall(len(ALL) - 3, 1, set(ALL) - MAY_LACK, set(),
                                   set(MAY_LACK), full=True)
        self.assertIn("FAILED", bad)

    def test_a_checks_line_without_the_field_scores_exactly_as_before(self):
        self.assertIsNone(sg._verify_shortfall(len(ALL), 0, set(ALL), set(), full=True))


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
class V6Observations(unittest.TestCase):
    """has_v6_default / has_v6_global, run against measured copies of guest tables.

    The unavailable verdict turns on these two reads and never on an errno, so what counts
    as "no v6 here" is pinned: a ::/0 route in /proc/net/ipv6_route, and a scope-00 address
    in /proc/net/if_inet6. The fd42… fixture is a ULA, which the kernel scopes 00 — counting
    it can only hold a verdict at SKIP that might have been UNAVAILABLE, never the reverse,
    so the discriminator errs strict. The lines below were read out of a live guest.
    """

    DEFAULT_ROUTE = ("00000000000000000000000000000000 00 "
                     "00000000000000000000000000000000 00 "
                     "fd426d73006200ed0000000000000001 00000400 00000002 00000000 "
                     "00000003     eth0\n")
    HOST_ROUTE = ("fd426d73006200ed0000000000000002 80 "
                  "00000000000000000000000000000000 00 "
                  "00000000000000000000000000000000 00000000 00000003 00000000 "
                  "80200001     eth0\n")
    ULA = "fd426d73006200ed0000000000000002 02 40 00 80     eth0\n"       # scope 00
    LINKLOCAL = "fe80000000000000006d73fffe00ed02 02 40 20 80     eth0\n"  # scope 20
    LOOPBACK = "00000000000000000000000000000001 01 80 10 80       lo\n"   # scope 10

    @classmethod
    def setUpClass(cls):
        cls.fns = "\n".join(re.search(rf"(?m)^{name}\(\)\{{.*$", TEXT)[0]
                            for name in ("has_v6_default", "has_v6_global"))

    def holds(self, fn, content):
        with tempfile.TemporaryDirectory() as tmp:
            table = Path(tmp) / "table"
            if content is not None:
                table.write_text(content)
            out = subprocess.run(["bash", "-c", f'{self.fns}\n{fn} "$1"', "_", str(table)],
                                 capture_output=True, text=True, timeout=30)
        return out.returncode == 0

    def test_a_default_route_is_recognized(self):
        self.assertTrue(self.holds("has_v6_default", self.HOST_ROUTE + self.DEFAULT_ROUTE))

    def test_host_routes_alone_are_not_a_default(self):
        self.assertFalse(self.holds("has_v6_default", self.HOST_ROUTE))

    def test_a_global_scope_address_is_a_subject(self):
        self.assertTrue(self.holds("has_v6_global",
                                   self.LOOPBACK + self.LINKLOCAL + self.ULA))

    def test_link_local_and_loopback_are_not(self):
        self.assertFalse(self.holds("has_v6_global", self.LOOPBACK + self.LINKLOCAL))

    def test_an_empty_or_missing_table_is_no_subject(self):
        for fn in ("has_v6_default", "has_v6_global"):
            self.assertFalse(self.holds(fn, ""), fn)
            self.assertFalse(self.holds(fn, None), fn)


@unittest.skipUnless(shutil.which("bash"), "no bash on PATH")
class UnavailableComposition(unittest.TestCase):
    """The three sites that can find no subject, each run for real over stubbed observations.

    What is pinned is which way each site resolves an absent capability. Check 5 probes
    first wherever a route exists and reads its own address table only after the probe has
    DIED — a connect or a refusal is a boundary answer whatever the table says, and a dead
    probe on a guest that holds a source address stays a SKIP, because that shape is a
    broken probe until proven otherwise. Check 11 reads no errno at all: its unavailability
    comes from /etc/hosts and the address table, after the v4 half answered with the mark.
    Check 15 excludes the destination nothing could probe BEFORE probing, names it, and
    keeps the v4 sweep's verdict rather than surrendering eight denials to a whole-check
    waiver.
    """

    SCORERS = ('P(){ echo "P $1 $2"; }; F(){ echo "F $1 $2"; }; '
               'S(){ echo "S $1 $2"; }; U(){ echo "U $1 $2"; }')

    @classmethod
    def setUpClass(cls):
        cls.grade = re.search(r"^grade\(\)\{\n.*?^\}$", TEXT, re.M | re.S)[0]
        cls.sweep_verdict = re.search(r"^sweep_verdict\(\)\{\n.*?^\}$", TEXT, re.M | re.S)[0]

    def run_block(self, num, *parts):
        script = "\n".join((self.SCORERS,) + parts + (BLOCKS[num][1],))
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                             timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        m = re.search(rf"(?m)^([PFSU]) {num} (.*)$", out.stdout)
        self.assertIsNotNone(m, out.stdout)
        return m[1], m[2]

    def check5(self, v6_default, v6_global, tcp_how, mech=1):
        return self.run_block(
            5, self.grade,
            f"mech={mech}; T=5; manner=refuse; manner_ms=1",
            f"has_v6_default(){{ {v6_default}; }}",
            f"has_v6_global(){{ {v6_global}; }}",
            f'tcp(){{ tcp_how={tcp_how}; tcp_ms=1; tcp_errno="probe errno"; '
            '[ "$tcp_how" = connected ]; }')

    def test_check5_no_route_is_unavailable(self):
        verdict, why = self.check5("false", "false", "dead")
        self.assertEqual(verdict, "U")
        self.assertIn("no ::/0 route", why)

    def test_check5_dead_probe_with_no_source_address_is_unavailable(self):
        verdict, why = self.check5("true", "false", "dead")
        self.assertEqual(verdict, "U")
        self.assertIn("no global-scope address", why)

    def test_check5_dead_probe_that_could_have_worked_still_skips(self):
        # the same errno with a source address present is a broken probe, not a platform
        verdict, why = self.check5("true", "true", "dead")
        self.assertEqual(verdict, "S")
        self.assertIn("proves nothing", why)

    def test_check5_the_boundary_outranks_the_table(self):
        # the probe runs first: whatever the address table claims, a completed handshake is
        # a leak and a refusal is containment
        self.assertEqual(self.check5("true", "false", "connected")[0], "F")
        self.assertEqual(self.check5("true", "false", "refused")[0], "P")

    def test_check5_silence_never_reads_as_unavailable(self):
        verdict, why = self.check5("true", "false", "silent")
        self.assertEqual(verdict, "S")

    def test_check5_a_dead_control_still_skips(self):
        self.assertEqual(self.check5("false", "false", "dead", mech=0)[0], "S")

    V4ONLY = "172.16.3.181\thost.microsandbox.internal\n127.0.0.1\tlocalhost\n"
    BOTH = V4ONLY + "fd42:6d73:62:ed::1\thost.microsandbox.internal\n"

    def check11(self, hosts, v6_default, v6_global, control_rc=0):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "hosts"
            fake.write_text(hosts)
            block = BLOCKS[11][1].replace("/etc/hosts", str(fake))
            script = "\n".join((
                self.SCORERS,
                "phost=host.microsandbox.internal; pport=8090",
                f"has_v6_default(){{ {v6_default}; }}",
                f"has_v6_global(){{ {v6_global}; }}",
                f"control_rc(){{ return {control_rc}; }}",
                block))
            out = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                 timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        m = re.search(r"(?m)^([PFSU]) 11 (.*)$", out.stdout)
        self.assertIsNotNone(m, out.stdout)
        return m[1], m[2]

    def test_check11_both_families_answering_pass(self):
        self.assertEqual(self.check11(self.BOTH, "true", "true")[0], "P")

    def test_check11_v4_only_mapping_with_no_v6_source_is_unavailable(self):
        verdict, why = self.check11(self.V4ONLY, "true", "false")
        self.assertEqual(verdict, "U")
        self.assertIn("no subject", why)

    def test_check11_v4_only_mapping_on_a_v6_capable_guest_still_skips(self):
        # the platform withheld a subject this guest could have used: an alarm, not a waiver
        verdict, why = self.check11(self.V4ONLY, "true", "true")
        self.assertEqual(verdict, "S")
        self.assertIn("would not be caught", why)

    def test_check11_no_route_and_no_mapping_still_passes(self):
        # long-standing behavior, kept: no route means v4 is every address there is
        self.assertEqual(self.check11(self.V4ONLY, "false", "false")[0], "P")

    def test_check11_a_dead_family_outranks_an_absent_one(self):
        self.assertEqual(self.check11(self.V4ONLY, "true", "false", control_rc=1)[0], "F")

    def test_check11_an_unmarked_answer_outranks_an_absent_subject(self):
        # something answered without X-Silkgate: deny: attribution fails first, and no
        # missing capability may talk that back down to "nothing to test"
        verdict, why = self.check11(self.V4ONLY, "true", "false", control_rc=2)
        self.assertEqual(verdict, "S")
        self.assertIn("cannot be attributed", why)

    def check15(self, v6_default, v6_global, mech=1):
        return self.run_block(
            15, self.sweep_verdict,
            f"mech={mech}; T=5; manner=refuse",
            f"has_v6_default(){{ {v6_default}; }}",
            f"has_v6_global(){{ {v6_global}; }}",
            'sweep(){ shift; sw_hit=""; sw_ref=" $*"; sw_dead=""; sw_silent=""; '
            'sw_left=""; }')

    def test_check15_sweeps_v6_where_the_guest_can_source_it(self):
        verdict, why = self.check15("true", "true")
        self.assertEqual(verdict, "P")
        self.assertIn("2001:db8::1/443", why)
        self.assertNotIn("not probed", why)

    def test_check15_excludes_and_names_what_nothing_could_probe(self):
        for v6_default, v6_global in (("true", "false"), ("false", "false")):
            verdict, why = self.check15(v6_default, v6_global)
            self.assertEqual(verdict, "P", why)
            self.assertNotIn("2001:db8::1/443", why)
            self.assertIn("2001:db8::1:443 not probed", why)

    def test_check15_a_dead_control_still_skips(self):
        self.assertEqual(self.check15("true", "true", mech=0)[0], "S")


@unittest.skipUnless(shutil.which("bash"), "no bash on PATH")
class BookkeepingLines(unittest.TestCase):
    """The script's own tail — the lines the caller parses — over synthetic tallies."""

    @classmethod
    def setUpClass(cls):
        cls.sortnum = re.search(r"^sortnum\(\)\{\n.*?^\}$", TEXT, re.M | re.S)[0]
        cls.tail = TEXT[TEXT.index('echo "CHECKS: ran='):]

    def run_tail(self, passed, failed, ran, skipped, unavail):
        script = (f'{self.sortnum}\npass={passed}; fail={failed}; ran="{ran}"; '
                  f'skipped="{skipped}"; unavail="{unavail}"\n{self.tail}')
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                             timeout=30)
        return out.stdout, out.returncode

    def test_a_clean_run_claims_containment(self):
        stdout, rc = self.run_tail(3, 0, ",1,2,3", "", "")
        self.assertIn("CHECKS: ran=1,2,3 skipped= unavailable=\n", stdout)
        self.assertIn("Containment holds: every check ran", stdout)
        self.assertEqual(rc, 0)

    def test_absent_subjects_are_named_not_hidden(self):
        stdout, rc = self.run_tail(2, 0, ",1,3", "", ",11,5")
        self.assertIn("CHECKS: ran=1,3 skipped= unavailable=5,11\n", stdout)
        self.assertIn("check(s) 5,11 found", stdout)
        self.assertIn("nothing here to test", stdout)
        self.assertEqual(rc, 0)

    def test_a_skip_still_defers_to_the_host(self):
        stdout, rc = self.run_tail(2, 0, ",1,3", ",2", ",5")
        self.assertIn("silkgate verify decides", stdout)
        self.assertEqual(rc, 0)

    def test_a_failure_is_still_a_leak(self):
        stdout, rc = self.run_tail(2, 1, ",1,2,3", "", ",5")
        self.assertIn("LEAK", stdout)
        self.assertEqual(rc, 1)

    def test_the_checks_line_round_trips_through_the_cli(self):
        stdout, _ = self.run_tail(2, 0, ",12,3", ",6", ",5,11")
        line = next(l for l in stdout.splitlines() if l.startswith("CHECKS:"))
        self.assertEqual(sg._parse_checks(line), ({3, 12}, {6}, {5, 11}))


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

    def test_a_dead_probe_alone_never_reads_as_unavailable(self):
        """Check 5 may downgrade a dead probe to UNAVAILABLE only against its own address
        table, and only for `dead` — never for silent, unknown, or a mannered skip. The
        guard is one literal branch, so it is pinned as one."""
        self.assertIn('[ "$dv" = s ] && [ "$tcp_how" = dead ] && ! has_v6_global', TEXT)

    def test_port_53_is_never_swept_as_a_host_port(self):
        """msb's stub answers on 53 for every destination, so a sweep containing it reports a
        leak on a healthy guest — `verify --port 52` computed alt=53 and did exactly that."""
        self.assertIn('[ "$alt" = 53 ] && alt=$((pport - 1))', TEXT)
        self.assertIn('[ "$n" != 53 ]', TEXT)


if __name__ == "__main__":
    unittest.main()
