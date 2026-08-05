#!/usr/bin/env python3
"""Unit tests for the pure verify logic in cli/silkgate.

    python3 test/test_verify_checks.py [-v]

`cmd_verify` renders its verdict from two guest-printed lines — `CHECKS: ran=… skipped=…`
and `RESULT: N passed, M failed` — through two pure functions: `_parse_checks` and
`_verify_shortfall`. CI's containment job and the README both lean on that contract, so
the parsing and the expected-set decision are pinned here, host-side, with no proxy, no
guest and no msb. What the guest script actually prints is the guest script's business;
nothing here greps a shell file for strings.

`cli/silkgate` has no .py suffix, so it is loaded through a SourceFileLoader. Importing
it has no side effects on disk, and these tests touch none of its state paths.
"""
import importlib.machinery
import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load_cli():
    loader = importlib.machinery.SourceFileLoader("silkgate_cli", str(REPO / "cli" / "silkgate"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


sg = _load_cli()

ALL = set(range(1, 12))


class ParseChecks(unittest.TestCase):
    def test_ran_and_skipped(self):
        self.assertEqual(sg._parse_checks("CHECKS: ran=3,7 skipped=1,2"), ({3, 7}, {1, 2}))

    def test_empty_skipped(self):
        ran, skipped = sg._parse_checks("CHECKS: ran=1,2,3,4,5,6,7,8,9,10,11 skipped=")
        self.assertEqual(ran, ALL)
        self.assertEqual(skipped, set())

    def test_empty_both(self):
        self.assertEqual(sg._parse_checks("CHECKS: ran= skipped="), (set(), set()))

    def test_order_is_immaterial(self):
        ran, _ = sg._parse_checks("CHECKS: ran=10,3,7 skipped=")
        self.assertEqual(ran, {3, 7, 10})


class ExpectedSets(unittest.TestCase):
    """The decision `--full` and bare runs are held to, as behavior, not as constants."""

    def test_full_run_of_all_eleven_is_clean(self):
        self.assertIsNone(sg._verify_shortfall(11, 0, ALL, set(), full=True))

    def test_bare_run_of_the_tool_free_five_is_clean(self):
        tool_free = {3, 7, 9, 10, 11}
        self.assertIsNone(sg._verify_shortfall(5, 0, tool_free, ALL - tool_free, full=False))

    def test_bare_run_of_only_3_and_7_is_no_longer_enough(self):
        bad = sg._verify_shortfall(2, 0, {3, 7}, set(), full=False)
        self.assertIsNotNone(bad)
        self.assertIn("9, 10, 11", bad)

    def test_full_run_missing_one_check_names_it(self):
        ran = ALL - {8}
        bad = sg._verify_shortfall(10, 0, ran, {8}, full=True)
        self.assertIsNotNone(bad)
        self.assertIn("check(s) 8", bad)
        self.assertIn("never ran", bad)

    def test_full_run_where_only_passes_were_counted_is_not_containment(self):
        # the original defect: five skips and two passes, zero failures
        bad = sg._verify_shortfall(2, 0, {3, 7}, ALL - {3, 7}, full=True)
        self.assertIsNotNone(bad)
        self.assertIn("never ran", bad)

    def test_tool_free_is_a_subset_of_the_full_set(self):
        self.assertLessEqual(sg._VERIFY_TOOL_FREE, sg._VERIFY_CHECKS)


class Shortfall(unittest.TestCase):
    def test_any_failure_wins_over_everything(self):
        bad = sg._verify_shortfall(10, 1, ALL, set(), full=True)
        self.assertIsNotNone(bad)
        self.assertIn("FAILED", bad)

    def test_pass_count_must_match_the_ran_set(self):
        bad = sg._verify_shortfall(10, 0, ALL, set(), full=True)
        self.assertIsNotNone(bad)
        self.assertIn("disagrees", bad)

    def test_extra_checks_beyond_the_expected_set_are_fine(self):
        # a bare run where the image happened to carry every tool
        self.assertIsNone(sg._verify_shortfall(11, 0, ALL, set(), full=False))


if __name__ == "__main__":
    unittest.main()
