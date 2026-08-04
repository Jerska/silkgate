#!/usr/bin/env python3
"""Unit tests for the input validation and guards in cli/silkgate.

    python3 test/test_cli_validation.py [-v]

Stdlib only, and no docker/msb/mitmproxy: every check here is about what the CLI refuses
before it starts anything. `cli/silkgate` has no .py suffix, so it is loaded through a
SourceFileLoader — importing it has no side effects on disk, but its state paths are
derived from $HOME at import time, so they are repointed at a scratch directory below
before any test runs. Nothing here may touch a real ~/.silkgate: live sessions use it.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent


def _load_cli():
    loader = importlib.machinery.SourceFileLoader("silkgate_cli", str(REPO / "cli" / "silkgate"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


sg = _load_cli()

# Everything the CLI would write lives under one scratch tree for the whole run.
_SCRATCH = Path(tempfile.mkdtemp(prefix="silkgate-tests-"))
sg.SILK_DIR = _SCRATCH / "silkgate"
sg.SESSIONS_DIR = sg.SILK_DIR / "sessions"
sg.LOG_DIR = sg.SILK_DIR / "logs"
sg.CA_DIR = sg.SILK_DIR / "ca"
sg.DOCKER_CFG_DIR = sg.SILK_DIR / "docker"
sg.PROXY_JSON = sg.SILK_DIR / "proxy.json"
sg.PROXY_SOCK = sg.SILK_DIR / "proxy.sock"


def tearDownModule():
    shutil.rmtree(_SCRATCH, ignore_errors=True)


class CliCase(unittest.TestCase):
    """Shared assertions. die() exits non-zero after printing one line to stderr."""

    def setUp(self):
        self.assertTrue(str(sg.SESSIONS_DIR).startswith(str(_SCRATCH)),
                        "tests must never point at a real ~/.silkgate")
        # Resolved, because _workspace_mount resolves what it is given and macOS hands out
        # temp paths under /var, which is a symlink to /private/var.
        self.tmp = Path(tempfile.mkdtemp(dir=_SCRATCH)).resolve()

    def refuses(self, needle, fn, *args, **kwargs):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            fn(*args, **kwargs)
        self.assertNotEqual(caught.exception.code, 0)
        self.assertIn(needle, err.getvalue())
        return err.getvalue()

    def refuses_argv(self, needle, flag, argv):
        err = io.StringIO()
        with mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            sg.main()
        self.assertEqual(caught.exception.code, 2)          # argparse usage error
        self.assertIn(needle, err.getvalue())
        self.assertIn(flag, err.getvalue())                 # the message names the flag


class TestBuildArguments(CliCase):
    """Finding 5: a version and a base image reach a generated Dockerfile that docker
    builds as root on the host, outside the proxy."""

    GOOD_VERSIONS = ["22.11.0", "3.12.7", "2.1.89", "1", "v1.2.3-rc1", "1.0.0+build.5", "a_b"]
    BAD_VERSIONS = ['1" ; echo PWNED-AT-BUILD-TIME ; #', "1$(id)", "1`id`", "1;id", "1 2",
                    "1\nRUN echo x", "-1", ".1", "", "1" * 65, "1&&id", "1|id", "1'x'"]

    def test_version_charset(self):
        for version in self.GOOD_VERSIONS:
            self.assertIsNone(sg._version_error(version), version)
        for version in self.BAD_VERSIONS:
            self.assertIsNotNone(sg._version_error(version), version)

    def test_image_charset(self):
        for ref in ["debian:bookworm-slim", "silkgate/node-claude:f357122f17de",
                    "localhost:5000/x/y:1.2", "debian@sha256:" + "a" * 64]:
            self.assertIsNone(sg._image_error(ref), ref)
        for ref in ["debian:bookworm-slim\nRUN echo INJECTED-DIRECTIVE", "debian bookworm",
                    "-x", "", "deb$(id)", "deb;id", "deb\rian", "x" * 300]:
            self.assertIsNotNone(sg._image_error(ref), ref)

    def test_profile_rejects_injected_version(self):
        self.assertEqual(sg.Profile("node", "22.11.0").version, "22.11.0")
        self.refuses("invalid version", sg.Profile, "node",
                     '1" ; echo PWNED-AT-BUILD-TIME ; #')

    def test_profile_default_version_is_checked_too(self):
        for profile in ("node", "python", "claude"):
            version = sg.Profile(profile).version
            self.assertIsNone(sg._version_error(version), f"{profile} default_version")

    def test_parse_time_errors_name_the_flag(self):
        self.refuses_argv("invalid version", "--with",
                          ["build", "--with", 'node@1" ; echo PWNED-AT-BUILD-TIME ; #'])
        self.refuses_argv("empty version", "--with", ["build", "--with", "node@"])
        self.refuses_argv("invalid image reference", "--base",
                          ["build", "--base", "debian:bookworm-slim\nRUN echo INJECTED"])
        self.refuses_argv("invalid image reference", "--image",
                          ["up", "--image=silkgate/x:1\nRUN echo INJECTED"])

    def test_valid_spec_survives_parsing(self):
        self.assertEqual(sg._with_arg("node@22.11.0"), "node@22.11.0")
        self.assertEqual(sg._with_arg("claude"), "claude")
        self.assertEqual(sg._image_arg(sg.BASE_IMAGE), sg.BASE_IMAGE)


class TestSessionNames(CliCase):
    """Finding 8: a session name is a path component of session_dir(), and what the
    meta.json found there says becomes msb argv and an rmtree target."""

    def plant(self, directory, meta):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "meta.json").write_text(json.dumps(meta))

    def test_traversing_name_is_refused_before_it_reads_anything(self):
        outside = self.tmp / "planted"
        self.plant(outside, {"name": "planted", "sandbox": "sg-planted", "port": 8090})
        sg.SESSIONS_DIR = self.tmp / "sessions"
        sg.SESSIONS_DIR.mkdir()
        self.addCleanup(setattr, sg, "SESSIONS_DIR", sg.SILK_DIR / "sessions")
        self.assertTrue((sg.session_dir("../planted") / "meta.json").is_file())
        for name in ["../planted", "../../etc", "/tmp/planted", "foo/../../planted", "..",
                     ".", "a b", "-x", "", "x" * 33, "sg;id"]:
            self.refuses("invalid session name", sg.read_meta, name)

    def test_meta_must_agree_with_its_directory(self):
        sg.SESSIONS_DIR = self.tmp / "sessions"
        self.addCleanup(setattr, sg, "SESSIONS_DIR", sg.SILK_DIR / "sessions")
        self.plant(sg.SESSIONS_DIR / "good", {"name": "good", "sandbox": "sg-good", "port": 8090})
        self.assertEqual(sg.read_meta("good")["sandbox"], "sg-good")
        self.assertIsNone(sg.read_meta("absent"))
        self.plant(sg.SESSIONS_DIR / "liar", {"name": "victim", "sandbox": "sg-victim"})
        self.refuses("refusing it", sg.read_meta, "liar")
        self.plant(sg.SESSIONS_DIR / "flag", {"name": "flag", "sandbox": "--net-rule=allow@x"})
        self.refuses("refusing it", sg.read_meta, "flag")

    def test_list_metas_skips_what_silkgate_did_not_create(self):
        sg.SESSIONS_DIR = self.tmp / "sessions"
        self.addCleanup(setattr, sg, "SESSIONS_DIR", sg.SILK_DIR / "sessions")
        self.plant(sg.SESSIONS_DIR / "good", {"name": "good", "sandbox": "sg-good", "port": 8090})
        self.plant(sg.SESSIONS_DIR / ".tmp-staging", {"name": "staging", "sandbox": "sg-x"})
        self.plant(sg.SESSIONS_DIR / "not a session", {"name": "elsewhere", "sandbox": "sg-y"})
        self.assertEqual([m["name"] for m in sg.list_metas()], ["good"])


class TestWorkspaceGuard(CliCase):
    """Finding 9: --workspace is mounted rw and is the only host path in the guest."""

    def test_plain_directory_is_mounted(self):
        project = self.tmp / "project"
        project.mkdir()
        self.assertEqual(sg._workspace_mount(str(project)),
                         (str(project), [f"{project}:/workspace:rw"]))
        self.assertEqual(sg._workspace_mount(None), (None, []))
        self.refuses("not a directory", sg._workspace_mount, str(project / "absent"))

    def test_git_directory_is_refused(self):
        repo = self.tmp / "repo"
        (repo / ".git" / "hooks").mkdir(parents=True)
        message = self.refuses("refusing to mount", sg._workspace_mount, str(repo))
        self.assertIn("worktree", message)                  # the error names the way out

    def test_git_worktree_pointer_file_is_allowed(self):
        tree = self.tmp / "tree"
        tree.mkdir()
        (tree / ".git").write_text("gitdir: /elsewhere/.git/worktrees/tree\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            path, mounts = sg._workspace_mount(str(tree))
        self.assertEqual((path, mounts), (str(tree), [f"{tree}:/workspace:rw"]))
        self.assertIn("worktree", err.getvalue())           # said, not silently allowed

    def test_host_state_and_home_are_refused(self):
        sg.SILK_DIR = self.tmp / "state" / "silkgate"
        sg.SILK_DIR.mkdir(parents=True)
        self.addCleanup(setattr, sg, "SILK_DIR", _SCRATCH / "silkgate")
        for path in [str(sg.SILK_DIR),                      # silkgate's own state
                     str(sg.SILK_DIR.parent),               # a directory containing it
                     str(Path.home()),
                     str(REPO),                             # the checkout this CLI runs from
                     os.sep]:
            self.refuses("refusing to mount", sg._workspace_mount, path)


class TestEnvGuard(CliCase):
    def test_proxy_variables_are_refused(self):
        sg.check_env(["FOO=bar", "PATH=/x"])                # ordinary pairs are fine
        for pair in ["HTTPS_PROXY=http://x", "http_proxy=http://x",
                     "NO_PROXY=api.anthropic.com", "no_proxy=*"]:
            self.refuses("-e", sg.check_env, [pair])
        self.refuses("expected NAME=VALUE", sg.check_env, ["nonsense"])
        self.refuses("newline", sg.check_env, ["FOO=a\nb"])


class TestProbeQuarantine(CliCase):
    def test_probe_only_resolves_for_verify(self):
        self.refuses("verify", sg.resolve_profiles, ["probe"])
        self.refuses("verify", sg.resolve_profiles, ["node", "probe"])
        self.assertEqual([p.name for p in sg.resolve_profiles(["probe"], allow_verify_only=True)],
                         ["probe"])

    def test_probe_rules_are_what_the_quarantine_is_about(self):
        rules = sg.compose_rules(sg.resolve_profiles(["probe"], allow_verify_only=True))
        self.assertIn("deb.debian.org", rules)


class TestEmptyAllowlist(CliCase):
    """No --with and no --rule is the strictest policy silkgate can express."""

    def test_empty_ruleset_parses_and_denies(self):
        self.assertEqual(sg.compose_rules([]), "")
        ruleset = sg.load_ruleset(sg.compose_rules([]))
        self.assertEqual(ruleset.rules, [])
        self.assertIsNone(ruleset.match("api.anthropic.com", "/v1/messages", "POST"))

    def test_session_policy_accepts_it_and_says_so(self):
        args = mock.Mock(with_=None, rule=None)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            profiles, text, ruleset = sg._session_policy(args)
        self.assertEqual((profiles, text, ruleset.rules), ([], "", []))
        self.assertIn("reach nothing", err.getvalue())

    def test_guest_brief_describes_an_empty_allowlist(self):
        empty = sg.session_context([], sg.load_ruleset(""), workspace=None, persistent=False)
        self.assertIn("allowlist for this machine is empty", empty)
        self.assertNotIn("Only these", empty)
        listed = sg.session_context([], sg.load_ruleset("api.anthropic.com/v1/** POST\n"),
                                    workspace=None, persistent=False)
        self.assertIn("Only these", listed)
        self.assertIn("`api.anthropic.com/v1/**`", listed)


class TestVerifyScoring(CliCase):
    """Finding 9: a run where five of seven checks SKIP is not containment."""

    ALL = frozenset(range(1, 8))

    def test_parse_checks(self):
        self.assertEqual(sg._parse_checks("CHECKS: ran=1,2,3,4,5,6,7 skipped="),
                         (set(self.ALL), set()))
        self.assertEqual(sg._parse_checks("[12:00:00.000] CHECKS: ran=3,7 skipped=1,2,4,5,6"),
                         ({3, 7}, {1, 2, 4, 5, 6}))
        self.assertEqual(sg._parse_checks("CHECKS: ran= skipped="), (set(), set()))

    def test_full_demands_all_seven(self):
        self.assertIsNone(sg._verify_shortfall(7, 0, set(self.ALL), set(), full=True))
        self.assertIn("never ran",
                      sg._verify_shortfall(2, 0, {3, 7}, {1, 2, 4, 5, 6}, full=True))
        self.assertIn("6", sg._verify_shortfall(6, 0, self.ALL - {6}, {6}, full=True))

    def test_quick_form_demands_the_tool_free_pair(self):
        self.assertIsNone(sg._verify_shortfall(2, 0, {3, 7}, {1, 2, 4, 5, 6}, full=False))
        self.assertIn("never ran",
                      sg._verify_shortfall(5, 0, {1, 2, 4, 5, 6}, {3, 7}, full=False))

    def test_a_failure_is_still_a_failure(self):
        self.assertIn("FAILED", sg._verify_shortfall(6, 1, set(self.ALL), set(), full=True))
        self.assertIn("disagrees", sg._verify_shortfall(3, 0, {3, 7}, set(), full=False))

    def test_verify_guest_script_reports_the_ids_the_cli_expects(self):
        script = (REPO / "test" / "verify_guest.sh").read_text()
        self.assertIn('echo "CHECKS: ran=', script)
        self.assertIn('echo "RESULT: $pass passed, $fail failed"', script)
        for check in self.ALL:
            self.assertRegex(script, rf"(?m)(?:^|\s)[PFS] {check} ")


if __name__ == "__main__":
    unittest.main()
