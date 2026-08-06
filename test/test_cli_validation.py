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
import subprocess
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
        # Bytes, not str: str.splitlines treats the mark (RS) itself as a line boundary,
        # which is exactly the invisibility the byte check exists to see through.
        for line in err.getvalue().encode().splitlines():   # argparse speaks as the host,
            self.assertTrue(line.startswith(sg._ERR_TAG),   # so every line is marked
                            f"unmarked host-voice line: {line!r}")

    def no_preflight(self):
        """Preflight stub for tests about what lies past it — this suite must pass on a
        machine with no docker/msb/mitmproxy installed."""
        return mock.patch.object(sg, "preflight", lambda *binaries: None)


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


class TestBaseFlag(CliCase):
    """--base was validated everywhere but honoured only by `build`: run/up called
    ensure_image without it, so a named base silently built the default instead."""

    def test_run_and_up_pass_base_to_ensure_image(self):
        for argv in (["run", "--base", "example.com/alt:9", "--", "true"],
                     ["up", "--name", "bf1", "--base", "example.com/alt:9"]):
            seen = {}

            def spy(profiles, image, *, base=sg.BASE_IMAGE):
                seen["base"] = base
                raise SystemExit(42)                        # stop before any proxy/msb work

            with self.no_preflight(), \
                    mock.patch.object(sg, "ensure_image", spy), \
                    mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as caught:
                sg.main()
            self.assertEqual(caught.exception.code, 42, argv)
            self.assertEqual(seen["base"], "example.com/alt:9", argv)

    def test_image_beside_a_named_base_is_refused(self):
        # An explicit image means nothing is built, so the base would be ignored — the
        # exact accepted-then-inert behaviour the passthrough above exists to end.
        self.assertEqual(sg.ensure_image([], "explicit:1"), "explicit:1")
        self.refuses("--image and --base", sg.ensure_image, [], "explicit:1",
                     base="example.com/alt:9")
        with self.no_preflight(), \
                mock.patch.object(sys, "argv", ["silkgate", "run", "--image", "img:1",
                                                "--base", "example.com/alt:9", "--", "true"]):
            self.refuses("--image and --base", sg.main)


class TestImageRef(CliCase):
    """The tag hash must cover everything that shapes the built image, or the cached-image
    lookup in ensure_image serves a stale build after that thing changes."""

    def test_hash_covers_the_base(self):
        self.assertNotEqual(sg.image_ref([]), sg.image_ref([], base="ubuntu:24.04"))

    def test_hash_covers_the_base_layer_bytes(self):
        before = sg.image_ref([])
        with mock.patch.object(sg, "_BASE_LAYER", sg._BASE_LAYER + "ENV X=1\n"):
            self.assertNotEqual(before, sg.image_ref([]))


class TestGuestCaEnv(CliCase):
    """Every TLS stack that reads only SSL_CERT_FILE (uv, anything rustls or Go) failed with
    UnknownIssuer in the guest until it was set; ARCHITECTURE.md promises all five vars.

    Which file each one names matters as much as that it is set. NODE_EXTRA_CA_CERTS is
    additive, so it names the CA alone. The rest replace the default roots, so they must name
    the bundle `update-ca-certificates` regenerates, which holds the distro's roots as well as
    ours: aimed at the bare CA they produce an image whose every later layer distrusts the real
    internet, and a profile's setup.sh installs from the real internet, over the host's
    network, outside the proxy. That combination broke every image build until it was caught.
    """

    CERT = "/usr/local/share/ca-certificates/egress.crt"
    BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
    CA_VARS = {"NODE_EXTRA_CA_CERTS": CERT,       # additive: the CA on its own
               "REQUESTS_CA_BUNDLE": BUNDLE,      # the rest replace the default roots
               "GIT_SSL_CAINFO": BUNDLE,
               "SSL_CERT_FILE": BUNDLE,
               "PIP_CERT": BUNDLE}

    def assert_ca_env(self, text):
        for var, path in self.CA_VARS.items():
            self.assertIn(f"{var}={path}", text)
            if path == self.BUNDLE:
                self.assertNotIn(f"{var}={self.CERT}", text,
                                 f"{var} replaces the default roots; aiming it at the CA "
                                 f"alone leaves the build unable to reach the internet")

    def test_base_layer_sets_every_promised_var(self):
        self.assert_ca_env(sg._BASE_LAYER)

    def test_written_dockerfile_carries_them(self):
        cert = self.tmp / "egress-ca.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\nnot-a-real-ca\n-----END CERTIFICATE-----\n")
        context = self.tmp / "context"
        context.mkdir()
        with mock.patch.object(sg, "ensure_ca", lambda: cert):
            sg.write_build_context(context, [], "debian:bookworm-slim")
        dockerfile = (context / "Dockerfile").read_text()
        self.assertTrue(dockerfile.startswith("FROM debian:bookworm-slim\n"))
        self.assert_ca_env(dockerfile)


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

    def test_nested_git_directory_is_refused_and_located(self):
        mount = self.tmp / "mount"
        (mount / "clean").mkdir(parents=True)
        (mount / "vendor" / "dep" / ".git" / "hooks").mkdir(parents=True)
        message = self.refuses("refusing to mount", sg._workspace_mount, str(mount))
        self.assertIn(str(Path("vendor") / "dep"), message)  # names where it found it
        self.assertIn("--allow-git-dir", message)            # and both ways forward
        self.assertIn("worktree", message)

    def test_nested_worktree_pointer_file_stays_allowed(self):
        mount = self.tmp / "trees"
        (mount / "wt").mkdir(parents=True)
        (mount / "wt" / ".git").write_text("gitdir: /elsewhere/.git/worktrees/wt\n")
        path, mounts = sg._workspace_mount(str(mount))
        self.assertEqual((path, mounts), (str(mount), [f"{mount}:/workspace:rw"]))

    def test_allow_git_dir_mounts_anyway_and_says_so(self):
        repo = self.tmp / "repo"
        (repo / ".git" / "hooks").mkdir(parents=True)
        (repo / "sub" / ".git").mkdir(parents=True)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            path, mounts = sg._workspace_mount(str(repo), allow_git_dir=True)
        self.assertEqual((path, mounts), (str(repo), [f"{repo}:/workspace:rw"]))
        self.assertIn("--allow-git-dir", err.getvalue())    # loud, never silent

    def test_allow_git_dir_does_not_unlock_forbidden_mounts(self):
        for path in [str(Path.home()), str(REPO), os.sep]:
            self.refuses("refusing to mount", sg._workspace_mount, path, allow_git_dir=True)

    def test_run_and_up_wire_allow_git_dir(self):
        for argv in (["run", "--allow-git-dir", "--", "true"],
                     ["up", "--name", "wire1", "--allow-git-dir"]):
            seen = {}

            def spy(workspace, *, allow_git_dir=False):
                seen["flag"] = allow_git_dir
                raise SystemExit(42)                        # stop before any proxy/msb work

            with self.no_preflight(), \
                    mock.patch.object(sg, "_workspace_mount", spy), \
                    mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as caught:
                sg.main()
            self.assertEqual(caught.exception.code, 42, argv)
            self.assertTrue(seen["flag"], argv)

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

    def test_listing_marks_probe_as_verify_only(self):
        # cmd_profiles builds Profile objects directly, bypassing resolve_profiles' guard,
        # so the truth has to be in the listing itself.
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            sg.cmd_profiles(None)
        lines = out.getvalue().splitlines()
        probe = next(ln for ln in lines if ln.startswith("probe "))
        self.assertIn("silkgate verify only", probe)
        for ln in lines:
            if not ln.startswith(("probe ", "PROFILE")):
                self.assertNotIn("verify only", ln)


class TestProfileRequires(CliCase):
    """`requires` in profile.conf is an extension point no shipped profile uses yet. It is
    kept because profiles are user-addable data — a directory, not code — and this is the
    executed path that keeps the enforcement from rotting unseen."""

    def setUp(self):
        super().setUp()
        pdir = self.tmp / "profiles"
        for name, conf in (("needy", "requires = helper\n"),
                           ("greedy", "requires = helper, needy\n"),
                           ("helper", "")):
            (pdir / name).mkdir(parents=True)
            if conf:
                (pdir / name / "profile.conf").write_text(conf)
        self._profile_dir = sg.PROFILE_DIR
        sg.PROFILE_DIR = pdir
        self.addCleanup(setattr, sg, "PROFILE_DIR", self._profile_dir)

    def test_missing_requirement_is_refused_and_named(self):
        message = self.refuses("requires helper", sg.resolve_profiles, ["needy"])
        self.assertIn("--with", message)                    # the error names the way out
        self.refuses("requires helper, needy", sg.resolve_profiles, ["greedy"])

    def test_satisfied_requirement_resolves_in_either_order(self):
        for specs in (["needy", "helper"], ["helper", "needy"]):
            self.assertEqual([p.name for p in sg.resolve_profiles(specs)], specs)
        self.assertEqual([p.name for p in sg.resolve_profiles(["helper", "needy", "greedy"])],
                         ["helper", "needy", "greedy"])


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
    """Finding 9: a run where most checks SKIP is not containment.

    The two sets come from the module rather than being spelled out again, so adding a check
    to the guest script cannot leave these assertions describing a contract that moved.
    """

    ALL = frozenset(sg._VERIFY_CHECKS)
    FREE = frozenset(sg._VERIFY_TOOL_FREE)
    NEEDS_TOOLS = ALL - FREE

    def test_parse_checks(self):
        ran = ",".join(str(i) for i in sorted(self.ALL))
        self.assertEqual(sg._parse_checks(f"CHECKS: ran={ran} skipped="),
                         (set(self.ALL), set(), set()))
        self.assertEqual(sg._parse_checks("[12:00:00.000] CHECKS: ran=3,7 skipped=1,2,4,5,6"),
                         ({3, 7}, {1, 2, 4, 5, 6}, set()))
        self.assertEqual(sg._parse_checks("CHECKS: ran= skipped="), (set(), set(), set()))

    def test_full_demands_every_check(self):
        self.assertIsNone(
            sg._verify_shortfall(len(self.ALL), 0, set(self.ALL), set(), full=True))
        self.assertIn("never ran",
                      sg._verify_shortfall(len(self.FREE), 0, set(self.FREE),
                                           set(self.NEEDS_TOOLS), full=True))
        one = max(self.ALL)
        self.assertIn(str(one), sg._verify_shortfall(len(self.ALL) - 1, 0,
                                                    self.ALL - {one}, {one}, full=True))

    def test_quick_form_demands_the_tool_free_checks(self):
        self.assertIsNone(sg._verify_shortfall(len(self.FREE), 0, set(self.FREE),
                                               set(self.NEEDS_TOOLS), full=False))
        self.assertIn("never ran",
                      sg._verify_shortfall(len(self.NEEDS_TOOLS), 0, set(self.NEEDS_TOOLS),
                                           set(self.FREE), full=False))

    def test_a_failure_is_still_a_failure(self):
        self.assertIn("FAILED",
                      sg._verify_shortfall(len(self.ALL) - 1, 1, set(self.ALL), set(),
                                           full=True))
        self.assertIn("disagrees",
                      sg._verify_shortfall(len(self.FREE) + 1, 0, set(self.FREE), set(),
                                           full=False))

    def test_verify_guest_script_reports_the_ids_the_cli_expects(self):
        script = (REPO / "test" / "verify_guest.sh").read_text()
        self.assertIn('echo "CHECKS: ran=', script)
        self.assertIn('echo "RESULT: $pass passed, $fail failed"', script)
        for check in self.ALL:
            self.assertRegex(script, rf"(?m)(?:^|\s)[PFS] {check} ")


class TestPreflight(CliCase):
    """One failed run must name every absent tool with its install command, and which()
    stays behind it as the per-use check. Hints come from sg._TOOL_HINTS rather than
    being spelled out again, so rewording a hint cannot leave these asserting stale text.
    """

    def path_holding(self, *present):
        """shutil.which resolves only `present` (to fake paths); everything else is
        absent — the machine the test pretends to be."""
        return mock.patch.object(sg.shutil, "which",
                                 lambda b, *a, **k: f"/fake/bin/{b}" if b in present else None)

    def demanded(self, argv, *, ca=False):
        """The set of binaries a command's preflight asks for, via a spy that stops the
        command before it does anything else."""
        seen = []

        def spy(*binaries):
            seen.extend(binaries)
            raise SystemExit(42)

        ca_path = self.tmp / "mitmproxy-ca-cert.pem"
        ca_path.unlink(missing_ok=True)                     # a prior call may have left one
        if ca:
            ca_path.write_text("not a real CA")
        with mock.patch.object(sg, "preflight", spy), \
                mock.patch.object(sg, "MITM_CA", ca_path), \
                mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as caught:
            sg.main()
        self.assertEqual(caught.exception.code, 42, argv)
        return set(seen)

    def test_the_per_command_matrix(self):
        # `down` validates the session exists before asking after the toolchain, so it
        # needs one to tear down.
        sdir = sg.SESSIONS_DIR / "pf3"
        sdir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, sdir, ignore_errors=True)
        (sdir / "meta.json").write_text(json.dumps(
            {"name": "pf3", "sandbox": sg.sandbox_name("pf3"), "port": 8090}))
        # Derived from what each cmd_* dials, not from what feels symmetric: an explicit
        # --image is run as-is (never built), so docker drops out of run/up with it.
        for argv, tools in [
            (["build"], {"docker", "msb", "mitmdump"}),
            (["run", "--", "true"], {"docker", "msb", "mitmdump"}),
            (["up", "--name", "pf1"], {"docker", "msb", "mitmdump"}),
            (["run", "--image", "img:1", "--", "true"], {"msb", "mitmdump"}),
            (["up", "--name", "pf2", "--image", "img:1"], {"msb", "mitmdump"}),
            (["verify"], {"msb", "mitmdump"}),
            (["down", "pf3"], {"msb"}),
        ]:
            self.assertEqual(self.demanded(argv), tools, argv)

    def test_build_needs_mitmdump_only_until_the_ca_exists(self):
        # write_build_context runs ensure_ca, which shells out to mitmdump only when
        # ~/.mitmproxy holds no CA yet.
        self.assertEqual(self.demanded(["build"], ca=True), {"docker", "msb"})
        self.assertEqual(self.demanded(["build"], ca=False), {"docker", "msb", "mitmdump"})

    def test_one_run_names_every_missing_tool(self):
        err = io.StringIO()
        with self.path_holding(), \
                mock.patch.object(sg, "MITM_CA", self.tmp / "absent-ca.pem"), \
                mock.patch.object(sys, "argv", ["silkgate", "run", "--", "true"]), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            sg.main()
        self.assertEqual(caught.exception.code, 1)
        for binary, hint in sg._TOOL_HINTS.items():
            self.assertIn(f"{binary} — {hint}", err.getvalue())
        # Bytes: str.splitlines would split on the (invisible) mark itself.
        for line in err.getvalue().encode().splitlines():    # host voice, so marked
            self.assertTrue(line.startswith(sg._ERR_TAG), repr(line))

    def test_a_complete_toolchain_passes_silently(self):
        err = io.StringIO()
        with self.path_holding("docker", "msb", "mitmdump"), contextlib.redirect_stderr(err):
            sg.preflight("docker", "msb", "mitmdump")
        self.assertEqual(err.getvalue(), "")

    def test_which_stays_the_last_line_of_defence(self):
        with self.path_holding():
            message = self.refuses("mitmdump not found", sg.which, "mitmdump",
                                   "pip install mitmproxy")
            self.assertIn(sg._TOOL_HINTS["mitmdump"], message)

    def test_the_table_owns_the_hint(self):
        # A call-site hint that drifted from the table is overridden by it; a binary the
        # table does not know still gets the hint it was called with.
        with self.path_holding():
            message = self.refuses("docker not found", sg.which, "docker", "a stale hint")
            self.assertIn(sg._TOOL_HINTS["docker"], message)
            self.assertNotIn("a stale hint", message)
            message = self.refuses("exotic not found", sg.which, "exotic", "install exotic")
            self.assertIn("install exotic", message)
        with self.path_holding("docker"):
            self.assertEqual(sg.which("docker"), "/fake/bin/docker")

    def test_commands_needing_nothing_run_with_the_toolchain_absent(self):
        with self.path_holding():
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                sg.cmd_profiles(None)
            self.assertIn("PROFILE", out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                sg.cmd_ls(None)
            self.assertIn("no sessions", out.getvalue())
            self.assertIn("proxy: not running", out.getvalue())

    def test_a_single_tool_command_names_its_tool_at_the_moment_of_use(self):
        # exec (like attach/proxy/logs) needs one tool, so lazy which() already reports
        # its full shortfall in one run — no preflight, and the message names the fix.
        sdir = sg.SESSIONS_DIR / "lazy1"
        sdir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, sdir, ignore_errors=True)
        (sdir / "meta.json").write_text(json.dumps(
            {"name": "lazy1", "sandbox": sg.sandbox_name("lazy1"), "port": 8090,
             "command": ["true"]}))
        with self.path_holding(), \
                mock.patch.object(sys, "argv",
                                  ["silkgate", "exec", "lazy1", "--no-tty", "--", "true"]):
            message = self.refuses("msb not found", sg.main)
        self.assertIn(sg._TOOL_HINTS["msb"], message)


class TestDoctor(CliCase):
    """One command for a user whose sandbox will not start: every tool, one pass,
    presence only — health is `silkgate verify`'s question."""

    def which_finding(self, *present):
        return mock.patch.object(sg.shutil, "which",
                                 lambda b, *a, **k: f"/fake/bin/{b}" if b in present else None)

    def doctor(self):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                sg.cmd_doctor(None)
            except SystemExit as e:
                code = e.code
        return out.getvalue(), err.getvalue(), code

    def test_reports_every_missing_tool_and_fails(self):
        with self.which_finding():
            out, err, code = self.doctor()
        self.assertNotEqual(code, 0)
        for binary, hint in sg._TOOL_HINTS.items():
            self.assertIn(binary, out)
            self.assertIn(hint, out)
        self.assertIn(f"missing {len(sg._TOOL_HINTS)} of {len(sg._TOOL_HINTS)}", err)

    def test_reports_paths_and_passes_when_complete(self):
        with self.which_finding(*sg._TOOL_HINTS):
            out, err, code = self.doctor()
        self.assertEqual(code, 0)
        for binary in sg._TOOL_HINTS:
            self.assertIn(f"/fake/bin/{binary}", out)
        self.assertNotIn("missing", out)
        self.assertIn("toolchain complete", err)

    def test_a_partial_shortfall_is_counted(self):
        with self.which_finding(*(set(sg._TOOL_HINTS) - {"msb"})):
            out, err, code = self.doctor()
        self.assertNotEqual(code, 0)
        self.assertIn(sg._TOOL_HINTS["msb"], out)
        self.assertIn(f"missing 1 of {len(sg._TOOL_HINTS)}", err)


class TestMarkedArgparse(CliCase):
    """Task 2: argparse's usage/error lines are host voice, so every one of its stderr
    lines must open with the mark — asserted on bytes from a real subprocess, because
    the marker is invisible in a terminal by design. The expected byte is read from the
    module (sg._ERR_TAG): argparse is held to say()'s convention, whatever that byte is.
    """

    def run_cli(self, *argv, path=None):
        env = dict(os.environ, HOME=str(self.tmp))           # never a real ~/.silkgate
        if path is not None:
            env["PATH"] = path
        return subprocess.run([sys.executable, str(REPO / "cli" / "silkgate"), *argv],
                              capture_output=True, env=env, timeout=60)

    def assert_marked(self, data):
        self.assertTrue(data, "expected something on stderr")
        for line in data.splitlines():
            self.assertTrue(line.startswith(sg._ERR_TAG),
                            f"unmarked host-voice line: {line!r}")

    def test_bad_subcommand_keeps_status_and_text_and_gains_the_mark(self):
        proc = self.run_cli("bogus")
        self.assertEqual(proc.returncode, 2)                 # argparse's usage-error status
        self.assert_marked(proc.stderr)
        self.assertIn(b"usage: silkgate", proc.stderr)       # the message text survives
        self.assertIn(b"silkgate: error:", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_subparser_errors_are_marked_too(self):
        for argv, prog in [(("exec",), b"silkgate exec"),
                           (("logs",), b"silkgate logs"),
                           (("secret",), b"silkgate secret"),   # a nested subparser's parser
                           (("run", "--port"), b"silkgate run")]:
            proc = self.run_cli(*argv)
            self.assertEqual(proc.returncode, 2, argv)
            self.assert_marked(proc.stderr)
            self.assertIn(prog + b": error:", proc.stderr, argv)

    def test_help_stays_bare_and_exits_zero(self):
        proc = self.run_cli("-h")
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"usage: silkgate", proc.stdout)
        self.assertNotIn(sg._ERR_TAG, proc.stdout)   # stdout carries no claim of host voice
        self.assertEqual(proc.stderr, b"")

    def test_preflight_shortfall_is_marked_end_to_end(self):
        # A PATH with no toolchain, a HOME with no CA: `run` must name all three tools in
        # one marked report, exit 1, and never get as far as any host process.
        proc = self.run_cli("run", "--", "true", path="/nonexistent-path-entry")
        self.assertEqual(proc.returncode, 1)
        self.assert_marked(proc.stderr)
        for binary, hint in sg._TOOL_HINTS.items():
            self.assertIn(f"{binary} — {hint}".encode(), proc.stderr)


if __name__ == "__main__":
    unittest.main()
