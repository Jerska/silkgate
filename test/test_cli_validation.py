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


def _git_env():
    """os.environ with every GIT_* override dropped (git honors far more than GIT_DIR —
    GIT_OBJECT_DIRECTORY, GIT_COMMON_DIR, GIT_CEILING_DIRECTORIES, ...) and config pinned
    to nothing, so fixture git sees only its own temp repos. Without this, an inherited
    GIT_DIR sends `git init <dir>`/`git -C <dir> commit` at the parent's repository.
    GIT_EXEC_PATH stays: some installs need it to find git's subcommands at all."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") or k == "GIT_EXEC_PATH"}
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


class CliCase(unittest.TestCase):
    """Shared assertions. die() exits non-zero after printing one line to stderr."""

    def setUp(self):
        self.assertTrue(str(sg.SESSIONS_DIR).startswith(str(_SCRATCH)),
                        "tests must never point at a real ~/.silkgate")
        # Resolved, because _mount_pair resolves what it is given and macOS hands out
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

    def provision_capture(self, argv):
        """Everything cmd_run/cmd_up hand _provision_session, captured at the call and
        the run stopped there — before any proxy or msb work."""
        seen = {}

        def spy(name, image, port, rules_text, ruleset, mounts, ws, env, meta_extra,
                context=None, context_paths=()):
            seen.update(name=name, mounts=mounts, ws=ws, env=env, meta=meta_extra,
                        context=context)
            raise SystemExit(42)

        with self.no_preflight(), \
                mock.patch.object(sg, "ensure_image", lambda *a, **k: "img:1"), \
                mock.patch.object(sg, "_proxy_running", lambda: True), \
                mock.patch.object(sg, "ensure_proxy",
                                  lambda port: {"log": "/dev/null", "ports": [8090]}), \
                mock.patch.object(sg, "pick_port", lambda proxy, name: 8090), \
                mock.patch.object(sg, "_provision_session", spy), \
                mock.patch.object(sg, "_release_port", lambda *a, **k: None), \
                mock.patch.object(sg, "stop_proxy", lambda *a, **k: None), \
                mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as caught:
            sg.main()
        self.assertEqual(caught.exception.code, 42, argv)
        return seen


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


class TestMountGuards(CliCase):
    """-v/--mount: the mounts are the only host paths in the guest, so each one is
    validated on both sides before any host process starts — forbidden directories in
    either mode, the .git walk for rw, and the guest-path rules."""

    def test_plain_directory_is_mounted_ro_by_default(self):
        project = self.tmp / "project"
        project.mkdir()
        self.assertEqual(sg._mount_args([f"{project}:/workspace"]),
                         [(str(project), "/workspace", "ro")])
        self.assertEqual(sg._mount_args([f"{project}:/workspace:rw"]),
                         [(str(project), "/workspace", "rw")])
        self.assertEqual(sg._mount_args(None), [])
        self.assertEqual(sg._mount_args([]), [])
        self.refuses("not a directory", sg._mount_args,
                     [f"{project / 'absent'}:/workspace:rw"])

    def test_malformed_specs_are_refused(self):
        d = str(self.tmp)
        for bad in ("", d, f"{d}:", f":{d}", f"{d}:/x:rx", f"{d}:/x:RW", f"{d}:/x:ro:extra"):
            self.refuses("invalid mount", sg._mount_args, [bad])

    def test_parse_time_errors_name_the_flag(self):
        self.refuses_argv("invalid mount", "--mount",
                          ["run", "-v", "nocolon", "--", "true"])
        self.refuses_argv("invalid mount", "--mount", ["up", "-v", "a:/b:rx"])

    def test_git_directory_is_refused_rw_and_located(self):
        mount = self.tmp / "mount"
        (mount / "clean").mkdir(parents=True)
        (mount / "vendor" / "dep" / ".git" / "hooks").mkdir(parents=True)
        message = self.refuses("refusing to mount", sg._mount_args, [f"{mount}:/workspace:rw"])
        self.assertIn(str(Path("vendor") / "dep"), message)  # names where it found it
        self.assertIn("--allow-git-dir", message)            # and every way forward
        self.assertIn("worktree", message)
        self.assertIn("read-only", message)

    def test_git_directory_is_accepted_ro(self):
        repo = self.tmp / "repo"
        (repo / ".git" / "hooks").mkdir(parents=True)
        self.assertEqual(sg._mount_args([f"{repo}:/workspace"]),
                         [(str(repo), "/workspace", "ro")])

    def test_worktree_pointer_file_is_allowed_in_both_modes_and_said(self):
        tree = self.tmp / "tree"
        tree.mkdir()
        (tree / ".git").write_text("gitdir: /elsewhere/.git/worktrees/tree\n")
        for mode in ("ro", "rw"):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                mounts = sg._mount_args([f"{tree}:/workspace:{mode}"])
            self.assertEqual(mounts, [(str(tree), "/workspace", mode)], mode)
            self.assertIn("worktree", err.getvalue())        # said, not silently allowed

    def test_nested_worktree_pointer_file_stays_allowed_rw(self):
        mount = self.tmp / "trees"
        (mount / "wt").mkdir(parents=True)
        (mount / "wt" / ".git").write_text("gitdir: /elsewhere/.git/worktrees/wt\n")
        self.assertEqual(sg._mount_args([f"{mount}:/workspace:rw"]),
                         [(str(mount), "/workspace", "rw")])

    def test_allow_git_dir_mounts_anyway_and_says_so(self):
        repo = self.tmp / "repo"
        (repo / ".git" / "hooks").mkdir(parents=True)
        (repo / "sub" / ".git").mkdir(parents=True)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            mounts = sg._mount_args([f"{repo}:/workspace:rw"], allow_git_dir=True)
        self.assertEqual(mounts, [(str(repo), "/workspace", "rw")])
        self.assertIn("--allow-git-dir", err.getvalue())    # loud, never silent

    def test_allow_git_dir_does_not_unlock_forbidden_mounts(self):
        for path in [str(Path.home()), str(REPO), os.sep]:
            self.refuses("refusing to mount", sg._mount_args,
                         [f"{path}:/workspace:rw"], allow_git_dir=True)

    def test_host_state_and_home_are_refused_in_both_modes(self):
        sg.SILK_DIR = self.tmp / "state" / "silkgate"
        sg.SILK_DIR.mkdir(parents=True)
        self.addCleanup(setattr, sg, "SILK_DIR", _SCRATCH / "silkgate")
        for path in [str(sg.SILK_DIR),                      # silkgate's own state
                     str(sg.SILK_DIR.parent),               # a directory containing it
                     str(Path.home()),
                     str(REPO),                             # the checkout this CLI runs from
                     os.sep]:
            for mode in ("ro", "rw"):
                self.refuses("refusing to mount", sg._mount_args, [f"{path}:/data:{mode}"])

    def test_guest_destination_guards(self):
        src = self.tmp / "src"
        src.mkdir()
        self.refuses("not absolute", sg._mount_args, [f"{src}:data"])
        self.refuses("not absolute", sg._mount_args, [f"{src}:./x"])
        self.refuses("whole filesystem", sg._mount_args, [f"{src}:/"])
        self.refuses("whole filesystem", sg._mount_args, [f"{src}:/data/.."])
        for reserved in ("/silkgate", "/silkgate/base.git", "/root/lfsstore",
                         "/root/lfsstore/objects"):
            self.refuses("silkgate's own", sg._mount_args, [f"{src}:{reserved}"])

    def test_duplicate_and_nested_destinations_are_refused(self):
        a, b = self.tmp / "a", self.tmp / "b"
        a.mkdir()
        b.mkdir()
        self.refuses("duplicate mount destination", sg._mount_args,
                     [f"{a}:/data", f"{b}:/data:rw"])
        self.refuses("duplicate mount destination", sg._mount_args,
                     [f"{a}:/data", f"{b}:/data/"])          # normalization, not spelling
        for specs in ([f"{a}:/data", f"{b}:/data/sub"],
                      [f"{a}:/data/sub", f"{b}:/data"]):     # either order
            self.refuses("nest", sg._mount_args, specs)
        two = sg._mount_args([f"{a}:/data", f"{b}:/database"])  # a shared prefix is no nest
        self.assertEqual([guest for _, guest, _ in two], ["/data", "/database"])

    def test_destination_above_a_reserved_path_is_refused(self):
        src = self.tmp / "src"
        src.mkdir()
        for dst in ("/root",                                # above lfsstore and gitdir
                    "/root/gitdir",                         # a branch session's clone
                    "/root/gitdir/objects"):
            self.refuses("silkgate's own", sg._mount_args, [f"{src}:{dst}"])
        ok = sg._mount_args([f"{src}:/root/caches"])        # a sibling shares no fate
        self.assertEqual([guest for _, guest, _ in ok], ["/root/caches"])

    def test_allow_git_dir_without_a_rw_mount_is_refused(self):
        src = self.tmp / "src"
        src.mkdir()
        for specs in ([], [f"{src}:/data"], [f"{src}:/data:ro"]):
            self.refuses("does nothing", sg._mount_args, specs, allow_git_dir=True)

    def test_run_and_up_wire_mounts_and_allow_git_dir(self):
        project = self.tmp / "project"
        project.mkdir()
        spec = f"{project}:/data:rw"
        for argv in (["run", "-v", spec, "--allow-git-dir", "--", "true"],
                     ["up", "--name", "wire1", "--mount", spec, "--allow-git-dir"]):
            seen = {}

            def spy(specs, *, allow_git_dir=False):
                seen["specs"], seen["flag"] = specs, allow_git_dir
                raise SystemExit(42)                        # stop before any proxy/msb work

            with self.no_preflight(), \
                    mock.patch.object(sg, "_mount_args", spy), \
                    mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as caught:
                sg.main()
            self.assertEqual(caught.exception.code, 42, argv)
            self.assertEqual(seen["specs"], [spec], argv)
            self.assertTrue(seen["flag"], argv)


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
        empty = sg.session_context([], sg.load_ruleset(""), persistent=False)
        self.assertIn("allowlist for this machine is empty", empty)
        self.assertNotIn("Only these", empty)
        listed = sg.session_context([], sg.load_ruleset("api.anthropic.com/v1/** POST\n"),
                                    persistent=False)
        self.assertIn("Only these", listed)
        self.assertIn("`api.anthropic.com/v1/**`", listed)


class TestSecretValidation(CliCase):
    """Launch-time secret checks: check_secrets validates values, not just presence;
    the session comes up even when secrets are missing or malformed; cmd_secret_set
    is the one hard-error path for absent or malformed values."""

    _RULE = "api.anthropic.com/v1/** POST inject_auth=anthropic max_body=10m"

    def _ruleset(self):
        return sg.load_ruleset(self._RULE)

    def test_check_secrets_passes_when_valid(self):
        ruleset = self._ruleset()
        err = io.StringIO()
        with mock.patch.dict(os.environ,
                             {"SILKGATE_EGRESS_SECRET_ANTHROPIC": "x-api-key: sk-ant-test"}):
            with contextlib.redirect_stderr(err):
                sg.check_secrets(ruleset)
        self.assertEqual(err.getvalue(), "")

    def test_check_secrets_warns_when_absent(self):
        ruleset = self._ruleset()
        err = io.StringIO()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("SILKGATE_EGRESS_SECRET_")}
        with mock.patch.dict(os.environ, env, clear=True):
            with contextlib.redirect_stderr(err):
                sg.check_secrets(ruleset)
        self.assertIn("SILKGATE_EGRESS_SECRET_ANTHROPIC", err.getvalue())
        self.assertIn("is not set", err.getvalue())
        self.assertIn("inject_auth=anthropic", err.getvalue())

    def test_check_secrets_warns_when_malformed(self):
        """A value like "x-api-key: " (empty after the colon) passes truthiness but is
        rejected by _parse_secret — the proxy would deny every matching request."""
        ruleset = self._ruleset()
        err = io.StringIO()
        with mock.patch.dict(os.environ,
                             {"SILKGATE_EGRESS_SECRET_ANTHROPIC": "x-api-key: "}):
            with contextlib.redirect_stderr(err):
                sg.check_secrets(ruleset)
        self.assertIn("SILKGATE_EGRESS_SECRET_ANTHROPIC", err.getvalue())
        self.assertIn('not a valid', err.getvalue())
        self.assertIn("inject_auth=anthropic", err.getvalue())

    def test_check_secrets_does_not_die_when_missing(self):
        """Launches always warn and continue — check_secrets never dies."""
        ruleset = self._ruleset()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("SILKGATE_EGRESS_SECRET_")}
        with mock.patch.dict(os.environ, env, clear=True):
            with contextlib.redirect_stderr(io.StringIO()):
                sg.check_secrets(ruleset)   # must not raise

    def test_check_secrets_does_not_die_when_malformed(self):
        """A malformed but set secret is a warning, not a fatal error at launch."""
        ruleset = self._ruleset()
        with mock.patch.dict(os.environ,
                             {"SILKGATE_EGRESS_SECRET_ANTHROPIC": "no-colon-here"}):
            with contextlib.redirect_stderr(io.StringIO()):
                sg.check_secrets(ruleset)   # must not raise

    def test_cmd_secret_set_rejects_malformed_value(self):
        """cmd_secret_set keeps a hard error so push errors are caught before the proxy."""
        args = mock.Mock()
        args.name = "anthropic"
        args.session = "foo"
        with mock.patch.dict(os.environ,
                             {"SILKGATE_EGRESS_SECRET_ANTHROPIC": "no-colon-here"}):
            self.refuses("not a valid", sg.cmd_secret_set, args)

    def test_cmd_secret_set_dies_when_absent(self):
        """Absence is still a hard error for explicit set operations."""
        args = mock.Mock()
        args.name = "anthropic"
        args.session = "foo"
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("SILKGATE_EGRESS_SECRET_")}
        with mock.patch.dict(os.environ, env, clear=True):
            self.refuses("missing secret", sg.cmd_secret_set, args)

    def test_session_context_lists_available_credential(self):
        ruleset = self._ruleset()
        with mock.patch.dict(os.environ,
                             {"SILKGATE_EGRESS_SECRET_ANTHROPIC": "x-api-key: sk-ant-test"}):
            ctx = sg.session_context([], ruleset, persistent=False)
        self.assertIn("inject_auth=anthropic", ctx)
        self.assertIn("Available", ctx)
        self.assertIn("`x-api-key`", ctx)          # names the header the proxy rewrites
        self.assertNotIn("sk-ant-test", ctx)       # and never any part of its value

    def test_session_context_lists_missing_credential(self):
        ruleset = self._ruleset()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("SILKGATE_EGRESS_SECRET_")}
        with mock.patch.dict(os.environ, env, clear=True):
            ctx = sg.session_context([], ruleset, persistent=False)
        self.assertIn("inject_auth=anthropic", ctx)
        self.assertIn("Missing or malformed", ctx)
        self.assertIn("not set", ctx)

    def test_session_context_lists_malformed_credential(self):
        ruleset = self._ruleset()
        with mock.patch.dict(os.environ,
                             {"SILKGATE_EGRESS_SECRET_ANTHROPIC": "x-api-key: "}):
            ctx = sg.session_context([], ruleset, persistent=False)
        self.assertIn("inject_auth=anthropic", ctx)
        self.assertIn("Missing or malformed", ctx)
        # A header name parsed out of a malformed secret is a guess — never surface it.
        self.assertNotIn("x-api-key", ctx)

    def test_session_context_omits_section_when_no_inject_auth(self):
        ruleset = sg.load_ruleset("api.anthropic.com/v1/** POST\n")
        ctx = sg.session_context([], ruleset, persistent=False)
        self.assertNotIn("Injected credentials", ctx)


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
            (["run", "--checkout", "--", "true"], {"docker", "msb", "mitmdump", "git"}),
            (["up", "--name", "pf4", "--checkout"], {"docker", "msb", "mitmdump", "git"}),
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
        # A plain run's toolchain — git is hinted too, but only --checkout/--branch demand it.
        for binary in ("docker", "msb", "mitmdump"):
            self.assertIn(f"{binary} — {sg._TOOL_HINTS[binary]}", err.getvalue())
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
        # A plain run's toolchain — git is in _TOOL_HINTS too, but only --checkout/--branch demand it.
        for binary in ("docker", "msb", "mitmdump"):
            self.assertIn(f"{binary} — {sg._TOOL_HINTS[binary]}".encode(), proc.stderr)


class GitRepoCase(CliCase):
    """Fixtures the --branch and --checkout suites share: a scratch repository, a cwd
    guard, a stub git profile, and refusal-through-main()."""

    def argv_refuses(self, needle, argv):
        with mock.patch.object(sys, "argv", ["silkgate"] + argv), self.no_preflight():
            return self.refuses(needle, sg.main)

    def git_profile(self):
        import types
        return [types.SimpleNamespace(name="git")]

    def _repo(self, commit=True, name="repo"):
        root = self.tmp / name
        subprocess.run(["git", "init", "-q", "-b", "main", str(root)],
                       check=True, capture_output=True, env=_git_env())
        if commit:
            subprocess.run(["git", "-C", str(root), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "commit", "-q",
                            "--allow-empty", "-m", "seed"], check=True, capture_output=True,
                           env=_git_env())
        return root

    def _rev(self, root, ref="HEAD"):
        return subprocess.run(["git", "-C", str(root), "rev-parse", ref],
                              capture_output=True, text=True, check=True,
                              env=_git_env()).stdout.strip()

    @contextlib.contextmanager
    def _cwd(self, path):
        old = os.getcwd()
        os.chdir(path)
        try:
            yield
        finally:
            os.chdir(old)


class TestBranchGuards(GitRepoCase):
    """--branch: what run/up refuse before any host process, and the derived-workspace locks."""

    # --- flag surface, no git needed ------------------------------------------

    def test_branch_owns_workspace_against_mounts(self):
        # /workspace and anything under it — a nested DST would be nested virtiofs on
        # top of the branch workspace mount, and spelling must not dodge the rule.
        d = str(self.tmp)
        for dst in ("/workspace", "/workspace/", "/workspace/sub", "/x/../workspace"):
            self.argv_refuses("owns /workspace",
                              ["run", "--branch", "x", "-v", f"{d}:{dst}", "--", "true"])
            self.argv_refuses("owns /workspace",
                              ["up", "--name", "col1", "--branch", "x", "-v", f"{d}:{dst}"])

    def test_mounts_combine_with_branch(self):
        # A -v mount beside --branch is legal now; only /workspace is owned. Reaching the
        # _branch_workspace spy proves _mount_args accepted the pair (it runs first).
        data = self.tmp / "data"
        data.mkdir()
        fake_spec = {"branch": "nb", "git_dir": "/g", "base": "0" * 40,
                     "repo_root": "/r", "workspace_derived": True}

        def spy(spec, name):
            raise SystemExit(42)

        with mock.patch.object(sys, "argv",
                               ["silkgate", "run", "--with", "git", "--branch", "nb",
                                "-v", f"{data}:/data:rw", "--allow-git-dir", "--", "true"]), \
                mock.patch.object(sg, "_branch_spec", lambda *a: fake_spec), \
                mock.patch.object(sg, "_branch_workspace", spy), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.no_preflight(), self.assertRaises(SystemExit) as caught:
            sg.main()
        self.assertEqual(caught.exception.code, 42)

    def test_branch_needs_the_git_profile(self):
        self.argv_refuses("--with git", ["run", "--branch", "x", "--", "true"])

    def test_branch_owns_its_guest_env(self):
        self.argv_refuses("conflicts with --branch",
                          ["run", "--with", "git", "--branch", "x",
                           "-e", "GIT_DIR=/x", "--", "true"])

    def test_branch_name_precheck_needs_no_git(self):
        for bad in ("-x", "a b", "a\tb"):
            self.refuses("invalid branch name", sg._branch_spec, bad, self.git_profile(), [])

    # --- repo validation, real git --------------------------------------------

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_branch_spec_against_a_repo(self):
        root = self._repo()
        with self._cwd(root):
            self.refuses("invalid branch name", sg._branch_spec, "a..b", self.git_profile(), [])
            self.refuses("already exists", sg._branch_spec, "main", self.git_profile(), [])
            spec = sg._branch_spec("agent/x", self.git_profile(), [])
        self.assertEqual(Path(spec["git_dir"]), (root / ".git").resolve())
        self.assertEqual(Path(spec["repo_root"]), root.resolve())
        self.assertRegex(spec["base"], r"\A[0-9a-f]{40}\Z")
        self.assertTrue(spec["workspace_derived"])
        exclude = root / ".git" / "info" / "exclude"
        self.assertIn(".silkgate/", exclude.read_text().splitlines())

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_branch_spec_ignores_inherited_git_env(self):
        # A parent process may export GIT_DIR/GIT_WORK_TREE — a silkgate --branch guest
        # does, at the session clone. The spec must describe the repository at cwd, and
        # the exported one must come out untouched: without _host_git_env() this based
        # the session on the decoy and wrote its info/exclude.
        root = self._repo()
        decoy = self._repo(name="decoy")
        with mock.patch.dict(os.environ, {"GIT_DIR": str(decoy / ".git"),
                                          "GIT_WORK_TREE": str(decoy)}), self._cwd(root):
            spec = sg._branch_spec("agent/x", self.git_profile(), [])
        self.assertEqual(Path(spec["git_dir"]), (root / ".git").resolve())
        self.assertEqual(Path(spec["repo_root"]), root.resolve())
        exclude = decoy / ".git" / "info" / "exclude"
        self.assertNotIn(".silkgate/",
                         exclude.read_text().splitlines() if exclude.is_file() else [])

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_branch_spec_refuses_a_repoless_cwd_and_an_unborn_head(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        with self._cwd(empty):
            self.refuses("inside a git work tree", sg._branch_spec, "x", self.git_profile(), [])
        with self._cwd(self._repo(commit=False, name="unborn")):
            message = self.refuses("cannot resolve", sg._branch_spec, "x",
                                   self.git_profile(), [])
        self.assertIn("'HEAD'", message)            # the unresolvable ref is named

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_branch_spec_from_a_linked_worktree(self):
        # git_dir must be the common dir (the worktree's own gitdir has no objects), and
        # the base must be the worktree's HEAD, not the main checkout's.
        root = self._repo()
        wt = self.tmp / "wt"
        subprocess.run(["git", "-C", str(root), "worktree", "add", "-q", "--detach", str(wt)],
                       check=True, capture_output=True, env=_git_env())
        subprocess.run(["git", "-C", str(wt), "-c", "user.name=t", "-c",
                        "user.email=t@t.invalid", "commit", "-q", "--allow-empty",
                        "-m", "ahead"], check=True, capture_output=True, env=_git_env())
        head = subprocess.run(["git", "-C", str(wt), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True,
                              env=_git_env()).stdout.strip()
        with self._cwd(wt):
            spec = sg._branch_spec("agent/x", self.git_profile(), [])
        self.assertEqual(Path(spec["git_dir"]), (root / ".git").resolve())
        self.assertEqual(spec["base"], head)

    def test_exclude_silkgate_is_idempotent_and_preserving(self):
        git_dir = self.tmp / "gd"
        (git_dir / "info").mkdir(parents=True)
        (git_dir / "info" / "exclude").write_text("prior\n")
        sg._exclude_silkgate(git_dir)
        sg._exclude_silkgate(git_dir)
        self.assertEqual((git_dir / "info" / "exclude").read_text(), "prior\n.silkgate/\n")

    # --- the derived workspace -------------------------------------------------

    def spec_for(self, root):
        return {"branch": "agent/x", "git_dir": str(root / ".git"), "base": "0" * 40,
                "repo_root": str(root), "workspace_derived": True}

    def test_branch_workspace_mounts(self):
        root = self.tmp / "proj"
        (root / ".git").mkdir(parents=True)
        ws, mounts = sg._branch_workspace(self.spec_for(root), "n1")
        self.assertEqual(Path(ws), (root / ".silkgate" / "sandboxes" / "n1").resolve())
        self.assertIn(f"{ws}:/workspace:rw", mounts)
        self.assertIn(f"{root / '.git'}:/silkgate/base.git:ro", mounts)
        self.assertFalse(any("/root/lfsstore" in m for m in mounts),
                         "no lfs mount when the repo has no .git/lfs")
        (root / ".git" / "lfs").mkdir()
        ws2, mounts2 = sg._branch_workspace(self.spec_for(root), "n2")
        self.assertIn(f"{root / '.git' / 'lfs'}:/root/lfsstore:rw", mounts2)

    def test_branch_workspace_refuses_a_leftover(self):
        root = self.tmp / "proj"
        (root / ".silkgate" / "sandboxes" / "n1").mkdir(parents=True)
        self.refuses("leftover workspace", sg._branch_workspace, self.spec_for(root), "n1")

    def test_branch_workspace_refuses_silkgates_own_state(self):
        root = Path(sg.SILK_DIR) / "somerepo"
        self.refuses("silkgate's own state", sg._branch_workspace, self.spec_for(root), "n1")

    def test_mount_guard_accepts_the_nested_sandbox_dir(self):
        # The pin for the whole layout: the repo root stays refused while the derived
        # directory nested inside it mounts — nesting is what separates the two.
        repo = self.tmp / "nestrepo"
        (repo / ".git").mkdir(parents=True)
        nested = repo / ".silkgate" / "sandboxes" / "x"
        nested.mkdir(parents=True)
        self.refuses("refusing to mount", sg._mount_args, [f"{repo}:/workspace:rw"])
        self.assertEqual(sg._mount_args([f"{nested}:/workspace:rw"]),
                         [(str(nested.resolve()), "/workspace", "rw")])

    # --- meta as input ----------------------------------------------------------

    def plant_meta(self, name, **extra):
        sdir = sg.SESSIONS_DIR / name
        sdir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, sdir, ignore_errors=True)
        (sdir / "meta.json").write_text(json.dumps(
            {"name": name, "sandbox": f"sg-{name}", **extra}))

    def test_read_meta_refuses_a_planted_branch(self):
        self.plant_meta("aaa111", branch="-evil", base="0" * 40)
        self.refuses("refusing it", sg.read_meta, "aaa111")

    def test_read_meta_refuses_a_planted_base(self):
        self.plant_meta("bbb222", branch="fine", base="not-a-sha")
        self.refuses("refusing it", sg.read_meta, "bbb222")

    def test_read_meta_accepts_a_wellformed_branch_meta(self):
        self.plant_meta("ccc333", branch="agent/x", base="0" * 40)
        self.assertEqual(sg.read_meta("ccc333")["branch"], "agent/x")

    def test_reap_needs_both_locks(self):
        root = self.tmp / "proj"
        ws = root / ".silkgate" / "sandboxes" / "n1"
        ws.mkdir(parents=True)
        base = {"name": "n1", "repo_root": str(root), "workspace": str(ws)}
        sg._reap_derived_workspace({**base})                          # no flag
        self.assertTrue(ws.exists())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):                         # flag, wrong path
            sg._reap_derived_workspace({**base, "workspace_derived": True,
                                        "workspace": str(self.tmp)})
        self.assertTrue(self.tmp.exists())
        self.assertIn("not this session's derived workspace", err.getvalue())
        sg._reap_derived_workspace({**base, "workspace_derived": True})
        self.assertFalse(ws.exists())

    # --- wiring ------------------------------------------------------------------

    def test_run_and_up_wire_branch_through_spec_and_workspace(self):
        fake_spec = {"branch": "nb", "git_dir": "/g", "base": "0" * 40,
                     "repo_root": "/r", "workspace_derived": True}
        for argv in (["run", "--with", "git", "--branch", "nb", "--", "true"],
                     ["up", "--name", "w1", "--with", "git", "--branch", "nb"]):
            seen = {}

            def spy(spec, name, _seen=seen):
                _seen["spec"], _seen["name"] = spec, name
                raise SystemExit(42)                # stop before any proxy/msb work

            with mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                    mock.patch.object(sg, "_branch_spec", lambda *a: fake_spec), \
                    mock.patch.object(sg, "_branch_workspace", spy), \
                    self.no_preflight(), self.assertRaises(SystemExit) as caught:
                sg.main()
            self.assertEqual(caught.exception.code, 42, argv[0])
            self.assertEqual(seen["spec"], fake_spec)
            self.assertTrue(seen["name"] == "w1" if argv[0] == "up"
                            else sg._name_ok(seen["name"]))


class TestHarvestWiring(CliCase):
    """cmd_run's finally block and cmd_down: the harvest runs before the teardown, a
    failed harvest keeps the workspace and forces exit 1, and a vanished meta.json still
    harvests from the launch spec. Everything past the CLI is stubbed at module
    attributes, as in test_run_and_up_wire_branch_through_spec_and_workspace."""

    FAKE_SPEC = {"branch": "nb", "git_dir": "/g", "base": "0" * 40,
                 "repo_root": "/r", "workspace_derived": True}

    def drive_run(self, *, harvest_ok, meta_on_disk=True):
        """`run --branch` driven past run_guest -> (exit code, ordered calls, harvest meta)."""
        ws = str(self.tmp / "ws")
        calls, seen = [], {}

        def read_meta(name):
            if not meta_on_disk:
                return None
            return {"name": name, "sandbox": sg.sandbox_name(name), "workspace": ws,
                    **self.FAKE_SPEC}

        def harvest(meta):
            calls.append("harvest")
            seen["meta"] = meta
            return harvest_ok

        with mock.patch.object(sys, "argv", ["silkgate", "run", "--with", "git",
                                             "--branch", "nb", "--", "true"]), \
                self.no_preflight(), \
                mock.patch.object(sg, "_branch_spec", lambda *a: dict(self.FAKE_SPEC)), \
                mock.patch.object(sg, "_branch_workspace", lambda spec, name: (ws, [])), \
                mock.patch.object(sg, "ensure_image", lambda *a, **k: "img:1"), \
                mock.patch.object(sg, "_proxy_running", lambda: True), \
                mock.patch.object(sg, "ensure_proxy",
                                  lambda port: {"log": "/dev/null", "ports": [8090]}), \
                mock.patch.object(sg, "pick_port", lambda proxy, name: 8090), \
                mock.patch.object(sg, "_provision_session", lambda *a, **k: None), \
                mock.patch.object(sg, "tier1_fault", lambda *a: None), \
                mock.patch.object(sg, "_setup_branch_guest", lambda *a: None), \
                mock.patch.object(sg, "run_guest", lambda *a, **k: 0), \
                mock.patch.object(sg, "read_meta", read_meta), \
                mock.patch.object(sg, "_harvest_branch", harvest), \
                mock.patch.object(sg, "_teardown_session",
                                  lambda meta: calls.append("teardown")), \
                mock.patch.object(sg, "_reap_derived_workspace",
                                  lambda meta: calls.append("reap")), \
                mock.patch.object(sg, "list_metas", lambda: []), \
                mock.patch.object(sg, "stop_proxy", lambda *a, **k: None), \
                mock.patch.object(sg, "say", lambda *a, **k: None), \
                self.assertRaises(SystemExit) as caught:
            sg.main()
        return caught.exception.code, calls, seen.get("meta")

    def test_run_harvests_from_the_launch_spec_when_meta_vanishes(self):
        # Regression: with meta.json unreadable mid-run, the fallback meta lacked
        # branch/base/workspace — _bundle_in_guest raised KeyError inside the finally,
        # so _teardown_session never ran and the sandbox leaked.
        code, calls, meta = self.drive_run(harvest_ok=True, meta_on_disk=False)
        self.assertEqual(code, 0)
        self.assertEqual(meta["branch"], "nb")
        self.assertEqual(meta["base"], "0" * 40)
        self.assertEqual(meta["workspace"], str(self.tmp / "ws"))
        self.assertIn("teardown", calls)


class TestCheckoutSessions(GitRepoCase):
    """--checkout [REF]: a disposable, guest-local checkout of the enclosing repo, with
    --branch layered on top of the same validation and mounts."""

    # --- flag surface, no git needed ------------------------------------------

    def test_checkout_needs_the_git_profile(self):
        self.argv_refuses("--with git", ["run", "--checkout", "--", "true"])
        self.argv_refuses("--with git", ["up", "--name", "co1", "--checkout"])

    def test_checkout_owns_its_guest_env(self):
        self.argv_refuses("conflicts with --checkout",
                          ["run", "--with", "git", "--checkout",
                           "-e", "GIT_DIR=/x", "--", "true"])
        self.argv_refuses("conflicts with --checkout",
                          ["up", "--name", "co2", "--with", "git", "--checkout",
                           "-e", "GIT_WORK_TREE=/x"])

    def test_checkout_owns_workspace_against_mounts(self):
        d = str(self.tmp)
        for dst in ("/workspace", "/workspace/sub"):
            self.argv_refuses("owns /workspace",
                              ["run", "--checkout", "-v", f"{d}:{dst}", "--", "true"])

    def test_ref_charset_precheck_needs_no_git(self):
        for bad in ("-x", "a b", "a\tb"):
            self.refuses("invalid ref", sg._checkout_spec, bad, self.git_profile(), [])

    def test_run_and_up_demand_host_git(self):
        # preflight must name git before any repo probe runs.
        for argv in (["run", "--checkout", "--", "true"],
                     ["up", "--name", "co3", "--checkout"]):
            seen = []

            def spy(*binaries):
                seen.extend(binaries)
                raise SystemExit(42)

            with mock.patch.object(sg, "preflight", spy), \
                    mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as caught:
                sg.main()
            self.assertEqual(caught.exception.code, 42, argv)
            self.assertIn("git", seen, argv)

    # --- repo validation, real git --------------------------------------------

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_bare_flag_resolves_head_and_explicit_refs_resolve(self):
        root = self._repo()
        first = self._rev(root)
        subprocess.run(["git", "-C", str(root), "tag", "v1"],
                       check=True, capture_output=True, env=_git_env())
        subprocess.run(["git", "-C", str(root), "branch", "keep"],
                       check=True, capture_output=True, env=_git_env())
        subprocess.run(["git", "-C", str(root), "-c", "user.name=t",
                        "-c", "user.email=t@t.invalid", "commit", "-q",
                        "--allow-empty", "-m", "second"], check=True, capture_output=True,
                       env=_git_env())
        head = self._rev(root)
        with self._cwd(root):
            bare = sg._checkout_spec("HEAD", self.git_profile(), [])
            self.assertEqual(bare["base"], head)
            for ref in ("v1", "keep", first, first[:10]):    # tag, branch, sha, short sha
                spec = sg._checkout_spec(ref, self.git_profile(), [])
                self.assertEqual(spec["base"], first, ref)
                self.assertEqual(spec["checkout"], ref)
        self.assertEqual(Path(bare["git_dir"]), (root / ".git").resolve())
        self.assertEqual(Path(bare["repo_root"]), root.resolve())
        self.assertNotIn("branch", bare)
        self.assertNotIn("workspace_derived", bare)

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_a_bad_ref_dies_naming_it(self):
        with self._cwd(self._repo()):
            message = self.refuses("cannot resolve", sg._checkout_spec, "nope",
                                   self.git_profile(), [])
        self.assertIn("'nope'", message)

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_checkout_spec_dies_outside_a_repo(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        with self._cwd(empty):
            self.refuses("inside a git work tree", sg._checkout_spec, "HEAD",
                         self.git_profile(), [])

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_checkout_leaves_info_exclude_alone(self):
        # No host directory is created, so no .silkgate/ exclusion either.
        root = self._repo()
        with self._cwd(root):
            sg._checkout_spec("HEAD", self.git_profile(), [])
        exclude = root / ".git" / "info" / "exclude"
        self.assertNotIn(".silkgate/",
                         exclude.read_text().splitlines() if exclude.is_file() else [])

    # --- composition with --branch ---------------------------------------------

    @unittest.skipUnless(shutil.which("git"), "these drive a real repository")
    def test_branch_base_is_the_checkout_ref_or_head(self):
        root = self._repo()
        first = self._rev(root)
        subprocess.run(["git", "-C", str(root), "-c", "user.name=t",
                        "-c", "user.email=t@t.invalid", "commit", "-q",
                        "--allow-empty", "-m", "second"], check=True, capture_output=True,
                       env=_git_env())
        head = self._rev(root)
        with self._cwd(root):
            based = sg._branch_spec("agent/x", self.git_profile(), [], first)
            plain = sg._branch_spec("agent/y", self.git_profile(), [])
        self.assertEqual(based["base"], first)
        self.assertEqual(plain["base"], head)

    def test_run_wires_the_checkout_ref_into_branch_spec(self):
        seen = {}

        def spy(branch, profiles, env, ref="HEAD"):
            seen["branch"], seen["ref"] = branch, ref
            raise SystemExit(42)

        for argv, ref in ((["run", "--with", "git", "--branch", "nb",
                            "--checkout", "abc123", "--", "true"], "abc123"),
                          (["run", "--with", "git", "--branch", "nb", "--", "true"], "HEAD")):
            with mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                    mock.patch.object(sg, "_branch_spec", spy), \
                    self.no_preflight(), self.assertRaises(SystemExit) as caught:
                sg.main()
            self.assertEqual(caught.exception.code, 42, argv)
            self.assertEqual((seen["branch"], seen["ref"]), ("nb", ref), argv)

    # --- mounts and provisioning -------------------------------------------------

    def test_checkout_workspace_mounts(self):
        root = self.tmp / "proj"
        (root / ".git").mkdir(parents=True)
        spec = {"checkout": "HEAD", "git_dir": str(root / ".git"), "base": "0" * 40,
                "repo_root": str(root)}
        mounts = sg._checkout_workspace(spec)
        self.assertEqual(mounts, [f"{root / '.git'}:/silkgate/base.git:ro"])
        self.assertFalse(any("/workspace" in m for m in mounts), "no /workspace mount")
        (root / ".git" / "lfs").mkdir()
        self.assertIn(f"{root / '.git' / 'lfs'}:/root/lfsstore:rw",
                      sg._checkout_workspace(spec))

    def test_checkout_session_provisions_without_workspace(self):
        fake = {"checkout": "v1", "git_dir": "/g/.git", "base": "0" * 40, "repo_root": "/g"}
        with mock.patch.object(sg, "_checkout_spec", lambda *a: fake):
            seen = self.provision_capture(["run", "--with", "git", "--checkout", "v1",
                                           "--", "true"])
        self.assertEqual(seen["mounts"], ["/g/.git:/silkgate/base.git:ro"])
        self.assertIsNone(seen["ws"])
        self.assertEqual(seen["env"], [], "no GIT_DIR/GIT_WORK_TREE pair for a checkout")
        self.assertEqual(seen["meta"]["checkout"], "v1")
        self.assertEqual(seen["meta"]["base"], "0" * 40)
        self.assertNotIn("branch", seen["meta"])
        self.assertNotIn("workspace_derived", seen["meta"])
        self.assertIn("disposable checkout of the project at\n`v1`", seen["context"])
        self.assertIn("Put your results in printed output", seen["context"])

    # --- a branchless session at harvest/down -------------------------------------

    def plant_checkout_meta(self, name):
        sdir = sg.SESSIONS_DIR / name
        sdir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, sdir, ignore_errors=True)
        (sdir / "meta.json").write_text(json.dumps(
            {"name": name, "sandbox": f"sg-{name}", "port": 8090, "checkout": "HEAD",
             "base": "0" * 40, "git_dir": "/nowhere/.git", "repo_root": "/nowhere"}))

    def test_harvest_refuses_a_checkout_session(self):
        self.plant_checkout_meta("co9aa")
        args = mock.Mock()
        args.name = "co9aa"
        with self.no_preflight():
            self.refuses("no --branch", sg.cmd_harvest, args)

    def test_down_on_a_checkout_session_harvests_and_reaps_nothing(self):
        self.plant_checkout_meta("co8bb")
        calls = []
        args = mock.Mock()
        args.name = "co8bb"
        with self.no_preflight(), \
                mock.patch.object(sg, "_harvest_branch",
                                  lambda meta: calls.append("harvest") or True), \
                mock.patch.object(sg, "_reap_derived_workspace",
                                  lambda meta: calls.append("reap")), \
                mock.patch.object(sg, "_teardown_session",
                                  lambda meta: calls.append("teardown")), \
                contextlib.redirect_stderr(io.StringIO()):
            sg.cmd_down(args)
        self.assertEqual(calls, ["teardown"])


class TestGithubGrants(CliCase):
    """--github-read/--github-write: validation, rule generation, wiring, guest config."""

    # --- OWNER/REPO validation ---

    def test_good_repo_names_accepted(self):
        for good in ("owner/repo", "Org.Name/My.Repo-1", "a/b", "x_y/z_w",
                     "owner-1/repo.2", "O/R"):
            self.assertEqual(sg._github_repo_arg(good), good)

    def test_bad_repo_names_refused(self):
        import argparse as ap_mod
        for bad in ("noslash", "a/b/c", "../x", "/repo", "owner/",
                    "", "a b/c", "a/b c"):
            with self.assertRaises(ap_mod.ArgumentTypeError, msg=f"should reject {bad!r}"):
                sg._github_repo_arg(bad)

    def test_bad_repo_via_flag(self):
        for bad in ("noslash", "a/b/c", "../evil"):
            self.refuses_argv("OWNER/REPO", "--github-read",
                              ["run", "--with", "git", "--github-read", bad, "--", "true"])

    # --- rule generation: inspect parsed ruleset ---

    def _read_ruleset(self, read_repos, write_repos=None):
        rules = sg._github_rules(read_repos, write_repos or [])
        return sg.RuleSet.parse("\n".join(rules) + "\n")

    def test_read_rules_control_hosts_have_inject_auth(self):
        rs = self._read_ruleset(["owner/repo"])
        for prefix in ("github.com/owner/repo/",
                        "github.com/owner/repo.git/",
                        "lfs.github.com/owner/repo/",
                        "api.github.com/repos/owner/repo/"):
            rule = next((r for r in rs.rules if r.raw.startswith(prefix)), None)
            self.assertIsNotNone(rule, f"missing rule for {prefix}")
            self.assertEqual(rule.inject_auth, "github",
                             f"rule for {prefix} must inject github token")

    def test_read_rules_storage_hosts_have_no_inject_auth(self):
        rs = self._read_ruleset(["owner/repo"])
        cdn = next(r for r in rs.rules
                   if r.raw.startswith("github-cloud.githubusercontent.com"))
        self.assertIsNone(cdn.inject_auth, "download storage must not inject auth")
        self.assertTrue(cdn.allow_query, "download storage must pass query string")

    def test_read_rules_no_s3_upload_rule(self):
        rs = self._read_ruleset(["owner/repo"])
        s3 = [r for r in rs.rules if "s3.amazonaws.com" in r.raw]
        self.assertEqual(s3, [], "read grant must not include s3 upload rule")

    def test_read_api_is_get_only(self):
        rs = self._read_ruleset(["owner/repo"])
        api = next(r for r in rs.rules
                   if r.raw.startswith("api.github.com/repos/owner/repo/"))
        self.assertIn("GET", api.methods)
        self.assertNotIn("POST", api.methods)
        self.assertNotIn("PATCH", api.methods)
        self.assertNotIn("DELETE", api.methods)

    def test_write_rules_include_s3_upload(self):
        rs = self._read_ruleset([], ["owner/repo"])
        s3 = next((r for r in rs.rules if "s3.amazonaws.com" in r.raw), None)
        self.assertIsNotNone(s3, "write grant must include s3 upload rule")
        self.assertIn("PUT", s3.methods)
        self.assertIsNone(s3.inject_auth, "s3 upload must not inject auth")
        self.assertTrue(s3.allow_query, "s3 upload must pass query string")

    def test_write_api_includes_mutations(self):
        rs = self._read_ruleset([], ["owner/repo"])
        api = next(r for r in rs.rules
                   if r.raw.startswith("api.github.com/repos/owner/repo/"))
        for method in ("GET", "POST", "PATCH", "DELETE"):
            self.assertIn(method, api.methods, f"write API rule missing {method}")

    def test_write_supersedes_read_for_same_repo(self):
        rs = self._read_ruleset(["a/b"], ["a/b"])
        api_rules = [r for r in rs.rules
                     if r.raw.startswith("api.github.com/repos/a/b/")]
        self.assertEqual(len(api_rules), 1, "write must supersede read — no duplicate api rule")
        self.assertIn("POST", api_rules[0].methods, "superseded rule must be the write variant")

    def test_two_repos_produce_per_repo_rules(self):
        rs = self._read_ruleset(["org/a"], ["org/b"])
        prefixes_ab = [r.raw for r in rs.rules if "org/a" in r.raw]
        prefixes_bb = [r.raw for r in rs.rules if "org/b" in r.raw]
        self.assertTrue(len(prefixes_ab) >= 1)
        self.assertTrue(len(prefixes_bb) >= 1)

    def test_no_rules_for_empty_grants(self):
        self.assertEqual(sg._github_rules([], []), [])

    # --- wiring: flags reach run and up ---

    def test_run_and_up_wire_github_flags(self):
        """Both run and up pass --github-read/--github-write into _session_policy."""
        cases = [
            ["run", "--with", "git", "--github-read", "a/b",
             "--github-write", "c/d", "--", "true"],
            ["up", "--name", "u1", "--with", "git", "--github-read", "a/b",
             "--github-write", "c/d"],
        ]
        for argv in cases:
            seen = {}

            def spy(args_, _seen=seen):
                _seen["read"] = getattr(args_, "github_read", None)
                _seen["write"] = getattr(args_, "github_write", None)
                raise SystemExit(42)

            with mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                    mock.patch.object(sg, "_session_policy", spy), \
                    self.no_preflight(), self.assertRaises(SystemExit) as caught:
                sg.main()
            self.assertEqual(caught.exception.code, 42, f"argv={argv!r}")
            self.assertEqual(seen["read"], ["a/b"], f"argv={argv!r}")
            self.assertEqual(seen["write"], ["c/d"], f"argv={argv!r}")

    # --- requires --with git ---

    def test_github_grant_without_git_profile_refused(self):
        for argv in (
            ["run", "--github-read", "a/b", "--", "true"],
            ["run", "--github-write", "a/b", "--", "true"],
            ["up", "--name", "u2", "--github-read", "a/b"],
            ["up", "--name", "u2", "--github-write", "a/b"],
        ):
            with mock.patch.object(sys, "argv", ["silkgate"] + argv), \
                    self.no_preflight():
                self.refuses("--with git", sg.main)

    # --- guest git-config: URL-scoped per host, no global http.extraheader ---

    def test_github_gitconfig_sh_sets_url_scoped_headers(self):
        sh = sg._GITHUB_GITCONFIG_SH
        for host_url in ("https://github.com/", "https://lfs.github.com/",
                         "https://api.github.com/"):
            self.assertIn(host_url, sh,
                          f"gitconfig must set URL-scoped header for {host_url}")

    def test_github_gitconfig_sh_no_global_extraheader(self):
        """A bare http.extraheader would bleed the dummy token onto github-cloud.*
        storage requests that carry their own AWS SigV4, causing S3 to return 501."""
        sh = sg._GITHUB_GITCONFIG_SH
        # URL-scoped keys look like http.https://github.com/.extraHeader — that substring
        # does not contain the bare 'http.extraheader' pattern.
        self.assertNotIn("http.extraheader", sh.lower(),
                         "must not set bare http.extraheader (use URL-scoped form only)")

    def test_github_gitconfig_sh_does_not_touch_storage_hosts(self):
        sh = sg._GITHUB_GITCONFIG_SH
        self.assertNotIn("s3.amazonaws.com", sh,
                         "s3 storage host must not appear in gitconfig setup")
        self.assertNotIn("githubusercontent.com", sh,
                         "cdn storage host must not appear in gitconfig setup")

    # --- session_context: grants surface in the Injected credentials section ---

    def _github_ctx(self):
        ruleset = sg.load_ruleset("\n".join(sg._github_rules(["a/b"], [])) + "\n")
        return sg.session_context([], ruleset, persistent=False,
                                  github_read=["a/b"])

    def test_session_context_github_grant_reports_missing_secret(self):
        """The warn-not-die contract: a launch without the github secret still hands the
        guest a context that names the grant AND its unusable credential."""
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("SILKGATE_EGRESS_SECRET_")}
        with mock.patch.dict(os.environ, env, clear=True):
            ctx = self._github_ctx()
        self.assertIn("## GitHub access", ctx)
        self.assertIn("inject_auth=github", ctx)
        self.assertIn("Missing or malformed", ctx)

    def test_session_context_github_grant_reports_available_secret(self):
        with mock.patch.dict(os.environ,
                             {"SILKGATE_EGRESS_SECRET_GITHUB": "Authorization: Basic abc"}):
            ctx = self._github_ctx()
        self.assertIn("## GitHub access", ctx)
        self.assertIn("inject_auth=github", ctx)
        self.assertIn("Available", ctx)

    # --- read_meta hardening ---

    def _plant_meta(self, name, **extra):
        sdir = sg.SESSIONS_DIR / name
        sdir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, sdir, ignore_errors=True)
        (sdir / "meta.json").write_text(json.dumps(
            {"name": name, "sandbox": f"sg-{name}", **extra}))

    def test_read_meta_refuses_traversal_in_github_read(self):
        self._plant_meta("ghr1aa", github_read=["../evil"])
        self.refuses("refusing it", sg.read_meta, "ghr1aa")

    def test_read_meta_refuses_multi_slash_in_github_write(self):
        self._plant_meta("ghw2bb", github_write=["a/b/c"])
        self.refuses("refusing it", sg.read_meta, "ghw2bb")

    def test_read_meta_refuses_non_list_github_field(self):
        self._plant_meta("ghn3cc", github_read="owner/repo")
        self.refuses("refusing it", sg.read_meta, "ghn3cc")

    def test_read_meta_accepts_valid_github_fields(self):
        self._plant_meta("ghv4dd", github_read=["owner/repo"], github_write=["org/proj"])
        meta = sg.read_meta("ghv4dd")
        self.assertEqual(meta["github_read"], ["owner/repo"])
        self.assertEqual(meta["github_write"], ["org/proj"])


class TestMountProvisioning(CliCase):
    """What run/up hand _provision_session for -v mounts: the :MODE suffix in the msb
    list is the whole enforcement, and the meta `mounts` list is what ls and the guest
    brief stand on — so both are proven through main(), not by calling _mount_args."""

    def test_mounts_reach_msb_meta_and_brief(self):
        project = self.tmp / "project"
        project.mkdir()
        for argv in (["run", "-v", f"{project}:/data", "-v", f"{project}:/workspace:rw",
                      "--", "true"],
                     ["up", "--name", "prov1", "-v", f"{project}:/data",
                      "-v", f"{project}:/workspace:rw"]):
            seen = self.provision_capture(argv)
            expected = [f"{project}:/data:ro", f"{project}:/workspace:rw"]
            self.assertEqual(seen["mounts"], expected, argv)
            self.assertEqual(seen["meta"]["mounts"], expected, argv)
            self.assertIsNone(seen["ws"], argv)
            self.assertIn("read-write, and a directory on the host", seen["context"], argv)
            self.assertIn("`/data` — read-only", seen["context"], argv)

    def test_no_mounts_records_no_mounts_key(self):
        seen = self.provision_capture(["run", "--", "true"])
        self.assertEqual(seen["mounts"], [])
        self.assertNotIn("mounts", seen["meta"])
        self.assertIn("No host directory is mounted", seen["context"])


class TestGuestBriefMounts(CliCase):
    """session_context keys the /workspace sentence on the mount at /workspace and lists
    every other mount with its mode."""

    def ctx(self, mounts, branch=None, checkout=None):
        return sg.session_context([], sg.load_ruleset(""), mounts=mounts,
                                  persistent=False, branch=branch, checkout=checkout)

    def test_workspace_rw_text(self):
        ctx = self.ctx([("/h/p", "/workspace", "rw")])
        self.assertIn("read-write, and a directory on the host", ctx)

    def test_workspace_ro_text(self):
        ctx = self.ctx([("/h/p", "/workspace", "ro")])
        self.assertIn("`/workspace` is read-only", ctx)
        self.assertIn("is host code, and writes to it fail", ctx)
        self.assertIn("Put your results in printed output", ctx)

    def test_no_mounts_text(self):
        self.assertIn("Nothing you write survives this machine", self.ctx([]))

    def test_other_mounts_listed_with_modes(self):
        ctx = self.ctx([("/h/a", "/data", "ro"), ("/h/b", "/out", "rw")])
        self.assertIn("no host directory is mounted there", ctx)
        self.assertIn("`/data` — read-only", ctx)
        self.assertIn("`/out` — read-write", ctx)

    def test_branch_text_wins_and_other_mounts_still_listed(self):
        ctx = self.ctx([("/h/a", "/data", "ro")], branch="agent/x")
        self.assertIn("Commit your work to branch `agent/x`", ctx)
        self.assertIn("commits are the\ndeliverable", ctx)
        self.assertIn("`/data` — read-only", ctx)

    def test_checkout_text(self):
        ctx = self.ctx([], checkout="v1.2")
        self.assertIn("disposable checkout of the project at\n`v1.2`", ctx)
        self.assertIn("Put your results in printed output", ctx)
        self.assertIn("No remote accepts a push", ctx)
        self.assertIn("`git fetch origin` and `git log` work", ctx)

    def test_branch_text_wins_over_the_checkout_base(self):
        # --branch --checkout REF: REF is the base, the session is still a branch one.
        ctx = self.ctx([], branch="agent/x", checkout="v1.2")
        self.assertIn("Commit your work to branch `agent/x`", ctx)
        self.assertNotIn("disposable checkout", ctx)


class TestGuestBriefEgress(CliCase):
    """The egress half of the guest brief: the injected-rule marker, the glob legend,
    the 500 action, and the report channel."""

    def ctx(self, rules="api.anthropic.com/v1/** POST inject_auth=anthropic\n"):
        return sg.session_context([], sg.load_ruleset(rules), persistent=False)

    def test_injected_rule_carries_the_marker(self):
        self.assertIn("- `api.anthropic.com/v1/**` — POST — injects `anthropic`",
                      self.ctx())

    def test_plain_rule_carries_no_marker(self):
        self.assertNotIn("injects", self.ctx("api.anthropic.com/v1/** POST\n"))

    def test_the_silkgate_500_has_an_action(self):
        ctx = self.ctx()
        self.assertIn("Do not retry it in a loop", ctx)
        self.assertIn("Report it, with the\nrequest that caused it", ctx)

    def test_glob_legend_sits_under_the_reachable_list(self):
        ctx = self.ctx()
        self.assertIn("`*` matches one DNS label in a host and one path segment", ctx)
        self.assertIn("dots in a host, slashes in a path, or an empty path", ctx)

    def test_empty_allowlist_has_no_glob_legend(self):
        # No rules, no patterns — a legend under an empty list would explain nothing.
        self.assertNotIn("DNS label", self.ctx(""))

    def test_the_report_channel_is_defined(self):
        self.assertIn("Printed output reaches whoever\nset your task — that is the "
                      "channel", self.ctx())


if __name__ == "__main__":
    unittest.main()
