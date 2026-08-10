#!/usr/bin/env python3
"""Host-side ingest tests for --branch: real repositories, real bundles, no guest.

    python3 test/test_cli_branch_ingest.py [-v]

The guest seam (_bundle_in_guest) is one subprocess into msb, so tests that need it stub it;
everything below — the fetch under fsck, the ancestry rule, the compare-and-swap promote,
staging-ref hygiene, meta idempotence — runs against real git repositories in a scratch tree.
The one rule under test: a branch only ever fast-forwards, and refused commits stay reachable
at the session's staging ref.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent

if shutil.which("git") is None:
    raise unittest.SkipTest("git is not installed — the ingest tests drive real repositories")


def _load_cli():
    loader = importlib.machinery.SourceFileLoader("silkgate_cli_ingest",
                                                  str(REPO / "cli" / "silkgate"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


sg = _load_cli()

# Everything the CLI would write lives under one scratch tree for the whole run.
_SCRATCH = Path(tempfile.mkdtemp(prefix="silkgate-ingest-tests-"))
sg.SILK_DIR = _SCRATCH / "silkgate"
sg.SESSIONS_DIR = sg.SILK_DIR / "sessions"


def tearDownModule():
    shutil.rmtree(_SCRATCH, ignore_errors=True)


def _git_env():
    """os.environ with every GIT_* override dropped (git honors far more than GIT_DIR —
    GIT_OBJECT_DIRECTORY, GIT_COMMON_DIR, GIT_CEILING_DIRECTORIES, ...) and config pinned
    to nothing, so fixture git sees only its own temp repos and the -c flags below.
    GIT_EXEC_PATH stays: some installs need it to find git's subcommands at all."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") or k == "GIT_EXEC_PATH"}
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def _git(*argv, cwd=None):
    proc = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                           "-c", "init.defaultBranch=main", *argv],
                          capture_output=True, text=True, cwd=cwd, env=_git_env())
    if proc.returncode:
        raise AssertionError(f"fixture git {argv} failed: {proc.stderr}")
    return proc.stdout.strip()


class IngestCase(unittest.TestCase):
    """One host repo and one 'guest' clone per test, plus the meta a branch session writes."""

    NAME = "abc123"
    BRANCH = "agent/feature"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=_SCRATCH)).resolve()
        self.host = self.tmp / "host"
        _git("init", "-q", str(self.host))
        (self.host / "seed.txt").write_text("seed\n")
        _git("add", "seed.txt", cwd=self.host)
        _git("commit", "-qm", "seed", cwd=self.host)
        self.base = _git("rev-parse", "HEAD", cwd=self.host)
        self.git_dir = str((self.host / ".git").resolve())
        # The 'guest': a clone working the branch, standing in for /root/gitdir.
        self.guest = self.tmp / "guest"
        _git("clone", "-q", str(self.host), str(self.guest))
        _git("checkout", "-qb", self.BRANCH, self.base, cwd=self.guest)
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def meta(self, **extra):
        return {"name": self.NAME, "sandbox": f"sg-{self.NAME}", "branch": self.BRANCH,
                "git_dir": self.git_dir, "base": self.base,
                "repo_root": str(self.host.resolve()), "workspace": str(self.ws),
                "workspace_derived": True, **extra}

    def commit(self, msg, exe=False):
        path = self.guest / f"{msg}.txt"
        path.write_text(msg + "\n")
        if exe:
            path.chmod(0o755)
        _git("add", path.name, cwd=self.guest)
        _git("commit", "-qm", msg, cwd=self.guest)
        return _git("rev-parse", "HEAD", cwd=self.guest)

    def bundle(self):
        out = self.ws / ".silkgate.bundle"
        out.unlink(missing_ok=True)
        _git("bundle", "create", "--quiet", str(out),
             f"{self.base}..refs/heads/{self.BRANCH}", cwd=self.guest)
        return out, _git("rev-parse", f"refs/heads/{self.BRANCH}", cwd=self.guest)

    def ingest(self, meta, bundle, tip):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ok = sg._ingest_bundle(meta, bundle, tip)
        return ok, err.getvalue()

    def host_ref(self, ref):
        proc = subprocess.run(["git", "--git-dir", self.git_dir, "rev-parse", "--verify",
                               ref], capture_output=True, text=True, env=_git_env())
        return proc.stdout.strip() if proc.returncode == 0 else None

    def staging(self):
        return self.host_ref(f"refs/silkgate/{self.NAME}/{self.BRANCH}")


class TestFirstHarvest(IngestCase):

    def test_happy_path_creates_the_branch(self):
        tip = self.commit("one")
        self.commit("two")
        bundle, tip = self.bundle()
        ok, err = self.ingest(self.meta(), bundle, tip)
        self.assertTrue(ok, err)
        self.assertEqual(self.host_ref(f"refs/heads/{self.BRANCH}"), tip)
        self.assertIsNone(self.staging(), "the staging ref is deleted after a promote")
        self.assertIn("2 commit(s)", err)

    def test_exec_bit_survives_the_bundle(self):
        self.commit("tool", exe=True)
        bundle, tip = self.bundle()
        ok, _ = self.ingest(self.meta(), bundle, tip)
        self.assertTrue(ok)
        mode = _git("ls-tree", tip, "tool.txt", cwd=self.host).split()[0]
        self.assertEqual(mode, "100755", "the mode rides in the tree — the ritual this kills")

    def test_existing_branch_is_never_moved(self):
        _git("branch", self.BRANCH, self.base, cwd=self.host)
        tip = self.commit("one")
        bundle, tip = self.bundle()
        ok, err = self.ingest(self.meta(), bundle, tip)
        self.assertFalse(ok)
        self.assertEqual(self.host_ref(f"refs/heads/{self.BRANCH}"), self.base,
                         "the pre-existing branch is untouched")
        self.assertEqual(self.staging(), tip, "the commits stay reachable at the staging ref")
        self.assertIn("moved since the last harvest", err)

    def test_disjoint_history_is_refused(self):
        _git("checkout", "-q", "--orphan", "rewrite", cwd=self.guest)
        (self.guest / "alien.txt").write_text("alien\n")
        _git("add", "-A", cwd=self.guest)
        _git("commit", "-qm", "alien", cwd=self.guest)
        _git("branch", "-Df", self.BRANCH, cwd=self.guest)
        _git("branch", self.BRANCH, cwd=self.guest)
        bundle, tip = self.bundle()
        ok, err = self.ingest(self.meta(), bundle, tip)
        self.assertFalse(ok)
        self.assertIsNone(self.host_ref(f"refs/heads/{self.BRANCH}"))
        self.assertEqual(self.staging(), tip)
        self.assertIn("descend from the base commit", err)

    def test_corrupt_bundle_fails_verify(self):
        self.commit("one")
        bundle, tip = self.bundle()
        bundle.write_bytes(b"# v2 git bundle\ngarbage\n")
        ok, err = self.ingest(self.meta(), bundle, tip)
        self.assertFalse(ok)
        self.assertIn("does not verify", err)

    def test_tip_mismatch_is_refused(self):
        self.commit("one")
        bundle, tip = self.bundle()
        ok, err = self.ingest(self.meta(), bundle, self.base)
        self.assertFalse(ok)
        self.assertIn("not what the guest bundled", err)
        self.assertIsNone(self.host_ref(f"refs/heads/{self.BRANCH}"))

    def test_missing_bundle_is_refused(self):
        ok, err = self.ingest(self.meta(), self.ws / ".silkgate.bundle", self.base)
        self.assertFalse(ok)
        self.assertIn("never landed", err)

    def test_stale_staging_ref_self_heals(self):
        # A crashed prior run leaves a staging ref behind; the + refspec overwrites it.
        self.commit("junk")
        subprocess.run(["git", "--git-dir", self.git_dir, "fetch", "-q", str(self.guest),
                        f"+refs/heads/{self.BRANCH}:refs/silkgate/{self.NAME}/{self.BRANCH}"],
                       check=True, capture_output=True, env=_git_env())
        tip = self.commit("real")
        bundle, tip = self.bundle()
        ok, err = self.ingest(self.meta(), bundle, tip)
        self.assertTrue(ok, err)
        self.assertEqual(self.host_ref(f"refs/heads/{self.BRANCH}"), tip)

    def test_meta_records_the_ingested_tip(self):
        sdir = sg.SESSIONS_DIR / self.NAME
        sdir.mkdir(parents=True)
        (sdir / "meta.json").write_text(json.dumps(self.meta()))
        self.addCleanup(shutil.rmtree, sdir, ignore_errors=True)
        self.commit("one")
        bundle, tip = self.bundle()
        meta = self.meta()
        ok, _ = self.ingest(meta, bundle, tip)
        self.assertTrue(ok)
        self.assertEqual(json.loads((sdir / "meta.json").read_text())["branch_ingested"], tip)
        self.assertEqual(meta["branch_ingested"], tip, "the in-memory meta learns it too")


class TestLaterHarvests(IngestCase):
    """The fast-forward-only rule, across a first harvest and everything after it."""

    def first_harvest(self):
        self.t1 = self.commit("one")
        bundle, tip = self.bundle()
        ok, err = self.ingest(self.meta(), bundle, tip)
        self.assertTrue(ok, err)
        return self.meta(branch_ingested=self.t1)

    def test_new_commits_fast_forward(self):
        meta = self.first_harvest()
        t2 = self.commit("two")
        bundle, tip = self.bundle()
        ok, err = self.ingest(meta, bundle, tip)
        self.assertTrue(ok, err)
        self.assertEqual(self.host_ref(f"refs/heads/{self.BRANCH}"), t2)

    def test_rewritten_history_is_refused(self):
        """A rewritten tip still descends from the base and still matches the CAS old
        value — only the ancestry-against-last-harvest rule catches it."""
        meta = self.first_harvest()
        _git("commit", "-q", "--amend", "-m", "one, rewritten", cwd=self.guest)
        bundle, tip = self.bundle()
        ok, err = self.ingest(meta, bundle, tip)
        self.assertFalse(ok)
        self.assertEqual(self.host_ref(f"refs/heads/{self.BRANCH}"), self.t1,
                         "the branch stays at the harvested tip")
        self.assertEqual(self.staging(), tip)
        self.assertIn("fast-forward the last harvested tip", err)

    def test_host_branch_moved_by_someone_else_is_refused(self):
        meta = self.first_harvest()
        _git("update-ref", f"refs/heads/{self.BRANCH}", self.base, cwd=self.host)
        t2 = self.commit("two")
        bundle, tip = self.bundle()
        ok, err = self.ingest(meta, bundle, tip)
        self.assertFalse(ok)
        self.assertEqual(self.host_ref(f"refs/heads/{self.BRANCH}"), self.base,
                         "whoever moved the branch keeps it")
        self.assertEqual(self.staging(), tip)
        self.assertIn("moved since the last harvest", err)


class TestHarvestDispatch(IngestCase):
    """_harvest_branch's token protocol, with the guest seam stubbed."""

    def dispatch(self, token, detail="", **meta_extra):
        meta = self.meta(**meta_extra)
        err = io.StringIO()
        with mock.patch.object(sg, "_bundle_in_guest", lambda m: (token, detail)), \
                contextlib.redirect_stderr(err):
            ok = sg._harvest_branch(meta)
        return ok, err.getvalue()

    def test_no_commits_is_a_quiet_success(self):
        ok, err = self.dispatch("SILKGATE_NO_COMMITS")
        self.assertTrue(ok)
        self.assertIn("since the base commit", err)
        self.assertIsNone(self.host_ref(f"refs/heads/{self.BRANCH}"))

    def test_nothing_new_since_last_harvest(self):
        ok, err = self.dispatch("SILKGATE_NO_COMMITS", branch_ingested=self.base)
        self.assertTrue(ok)
        self.assertIn("since the last harvest", err)

    def test_deleted_branch_is_an_explicit_no(self):
        ok, err = self.dispatch("SILKGATE_NO_BRANCH")
        self.assertTrue(ok)
        self.assertIn("deleted branch", err)

    def test_unreachable_guest_keeps_the_workspace(self):
        ok, err = self.dispatch("SILKGATE_ERROR", "timed out")
        self.assertFalse(ok)
        self.assertIn("could not harvest", err)

    def test_unreachable_guest_after_a_harvest_names_the_banked_state(self):
        ok, err = self.dispatch("SILKGATE_ERROR", "timed out", branch_ingested=self.base)
        self.assertFalse(ok)
        self.assertIn("last harvested state", err)

    def test_bundled_token_routes_into_ingest(self):
        tip = self.commit("one")
        self.bundle()
        ok, err = self.dispatch("SILKGATE_BUNDLED", tip)
        self.assertTrue(ok, err)
        self.assertEqual(self.host_ref(f"refs/heads/{self.BRANCH}"), tip)


class TestWorktreeHost(IngestCase):
    """A host repo driven from a linked worktree: the ingest lands in the common gitdir."""

    def test_ingest_from_a_worktree_repo(self):
        wt = self.tmp / "wt"
        _git("worktree", "add", "-q", "--detach", str(wt), cwd=self.host)
        tip = self.commit("one")
        bundle, tip = self.bundle()
        ok, err = self.ingest(self.meta(), bundle, tip)
        self.assertTrue(ok, err)
        self.assertEqual(_git("rev-parse", f"refs/heads/{self.BRANCH}", cwd=wt), tip,
                         "the branch is visible from the linked worktree too")


if __name__ == "__main__":
    unittest.main()
