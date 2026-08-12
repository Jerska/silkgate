#!/usr/bin/env python3
"""Durable-session tests for cli/silkgate: the journal, the archive, --brief, the meta
additions and the exec marker in the relay.

    python3 test/test_cli_journal.py [-v]

Stdlib only, no docker/msb/mitmproxy: the msb seams (_remove_sandbox, _run_msb_logs,
subprocess into msb/mitmdump) are stubbed, following test_cli_branch_ingest.py. The
module's state paths derive from $HOME at import time, so they are repointed at a
scratch tree below — ARCHIVE_DIR included — before any test runs. Nothing here may
touch a real ~/.silkgate: live sessions use it.
"""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent


def _load_cli():
    loader = importlib.machinery.SourceFileLoader("silkgate_cli_journal",
                                                  str(REPO / "cli" / "silkgate"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


sg = _load_cli()

# Everything the CLI would write lives under one scratch tree for the whole run.
_SCRATCH = Path(tempfile.mkdtemp(prefix="silkgate-journal-tests-"))
sg.SILK_DIR = _SCRATCH / "silkgate"
sg.SESSIONS_DIR = sg.SILK_DIR / "sessions"
sg.ARCHIVE_DIR = sg.SILK_DIR / "archive"
sg.LOG_DIR = sg.SILK_DIR / "logs"
sg.CA_DIR = sg.SILK_DIR / "ca"
sg.PROXY_JSON = sg.SILK_DIR / "proxy.json"
sg.PROXY_SOCK = sg.SILK_DIR / "proxy.sock"

for _knob in ("SILKGATE_LOG_RETAIN_DAYS", "SILKGATE_CAPTURE_RETAIN_DAYS",
              "SILKGATE_ARCHIVE_RETAIN_DAYS"):
    os.environ.pop(_knob, None)

RULE = "api.anthropic.com/** GET\n"


def tearDownModule():
    shutil.rmtree(_SCRATCH, ignore_errors=True)


class JournalCase(unittest.TestCase):
    """Shared fixture: fresh registry/archive dirs and the refusal assertion."""

    def setUp(self):
        self.assertTrue(str(sg.SESSIONS_DIR).startswith(str(_SCRATCH)),
                        "tests must never point at a real ~/.silkgate")
        self.tmp = Path(tempfile.mkdtemp(dir=_SCRATCH))
        sg.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        sg.ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, sg.SESSIONS_DIR, ignore_errors=True)
        self.addCleanup(shutil.rmtree, sg.ARCHIVE_DIR, ignore_errors=True)

    def refuses(self, needle, fn, *args, **kwargs):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            fn(*args, **kwargs)
        self.assertNotEqual(caught.exception.code, 0)
        self.assertIn(needle, err.getvalue())
        return err.getvalue()

    def write_session(self, name, sid=None, **extra):
        sdir = sg.session_dir(name)
        sdir.mkdir(parents=True)
        (sdir / "rules.txt").write_text(RULE)
        meta = {"name": name, "sandbox": f"sg-{name}", "port": 8090, **extra}
        if sid is not None:
            meta["sid"] = sid
        sg._write_json(sdir / "meta.json", meta)
        return meta

    def journal_events(self, path):
        return [rec.get("event") for rec in sg._read_journal(path)]


# -- the journal helper ---------------------------------------------------------

class TestJournal(JournalCase):

    def test_appends_parseable_lines(self):
        self.write_session("j1")
        sg._journal("j1", "exec_start", exec_id="cafe1234", argv=["echo", "hi"],
                    tty=False, env_names=["FOO"], via="exec")
        sg._journal("j1", "exec_end", exec_id="cafe1234", rc=0)
        records = sg._read_journal(sg.session_dir("j1") / "journal.jsonl")
        self.assertEqual([r["event"] for r in records], ["exec_start", "exec_end"])
        for rec in records:
            self.assertIn("ts", rec)
            self.assertEqual(rec["exec_id"], "cafe1234")
        self.assertEqual(records[0]["argv"], ["echo", "hi"])
        self.assertEqual(records[1]["rc"], 0)

    def test_journal_file_is_private(self):
        self.write_session("j2")
        sg._journal("j2", "down")
        mode = (sg.session_dir("j2") / "journal.jsonl").stat().st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600,
                         "exec argv holds the operator's prompt — owner-only")

    def test_unwritable_dir_warns_and_never_raises(self):
        """Pins the fail-open policy: bookkeeping must never block (or crash) the
        operation it records."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            sg._journal("nosuchsession", "down")     # no session dir to write into
        self.assertIn("warning", err.getvalue())
        self.assertIn("could not journal", err.getvalue())

    def test_read_journal_skips_garbage(self):
        self.write_session("j3")
        path = sg.session_dir("j3") / "journal.jsonl"
        good1 = json.dumps({"ts": "t", "event": "created"})
        good2 = json.dumps({"ts": "t", "event": "down"})
        path.write_bytes((good1 + "\n" + '{"ts": "torn' + "\n" + "\xff\xfe garbage\n"
                          + "[1, 2]\n" + "\n" + good2 + "\n").encode("utf-8", "replace"))
        self.assertEqual(self.journal_events(path), ["created", "down"])

    def test_read_journal_missing_file_is_empty(self):
        self.assertEqual(sg._read_journal(self.tmp / "absent.jsonl"), [])


# -- session ids ------------------------------------------------------------------

class TestSid(JournalCase):

    def test_new_sid_matches_the_validator(self):
        sid = sg._new_sid("abc-123")
        self.assertTrue(sg._SID_RE.fullmatch(sid), sid)
        self.assertIn("-abc-123-", sid)

    def test_sids_are_unique(self):
        self.assertNotEqual(sg._new_sid("x"), sg._new_sid("x"))

    def test_sid_re_refuses_what_is_not_a_sid(self):
        for bad in ("", "../etc", "20250101T000000Z-x-zzzzzz",     # not hex
                    "20250101T000000Z--abcdef",                    # empty name
                    "20250101T000000Z-a/b-abcdef",                 # path component
                    "x-20250101T000000Z-abcdef",
                    "20250101T000000Z-" + "a" * 33 + "-abcdef"):   # name over 32
            self.assertIsNone(sg._SID_RE.fullmatch(bad), bad)


# -- archived-meta reads -----------------------------------------------------------

class TestArchivedMetaReads(JournalCase):
    """read_archived_meta holds the archive to read_meta's bar: archived metas reach
    git argv in wave 2, so a planted one is refused, never used."""

    SID = "20250101T000000Z-aaa111-abcdef"

    def plant_archive(self, sid, meta):
        adir = sg.ARCHIVE_DIR / sid
        adir.mkdir(parents=True, exist_ok=True)
        (adir / "meta.json").write_text(json.dumps(meta))

    def meta(self, **extra):
        return {"name": "aaa111", "sandbox": "sg-aaa111", "sid": self.SID, **extra}

    def test_bad_sid_is_refused_before_it_reads_anything(self):
        for bad in ("../aaa", "", "a" * 40, "20250101T000000Z-x-ZZZZZZ"):
            self.refuses("invalid archive sid", sg.read_archived_meta, bad)

    def test_absent_archive_is_none(self):
        self.assertIsNone(sg.read_archived_meta(self.SID))

    def test_meta_must_agree_with_its_directory(self):
        self.plant_archive(self.SID, self.meta(sid="20250101T000000Z-bbb222-abcdef"))
        self.refuses("refusing it", sg.read_archived_meta, self.SID)

    def test_planted_sandbox_is_refused(self):
        self.plant_archive(self.SID, self.meta(sandbox="--net-rule=allow@x"))
        self.refuses("refusing it", sg.read_archived_meta, self.SID)

    def test_planted_branch_is_refused(self):
        self.plant_archive(self.SID, self.meta(branch="-evil", base="0" * 40))
        self.refuses("refusing it", sg.read_archived_meta, self.SID)

    def test_checkout_meta_needs_a_clean_base(self):
        self.plant_archive(self.SID, self.meta(checkout="HEAD", base="not-a-sha"))
        self.refuses("refusing it", sg.read_archived_meta, self.SID)

    def test_git_dir_must_be_a_clean_absolute_path(self):
        for bad in ("relative/.git", "/has\nnewline/.git", "/has\x1b[31mcolor/.git"):
            self.plant_archive(self.SID, self.meta(git_dir=bad))
            self.refuses("refusing it", sg.read_archived_meta, self.SID)

    def test_workspace_must_be_a_clean_absolute_path(self):
        self.plant_archive(self.SID, self.meta(workspace="../../etc"))
        self.refuses("refusing it", sg.read_archived_meta, self.SID)

    def test_wellformed_meta_is_returned(self):
        meta = self.meta(checkout="v1", base="0" * 40, git_dir="/repo/.git",
                         workspace="/repo/.silkgate/sandboxes/aaa111", ended="t")
        self.plant_archive(self.SID, meta)
        self.assertEqual(sg.read_archived_meta(self.SID), meta)

    def test_new_checks_hold_for_live_reads_too(self):
        self.write_session("live1", git_dir="not/absolute")
        self.refuses("refusing it", sg.read_meta, "live1")

    def test_list_archived_metas_is_chronological_and_skips_foreign_dirs(self):
        older = "20240101T000000Z-old-abcdef"
        newer = "20250101T000000Z-new-abcdef"
        self.plant_archive(newer, {"name": "new", "sid": newer})
        self.plant_archive(older, {"name": "old", "sid": older})
        (sg.ARCHIVE_DIR / "not-a-sid").mkdir()
        self.assertEqual([m["sid"] for m in sg.list_archived_metas()], [older, newer])


# -- teardown: the archive lands complete -------------------------------------------

class TestTeardownArchive(JournalCase):

    def teardown(self, meta, *, logs=(["line one", "line two"], None), removed=True,
                 archive=True):
        """_teardown_session with the msb seams stubbed; returns captured stderr."""
        err = io.StringIO()
        with mock.patch.object(sg, "_remove_sandbox", lambda sandbox: removed), \
                mock.patch.object(sg, "_run_msb_logs",
                                  lambda sandbox, tail_n=None, since=None: logs), \
                contextlib.redirect_stderr(err):
            sg._teardown_session(meta, archive=archive)
        return err.getvalue()

    def claim(self, port, name):
        d = sg.SESSIONS_DIR / ".ports"
        d.mkdir(exist_ok=True)
        (d / str(port)).write_text(json.dumps({"name": name, "pid": os.getpid()}))
        return d / str(port)

    def test_archive_lands_complete(self):
        sid = sg._new_sid("t1")
        meta = self.write_session("t1", sid=sid)
        sg._journal("t1", "exec_start", exec_id="cafe1234", argv=["true"], tty=False,
                    env_names=[], via="exec")
        claim = self.claim(8090, "t1")
        self.teardown(meta)
        adir = sg.ARCHIVE_DIR / sid
        self.assertFalse(sg.session_dir("t1").exists())
        self.assertFalse(claim.exists(), "the port claim outlived the session")
        archived = json.loads((adir / "meta.json").read_text())
        self.assertEqual(archived["sid"], sid)
        self.assertIn("ended", archived)
        self.assertEqual((adir / "rules.txt").read_text(), RULE)
        self.assertEqual((adir / "output.log").read_text(), "line one\nline two\n")
        self.assertEqual(self.journal_events(adir / "journal.jsonl")[-1], "down",
                         "down is the journal's last word")

    def test_prefeature_meta_gets_a_sid_minted(self):
        meta = self.write_session("t2")                  # no sid, as old metas have none
        self.teardown(meta)
        entries = [d for d in sg.ARCHIVE_DIR.iterdir() if d.is_dir()]
        self.assertEqual(len(entries), 1)
        self.assertTrue(sg._SID_RE.fullmatch(entries[0].name), entries[0].name)
        self.assertEqual(json.loads((entries[0] / "meta.json").read_text())["sid"],
                         entries[0].name)

    def test_snapshot_failure_warns_and_teardown_completes(self):
        sid = sg._new_sid("t3")
        meta = self.write_session("t3", sid=sid)
        err = self.teardown(meta, logs=(None, "guest is gone"))
        self.assertIn("no guest-output snapshot", err)
        adir = sg.ARCHIVE_DIR / sid
        self.assertTrue((adir / "meta.json").exists(), "teardown must finish regardless")
        self.assertFalse((adir / "output.log").exists())

    def test_archive_false_removes_the_session_whole(self):
        meta = self.write_session("t4", sid=sg._new_sid("t4"))
        self.teardown(meta, archive=False)
        self.assertFalse(sg.session_dir("t4").exists())
        self.assertEqual(list(sg.ARCHIVE_DIR.iterdir()), [],
                         "a session never handed over leaves no archive")

    def test_rename_failure_warns_and_teardown_completes(self):
        meta = self.write_session("t5", sid=sg._new_sid("t5"))
        blocker = self.tmp / "blocker"
        blocker.write_text("")                           # ARCHIVE_DIR.mkdir must fail
        with mock.patch.object(sg, "ARCHIVE_DIR", blocker / "archive"):
            err = self.teardown(meta)
        self.assertIn("could not archive", err)
        self.assertFalse(sg.session_dir("t5").exists(),
                         "the teardown must complete even when the archive cannot")

    def test_unremovable_sandbox_still_keeps_the_session(self):
        meta = self.write_session("t6", sid=sg._new_sid("t6"))
        err = io.StringIO()
        with mock.patch.object(sg, "_remove_sandbox", lambda sandbox: False), \
                mock.patch.object(sg, "_run_msb_logs",
                                  lambda sandbox, tail_n=None, since=None: ([], None)), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            sg._teardown_session(meta)
        self.assertTrue(sg.session_dir("t6").exists(),
                        "enforcement stays fail-closed: no removal, no archive")
        self.assertEqual(list(sg.ARCHIVE_DIR.iterdir()), [])

    def test_snapshot_is_bounded(self):
        sid = sg._new_sid("t7")
        meta = self.write_session("t7", sid=sid)
        big = ["x" * 1000] * 2000                        # ~2 MiB of guest chatter
        self.teardown(meta, logs=(big, None))
        size = (sg.ARCHIVE_DIR / sid / "output.log").stat().st_size
        self.assertLessEqual(size, sg._SNAPSHOT_MAX_BYTES)


# -- archive retention ---------------------------------------------------------------

class TestPruneArchive(JournalCase):

    def archive_dir(self, i, age_days):
        sid = f"20200101T{i:06d}Z-s{i}-abcdef"
        d = sg.ARCHIVE_DIR / sid
        d.mkdir(parents=True)
        past = time.time() - age_days * 86400
        os.utime(d, (past, past))
        return d

    def test_removal_needs_both_beyond_count_and_beyond_age(self):
        n = sg.ARCHIVE_RETAIN_COUNT + 5
        dirs = [self.archive_dir(i, age_days=sg.ARCHIVE_RETAIN_DAYS + 10 + i)
                for i in range(n)]
        newest_first = sorted(dirs, key=lambda d: d.stat().st_mtime, reverse=True)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            sg._prune_archive()
        kept = [d for d in dirs if d.exists()]
        self.assertEqual(len(kept), sg.ARCHIVE_RETAIN_COUNT)
        self.assertEqual(set(kept), set(newest_first[:sg.ARCHIVE_RETAIN_COUNT]))
        self.assertEqual(err.getvalue().count("pruned archived session"), 5,
                         "every removal is announced")

    def test_age_alone_never_prunes(self):
        for i in range(5):
            self.archive_dir(i, age_days=400 + i)
        sg._prune_archive()
        self.assertEqual(len(list(sg.ARCHIVE_DIR.iterdir())), 5)

    def test_count_alone_never_prunes(self):
        for i in range(sg.ARCHIVE_RETAIN_COUNT + 10):
            self.archive_dir(i, age_days=0)
        sg._prune_archive()
        self.assertEqual(len(list(sg.ARCHIVE_DIR.iterdir())),
                         sg.ARCHIVE_RETAIN_COUNT + 10)

    def test_retention_zero_keeps_everything(self):
        for i in range(sg.ARCHIVE_RETAIN_COUNT + 10):
            self.archive_dir(i, age_days=400 + i)
        os.environ["SILKGATE_ARCHIVE_RETAIN_DAYS"] = "0"
        self.addCleanup(os.environ.pop, "SILKGATE_ARCHIVE_RETAIN_DAYS", None)
        sg._prune_archive()
        self.assertEqual(len(list(sg.ARCHIVE_DIR.iterdir())),
                         sg.ARCHIVE_RETAIN_COUNT + 10)

    def test_foreign_dirs_are_never_touched(self):
        foreign = sg.ARCHIVE_DIR / "keep-me"
        foreign.mkdir()
        past = time.time() - 400 * 86400
        os.utime(foreign, (past, past))
        for i in range(sg.ARCHIVE_RETAIN_COUNT + 5):
            self.archive_dir(i, age_days=sg.ARCHIVE_RETAIN_DAYS + 10 + i)
        with contextlib.redirect_stderr(io.StringIO()):
            sg._prune_archive()
        self.assertTrue(foreign.exists())


# -- --brief -----------------------------------------------------------------------

class TestBrief(JournalCase):

    def test_read_brief_refusals(self):
        self.assertIsNone(sg._read_brief(None))
        self.refuses("cannot read --brief", sg._read_brief, str(self.tmp / "absent.md"))
        big = self.tmp / "big.md"
        big.write_bytes(b"x" * (sg._BRIEF_MAX_BYTES + 1))
        self.refuses("over the 1 MiB limit", sg._read_brief, str(big))

    def test_provision_writes_brief_and_copy_file_argv(self):
        """The exact context.md --copy-file pattern, asserted on the built msb argv —
        no real msb runs."""
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            return types.SimpleNamespace(returncode=0)

        ruleset = sg.RuleSet.parse(RULE)
        with mock.patch.object(sg, "_msb", lambda: "msb"), \
                mock.patch.object(sg.subprocess, "run", fake_run):
            sg._provision_session("br1", "img:1", 8090, RULE, ruleset, [], None, [],
                                  {}, context="ctx", context_paths=(sg.GUEST_CONTEXT,),
                                  brief=b"# the task\n")
        sdir = sg.session_dir("br1")
        self.assertEqual((sdir / "brief.md").read_bytes(), b"# the task\n")
        pairs = [seen["argv"][i + 1] for i, a in enumerate(seen["argv"])
                 if a == "--copy-file"]
        self.assertIn(f"{sdir / 'brief.md'}:{sg.GUEST_BRIEF}", pairs)
        self.assertIn(f"{sdir / 'context.md'}:{sg.GUEST_CONTEXT}", pairs)
        self.assertEqual(self.journal_events(sdir / "journal.jsonl"), ["created"],
                         "the session appears with its journal already begun")
        meta = json.loads((sdir / "meta.json").read_text())
        self.assertTrue(sg._SID_RE.fullmatch(meta["sid"]), "sid persisted at provision")


# -- meta additions ------------------------------------------------------------------

class TestMetaAdditions(JournalCase):

    def spy_main(self, argv):
        """cmd_run/cmd_up driven to the _provision_session call and stopped there."""
        seen = {}

        def spy(name, image, port, rules_text, ruleset, mounts, ws, env, meta_extra,
                context=None, context_paths=(), brief=None):
            seen.update(meta=meta_extra, brief=brief, rules_text=rules_text)
            raise SystemExit(42)

        with mock.patch.object(sg, "preflight", lambda *a: None), \
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

    def test_run_records_the_ask(self):
        seen = self.spy_main(["run", "-e", "TOKEN=secretvalue", "-e", "AA=1",
                              "--", "true"])
        meta = seen["meta"]
        self.assertEqual(meta["env_names"], ["AA", "TOKEN"],
                         "sorted names from -e")
        self.assertNotIn("secretvalue", json.dumps(meta), "names only, never values")
        self.assertIs(meta["tty"], False)
        self.assertIs(meta["allow_git_dir"], False)
        self.assertEqual(meta["rules_sha256"],
                         hashlib.sha256(seen["rules_text"].encode()).hexdigest())
        self.assertNotIn("base_ref", meta)
        self.assertNotIn("brief_path", meta)

    def test_up_records_the_ask_without_tty(self):
        seen = self.spy_main(["up", "--name", "m1", "-e", "B=2"])
        meta = seen["meta"]
        self.assertEqual(meta["env_names"], ["B"])
        self.assertNotIn("tty", meta, "tty is a run-only field")

    def test_brief_flows_into_meta_and_provision(self):
        brief = self.tmp / "task.md"
        brief.write_bytes(b"# do the thing\n")
        seen = self.spy_main(["run", "--brief", str(brief), "--", "true"])
        self.assertEqual(seen["brief"], b"# do the thing\n")
        self.assertEqual(seen["meta"]["brief_path"], str(brief.resolve()))
        self.assertEqual(seen["meta"]["brief_sha256"],
                         hashlib.sha256(b"# do the thing\n").hexdigest())

    def test_base_ref_is_the_operators_spelling(self):
        args = types.SimpleNamespace(env=[], allow_git_dir=False, branch="nb",
                                     checkout=None, brief=None)
        self.assertEqual(sg._observability_meta(args, RULE, None)["base_ref"], "HEAD")
        args.checkout = "v1"
        self.assertEqual(sg._observability_meta(args, RULE, None)["base_ref"], "v1")
        args.branch, args.checkout = None, None
        self.assertNotIn("base_ref", sg._observability_meta(args, RULE, None))


# -- exec journal write points ---------------------------------------------------------

class TestExecJournal(JournalCase):

    def run_cmd(self, fn, args, rc=7):
        captured = {}

        def fake_run_guest(build_argv, cmd, *, tty, on_line=None, exec_id=None):
            captured.update(cmd=list(cmd), tty=tty, exec_id=exec_id)
            return rc

        with mock.patch.object(sg, "run_guest", fake_run_guest), \
                self.assertRaises(SystemExit) as caught:
            fn(args)
        self.assertEqual(caught.exception.code, rc)
        return captured

    def test_cmd_exec_brackets_run_guest(self):
        self.write_session("e1")
        args = types.SimpleNamespace(name="e1", env=["FOO=secret"], tty=False,
                                     cmd=["--", "echo", "hi"])
        captured = self.run_cmd(sg.cmd_exec, args)
        records = sg._read_journal(sg.session_dir("e1") / "journal.jsonl")
        self.assertEqual([r["event"] for r in records], ["exec_start", "exec_end"])
        start, end = records
        self.assertEqual(start["via"], "exec")
        self.assertEqual(start["argv"], ["echo", "hi"])
        self.assertEqual(start["env_names"], ["FOO"])
        self.assertNotIn("secret", json.dumps(records))
        self.assertEqual(end["rc"], 7, "rc journaled before sys.exit takes it")
        self.assertEqual(start["exec_id"], end["exec_id"])
        self.assertEqual(start["exec_id"], captured["exec_id"],
                         "the journaled id is the one threaded into the relay")
        self.assertRegex(start["exec_id"], r"^[0-9a-f]{8}$")
        meta = sg._read_json(sg.session_dir("e1") / "meta.json")
        self.assertEqual(meta["last_rc"], 7, "exec_end also lands meta.last_rc")

    def test_cmd_attach_brackets_run_guest(self):
        self.write_session("e2", command=["claude"])
        args = types.SimpleNamespace(name="e2")
        self.run_cmd(sg.cmd_attach, args, rc=0)
        records = sg._read_journal(sg.session_dir("e2") / "journal.jsonl")
        self.assertEqual([r["event"] for r in records], ["exec_start", "exec_end"])
        self.assertEqual(records[0]["via"], "attach")
        self.assertIs(records[0]["tty"], True)

    def test_interrupted_exec_still_closes_its_bracket(self):
        """A Ctrl-C raises through run_guest; the bracket must still journal exec_end
        — rc 130, the shell convention for SIGINT — and land it in meta.last_rc."""
        self.write_session("e3")
        args = types.SimpleNamespace(name="e3", env=[], tty=False, cmd=["--", "true"])

        def interrupted(*a, **k):
            raise KeyboardInterrupt

        with mock.patch.object(sg, "run_guest", interrupted), \
                self.assertRaises(KeyboardInterrupt):
            sg.cmd_exec(args)
        records = sg._read_journal(sg.session_dir("e3") / "journal.jsonl")
        self.assertEqual([r["event"] for r in records], ["exec_start", "exec_end"])
        self.assertEqual(records[1]["rc"], 130)
        self.assertEqual(sg._read_json(sg.session_dir("e3") / "meta.json")["last_rc"],
                         130)

    def test_unknowable_rc_journals_null_and_skips_last_rc(self):
        """A die() inside run_guest carries no exit status for the guest command: the
        bracket closes with rc null and meta gains no last_rc."""
        self.write_session("e4")
        args = types.SimpleNamespace(name="e4", env=[], tty=False, cmd=["--", "true"])

        def dies(*a, **k):
            raise SystemExit("not an int")

        with mock.patch.object(sg, "run_guest", dies), self.assertRaises(SystemExit):
            sg.cmd_exec(args)
        records = sg._read_journal(sg.session_dir("e4") / "journal.jsonl")
        self.assertEqual([r["event"] for r in records], ["exec_start", "exec_end"])
        self.assertIsNone(records[1]["rc"])
        self.assertNotIn("last_rc", sg._read_json(sg.session_dir("e4") / "meta.json"))

    def test_harvest_journals_its_verdict(self):
        meta = self.write_session("h1", branch="agent/x", base="0" * 40,
                                  git_dir="/g/.git", workspace="/w")
        err = io.StringIO()
        with mock.patch.object(sg, "_bundle_in_guest",
                               lambda m: ("SILKGATE_NO_COMMITS", "")), \
                contextlib.redirect_stderr(err):
            self.assertTrue(sg._harvest_branch(meta))
        with mock.patch.object(sg, "_bundle_in_guest",
                               lambda m: ("SILKGATE_ERROR", "timed out")), \
                contextlib.redirect_stderr(err):
            self.assertFalse(sg._harvest_branch(meta))
        records = sg._read_journal(sg.session_dir("h1") / "journal.jsonl")
        self.assertEqual([r["result"] for r in records], ["no_commits", "failed"])
        self.assertEqual(records[1]["detail"], "timed out")

    def test_harvest_verdict_survives_a_dead_journal(self):
        """The guard the spec pins: a journal failure cannot change the return value."""
        meta = {"name": "gone99", "branch": "agent/x", "base": "0" * 40,
                "workspace": "/w"}                        # no session dir to journal into
        err = io.StringIO()
        with mock.patch.object(sg, "_bundle_in_guest",
                               lambda m: ("SILKGATE_NO_BRANCH", "")), \
                contextlib.redirect_stderr(err):
            self.assertTrue(sg._harvest_branch(meta))
        self.assertIn("could not journal", err.getvalue())


# -- the exec marker in the relay ------------------------------------------------------

class TestExecMarker(JournalCase):

    def built_argv(self, tty, exec_id):
        seen = {}

        def fake_relay(argv, *, demux, on_line=None):
            seen["argv"] = argv
            return 0

        with mock.patch.object(sg, "_pty_relay", fake_relay):
            sg.run_guest(lambda c: ["msb", "exec", "-q", "sg-x", "--"] + c,
                         ["echo", "hi"], tty=tty, exec_id=exec_id)
        return " ".join(seen["argv"])

    def test_relay_argv_carries_the_merged_export_and_the_pidfile(self):
        text = self.built_argv(False, "cafe1234")
        self.assertIn("X-Silkgate-Exec: cafe1234", text)
        self.assertIn("${ANTHROPIC_CUSTOM_HEADERS:+", text,
                      "a caller-provided value is merged, never clobbered")
        self.assertIn("export ANTHROPIC_CUSTOM_HEADERS", text)
        self.assertIn(f"{sg.GUEST_EXECS}/cafe1234.pid", text)
        self.assertIn("mkdir -p", text)

    def test_tty_wrapper_carries_the_marker_too(self):
        text = self.built_argv(True, "beef5678")
        self.assertIn("X-Silkgate-Exec: beef5678", text)
        self.assertIn(f"{sg.GUEST_EXECS}/beef5678.pid", text)

    def test_no_exec_id_leaves_the_relay_untouched(self):
        text = self.built_argv(False, None)
        self.assertNotIn("X-Silkgate-Exec", text)
        self.assertNotIn("ANTHROPIC_CUSTOM_HEADERS", text)

    def test_marker_merges_and_writes_the_pidfile_for_real(self):
        """The wrapper run by a real sh: an existing header value keeps its line, the
        marker lands appended on a new one, and the pidfile holds the shell's pid."""
        execs = self.tmp / "execs"
        lines = []
        quiet = io.TextIOWrapper(io.BytesIO())           # the relay writes stdout.buffer
        with mock.patch.object(sg, "GUEST_EXECS", str(execs)), \
                mock.patch.dict(os.environ,
                                {"ANTHROPIC_CUSTOM_HEADERS": "X-Existing: keepme"}), \
                contextlib.redirect_stdout(quiet):
            rc = sg.run_guest(lambda argv: argv,
                              ["sh", "-c", 'printf "%s\\n" "$ANTHROPIC_CUSTOM_HEADERS"'],
                              tty=False, on_line=lines.append, exec_id="cafe1234")
        self.assertEqual(rc, 0)
        self.assertEqual(lines, ["X-Existing: keepme", "X-Silkgate-Exec: cafe1234"])
        pid = (execs / "cafe1234.pid").read_text()
        self.assertTrue(pid.isdigit(), pid)

    def test_pidfile_failure_does_not_fail_the_exec(self):
        blocker = self.tmp / "blocker"
        blocker.write_text("")                            # mkdir -p under a file fails
        quiet = io.TextIOWrapper(io.BytesIO())
        with mock.patch.object(sg, "GUEST_EXECS", str(blocker / "execs")), \
                contextlib.redirect_stdout(quiet):
            rc = sg.run_guest(lambda argv: argv, ["sh", "-c", "exit 0"],
                              tty=False, exec_id="cafe1234")
        self.assertEqual(rc, 0, "the pidfile is best-effort; the command still runs")


# -- capture-file wiring ----------------------------------------------------------------

class TestCaptureWiring(JournalCase):

    def setUp(self):
        super().setUp()
        sg.LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, sg.LOG_DIR, ignore_errors=True)

    @staticmethod
    def fake_proc():
        proc = mock.MagicMock()
        proc.poll.return_value = None
        proc.pid = 4242
        return proc

    def spawn(self, fn, *args):
        seen = {}
        real_popen = sg.subprocess.Popen

        def fake_popen(argv, **kwargs):
            seen["env"] = kwargs.get("env")
            return self.fake_proc()

        with mock.patch.object(sg, "which", return_value="mitmdump"), \
                mock.patch.object(sg.subprocess, "Popen", fake_popen), \
                mock.patch.object(sg.socket, "create_connection", mock.MagicMock()):
            result = fn(*args)
        return result, seen["env"]

    def test_start_proxy_names_a_capture_file(self):
        (_, log_path), env = self.spawn(sg.start_proxy, RULE, 18090)
        capture = env["SILKGATE_EGRESS_CAPTURE_FILE"]
        self.assertEqual(Path(capture).parent, sg.LOG_DIR)
        self.assertRegex(Path(capture).name, r"^capture-.*\.jsonl$")

    def test_start_shared_proxy_records_capture_in_its_meta(self):
        meta, env = self.spawn(sg.start_shared_proxy, 18090)
        self.assertEqual(meta["capture"], env["SILKGATE_EGRESS_CAPTURE_FILE"])
        self.assertRegex(Path(meta["capture"]).name, r"^capture-.*\.jsonl$")

    def test_cmd_proxy_names_a_capture_file(self):
        proc = self.fake_proc()
        proc.wait.return_value = 0
        proc.poll.return_value = 0
        seen = {}

        def fake_popen(argv, **kwargs):
            seen["env"] = kwargs.get("env")
            return proc

        with mock.patch.object(sg, "which", return_value="mitmdump"), \
                mock.patch.object(sg.subprocess, "Popen", fake_popen), \
                self.assertRaises(SystemExit):
            sg.cmd_proxy(types.SimpleNamespace(with_=None, rule=[RULE.strip()],
                                               port=18090))
        self.assertIn("SILKGATE_EGRESS_CAPTURE_FILE", seen["env"])

    def log_file(self, name, age_days):
        p = sg.LOG_DIR / name
        p.write_text("x\n")
        past = time.time() - age_days * 86400
        os.utime(p, (past, past))
        return p

    def test_capture_prunes_on_its_own_week_knob(self):
        n = sg.LOG_RETAIN_COUNT + 2
        for i in range(n):
            age = 8 + i * 0.5                            # every file > 7d and < 30d old
            self.log_file(f"capture-{i:02d}.jsonl", age_days=age)
            self.log_file(f"events-{i:02d}.jsonl", age_days=age)
        with contextlib.redirect_stderr(io.StringIO()):
            sg._prune_logs()
        names = sorted(p.name for p in sg.LOG_DIR.iterdir())
        self.assertIn("capture-00.jsonl", names)
        self.assertNotIn(f"capture-{n - 1:02d}.jsonl", names,
                         "capture beyond count+week must go")
        self.assertIn(f"events-{n - 1:02d}.jsonl", names,
                      "events keep the 30-day knob")

    def test_capture_knob_zero_keeps_captures_only(self):
        n = sg.LOG_RETAIN_COUNT + 2
        for i in range(n):
            self.log_file(f"capture-{i:02d}.jsonl", age_days=sg.LOG_RETAIN_DAYS + 10 + i)
            self.log_file(f"proxy-{i:02d}.log", age_days=sg.LOG_RETAIN_DAYS + 10 + i)
        os.environ["SILKGATE_CAPTURE_RETAIN_DAYS"] = "0"
        self.addCleanup(os.environ.pop, "SILKGATE_CAPTURE_RETAIN_DAYS", None)
        with contextlib.redirect_stderr(io.StringIO()):
            sg._prune_logs()
        names = sorted(p.name for p in sg.LOG_DIR.iterdir())
        self.assertIn(f"capture-{n - 1:02d}.jsonl", names,
                      "the capture knob at 0 keeps every capture file")
        self.assertNotIn(f"proxy-{n - 1:02d}.log", names,
                         "each knob turns off only its own kinds")

    def test_live_capture_file_survives_a_full_prune(self):
        live = self.log_file("capture-00-live.jsonl", age_days=90)
        sg._write_json(sg.PROXY_JSON, {"pid": os.getpid(), "capture": str(live)})
        self.addCleanup(sg.PROXY_JSON.unlink)
        for i in range(1, sg.LOG_RETAIN_COUNT + 6):
            self.log_file(f"capture-{i:02d}.jsonl", age_days=40 + i)
        with contextlib.redirect_stderr(io.StringIO()):
            sg._prune_logs()
        self.assertTrue(live.exists(), "pruned the capture file a live proxy is writing")


if __name__ == "__main__":
    unittest.main()
