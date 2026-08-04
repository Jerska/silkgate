#!/usr/bin/env python3
"""Log-retention, standalone-proxy and audit-follow tests for cli/silkgate.

Everything runs against a temp state tree — never ~/.silkgate — with the module's
directory attributes reassigned in setUp, fake executables on PATH where a binary is
unavoidable, and mocks elsewhere, so no docker, msb or mitmproxy is needed. cli/silkgate
has no .py extension, so it is loaded through SourceFileLoader; SILKGATE_CLI overrides
which copy is loaded, which is how the same tests demonstrate the pre-fix failures.

    python3 test/test_cli_logs.py -v
    SILKGATE_CLI=/path/to/old/cli/silkgate python3 test/test_cli_logs.py -v

What is covered:
  * _prune_logs: removal needs BOTH beyond-count AND beyond-age; the log a live proxy
    is writing survives a prune that removes its neighbours; retention can be turned
    off; only silkgate's own log patterns are touched
  * every log-creating path (start_proxy, start_shared_proxy, cmd_proxy) applies it
  * cmd_proxy's mitmdump argv: one listener per PROXY_BINDS address (loopback both
    families by default, never a wildcard --listen-port) and rawtcp off
  * ensure_ca: one-shot --no-server generation — no listener, key never handed out
  * _audit_match/_read_from, and `logs --audit -f` trusting the control socket's
    identity over a pid that may have been recycled
"""
import contextlib
import importlib.util
import io
import itertools
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("SILKGATE_CLI", REPO / "cli" / "silkgate"))

# The module reads SILKGATE_PROXY_BIND at import; the tests assert the default.
os.environ.pop("SILKGATE_PROXY_BIND", None)
os.environ.pop("SILKGATE_LOG_RETAIN_DAYS", None)

_loader = SourceFileLoader("silkgate_cli_logs", str(CLI))
_spec = importlib.util.spec_from_file_location("silkgate_cli_logs", CLI, loader=_loader)
MOD = importlib.util.module_from_spec(_spec)
sys.modules["silkgate_cli_logs"] = MOD
_loader.exec_module(MOD)

RULE = "api.anthropic.com/** GET"

# Fake mitmdump for the ensure_ca path: records its argv, refuses to be a server (a
# listener during CA generation is the exact regression these tests exist to catch),
# and writes the CA pair into the confdir it was told — never a default location.
FAKE_MITMDUMP_CA_SRC = r"""
import os, json, sys
rec = os.environ.get("FAKE_MITM_ARGV")
if rec:
    with open(rec, "w") as fh:
        json.dump(sys.argv[1:], fh)
if "--no-server" not in sys.argv:
    sys.exit(3)
confdir = None
for i, a in enumerate(sys.argv):
    if a == "--set" and i + 1 < len(sys.argv) and sys.argv[i + 1].startswith("confdir="):
        confdir = sys.argv[i + 1].split("=", 1)[1]
if not confdir:
    sys.exit(4)
os.makedirs(confdir, exist_ok=True)
with open(os.path.join(confdir, "mitmproxy-ca-cert.pem"), "w") as fh:
    fh.write("CERT\n")
with open(os.path.join(confdir, "mitmproxy-ca.pem"), "w") as fh:
    fh.write("KEY\n")
sys.exit(0)
"""


class _ControlSock(threading.Thread):
    """Answers the control protocol on a unix socket path, in-process — so the kernel
    names this test process as the peer, which is all _proxy_ident needs."""

    def __init__(self, path):
        super().__init__(daemon=True)
        self.path = str(path)
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(self.path)
        self.srv.listen(8)
        self.start()

    def run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _handle(conn):
        with conn:
            f = conn.makefile("rw")
            for _ in f:
                f.write('{"ok": true}\n')
                f.flush()

    def close(self):
        self.srv.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass


def _dead_pid():
    """A pid that no process holds: a reaped child's."""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def _args(name, **kw):
    base = dict(follow=False, tail=None, since=None, interval=0.01, audit=True)
    base.update(kw)
    return types.SimpleNamespace(name=name, **base)


class SilkgateTest(unittest.TestCase):
    """Base: every path the module writes points into a temp tree, never ~/.silkgate."""

    maxDiff = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sglog-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        silk = self.root / "silk"
        self._saved = {k: getattr(MOD, k) for k in
                       ("SILK_DIR", "LOG_DIR", "SESSIONS_DIR", "PROXY_JSON", "PROXY_SOCK",
                        "CA_DIR", "MITM_CA")}
        self.addCleanup(self._restore)
        MOD.SILK_DIR = silk
        MOD.LOG_DIR = silk / "logs"
        MOD.SESSIONS_DIR = silk / "sessions"
        MOD.PROXY_JSON = silk / "proxy.json"
        MOD.PROXY_SOCK = silk / "proxy.sock"
        MOD.CA_DIR = silk / "ca"
        MOD.MITM_CA = self.root / "mitmproxy" / "mitmproxy-ca-cert.pem"
        MOD.LOG_DIR.mkdir(parents=True)
        MOD.SESSIONS_DIR.mkdir(parents=True)
        os.environ.pop("SILKGATE_LOG_RETAIN_DAYS", None)

    def _restore(self):
        for k, v in self._saved.items():
            setattr(MOD, k, v)

    # -- helpers ---------------------------------------------------------------

    def log_file(self, name, age_days=0.0, text="x\n"):
        p = MOD.LOG_DIR / name
        p.write_text(text)
        if age_days:
            past = time.time() - age_days * 86400
            os.utime(p, (past, past))
        return p

    def proxy_meta(self, pid=None, log=None, base=8090):
        meta = {"pid": pid or os.getpid(), "base_port": base,
                "ports": list(range(base, base + MOD.POOL_SIZE)),
                "log": str(log or (MOD.LOG_DIR / "proxy-live.log")),
                "sock": str(MOD.PROXY_SOCK)}
        MOD._write_json(MOD.PROXY_JSON, meta)
        return meta

    def write_session(self, name, port=8090):
        sdir = MOD.session_dir(name)
        sdir.mkdir(parents=True)
        (sdir / "rules.txt").write_text(RULE + "\n")
        MOD._write_json(sdir / "meta.json",
                        {"name": name, "sandbox": "sg-" + name, "port": port})

    def log_names(self):
        return sorted(p.name for p in MOD.LOG_DIR.iterdir())

    def start_sleeper(self):
        """A live process that is definitely not the proxy. Cleanups run LIFO: kill,
        then wait, so nothing leaks and nothing blocks."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        return proc

    @staticmethod
    def fake_proc():
        proc = mock.MagicMock()
        proc.poll.return_value = None
        proc.pid = 4242
        return proc


# -- retention (_prune_logs) ---------------------------------------------------

class PruneLogsTest(SilkgateTest):

    def test_removal_needs_both_beyond_count_and_beyond_age(self):
        n = MOD.LOG_RETAIN_COUNT + 5
        for i in range(n):                       # i=0 newest; all older than the age
            self.log_file(f"proxy-{i:02d}.log", age_days=MOD.LOG_RETAIN_DAYS + 10 + i)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            MOD._prune_logs()
        kept = self.log_names()
        self.assertEqual(len(kept), MOD.LOG_RETAIN_COUNT)
        for i in range(MOD.LOG_RETAIN_COUNT):
            self.assertIn(f"proxy-{i:02d}.log", kept)
        self.assertIn("pruned 5", err.getvalue(), "removals must be announced, not silent")
        self.assertIn("SILKGATE_LOG_RETAIN_DAYS=0", err.getvalue(),
                      "the announcement must say how to keep everything")

    def test_age_alone_never_prunes(self):
        """Ancient but within the newest-N: the last runs stay reviewable after a gap."""
        for i in range(5):
            self.log_file(f"proxy-{i}.log", age_days=400 + i)
        MOD._prune_logs()
        self.assertEqual(len(self.log_names()), 5)

    def test_count_alone_never_prunes(self):
        """A burst of recent starts is history the age guard protects."""
        for i in range(MOD.LOG_RETAIN_COUNT + 10):
            self.log_file(f"proxy-{i:02d}.log")
        MOD._prune_logs()
        self.assertEqual(len(self.log_names()), MOD.LOG_RETAIN_COUNT + 10)

    def test_live_log_survives_a_full_prune(self):
        """The oldest file of all is the one the live proxy is writing (proxy.json names
        it): everything beyond count+age goes except that one."""
        live = self.log_file("proxy-00-live.log", age_days=90)
        self.proxy_meta(log=live)
        for i in range(1, MOD.LOG_RETAIN_COUNT + 6):
            self.log_file(f"proxy-{i:02d}.log", age_days=40 + i)
        MOD._prune_logs()
        self.assertTrue(live.exists(), "pruned the log a live proxy is writing")
        self.assertEqual(len(self.log_names()), MOD.LOG_RETAIN_COUNT + 1,
                         "the live log must not displace or spare other candidates")

    def test_retention_zero_keeps_everything(self):
        for i in range(MOD.LOG_RETAIN_COUNT + 10):
            self.log_file(f"proxy-{i:02d}.log", age_days=400 + i)
        os.environ["SILKGATE_LOG_RETAIN_DAYS"] = "0"
        MOD._prune_logs()
        self.assertEqual(len(self.log_names()), MOD.LOG_RETAIN_COUNT + 10)

    def test_every_kind_pruned_and_foreign_files_untouched(self):
        n = MOD.LOG_RETAIN_COUNT + 2
        for i in range(n):
            age = MOD.LOG_RETAIN_DAYS + 10 + i
            self.log_file(f"proxy-{i:02d}.log", age_days=age)
            self.log_file(f"proxy-{i:02d}.rules", age_days=age)
            self.log_file(f"standalone-{i:02d}.rules", age_days=age)
        self.log_file("NOTES.log", age_days=999)         # a user's file, not our pattern
        MOD._prune_logs()
        names = self.log_names()
        self.assertIn("NOTES.log", names)
        for kind in ("proxy-{:02d}.log", "proxy-{:02d}.rules", "standalone-{:02d}.rules"):
            self.assertIn(kind.format(0), names)
            self.assertNotIn(kind.format(n - 1), names)


# -- retention applied where logs are created -----------------------------------

class CreationSitePruneTest(SilkgateTest):

    def _overfull(self):
        """More beyond-count-and-age logs than retention keeps; returns the doomed one."""
        n = MOD.LOG_RETAIN_COUNT + 3
        for i in range(n):
            self.log_file(f"proxy-{i:02d}.log", age_days=MOD.LOG_RETAIN_DAYS + 10 + i)
        return MOD.LOG_DIR / f"proxy-{n - 1:02d}.log"

    def test_start_proxy_applies_retention(self):
        doomed = self._overfull()
        with mock.patch.object(MOD, "which", return_value="mitmdump"), \
             mock.patch.object(MOD.subprocess, "Popen", return_value=self.fake_proc()), \
             mock.patch.object(MOD.socket, "create_connection", mock.MagicMock()):
            proc, log_path = MOD.start_proxy(RULE + "\n", 18090)
        self.assertFalse(doomed.exists(), "start_proxy did not prune old logs")
        self.assertTrue(log_path.exists() and log_path.name.startswith("proxy-"))

    def test_start_shared_proxy_applies_retention_and_spares_live_log(self):
        live = self.log_file("proxy-00-live.log", age_days=90)
        self.proxy_meta(log=live)
        doomed = self._overfull()
        with mock.patch.object(MOD, "which", return_value="mitmdump"), \
             mock.patch.object(MOD.subprocess, "Popen", return_value=self.fake_proc()), \
             mock.patch.object(MOD.socket, "create_connection", mock.MagicMock()):
            meta = MOD.start_shared_proxy(18090)
        self.assertFalse(doomed.exists(), "start_shared_proxy did not prune old logs")
        self.assertTrue(live.exists(), "pruned the previous proxy's still-live log")
        self.assertTrue(Path(meta["log"]).exists())

    def test_cmd_proxy_applies_retention(self):
        doomed = self._overfull()
        proc = self.fake_proc()
        proc.wait.return_value = 0
        proc.poll.return_value = 0
        with mock.patch.object(MOD, "which", return_value="mitmdump"), \
             mock.patch.object(MOD.subprocess, "Popen", return_value=proc):
            with self.assertRaises(SystemExit):
                MOD.cmd_proxy(types.SimpleNamespace(with_=None, rule=[RULE], port=18090))
        self.assertFalse(doomed.exists(), "cmd_proxy did not prune old logs")


# -- cmd_proxy: bind and rawtcp --------------------------------------------------

class CmdProxyTest(SilkgateTest):

    def run_cmd_proxy(self, port=18090):
        proc = self.fake_proc()
        proc.wait.return_value = 0
        proc.poll.return_value = 0
        with mock.patch.object(MOD, "which", return_value="mitmdump"), \
             mock.patch.object(MOD.subprocess, "Popen", return_value=proc) as popen:
            with self.assertRaises(SystemExit) as ctx:
                MOD.cmd_proxy(types.SimpleNamespace(with_=None, rule=[RULE], port=port))
        self.assertEqual(ctx.exception.code, 0)
        return popen.call_args[0][0], popen.call_args[1]["env"]

    def test_binds_each_loopback_family_and_disables_rawtcp(self):
        """§3's leftover: `silkgate proxy` was the one entry point still binding every
        interface (--listen-port with no host) with the raw-TCP fallback on."""
        argv, env = self.run_cmd_proxy()
        pairs = list(zip(argv, argv[1:]))
        self.assertIn(("--set", "rawtcp=false"), pairs,
                      "raw-TCP fallback left on: an unparsable CONNECT becomes a tunnel")
        modes = [m for f, m in pairs if f == "--mode"]
        self.assertEqual(modes, ["regular@127.0.0.1:18090", "regular@::1:18090"],
                         "both loopback families, and nothing wider, by default")
        self.assertNotIn("--listen-port", argv,
                         "--listen-port binds every interface: allowlist + credential "
                         "injection offered to the whole LAN")

    def test_bind_override_reaches_the_argv(self):
        """A guest on another machine opts in through SILKGATE_PROXY_BIND (read into
        PROXY_BINDS at import), naming the one interface it can route to."""
        with mock.patch.object(MOD, "PROXY_BINDS", ("10.0.0.2",)):
            argv, _ = self.run_cmd_proxy(port=19000)
        modes = [m for f, m in zip(argv, argv[1:]) if f == "--mode"]
        self.assertEqual(modes, ["regular@10.0.0.2:19000"])

    def test_rules_snapshot_and_single_ruleset_env(self):
        argv, env = self.run_cmd_proxy()
        self.assertNotIn("EGRESS_SESSIONS_DIR", env,
                         "the addon needs exactly one ruleset source")
        rules_file = Path(env["EGRESS_RULES"])
        self.assertEqual(rules_file.parent, MOD.LOG_DIR)
        self.assertTrue(rules_file.name.startswith("standalone-"))
        self.assertIn(RULE, rules_file.read_text())


# -- ensure_ca: one-shot, no listener --------------------------------------------

class EnsureCaTest(SilkgateTest):

    def setUp(self):
        super().setUp()
        fakebin = self.root / "bin"
        fakebin.mkdir()
        exe = fakebin / "mitmdump"
        exe.write_text(f"#!{sys.executable}\n{FAKE_MITMDUMP_CA_SRC}")
        exe.chmod(0o755)
        self.argv_rec = self.root / "mitm-argv.json"
        self._env = {k: os.environ.get(k) for k in ("PATH", "FAKE_MITM_ARGV")}
        self.addCleanup(self._restore_env)
        os.environ["PATH"] = f"{fakebin}:{os.environ['PATH']}"
        os.environ["FAKE_MITM_ARGV"] = str(self.argv_rec)

    def _restore_env(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_first_run_generates_one_shot_with_no_server(self):
        """§2's leftover: first run used to put a bare, rule-less mitmdump on a wildcard
        port for up to 15s. The fake refuses to run as a server at all."""
        cert = MOD.ensure_ca()
        self.assertEqual(cert, MOD.CA_DIR / "egress-ca.pem")
        self.assertEqual(cert.read_text(), "CERT\n")
        argv = json.loads(self.argv_rec.read_text())
        self.assertIn("--no-server", argv)
        self.assertIn(f"confdir={MOD.MITM_CA.parent}", argv)
        self.assertNotIn("--listen-port", argv)
        self.assertNotIn("--listen-host", argv)
        self.assertFalse((MOD.CA_DIR / "mitmproxy-ca.pem").exists(),
                         "the private key must never leave the confdir")

    def test_existing_ca_starts_nothing(self):
        MOD.MITM_CA.parent.mkdir(parents=True)
        MOD.MITM_CA.write_text("EXISTING\n")
        cert = MOD.ensure_ca()
        self.assertEqual(cert.read_text(), "EXISTING\n")
        self.assertFalse(self.argv_rec.exists(), "mitmdump ran though the CA exists")


# -- audit records: parsing and filtering ----------------------------------------

class AuditMatchTest(SilkgateTest):

    def test_matches_prefixed_record_for_the_session_only(self):
        line = '[12:00:00.123] {"decision": "allow", "host": "h", "session": "foo"}'
        self.assertTrue(MOD._audit_match(line, "foo"))
        self.assertFalse(MOD._audit_match(line, "bar"))

    def test_matches_records_carrying_new_fields(self):
        """The audit record is growing (a date, a response status, byte counts): the
        reader filters on "session" alone, so unknown fields must never break it."""
        rec = {"date": "2026-08-04", "status": 200, "bytes_in": 512, "bytes_out": 2048,
               "decision": "allow", "host": "h", "path": "/", "session": "foo"}
        self.assertTrue(MOD._audit_match("[12:00:00.123] " + json.dumps(rec), "foo"))

    def test_rejects_chatter_and_broken_records(self):
        for line in ("[12:00:00.123] client connect",
                     "no braces at all",
                     '[12:00:00.123] {"session": "foo"',       # cut-off JSON
                     ""):
            self.assertFalse(MOD._audit_match(line, "foo"), repr(line))


class ReadFromTest(SilkgateTest):

    def test_only_whole_lines_advance_the_offset(self):
        p = MOD.LOG_DIR / "a.log"
        p.write_bytes(b"one\ntwo\npart")
        lines, off = MOD._read_from(p, 0)
        self.assertEqual((lines, off), (["one", "two"], 8))
        self.assertEqual(MOD._read_from(p, off), ([], 8),
                         "a half-written trailing line must be left for the next poll")
        p.write_bytes(b"one\ntwo\npartial done\n")
        lines, _ = MOD._read_from(p, off)
        self.assertEqual(lines, ["partial done"])

    def test_unreadable_file_reports_none(self):
        self.assertEqual(MOD._read_from(MOD.LOG_DIR / "gone.log", 5), (None, 5))


# -- logs --audit ------------------------------------------------------------------

class LogsAuditTest(SilkgateTest):

    def audit_log(self, *recs, name="proxy-live.log"):
        path = MOD.LOG_DIR / name
        lines = ["[12:00:00.000] " + (json.dumps(r) if isinstance(r, dict) else r)
                 for r in recs]
        path.write_text("".join(ln + "\n" for ln in lines))
        return path

    def test_one_shot_prints_only_this_sessions_records(self):
        path = self.audit_log({"session": "foo", "decision": "allow", "host": "a"},
                              "client connect",
                              {"session": "bar", "decision": "deny", "host": "b"},
                              {"session": "foo", "decision": "deny", "host": "c",
                               "date": "2026-08-04", "status": 403, "bytes_out": 0})
        self.proxy_meta(log=path)
        self.write_session("foo")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            MOD._logs_audit(_args("foo"))
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all('"session": "foo"' in ln for ln in lines))
        self.assertIn('"status": 403', lines[1],
                      "a record with fields this reader does not know is shown as-is")

    def test_tail_trims_the_first_view(self):
        path = self.audit_log({"session": "foo", "host": "a"},
                              {"session": "foo", "host": "b"},
                              {"session": "foo", "host": "c"})
        self.proxy_meta(log=path)
        self.write_session("foo")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            MOD._logs_audit(_args("foo", tail=1))
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertIn('"host": "c"', out.getvalue())

    def test_follow_stops_when_nothing_answers_the_control_socket(self):
        """§8's leftover: a live pid in proxy.json is not the proxy — after an unclean
        exit the pid may be recycled. With nothing on the control socket, follow must
        stop rather than trust os.kill(pid, 0) forever."""
        sleeper = self.start_sleeper()
        path = self.audit_log({"session": "foo", "decision": "allow"})
        self.proxy_meta(pid=sleeper.pid, log=path)       # a pid that IS alive — just not
        self.write_session("foo")                        # the proxy: no socket answers
        polls = itertools.count()

        def guarded_sleep(_):
            if next(polls) >= 3:
                raise AssertionError("follow kept polling on pid liveness alone")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(MOD.time, "sleep", guarded_sleep), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit):
                MOD._logs_audit(_args("foo", follow=True))
        self.assertIn("shared proxy is gone", err.getvalue())

    def test_follow_emits_new_lines_while_the_proxy_answers(self):
        path = self.audit_log({"session": "foo", "decision": "allow", "host": "a"})
        self.proxy_meta(log=path)
        self.write_session("foo")
        srv = _ControlSock(MOD.PROXY_SOCK)
        self.addCleanup(srv.close)
        steps = itertools.count()

        def scripted_sleep(_):
            step = next(steps)
            if step == 0:                                # new lines land between polls
                with open(path, "a") as fh:
                    fh.write('[12:00:01.000] {"session": "bar", "decision": "deny"}\n'
                             '[12:00:01.500] {"session": "foo", "decision": "deny", '
                             '"host": "b", "date": "2026-08-04", "status": 403}\n')
            elif step == 1:                              # `silkgate down foo` elsewhere
                shutil.rmtree(MOD.session_dir("foo"))
            else:
                raise AssertionError("follow did not stop after its session went away")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(MOD.time, "sleep", scripted_sleep), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit):
                MOD._logs_audit(_args("foo", follow=True))
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2, out.getvalue())
        self.assertIn('"host": "a"', lines[0])
        self.assertIn('"status": 403', lines[1])
        self.assertNotIn("bar", out.getvalue())


# -- ls: proxy health by identity ---------------------------------------------------

class CmdLsTest(SilkgateTest):

    def ls_output(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            MOD.cmd_ls(types.SimpleNamespace())
        return out.getvalue()

    def test_recycled_pid_is_not_reported_alive(self):
        """§8's leftover: `ls` used to report `proxy: pid N alive` about whatever
        unrelated process happened to hold the recycled pid."""
        sleeper = self.start_sleeper()
        self.proxy_meta(pid=sleeper.pid)                 # alive, but not the proxy
        self.assertIn("proxy: not running", self.ls_output())

    def test_socket_owner_is_reported_alive_over_a_stale_record(self):
        srv = _ControlSock(MOD.PROXY_SOCK)
        self.addCleanup(srv.close)
        self.proxy_meta(pid=_dead_pid())                 # record lies; the socket doesn't
        out = self.ls_output()
        self.assertIn("alive", out)
        self.assertIn(str(os.getpid()), out,
                      "the pid shown must be the socket owner's, not the record's")

    def test_socket_without_record_is_reported_not_silently_dropped(self):
        srv = _ControlSock(MOD.PROXY_SOCK)
        self.addCleanup(srv.close)
        out = self.ls_output()
        self.assertIn("proxy.json", out)
        self.assertNotIn("not running", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
