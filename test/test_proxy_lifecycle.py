#!/usr/bin/env python3
"""Lifecycle and race tests for cli/silkgate's proxy/session plumbing (FEEDBACK §2, §3, §8).

Everything runs against a temp state directory — never ~/.silkgate — with fake `msb` and
`mitmdump` executables on PATH and stub unix control sockets standing in for the live
proxy, so no docker, msb or mitmproxy is needed. cli/silkgate has no .py extension, so it
is loaded through SourceFileLoader; SILKGATE_CLI overrides which copy is loaded, which is
how the same tests demonstrate the pre-fix failures.

    python3 test/test_proxy_lifecycle.py -v
    SILKGATE_CLI=/path/to/old/cli/silkgate python3 test/test_proxy_lifecycle.py -v

What is covered:
  * pick_port under real concurrency (forked processes racing on one pool)
  * the port claim's lifetime: in-flight, crash leftover, provision failure, teardown
  * proxy identity (control socket + kernel peer pid) vs pid liveness, for
    _proxy_running, ensure_proxy and stop_proxy
  * `down <last>` racing an `up`: stop_proxy defers to claims; pick_port revives
  * _provision_session losing the name race without destroying the winner
  * _teardown_session keeping the session while the sandbox cannot be removed
  * both proxy entry points passing --listen-host (loopback) and --set rawtcp=false
"""
import importlib.util
import json
import multiprocessing
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("SILKGATE_CLI", REPO / "cli" / "silkgate"))

# The module reads SILKGATE_PROXY_BIND at import; the tests assert the default.
os.environ.pop("SILKGATE_PROXY_BIND", None)

_loader = SourceFileLoader("silkgate_cli", str(CLI))
_spec = importlib.util.spec_from_file_location("silkgate_cli", CLI, loader=_loader)
MOD = importlib.util.module_from_spec(_spec)
sys.modules["silkgate_cli"] = MOD
_loader.exec_module(MOD)

RULE = "api.anthropic.com/** GET\n"

# A stub proxy: owns a unix socket path and answers the control protocol, from its own
# process so kernel peer-pid checks see a pid that is not the test's. Prints "ready".
STUB_SOCK_SRC = r"""
import json, os, socket, sys, threading
path = sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(16)
sys.stdout.write("ready\n")
sys.stdout.flush()
def handle(conn):
    f = conn.makefile("rw")
    for line in f:
        try:
            req = json.loads(line)
        except ValueError:
            req = {}
        resp = {"ok": True}
        if req.get("op") == "list_secrets":
            resp["names"] = []
        f.write(json.dumps(resp) + "\n")
        f.flush()
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
"""

# Fake mitmdump: records its argv, binds its listen ports on exactly the host it was
# given (so a missing --listen-host is observable as a wildcard bind), serves the
# control protocol on EGRESS_CONTROL_SOCK, and runs until signalled.
FAKE_MITMDUMP_SRC = r"""
import json, os, socket, sys, threading, time
rec = os.environ.get("FAKE_MITM_ARGV")
if rec:
    with open(rec, "w") as fh:
        json.dump(sys.argv[1:], fh)
def opts(flag):
    return [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == flag and i + 1 < len(sys.argv)]
host = (opts("--listen-host") or [""])[0]
ports = [int(m.split("@", 1)[1]) for m in opts("--mode") if "@" in m]
ports += [int(p) for p in opts("--listen-port")]
keep = []
for p in ports:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, p))
    s.listen(16)
    keep.append(s)
def handle(conn):
    f = conn.makefile("rw")
    for line in f:
        try:
            req = json.loads(line)
        except ValueError:
            req = {}
        resp = {"ok": True}
        if req.get("op") == "list_secrets":
            resp["names"] = []
        f.write(json.dumps(resp) + "\n")
        f.flush()
cs = os.environ.get("EGRESS_CONTROL_SOCK")
if cs:
    try:
        os.unlink(cs)
    except FileNotFoundError:
        pass
    us = socket.socket(socket.AF_UNIX)
    us.bind(cs)
    us.listen(16)
    def acc():
        while True:
            c, _ = us.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=acc, daemon=True).start()
while True:
    time.sleep(3600)
"""

# Fake msb: logs every invocation; `rm`/`create` succeed per a JSON config file, and
# `list` shows whatever sandboxes the config says exist.
FAKE_MSB_SRC = r"""
import json, os, sys
d = os.environ["FAKE_MSB_DIR"]
with open(os.path.join(d, "log"), "a") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\n")
with open(os.path.join(d, "cfg")) as fh:
    cfg = json.load(fh)
cmd = sys.argv[1] if len(sys.argv) > 1 else ""
if cmd == "rm":
    sys.exit(0 if cfg.get("rm_ok", True) else 1)
if cmd == "create":
    sys.exit(0 if cfg.get("create_ok", True) else 1)
if cmd == "list":
    print("NAME IMAGE STATUS")
    for n in cfg.get("listed", []):
        print(n + " img running")
sys.exit(0)
"""


def _lan_ip():
    """A non-loopback address of this machine, or None (UDP connect sends nothing)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return None if ip.startswith("127.") else ip


def _free_pool_base(size):
    """A base port with `size` consecutive free ports above it."""
    for base in range(23000, 60000, size + 7):
        socks = []
        try:
            for p in range(base, base + size):
                s = socket.socket()
                s.bind(("", p))
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no free port pool found")


def _ping(sock_path):
    """Whether anything answers the control protocol at sock_path."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(str(sock_path))
            f = s.makefile("rw")
            f.write('{"op": "ping"}\n')
            f.flush()
            line = f.readline()
        return bool(line) and json.loads(line).get("ok") is True
    except (OSError, ValueError):
        return False


def _dead_pid():
    """A pid that no process holds: a reaped child's."""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def _autoreap(pid):
    """Reap `pid` the moment it dies, so kill(pid, 0) stops seeing a zombie."""
    def reap():
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
    threading.Thread(target=reap, daemon=True).start()


def _race_worker(barrier, q, proxy, name):
    """One concurrent `up`: pick a port, dawdle like provisioning does, land the meta."""
    try:
        barrier.wait(timeout=20)
        port = MOD.pick_port(proxy, name)
        time.sleep(0.05)                      # the window before meta.json becomes visible
        sdir = MOD.session_dir(name)
        sdir.mkdir(parents=True)
        (sdir / "rules.txt").write_text(RULE)
        MOD._write_json(sdir / "meta.json",
                        {"name": name, "sandbox": "sg-" + name, "port": port})
        q.put((name, port))
    except SystemExit as e:
        q.put((name, f"die: {e}"))
    except BaseException as e:
        q.put((name, f"error: {e!r}"))


class LifecycleTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sglc-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        silk = root / "silk"
        silk.mkdir()
        self._saved = {k: getattr(MOD, k) for k in
                       ("SILK_DIR", "LOG_DIR", "SESSIONS_DIR", "PROXY_JSON", "PROXY_SOCK")}
        MOD.SILK_DIR = silk
        MOD.LOG_DIR = silk / "logs"
        MOD.SESSIONS_DIR = silk / "sessions"
        MOD.PROXY_JSON = silk / "proxy.json"
        MOD.PROXY_SOCK = silk / "proxy.sock"
        MOD.SESSIONS_DIR.mkdir()
        # Fake tools first on PATH; env telling them where to record what they saw.
        fakebin = root / "bin"
        fakebin.mkdir()
        self.msb_dir = root / "msb"
        self.msb_dir.mkdir()
        (self.msb_dir / "log").write_text("")
        self.msb_cfg({})
        self.mitm_argv = root / "mitm-argv.json"
        for name, src in (("msb", FAKE_MSB_SRC), ("mitmdump", FAKE_MITMDUMP_SRC)):
            exe = fakebin / name
            exe.write_text(f"#!{sys.executable}\n{src}")
            exe.chmod(0o755)
        self._env = {k: os.environ.get(k) for k in ("PATH", "FAKE_MSB_DIR", "FAKE_MITM_ARGV")}
        os.environ["PATH"] = f"{fakebin}:{os.environ['PATH']}"
        os.environ["FAKE_MSB_DIR"] = str(self.msb_dir)
        os.environ["FAKE_MITM_ARGV"] = str(self.mitm_argv)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(MOD, k, v)
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # -- helpers ---------------------------------------------------------------

    def msb_cfg(self, cfg):
        (self.msb_dir / "cfg").write_text(json.dumps(cfg))

    def msb_log(self):
        return (self.msb_dir / "log").read_text()

    def claim_path(self, port):
        return MOD.SESSIONS_DIR / ".ports" / str(port)

    def write_claim(self, port, name, pid):
        d = MOD.SESSIONS_DIR / ".ports"
        d.mkdir(exist_ok=True)
        (d / str(port)).write_text(json.dumps({"name": name, "pid": pid}))

    def write_session(self, name, port):
        sdir = MOD.session_dir(name)
        sdir.mkdir(parents=True)
        (sdir / "rules.txt").write_text(RULE)
        MOD._write_json(sdir / "meta.json",
                        {"name": name, "sandbox": "sg-" + name, "port": port})

    def proxy_meta(self, pid, base=8090):
        meta = {"pid": pid, "base_port": base, "ports": list(range(base, base + MOD.POOL_SIZE)),
                "log": str(MOD.LOG_DIR / "proxy.log"), "sock": str(MOD.PROXY_SOCK)}
        MOD._write_json(MOD.PROXY_JSON, meta)
        return meta

    def start_stub_sock(self):
        proc = subprocess.Popen([sys.executable, "-c", STUB_SOCK_SRC, str(MOD.PROXY_SOCK)],
                                stdout=subprocess.PIPE, text=True)
        self.addCleanup(self._kill, proc)
        self.assertEqual(proc.stdout.readline().strip(), "ready")
        return proc

    def start_sleeper(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        self.addCleanup(self._kill, proc)
        return proc

    @staticmethod
    def _kill(proc):
        try:
            proc.kill()
            proc.wait(5)
        except OSError:
            pass
        if proc.stdout:
            proc.stdout.close()

    @staticmethod
    def _kill_pid(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    @staticmethod
    def _flag_pairs(argv):
        return list(zip(argv, argv[1:]))

    # -- pick_port: the port claim ----------------------------------------------

    def test_concurrent_pick_port_yields_distinct_ports(self):
        """§8 TOCTOU: N `up`s fanned out at once must not share a port."""
        stub = self.start_stub_sock()
        base = 8090
        proxy = self.proxy_meta(pid=stub.pid, base=base)
        n = 8
        ctx = multiprocessing.get_context("fork")
        barrier = ctx.Barrier(n)
        q = ctx.Queue()
        procs = [ctx.Process(target=_race_worker, args=(barrier, q, proxy, f"w{i}"))
                 for i in range(n)]
        for p in procs:
            p.start()
        results = [q.get(timeout=30) for _ in range(n)]
        for p in procs:
            p.join(10)
        ports = [port for _, port in results]
        self.assertTrue(all(isinstance(p, int) for p in ports), f"workers failed: {results}")
        self.assertEqual(len(set(ports)), n,
                         f"port collision: {sorted(results)} — two sessions would share a "
                         "listener and one guest would run under the other's ruleset")

    def test_pick_port_skips_inflight_claim(self):
        """A claim whose maker is alive is another `up` mid-provision, not a free port."""
        stub = self.start_stub_sock()
        proxy = self.proxy_meta(pid=stub.pid)
        self.write_claim(8090, "other", os.getpid())
        self.assertEqual(MOD.pick_port(proxy, "me"), 8091)

    def test_pick_port_reaps_crashed_claim(self):
        """A claim whose maker died with no session dir is a leftover, not a full pool."""
        stub = self.start_stub_sock()
        proxy = self.proxy_meta(pid=stub.pid)
        self.write_claim(8090, "ghost", _dead_pid())
        self.assertEqual(MOD.pick_port(proxy, "me"), 8090)

    def test_pick_port_respects_session_of_dead_provisioner(self):
        """Once the session dir exists the guest may be live: only `down` frees the port."""
        stub = self.start_stub_sock()
        proxy = self.proxy_meta(pid=stub.pid)
        self.write_session("crashed", 8090)
        self.write_claim(8090, "crashed", _dead_pid())
        self.assertEqual(MOD.pick_port(proxy, "me"), 8091)

    def test_pick_port_full_pool_dies(self):
        stub = self.start_stub_sock()
        proxy = self.proxy_meta(pid=stub.pid)
        for i, port in enumerate(proxy["ports"]):
            self.write_session(f"s{i}", port)
        with self.assertRaises(SystemExit):
            MOD.pick_port(proxy, "me")

    def test_pick_port_revives_proxy_stopped_under_it(self):
        """§8 lifecycle race: `down <last>` stopped the proxy after our ensure_proxy —
        picking a port must leave us with a live proxy, not a session nothing polices."""
        base = _free_pool_base(MOD.POOL_SIZE)
        proxy = self.proxy_meta(pid=_dead_pid(), base=base)
        port = MOD.pick_port(proxy, "me")
        started = MOD.read_proxy()
        if started and started.get("pid"):
            _autoreap(started["pid"])
            self.addCleanup(self._kill_pid, started["pid"])
        self.assertEqual(port, base)
        self.assertTrue(_ping(MOD.PROXY_SOCK),
                        "picked a port but no proxy is listening for the session")

    # -- proxy identity vs pid liveness ------------------------------------------

    def test_proxy_running_ignores_recycled_pid(self):
        """§8 PID reuse: a live unrelated process on the recorded pid is not the proxy."""
        sleeper = self.start_sleeper()
        self.proxy_meta(pid=sleeper.pid)
        self.assertFalse(MOD._proxy_running(),
                         "an unrelated process holding the pid counted as the proxy")

    def test_stop_proxy_spares_recycled_pid(self):
        """stop_proxy must never signal a pid nothing identified as the proxy."""
        sleeper = self.start_sleeper()
        _autoreap(sleeper.pid)
        meta = self.proxy_meta(pid=sleeper.pid)
        MOD.stop_proxy(meta)
        self.assertIsNone(sleeper.poll(), "SIGTERM/SIGKILL went to a recycled pid")
        self.assertFalse(MOD.PROXY_JSON.exists(), "stale proxy.json not cleared")

    def test_stop_proxy_kills_the_socket_owner(self):
        """When proxy.json lies about the pid, the socket's owner is the proxy."""
        stub = self.start_stub_sock()
        _autoreap(stub.pid)
        sleeper = self.start_sleeper()
        _autoreap(sleeper.pid)
        meta = self.proxy_meta(pid=sleeper.pid)
        MOD.stop_proxy(meta)
        try:
            stub.wait(5)
        except subprocess.TimeoutExpired:
            pass
        self.assertIsNotNone(stub.poll(),
                             "the process holding the control socket was not stopped")
        self.assertIsNone(sleeper.poll(), "the pid named by proxy.json was killed instead")
        self.assertFalse(MOD.PROXY_JSON.exists())

    def test_ensure_proxy_trusts_socket_not_pidfile(self):
        """A dead pid in proxy.json beside a live socket is a stale record, not a dead
        proxy: repair the record, never restart over the running one."""
        stub = self.start_stub_sock()
        self.proxy_meta(pid=_dead_pid())
        meta = MOD.ensure_proxy(8090)
        self.assertEqual(meta.get("pid"), stub.pid,
                         "returned meta does not name the live proxy")
        self.assertEqual((MOD.read_proxy() or {}).get("pid"), stub.pid,
                         "proxy.json still names a pid that is not the proxy")
        self.assertFalse(self.mitm_argv.exists(),
                         "a second proxy was started over the live one")
        self.assertIsNone(stub.poll())

    # -- stop racing up -----------------------------------------------------------

    def test_stop_proxy_defers_to_inflight_claim(self):
        """§8 lifecycle race, other half: a claimed port is a session being born."""
        stub = self.start_stub_sock()
        meta = self.proxy_meta(pid=stub.pid)
        self.write_claim(8090, "starting", os.getpid())
        MOD.stop_proxy(meta)
        self.assertIsNone(stub.poll(), "proxy killed under a starting session")
        self.assertTrue(MOD.PROXY_JSON.exists(), "proxy.json cleared under a starting session")

    def test_maybe_stop_proxy_leaves_proxy_for_inflight_claim(self):
        stub = self.start_stub_sock()
        self.proxy_meta(pid=stub.pid)
        self.write_claim(8090, "starting", os.getpid())
        MOD._maybe_stop_proxy()
        self.assertIsNone(stub.poll(), "proxy killed under a starting session")

    def test_maybe_stop_proxy_stops_when_idle(self):
        stub = self.start_stub_sock()
        _autoreap(stub.pid)
        self.proxy_meta(pid=stub.pid)
        MOD._maybe_stop_proxy()
        stub.wait(5)
        self.assertIsNotNone(stub.poll(), "idle proxy left running")
        self.assertFalse(MOD.PROXY_JSON.exists())

    # -- provisioning and teardown -------------------------------------------------

    def test_provision_failure_cleans_everything(self):
        """§8: a failed `msb create` must release the port claim and remove whatever
        sandbox msb half-registered, or the next `up` with that name collides."""
        stub = self.start_stub_sock()
        proxy = self.proxy_meta(pid=stub.pid)
        self.msb_cfg({"create_ok": False, "rm_ok": True})
        port = MOD.pick_port(proxy, "prov1")
        ruleset = MOD.RuleSet.parse(RULE)
        with self.assertRaises(SystemExit):
            MOD._provision_session("prov1", "img", port, RULE, ruleset,
                                   [], None, [], {"profiles": [], "command": None})
        self.assertFalse(MOD.session_dir("prov1").exists())
        self.assertFalse((MOD.SESSIONS_DIR / ".tmp-prov1").exists())
        self.assertFalse(self.claim_path(port).exists(), "port claim leaked")
        self.assertIn("rm sg-prov1", self.msb_log(),
                      "the half-created sandbox was left behind in msb")

    def test_provision_name_race_spares_the_winner(self):
        """Losing the name race must not destroy the winner's freshly landed session."""
        stub = self.start_stub_sock()
        self.proxy_meta(pid=stub.pid)
        self.msb_cfg({"create_ok": True})
        ruleset = MOD.RuleSet.parse(RULE)
        orig, planted = MOD._write_json, []

        def landing_racer(path, obj):
            if not planted:                       # the winner lands while we stage
                planted.append(True)
                self.write_session("racy", 8091)
                (MOD.session_dir("racy") / "marker").write_text("winner")
            orig(path, obj)

        MOD._write_json = landing_racer
        self.addCleanup(setattr, MOD, "_write_json", orig)
        with self.assertRaises(SystemExit):
            MOD._provision_session("racy", "img", 8090, RULE, ruleset,
                                   [], None, [], {"profiles": [], "command": None})
        self.assertTrue((MOD.session_dir("racy") / "marker").exists(),
                        "loser's cleanup deleted the winner's session dir")
        self.assertEqual((MOD.read_meta("racy") or {}).get("port"), 8091,
                         "winner's meta.json destroyed")

    def test_teardown_keeps_session_while_sandbox_survives(self):
        """§8: `msb rm` failing on a listed sandbox means a guest may still hold L3
        access to the port — the session dir and its claim must both stay."""
        self.write_session("t1", 8090)
        self.write_claim(8090, "t1", _dead_pid())
        self.msb_cfg({"rm_ok": False, "listed": ["sg-t1"]})
        meta = MOD.read_meta("t1")
        with self.assertRaises(SystemExit):
            MOD._teardown_session(meta)
        self.assertTrue(MOD.session_dir("t1").exists(),
                        "session dir removed while its guest may be alive")
        self.assertTrue(self.claim_path(8090).exists(),
                        "port freed while its guest may be alive")
        self.msb_cfg({"rm_ok": True})
        MOD._teardown_session(meta)
        self.assertFalse(MOD.session_dir("t1").exists())
        self.assertFalse(self.claim_path(8090).exists())

    def test_teardown_forgives_rm_of_unregistered_sandbox(self):
        """rm failing because the sandbox never registered is not a live guest."""
        self.write_session("t2", 8090)
        self.write_claim(8090, "t2", _dead_pid())
        self.msb_cfg({"rm_ok": False, "listed": []})
        MOD._teardown_session(MOD.read_meta("t2"))
        self.assertFalse(MOD.session_dir("t2").exists())
        self.assertFalse(self.claim_path(8090).exists())

    def test_teardown_releases_port_claim(self):
        self.write_session("t3", 8090)
        self.write_claim(8090, "t3", _dead_pid())
        self.msb_cfg({"rm_ok": True})
        MOD._teardown_session(MOD.read_meta("t3"))
        self.assertFalse(MOD.session_dir("t3").exists())
        self.assertFalse(self.claim_path(8090).exists(), "port claim outlived its session")

    # -- proxy entry points: bind address and rawtcp (§2, §3) ----------------------

    def test_start_shared_proxy_binds_loopback_and_disables_rawtcp(self):
        base = _free_pool_base(MOD.POOL_SIZE)
        meta = MOD.start_shared_proxy(base)
        _autoreap(meta["pid"])
        self.addCleanup(self._kill_pid, meta["pid"])
        argv = json.loads(self.mitm_argv.read_text())
        pairs = self._flag_pairs(argv)
        self.assertIn(("--set", "rawtcp=false"), pairs,
                      "raw-TCP fallback left on: an unparsable CONNECT becomes a tunnel")
        self.assertIn(("--listen-host", "127.0.0.1"), pairs,
                      "no explicit bind: every pool port is open to the LAN")
        self.assertEqual(sorted(int(m.split("@", 1)[1]) for f, m in pairs
                                if f == "--mode"),
                         list(range(base, base + MOD.POOL_SIZE)))
        with socket.create_connection(("127.0.0.1", base), timeout=2):
            pass
        lan = _lan_ip()
        if lan:
            with self.assertRaises(OSError, msg=f"pool port reachable via LAN addr {lan}"):
                socket.create_connection((lan, base), timeout=2).close()
        MOD.stop_proxy(meta)
        self.assertFalse(MOD.PROXY_JSON.exists())

    def test_start_proxy_binds_loopback_and_disables_rawtcp(self):
        port = _free_pool_base(1)
        proc, _log = MOD.start_proxy(RULE, port)
        self.addCleanup(self._kill, proc)
        argv = json.loads(self.mitm_argv.read_text())
        pairs = self._flag_pairs(argv)
        self.assertIn(("--set", "rawtcp=false"), pairs)
        self.assertIn(("--listen-host", "127.0.0.1"), pairs)
        self.assertIn(("--listen-port", str(port)), pairs)
        lan = _lan_ip()
        if lan:
            with self.assertRaises(OSError, msg=f"verify proxy reachable via LAN addr {lan}"):
                socket.create_connection((lan, port), timeout=2).close()
        MOD.stop(proc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
