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
  * the proxy's lifetime following the session registry (#29): the teardown or
    provision failure that leaves the registry empty stops the proxy, however many
    teardowns race and whoever started it — while other sessions or in-flight claims
    still keep it up
  * proxy startup refusing a port something else already holds, naming the holder
    (#30), and reading its own child's log for the bind failure a port probe cannot
    see — a bare connect answers in milliseconds against a squatter, long before the
    spawned mitmdump gets anywhere near its own bind
  * what each entry point leaves behind under the ways a human actually stops it —
    Ctrl-C in every phase (proxy wait, provisioning, the Tier-1 probe, the guest
    command, teardown itself), a second Ctrl-C during the unwind, SIGHUP, SIGTERM,
    and a reader closing the pipe — driven end to end: the real CLI as a subprocess
    in its own process group, fake msb/mitmdump holding each phase open long enough
    to land a signal in it (InterruptTest)
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
import termios
import threading
import time
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

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

# Fake mitmdump: records its argv (and its pid, beside it, so a test can still find it
# once it is orphaned), binds each `--mode regular@host:port` on exactly the host it
# names (so a wildcard bind is observable as one), serves the control protocol on
# EGRESS_CONTROL_SOCK, and runs until signalled. Mode specs split host from port at the
# last colon, as mitmproxy's own grammar does, so an IPv6 literal arrives bare.
FAKE_MITMDUMP_SRC = r"""
import json, os, socket, sys, threading, time
rec = os.environ.get("FAKE_MITM_ARGV")
if rec:
    with open(rec, "w") as fh:
        json.dump(sys.argv[1:], fh)
    with open(rec + ".pid", "w") as fh:
        fh.write(str(os.getpid()))
def opts(flag):
    return [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == flag and i + 1 < len(sys.argv)]
listens = []
for m in opts("--mode"):
    if "@" not in m:
        continue
    at = m.split("@", 1)[1]
    h, _, p = at.rpartition(":")
    listens.append((h, int(p)))
listens += [("", int(p)) for p in opts("--listen-port")]
keep = []
for h, p in listens:
    v6 = ":" in h
    s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((h, p))
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

# Fake mitmdump that lost its bind race but stays up, the failure reported only on its
# stdout/stderr — which start_proxy points at the log file. mitmproxy 12 exits instead,
# but only after a startup's worth of imports; this is the worst case either way: the
# port never answers and the log is the only witness. The message is the one a real
# mitmdump 12.2.3 writes (observed), so the log scan is held to the real format.
FAKE_MITMDUMP_BINDLESS_SRC = r"""
import sys, time
port = "?"
for i, a in enumerate(sys.argv):
    if a == "--mode" and i + 1 < len(sys.argv):
        port = sys.argv[i + 1].rsplit(":", 1)[1]
        break
print(f"[Errno 98] HTTP(S) proxy failed to listen on 127.0.0.1:{port} with [Errno 98] "
      f"error while attempting to bind on address ('127.0.0.1', {port}): "
      f"[errno 98] address already in use", flush=True)
while True:
    time.sleep(3600)
"""

# Fake mitmdump that starts and stays up but never binds or answers anything — a hung
# startup, as the readiness loop sees it. It advertises itself with a `.live` marker it
# removes on the SIGTERM stop() sends, so a test can tell "stopped on the way out" from
# "orphaned" without trusting pid probes: an exited-but-unreaped child is a zombie that
# still answers kill -0.
FAKE_MITMDUMP_DEAF_SRC = r"""
import os, signal, sys, time
rec = os.environ["FAKE_MITM_ARGV"]
with open(rec + ".pid", "w") as fh:
    fh.write(str(os.getpid()))
def bow_out(signum, frame):
    try:
        os.unlink(rec + ".live")
    except FileNotFoundError:
        pass
    sys.exit(0)
signal.signal(signal.SIGTERM, bow_out)
open(rec + ".live", "w").close()
while True:
    time.sleep(0.1)
"""

# Fake msb: logs every invocation; `rm`/`create` succeed per a JSON config file, and
# `list` shows whatever sandboxes the config says exist. The *_sleep keys hold one phase
# open so a signal can land inside it, each phase announcing itself with a marker file:
# `create`/`rm`/the Tier-1 `exec` sleep with SIGINT ignored (a group-wide Ctrl-C is aimed
# at what silkgate was doing; how these children die is not the thing under test), while
# a guest `exec` mimics the real one, whose in-guest command the terminal's Ctrl-C kills
# — it exits 130, cleanly. `exec_spew` floods stdout instead, for a reader that hangs up.
FAKE_MSB_SRC = r"""
import json, os, signal, sys, time
d = os.environ["FAKE_MSB_DIR"]
with open(os.path.join(d, "log"), "a") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\n")
with open(os.path.join(d, "cfg")) as fh:
    cfg = json.load(fh)
def mark(name):
    open(os.path.join(d, name), "w").close()
cmd = sys.argv[1] if len(sys.argv) > 1 else ""
if cmd == "rm":
    if cfg.get("rm_sleep"):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        mark("rm-live")
        time.sleep(cfg["rm_sleep"])
    sys.exit(0 if cfg.get("rm_ok", True) else 1)
if cmd == "create":
    if cfg.get("create_sleep"):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        mark("create-live")
        time.sleep(cfg["create_sleep"])
    sys.exit(0 if cfg.get("create_ok", True) else 1)
if cmd == "exec":
    if any("TIER1_" in a for a in sys.argv):
        if cfg.get("tier1_sleep"):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            mark("tier1-live")
            time.sleep(cfg["tier1_sleep"])
        print(cfg.get("tier1_out", "TIER1_OK"))
        sys.exit(0)
    mark("exec-live")
    signal.signal(signal.SIGINT, lambda *a: sys.exit(130))
    if cfg.get("exec_sleep"):
        time.sleep(cfg["exec_sleep"])
    if cfg.get("exec_spew"):
        while True:
            print("guest output " * 40, flush=True)
    print(cfg.get("exec_out", ""))
    sys.exit(cfg.get("exec_rc", 0))
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


def _teardown_worker(barrier, q, name, down_style):
    """One concurrent session teardown. down_style=False is what `run`'s finally block
    does for a proxy it did not start — _teardown_session and nothing else; True adds
    the _maybe_stop_proxy that `down` follows up with."""
    try:
        barrier.wait(timeout=20)
        MOD._teardown_session(MOD.read_meta(name))
        if down_style:
            MOD._maybe_stop_proxy()
        q.put((name, "ok"))
    except SystemExit as e:
        q.put((name, f"die: {e}"))
    except BaseException as e:
        q.put((name, f"error: {e!r}"))


class _FakeToolsCase(unittest.TestCase):
    """Temp state dir plus fake msb/mitmdump on PATH — the harness the in-process
    cases run against. Test classes subclass this; it holds no tests of its own."""

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
    def _settle(proc, timeout=5):
        """Give proc time to stop; it staying up is the caller's assertion, not an error."""
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            pass

    @staticmethod
    def _flag_pairs(argv):
        return list(zip(argv, argv[1:]))

    def install_mitmdump(self, src):
        """Swap the fake mitmdump for a variant with a different failure mode."""
        exe = Path(self._tmp.name) / "bin" / "mitmdump"
        exe.write_text(f"#!{sys.executable}\n{src}")
        exe.chmod(0o755)

    def expect_die(self, fn, *args):
        """Run fn expecting die(); return everything it said. If it succeeds instead —
        the pre-fix behavior the port-collision tests demonstrate — kill whatever proxy
        it started, then fail."""
        msgs = []
        with mock.patch.object(MOD, "say", msgs.append):
            try:
                result = fn(*args)
            except SystemExit:
                return "\n".join(str(m) for m in msgs)
        if isinstance(result, tuple):                     # start_proxy's (proc, log)
            self._kill(result[0])
        elif isinstance(result, dict) and result.get("pid"):   # start_shared_proxy's meta
            self._kill_pid(result["pid"])
        self.fail(f"{getattr(fn, '__name__', fn)} did not die")

    def squat(self, port, host="127.0.0.1"):
        """A live foreign listener on `port` — what an orphaned proxy looks like."""
        s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(8)
        self.addCleanup(s.close)
        return s

    def run_teardown_race(self, names, *, down_style):
        """Fork one _teardown_worker per session name and wait for all of them."""
        ctx = multiprocessing.get_context("fork")
        barrier = ctx.Barrier(len(names))
        q = ctx.Queue()
        procs = [ctx.Process(target=_teardown_worker, args=(barrier, q, n, down_style))
                 for n in names]
        for p in procs:
            p.start()
        results = [q.get(timeout=30) for _ in names]
        for p in procs:
            p.join(10)
        self.assertEqual([r for r in results if r[1] != "ok"], [],
                         f"teardown workers failed: {results}")


class LifecycleTest(_FakeToolsCase):

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
        _autoreap(stub.pid)
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

    # -- the proxy's lifetime follows the registry (#29) ---------------------------

    def test_teardown_of_last_session_stops_the_proxy(self):
        """#29: a `run` that found the proxy already up never offers to stop it, so the
        stop must belong to the teardown itself — reached by every session-removing
        path — not to each command's courtesy."""
        stub = self.start_stub_sock()
        _autoreap(stub.pid)
        self.proxy_meta(pid=stub.pid)
        self.write_session("last", 8090)
        self.write_claim(8090, "last", os.getpid())
        MOD._teardown_session(MOD.read_meta("last"))
        self._settle(stub)
        self.assertIsNotNone(stub.poll(),
                             "the proxy outlived its last session — the #29 orphan")
        self.assertFalse(MOD.PROXY_JSON.exists())

    def test_teardown_keeps_proxy_while_other_sessions_remain(self):
        stub = self.start_stub_sock()
        self.proxy_meta(pid=stub.pid)
        self.write_session("going", 8090)
        self.write_session("staying", 8091)
        MOD._teardown_session(MOD.read_meta("going"))
        self.assertIsNone(stub.poll(), "proxy stopped while a session still needs it")
        self.assertTrue(MOD.PROXY_JSON.exists())

    def test_teardown_keeps_proxy_under_inflight_claim(self):
        """`down <last>` racing an `up`: the claim of a session being born must keep
        the proxy up through the teardown-side stop, same as through stop_proxy."""
        stub = self.start_stub_sock()
        self.proxy_meta(pid=stub.pid)
        self.write_session("going", 8090)
        self.write_claim(8091, "starting", os.getpid())
        MOD._teardown_session(MOD.read_meta("going"))
        self.assertIsNone(stub.poll(), "proxy killed under a starting session")
        self.assertTrue(MOD.PROXY_JSON.exists())

    def test_concurrent_run_teardowns_leave_no_orphan(self):
        """#29 as observed: four concurrent `run`s finish, `ls` says no sessions, the
        proxy still holds every pool port. A run that did not start the proxy tears its
        session down and nothing more, so the last teardown out must stop the proxy."""
        stub = self.start_stub_sock()
        _autoreap(stub.pid)
        self.proxy_meta(pid=stub.pid)
        names = [f"r{i}" for i in range(4)]
        for i, name in enumerate(names):
            self.write_session(name, 8090 + i)
            self.write_claim(8090 + i, name, os.getpid())
        self.run_teardown_race(names, down_style=False)
        self.assertEqual(MOD.list_metas(), [])
        self._settle(stub)
        self.assertIsNotNone(stub.poll(),
                             "no sessions remain yet the proxy is still up — the #29 orphan")
        self.assertFalse(MOD.PROXY_JSON.exists())
        self.assertEqual(MOD._live_claims(), [])

    def test_concurrent_down_teardowns_stop_the_proxy(self):
        """The shape #29's sketch suspected: racing `down`s each seeing another's meta
        or claim and all deferring. Metas are removed in some total order and each
        worker's stop-check runs after its own removal, so the last one out always sees
        an empty registry — this passes against the pre-fix module too, which is the
        evidence the sketch was not the mechanism."""
        stub = self.start_stub_sock()
        _autoreap(stub.pid)
        self.proxy_meta(pid=stub.pid)
        names = [f"d{i}" for i in range(4)]
        for i, name in enumerate(names):
            self.write_session(name, 8090 + i)
            self.write_claim(8090 + i, name, os.getpid())
        self.run_teardown_race(names, down_style=True)
        self._settle(stub)
        self.assertIsNotNone(stub.poll(), "racing downs all deferred; proxy orphaned")
        self.assertFalse(MOD.PROXY_JSON.exists())

    def test_provision_failure_stops_proxy_left_without_sessions(self):
        """A first `up` whose provisioning fails must not leave the proxy it caused to
        be started running over an empty registry."""
        stub = self.start_stub_sock()
        _autoreap(stub.pid)
        proxy = self.proxy_meta(pid=stub.pid)
        self.msb_cfg({"create_ok": False, "rm_ok": True})
        port = MOD.pick_port(proxy, "solo")
        ruleset = MOD.RuleSet.parse(RULE)
        with self.assertRaises(SystemExit):
            MOD._provision_session("solo", "img", port, RULE, ruleset,
                                   [], None, [], {"profiles": [], "command": None})
        self._settle(stub)
        self.assertIsNotNone(stub.poll(),
                             "proxy left running with no session and no claim")
        self.assertFalse(MOD.PROXY_JSON.exists())

    # -- readiness is identity, not liveness (#30) ---------------------------------

    def test_start_proxy_refuses_port_already_in_use(self):
        """#30 as observed: with an orphan on the port, start_proxy's probe answered in
        milliseconds while its own mitmdump was still importing — it then failed its
        bind into the log alone and the guest talked to the wrong proxy. The collision
        must be refused before the spawn, and must say so."""
        port = _free_pool_base(1)
        self.squat(port)
        msg = self.expect_die(MOD.start_proxy, RULE, port)
        self.assertIn(f"port {port} is already in use", msg)
        self.assertFalse(self.mitm_argv.exists(),
                         "a mitmdump was spawned against a port something else holds")

    def test_port_collision_names_the_shared_proxy(self):
        """The error message is half the fix: when the squatter is the shared proxy —
        the one listener whose identity the control socket can vouch for — the refusal
        names its pid and points at `silkgate ls`, instead of leaving the next person
        to trace a 403 back through a guest's apt output."""
        stub = self.start_stub_sock()
        base = _free_pool_base(1)
        self.proxy_meta(pid=stub.pid, base=base)
        self.squat(base)
        msg = self.expect_die(MOD.start_proxy, RULE, base)
        self.assertIn(f"pid {stub.pid}", msg)
        self.assertIn("silkgate ls", msg)

    def test_start_shared_proxy_refuses_squatted_pool_port(self):
        """The whole pool is checked, not just the base port: mitmdump binds all
        sixteen or exits, so a squatter anywhere in the pool dooms it."""
        base = _free_pool_base(MOD.POOL_SIZE)
        self.squat(base + 3)
        msg = self.expect_die(MOD.start_shared_proxy, base)
        self.assertIn(f"port {base + 3} is already in use", msg)
        self.assertFalse(MOD.PROXY_JSON.exists())

    def test_bind_failure_surfaces_from_the_log(self):
        """A mitmdump that loses its bind reports it only inside the log file (stdout
        and stderr both point there). The readiness loop must read it and fail fast,
        naming the failure — not wait out the timeout, and never report ready."""
        self.install_mitmdump(FAKE_MITMDUMP_BINDLESS_SRC)
        port = _free_pool_base(1)
        msg = self.expect_die(MOD.start_proxy, RULE, port)
        self.assertIn("address already in use", msg,
                      "the bind error stayed buried in the log file")

    def test_wait_control_sock_verifies_the_owner(self):
        """Given a pid, the control-socket wait accepts only that process answering:
        ports coming up says nothing about who owns the socket."""
        stub = self.start_stub_sock()
        MOD._wait_control_sock(2, stub.pid)      # the stub answering as itself: ready
        msg = self.expect_die(MOD._wait_control_sock, 2, stub.pid + 1)
        self.assertIn(str(stub.pid), msg)

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
        modes = [m.split("@", 1)[1] for f, m in pairs if f == "--mode"]
        for port in range(base, base + MOD.POOL_SIZE):
            for addr in ("127.0.0.1", "::1"):
                self.assertIn(f"{addr}:{port}", modes,
                              "every pool port needs both loopback families: a guest "
                              "resolves the host alias to its IPv6 address first")
        self.assertEqual(len(modes), MOD.POOL_SIZE * 2,
                         "a bind beyond the two loopbacks would widen the exposure")
        # Both families must actually accept, not merely appear in the argv: a guest
        # resolves the host alias to its IPv6 address first, so a v4-only listener is
        # reached by nothing that trusts getaddrinfo's ordering.
        for addr in ("127.0.0.1", "::1"):
            with socket.create_connection((addr, base), timeout=2):
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
        modes = [m.split("@", 1)[1] for f, m in pairs if f == "--mode"]
        self.assertEqual(sorted(modes), sorted([f"127.0.0.1:{port}", f"::1:{port}"]))
        for addr in ("127.0.0.1", "::1"):
            with socket.create_connection((addr, port), timeout=2):
                pass
        lan = _lan_ip()
        if lan:
            with self.assertRaises(OSError, msg=f"verify proxy reachable via LAN addr {lan}"):
                socket.create_connection((lan, port), timeout=2).close()
        MOD.stop(proc)

    def test_modes_place_one_listener_per_bind_address(self):
        """A mode spec is the only way to bind more than one address, and its grammar
        splits host from port at the last colon — so an IPv6 literal must go in bare."""
        self.assertEqual(MOD._modes(8090),
                         ["--mode", "regular@127.0.0.1:8090", "--mode", "regular@::1:8090"])
        for binds, want in (
            (("127.0.0.1",), ["regular@127.0.0.1:9000"]),
            (("::1",), ["regular@::1:9000"]),
            (("10.0.0.2", "fd00::2"), ["regular@10.0.0.2:9000", "regular@fd00::2:9000"]),
        ):
            with mock.patch.object(MOD, "PROXY_BINDS", binds):
                self.assertEqual([a for a in MOD._modes(9000) if a != "--mode"], want)
                # Brackets would be read as part of the hostname and fail to resolve.
                self.assertNotIn("[", "".join(MOD._modes(9000)))

    def test_bind_override_is_a_list_and_drives_the_readiness_probe(self):
        """SILKGATE_PROXY_BIND exists for a platform whose guests reach the host on a real
        interface; the probe follows the bind so the two cannot drift apart."""
        self.assertEqual(MOD.PROXY_BINDS, ("127.0.0.1", "::1"))
        self.assertEqual(MOD._probe_addr(8090), ("127.0.0.1", 8090))
        with mock.patch.object(MOD, "PROXY_BINDS", ("::1",)):
            self.assertEqual(MOD._probe_addr(8090), ("::1", 8090))
        for wildcard, dialed in (("0.0.0.0", "127.0.0.1"), ("::", "::1")):
            with mock.patch.object(MOD, "PROXY_BINDS", (wildcard,)):
                self.assertEqual(MOD._probe_addr(8090), (dialed, 8090))


def _start_proxy_worker(barrier, port):
    """One start_proxy against a mitmdump that never comes up, ready to be interrupted."""
    barrier.wait(timeout=20)
    try:
        MOD.start_proxy(RULE, port)
    except BaseException:
        pass


class InterruptSideEffectTest(_FakeToolsCase):
    """The in-process halves of the interrupt work: pieces whose contract is a return
    value or a side effect on this process, not an exit status."""

    def test_wait_foreground_reports_a_signal_death_like_a_shell(self):
        """proc.wait() hands back -SIGINT for a child Ctrl-C killed; fed to sys.exit
        that is read as a status byte and mangled, so the caller must see 130."""
        proc = subprocess.Popen([sys.executable, "-c",
                                 "import os, signal;"
                                 " signal.signal(signal.SIGINT, signal.SIG_DFL);"
                                 " os.kill(os.getpid(), signal.SIGINT)"])
        self.assertEqual(MOD.wait_foreground(proc), 130)

    def test_say_survives_a_dead_stderr(self):
        """The unwind's own prints must not become a second failure: by teardown time
        stderr can be a closed pipe or a vanished terminal."""
        class Dead:
            def write(self, *a):
                raise BrokenPipeError()

            def flush(self):
                raise BrokenPipeError()
        with mock.patch.object(sys, "stderr", Dead()):
            MOD.say("teardown progress")             # must not raise

    def test_deferred_interrupts_holds_sigint_and_restores(self):
        """Inside the guard a SIGINT is noted, never raised; outside, the previous
        handler is back. This is what keeps a second Ctrl-C out of a teardown."""
        before = signal.getsignal(signal.SIGINT)
        saved, devnull = os.dup(2), os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 2)                          # the guard acknowledges on fd 2
        try:
            with MOD._deferred_interrupts():
                os.kill(os.getpid(), signal.SIGINT)  # bare, this raises KeyboardInterrupt
                time.sleep(0.05)                     # give the handler its bytecode edge
        finally:
            os.dup2(saved, 2)
            os.close(saved)
            os.close(devnull)
        self.assertIs(signal.getsignal(signal.SIGINT), before)

    def test_pty_relay_stops_a_child_the_reader_hung_up_on(self):
        """A BrokenPipeError mid-relay must not orphan the msb exec child against a
        sandbox the caller is about to remove."""
        stopped = Path(self._tmp.name) / "child-stopped"
        child = ("import signal, sys, time\n"
                 "def bye(*a):\n"
                 f"    open({str(stopped)!r}, 'w').close()\n"
                 "    sys.exit(0)\n"
                 "signal.signal(signal.SIGTERM, bye)\n"
                 "print('x', flush=True)\n"
                 "time.sleep(30)\n")
        real = sys.stdout
        sys.stdout = type("Gone", (), {"buffer": property(lambda s: (_ for _ in ()).throw(
            BrokenPipeError()))})()
        try:
            with self.assertRaises(BrokenPipeError):
                MOD._pty_relay([sys.executable, "-c", child], demux=True)
        finally:
            sys.stdout = real
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not stopped.exists():
            time.sleep(0.05)
        self.assertTrue(stopped.exists(),
                        "the relay's child outlived the dead pipe — an msb exec left "
                        "running against a sandbox about to be removed")

    def test_start_proxy_interrupted_mid_wait_stops_its_mitmdump(self):
        """A Ctrl-C during the readiness wait lands before the caller has any handle on
        the spawned mitmdump — start_proxy itself must stop it or nobody ever does."""
        self.install_mitmdump(FAKE_MITMDUMP_DEAF_SRC)
        live = Path(str(self.mitm_argv) + ".live")
        self.addCleanup(self._kill_recorded_mitm)
        port = _free_pool_base(1)
        ctx = multiprocessing.get_context("fork")
        barrier = ctx.Barrier(2)
        worker = ctx.Process(target=_start_proxy_worker, args=(barrier, port))
        worker.start()
        barrier.wait(timeout=20)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not live.exists():
            time.sleep(0.02)
        self.assertTrue(live.exists(), "the fake mitmdump never started")
        os.kill(worker.pid, signal.SIGINT)
        worker.join(20)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and live.exists():
            time.sleep(0.05)
        self.assertFalse(live.exists(),
                         "the mitmdump spawned before the interrupt was left running "
                         "— an orphan proxy nothing can ever stop")

    def test_run_guest_tty_restores_the_callers_terminal(self):
        """-t with a real terminal hands the child the caller's tty directly; a child
        that leaves it raw must not hand it back that way (the `stty sane` failure)."""
        ptm, pts = os.openpty()
        self.addCleanup(os.close, ptm)
        raw = "import sys, tty; tty.setraw(sys.stdout.fileno())"
        driver = (
            "import importlib.util, sys\n"
            "from importlib.machinery import SourceFileLoader\n"
            f"loader = SourceFileLoader('sg', {str(CLI)!r})\n"
            f"spec = importlib.util.spec_from_file_location('sg', {str(CLI)!r},"
            " loader=loader)\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "loader.exec_module(mod)\n"
            f"sys.exit(mod.run_guest(lambda c: [sys.executable, '-c', {raw!r}],"
            " ['x'], tty=True))\n")
        proc = subprocess.Popen([sys.executable, "-c", driver],
                                stdin=pts, stdout=pts, stderr=subprocess.PIPE, text=True)
        os.close(pts)
        _, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 0, err)
        self.assertTrue(termios.tcgetattr(ptm)[3] & termios.ECHO,
                        "the child left the terminal raw and nothing restored it")

    def _kill_recorded_mitm(self):
        pidfile = Path(str(self.mitm_argv) + ".pid")
        if pidfile.exists():
            self._kill_pid(int(pidfile.read_text()))


class InterruptTest(unittest.TestCase):
    """What each entry point leaves behind when a human stops it, end to end: the real
    CLI runs as a subprocess in its own process group with HOME pointed at a scratch
    directory (so ~/.silkgate lives there), fake msb/mitmdump on PATH hold whichever
    phase the test targets open (see FAKE_MSB_SRC), the signal goes to the whole group
    — what a terminal's Ctrl-C or a closing session actually does — and the assertions
    are on what survives: session dirs, port claims, proxy listeners, the exit status,
    and a stderr free of tracebacks. Proxy death is asserted on its listeners and
    control socket, never kill -0: the mitmdump child is not ours to reap, and its
    zombie would answer. SILKGATE_CLI points these tests at an older CLI the same way
    it does the in-process ones."""

    maxDiff = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sgint-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.home = root / "home"
        self.home.mkdir()
        self.silk = self.home / ".silkgate"
        fakebin = root / "bin"
        fakebin.mkdir()
        self.fakebin = fakebin
        self.msb_dir = root / "msb"
        self.msb_dir.mkdir()
        (self.msb_dir / "log").write_text("")
        self.cfg({})
        self.mitm_argv = root / "mitm-argv.json"
        for name, src in (("msb", FAKE_MSB_SRC), ("mitmdump", FAKE_MITMDUMP_SRC)):
            exe = fakebin / name
            exe.write_text(f"#!{sys.executable}\n{src}")
            exe.chmod(0o755)
        self.env = dict(os.environ, HOME=str(self.home),
                        PATH=f"{fakebin}:{os.environ['PATH']}",
                        FAKE_MSB_DIR=str(self.msb_dir),
                        FAKE_MITM_ARGV=str(self.mitm_argv))
        self.env.pop("SILKGATE_PROXY_BIND", None)
        self.base = _free_pool_base(MOD.POOL_SIZE)
        self.addCleanup(self._kill_recorded_mitm)

    # -- plumbing ----------------------------------------------------------------

    def cfg(self, cfg):
        (self.msb_dir / "cfg").write_text(json.dumps(cfg))

    def msb_log(self):
        return (self.msb_dir / "log").read_text()

    def spawn(self, *argv, preexec_fn=None):
        proc = subprocess.Popen([sys.executable, str(CLI), *argv],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, env=self.env, text=True,
                                start_new_session=True, preexec_fn=preexec_fn)
        self.addCleanup(self._kill_group, proc)
        return proc

    def run_argv(self):
        return ("run", "--image", "img", "--port", str(self.base), "--", "guestcmd")

    def wait_for(self, predicate, what, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail(f"timed out waiting for {what}")

    def marker(self, name):
        return (self.msb_dir / name).exists

    def interrupt(self, proc, sig=signal.SIGINT):
        os.killpg(proc.pid, sig)

    def finish(self, proc, timeout=60):
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            out, err = proc.communicate()
            self.fail(f"silkgate did not exit; stderr so far:\n{err}")
        return out, err

    def _kill_group(self, proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.wait(5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for stream in (proc.stdout, proc.stderr):
            if stream:
                stream.close()

    def _kill_recorded_mitm(self):
        pidfile = Path(str(self.mitm_argv) + ".pid")
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except OSError:
                pass

    # -- assertions --------------------------------------------------------------

    def assert_quiet(self, err):
        self.assertNotIn("Traceback", err, f"an interrupt printed a stack trace:\n{err}")
        self.assertNotIn("Exception ignored", err,
                         f"interpreter-shutdown noise reached the user:\n{err}")

    def assert_no_leftovers(self, err):
        sessions = self.silk / "sessions"
        if sessions.is_dir():
            left = [p.name for p in sessions.iterdir() if p.name != ".ports"]
            self.assertEqual(left, [], f"session state survived: {left}\nstderr:\n{err}")
            claims = sessions / ".ports"
            if claims.is_dir():
                self.assertEqual([p.name for p in claims.iterdir()], [],
                                 "a port claim survived")
        self.assert_proxy_stopped(err)

    def assert_proxy_stopped(self, err):
        self.assertFalse((self.silk / "proxy.json").exists(),
                         f"proxy.json survived\nstderr:\n{err}")
        self.assertFalse(_ping(self.silk / "proxy.sock"),
                         "something still answers the control socket")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.base), timeout=0.5).close()
            except OSError:
                return
            time.sleep(0.05)
        self.fail("the shared proxy still holds its base port — the orphan this "
                  "brief opened with")

    def write_session(self, name, port, command=None):
        sdir = self.silk / "sessions" / name
        sdir.mkdir(parents=True)
        (sdir / "rules.txt").write_text(RULE)
        meta = {"name": name, "sandbox": "sg-" + name, "port": port}
        if command:
            meta["command"] = command
        (sdir / "meta.json").write_text(json.dumps(meta))
        return sdir

    # -- run ---------------------------------------------------------------------

    def test_run_sigint_during_the_guest_command(self):
        """Ctrl-C mid-command: the guest dies, the session is torn down whole, and the
        user sees no traceback — just status 130, the shell's own convention."""
        self.cfg({"exec_sleep": 120})
        proc = self.spawn(*self.run_argv())
        self.wait_for(self.marker("exec-live"), "the guest command to start")
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 130, err)
        self.assert_no_leftovers(err)
        self.assertIn("rm sg-", self.msb_log(), "the guest sandbox was never removed")

    def test_run_sigint_during_provisioning(self):
        """Ctrl-C while msb create is in flight: the half-made session is unwound —
        staging dir, port claim, half-registered sandbox, proxy — with status 130."""
        self.cfg({"create_sleep": 120})
        proc = self.spawn(*self.run_argv())
        self.wait_for(self.marker("create-live"), "msb create to start")
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 130, err)
        self.assert_no_leftovers(err)
        self.assertIn("rm sg-", self.msb_log(),
                      "a create the interrupt cut short can still have registered "
                      "the sandbox; nothing removed it")

    def test_run_second_sigint_does_not_abort_the_teardown(self):
        """The impatient second Ctrl-C, landing mid-unwind: it is deferred (and said
        to be), the removal completes, and nothing is left half-removed."""
        self.cfg({"exec_sleep": 120, "rm_sleep": 1.5})
        proc = self.spawn(*self.run_argv())
        self.wait_for(self.marker("exec-live"), "the guest command to start")
        self.interrupt(proc)
        self.wait_for(self.marker("rm-live"), "the teardown's msb rm to start")
        time.sleep(0.1)
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 130, err)
        self.assert_no_leftovers(err)
        self.assertIn("finishing cleanup", err,
                      "the deferred interrupt was not acknowledged — a silent pause "
                      "reads as a hang and invites a kill -9")

    def test_run_broken_pipe_tears_down_quietly(self):
        """`silkgate run ... | head -3`: the reader hangs up mid-stream. The guest and
        session still come down, and the exit is a pipe death (141), not a traceback —
        the failure that left a microVM running this evening."""
        self.cfg({"exec_spew": True})
        proc = self.spawn(*self.run_argv())
        self.wait_for(self.marker("exec-live"), "the guest command to start")
        proc.stdout.readline()                       # the stream is flowing; now hang up
        proc.stdout.close()
        err = proc.stderr.read()
        try:
            rc = proc.wait(60)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            self.fail(f"silkgate did not exit after its reader hung up:\n{err}")
        self.assert_quiet(err)
        self.assertEqual(rc, 141, err)
        self.assert_no_leftovers(err)
        self.assertIn("rm sg-", self.msb_log(), "the guest sandbox was never removed")

    def test_run_sighup_unwinds_like_sigterm(self):
        """The terminal closing over a live run: SIGHUP must reach the finally blocks
        — status 129, session and proxy gone — not kill silkgate outright."""
        self.cfg({"exec_sleep": 120})
        proc = self.spawn(*self.run_argv())
        self.wait_for(self.marker("exec-live"), "the guest command to start")
        self.interrupt(proc, signal.SIGHUP)
        out, err = self.finish(proc)
        self.assertEqual(proc.returncode, 129,
                         f"SIGHUP did not run the unwind (exit {proc.returncode})")
        self.assert_no_leftovers(err)

    def test_run_sigterm_still_cleans_up(self):
        """The behavior the brief calls already safe — `timeout N silkgate run` — held
        as a regression: SIGTERM exits 143 through the same unwind."""
        self.cfg({"exec_sleep": 120})
        proc = self.spawn(*self.run_argv())
        self.wait_for(self.marker("exec-live"), "the guest command to start")
        self.interrupt(proc, signal.SIGTERM)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 143, err)
        self.assert_no_leftovers(err)

    def test_run_sigint_during_the_proxy_wait(self):
        """Ctrl-C inside the up-to-15s readiness wait — the impatient interrupt a slow
        proxy invites. The mitmdump just spawned has no record yet; if this exit does
        not stop it, nothing ever can."""
        deaf = self.fakebin / "mitmdump"
        deaf.write_text(f"#!{sys.executable}\n{FAKE_MITMDUMP_DEAF_SRC}")
        live = Path(str(self.mitm_argv) + ".live")
        proc = self.spawn(*self.run_argv())
        self.wait_for(live.exists, "the fake mitmdump to start")
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 130, err)
        self.wait_for(lambda: not live.exists(), "the spawned mitmdump to be stopped",
                      timeout=10)
        self.assertFalse((self.silk / "proxy.json").exists())

    # -- up ----------------------------------------------------------------------

    def test_up_sigint_during_provisioning(self):
        """An interrupted `up` unwinds whole: no session dir, no claim, no proxy —
        and quietly. (What to leave behind is a judgement: nothing of the user's is
        in the guest until exec/attach run, after `up` returns, and a session left
        up would hide that the command failed.)"""
        self.cfg({"create_sleep": 120})
        proc = self.spawn("up", "--name", "s1", "--image", "img",
                          "--port", str(self.base))
        self.wait_for(self.marker("create-live"), "msb create to start")
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 130, err)
        self.assert_no_leftovers(err)

    def test_up_sigint_during_the_tier1_probe(self):
        """The window after the guest exists and before it is handed over: an
        interrupt here must not leave an unproven session up behind a failed
        command — the leak `up` had, since nothing here was under a finally."""
        self.cfg({"tier1_sleep": 120})
        proc = self.spawn("up", "--name", "s1", "--image", "img",
                          "--port", str(self.base))
        self.wait_for(self.marker("tier1-live"), "the Tier-1 probe to start")
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 130, err)
        self.assert_no_leftovers(err)
        self.assertIn("rm sg-s1", self.msb_log(), "the booted guest was never removed")

    def test_up_under_nohup_ignores_sighup(self):
        """nohup's SIG_IGN is the caller declaring hangups expected; installing the
        129 handler over it would turn every hangup into a torn-down `up`."""
        self.cfg({"create_sleep": 120})
        proc = self.spawn("up", "--name", "s1", "--image", "img",
                          "--port", str(self.base),
                          preexec_fn=lambda: signal.signal(signal.SIGHUP,
                                                           signal.SIG_IGN))
        self.wait_for(self.marker("create-live"), "msb create to start")
        self.interrupt(proc, signal.SIGHUP)
        time.sleep(0.5)
        self.assertIsNone(proc.poll(), "SIGHUP killed a nohup'd silkgate")
        self.interrupt(proc)                         # now end the test run for real
        out, err = self.finish(proc)
        self.assertEqual(proc.returncode, 130, err)

    # -- exec / attach: the session is the user's; an interrupt ends only the command

    def test_exec_sigint_leaves_the_session_alone(self):
        sdir = self.write_session("s1", self.base)
        self.cfg({"exec_sleep": 120})
        proc = self.spawn("exec", "s1", "--", "guestcmd")
        self.wait_for(self.marker("exec-live"), "the exec'd command to start")
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 130, err)
        self.assertTrue(sdir.exists(), "Ctrl-C in an exec tore down a persistent session")
        self.assertNotIn("rm sg-s1", self.msb_log(),
                         "Ctrl-C in an exec removed a persistent session's sandbox")

    def test_attach_sigint_leaves_the_session_alone(self):
        sdir = self.write_session("s1", self.base, command=["guestcmd"])
        self.cfg({"exec_sleep": 120})
        proc = self.spawn("attach", "s1")
        self.wait_for(self.marker("exec-live"), "the attached command to start")
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 130, err)
        self.assertTrue(sdir.exists(), "Ctrl-C in an attach tore down the session")

    # -- down --------------------------------------------------------------------

    def test_down_sigint_mid_removal_completes_the_removal(self):
        """Ctrl-C while `down` is mid-removal is the half-removed-session recipe: the
        signal is deferred, the msb child (its own process group) keeps removing, and
        the command finishes what it started — exit 0, session gone."""
        sdir = self.write_session("s1", self.base)
        self.cfg({"rm_sleep": 1.5})
        proc = self.spawn("down", "s1")
        self.wait_for(self.marker("rm-live"), "the msb rm to start")
        time.sleep(0.1)
        self.interrupt(proc)
        out, err = self.finish(proc)
        self.assert_quiet(err)
        self.assertEqual(proc.returncode, 0, err)
        self.assertFalse(sdir.exists(), "the session survived a completed `down`")
        self.assertIn("session s1 down", err,
                      "the completed removal was not reported")


if __name__ == "__main__":
    unittest.main(verbosity=2)
