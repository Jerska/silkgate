#!/usr/bin/env python3
"""The host-side oracles `silkgate verify` reads its evidence from.

    python3 test/test_verify_oracles.py [-v]

`cmd_verify` used to render its whole verdict from two lines the guest printed. These are the
fixtures that put evidence outside the guest, and everything about them that does not need a
microVM is exercised here for real: the recording endpoint against a real HTTP client, the
arrival observer against real TCP and UDP sends (including one it must report as a leak), the
guest-side probe script under a real bash against a stub proxy, the audit assertion against a
log shaped like mitmdump's, and the argv the run would hand msb.

The last class runs `cmd_verify` itself over fakes — a fake msb that runs the guest command on
this host, a stub proxy whose every decision comes from the real rule engine, and a stub check
script — so the sequencing and the verdicts are pinned too, not only the pieces.

What is deliberately NOT here: msb, mitmproxy, docker, a guest, or any network beyond
loopback. The three links this file cannot reach — that `msb create` boots the bare `debian`
image, that mitmproxy resolves `localhost` to the loopback the recorder bound, and that a
guest's denied sendto really produces no arrival — are named in the report that accompanies
these changes, each with the host command that settles it.

`cli/silkgate` has no .py suffix, so it is loaded through a SourceFileLoader; importing it
touches no state on disk. A fake `msb` goes on PATH for the argv and reaping tests, because
those call which() and would otherwise die naming an install command.
"""
import http.client
import importlib.machinery
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]

_loader = importlib.machinery.SourceFileLoader("silkgate_cli", str(REPO / "cli" / "silkgate"))
_spec = importlib.util.spec_from_loader("silkgate_cli", _loader)
sg = importlib.util.module_from_spec(_spec)
sys.modules["silkgate_cli"] = sg
_loader.exec_module(sg)

sys.path.insert(0, str(REPO / "mitmaddon"))
from rule_engine import RuleSet                                          # noqa: E402

_BIN = tempfile.TemporaryDirectory(prefix="silkgate-oracle-bin-")


def setUpModule():
    """A fake msb on PATH, logging every invocation, so argv/reaping tests need no real one."""
    binary = Path(_BIN.name) / "msb"
    binary.write_text("#!/bin/sh\n"
                      'echo "$*" >> "$MSB_LOG"\n'
                      'case "$1" in list) cat "$MSB_LIST" ;; esac\n'
                      "exit ${MSB_RC:-0}\n")
    binary.chmod(0o755)
    os.environ["PATH"] = f"{_BIN.name}{os.pathsep}{os.environ['PATH']}"
    os.environ.setdefault("MSB_LOG", str(Path(_BIN.name) / "msb.log"))
    os.environ.setdefault("MSB_LIST", str(Path(_BIN.name) / "msb.list"))


def tearDownModule():
    _BIN.cleanup()


def _dead_pid():
    """A pid no process holds: a reaped child's."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _free_port(span=1):
    """A port with `span` consecutive ports free on both loopback families — what the oracles
    bind, since they take the two ports beside the proxy's."""
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port + span <= 65535 and all(_port_free(port + n) for n in range(span)):
            return port
    raise unittest.SkipTest(f"no {span} consecutive ports free on both loopback families")


def _squat(case, port):
    """Hold `port` on IPv4 loopback until `case` ends. One family is enough to make the
    CLI's _port_free report taken: it asks every bind address and fails on the first."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind(("127.0.0.1", port))
    holder.listen(1)
    case.addCleanup(holder.close)


# The CLI's port-collision refusals, by fragment — the predicate that tells a neighbor
# taking a port between a probe and a bind from a real verdict. Each copies message text
# from cli/silkgate: _IN_USE from _port_in_use_error (the proxy's own port), _CANNOT_BIND
# from _oracle_bind and the recorder's bind (the oracle ports). They drift if those
# messages change, until the queued verify-port-probe task moves them into cli/silkgate
# as named constants.
_IN_USE = "is already in use"
_CANNOT_BIND = "cannot bind the"


def _collided(text):
    # The third surface has a named constant already: a proxy that loses its bind after
    # start_proxy's probe dies with the log's tail in the refusal, and sg._BIND_FAILURE
    # is the fragment _wait_proxy_ready itself reads that tail for.
    return (_IN_USE in text or _CANNOT_BIND in text
            or sg._BIND_FAILURE.decode() in text.lower())


def _bind_or_skip(action, span=1, attempts=5, pick=None):
    """Pick a free port with `pick` and run `action(port)`; return (port, result).

    Every pick is probe-then-bind, so a concurrent process on this host can take the port
    in between: the action then raises OSError (a raw bind) or SystemExit (the CLI's die
    naming the holder). Either way the port is lost, not the test — retry on a fresh one,
    and after `attempts` collisions skip naming the last error rather than fail on a host
    this contended.
    """
    pick = pick or _free_port
    last = None
    for _ in range(attempts):
        port = pick(span)
        said = []
        try:
            with mock.patch.object(sg, "say", said.append):
                result = action(port)
        except SystemExit:
            last = "\n".join(str(m) for m in said)
            continue
        except OSError as e:
            last = str(e)
            continue
        return port, result
    raise unittest.SkipTest(f"ports collided {attempts} times; last error: {last}")


def _die_message(fn, *args, **kwargs):
    """Run `fn` expecting die(); return everything it said."""
    said = []
    with mock.patch.object(sg, "say", said.append):
        try:
            fn(*args, **kwargs)
        except SystemExit:
            return "\n".join(str(m) for m in said)
    raise AssertionError(f"{getattr(fn, '__name__', fn)} did not die")


class PortProbe(unittest.TestCase):
    """The probe every pick above trusts, against the binds the oracles actually make."""

    def test_a_udp_holder_on_v6_loopback_is_seen(self):
        # sg._ArrivalObserver binds udp on ::1 too: a probe that skips that family passes
        # a port the observer then dies on — the flake this module used to have.
        holder = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.addCleanup(holder.close)
        holder.bind(("::1", 0))
        self.assertFalse(_port_free(holder.getsockname()[1]))


# --- the recording endpoint ---------------------------------------------------------------

class RecorderEndpoint(unittest.TestCase):
    """The Tier-2 fixture against a real HTTP client: it records, and it reflects nothing."""

    def setUp(self):
        _, self.recorder = _bind_or_skip(sg._HeaderRecorder)
        self.addCleanup(self.recorder.close)

    def post(self, target, headers, body=b"", method="POST", host="127.0.0.1"):
        conn = http.client.HTTPConnection(host, self.recorder.port, timeout=5)
        try:
            conn.request(method, target, body=body, headers=headers)
            reply = conn.getresponse()
            return reply.status, reply.read()
        finally:
            conn.close()

    def test_records_the_header_that_arrived_and_answers_with_nothing(self):
        status, body = self.post("/verify/record/replace?leak=abc",
                                 {"x-api-key": "SENTINEL-NOT-A-REAL-KEY", "x-exfil": "abc"})
        self.assertEqual((status, body), (204, b""))
        rec, = self.recorder.records
        self.assertEqual(rec["method"], "POST")
        self.assertEqual(rec["target"], "/verify/record/replace?leak=abc")
        self.assertIn(("x-api-key", "SENTINEL-NOT-A-REAL-KEY"), rec["headers"])
        self.assertIn(("x-exfil", "abc"), rec["headers"])

    def test_header_names_are_recorded_case_folded_so_assertions_cannot_miss_one(self):
        self.post("/verify/record/add", {"X-Api-Key": "surprise"})
        self.assertIn("x-api-key", [name for name, _ in self.recorder.records[0]["headers"]])

    def test_a_body_is_measured_but_not_kept(self):
        self.post("/verify/record/add", {"content-type": "text/plain"}, body=b"hello")
        self.assertEqual(self.recorder.records[0]["body_len"], 5)
        self.assertNotIn("hello", json.dumps(self.recorder.records))

    def test_every_method_is_recorded_because_arrival_is_the_evidence(self):
        self.post("/verify/record/method", {}, method="GET")
        self.assertEqual(self.recorder.records[0]["method"], "GET")

    def test_it_answers_on_both_loopback_families(self):
        # The guest's /etc/hosts hands out the v6 alias address first and the proxy resolves
        # `localhost` itself, so a v4-only recorder could be silent for the wrong reason.
        for host in ("127.0.0.1", "::1"):
            with self.subTest(host=host):
                status, _ = self.post("/verify/record/add", {}, host=host)
                self.assertEqual(status, 204)

    def test_a_held_port_is_refused_naming_the_port(self):
        held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(held.close)
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        port = held.getsockname()[1]
        message = _die_message(sg._HeaderRecorder, port)
        self.assertIn(str(port), message)
        self.assertIn("recorder", message)

    def test_a_held_port_names_the_holding_process_when_lsof_can_say(self):
        lsof = Path(_BIN.name) / "lsof"
        lsof.write_text("#!/bin/sh\necho 'COMMAND PID USER'\necho 'squatter 4242 root'\n")
        lsof.chmod(0o755)
        self.addCleanup(lsof.unlink)
        held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(held.close)
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        message = _die_message(sg._HeaderRecorder, held.getsockname()[1])
        self.assertIn("squatter (pid 4242)", message)

    def test_without_lsof_the_error_names_the_command_that_would_say(self):
        with mock.patch.object(sg.shutil, "which", lambda *a, **k: None):
            self.assertIn("lsof -nP -i:6100", sg._port_holder(6100))


class RecorderRule(unittest.TestCase):
    """The one verify-only rule that puts the endpoint in the guest's reach."""

    def setUp(self):
        self.recorder_port = 9192
        # Exactly what cmd_verify composes: the probe profile's rules plus the one rule the
        # recorder adds, parsed by the engine the proxy will use.
        self.rules = (sg.compose_rules(sg.resolve_profiles(["probe"], allow_verify_only=True))
                      + sg._recorder_rules(self.recorder_port))
        self.ruleset = RuleSet.parse(self.rules)

    def matched(self, method, path, port=None):
        return self.ruleset.match("localhost", path, method, port or self.recorder_port)

    def test_the_composed_ruleset_parses(self):
        self.assertTrue(self.ruleset.rules)

    def test_post_to_the_recorder_path_matches_and_injects(self):
        rule = self.matched("POST", "/verify/record/replace")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.inject_auth, sg._VERIFY_SECRET_NAME)

    def test_the_method_the_fixture_expects_to_be_refused_matches_nothing(self):
        self.assertIsNone(self.matched("GET", "/verify/record/method"))

    def test_the_rule_is_scoped_to_one_port_and_one_path_prefix(self):
        self.assertIsNone(self.matched("POST", "/verify/record/replace", port=443))
        self.assertIsNone(self.matched("POST", "/elsewhere"))

    def test_query_and_headers_stay_deny_by_default(self):
        rule = self.matched("POST", "/verify/record/add")
        self.assertFalse(rule.allow_query)
        self.assertFalse(rule.allow_all_headers)
        self.assertFalse(rule.query_ok("leak", "x"))
        self.assertFalse(rule.header_ok("x-exfil", "x"))
        self.assertEqual(rule.max_body, 0)

    def test_no_shipped_profile_puts_a_host_loopback_service_in_reach(self):
        for rules in (REPO / "profiles").glob("*/rules.txt"):
            self.assertNotIn(sg._RECORDER_HOST, rules.read_text(), rules)


class RecorderVerdict(unittest.TestCase):
    """What the recorder's records mean, as a pure function over them."""

    TOKEN = "guest-cafe"

    def record(self, leaf, headers, method="POST", query=""):
        return {"method": method, "target": f"/verify/record/{leaf}{query}",
                "headers": [(n.lower(), v) for n, v in headers], "body_len": 0}

    def clean(self):
        return [self.record("replace", [("host", "localhost:9192"),
                                        ("x-api-key", sg._VERIFY_SENTINEL)]),
                self.record("add", [("host", "localhost:9192")])]

    def problems(self, records):
        found, _ = sg._recorder_problems(records, token=self.TOKEN, port=9192)
        return found

    def assertProblem(self, records, kind, needle):
        found = self.problems(records)
        self.assertTrue(found, "expected a problem")
        self.assertIn(kind, [k for k, _ in found])
        self.assertTrue(any(needle in text for _, text in found),
                        f"{needle!r} not in {[t for _, t in found]}")

    def test_the_healthy_pair_is_clean(self):
        self.assertEqual(self.problems(self.clean()), [])

    def test_the_summary_says_what_it_proved(self):
        _, summary = sg._recorder_problems(self.clean(), token=self.TOKEN, port=9192)
        self.assertIn("replaced", summary)
        self.assertIn("never added", summary)

    def test_the_guests_dummy_credential_reaching_upstream_is_a_leak(self):
        records = self.clean()
        records[0]["headers"] = [("x-api-key", f"DUMMY-{self.TOKEN}")]
        self.assertProblem(records, "observed", "token crossed the proxy")

    def test_an_unstripped_query_param_is_a_leak(self):
        records = self.clean()
        records[0]["target"] += f"?leak={self.TOKEN}"
        self.assertProblem(records, "observed", "token crossed the proxy")

    def test_an_unstripped_header_is_a_leak(self):
        records = self.clean()
        records[0]["headers"].append(("x-exfil", self.TOKEN))
        self.assertProblem(records, "observed", "token crossed the proxy")

    def test_a_credential_added_to_a_request_that_carried_none_is_the_headline_failure(self):
        records = self.clean()
        records[1]["headers"].append(("x-api-key", sg._VERIFY_SENTINEL))
        self.assertProblem(records, "observed", "ADDED a credential")

    def test_a_credential_that_was_not_replaced_is_a_failure_too(self):
        records = self.clean()
        records[0]["headers"] = [("x-api-key", "DUMMY-something-else")]
        self.assertProblem(records, "observed", "must REPLACE the header")

    def test_a_credential_the_proxy_dropped_instead_of_replacing_is_unproven(self):
        # Nothing leaked and nothing was added, but the fixture proved neither: say so.
        records = self.clean()
        records[0]["headers"] = [("host", "localhost:9192")]
        found = self.problems(records)
        self.assertEqual([k for k, _ in found], ["unproven"])
        self.assertIn("proves nothing either way", found[0][1])

    def test_two_credentials_arriving_is_not_a_replacement(self):
        records = self.clean()
        records[0]["headers"].append(("x-api-key", sg._VERIFY_SENTINEL))
        self.assertProblem(records, "observed", "exactly once")

    def test_a_missing_arrival_is_unproven_not_a_leak(self):
        self.assertProblem(self.clean()[:1], "unproven", "never reached the recorder")
        self.assertNotIn("observed", [k for k, _ in self.problems(self.clean()[:1])])

    def test_a_refused_method_that_arrived_anyway_is_observed(self):
        records = self.clean() + [self.record("method", [], method="GET")]
        self.assertProblem(records, "observed", "no rule in this run's ruleset allows it")

    def test_a_wrong_method_on_an_expected_path_is_observed(self):
        records = self.clean()
        records[1]["method"] = "PUT"
        self.assertProblem(records, "observed", "allows POST only")


# --- the arrival observer -----------------------------------------------------------------

class ArrivalObserverTest(unittest.TestCase):
    """A listener that either receives a packet or does not — the one thing no probe inside
    the guest can report, since a denied sendto succeeds and no ICMP comes back."""

    def setUp(self):
        _, self.observer = _bind_or_skip(sg._ArrivalObserver)
        self.addCleanup(self.observer.close)

    def verdict(self):
        return sg._observer_problems(self.observer.arrivals, bound=self.observer.bound(),
                                     self_token=self.observer.self_token,
                                     guest_token=self.observer.guest_token,
                                     port=self.observer.port, proxy_port=8090)

    def send(self, proto, payload, host="127.0.0.1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        with socket.socket(family, kind) as s:
            s.settimeout(2)
            if proto == "tcp":
                s.connect((host, self.observer.port))
                s.sendall(payload.encode())
            else:
                s.sendto(payload.encode(), (host, self.observer.port))

    def test_it_binds_both_families_and_both_protocols(self):
        self.assertEqual(sorted(self.observer.bound()),
                         sorted([("tcp", "127.0.0.1"), ("tcp", "::1"),
                                 ("udp", "127.0.0.1"), ("udp", "::1")]))

    def test_the_self_test_proves_every_address_and_protocol(self):
        self.observer.self_test()
        problems, summary = self.verdict()
        self.assertEqual(problems, [])
        self.assertIn("4/4 self-sends heard", summary)

    def test_silence_after_a_passing_self_test_is_containment(self):
        self.observer.self_test()
        self.observer.drain()
        problems, summary = self.verdict()
        self.assertEqual(problems, [])
        self.assertIn("nothing from the guest", summary)

    def test_a_datagram_carrying_the_guests_token_is_a_leak_the_host_saw(self):
        self.observer.self_test()
        self.send("udp", self.observer.guest_token)
        self.observer.drain()
        problems, _ = self.verdict()
        self.assertEqual([k for k, _ in problems], ["observed"])
        self.assertIn("REACHED the host", problems[0][1])
        self.assertIn("udp", problems[0][1])
        self.assertIn("wider than tcp:8090", problems[0][1])

    def test_a_tcp_connection_carrying_the_token_is_a_leak_too(self):
        self.observer.self_test()
        self.send("tcp", self.observer.guest_token, host="::1")
        self.observer.drain()
        problems, _ = self.verdict()
        self.assertEqual([k for k, _ in problems], ["observed"])
        self.assertIn("tcp packet from the verify guest", problems[0][1])
        self.assertIn("::1", problems[0][1])

    def test_an_arrival_with_no_token_is_reported_as_something_else_entirely(self):
        self.observer.self_test()
        self.send("udp", "who-sent-this")
        self.observer.drain()
        problems, _ = self.verdict()
        self.assertEqual([k for k, _ in problems], ["observed"])
        self.assertIn("neither token", problems[0][1])

    def test_a_tcp_arrival_with_no_payload_still_counts(self):
        self.observer.self_test()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(("127.0.0.1", self.observer.port))
        self.observer.drain()
        problems, _ = self.verdict()
        self.assertIn("neither token", problems[0][1])

    def test_an_observer_that_cannot_hear_itself_refuses_to_mean_anything(self):
        # A listener whose sockets are gone is silent exactly like a contained guest — and it
        # still reports what it bound, so its silence cannot pass by forgetting the question.
        self.observer.close()
        self.observer.self_test()
        self.assertEqual(len(self.observer.bound()), 4)
        problems, summary = self.verdict()
        self.assertEqual([k for k, _ in problems], ["unproven"])
        self.assertIn("cannot hear itself", problems[0][1])
        self.assertIn("problem(s)", summary)

    def test_one_deaf_family_is_enough_to_refuse(self):
        self.observer.self_test()
        arrivals = [a for a in self.observer.arrivals if a["addr"] != "::1"]
        problems, _ = sg._observer_problems(arrivals, bound=self.observer.bound(),
                                            self_token=self.observer.self_token,
                                            guest_token=self.observer.guest_token,
                                            port=self.observer.port, proxy_port=8090)
        self.assertEqual([k for k, _ in problems], ["unproven"])
        self.assertIn("::1", problems[0][1])

    def test_a_held_port_is_refused_naming_the_port(self):
        # Not a kernel-assigned number: the observer must get through its tcp
        # bind before it can fail on udp, and the ephemeral range is exactly
        # where every concurrent tests.py worker's live sockets sit — a pick
        # there loses the tcp side often enough to flake. Below the ephemeral
        # floors (32768 Linux, 49152 macOS) and tests.py's port floors (23000
        # and up), nothing else in the suite ever lands.
        def low_pick(span):
            for port in range(21000, 23000):
                if _port_free(port):
                    return port
            raise unittest.SkipTest("no free port below the ephemeral range")

        def hold(port):
            held = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                held.bind(("127.0.0.1", port))
            except OSError:
                held.close()
                raise
            self.addCleanup(held.close)

        port, _ = _bind_or_skip(hold, pick=low_pick)
        message = _die_message(sg._ArrivalObserver, port)
        self.assertIn("arrival observer (udp)", message)


# --- the guest's half, under a real bash --------------------------------------------------

class _StubProxy:
    """Enough of the proxy for the guest script to talk to: it records the request bytes and
    answers by rule, so what is asserted is the request the guest actually composed."""

    def __init__(self, port, answers):
        self.requests = []
        self.silent = False              # set to hold the port and answer nothing at all
        self._answers = answers
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    self.requests.append(data.decode("ascii", "replace"))
                    if self.silent:               # something holds the port and is not a proxy
                        return
                    status = next((v for k, v in self._answers.items() if k in data.decode()),
                                 "500 Internal Server Error")
                    conn.sendall(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n"
                                 .encode())
                except OSError:
                    pass

    def close(self):
        self._stop = True
        self._sock.close()


class GuestProbeScript(unittest.TestCase):
    """The probes the guest runs, generated by the CLI and executed by a real bash 5 with
    /dev/tcp and /dev/udp — the same built-ins the guest has, pointed at loopback."""

    ANSWERS = {"/verify/record/replace": "204 No Content",
               "/verify/record/add": "204 No Content",
               "/verify/record/method": "403 Forbidden"}

    def setUp(self):
        if not sg.shutil.which("bash"):
            self.skipTest("no bash here; the guest half needs its /dev/tcp built-in")
        _, self.observer = _bind_or_skip(sg._ArrivalObserver)
        self.addCleanup(self.observer.close)
        self.proxy = _StubProxy(0, self.ANSWERS)
        self.addCleanup(self.proxy.close)
        self.recorder_port = 9192

    def run_script(self):
        # PROXY_ALIAS is the only thing standing between this script and loopback: the guest
        # reaches the host by that name, and here the host is 127.0.0.1.
        with mock.patch.object(sg, "PROXY_ALIAS", "127.0.0.1"):
            script = sg._oracle_guest_script(proxy_port=self.proxy.port,
                                             observer_port=self.observer.port,
                                             recorder_port=self.recorder_port,
                                             token=self.observer.guest_token)
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return sg._oracle_report(done.stdout.splitlines()), done.stdout

    def test_it_reports_every_probe_it_attempted(self):
        report, out = self.run_script()
        self.assertEqual(sorted(report), ["observer-tcp", "observer-udp", "recorder-add",
                                         "recorder-method", "recorder-replace"], out)

    def test_the_requests_the_guest_composes_are_what_the_ruleset_is_written_for(self):
        self.run_script()
        first = self.proxy.requests[0]
        self.assertTrue(first.startswith(
            f"POST http://localhost:{self.recorder_port}/verify/record/replace"
            f"?leak={self.observer.guest_token} HTTP/1.1\r\n"), first)
        self.assertIn(f"Host: localhost:{self.recorder_port}\r\n", first)
        self.assertIn(f"x-api-key: DUMMY-{self.observer.guest_token}\r\n", first)
        self.assertIn(f"x-exfil: {self.observer.guest_token}\r\n", first)
        self.assertIn("Content-Length: 0\r\n", first)
        self.assertTrue(first.endswith("\r\n\r\n"))

    def test_the_second_request_carries_no_credential_at_all(self):
        self.run_script()
        self.assertNotIn("x-api-key", self.proxy.requests[1])
        self.assertIn("/verify/record/add", self.proxy.requests[1])

    def test_the_third_request_is_the_method_the_rule_forbids(self):
        self.run_script()
        self.assertTrue(self.proxy.requests[2].startswith("GET http://localhost:"))

    def test_the_guest_reads_only_the_status_line_and_reports_the_code(self):
        report, out = self.run_script()
        self.assertIn("code=204", report["recorder-replace"])
        self.assertIn("code=204", report["recorder-add"])
        self.assertIn("code=403", report["recorder-method"])
        self.assertNotIn("Content-Length", out)        # nothing beyond the status line is read

    def test_a_reachable_observer_port_is_reported_as_sent_and_arrives(self):
        report, _ = self.run_script()
        self.assertEqual(report["observer-tcp"], "sent")
        self.assertEqual(report["observer-udp"], "sent")
        self.observer.drain()
        got = {a["proto"] for a in self.observer.arrivals
               if self.observer.guest_token in a["data"]}
        self.assertEqual(got, {"tcp", "udp"})          # the leak, seen from the host

    def test_a_refused_observer_port_carries_the_errno_the_guest_saw(self):
        # What a healthy run looks like: the boundary refuses the TCP connect, and the errno
        # is the difference between a policy decision and a guest with no route.
        self.observer.close()
        report, _ = self.run_script()
        self.assertTrue(report["observer-tcp"].startswith("blocked"), report["observer-tcp"])
        self.assertIn("refused", report["observer-tcp"].lower())
        self.assertEqual(report["observer-udp"], "sent")   # a denied sendto still "succeeds"

    def test_a_port_that_answers_nothing_is_not_read_as_a_pass(self):
        # Something holds the proxy port and is not a proxy — the collision cli/silkgate records
        # as having surfaced in the field. The guest gets no status line, and the host must call
        # that unproven rather than let a missing code stand in for a decision.
        self.proxy.silent = True
        report, out = self.run_script()
        problems, _ = sg._probe_problems(report, observer_port=self.observer.port)
        self.assertEqual({k for k, _ in problems}, {"unproven"}, out)
        self.assertTrue(any("recorder-replace" in text for _, text in problems), out)
        self.assertIn("code=000", report["recorder-replace"])


class ProbeReport(unittest.TestCase):
    """What the guest says it attempted, as a pure function over its ORACLE lines."""

    HEALTHY = {"observer-tcp": "blocked bash: connect: Connection refused",
               "observer-udp": "sent",
               "recorder-replace": "code=204 rc=0 reply=HTTP/1.1 204 No Content",
               "recorder-add": "code=204 rc=0 reply=HTTP/1.1 204 No Content",
               "recorder-method": "code=403 rc=0 reply=HTTP/1.1 403 Forbidden"}

    def problems(self, **overrides):
        report = dict(self.HEALTHY, **overrides)
        for key, value in list(report.items()):
            if value is None:
                del report[key]
        found, _ = sg._probe_problems(report, observer_port=8091)
        return found

    def test_the_healthy_report_is_clean(self):
        self.assertEqual(self.problems(), [])

    def test_the_report_is_parsed_out_of_the_relayed_lines(self):
        report = sg._oracle_report(["[PASS] 3. something", "ORACLE observer-udp sent",
                                    "ORACLE recorder-add code=204 rc=0 reply=x"])
        self.assertEqual(report, {"observer-udp": "sent",
                                  "recorder-add": "code=204 rc=0 reply=x"})

    def test_a_probe_the_guest_never_ran_is_unproven(self):
        found = self.problems(**{"observer-udp": None})
        self.assertEqual([k for k, _ in found], ["unproven"])
        self.assertIn("never reported its udp probe", found[0][1])

    def test_a_udp_socket_the_guest_could_not_open_is_a_broken_probe(self):
        found = self.problems(**{"observer-udp": "blocked bash: /dev/udp: no such thing"})
        self.assertIn("broken probe, not", " ".join(t for _, t in found))

    def test_a_refused_tcp_probe_is_normal(self):
        self.assertEqual(self.problems(**{"observer-tcp": "blocked whatever"}), [])

    def test_the_forbidden_method_getting_through_is_observed(self):
        found = self.problems(**{"recorder-method": "code=204 rc=0 reply=x"})
        self.assertEqual([k for k, _ in found], ["observed"])
        self.assertIn("a method the rule does not allow was forwarded", found[0][1])

    def test_a_recorder_request_the_proxy_refused_is_unproven(self):
        found = self.problems(**{"recorder-replace": "code=403 rc=0 reply=x"})
        self.assertEqual([k for k, _ in found], ["unproven"])
        self.assertIn("403", found[0][1])


# --- the audit log ------------------------------------------------------------------------

def _log(*records, chatter=True):
    """A proxy log shaped like mitmdump's: its own time-of-day prefix, its own noise."""
    lines = []
    if chatter:
        lines += ["[16:04:01.001] HTTP(S) proxy listening at 127.0.0.1:8090.",
                  "[16:04:01.002] client connect"]
    for rec in records:
        lines.append("[16:04:02.123] " + json.dumps(rec))
    return "\n".join(lines) + "\n"


def _rec(decision, host, **extra):
    return {"ts": "2026-08-05T16:04:02.123+02:00", "decision": decision, "id": "abc",
            "method": extra.pop("method", "CONNECT"), "host": host,
            "port": extra.pop("port", 443), "path": "/", "reason": "", "session": None,
            **extra}


class AuditRecords(unittest.TestCase):
    def test_json_is_read_past_mitmdumps_own_prefix_and_noise(self):
        records = sg._audit_records(_log(_rec("deny", "evil.com")))
        self.assertEqual([r["host"] for r in records], ["evil.com"])

    def test_a_line_that_is_not_a_record_is_skipped_not_fatal(self):
        text = _log(_rec("allow", "a.com")) + "[16:04:03.000] {not json}\n{}\n"
        self.assertEqual(len(sg._audit_records(text)), 1)

    def test_control_lines_count_as_records_but_carry_no_host(self):
        text = _log({"decision": "control", "reason": "listening on /x"})
        self.assertEqual(sg._audit_records(text)[0]["decision"], "control")


class AuditOracle(unittest.TestCase):
    """The host's record against what this run's probes should have provoked."""

    def setUp(self):
        self.path = Path(tempfile.mkdtemp(prefix="silkgate-oracle-log-")) / "proxy-x.log"

    def problems(self, text, *, full=True, recorder_port=9192):
        expect = sg._audit_expectations(full=full, recorder_port=recorder_port)
        found, summary = sg._audit_problems(text, expect, log_path=self.path)
        return found, summary

    def healthy(self):
        return _log(_rec("deny", "silkgate.invalid", method="GET", port=80),
                    _rec("allow", "registry.npmjs.org"),
                    _rec("deny", "evil.com"),
                    _rec("allow", "localhost", method="POST", port=9192),
                    _rec("deny", "localhost", method="GET", port=9192))

    def test_a_log_holding_every_expected_decision_is_clean(self):
        found, summary = self.problems(self.healthy())
        self.assertEqual(found, [])
        self.assertIn("2 allow, 3 deny", summary)

    def test_a_missing_allow_names_the_check_it_would_have_corroborated(self):
        text = self.healthy().replace("registry.npmjs.org", "unrelated.example")
        found, _ = self.problems(text)
        self.assertEqual([k for k, _ in found], ["unproven"])
        self.assertIn("check 1's allowed host", found[0][1])
        self.assertIn(str(self.path), found[0][1])

    def test_a_missing_deny_for_the_unlisted_host_is_reported(self):
        text = self.healthy().replace("evil.com", "unrelated.example")
        found, _ = self.problems(text)
        self.assertIn("check 2's unlisted host", " ".join(t for _, t in found))

    def test_the_proxy_path_expectations_apply_only_to_a_full_run(self):
        text = _log(_rec("deny", "silkgate.invalid", method="GET", port=80),
                    _rec("allow", "localhost", method="POST", port=9192),
                    _rec("deny", "localhost", method="GET", port=9192))
        self.assertEqual(self.problems(text, full=False)[0], [])
        self.assertNotEqual(self.problems(text, full=True)[0], [])

    def test_a_run_without_oracles_expects_only_a_decision_of_its_own(self):
        text = _log(_rec("deny", "silkgate.invalid", method="GET", port=80))
        self.assertEqual(self.problems(text, full=False, recorder_port=None)[0], [])

    def test_the_recorders_own_decisions_are_asserted(self):
        text = self.healthy().replace('"method": "POST"', '"method": "PUT"')
        found, _ = self.problems(text)
        self.assertIn("allowed POSTs", " ".join(t for _, t in found))

    def test_an_empty_log_is_the_loudest_unproven(self):
        found, summary = self.problems(_log())
        self.assertEqual([k for k, _ in found], ["unproven"])
        self.assertIn("no audit record at all", found[0][1])
        self.assertEqual(summary, "audit: no records")

    def test_a_log_with_no_deny_cannot_be_this_runs(self):
        found, _ = self.problems(_log(_rec("allow", "registry.npmjs.org")),
                                 full=False, recorder_port=None)
        self.assertIn("records no deny at all", " ".join(t for _, t in found))

    def test_a_control_probe_under_another_name_is_a_note_not_a_failure(self):
        text = self.healthy().replace("silkgate.invalid", "nowhere.invalid")
        said = []
        with mock.patch.object(sg, "say", said.append):
            found, _ = self.problems(text)
        self.assertEqual(found, [])
        self.assertIn("silkgate.invalid", " ".join(said))

    def test_the_injected_credential_must_never_appear_in_the_trail(self):
        text = self.healthy() + _log(_rec("allow", "localhost", method="POST", port=9192,
                                          reason=f"x-api-key: {sg._VERIFY_SENTINEL}"),
                                     chatter=False)
        found, _ = self.problems(text)
        self.assertEqual([k for k, _ in found], ["observed"])
        self.assertIn("sentinel credential appears", found[0][1])

    def test_await_returns_as_soon_as_the_expectations_are_met(self):
        self.path.write_text(self.healthy())
        started = time.monotonic()
        text = sg._await_audit(self.path, sg._audit_expectations(full=True, recorder_port=9192))
        self.assertIn("evil.com", text)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_await_gives_a_late_record_time_to_land(self):
        self.path.write_text(_log(_rec("deny", "silkgate.invalid", method="GET", port=80)))
        expect = sg._audit_expectations(full=False, recorder_port=None)
        expect.append({"decision": "allow", "host": "late.example", "why": "a late record"})

        def append():
            time.sleep(0.4)
            with self.path.open("a") as fh:
                fh.write("[16:04:09.000] " + json.dumps(_rec("allow", "late.example")) + "\n")

        thread = threading.Thread(target=append)
        thread.start()
        self.addCleanup(thread.join)
        text = sg._await_audit(self.path, expect, timeout=5)
        self.assertIn("late.example", text)

    def test_await_gives_up_and_hands_back_what_it_has(self):
        self.path.write_text(_log(_rec("deny", "silkgate.invalid", method="GET", port=80)))
        started = time.monotonic()
        text = sg._await_audit(self.path, sg._audit_expectations(full=True), timeout=0.5)
        self.assertIn("silkgate.invalid", text)
        self.assertLess(time.monotonic() - started, 3.0)


# --- the guest itself: argv, names, and the negative control ------------------------------

class GuestArgv(unittest.TestCase):
    def argv(self, **kwargs):
        return sg._verify_msb_argv("silkgate-verify-1-main", 8090, **kwargs)

    def pairs(self, argv):
        return list(zip(argv, argv[1:]))

    def test_the_guest_is_named_so_it_can_be_removed(self):
        argv = self.argv()
        self.assertEqual(argv[1:4], ["create", sg._VERIFY_IMAGE, "--name"])
        self.assertEqual(argv[4], "silkgate-verify-1-main")

    def test_the_name_is_one_msb_accepts_and_no_session_can_produce(self):
        name = sg._verify_guest_name("main")
        self.assertTrue(sg._SANDBOX_RE.fullmatch(name))
        self.assertFalse(name.startswith("sg-"))       # sandbox_name()'s prefix; never ours
        self.assertTrue(sg._VERIFY_GUEST_RE.fullmatch(name))
        self.assertIn(str(os.getpid()), name)

    def test_egress_is_denied_by_default_with_exactly_one_allow_rule(self):
        pairs = self.pairs(self.argv())
        self.assertIn(("--net-default-egress", "deny"), pairs)
        rules = [v for k, v in pairs if k == "--net-rule"]
        self.assertEqual(rules, ["allow@host:tcp:8090"])

    def test_the_proxy_is_named_to_the_guest_the_way_every_session_names_it(self):
        pairs = self.pairs(self.argv())
        for var in sg.PROXY_ENV_VARS:
            self.assertIn(("-e", f"{var}=http://{sg.PROXY_ALIAS}:8090"), pairs)

    def test_mounts_are_passed_through(self):
        pairs = self.pairs(self.argv(mounts=[f"{REPO}:/mnt/poc:ro"]))
        self.assertIn(("-v", f"{REPO}:/mnt/poc:ro"), pairs)

    def test_the_flag_shape_is_the_sessions_shape(self):
        # The policy under test must be the one a real session gets, or verify tests something
        # nobody runs. Compare against the session builder's own flags.
        session = sg.msb_create_argv("sg-x", "img", 8090)
        mine = self.argv()
        for flag in ("--net-default-egress", "--net-rule"):
            self.assertEqual(session[session.index(flag) + 1], mine[mine.index(flag) + 1])


class NegativeControlArgv(unittest.TestCase):
    def test_the_flip_is_the_one_thing_that_changes(self):
        argv = sg._verify_msb_argv("silkgate-verify-1-leaky", 8090)
        leaky = sg._leaky_argv(argv)
        self.assertEqual(len(leaky), len(argv))
        differ = [(a, b) for a, b in zip(argv, leaky) if a != b]
        self.assertEqual(differ, [("deny", "allow")])

    def test_a_missing_flag_refuses_rather_than_producing_a_contained_control(self):
        message = _die_message(sg._leaky_argv, ["msb", "create", "debian"])
        self.assertIn("--net-default-egress", message)
        self.assertIn("prove nothing", message)

    def test_an_unexpected_default_refuses_too(self):
        message = _die_message(sg._leaky_argv,
                               ["msb", "create", "--net-default-egress", "allow"])
        self.assertIn("refusing to guess", message)


class CheckOutcomes(unittest.TestCase):
    def test_each_checks_own_line_is_read(self):
        lines = ["[OKAY] 0. bash /dev/tcp works", "[PASS] 3. direct TCP egress blocked",
                 "[FAIL] 1. allowed host via proxy", "[SKIP] 7. route-escape (no ip tool)",
                 "CHECKS: ran=1,3 skipped=7", "RESULT: 1 passed, 1 failed"]
        self.assertEqual(sg._check_outcomes(lines), {3: "PASS", 1: "FAIL", 7: "SKIP"})

    def test_the_last_line_for_a_check_wins(self):
        self.assertEqual(sg._check_outcomes(["[PASS] 3. x", "[FAIL] 3. y"]), {3: "FAIL"})

    def test_nothing_is_invented_from_output_that_has_no_check_lines(self):
        self.assertEqual(sg._check_outcomes(["RESULT: 7 passed, 0 failed"]), {})


class NegativeControlVerdict(unittest.TestCase):
    """The control's own entry condition: a guest that was supposed to leak must show it."""

    CONTAINED = {1: "PASS", 2: "PASS", 3: "PASS", 9: "PASS", 10: "PASS", 11: "PASS"}

    def test_a_leaking_guest_whose_check_3_failed_establishes_the_control(self):
        leaky = {**self.CONTAINED, 3: "FAIL"}
        problem, summary = sg._negative_control_problem(self.CONTAINED, leaky)
        self.assertIsNone(problem)
        self.assertIn("check 3 FAILED in the leaking guest", summary)

    def test_the_checks_that_passed_in_both_guests_are_named(self):
        leaky = {**self.CONTAINED, 3: "FAIL", 9: "FAIL", 10: "FAIL"}
        _, summary = sg._negative_control_problem(self.CONTAINED, leaky)
        self.assertIn("checks 1, 2, 11 passed in both guests", summary)

    def test_a_check_3_that_passed_in_the_leaky_guest_proves_nothing_and_says_so(self):
        problem, summary = sg._negative_control_problem(self.CONTAINED, self.CONTAINED)
        self.assertIsNone(summary)
        self.assertIn("established no leak", problem)
        self.assertIn("draws no conclusion", problem)

    def test_a_leaky_run_that_never_reached_check_3_is_the_same_refusal(self):
        problem, _ = sg._negative_control_problem(self.CONTAINED, {})
        self.assertIn("reported no line", problem)

    def test_a_skipped_check_3_is_not_a_leak_either(self):
        problem, _ = sg._negative_control_problem(self.CONTAINED, {3: "SKIP"})
        self.assertIn("reported SKIP", problem)


class LeakedGuests(unittest.TestCase):
    """An interrupted verify leaves its sandbox running; the next one must clear it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="silkgate-oracle-msb-")
        self.addCleanup(tmp.cleanup)
        self.log = Path(tmp.name) / "msb.log"
        self.listing = Path(tmp.name) / "msb.list"
        self.log.write_text("")
        os.environ["MSB_LOG"], os.environ["MSB_LIST"] = str(self.log), str(self.listing)

    def listed(self, *names):
        rows = "\n".join(f"{n}  debian  running" for n in names)
        self.listing.write_text(f"NAME  IMAGE  STATUS\n{rows}\n")

    def reap(self):
        said = []
        with mock.patch.object(sg, "say", said.append):
            sg._reap_leaked_verify_guests()
        return "\n".join(str(m) for m in said), self.log.read_text()

    def test_a_leftover_whose_owner_is_gone_is_removed_and_named(self):
        dead = _dead_pid()
        self.listed(f"silkgate-verify-{dead}-main")
        said, log = self.reap()
        self.assertIn(f"removing silkgate-verify-{dead}-main", said)
        self.assertIn("Tier-1 rule", said)
        self.assertIn(f"stop silkgate-verify-{dead}-main", log)
        self.assertIn(f"rm silkgate-verify-{dead}-main", log)

    def test_a_guest_whose_owner_still_runs_is_left_alone(self):
        self.listed(f"silkgate-verify-{os.getpid()}-leaky")
        said, log = self.reap()
        self.assertEqual(said, "")
        self.assertNotIn("rm ", log)

    def test_a_sessions_sandbox_is_never_touched(self):
        # `verify foo` is not a thing, but `up --name verify-123-main` is, and its sandbox is
        # sg-prefixed for exactly this reason.
        self.listed(sg.sandbox_name(f"verify-{_dead_pid()}-main"), "sg-other")
        _, log = self.reap()
        self.assertNotIn("rm ", log)

    def test_an_msb_that_cannot_list_reaps_nothing(self):
        self.listed(f"silkgate-verify-{_dead_pid()}-main")
        os.environ["MSB_RC"] = "1"
        self.addCleanup(os.environ.pop, "MSB_RC", None)
        _, log = self.reap()
        self.assertNotIn("rm ", log)

    def test_a_removal_that_cannot_be_confirmed_names_the_manual_command(self):
        dead = _dead_pid()
        self.listed(f"silkgate-verify-{dead}-main")
        with mock.patch.object(sg, "_remove_sandbox", lambda name: False):
            said, _ = self.reap()
        self.assertIn(f"msb stop silkgate-verify-{dead}-main", said)


class OracleFraming(unittest.TestCase):
    """A leak the host saw and an oracle that could not be trusted must not read alike."""

    def framing(self, problems):
        return _die_message(sg._oracle_die, problems, Path("/tmp/proxy-x.log"))

    def test_an_observed_failure_leads_with_the_boundary(self):
        text = self.framing([("observed", "a udp packet REACHED the host")])
        self.assertIn("CONTAINMENT FAILED OUTSIDE THE GUEST", text)
        self.assertNotIn("ORACLE UNPROVEN", text)

    def test_missing_evidence_says_the_oracle_is_the_suspect(self):
        text = self.framing([("unproven", "no allow record for check 1")])
        self.assertIn("ORACLE UNPROVEN", text)
        self.assertIn("not a failed check", text)
        self.assertNotIn("CONTAINMENT FAILED", text)

    def test_both_kinds_together_lead_with_the_leak(self):
        text = self.framing([("unproven", "no allow record"), ("observed", "a packet arrived")])
        self.assertLess(text.index("CONTAINMENT FAILED"), text.index("incomplete"))

    def test_the_audit_log_is_always_named(self):
        self.assertIn("audit log: /tmp/proxy-x.log", self.framing([("unproven", "x")]))


class OracleWiring(unittest.TestCase):
    """The bundle: which ports it takes, what it adds to the ruleset, what it tears down."""

    def oracles(self):
        """A bundle on a freshly proven proxy port; return (base, oracles)."""
        base, oracles = _bind_or_skip(sg._VerifyOracles, span=3)
        self.addCleanup(oracles.close)
        return base, oracles

    def test_the_ports_sit_beside_the_proxys(self):
        base, oracles = self.oracles()
        self.assertEqual((oracles.observer.port, oracles.recorder.port), (base + 1, base + 2))

    def test_the_offset_folds_below_the_proxy_port_at_the_top_of_the_range(self):
        self.assertEqual(sg._oracle_port(8090, 1), 8091)
        self.assertEqual(sg._oracle_port(65535, 2), 65533)

    def test_the_recorder_rule_is_added_to_the_ruleset_and_the_secret_to_the_environment(self):
        base, oracles = self.oracles()
        self.assertIn(f"localhost:{base + 2}/verify/record/** POST", oracles.rules())
        self.assertEqual(os.environ[f"SILKGATE_EGRESS_SECRET_{sg._VERIFY_SECRET_NAME.upper()}"],
                         f"x-api-key: {sg._VERIFY_SENTINEL}")
        self.assertIn(sg._VERIFY_SENTINEL, "SENTINEL-NOT-A-REAL-KEY")   # never a real key

    def test_close_frees_every_port_it_took(self):
        # A neighbor can take a just-released port before the probe reaches it — the
        # kernel reoffers fresh releases first — so one held port proves nothing. A close
        # that leaks holds its port on every base tried; a neighbor holds at most one.
        for _ in range(5):
            base, oracles = _bind_or_skip(sg._VerifyOracles, span=3)
            oracles.close()
            oracles.close()                            # idempotent: the finally calls it again
            if all(_port_free(base + n) for n in (1, 2)):
                return
        self.fail(f"a port beside {base} still held after close, on 5 bases")

    def test_expectations_cover_the_recorders_own_decisions(self):
        expect = sg._audit_expectations(full=False, recorder_port=9192)
        self.assertEqual([(e["decision"], e.get("method")) for e in expect],
                         [("allow", "POST"), ("deny", "GET")])


class VerifyPortSelection(unittest.TestCase):
    """How one verify run picks its proxy port: the default scans to a base where every
    port the run binds is free, an explicit --port is taken verbatim.

    The scan is _find_free_pool, the same walk the shared pool does, so a shared proxy
    holding the default range shifts verify forward instead of blocking it — and the
    POOL_SIZE ports it proves free cover all three verify binds: the proxy's port and
    the two oracle ports beside it.
    """

    def needed(self, base):
        """Every port a verify run at `base` binds: the proxy's, the observer's, the
        recorder's."""
        return [base, sg._oracle_port(base, 1), sg._oracle_port(base, 2)]

    def test_the_default_scans_past_an_occupied_floor_to_a_base_with_every_port_free(self):
        # The squat is what a shared proxy on the default floor looks like.
        base, _ = _bind_or_skip(lambda port: _squat(self, port), span=sg.POOL_SIZE + 1)
        with mock.patch.object(sg, "DEFAULT_BASE_PORT", base):
            chosen = sg._verify_port(None)
        self.assertEqual(chosen, base + 1, "the scan did not land one past the blocker")
        for port in self.needed(chosen):
            self.assertTrue(sg._port_free(port), f"verify binds {port} and it is taken")

    def test_an_explicit_port_is_honored_verbatim_even_when_taken(self):
        port, _ = _bind_or_skip(lambda p: _squat(self, p))
        self.assertEqual(sg._verify_port(port), port,
                         "an explicit --port moved instead of being handed to start_proxy's "
                         "die-if-taken guard")


# --- cmd_verify end to end, over fakes ---------------------------------------------------

_FAKE_MSB = '''\
import json, os, subprocess, sys
argv = sys.argv[1:]
with open(os.environ["MSB_LOG"], "a") as log:
    log.write(" ".join(argv).replace("\\n", " ") + "\\n")   # one line per invocation
state = os.environ["MSB_STATE"]
guests = json.load(open(state)) if os.path.exists(state) else {}
op = argv[0] if argv else ""
if op == "list":
    print("NAME  IMAGE  STATUS")
elif op == "create":
    guests[argv[argv.index("--name") + 1]] = {
        "egress": argv[argv.index("--net-default-egress") + 1],
        "mounts": [argv[i + 1] for i, a in enumerate(argv) if a == "-v"],
        "env": [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]}
    json.dump(guests, open(state, "w"))
elif op == "exec":
    # The fake guest is this host: run the command it was handed, with the mounts resolved back
    # to where they came from and the sandbox's egress default in the environment — so a stub
    # check script can behave like the guest a leaking sandbox would hold.
    info = guests.get(argv[argv.index("--") - 1], {})
    cmd = argv[argv.index("--") + 1:]
    for mount in info.get("mounts", []):
        host, guest = mount.split(":")[:2]
        cmd = [part.replace(guest, host) for part in cmd]
    env = dict(os.environ, GUEST_EGRESS=info.get("egress", "deny"))
    env.update(pair.split("=", 1) for pair in info.get("env", []))   # create-time -e, inherited
    sys.exit(subprocess.run(cmd, env=env).returncode)
elif op == "rm":
    guests.pop(argv[1], None)
    json.dump(guests, open(state, "w"))
sys.exit(0)
'''

# A stand-in for mitmdump plus the addon. It owns no policy: every decision comes from the real
# rule_engine, parsing the very ruleset cmd_verify composed, so what this pins is that the
# recorder rule, the guest's requests and the host's assertions agree with the matcher the proxy
# runs. What the real addon does with them is test_addon.py's business.
_FAKE_MITMDUMP = '''\
import json, os, selectors, socket, sys
sys.path.insert(0, %(mitmaddon)r)
from rule_engine import RuleSet, normalize_host

rules = RuleSet.parse(open(os.environ["SILKGATE_EGRESS_RULES"]).read())
misbehave = os.environ.get("STUB_MISBEHAVE", "")
binds = [a.split("@", 1)[1] for a in sys.argv if a.startswith("regular@")]
listeners = []
sel = selectors.DefaultSelector()
for spec in binds:
    addr, _, port = spec.rpartition(":")
    s = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, int(port)))
    s.listen(8)
    sel.register(s, selectors.EVENT_READ)


def audit(decision, method, host, port, path, reason):
    print(json.dumps({"ts": "x", "decision": decision, "id": "stub", "method": method,
                      "host": host, "port": port, "path": path, "reason": reason,
                      "session": None}), flush=True)


def forward(method, host, port, path, headers, body):
    import http.client
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request(method, path, body=body, headers=dict(headers))
    reply = conn.getresponse()
    reply.read()
    conn.close()
    return reply.status, reply.reason


def serve(conn):
    data = b""
    while b"\\r\\n\\r\\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return
        data += chunk
    head, _, rest = data.partition(b"\\r\\n\\r\\n")
    lines = head.decode("latin1").split("\\r\\n")
    method, target, _ = lines[0].split(" ", 2)
    headers = [tuple(h.split(": ", 1)) for h in lines[1:] if ": " in h]
    authority = target.split("//", 1)[1]
    hostport, _, path = authority.partition("/")
    host, _, port = hostport.partition(":")
    path, _, query = ("/" + path).partition("?")
    host, port = normalize_host(host), int(port or 80)
    rule = rules.match(host, path, method, port) if host else None
    if rule is None:
        audit("deny", method, host, port, path, "no matching rule")
        conn.sendall(b"HTTP/1.1 403 Forbidden\\r\\nX-Silkgate: deny\\r\\n"
                     b"Content-Length: 0\\r\\n\\r\\n")
        return
    kept = [p for p in query.split("&") if p and rule.query_ok(*p.split("=", 1))]
    secret = os.environ.get("SILKGATE_EGRESS_SECRET_" + (rule.inject_auth or "x").upper(), "")
    name, _, value = secret.partition(": ")
    if rule.inject_auth and secret:
        have = [h for h in headers if h[0].lower() == name.lower()]
        if have or misbehave == "add-credential":
            headers = [h for h in headers if h[0].lower() != name.lower()]
            headers.append((name, value))
    headers = [h for h in headers
               if h[0].lower() == name.lower() or rule.header_ok(h[0], h[1])]
    audit("allow", method, host, port, path, rule.raw)
    status, reason = forward(method, host, port,
                             path + ("?" + "&".join(kept) if kept else ""), headers, rest)
    conn.sendall(f"HTTP/1.1 {status} {reason}\\r\\nContent-Length: 0\\r\\n\\r\\n".encode())


while True:
    for key, _ in sel.select():
        conn, _ = key.fileobj.accept()
        with conn:
            conn.settimeout(5)
            try:
                serve(conn)
            except Exception as e:                      # a stub: say so and keep serving
                print(json.dumps({"decision": "control", "reason": repr(e)}), flush=True)
'''

# The guest script cmd_verify runs, stubbed: the CHECKS/RESULT contract plus one per-check line
# each, and a check that fails exactly when the sandbox was created with egress open. The set it
# claims to have run comes from the CLI's own tool-free constant, so this fixture follows the
# check-set contract instead of pinning a second copy of it.
def _stub_checks_script():
    ran = sorted(sg._VERIFY_TOOL_FREE)
    leaky = sg._NEGATIVE_CONTROL_CHECK
    passes = "\n".join(f'echo "[PASS] {i}. tool-free check {i}"' for i in ran if i != leaky)
    skipped = sorted(sg._VERIFY_CHECKS - set(ran))
    return f"""#!/usr/bin/env bash
echo "PROXY=$HTTPS_PROXY"
# control 0, which every real run makes: a request through the proxy for a host no ruleset
# allows, so the host's audit log holds a decision of this run's even on a bare guest.
target=${{HTTPS_PROXY#*://}}
if exec 3<>/dev/tcp/${{target%%:*}}/${{target##*:}}; then
  printf 'GET http://silkgate.invalid/ HTTP/1.1\\r\\nHost: silkgate.invalid\\r\\n\\r\\n' >&3
  IFS= read -r reply <&3
  echo "[OKAY] 0. proxy answered: $reply"
  exec 3<&-
fi
if [ "${{GUEST_EGRESS:-deny}}" = allow ]; then
  echo "[FAIL] {leaky}. direct TCP egress connected"
  fail=1
else
  echo "[PASS] {leaky}. direct TCP egress blocked"
  fail=0
fi
{passes}
echo "CHECKS: ran={sg._ids(ran).replace(", ", ",")} skipped={sg._ids(skipped).replace(", ", ",")}"
echo "RESULT: $(({len(ran)} - fail)) passed, $fail failed"
exit $fail
"""


class _Args:
    def __init__(self, **kwargs):
        self.__dict__.update(dict(full=False, oracles=True, negative_control=False), **kwargs)


class VerifyWiring(unittest.TestCase):
    """`cmd_verify` end to end over fakes: a fake msb that runs the guest command here, a stub
    proxy whose every decision comes from the real rule engine, and a stub check script.

    What this pins is the sequencing and the verdicts — the oracles armed before a guest exists,
    the guest removed by name afterwards, a Tier-2 failure the host observed refusing the run,
    the negative control's entry condition, and a success line that says what actually held.
    Nothing here is evidence about msb or mitmproxy; it is evidence about cmd_verify.
    """

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="silkgate-wiring-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        binaries = self.tmp / "bin"
        binaries.mkdir()
        for name, src in (("msb", _FAKE_MSB),
                          ("mitmdump", _FAKE_MITMDUMP % {"mitmaddon": str(REPO / "mitmaddon")})):
            (binaries / name).write_text(f"#!{sys.executable}\n{src}")
            (binaries / name).chmod(0o755)
        (self.tmp / "repo" / "test").mkdir(parents=True)
        (self.tmp / "repo" / "test" / "verify_guest.sh").write_text(_stub_checks_script())
        self.log = self.tmp / "msb.log"
        self.log.write_text("")
        os.environ["MSB_LOG"] = str(self.log)
        os.environ["MSB_STATE"] = str(self.tmp / "msb.state")
        os.environ["PATH"] = f"{binaries}{os.pathsep}{os.environ['PATH']}"
        self.addCleanup(os.environ.__setitem__, "PATH", os.environ["PATH"])
        self.port = _free_port(span=3)      # the proxy's, plus the two oracle ports
        for patch in (mock.patch.object(sg, "REPO", self.tmp / "repo"),
                      mock.patch.object(sg, "LOG_DIR", self.tmp / "logs"),
                      mock.patch.object(sg, "SILK_DIR", self.tmp / "silk"),
                      mock.patch.object(sg, "PROXY_JSON", self.tmp / "silk" / "proxy.json"),
                      # The guest reaches the host by the alias; here the host is loopback.
                      mock.patch.object(sg, "PROXY_ALIAS", "127.0.0.1")):
            patch.start()
            self.addCleanup(patch.stop)

    def verify(self, **kwargs):
        """Run cmd_verify; return (everything silkgate said, whether it refused the run).

        A refusal whose text names a port collision is a concurrent process having taken
        one of this run's three ports between the free-port probe and cmd_verify's bind —
        the window spans a subprocess spawn — so it is a lost port, not a verdict: re-run
        on a fresh port (port=None re-scans by itself). Never when the caller pinned an
        explicit port: a pinned port's collision is the behavior under test.
        """
        pinned = kwargs.get("port") is not None
        text = None
        for _ in range(5):
            said = []
            with mock.patch.object(sg, "say", said.append):
                try:
                    sg.cmd_verify(_Args(**{"port": self.port, **kwargs}))
                except SystemExit:
                    text = "\n".join(str(m) for m in said)
                    if pinned or not _collided(text):
                        return text, True
                    if "port" not in kwargs:
                        self.port = _free_port(span=3)
                    continue
            return "\n".join(str(m) for m in said), False
        raise unittest.SkipTest(f"verify's ports collided 5 times; last error: {text}")

    def aim_probes_at(self, port):
        """Point the guest's observer probes at `port` instead of the observer's own.

        The fake guest is this host, so a probe aimed at the live observer always arrives —
        which is the leak, not containment. A port nothing holds is what a denied one looks
        like from the host's side of the wire: the connect is refused and the datagram goes
        nowhere.
        """
        real = sg._oracle_guest_script

        def aimed(**kwargs):
            return real(**{**kwargs, "observer_port": port})

        patch = mock.patch.object(sg, "_oracle_guest_script", aimed)
        patch.start()
        self.addCleanup(patch.stop)

    def dead_port(self, *extra_reserved):
        """A port nothing holds — and specifically not one of this run's oracle ports.

        `_free_port(span=3)` reserves the proxy port and the two oracle ports by binding and
        closing them, so those three numbers are freshly released and are precisely what the
        kernel offers next. An unguarded ephemeral pick therefore lands on the observer's own
        port often enough to make a contained run look like a leak — on one platform and not
        another, which is the worst way for a test to be wrong. A run whose port the scan
        picks (not self.port) names its own range via `extra_reserved`.
        """
        reserved = {self.port, self.port + 1, self.port + 2, *extra_reserved}
        for _ in range(50):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            if port not in reserved:
                return port
        raise AssertionError("no free port outside this run's oracle ports")

    def test_a_contained_run_reports_what_each_oracle_proved(self):
        self.aim_probes_at(self.dead_port())
        said, refused = self.verify()
        self.assertFalse(refused, said)
        self.assertIn("containment holds", said)
        self.assertIn("host-side oracles agree", said)
        self.assertIn("credential replaced, never added, on 2/2 requests", said)
        self.assertIn("nothing from the guest", said)
        self.assertIn("2 allow, 2 deny", said)

    def test_the_guest_is_created_named_and_removed(self):
        self.aim_probes_at(self.dead_port())
        self.verify()
        log = self.log.read_text()
        name = sg._verify_guest_name("main")
        self.assertIn(f"create debian --name {name}", log)
        self.assertIn(f"stop {name}", log)
        self.assertIn(f"rm {name}", log)
        self.assertEqual(json.loads((self.tmp / "msb.state").read_text()), {})

    def test_the_oracle_probes_run_before_the_check_script(self):
        self.aim_probes_at(self.dead_port())
        self.verify()
        # check 7 changes the guest's routing and never restores it, so the probes must not
        # follow it: two execs, the oracle one first.
        execs = [ln for ln in self.log.read_text().splitlines() if ln.startswith("exec")]
        self.assertEqual(len(execs), 2)
        self.assertIn("ORACLE", execs[0])
        self.assertIn("verify_guest.sh", execs[1])

    def test_a_packet_that_reaches_the_host_refuses_the_run(self):
        said, refused = self.verify()            # probes aimed at the live observer
        self.assertTrue(refused)
        self.assertIn("CONTAINMENT FAILED OUTSIDE THE GUEST", said)
        self.assertIn("REACHED the host", said)
        self.assertNotIn("containment holds", said)

    def test_a_credential_added_where_none_was_sent_refuses_the_run(self):
        self.aim_probes_at(self.dead_port())
        os.environ["STUB_MISBEHAVE"] = "add-credential"
        self.addCleanup(os.environ.pop, "STUB_MISBEHAVE", None)
        said, refused = self.verify()
        self.assertTrue(refused)
        self.assertIn("ADDED a credential", said)
        self.assertNotIn("containment holds", said)

    def test_the_guest_is_removed_even_when_the_run_is_refused(self):
        _, refused = self.verify()               # the leak path
        self.assertTrue(refused)
        self.assertIn(f"rm {sg._verify_guest_name('main')}", self.log.read_text())

    def test_no_oracles_runs_the_checks_alone_and_says_so(self):
        said, refused = self.verify(oracles=False)
        self.assertFalse(refused, said)
        self.assertIn("host-side oracles skipped", said)
        self.assertNotIn("recorder", said)
        # and the ruleset the proxy was given holds no host-loopback rule at all
        snapshot, = sg.LOG_DIR.glob("*.rules")
        self.assertNotIn(sg._RECORDER_HOST, snapshot.read_text())

    def test_the_negative_control_boots_a_second_guest_and_requires_check_3_to_fail(self):
        self.aim_probes_at(self.dead_port())
        said, refused = self.verify(negative_control=True)
        self.assertFalse(refused, said)
        log = self.log.read_text()
        leaky = sg._verify_guest_name("leaky")
        self.assertIn(f"--name {leaky}", log)
        self.assertIn("--net-default-egress allow", log)
        self.assertIn("check 3 FAILED in the leaking guest", said)
        self.assertIn(f"rm {leaky}", log)

    def test_a_negative_control_that_established_no_leak_refuses_to_conclude(self):
        self.aim_probes_at(self.dead_port())
        # A guest that ignores the flag: msb accepted `allow` and the checks passed anyway.
        (self.tmp / "repo" / "test" / "verify_guest.sh").write_text(
            _stub_checks_script().replace("${GUEST_EGRESS:-deny}", "deny"))
        said, refused = self.verify(negative_control=True)
        self.assertTrue(refused)
        self.assertIn("established no leak", said)
        self.assertIn("draws no conclusion", said)
        self.assertNotIn("containment holds", said)

    def test_no_port_scans_past_a_held_floor_and_the_run_completes(self):
        # The whole point of the default: a shared proxy holds the floor, verify with no
        # --port lands one past it and runs to its verdict — no die, no contention.
        floor, _ = _bind_or_skip(lambda port: _squat(self, port), span=sg.POOL_SIZE + 1)
        self.aim_probes_at(self.dead_port(*range(floor, floor + sg.POOL_SIZE + 1)))
        with mock.patch.object(sg, "DEFAULT_BASE_PORT", floor):
            said, refused = self.verify(port=None)
        self.assertFalse(refused, said)
        self.assertIn(f"proxy :{floor + 1} ·", said, "verify did not land one past the holder")
        self.assertIn("containment holds", said)

    def test_an_explicit_port_that_is_taken_dies_instead_of_moving(self):
        # span=3 keeps the oracle ports beside the squat free, so the die start_proxy
        # pins is the one the proxy port's holder causes. Passing the port pins it:
        # verify() must not retry a collision that is the behavior under test.
        self.port, _ = _bind_or_skip(lambda port: _squat(self, port), span=3)
        said, refused = self.verify(port=self.port)
        self.assertTrue(refused)
        self.assertIn(f"port {self.port} is already in use", said)
        self.assertNotIn("containment holds", said)

    def test_a_guest_that_cannot_be_removed_is_a_failure_of_its_own(self):
        self.aim_probes_at(self.dead_port())
        with mock.patch.object(sg, "_remove_sandbox", lambda name: False):
            said, refused = self.verify()
        self.assertTrue(refused)
        self.assertIn("could not be removed", said)
        self.assertIn("collides with proxy port", said)
        self.assertIn("by hand", said)                 # and the finally says it again, louder


def _port_free(port):
    # Every bind the oracles make must be probed, or a pick passes here and dies there:
    # sg._ArrivalObserver binds tcp and udp on both loopback addresses.
    for family, addr, kind in ((socket.AF_INET, "127.0.0.1", socket.SOCK_STREAM),
                               (socket.AF_INET6, "::1", socket.SOCK_STREAM),
                               (socket.AF_INET, "127.0.0.1", socket.SOCK_DGRAM),
                               (socket.AF_INET6, "::1", socket.SOCK_DGRAM)):
        with socket.socket(family, kind) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((addr, port))
            except OSError:
                return False
    return True


if __name__ == "__main__":
    unittest.main()
