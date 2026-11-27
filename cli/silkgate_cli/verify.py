"""silkgate verify: containment checked in a real guest, and evidence the host gathers itself."""
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from uuid import uuid4

from . import console, core, paths


# The full check installs its own probe tools *through* the proxy, then trusts the CA so
# the https probes can complete. The CA is mounted in, since nothing is baked here.
# -q is explicit because apt's tty detection asks about the guest's stdout, and a terminal
# there gets a \r-repainting meter that's unreadable line by line. One -q drops the meter
# and keeps the Get:/Fetched lines, which explain a failed install.
FULL_SETUP = ("export DEBIAN_FRONTEND=noninteractive && "
              "apt-get -q update && "
              "apt-get -q -o Dpkg::Use-Pty=0 install -y --no-install-recommends"
              " curl ca-certificates dnsutils iputils-ping iproute2 && "
              "cp /mnt/ca/egress-ca.pem /usr/local/share/ca-certificates/egress.crt && "
              "update-ca-certificates && ")


# verify_guest.sh reports which checks ran. A check that didn't run proves nothing, so the
# set that ran is asserted, not a count of passes.
#
# The checks, and which ones a bare guest must run, are read from the script. Each check
# opens with a line naming what it needs installed:
#
#     # CHECK 7 tools:ip — root routes around the boundary
#     # CHECK 3 tools:none — direct TCP/443 to a raw IP
#
# and `tools:none` is what makes a check part of the bare run. The set is derived, never
# restated here, so it can't drift from the script: a `have` gate added to a tool-free check
# moves it out of the bare set by itself. Check 7, for example, needs `ip`, which only
# `--full` installs.
#
# A `subject:<capability>` field lets a check report UNAVAILABLE, when the guest lacks what
# it would probe (a v6 check with no v6 path). _verify_shortfall refuses UNAVAILABLE from a
# check that declares no subject, so "nothing to test" can't slip in as a bare string.
#
# If the script can't be read, the sets are empty and _verify_shortfall refuses the run.
# Other commands don't need them, and still work.
_VERIFY_SCRIPT = paths.REPO / "test" / "verify_guest.sh"
_CHECK_DECL = re.compile(r"^#\s*CHECK\s+(\d+)\s+tools:(\S+)(?:\s+subject:(\S+))?", re.M)


def _declared_checks(path=None):
    """(every check id, the ids needing no installed tool, {id: the subject a guest may
    lack}) as verify_guest.sh declares them."""
    try:
        text = (path or _VERIFY_SCRIPT).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset(), frozenset(), {}
    declared = _CHECK_DECL.findall(text)
    return (frozenset(int(n) for n, _, _ in declared),
            frozenset(int(n) for n, tools, _ in declared if tools == "none"),
            {int(n): subject for n, _, subject in declared if subject})


_VERIFY_CHECKS, _VERIFY_TOOL_FREE, _VERIFY_SUBJECTS = _declared_checks()


def _ids(ids):
    return ", ".join(str(i) for i in sorted(ids))


def _parse_checks(line):
    """`CHECKS: ran=3,7 skipped=1,2 unavailable=5` -> ({3, 7}, {1, 2}, {5}). A line from
    before the unavailable field parses with an empty third set."""
    fields = dict(re.findall(r"(ran|skipped|unavailable)=([\d,]*)", line))

    def ids(key):
        return {int(i) for i in fields.get(key, "").split(",") if i}

    return ids("ran"), ids("skipped"), ids("unavailable")


def _verify_shortfall(passed, failed, ran, skipped, unavailable=frozenset(), *, full):
    """Why a verify run does not prove containment, or None if it does."""
    if failed:
        return f"containment check FAILED ({passed} passed, {failed} failed)"
    expected = _VERIFY_CHECKS if full else _VERIFY_TOOL_FREE
    if not expected:
        return (f"cannot tell which checks should have run: no '# CHECK n tools:' declarations "
                f"in {_VERIFY_SCRIPT} — containment unproven")
    # "Nothing to test" is the easiest verdict to abuse — accepted wholesale, unavailable=1..15
    # from a guest that ran nothing would read as containment — so it is honoured only from
    # the checks whose declarations say their subject can be absent, and never for a check
    # that also claims to have run.
    undeclared = unavailable - _VERIFY_SUBJECTS.keys()
    if undeclared:
        return (f"check(s) {_ids(undeclared)} report their subject absent, but their CHECK "
                f"declarations name no subject: a guest may lack "
                f"(only {_ids(_VERIFY_SUBJECTS) or 'none of them'} do) — a check that could "
                "have run did not, so containment is unproven")
    contradicted = unavailable & ran
    if contradicted:
        return (f"verify output disagrees with itself: check(s) {_ids(contradicted)} both ran "
                "and reported nothing to test")
    missing = expected - ran - unavailable
    if missing:
        needs_tools = _ids(_VERIFY_CHECKS - _VERIFY_TOOL_FREE) or "none of them"
        return (f"containment unproven — check(s) {_ids(missing)} never ran"
                + (f" (skipped: {_ids(skipped)})" if skipped else "")
                + (f"; --full installs what {needs_tools} need, and the rest skip only when "
                   "an in-guest control failed" if full
                   else "; those declare tools:none, so something other than a missing tool "
                        "is wrong"))
    if passed != len(ran):
        return f"verify output disagrees with itself: {passed} passed of {len(ran)} that ran"
    return None


# --- verify: evidence outside the guest ---------------------------------------------------
# Everything above trusts two lines the GUEST printed, and a hostile guest can print them.
# The oracles are the host's own record of the same run, which no guest can produce: the
# run's audit log, a listener that does or doesn't receive a packet, and an endpoint that
# records the header that arrived.
#
# Each oracle reports (kind, text). "observed": the host saw something forbidden (a packet,
# an added credential). "unproven": corroborating evidence is missing. A failed check is a
# boundary result, a silent audit log is a broken oracle, so they read differently.

_VERIFY_IMAGE = "debian"                  # the guest verify boots; bare, so probes stay honest

# The credential the recording endpoint must see arrive. Deliberately the string
# test/test_addon.py already uses, for the same reason: what proves the injection path must
# never be a real key, and one grep finds both the unit test and this live fixture.
_VERIFY_SENTINEL = "SENTINEL-NOT-A-REAL-KEY"
_VERIFY_SECRET_NAME = "verify_sentinel"   # -> SILKGATE_EGRESS_SECRET_VERIFY_SENTINEL, set for this run
_VERIFY_AUTH_HEADER = "x-api-key"         # the header the guest sends and the secret replaces

# The recorder's rule host must be a NAME: normalize_host rejects IP literals by design, in
# both the pattern and the request. `localhost` is the one name every host resolves to
# loopback without a hosts-file edit, and only the *proxy* resolves it — it runs on the host,
# and the guest names the same authority in an absolute-form request line it never resolves.
_RECORDER_HOST = "localhost"
_RECORDER_PATH = "/verify/record"

# The hosts checks 1 and 2 reach (check 1's is profiles/probe/rules.txt's), so a missing
# audit record can name its check. They mirror test/verify_guest.sh: if it changes them,
# the audit assertion fails naming the expected host.
_VERIFY_ALLOWED_HOST = "registry.npmjs.org"
_VERIFY_UNLISTED_HOST = "evil.com"
# What control 0 asks the proxy for: a host no ruleset allows, so it is refused from the proxy's
# own memory. The record it produces is the only host-side evidence a *bare* run leaves.
_VERIFY_CONTROL_HOST = "silkgate.invalid"

# Verify guests are named, so an interrupted run's guest can be removed later. The pid in the
# name marks a leftover: if that pid is gone, nobody owns it. The prefix can't collide with
# session sandboxes, which start with `sg-`.
_VERIFY_GUEST_RE = re.compile(r"silkgate-verify-(\d+)-(?:main|leaky)\Z")


def _verify_guest_name(kind):
    return f"silkgate-verify-{os.getpid()}-{kind}"


def _verify_msb_argv(sandbox, port, *, mounts=()):
    """`msb create` argv for a named verify guest whose only egress is one proxy port.

    A named `create` + `exec` + `rm` guest, because stopping an `msb run` client leaves its
    sandbox running, with a port allowance the next run collides with. The flags are
    msb_argv's, so verify tests the policy every session gets. _leaky_argv derives the
    negative control from this.
    """
    argv = [core._msb(), "create", _VERIFY_IMAGE, "--name", sandbox]
    for m in mounts:
        argv += ["-v", m]
    url = f"http://{core.PROXY_ALIAS}:{port}"
    for var in core.PROXY_ENV_VARS:
        argv += ["-e", f"{var}={url}"]
    argv += ["--net-default-egress", "deny", "--net-rule", f"allow@host:tcp:{port}"]
    return argv


def _leaky_argv(argv):
    """The same guest with msb's egress default flipped to allow — a guest that really leaks.

    Dropping --net-default-egress deny does NOT open egress: msb denies by default once
    any --net-rule is present. Setting it to `allow` does. So the flip is the whole
    mechanism, and a renamed flag must fail here, not quietly produce a contained guest
    whose silence would read as "the checks cannot fail".
    """
    out = list(argv)
    try:
        i = out.index("--net-default-egress")
    except ValueError:
        console.die("cannot build the negative control: the verify guest's argv carries no "
                    "--net-default-egress to flip, so nothing here would open egress — the guest "
                    "would be contained and its passing checks would prove nothing")
    if out[i + 1] != "deny":
        console.die(f"cannot build the negative control: --net-default-egress is {out[i + 1]!r}, "
                    "not 'deny' — refusing to guess what would open egress")
    out[i + 1] = "allow"
    return out


def _create_verify_guest(sandbox, port, *, mounts=(), leaky=False, why=""):
    """Create (and boot) one named verify guest, or die. msb's own output is inherited rather
    than captured, as in _provision_session: the first run pulls the image, and a silent minute
    reads as a hang. `leaky` is the negative control's guest — the same guest, egress open."""
    argv = _verify_msb_argv(sandbox, port, mounts=mounts)
    if subprocess.run(_leaky_argv(argv) if leaky else argv).returncode:
        core._remove_sandbox(sandbox)              # a failed create can still register the name
        console.die(f"msb create failed for verify guest {sandbox} (see msb's output above){why}")


def _drop_verify_guest(sandbox, guests):
    """Remove one verify guest now, keeping it in `guests` if it is not verifiably gone.

    Uses _remove_sandbox, as sessions do. A guest that survives isn't just untidy: its port
    allowance collides with the next verify.
    """
    if core._remove_sandbox(sandbox):
        guests.discard(sandbox)
        return True
    return False


def _reap_leaked_verify_guests():
    """Remove verify guests earlier runs left behind, naming each.

    Only guests whose pid is gone: a name whose owner still runs belongs to a concurrent
    verify (proxy_alive is a bare pid-liveness test despite its name — a recycled pid
    therefore keeps a leftover, which errs toward leaving another process's guest alone).
    """
    msb = shutil.which("msb")
    if not msb:
        return
    listed = subprocess.run([msb, "list"], capture_output=True, text=True)
    if listed.returncode:
        return
    for line in listed.stdout.splitlines()[1:]:
        name = (line.split() or [""])[0]
        match = _VERIFY_GUEST_RE.fullmatch(name)
        if not match or int(match[1]) == os.getpid() or core.proxy_alive(int(match[1])):
            continue
        console.say(f"removing {name}: an interrupted verify left it behind (pid {match[1]} is "
                    "gone), and it still holds a Tier-1 rule and a port allowance")
        if not core._remove_sandbox(name):
            console.say(f"could not remove {name} — `msb stop {name} && msb rm {name}` by hand")


def _oracle_port(proxy_port, offset):
    """A host port `offset` above the proxy's, folded below it at the top of the range — the
    same fold check 10 does for the neighbouring port it probes."""
    port = proxy_port + offset
    return port if port <= 65535 else proxy_port - offset


def _port_holder(port):
    """Who holds `port`, for an error message: lsof's answer where lsof is installed, else the
    command that would say. Same remedy shape as _port_in_use_error, which covers the proxy's
    own ports; these are the oracles'."""
    ask = f"lsof -nP -i:{port} names the holder"
    lsof = shutil.which("lsof")
    if not lsof:
        return ask
    try:
        out = subprocess.run([lsof, "-nP", f"-i:{port}"], capture_output=True, text=True,
                             timeout=5).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return ask
    rows = [ln.split() for ln in out[1:] if ln.strip()]
    named = "; ".join(f"{r[0]} (pid {r[1]})" for r in rows[:3] if len(r) >= 2)
    return f"held by {named}" if named else ask


def _oracle_bind(port, socktype, what):
    """Bind `port` on every address the proxy listens on, or die naming the holder.

    PROXY_BINDS, because guest traffic lands there, and the guest tries the v6 alias first.
    An oracle on one family could stay silent because the guest used the other, which would
    look exactly like containment.
    """
    socks = []
    for addr in core.PROXY_BINDS or ("127.0.0.1",):
        sock = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socktype)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((addr, port))
            if socktype == socket.SOCK_STREAM:
                sock.listen(16)
        except OSError as e:
            sock.close()
            for other in socks:
                other.close()
            console.die(f"cannot bind the {what} at {addr}:{port} ({e.strerror}) — "
                        f"{_port_holder(port)}")
        socks.append(sock)
    return socks


class _ArrivalObserver:
    """A host listener — TCP and UDP — on a port the guest's Tier-1 rule does not allow.

    Every other verdict is the guest saying it heard nothing, and for UDP it can't even
    tell (a denied sendto succeeds silently). This is the wire's other end. The port stays
    out of the allow rule, so an arrival means the rule is wider than `tcp:<proxy port>`.

    Nothing is read during the run: connections wait in the backlog, datagrams in the
    buffer, until drain(). Silence counts only after self_test() shows these sockets
    receive their own token, on every address and protocol.
    """

    def __init__(self, port):
        self.port = port
        self.arrivals = []
        self.self_token = "self-" + uuid4().hex
        self.guest_token = "guest-" + uuid4().hex
        self._socks = []
        try:
            self._socks = [("tcp", s) for s in
                           _oracle_bind(port, socket.SOCK_STREAM, "arrival observer (tcp)")]
            self._socks += [("udp", s) for s in
                            _oracle_bind(port, socket.SOCK_DGRAM, "arrival observer (udp)")]
        except BaseException:                  # incl. SystemExit from die(): keep no half-bind
            self.close()
            raise
        for _, sock in self._socks:
            sock.setblocking(False)
        # Recorded at construction, not read off the sockets on demand: what has to be proven
        # is what this observer *bound*, and a closed observer whose bound() answered "nothing"
        # would make the self-proof below vacuous — silence passing for the reason it must not.
        self._bound = [(proto, sock.getsockname()[0]) for proto, sock in self._socks]

    def bound(self):
        """The (proto, address) pairs this observer listened on, closed or not."""
        return list(self._bound)

    def self_test(self):
        """Send this observer's own token to every address it bound, both protocols. What
        comes back is what the caller may treat as functional; anything else makes this
        observer's later silence meaningless, and the run says so instead of concluding."""
        for proto, sock in self._socks:
            addr = sock.getsockname()[0]
            family = sock.family
            try:
                if proto == "tcp":
                    with socket.socket(family, socket.SOCK_STREAM) as probe:
                        probe.settimeout(2)
                        probe.connect((addr, self.port))
                        probe.sendall(self.self_token.encode())
                else:
                    with socket.socket(family, socket.SOCK_DGRAM) as probe:
                        probe.settimeout(2)
                        probe.sendto(self.self_token.encode(), (addr, self.port))
            except OSError:
                continue                       # the missing arrival is the report
        self.drain()

    def drain(self, settle=0.3):
        """Take everything the kernel has queued on these sockets into self.arrivals."""
        time.sleep(settle)                     # a loopback or VMM delivery lands in µs
        for proto, sock in self._socks:
            addr = sock.getsockname()[0]
            while True:
                try:
                    if proto == "tcp":
                        conn, peer = sock.accept()
                        with conn:
                            conn.settimeout(0.3)
                            try:
                                data = conn.recv(4096)
                            except OSError:    # connected and sent nothing: still an arrival
                                data = b""
                    else:
                        data, peer = sock.recvfrom(4096)
                except OSError:                # BlockingIOError included: nothing more queued
                    break
                self.arrivals.append({
                    "proto": proto, "addr": addr,
                    "peer": f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else str(peer),
                    "data": data.decode("ascii", "replace")[:200],
                })

    def close(self):
        for _, sock in self._socks:
            try:
                sock.close()
            except OSError:
                pass
        self._socks = []


def _observer_problems(arrivals, *, bound, self_token, guest_token, port, proxy_port):
    """(problems, summary) for what did and did not reach the observer."""
    proved = {(a["proto"], a["addr"]) for a in arrivals if self_token in a["data"]}
    missing = [pair for pair in bound if pair not in proved]
    problems = []
    if missing:
        problems.append(("unproven",
                         "the arrival observer never received its own loopback send on "
                         + ", ".join(f"{proto} {addr}:{port}" for proto, addr in missing)
                         + " — a listener that cannot hear itself proves nothing by staying "
                         "silent, so this run observed nothing either way"))
    for a in arrivals:
        if guest_token in a["data"]:
            problems.append(("observed",
                             f"a {a['proto']} packet from the verify guest REACHED the host at "
                             f"{a['addr']}:{port} (peer {a['peer']}), carrying this run's "
                             f"token — the Tier-1 rule is wider than tcp:{proxy_port}, which "
                             "no probe inside the guest can see"))
        elif self_token not in a["data"]:
            problems.append(("observed",
                             f"a {a['proto']} arrival at {a['addr']}:{port} from {a['peer']} "
                             f"carried neither token ({a['data'][:60]!r}) — something reached a "
                             "host port this run denies, and it is not this fixture"))
    return problems, (f"observer: {len(proved)}/{len(bound)} self-sends heard, "
                      f"nothing from the guest at :{port}" if not problems
                      else f"observer: {len(problems)} problem(s) at :{port}")


def _recorder_rules(port):
    """The one verify-only rule that puts the recording endpoint in the guest's reach.

    It's the "host loopback service in reach" hazard, so it's narrow and in no profile: one
    port, one path, POST only (which also tests method enforcement). No `q:`, `h:`, or
    max_body, so stripping and the no-body default stay live.
    """
    return (f"# --- verify only: the host-side Tier-2 recorder, port {port} ---\n"
            f"{_RECORDER_HOST}:{port}{_RECORDER_PATH}/** POST "
            f"inject_auth={_VERIFY_SECRET_NAME}\n")


class _HeaderRecorder:
    """A host-loopback HTTP endpoint that RECORDS what arrived and reflects nothing.

    It tests "guest code execution can't steal the key" against the real proxy: the guest
    sends a dummy credential, the host holds a sentinel, and the header that arrives says
    which went upstream. It answers 204 and nothing else, so the guest learns nothing. It's
    not the reflector the docs warn about: it holds a sentinel, not a real key, for one run.
    """

    def __init__(self, port):
        # Local imports: only this fixture needs an HTTP server, and every `silkgate exec`
        # would otherwise pay for importing one.
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.port = port
        self.records = []
        records = self.records

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "silkgate-verify-recorder"
            sys_version = ""

            def _record(self):
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                records.append({"method": self.command, "target": self.path,
                                "headers": [(k.lower(), v) for k, v in self.headers.items()],
                                "body_len": len(body)})
                self.send_response(204)        # nothing useful: not the guest's oracle
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _record
            do_OPTIONS = _record

            def log_message(self, *a):         # the audit log is the record; this is noise
                pass

        class V4Server(ThreadingHTTPServer):
            daemon_threads = True              # on subclasses of our own, never on the stdlib's

        class V6Server(V4Server):
            address_family = socket.AF_INET6

        self._servers = []
        for addr in core.PROXY_BINDS or ("127.0.0.1",):
            cls = V6Server if ":" in addr else V4Server
            try:
                server = cls((addr, port), Handler)
            except OSError as e:
                self.close()
                console.die(f"cannot bind the Tier-2 recorder at {addr}:{port} ({e.strerror}) — "
                            f"{_port_holder(port)}")
            self._servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def rules(self):
        return _recorder_rules(self.port)

    def close(self):
        for server in getattr(self, "_servers", []):
            try:
                server.shutdown()
                server.server_close()
            except Exception:                  # already down; the records are the point
                pass
        self._servers = []


def _clip_oracle(text, limit=200):
    """Guest-supplied text in a host-side message, bounded — a header the guest chose must not
    be able to bury the finding it is evidence for."""
    return text if len(text) <= limit else text[:limit] + "..."


def _recorder_problems(records, *, token, port):
    """(problems, summary) for what the recording endpoint received.

    Two sentinels decide it. The guest's token, sent in the query, the dummy credential, and
    an extra header, must appear in nothing that arrived. The host's sentinel must be the
    auth header's value on the request that sent one, and absent from the one that didn't.
    """
    by_path = {}
    for rec in records:
        by_path.setdefault(rec["target"].partition("?")[0], []).append(rec)
    problems, seen = [], []
    for leaf, why in (("replace", "the request that carried a credential"),
                      ("add", "the request that carried none")):
        path = f"{_RECORDER_PATH}/{leaf}"
        got = by_path.pop(path, [])
        if not got:
            problems.append(("unproven",
                             f"nothing arrived at {_RECORDER_HOST}:{port}{path} — {why} never "
                             "reached the recorder, so Tier 2 is not proven end to end here "
                             "(the guest's own reply code and the audit log say which hop "
                             "dropped it)"))
            continue
        rec = got[-1]
        seen.append(leaf)
        auth = [v for name, v in rec["headers"] if name == _VERIFY_AUTH_HEADER]
        arrived = rec["target"] + " " + " ".join(f"{n}: {v}" for n, v in rec["headers"])
        if token in arrived:
            problems.append(("observed",
                             f"the guest's own token crossed the proxy to {path}: "
                             f"{_clip_oracle(arrived)} — a query param, a header or a header "
                             "value the ruleset does not allow was forwarded"))
        if rec["method"] != "POST":
            problems.append(("observed",
                             f"{rec['method']} reached {path}, and the rule allows POST only"))
        if leaf == "replace" and not auth:
            problems.append(("unproven",
                             f"no {_VERIFY_AUTH_HEADER} arrived at {path} at all, though the "
                             "guest sent one and the rule injects into it — the request got "
                             "through with the header dropped, which proves nothing either way"))
        elif leaf == "replace" and auth != [_VERIFY_SENTINEL]:
            problems.append(("observed",
                             f"{_VERIFY_AUTH_HEADER} arrived at {path} as {auth!r}, not the "
                             "host's sentinel exactly once — the injected value must REPLACE "
                             "the header the guest sent"))
        elif leaf == "add" and auth:
            problems.append(("observed",
                             f"{_VERIFY_AUTH_HEADER} arrived at {path} as {auth!r}, and that "
                             "request sent none — the proxy ADDED a credential to a request "
                             "that did not carry one, which is the guarantee every guest is "
                             "given"))
    for path, got in by_path.items():
        problems.append(("observed",
                         f"{got[-1]['method']} {path} reached the recorder, and no rule in this "
                         "run's ruleset allows it — the proxy forwarded a request it must have "
                         "refused"))
    return problems, (f"recorder: credential replaced, never added, on {len(seen)}/2 requests "
                      f"at :{port}; nothing else got through" if not problems
                      else f"recorder: {len(problems)} problem(s) at :{port}")


def _oracle_guest_script(*, proxy_port, observer_port, recorder_port, token):
    """The probes the guest runs for the host-side oracles: tool-free bash, one line each.

    Only /dev/tcp, /dev/udp, and printf, so they run on the bare image, over plain HTTP
    through the proxy. Every literal is baked in, so nothing dynamic is quoted.

    The observer probes hit a port Tier 1 denies: the guest's errno is its evidence, the
    observer's silence the host's. The recorder requests carry the token where it must be
    stripped, a dummy where the sentinel must replace it, no credential where none may be
    added, and a forbidden method.
    """
    alias, req = core.PROXY_ALIAS, f"http://{_RECORDER_HOST}:{recorder_port}{_RECORDER_PATH}"
    host_hdr = f"Host: {_RECORDER_HOST}:{recorder_port}"

    def request(method, leaf, *headers):
        """One request as bash ANSI-C quoting will carry it: CRLF-terminated, body-less.

        `$'...'` and not a command substitution, because $() strips the trailing newlines —
        which here are the blank line that ends the request.
        """
        lines = [f"{method} {req}/{leaf} HTTP/1.1", host_hdr, *headers,
                 "Content-Length: 0", "Connection: close", "", ""]
        return "\\r\\n".join(lines)

    replace = request("POST", f"replace?leak={token}",
                      f"{_VERIFY_AUTH_HEADER}: DUMMY-{token}", f"x-exfil: {token}")
    return "\n".join([
        "set -u",
        f"probe(){{ if err=$(timeout 5 bash -c \"exec 3<>/dev/$1/{alias}/{observer_port} "
        f"&& printf %s {token} >&3\" 2>&1); then echo \"ORACLE observer-$1 sent\"; "
        "else echo \"ORACLE observer-$1 blocked $(printf %s \"$err\" | tr -d '\\r' | "
        "tail -n1 | cut -c1-90)\"; fi; }",
        "probe tcp",
        "probe udp",
        # One connection per request, and only the status line is read: the guest's view of the
        # fixture is a three-digit number, which is all a hostile guest could learn here. The
        # code is reported as 000 unless it really is three digits, so a connection that never
        # got a reply cannot be read on the host as a status the proxy sent.
        f"req(){{ label=$1; out=$(timeout 5 bash -c 'exec 3<>/dev/tcp/{alias}/{proxy_port} "
        "|| exit 9\n"
        'printf %s "$1" >&3\nIFS= read -r line <&3\nprintf %s "$line"\' _ "$2" 2>&1); rc=$?; '
        "out=$(printf %s \"$out\" | tr -d '\\r' | head -n1); set -- $out; code=${2:-000}; "
        "case $code in [0-9][0-9][0-9]) ;; *) code=000 ;; esac; "
        "echo \"ORACLE $label code=$code rc=$rc reply=$(printf %s \"$out\" | cut -c1-70)\"; }",
        "req recorder-replace $'" + replace + "'",
        "req recorder-add $'" + request("POST", "add") + "'",
        "req recorder-method $'" + request("GET", "method") + "'",
    ]) + "\n"


_ORACLE_LINE_RE = re.compile(r"ORACLE\s+(\S+)\s+(.*)")


def _oracle_report(lines):
    """{label: detail} from the guest's own ORACLE lines — what it says it attempted."""
    report = {}
    for line in lines:
        m = _ORACLE_LINE_RE.search(line)
        if m:
            report[m[1]] = m[2].strip()
    return report


def _probe_problems(report, *, observer_port):
    """(problems, summary) for what the guest says its probes did.

    The observer's silence counts only once the guest confirms it sent. A TCP refusal is the
    expected result, and its errno separates a boundary decision from a missing route. So
    `blocked` passes, and a missing line doesn't.
    """
    problems, notes = [], []
    for proto in ("tcp", "udp"):
        detail = report.get(f"observer-{proto}")
        if detail is None:
            problems.append(("unproven",
                             f"the guest never reported its {proto} probe of the observer "
                             f"port {observer_port}, so nothing observed there means anything"))
        else:
            notes.append(f"{proto} {detail}")
    if report.get("observer-udp", "").split()[:1] == ["blocked"]:
        problems.append(("unproven",
                         "the guest could not even open a UDP socket to the observer port "
                         f"({report['observer-udp']}) — a denied sendto succeeds everywhere "
                         "this was verified, so a failure here is a broken probe, not "
                         "containment"))
    for label, want in (("recorder-replace", "204"), ("recorder-add", "204"),
                        ("recorder-method", "403")):
        detail = report.get(label)
        if detail is None:
            problems.append(("unproven",
                             f"the guest never reported {label}, so its half of the Tier-2 "
                             "fixture did not run"))
            continue
        got = re.search(r"code=(\d{3})", detail)
        if got is None or got[1] == "000":
            problems.append(("unproven",
                             f"the guest got no status line for {label} ({detail}) — its "
                             "request reached no proxy at all, so it says nothing about what "
                             "the proxy does with one"))
        elif got[1] != want:
            observed = label == "recorder-method" and got[1].startswith("2")
            problems.append(("observed" if observed else "unproven",
                             f"the guest saw {got[1]} for {label}, not {want} ({detail}) — "
                             + ("a method the rule does not allow was forwarded"
                                if observed else
                                "so what that request proves about Tier 2 is not what this "
                                "fixture claims")))
    return problems, ("guest probes: " + "; ".join(notes) if notes else "guest probes: none")


def _audit_records(text):
    """The addon's JSON audit records out of a proxy log, in order.

    Drops mitmdump's timestamp prefix and its own chatter: everything before the first brace,
    and any line that doesn't parse. Like `logs --audit`, without the session filter.
    """
    records = []
    for line in text.splitlines():
        brace = line.find("{")
        if brace < 0:
            continue
        try:
            rec = json.loads(line[brace:])
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("decision"):
            records.append(rec)
    return records


def _audit_expectations(*, full, recorder_port=None):
    """What this run's audit log must contain, each naming the guest line it corroborates."""
    expect = []
    if full:
        # Checks 1 and 2 are the two the guest reports as proxy-path results. Tying them to
        # the host's record is what closes the loop: a `403` the guest saw could have come
        # from anything on that port, and an allowed host it reached could have been reached
        # around the proxy entirely.
        expect.append({"decision": "allow", "host": _VERIFY_ALLOWED_HOST,
                       "why": "check 1's allowed host"})
        expect.append({"decision": "deny", "host": _VERIFY_UNLISTED_HOST,
                       "why": "check 2's unlisted host"})
    if recorder_port is not None:
        # Method, not path: the allow record is written after query stripping has rewritten the
        # request's path, and pinning the string mitmproxy leaves there would make this oracle
        # fail for a reason that is not about egress. The two POSTs are told apart at the
        # recorder, which sees what actually arrived.
        expect.append({"decision": "allow", "host": _RECORDER_HOST, "port": recorder_port,
                       "method": "POST", "why": "the recorder's two allowed POSTs"})
        expect.append({"decision": "deny", "host": _RECORDER_HOST, "port": recorder_port,
                       "method": "GET", "why": "the recorder request whose method no rule allows"})
    return expect


def _audit_missing(records, expectations):
    """The expectations no record satisfies — pure, because the poll loop below and the verdict
    itself must ask exactly the same question."""
    return [want for want in expectations
            if not any(all(rec.get(k) == v for k, v in want.items() if k != "why")
                       for rec in records)]


def _audit_problems(text, expectations, *, log_path):
    """(problems, summary) for the audit log against what this run should have provoked."""
    records = _audit_records(text)
    problems = []
    if not records:
        return ([("unproven",
                  f"{log_path} holds no audit record at all — either the addon stopped "
                  "auditing or the guest never reached this proxy, and the guest's own "
                  "proxy-path lines cannot tell those apart from success")],
                "audit: no records")
    for want in _audit_missing(records, expectations):
        fields = " ".join(f"{k}={v}" for k, v in want.items() if k != "why")
        problems.append(("unproven",
                         f"{log_path} holds no {fields} — nothing on the host corroborates "
                         f"{want['why']}, so that line is the guest's word alone"))
    if not any(rec["decision"] == "deny" for rec in records):
        problems.append(("unproven",
                         f"{log_path} records no deny at all, though every verify guest probes "
                         "the proxy with a host no ruleset allows (control 0) — an audit trail "
                         "with no refusal in it is not this run's"))
    elif not any(rec.get("host") == _VERIFY_CONTROL_HOST for rec in records):
        # Not fatal: the guest script owns that probe's URL, and a script that changed it is
        # not a containment finding. Worth a line, because this is the record that ties the
        # guest's `[OKAY] 0` to the proxy verify itself started.
        console.say(f"note: no audit record names {_VERIFY_CONTROL_HOST} — control 0's probe host "
                    "is not the one this oracle expects, so only the remaining records tie the "
                    "guest to this proxy")
    if _VERIFY_SENTINEL in text:
        problems.append(("observed",
                         f"the host's sentinel credential appears in {log_path} — the audit "
                         "trail is written where operators read it, and an injected value must "
                         "never be part of it"))
    decisions = {}
    for rec in records:
        decisions[rec["decision"]] = decisions.get(rec["decision"], 0) + 1
    counted = ", ".join(f"{n} {d}" for d, n in sorted(decisions.items()))
    return problems, (f"audit: {counted} in {log_path.name}" if not problems
                      else f"audit: {len(problems)} problem(s) in {log_path.name}")


def _await_audit(log_path, expectations, timeout=3.0):
    """The log's text once every expectation matches, or after `timeout` — mitmproxy logs
    through a StreamHandler, which flushes per record, but a decision made microseconds before
    the guest exited should not read as a missing one. The verdict is _audit_problems'; this
    only decides when to stop waiting for it."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            text = log_path.read_text(errors="replace")
        except OSError as e:
            # No skip condition here, deliberately: the log is the host's half of the verdict,
            # and a run that cannot read it has no more evidence than the guest's word.
            console.die(f"cannot read the audit log {log_path} ({e.strerror}) — the run's own "
                        "record is what the guest's verdict has to agree with, so nothing here is "
                        "proven")
        records = _audit_records(text)
        settled = (records and not _audit_missing(records, expectations)
                   and any(rec["decision"] == "deny" for rec in records))
        if settled or time.monotonic() >= deadline:
            return text
        time.sleep(0.2)


_CHECK_LINE_RE = re.compile(r"\[(PASS|FAIL|SKIP)\]\s+(\d+)\.")


def _check_outcomes(lines):
    """{check id: 'PASS'|'FAIL'|'SKIP'} from the guest's own per-check lines.

    The per-check outcome, which the CHECKS/RESULT pair does not carry, and which the negative
    control needs: whether a *named* check failed where it should. Last line per id wins.
    """
    outcomes = {}
    for line in lines:
        m = _CHECK_LINE_RE.search(line)
        if m:
            outcomes[int(m[2])] = m[1]
    return outcomes


_NEGATIVE_CONTROL_CHECK = 3        # direct TCP to a live public service: what `allow` opens


def _negative_control_problem(contained, leaky):
    """(problem or None, summary) for the same script run in a guest that really leaks.

    Check 3 must fail there, by name, not by count: an msb that accepted `allow` and still
    enforced deny would pass every check in both guests, which must not read as "the checks
    work". Checks that passed in both guests are listed, not judged: the proxy-path ones
    should.
    """
    got = leaky.get(_NEGATIVE_CONTROL_CHECK, "no line")
    if got != "FAIL":
        return (f"the negative control established no leak: check {_NEGATIVE_CONTROL_CHECK} "
                f"reported {got} in the guest whose egress was left open, and that check is a "
                "direct connect to a live public service. Either msb no longer honours "
                "--net-default-egress allow or the probe cannot succeed on this host — either "
                "way nothing here shows the blocked-direction checks capable of failing, so "
                "this run draws no conclusion from them", None)
    both = sorted(i for i, outcome in leaky.items()
                  if outcome == "PASS" and contained.get(i) == "PASS")
    summary = (f"negative control: check {_NEGATIVE_CONTROL_CHECK} FAILED in the leaking guest"
               + (f"; checks {_ids(both)} passed in both guests" if both else
                  "; no check passed in both guests"))
    return None, summary


class _VerifyOracles:
    """The host-side half of one verify run: ports bound here, evidence read here.

    Built before the proxy, whose ruleset needs the recorder's port, and whose ports must be
    free first. Closed before the leaky guest boots, which may legitimately reach the
    observer.
    """

    def __init__(self, proxy_port):
        # The observer takes the port beside the proxy's deliberately: check 10 already probes
        # exactly that port from inside the guest and expects a refusal, so the host is now
        # watching the port the guest pokes — they agree, or the disagreement is the finding.
        self.proxy_port = proxy_port
        self.observer = _ArrivalObserver(_oracle_port(proxy_port, 1))
        try:
            self.recorder = _HeaderRecorder(_oracle_port(proxy_port, 2))
        except BaseException:                  # incl. SystemExit from die()
            self.observer.close()
            raise
        # The proxy inherits this process's environment, and SecretStore reads SILKGATE_EGRESS_SECRET_*
        # for the unscoped (single-ruleset) proxy verify starts. The value is the sentinel, so
        # what this fixture spends is never a credential.
        os.environ[f"SILKGATE_EGRESS_SECRET_{_VERIFY_SECRET_NAME.upper()}"] = \
            f"{_VERIFY_AUTH_HEADER}: {_VERIFY_SENTINEL}"

    def rules(self):
        return self.recorder.rules()

    def arm(self):
        """Prove the observer functional before anything is allowed to conclude from silence."""
        self.observer.self_test()

    def probe(self, sandbox):
        """Run the guest's half in `sandbox`, before the check script: check 7 changes the
        guest's routing and never restores it, so probes that run after it are measuring a
        network the script broke."""
        lines = []
        script = _oracle_guest_script(proxy_port=self.proxy_port,
                                      observer_port=self.observer.port,
                                      recorder_port=self.recorder.port,
                                      token=self.observer.guest_token)
        core.run_guest(lambda cmd: core.msb_exec_argv(sandbox, cmd), ["bash", "-c", script],
                       tty=False, on_line=lines.append)
        self.observer.drain()
        return _oracle_report(lines)

    def expectations(self):
        return _audit_expectations(full=False, recorder_port=self.recorder.port)

    def problems(self, report):
        """(problems, summaries) from the observer, the recorder and the guest's own report."""
        problems, summaries = [], []
        for found, summary in (
            _probe_problems(report, observer_port=self.observer.port),
            _observer_problems(self.observer.arrivals, bound=self.observer.bound(),
                               self_token=self.observer.self_token,
                               guest_token=self.observer.guest_token,
                               port=self.observer.port, proxy_port=self.proxy_port),
            _recorder_problems(self.recorder.records, token=self.observer.guest_token,
                               port=self.recorder.port),
        ):
            problems += found
            summaries.append(summary)
        return problems, summaries

    def close(self):
        self.observer.close()
        self.recorder.close()


def _oracle_die(problems, log_path):
    """Refuse the run, with the loudest framing the problems justify.

    "observed" means the host saw enforcement fail, which outranks what the guest said.
    "unproven" means an oracle can't be trusted, and must not read as a boundary failure:
    the fault is in the audit path, the ruleset, or which proxy the guest reached.
    """
    observed = [text for kind, text in problems if kind == "observed"]
    unproven = [text for kind, text in problems if kind == "unproven"]
    lines = []
    if observed:
        lines.append("CONTAINMENT FAILED OUTSIDE THE GUEST — the host itself saw this, so it "
                     "rests on nothing the guest printed:")
        lines += [f"  - {t}" for t in observed]
    if unproven:
        lines.append("  and the evidence for the rest is incomplete:" if observed else
                     "ORACLE UNPROVEN — the guest's checks passed and the host's own record of "
                     "the same run does not corroborate them. This is not a failed check: "
                     "suspect the audit path, the composed ruleset, or which proxy the guest "
                     "reached.")
        lines += [f"  - {t}" for t in unproven]
    lines.append(f"audit log: {log_path}")
    console.die("\n".join(lines))


def _verify_port(port):
    """The proxy port for one verify run: --port as given (a taken one fails, never moves),
    else the base of the first free POOL_SIZE range. Verify needs three ports, the proxy's
    and the two oracles' after it, and the pool scan proves them free. It also skips past a
    shared proxy's pool, so verify never contends with live sessions."""
    return port if port is not None else core._find_free_pool(core.DEFAULT_BASE_PORT)[0]


def cmd_verify(args):
    console.preflight("msb", "mitmdump")
    args.port = _verify_port(args.port)
    _reap_leaked_verify_guests()
    rules_text = core.compose_rules(core.resolve_profiles(["probe"], allow_verify_only=True))
    oracles = _VerifyOracles(args.port) if args.oracles else None
    if oracles:
        rules_text += oracles.rules()
    core.load_ruleset(rules_text)
    script = "bash /mnt/poc/test/verify_guest.sh"
    mounts = [f"{paths.REPO}:/mnt/poc:ro"]
    if args.full:
        mounts.append(f"{core.ensure_ca().parent}:/mnt/ca:ro")
        script = FULL_SETUP + script

    # The same relay as every guest command: msb streams live only with a terminal, and a
    # real one would make everything inside format for a screen. msb gets a PTY, the command
    # pipes. The parse below then reads the same cleaned text a human sees.
    found, lines, report = {}, [], {}

    def note(text):
        lines.append(text)
        m = re.search(r"RESULT: (\d+) passed, (\d+) failed", text)
        if m:
            found["result"] = (int(m[1]), int(m[2]))
        if "CHECKS: ran=" in text:
            found["checks"] = _parse_checks(text)

    guests, proxy = set(), None
    try:
        proxy, log_path = core.start_proxy(rules_text, args.port)
        console.say(f"proxy :{args.port} · audit: tail -f {log_path}")
        guest = _verify_guest_name("main")
        with core._guarded_terminal():
            _create_verify_guest(guest, args.port, mounts=mounts)
            guests.add(guest)
            if oracles:
                oracles.arm()
                report = oracles.probe(guest)
            core.run_guest(lambda cmd: core.msb_exec_argv(guest, cmd), ["bash", "-c", script],
                           tty=False, on_line=note)
        _drop_verify_guest(guest, guests)      # nothing waits on it; the finally re-tries

        result, checks = found.get("result"), found.get("checks")
        if result is None:
            console.die("no RESULT line — the guest never ran verify_guest.sh "
                        "(msb server started?)")
        if checks is None:
            console.die("no CHECKS line — the guest did not report which checks ran, so nothing "
                        "is "
                        "proven")
        passed, failed = result
        ran, skipped, unavailable = checks
        bad = _verify_shortfall(passed, failed, ran, skipped, unavailable, full=args.full)
        if bad:
            console.die(bad)

        # The guest's own verdict holds. Now the host's record of the same run, which is the
        # half no guest can write.
        expect = _audit_expectations(full=args.full,
                                     recorder_port=oracles.recorder.port if oracles else None)
        problems, summaries = [], []
        if oracles:
            problems, summaries = oracles.problems(report)
        audit_problems, audit_summary = _audit_problems(
            _await_audit(log_path, expect), expect, log_path=log_path)
        problems += audit_problems
        summaries.append(audit_summary)
        if problems:
            _oracle_die(problems, log_path)
        if oracles:
            oracles.close()                    # before any guest with open egress exists

        if args.negative_control:
            leaky = _verify_guest_name("leaky")
            console.say("negative control: booting a second guest with --net-default-egress "
                        "allow, "
                        "the setting that actually opens egress")
            leaky_lines = []
            with core._guarded_terminal():
                _create_verify_guest(leaky, args.port, mounts=mounts, leaky=True,
                                     why=" — the control did not run, so this verify says "
                                         "nothing about whether its checks can fail")
                guests.add(leaky)
                core.run_guest(lambda cmd: core.msb_exec_argv(leaky, cmd), ["bash", "-c", script],
                               tty=False, on_line=leaky_lines.append)
            _drop_verify_guest(leaky, guests)
            problem, summary = _negative_control_problem(_check_outcomes(lines),
                                                         _check_outcomes(leaky_lines))
            if problem:
                console.die(problem)
            summaries.append(summary)

        left = sorted(guests)
        if left:
            console.die(f"verify guest(s) {', '.join(left)} could not be removed — each still "
                        "holds a Tier-1 rule and a port allowance, and the next verify collides "
                        f"with proxy port {args.port}. `msb stop NAME && msb rm NAME`, then "
                        "re-run")
        for summary in summaries:
            console.say(summary)
        # _verify_shortfall already refused any unavailable id without a declared subject,
        # so the lookup below cannot miss; the guest's [UNAV] lines above carry the detail.
        absent = ", ".join(sorted({_VERIFY_SUBJECTS[i] for i in unavailable}))
        console.say(f"containment holds ({passed} passed, 0 failed; checks {_ids(ran)} ran; "
                    + (f"checks {_ids(unavailable)} had no subject — this guest has no {absent}, "
                       "see their [UNAV] lines; " if unavailable else "")
                    + ("host-side oracles agree" if oracles else "host-side oracles skipped")
                    + ")")
    finally:
        if proxy is not None:
            core.stop(proxy)
        if oracles:
            oracles.close()
        for name in sorted(guests):
            if not core._remove_sandbox(name):
                console.say(f"could not remove verify guest {name} — `msb stop {name} && msb rm "
                            f"{name}` by hand; it holds a Tier-1 rule and a port allowance")
