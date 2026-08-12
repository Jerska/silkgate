#!/usr/bin/env python3
r"""Egress allowlist rule engine — dependency-free.

Default-deny. One allow-rule per line:

    <host>[:<port>][/<path>]   [METHOD ...]   [option ...]

Host globs (before the first '/'):   *  -> [^.]+   **  -> .*   **. -> (?:.*\.)?  (apex)
Path globs (after the first '/'):    *  -> [^/]+   **  -> .*
A pattern with no '/' matches any path. No ':<port>' means 80 and 443 only;
':*' means any port; ':N[,M...]' means exactly those ports.

Options (space-separated, after the pattern):
    GET POST ...        allowed methods                    (default: GET only)
    max_body=<size>     permit a request body up to <size> (default: none; bytes, k/m suffix)
    q:*                 allow all query params             (default: stripped)
    q:<name>=<value>    keep query param only if value == <value>;  others stripped
    q:<name>~<regex>    keep query param only if regex fullmatches; others stripped
    h:*                 allow all request headers          (default: baseline only)
    h:<name>=<value>    forward header only if value == <value>   (exact)
    h:<name>~<regex>    forward header only if regex fullmatches  (no spaces; use \s)
    inject_auth=<name>  set auth header from SILKGATE_EGRESS_SECRET_<NAME>
    capture=<format>    decode and record the response body       (formats: anthropic)

Security model:
  * The allowlist bounds *capability/blast-radius* (host+path+method), NOT exfil
    bandwidth. Any allowed destination is an exfil carrier; that is mitigated by
    rule discipline + volume/content limits, not by glob breadth.
  * Hosts and paths are normalized here (not in the proxy) so it cannot be skipped,
    and the SAME normalizer is applied to both pattern and request.
  * Headers are deny-by-default: only the baseline + per-rule constraints pass,
    and a passing header must also satisfy a value constraint. Everything else is
    dropped by the proxy. Baseline values are capped/regex'd but remain a residual
    low-bandwidth channel; pin exact per rule for a stricter posture.
  * Malformed rules (negative sizes, out-of-range or doubled ports) raise
    ValueError at parse time — an unmatchable rule reads as a granted permission
    in a ruleset a human reviews. A host pattern that is all wildcards is legal
    but warned about on stderr: it matches every destination.
"""

import ipaddress
import posixpath
import re
import sys
from urllib.parse import unquote

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

# The closed set of response decoders the proxy addon implements. Validated at parse
# time so a rules file naming a format no decoder exists for is refused before it can
# pretend to record.
CAPTURE_FORMATS = frozenset({"anthropic"})

# --- secret parser: "<Header>: <value>" ----------------------------------------
# Shared with cli/silkgate so launch-time validation uses the exact same rules as
# the proxy's runtime enforcement.  Kept stdlib-only so rule_engine stays importable
# everywhere without mitmproxy.

# A header name must be an RFC 9110 token: no spaces, no special chars beyond the set
# below; max 64 chars is generous and caps the residual channel.
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
# Routing/framing headers must never be rewritten by secret injection: rewriting Host
# would front another vhost behind an allowlisted destination; the others control
# framing (smuggling vector) or connection lifecycle.
_ROUTING_HEADERS = frozenset({"host", "content-length", "transfer-encoding",
                               "connection", "upgrade"})
_MAX_SECRET = 4096


def _parse_secret(value):
    """Split a "<Header>: <value>" secret into (header, value), or None if unusable.

    Rejected: a header name outside the token charset or naming a routing/framing
    header, a value that is empty or carries anything but printable ASCII (a CR/LF
    would inject a header of the guest's choosing into the upstream request), and
    anything over _MAX_SECRET bytes.
    """
    if not isinstance(value, str) or not value or len(value) > _MAX_SECRET:
        return None
    name, sep, val = value.partition(":")
    if not sep:
        return None
    name, val = name.strip(), val.strip()
    if not _HEADER_TOKEN.fullmatch(name) or name.lower() in _ROUTING_HEADERS:
        return None
    if not val or not all(0x20 <= ord(c) <= 0x7e for c in val):
        return None
    return name, val

# Underscore is invalid in public DNS (RFC 1123); excluded by default. A
# deployment targeting internal/service names can add it to these two patterns.
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_HOST_STRICT = re.compile(rf"^{_HOST_LABEL}(?:\.{_HOST_LABEL})*$")
_HOST_GLOB_CHARS = re.compile(r"^[a-z0-9.*-]+$")
_HOST_BAD_CHARS = "\x00 \t\r\n%@[]"


def normalize_host(raw, allow_glob=False):
    """Canonical ASCII host, or None if it must be rejected.

    allow_glob=True is for rule patterns (permits '*'/'**'); False is the strict
    path for request hosts — this is the null-byte / homograph / IP-literal guard.
    """
    if raw is None:
        return None
    h = raw
    if any(c in h for c in _HOST_BAD_CHARS):   # on the input as received: stripping
        return None                            # first would launder 'github.com\n'
    if ":" in h:                                   # strip + validate optional port
        h, _, port = h.rpartition(":")
        if not port.isdigit():
            return None
    h = h.lower().rstrip(".")
    if not h or not h.isascii():                   # force punycode -> kills homographs
        return None
    try:                                           # reject raw IP literals
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    if allow_glob:
        return h if _HOST_GLOB_CHARS.match(h) else None
    if not _HOST_STRICT.match(h):
        return None
    if len(h) > 253 or any(len(label) > 63 for label in h.split(".")):
        return None
    return h


def normalize_path(raw):
    """Decode and resolve '.'/'..' so path-scoped rules can't be slipped."""
    p = raw.split("#", 1)[0].split("?", 1)[0]
    p = unquote(p)
    norm = posixpath.normpath(p)
    return "/" if norm == "." else norm


def _compile_host(glob):
    out, i = [], 0
    while i < len(glob):
        if glob[i:i + 3] == "**.":
            out.append(r"(?:.*\.)?"); i += 3
        elif glob[i:i + 2] == "**":
            out.append(r".*"); i += 2
        elif glob[i] == "*":
            out.append(r"[^.]+"); i += 1
        else:
            out.append(re.escape(glob[i])); i += 1
    # \Z, not $: '$' also matches just before a trailing newline
    return re.compile("^" + "".join(out) + r"\Z", re.IGNORECASE)


def _compile_path(glob):
    out, i = [], 0
    while i < len(glob):
        if glob[i:i + 2] == "**":
            out.append(r".*"); i += 2
        elif glob[i] == "*":
            out.append(r"[^/]+"); i += 1
        else:
            out.append(re.escape(glob[i])); i += 1
    return re.compile("^" + "".join(out) + r"\Z")


def _parse_size(s):
    t = s.strip().lower()
    mult = 1
    if t.endswith("k"):
        t, mult = t[:-1], 1024
    elif t.endswith("m"):
        t, mult = t[:-1], 1024 * 1024
    if not re.fullmatch(r"[0-9]+", t):         # digits only: no sign, no '', no '1_0'
        raise ValueError(f"bad size: {s!r}")
    return int(t) * mult


def _parse_ports(spec):
    """'' -> {80, 443} (default); '*' -> None (any); 'N[,M...]' -> frozenset of ints."""
    if spec == "":
        return frozenset((80, 443))
    if spec == "*":
        return None
    ports = set()
    for p in spec.split(","):
        if not re.fullmatch(r"[0-9]+", p) or not 1 <= int(p) <= 65535:
            raise ValueError(f"bad port spec: {spec!r}")
        ports.add(int(p))
    return frozenset(ports)


# Default header policy: name -> constraint. ("any",) | ("exact", v) | ("re", compiled)
# fullmatch semantics for "re". Values are capped to shrink the residual channel.
_BASELINE_SPECS = {
    # Minimal structural baseline only. `host` is the (already-allowlisted) destination, not a
    # channel; content-type/length are needed for request bodies, and transfer-encoding is the
    # other legal body framing — stripping it narrows nothing and un-frames the body: the proxy
    # buffers the request either way, but a chunked upload whose header was dropped goes
    # upstream with no framing at all (a `git push` over http.postBuffer dies exactly there).
    # Only the one value bodies actually use is baseline; anything else stays deniable. accept,
    # accept-encoding, accept-language, user-agent, range are NOT baseline — opt in per rule
    # via `h:`.
    "host":              ("re", r"[A-Za-z0-9.:-]{1,253}"),
    "content-type":      ("re", r"[A-Za-z0-9.+/=; -]{1,64}"),
    "content-length":    ("re", r"\d{1,10}"),
    "transfer-encoding": ("exact", "chunked"),
}


def _compile_constraint(spec):
    if spec[0] == "re":
        return ("re", re.compile(spec[1]))
    return spec


_BASELINE = {name: _compile_constraint(spec) for name, spec in _BASELINE_SPECS.items()}


def _constraint_ok(constraint, value):
    if constraint is None:
        return False
    kind = constraint[0]
    if kind == "any":
        return True
    if kind == "exact":
        return value == constraint[1]
    return constraint[1].fullmatch(value) is not None


class Rule:
    __slots__ = ("raw", "host_re", "ports", "path_re", "methods", "max_body",
                 "allow_query", "query_params", "allow_all_headers", "headers", "inject_auth",
                 "capture", "wildcard_only_host")

    def __init__(self, raw):
        tokens = raw.split()
        if not tokens:
            raise ValueError("empty rule")
        host, slash, path = tokens[0].partition("/")
        # Split host:port at the FIRST colon so the whole port spec is validated in
        # one place; a second stripper downstream would let 'foo.com:443:8080' pass.
        host, _, port_spec = host.partition(":")
        norm = normalize_host(host, allow_glob=True)
        if norm is None:
            raise ValueError(f"invalid host pattern: {host!r}")
        self.raw = raw
        self.host_re = _compile_host(norm)
        # A host glob with no literal character ('**', '*', '*.*') names no
        # destination at all; RuleSet.parse warns about it on stderr.
        self.wildcard_only_host = set(norm) <= {"*", "."}
        self.ports = _parse_ports(port_spec)                    # frozenset, or None for any
        self.path_re = _compile_path(path) if slash else None  # None => any path
        self.methods = set()
        self.max_body = 0
        self.allow_query = False
        self.query_params = {}                                  # name -> constraint (case-sensitive)
        self.allow_all_headers = False
        self.headers = dict(_BASELINE)                          # per-rule overrides merge on top
        self.inject_auth = None
        self.capture = None
        for t in tokens[1:]:
            if t in HTTP_METHODS:
                self.methods.add(t)
            elif t == "q:*":
                self.allow_query = True
            elif t == "h:*":
                self.allow_all_headers = True
            elif t.startswith("h:"):
                self._add_header(t[2:])
            elif t.startswith("q:"):
                self._add_query(t[2:])
            elif "=" in t:
                k, v = t.split("=", 1)
                if k == "max_body":
                    self.max_body = _parse_size(v)
                elif k == "inject_auth":
                    self.inject_auth = v
                elif k == "capture":
                    # A format naming no decoder is refused at parse time, like a bad
                    # port: a rule that promises capture and records nothing reads as
                    # observability granted in a ruleset a human reviews.
                    if v not in CAPTURE_FORMATS:
                        raise ValueError(f"unknown capture format: {v!r}")
                    self.capture = v
                else:
                    raise ValueError(f"unknown option: {t!r}")
            else:
                raise ValueError(f"unknown token: {t!r}")
        if not self.methods:
            self.methods = {"GET"}

    def _add_header(self, body):
        m = re.search(r"[=~]", body)
        if not m:
            raise ValueError(f"bad header constraint: h:{body!r}")
        name, sep, val = body[:m.start()].lower(), body[m.start()], body[m.start() + 1:]
        if not name:
            raise ValueError(f"bad header constraint: h:{body!r}")
        self.headers[name] = ("exact", val) if sep == "=" else ("re", re.compile(val))

    def _add_query(self, body):
        m = re.search(r"[=~]", body)
        if not m:
            raise ValueError(f"bad query constraint: q:{body!r}")
        name, sep, val = body[:m.start()], body[m.start()], body[m.start() + 1:]
        if not name:
            raise ValueError(f"bad query constraint: q:{body!r}")
        self.query_params[name] = ("exact", val) if sep == "=" else ("re", re.compile(val))

    def matches(self, host, path, method, port=443):
        return (method in self.methods
                and (self.ports is None or port in self.ports)
                and self.host_re.fullmatch(host) is not None
                and (self.path_re is None or self.path_re.fullmatch(path) is not None))

    def header_ok(self, name, value):
        return self.allow_all_headers or _constraint_ok(self.headers.get(name.lower()), value)

    def query_ok(self, name, value):
        return self.allow_query or _constraint_ok(self.query_params.get(name), value)


# --- self-test data for _parse_secret -----------------------------------------
_SECRET_GOOD = [
    ("x-api-key: sk-ant-123",      ("x-api-key", "sk-ant-123")),
    ("Authorization:Bearer abc",   ("Authorization", "Bearer abc")),
    ("X-Custom: val with spaces",  ("X-Custom", "val with spaces")),
]
_SECRET_BAD = [
    "no-colon",                          # no colon → no header name
    "x-api-key: ",                        # empty value after strip
    "Host: evil.example",                 # routing header
    "Content-Length: 0",                  # framing header
    "Transfer-Encoding: chunked",         # framing header
    "Upgrade: websocket",                 # lifecycle header
    "x api key: v",                       # space not a token char
    "x-api-key: a\r\nx-exfil: b",         # CRLF injection
    "x-api-key: a\x00b",                  # NUL
    "x-api-key: k\u00e9y",               # non-ASCII
    "x-api-key: " + "x" * _MAX_SECRET,   # over length limit
    None,                                 # wrong type
    42,                                   # wrong type
]

# A wildcard-only host warns rather than erroring: it is a deliberate opt-out an
# operator may want, but one they must see. stderr reaches both the CLI operator at
# compose time and mitmdump's log. q:*/h:* on a *named* host stay silent — they widen
# an already-chosen destination (an accepted Tier-3 residual, and the claude profile
# carries them on every session; warning there would train operators to ignore this
# channel). Warned once per rule text per process: the CLI parses the same ruleset
# more than once per command.
_WARNED_WILDCARD = set()


def _warn_wildcard_host(line, n):
    if line in _WARNED_WILDCARD:
        return
    _WARNED_WILDCARD.add(line)
    print(f"silkgate rules: WARNING: line {n}: {line!r} — the host pattern is all "
          "wildcards, so this rule matches every destination", file=sys.stderr)


class RuleSet:
    def __init__(self, rules):
        self.rules = rules

    @classmethod
    def parse(cls, text):
        rules = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                rule = Rule(line)
            except (ValueError, re.error) as e:
                raise ValueError(f"rules:{n}: {e}") from None
            if rule.wildcard_only_host:
                _warn_wildcard_host(line, n)
            rules.append(rule)
        return cls(rules)

    def match(self, host, path, method, port=443):
        """Return the first matching Rule, or None (= deny).

        `host` must already be normalized via normalize_host() by the caller, so
        a hostile host is rejected (and logged) distinctly from a clean miss.
        """
        p = normalize_path(path).lstrip("/")
        for r in self.rules:
            if r.matches(host, p, method, port):
                return r
        return None


# --- self-test: `python3 rule_engine.py` ------------------------------------

_MATCH_CASES = [
    ("*.github.com GET",  "api.github.com", "/",  "GET", True),
    ("*.github.com GET",  "github.com",     "/",  "GET", False),
    ("*.github.com GET",  "a.b.github.com", "/",  "GET", False),
    ("**.github.com GET", "github.com",     "/x", "GET", True),
    ("**.github.com GET", "api.github.com", "/x", "GET", True),
    ("**.github.com GET", "a.b.github.com", "/x", "GET", True),
    ("**.github.com GET", "notgithub.com",  "/x", "GET", False),
    ("registry.npmjs.org/**", "registry.npmjs.org", "/lodash/-/lodash-4.tgz", "GET",  True),
    ("registry.npmjs.org/**", "registry.npmjs.org", "/lodash",                "POST", False),
    ("api.anthropic.com/v1/messages POST", "api.anthropic.com", "/v1/messages", "POST", True),
    ("api.anthropic.com/v1/messages POST", "api.anthropic.com", "/v1/other",    "POST", False),
    ("files.pythonhosted.org", "files.pythonhosted.org", "/packages/x.whl", "GET", True),
    ("github.com/**", "github.com", "/", "GET", True),
    ("github.com/**", "github.com", "",  "GET", True),
    ("github.com/*/repo GET", "github.com", "/org/repo", "GET", True),
    ("github.com/*/repo GET", "github.com", "/a/b/repo", "GET", False),
    ("registry.npmjs.org/**", "evil.com", "/x", "GET", False),
    # path normalization: '..' and %2e cannot escape a path scope
    ("github.com/your-org/** GET", "github.com", "/your-org/repo",          "GET", True),
    ("github.com/your-org/** GET", "github.com", "/your-org/x/../../other", "GET", False),
    ("github.com/your-org/** GET", "github.com", "/your-org/%2e%2e/other",  "GET", False),
    # \Z anchoring: a smuggled trailing newline cannot satisfy an exact path rule
    ("github.com/your-org/repo GET", "github.com", "/your-org/repo\n", "GET", False),
    # an empty ruleset is legal and matches nothing (reach-nothing is a valid policy)
    ("", "evil.com", "/x", "GET", False),
]

_HOST_CASES = [
    ("GitHub.COM",            "github.com"),
    ("github.com.",           "github.com"),
    ("github.com:443",        "github.com"),
    ("evil\x00.github.com",   None),
    ("a..b.com",              None),
    ("xn--n3h.com",           "xn--n3h.com"),
    ("☃.com",            None),   # raw unicode (snowman) -> rejected
    ("1.2.3.4",               None),   # raw IPv4 -> rejected
    ("under_score.com",       None),   # underscore excluded by default
    ("-bad.com",              None),
    ("ok-host.example.com",   "ok-host.example.com"),
    ("github.com\n",          None),   # trailing CR/LF rejected, not stripped
    (" github.com",           None),   # leading whitespace rejected, not stripped
]

_HEADER_RULE = ("api.anthropic.com/v1/messages POST "
                "h:anthropic-version=2023-06-01 inject_auth=anthropic")
_HEADER_CASES = [
    (_HEADER_RULE, "anthropic-version", "2023-06-01",       True),   # exact
    (_HEADER_RULE, "anthropic-version", "2099-01-01",       False),  # exact mismatch
    (_HEADER_RULE, "cookie",            "session=abc",       False),  # not in policy
    (_HEADER_RULE, "x-exfil",           "stolen",            False),  # arbitrary header
    (_HEADER_RULE, "accept",            "application/json",  False),  # not baseline -> stripped
    (_HEADER_RULE, "content-type",      "application/json",  True),   # baseline
    (_HEADER_RULE, "content-type",      "a" * 65,            False),  # exceeds 64-char cap
    (_HEADER_RULE, "transfer-encoding", "chunked",           True),   # baseline: body framing
    (_HEADER_RULE, "transfer-encoding", "gzip, chunked",     False),  # only the value git sends
    (r"registry.npmjs.org/** h:accept~application/(json|vnd\.npm.*)",
                   "accept", "application/vnd.npm.install-v1+json", True),
    (r"registry.npmjs.org/** h:accept~application/(json|vnd\.npm.*)",
                   "accept", "text/html",                    False),
    ("api.x.com/** GET h:*", "x-anything", "v", True),                  # h:* = allow all headers
    (r"api.x.com/** GET h:authorization~Bearer\s.+",
                   "authorization", "Bearer abc", True),                # authorization is allowlistable
]

_QUERY_RULE = r"api.anthropic.com/v1/** POST q:beta=true q:ver~v\d+ inject_auth=anthropic"
_QUERY_CASES = [
    (_QUERY_RULE, "beta", "true",  True),    # exact
    (_QUERY_RULE, "beta", "false", False),   # exact mismatch -> stripped
    (_QUERY_RULE, "ver",  "v2",    True),     # regex
    (_QUERY_RULE, "ver",  "x",     False),    # regex miss -> stripped
    (_QUERY_RULE, "evil", "data",  False),    # unlisted param -> stripped
    ("example.com/** GET q:*", "anything", "v", True),     # q:* = allow-all query
]

_PORT_CASES = [
    ("foo.com/** GET",      "foo.com", 443,  True),    # default allows 443
    ("foo.com/** GET",      "foo.com", 80,   True),    # default allows 80
    ("foo.com/** GET",      "foo.com", 8080, False),   # non-default port denied
    ("foo.com:8080/** GET", "foo.com", 8080, True),    # explicit port
    ("foo.com:8080/** GET", "foo.com", 443,  False),   # explicit port replaces the default
    ("foo.com:*/** GET",    "foo.com", 8080, True),    # :* = any port
    ("foo.com:65535/** GET", "foo.com", 65535, True),  # top of the valid range
]

# Malformed rules fail at parse time: an unmatchable rule would read as a granted
# permission in a ruleset a human reviews.
_PARSE_ERROR_CASES = [
    "a.com/** GET max_body=-5",     # negative size would deny every request
    "a.com:0/** GET",               # below the port range
    "a.com:65536/** GET",           # above the port range
    "a.com:99999999/** GET",        # far outside: an unmatchable rule
    "foo.com:443:8080/** GET",      # doubled port must not parse as ports={8080}
    "a.com/** GET capture=bogus",   # capture format outside the closed set
    "a.com/** GET capture=",        # empty capture format decodes nothing
]

# capture= names a decoder from CAPTURE_FORMATS; absent means no capture.
_CAPTURE_CASES = [
    ("api.anthropic.com/v1/messages POST capture=anthropic", "anthropic"),
    ("api.anthropic.com/v1/messages POST",                   None),
]

# A wildcard-only host pattern warns on stderr; q:*/h:* on a named host does not.
_WARN_CASES = [
    ("**/** GET POST h:* q:* max_body=100m", True),    # total allow-all
    ("**:* GET",                             True),    # any host, any port
    ("*.* GET",                              True),    # names no destination either
    ("**.github.com/** GET",                 False),   # broad, but bounded to a name
    ("api.anthropic.com/** GET POST q:* h:* max_body=10m inject_auth=anthropic", False),
]


def _selftest():
    import contextlib
    import io
    fails = 0
    for line, host, path, method, expected in _MATCH_CASES:
        got = RuleSet.parse(line).match(host, path, method) is not None
        if got != expected:
            fails += 1
            print(f"MATCH FAIL: {line!r}  {method} {host}{path}  want {expected} got {got}")
    for raw, expected in _HOST_CASES:
        got = normalize_host(raw)
        if got != expected:
            fails += 1
            print(f"HOST  FAIL: {raw!r}  want {expected!r} got {got!r}")
    for line, name, value, expected in _HEADER_CASES:
        got = RuleSet.parse(line).rules[0].header_ok(name, value)
        if got != expected:
            fails += 1
            print(f"HDR   FAIL: {line!r}  {name}: {value!r}  want {expected} got {got}")
    for line, name, value, expected in _QUERY_CASES:
        got = RuleSet.parse(line).rules[0].query_ok(name, value)
        if got != expected:
            fails += 1
            print(f"QRY   FAIL: {line!r}  {name}={value!r}  want {expected} got {got}")
    for line, host, port, expected in _PORT_CASES:
        got = RuleSet.parse(line).match(host, "/", "GET", port) is not None
        if got != expected:
            fails += 1
            print(f"PORT  FAIL: {line!r}  {host}:{port}  want {expected} got {got}")
    for line in _PARSE_ERROR_CASES:
        try:
            RuleSet.parse(line)
            fails += 1
            print(f"PARSE FAIL: {line!r}  want ValueError, got a rule")
        except ValueError:
            pass
    for line, expected in _CAPTURE_CASES:
        got = RuleSet.parse(line).rules[0].capture
        if got != expected:
            fails += 1
            print(f"CAPT  FAIL: {line!r}  want {expected!r} got {got!r}")
    for line, expected in _WARN_CASES:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            RuleSet.parse(line)
        got = "WARNING" in err.getvalue()
        if got != expected:
            fails += 1
            print(f"WARN  FAIL: {line!r}  want {expected} got {got}")
    for value, expected in _SECRET_GOOD:
        got = _parse_secret(value)
        if got != expected:
            fails += 1
            print(f"SECRET FAIL (good): {value!r}  want {expected!r} got {got!r}")
    for value in _SECRET_BAD:
        got = _parse_secret(value)
        if got is not None:
            fails += 1
            print(f"SECRET FAIL (bad):  {value!r}  want None got {got!r}")
    total = (len(_MATCH_CASES) + len(_HOST_CASES) + len(_HEADER_CASES)
             + len(_QUERY_CASES) + len(_PORT_CASES) + len(_PARSE_ERROR_CASES)
             + len(_CAPTURE_CASES) + len(_WARN_CASES) + len(_SECRET_GOOD)
             + len(_SECRET_BAD))
    print(f"{total - fails}/{total} passed")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    _selftest()
