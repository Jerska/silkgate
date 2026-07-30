#!/usr/bin/env python3
r"""Egress allowlist rule engine — dependency-free.

Default-deny. One allow-rule per line:

    <host>[/<path>]   [METHOD ...]   [option ...]

Host globs (before the first '/'):   *  -> [^.]+   **  -> .*   **. -> (?:.*\.)?  (apex)
Path globs (after the first '/'):    *  -> [^/]+   **  -> .*
A pattern with no '/' matches any path.

Options (space-separated, after the pattern):
    GET POST ...        allowed methods                    (default: GET only)
    max_body=<size>     permit a request body up to <size> (default: none; bytes, k/m suffix)
    query               permit a query string              (default: forbidden)
    h:<name>=<value>    forward header only if value == <value>   (exact)
    h:<name>~<regex>    forward header only if regex fullmatches  (no spaces; use \s)
    inject_auth=<name>  set auth header from EGRESS_SECRET_<NAME>

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
"""

import ipaddress
import posixpath
import re
from urllib.parse import unquote

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

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
    h = raw.strip()
    if any(c in h for c in _HOST_BAD_CHARS):
        return None
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
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def _compile_path(glob):
    out, i = [], 0
    while i < len(glob):
        if glob[i:i + 2] == "**":
            out.append(r".*"); i += 2
        elif glob[i] == "*":
            out.append(r"[^/]+"); i += 1
        else:
            out.append(re.escape(glob[i])); i += 1
    return re.compile("^" + "".join(out) + "$")


def _parse_size(s):
    s = s.strip().lower()
    if s.endswith("k"):
        return int(s[:-1]) * 1024
    if s.endswith("m"):
        return int(s[:-1]) * 1024 * 1024
    return int(s)


def _parse_ports(spec):
    """'' -> {80, 443} (default); '*' -> None (any); 'N[,M...]' -> frozenset of ints."""
    if spec == "":
        return frozenset((80, 443))
    if spec == "*":
        return None
    try:
        return frozenset(int(p) for p in spec.split(","))
    except ValueError:
        raise ValueError(f"bad port spec: {spec!r}") from None


# Default header policy: name -> constraint. ("any",) | ("exact", v) | ("re", compiled)
# fullmatch semantics for "re". Values are capped to shrink the residual channel.
_BASELINE_SPECS = {
    # Minimal structural baseline only. `host` is the (already-allowlisted) destination, not a
    # channel; content-type/length are needed for request bodies. accept, accept-encoding,
    # accept-language, user-agent, range are NOT baseline — opt in per rule via `h:`.
    "host":            ("re", r"[A-Za-z0-9.:-]{1,253}"),
    "content-type":    ("re", r"[A-Za-z0-9.+/=; -]{1,64}"),
    "content-length":  ("re", r"\d{1,10}"),
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
                 "allow_query", "query_params", "allow_all_headers", "headers", "inject_auth")

    def __init__(self, raw):
        tokens = raw.split()
        if not tokens:
            raise ValueError("empty rule")
        host, slash, path = tokens[0].partition("/")
        port_spec = ""
        if ":" in host:
            host, _, port_spec = host.rpartition(":")
        norm = normalize_host(host, allow_glob=True)
        if norm is None:
            raise ValueError(f"invalid host pattern: {host!r}")
        self.raw = raw
        self.host_re = _compile_host(norm)
        self.ports = _parse_ports(port_spec)                    # frozenset, or None for any
        self.path_re = _compile_path(path) if slash else None  # None => any path
        self.methods = set()
        self.max_body = 0
        self.allow_query = False
        self.query_params = {}                                  # name -> constraint (case-sensitive)
        self.allow_all_headers = False
        self.headers = dict(_BASELINE)                          # per-rule overrides merge on top
        self.inject_auth = None
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
                and self.host_re.match(host) is not None
                and (self.path_re is None or self.path_re.match(path) is not None))

    def header_ok(self, name, value):
        return self.allow_all_headers or _constraint_ok(self.headers.get(name.lower()), value)

    def query_ok(self, name, value):
        return self.allow_query or _constraint_ok(self.query_params.get(name), value)


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
                rules.append(Rule(line))
            except (ValueError, re.error) as e:
                raise ValueError(f"rules:{n}: {e}") from None
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
]


def _selftest():
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
    total = (len(_MATCH_CASES) + len(_HOST_CASES) + len(_HEADER_CASES)
             + len(_QUERY_CASES) + len(_PORT_CASES))
    print(f"{total - fails}/{total} passed")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    _selftest()
