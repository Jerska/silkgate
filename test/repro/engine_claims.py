#!/usr/bin/env python3
"""Parsing and matching claims about rule_engine.py. Each line prints observed vs
expected, and the script exits nonzero on any mismatch.

None of these is exploitable on its own; they are the kind of small disagreement between a
rule and the world that the threat model names as the likeliest way the proxy gets broken,
so each is also a case in rule_engine.py's own self-tests. This is the standalone repro.

    python3 test/repro/engine_claims.py
"""
import contextlib
import io
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "mitmaddon"))
from rule_engine import RuleSet, _parse_ports, _parse_size, normalize_host  # noqa: E402

fails = 0


def show(label, observed, expected):
    global fails
    ok = observed == expected
    fails += 0 if ok else 1
    print(f"{'  ' if ok else '!!'} {label}\n     observed={observed!r}  expected={expected!r}")


def outcome(fn, *args):
    """The return value, or 'ValueError' if that is what the call raises."""
    try:
        return fn(*args)
    except ValueError:
        return "ValueError"


# doc/DSL.md step 1 rejects a host containing CR/LF; stripping whitespace first would
# launder it into a valid host.
show("normalize_host('github.com\\n') — DSL.md says reject",
     normalize_host("github.com\n"), None)

# Path patterns anchor with \Z: '$' also matches just before a trailing newline, so a
# path with a smuggled newline would satisfy a rule that was written to be exact.
show("path '/your-org/repo\\n' vs rule 'github.com/your-org/repo' — must not match",
     RuleSet.parse("github.com/your-org/repo GET").match(
         "github.com", "/your-org/repo\n", "GET") is not None, False)

# A negative size would make `body_len > max_body` true for every request, so the rule
# would deny everything with "body 0B > max_body -5B" instead of failing at parse time.
show("_parse_size('-5') — raises", outcome(_parse_size, "-5"), "ValueError")

# A port outside 1..65535 would parse into a rule that can never match — which reads as
# a granted permission in a ruleset a human reviews. Reject at parse time.
show("_parse_ports('99999999') — raises", outcome(_parse_ports, "99999999"), "ValueError")

# 'foo.com:443:8080' must not parse: with two independent port strippers (Rule.__init__
# and normalize_host both taking a port off the same string) it silently took ports={8080}.
show("'foo.com:443:8080/**' — raises",
     outcome(RuleSet.parse, "foo.com:443:8080/** GET"), "ValueError")

# A bare '**' host is a total allow-all. It stays legal — a deliberate opt-out — but
# parsing warns on stderr, which reaches both the CLI operator and mitmdump's log.
err = io.StringIO()
with contextlib.redirect_stderr(err):
    matched = RuleSet.parse("**/** GET POST h:* q:* max_body=100m").match(
        "evil.com", "/anything", "POST") is not None
show("'**/**' matches evil.com (an explicit opt-out stays legal)", matched, True)
show("'**/**' warns on stderr at parse time", "WARNING" in err.getvalue(), True)

# ...whereas q:*/h:* on a *named* host is silent: it widens an already-chosen
# destination, and the claude profile carries it on every session — a warning there
# would only train operators to ignore the channel.
err = io.StringIO()
with contextlib.redirect_stderr(err):
    RuleSet.parse("api.anthropic.com/** GET POST q:* h:* max_body=10m")
show("named host with q:*/h:* does not warn", err.getvalue(), "")

sys.exit(1 if fails else 0)
