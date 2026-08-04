#!/usr/bin/env python3
"""Parsing and matching defects in rule_engine.py. Each line prints observed vs expected.

None of these is exploitable on its own; they are the kind of small disagreement between a
rule and the world that the threat model names as the likeliest way the proxy gets broken, so
they belong in rule_engine.py's own self-tests rather than here.

    python3 test/repro/engine_claims.py
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "mitmaddon"))
from rule_engine import RuleSet, _parse_ports, _parse_size, normalize_host  # noqa: E402


def show(label, observed, expected):
    flag = "  " if observed == expected else "!!"
    print(f"{flag} {label}\n     observed={observed!r}  expected={expected!r}")


# doc/DSL.md says a host containing CR/LF is rejected; normalize_host strips before checking.
show("normalize_host('github.com\\n') — DSL.md says reject",
     normalize_host("github.com\n"), None)

# '$' in a compiled path pattern also matches just before a trailing newline, so a path with a
# smuggled newline satisfies a rule that was written to be exact.
show("path '/your-org/repo\\n' vs rule 'github.com/your-org/repo' — should not match",
     RuleSet.parse("github.com/your-org/repo GET").match(
         "github.com", "/your-org/repo\n", "GET") is not None, False)

# A negative size parses, and then `body_len > max_body` is true for every request, so the rule
# denies everything with "body 0B > max_body -5B" instead of failing at parse time.
show("_parse_size('-5') — should raise", _parse_size("-5"), "ValueError")

# Ports outside 1..65535 parse into a rule that can never match.
show("_parse_ports('99999999') — should raise", _parse_ports("99999999"), "ValueError")

# A bare '**' host pattern is a total allow-all: one --rule opts out of the whole product.
# Arguably legal, but it should be loud rather than silent.
show("'**/**' matches evil.com — should at least warn",
     RuleSet.parse("**/** GET POST h:* q:* max_body=100m").match(
         "evil.com", "/anything", "POST") is not None, "a warning at compose time")

print("\nAlso worth a rule: `foo.com:443:8080/** GET` parses, taking ports={8080}, because both")
print("Rule.__init__ and normalize_host strip a port from the same string.")
show("'foo.com:443:8080/**' ports", sorted(RuleSet.parse("foo.com:443:8080/** GET").rules[0].ports),
     "ValueError")
