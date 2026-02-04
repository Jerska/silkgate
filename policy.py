"""
Mitmproxy addon for HTTP method/path policy enforcement.
Parses the custom DSL from policy.txt.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from mitmproxy import http, tls, ctx


# Request logging
import os
if "SILKGATE_SESSION_DIR" not in os.environ:
    raise RuntimeError("SILKGATE_SESSION_DIR environment variable must be set")
SESSION_DIR = Path(os.environ["SILKGATE_SESSION_DIR"])
LOG_FILE = SESSION_DIR / "requests.log"


def log_request(allowed: bool, method: str, host: str, path: str, reason: str):
    """Log a request."""
    timestamp = datetime.now().isoformat(timespec="seconds")
    status = "ALLOW" if allowed else "BLOCK"
    line = f"{timestamp} {status} {method} {host}{path} | {reason}\n"
    with LOG_FILE.open("a") as f:
        f.write(line)


@dataclass
class Rule:
    """A single allow/deny rule."""
    action: str  # "allow" or "deny"
    method: str  # HTTP method or "*"
    path: str | None  # Path pattern or None for all paths

    def matches(self, method: str, path: str) -> bool:
        """Check if this rule matches the request."""
        # Check method
        if self.method != "*" and self.method.upper() != method.upper():
            return False

        # Check path
        if self.path is None:
            return True

        return self._path_matches(self.path, path)

    @staticmethod
    def _path_matches(pattern: str, path: str) -> bool:
        """Match path against glob pattern."""
        # Convert glob to regex
        regex = "^"
        i = 0
        while i < len(pattern):
            if pattern[i:i+2] == "**":
                regex += ".*"
                i += 2
            elif pattern[i] == "*":
                regex += "[^/]*"
                i += 1
            elif pattern[i] in ".+^${}[]|()":
                regex += "\\" + pattern[i]
                i += 1
            else:
                regex += pattern[i]
                i += 1
        regex += "$"

        return bool(re.match(regex, path))


@dataclass
class DomainBlock:
    """A domain with its rules."""
    pattern: str  # Domain pattern (may include wildcard prefix)
    rules: list[Rule] = field(default_factory=list)
    passthrough: bool = False  # Skip TLS inspection entirely

    def matches_domain(self, host: str) -> bool:
        """Check if host matches this domain pattern."""
        if self.pattern.startswith("*."):
            suffix = self.pattern[1:]  # e.g., ".github.com"
            base = self.pattern[2:]    # e.g., "github.com"
            return host.endswith(suffix) or host == base
        return host == self.pattern

    def check(self, method: str, path: str) -> tuple[bool, str]:
        """Check request against rules. Returns (allowed, reason)."""
        if self.passthrough:
            return True, "Passthrough domain"

        for rule in self.rules:
            if rule.matches(method, path):
                allowed = rule.action == "allow"
                reason = f"Rule: {rule.action} {rule.method}"
                if rule.path:
                    reason += f" {rule.path}"
                return allowed, reason

        # No rule matched - deny by default within a domain block
        return False, "No matching rule in domain block"


class Policy:
    """Parsed policy with evaluation logic."""

    def __init__(self):
        self.default_allow = False
        self.domains: list[DomainBlock] = []

    def is_passthrough(self, host: str) -> bool:
        """Check if a host should bypass TLS inspection."""
        for domain in self.domains:
            if domain.matches_domain(host) and domain.passthrough:
                return True
        return False

    def check(self, host: str, method: str, path: str) -> tuple[bool, str]:
        """Check if request is allowed. Returns (allowed, reason)."""
        # Find matching domain block
        for domain in self.domains:
            if domain.matches_domain(host):
                return domain.check(method, path)

        # No domain block - use global default
        if self.default_allow:
            return True, "No domain block, default allow"
        return False, f"Domain not in policy: {host}"


def parse_policy(content: str) -> Policy:
    """Parse the DSL into a Policy object."""
    policy = Policy()
    current_domain: DomainBlock | None = None

    for line_num, line in enumerate(content.split("\n"), 1):
        # Strip comments
        if "#" in line:
            line = line[:line.index("#")]

        stripped = line.strip()
        if not stripped:
            continue

        # Check indentation
        is_indented = line.startswith("  ") or line.startswith("\t")

        if not is_indented:
            # Top-level directive
            if stripped.startswith("default "):
                value = stripped[8:].strip().lower()
                policy.default_allow = value == "allow"

            elif stripped.endswith(":"):
                # New domain block with custom rules
                domain_pattern = stripped[:-1].strip()
                current_domain = DomainBlock(pattern=domain_pattern)
                policy.domains.append(current_domain)

            elif " passthrough" in stripped:
                # Passthrough domain
                domain_pattern = stripped.replace(" passthrough", "").strip()
                domain = DomainBlock(pattern=domain_pattern, passthrough=True)
                policy.domains.append(domain)
                current_domain = None  # No rules expected

            else:
                # Shorthand: domain alone means GET-only
                domain_pattern = stripped
                domain = DomainBlock(
                    pattern=domain_pattern,
                    rules=[Rule(action="allow", method="GET", path=None)]
                )
                policy.domains.append(domain)
                current_domain = None  # No rules expected

        else:
            # Indented rule - must be inside a domain block
            if current_domain is None:
                ctx.log.warn(f"Line {line_num}: Rule outside domain block: {stripped}")
                continue

            rule = parse_rule(stripped)
            if rule:
                current_domain.rules.append(rule)
            else:
                ctx.log.warn(f"Line {line_num}: Invalid rule: {stripped}")

    return policy


def parse_rule(text: str) -> Rule | None:
    """Parse a single rule line like 'allow GET /path/**'."""
    parts = text.split()

    if len(parts) < 2:
        return None

    action = parts[0].lower()
    if action not in ("allow", "deny"):
        return None

    method = parts[1].upper()

    path = parts[2] if len(parts) > 2 else None

    return Rule(action=action, method=method, path=path)


# Global policy instance
_policy: Policy | None = None


def load_policy() -> Policy:
    """Load policy from file."""
    global _policy

    policy_file = Path(__file__).parent / "policy.txt"

    if not policy_file.exists():
        ctx.log.error(f"Policy file not found: {policy_file}")
        return Policy()  # Empty policy = deny all

    content = policy_file.read_text()
    _policy = parse_policy(content)

    domain_count = len(_policy.domains)
    rule_count = sum(len(d.rules) for d in _policy.domains)
    passthrough_count = sum(1 for d in _policy.domains if d.passthrough)
    ctx.log.info(f"Loaded policy: {domain_count} domains, {rule_count} rules, {passthrough_count} passthrough")

    return _policy


def get_policy() -> Policy:
    """Get or load the policy."""
    global _policy
    if _policy is None:
        _policy = load_policy()
    return _policy


def tls_clienthello(data: tls.ClientHelloData) -> None:
    """Handle TLS handshake - check for passthrough domains."""
    policy = get_policy()

    # Get SNI hostname
    sni = data.client_hello.sni
    if sni and policy.is_passthrough(sni):
        ctx.log.info(f"⇄ PASSTHROUGH {sni}")
        data.ignore_connection = True


def touch_activity():
    """Update last_activity timestamp for the session."""
    activity_file = SESSION_DIR / "last_activity"
    activity_file.touch(exist_ok=True)


def request(flow: http.HTTPFlow) -> None:
    """Intercept and check each request."""
    policy = get_policy()

    host = flow.request.pretty_host
    method = flow.request.method
    path = flow.request.path

    # Update session activity
    touch_activity()

    allowed, reason = policy.check(host, method, path)
    log_request(allowed, method, host, path, reason)

    if allowed:
        ctx.log.info(f"✓ {method} {host}{path}")
    else:
        ctx.log.warn(f"✗ {method} {host}{path} - {reason}")
        flow.response = http.Response.make(
            403,
            json.dumps({
                "error": "Blocked by sandbox policy",
                "reason": reason,
                "request": f"{method} {host}{path}"
            }, indent=2),
            {"Content-Type": "application/json"}
        )
