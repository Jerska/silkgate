"""Profiles: what each --with installs, what it may reach, and what it needs set."""
import os
import re

import rule_engine

from . import console, mitm, paths


# --- profiles ----------------------------------------------------------------
# A profile is one capability: how to install it (setup.sh, run at build time) and what it
# may reach once running (rules.txt, enforced by the proxy). Both come from the same
# `--with` list, so an image can't end up with a tool whose egress nobody allowed.

# A version and a base image reach the generated Dockerfile verbatim: the version as shell
# text in `RUN VERSION="<v>" sh setup.sh`, the base as `FROM`. `docker build` runs as root on
# the host, outside the proxy, so both are charset-checked at parse time, where the error can
# name the flag.
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_IMAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}")

# `probe` is not a capability a task may hold: its rules open the Debian mirrors so that
# `verify --full` can install its probe tools *through* the proxy (profiles/probe/rules.txt).
# Only that one path resolves it; everywhere else it is refused rather than composed.
_VERIFY_ONLY = frozenset({"probe"})


def _version_error(version):
    """Why `version` cannot be interpolated into a generated Dockerfile, or None."""
    if _VERSION_RE.fullmatch(version):
        return None
    return (f"invalid version {version!r} — letters and digits plus '.', '_', '+', '-', "
            "starting alphanumeric; it becomes shell text at image build time")


def _image_error(ref):
    """Why `ref` cannot be used as an image reference, or None."""
    if _IMAGE_RE.fullmatch(ref):
        return None
    return (f"invalid image reference {ref!r} — registry/name[:tag][@digest] characters only "
            "(letters, digits and '.', '_', '-', ':', '/', '@'); a newline here would be an "
            "extra Dockerfile directive")


def _arg_error(arg):
    """Why `arg` cannot land inside generated rule text, or None. A rule is one
    whitespace-separated line, so whitespace or a control character in an arg is rule
    injection and is refused unconditionally, whatever pattern the profile declares —
    everything finer is the declaring profile's arg_pattern's question."""
    if not arg:
        return "empty argument — drop the ':' or name an argument"
    if any(c.isspace() or not c.isprintable() for c in arg):
        return (f"invalid argument {arg!r} — whitespace and control characters never pass; "
                "the argument lands inside rule syntax")
    return None


def _parse_spec(spec):
    """Split `NAME[@VERSION][:ARG]` into (name, version, arg), or raise ValueError.

    Charset questions only: the name resolves later, against the profiles that exist,
    and the arg's shape against the profile's declared arg_pattern. Neither a name nor
    a version can contain ':', so the first ':' opens the arg — which may itself
    contain more of them."""
    head, sep, arg = spec.partition(":")
    name, vsep, version = head.partition("@")
    if vsep and not version:
        raise ValueError(
            f"{spec!r} pins an empty version — drop the '@' or name a version (an unset shell "
            "variable expands to this, and would quietly install the default instead)")
    bad = _version_error(version) if version else None
    if bad:
        raise ValueError(bad)
    if sep:
        bad = _arg_error(arg)
        if bad:
            raise ValueError(f"{spec!r}: {bad}")
    return name, version or None, arg if sep else None


class Profile:
    """One resolved `--with name[@version][:arg]`: its files, version, arg, metadata."""

    __slots__ = ("name", "version", "arg", "arg_pattern", "dir", "conf", "rules", "setup",
                 "env", "context", "packages", "guest_credentials")

    def __init__(self, name, version=None, arg=None):
        # The keys read here are mirrored in doc/PROFILES.md (profile.conf keys). Update both.
        self.name, self.dir = name, paths.PROFILE_DIR / name
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) or not self.dir.is_dir():
            avail = ", ".join(sorted(p.name for p in paths.PROFILE_DIR.iterdir() if p.is_dir()))
            console.die(f"unknown profile {name!r} (available: {avail})")
        self.conf = _parse_conf(self.dir / "profile.conf")
        self.rules = _read_if(self.dir / "rules.txt")
        self.setup = _read_if(self.dir / "setup.sh")
        self.env = _read_if(self.dir / "env")
        self.context = _read_if(self.dir / "context.md")
        self.packages = [t for t in re.split(r"[,\s]+", self.conf.get("packages", "")) if t]
        # header -> the `KEY=VALUE` pair whose client sends that header; see
        # _guest_credential_env. Checked at load, so `profiles` lists a defect too.
        self.guest_credentials = {k.partition(".")[2].lower(): v for k, v in self.conf.items()
                                  if k.startswith("guest_credential.")}
        if self.conf.get("guest_credential") and not self.guest_credentials:
            console.die(f"profile {name!r}: guest_credential names a secret but no "
                        "guest_credential.<header> line says what the guest holds")
        for header, pair in self.guest_credentials.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S+", pair):
                console.die(f"profile {name!r}: guest_credential.{header} must be KEY=VALUE, "
                            f"got {pair!r}")
        default = self.conf.get("default_version")
        if version and not default:
            console.die(f"profile {name!r} takes no version (it installs nothing versioned)")
        self.version = version or default
        if self.version:
            bad = _version_error(self.version)      # a profile.conf default is checked too
            if bad:
                console.die(f"profile {name!r}: {bad}")
        # The arg contract, both halves load-checked: a declared arg_pattern must be a
        # usable full-match regex, and a {arg} placeholder without one is a line
        # nothing may ever fill — refused at load so `profiles` lists the defect too.
        self.arg_pattern = self.conf.get("arg_pattern")
        if self.arg_pattern is not None:
            if not self.arg_pattern:
                console.die(f"profile {name!r}: empty arg_pattern — name a full-match pattern "
                            "or drop the key")
            try:
                re.compile(self.arg_pattern)
            except re.error as e:
                console.die(f"profile {name!r}: bad arg_pattern {self.arg_pattern!r} — {e}")
        elif "{arg}" in self.rules or "{arg}" in self.context:
            where = "rules.txt" if "{arg}" in self.rules else "context.md"
            console.die(f"profile {name!r}: {where} uses {{arg}} but profile.conf declares no "
                        "arg_pattern — declare one or drop the placeholder")
        if arg is not None:
            bad = _arg_error(arg)       # unconditional, wherever the arg came from
            if bad:
                console.die(f"profile {name!r}: {bad}")
            if self.arg_pattern is None:
                console.die(f"profile {name!r} takes no argument "
                            "(its profile.conf declares no arg_pattern)")
            if not re.fullmatch(self.arg_pattern, arg):
                console.die(f"profile {name!r}: argument {arg!r} does not match its arg_pattern "
                            f"{self.arg_pattern!r}")
        self.arg = arg

    @property
    def spec(self):
        return f"{self.image_spec}:{self.arg}" if self.arg is not None else self.image_spec

    @property
    def image_spec(self):
        """The spec without the arg — everything about this instance that the image
        can see. An arg reaches only composed rules, never setup.sh or env, so image
        identity must exclude it or every arg would force a pointless rebuild."""
        return f"{self.name}@{self.version}" if self.version else self.name

    def env_pairs(self):
        return [ln for ln in self.env.splitlines() if ln.strip() and not ln.startswith("#")]

    def rendered_rules(self):
        """rules.txt with every {arg} replaced by the validated arg. rules.txt and
        context.md are the templated files: setup.sh and env shape the image, which an
        arg must never touch (see image_ref, which hashes the template bytes as
        written)."""
        return self.rules.replace("{arg}", self.arg) if self.arg is not None else self.rules

    def rendered_context(self):
        """context.md with every {arg} replaced by the validated arg — the profile's
        own addition to the guest brief, appended by session_context once per instance.
        Session text only: it never shapes the image, so image_ref excludes it."""
        return self.context.replace("{arg}", self.arg) if self.arg is not None else self.context


def _parse_conf(path):
    """`key = value` lines; blanks and #-comments ignored."""
    conf = {}
    for line in _read_if(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            console.die(f"{path}: expected 'key = value', got {line!r}")
        conf[key.strip()] = value.strip()
    return conf


def _read_if(path):
    return path.read_text() if path.is_file() else ""


def resolve_profiles(specs, *, allow_verify_only=False):
    """Turn `--with` specs into Profiles, in the order given (which the image hash keeps).

    Each distinct (name, version, arg) instance lands once: exact duplicate specs and
    respellings that resolve the same — `node` beside `node@<its default>` — deduplicate
    silently, and each surviving instance expands its rules once.
    """
    profiles = []
    for spec in specs:
        try:
            name, version, arg = _parse_spec(spec)
        except ValueError as e:
            console.die(str(e))
        if name in _VERIFY_ONLY and not allow_verify_only:
            console.die(f"profile {name!r} is for `silkgate verify` only — it opens the Debian "
                        "mirrors so the containment check can install its probe tools through "
                        "the proxy")
        p = Profile(name, version, arg)
        if p.arg_pattern is not None and p.arg is None:
            console.die(f"profile {name!r} requires an argument — write {name}:ARG, with an ARG "
                        f"that fully matches its arg_pattern {p.arg_pattern!r}")
        if all((p.name, p.version, p.arg) != (q.name, q.version, q.arg) for q in profiles):
            profiles.append(p)
    # `supersedes = NAME` in profile.conf: an instance of the declaring profile drops
    # any NAME instance carrying the same arg — the wider grant absorbs the narrower
    # one, announced so the operator sees the list they asked for shrink.
    for p in list(profiles):
        target = p.conf.get("supersedes")
        if not target or p not in profiles:
            continue
        for q in [q for q in profiles if q is not p
                  and q.name == target and q.arg == p.arg]:
            console.say(f"profile {p.spec} supersedes {q.spec} — dropping {q.spec}")
            profiles.remove(q)
    have = {p.name for p in profiles}
    for p in profiles:
        missing = [r for r in re.split(r"[,\s]+", p.conf.get("requires", "")) if r and r not in have]
        if missing:
            console.die(f"profile {p.name!r} requires {', '.join(missing)} — add --with for them")
    return profiles


def profile_command(profiles):
    """The default command to run in the guest: the last profile that names one."""
    for p in reversed(profiles):
        if p.conf.get("command"):
            return p.conf["command"].split()
    return None


def compose_rules(profiles, extra_rules=()):
    """The session's ruleset text, in deliberate order: --rule lines first, then
    arg-instance expansions (grants such as github-read:OWNER/REPO), then the rules of
    profiles without args. The proxy is first-match-wins, so earlier rules override
    later ones for the paths they cover — explicit beats a grant, a grant beats the
    profile floor."""
    out = []
    if extra_rules:
        out.append("# --- --rule ---")
        out.extend(extra_rules)
    for p in profiles:
        if p.arg is not None and p.rules.strip():
            out.append(f"# --- profile {p.spec} ---")
            out.append(p.rendered_rules().rstrip("\n"))
    for p in profiles:
        if p.arg is None and p.rules.strip():
            out.append(f"# --- profile {p.spec} ---")
            out.append(p.rules.rstrip("\n"))
    return "\n".join(out) + "\n" if out else ""


def load_ruleset(text, where="rules"):
    """Parse up front so bad rules fail here, not inside mitmdump at startup."""
    try:
        return rule_engine.RuleSet.parse(text)
    except ValueError as e:
        console.die(f"{where}: {e}")


# The other half of the proxy configuration: NO_PROXY/no_proxy is an exemption list every
# HTTP client honours, and Tier 1 drops the direct connection it sends them to — so it takes
# hosts out of the proxy's reach without taking them out of the policy, which is the same
# footgun as clobbering HTTPS_PROXY and reads like the opposite.
_NO_PROXY_VARS = ("NO_PROXY", "no_proxy")


def check_env(pairs):
    """Validate -e NAME=VALUE pairs; clobbering the proxy config is always an error."""
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            console.die(f"bad -e argument {pair!r} (expected NAME=VALUE)")
        if name in mitm.PROXY_ENV_VARS:
            console.die(f"-e {name} collides with the proxy configuration silkgate sets")
        if name in _NO_PROXY_VARS:
            console.die(f"-e {name} tells the guest's clients to bypass the proxy for the hosts "
                        "it names, and Tier 1 drops those connections — they fail instead of "
                        "being policed, and nothing in it widens the allowlist")
        if "\n" in value:
            # msb aborts the guest (SIGABRT, before the agent relay comes up) on any env
            # value containing a newline, at any size. Fail here with a reason instead.
            console.die(f"-e {name} value contains a newline, which microsandbox cannot pass; "
                        "write it to a file in the workspace instead")


def check_secrets(ruleset):
    """Warn about any inject_auth secret in the ruleset that is absent or malformed.

    Each secret must be set AND pass _parse_secret: "x-api-key: " is set, but the proxy
    rejects its empty value at request time. Launches always warn and continue.
    """
    names = sorted({r.inject_auth for r in ruleset.rules if r.inject_auth})
    for n in names:
        value = os.environ.get(f"SILKGATE_EGRESS_SECRET_{n.upper()}")
        if not value:
            reason = "is not set"
        elif rule_engine._parse_secret(value) is None:
            reason = 'is set but not a valid "<Header>: <value>" line'
        else:
            continue
        msg = (f"SILKGATE_EGRESS_SECRET_{n.upper()} {reason} — "
               f"requests matching inject_auth={n} will be denied")
        console.say(f"warning: {msg}")
