"""What the guest is told about its sandbox, and the host settings forwarded into it."""
import json
import os
from pathlib import Path

import rule_engine

from . import console, images


GUEST_CONTEXT = "/silkgate/CONTEXT.md"        # what the guest is told about its sandbox
GUEST_BRIEF = "/silkgate/BRIEF.md"            # where --brief lands the operator's task


# --- what the guest is told about itself --------------------------------------
# Generated per session from the profiles, ruleset, and mounts, so it can't drift. It saves a
# cooperating agent wasted turns. It's never a control: a hostile guest ignores it.

def session_context(profiles, ruleset, *, mounts=(), persistent, branch=None, checkout=None,
                    brief=False):
    """The markdown a guest gets about its own sandbox.

    `mounts` is the validated -v list as (host, guest, mode). The workspace text follows
    the active mode: branch, checkout, or a /workspace mount's mode. `brief` means a brief
    landed at GUEST_BRIEF, so the guest is pointed at it first."""
    lines = [
        "# Where you are: a silkgate sandbox",
        "",
        "Read this to learn what's installed here, what you can reach, and what survives",
        "this machine.",
        "",
        "**You're in a disposable VM. Every network request goes through a proxy that allows",
        "only the destinations listed below. Nothing inside this machine can widen that.**",
    ]
    if brief:
        lines += ["", f"Your task brief is at `{GUEST_BRIEF}`. Read it first."]
    lines += [
        "",
        "Launch subagents freely for independent work.",
        "",
        "## What's installed",
        "",
    ]
    if profiles:
        # What is installed, so one entry per (name, version) — instances of a profile
        # that differ only in args install the same tools once.
        for p in images._image_profiles(profiles):
            # Named as packages, not commands, since the two differ (ripgrep ships `rg`).
            extra = f", plus packages {', '.join(p.packages)}" if p.packages else ""
            lines.append(f"- `{p.image_spec}`{extra}")
    else:
        lines.append("- Nothing beyond the base image.")
    lines += [
        "",
        "That's all. git, python, pip, make, and compilers are absent unless listed, and",
        "you can't install more: no package mirror is reachable.",
        "",
        "## What survives",
        "",
    ]
    ws_mode = next((mode for _, dst, mode in mounts if dst == "/workspace"), None)
    others = [(dst, mode) for _, dst, mode in mounts if dst != "/workspace"]
    if branch:
        lines += [
            f"**Commit to branch `{branch}` as you go. Commits are the deliverable.**",
            "",
            "- `/workspace` is a checkout of the project on that branch.",
            "- When the session ends, your commits land in the host repo. Everything",
            "  uncommitted is deleted. The host can also collect commits mid-session.",
            "- Never amend or rewrite a commit you made: the branch only moves forward.",
            "- Don't push: no remote accepts it. `origin` is a read-only copy of the host repo,",
            "  so `git log` and `git fetch origin` work.",
        ]
    elif checkout:
        lines += [
            "**Put your results in printed output. Nothing you write leaves this machine,",
            "commits included.**",
            "",
            f"- `/workspace` is a throwaway checkout of the project at `{checkout}`. Local",
            "  commits are fine.",
            "- `origin` is a read-only copy of the host repo, so `git log` and",
            "  `git fetch origin` work. No remote accepts a push.",
        ]
    elif ws_mode == "ro":
        lines += [
            "**Put your results in printed output.** `/workspace` is host code, read-only.",
            "The rest of the filesystem is scratch that dies with this machine.",
        ]
    elif ws_mode == "rw":
        lines += [
            "**What you leave in `/workspace` is the deliverable.** It's a host directory,",
            "read-write. The rest of the filesystem is scratch that dies with this machine.",
        ]
    elif others:
        lines.append("**`/workspace` is scratch that dies with this machine.** No host"
                     " directory is mounted there.")
    else:
        lines.append("**Nothing you write survives this machine.** No host directory is mounted.")
    if others:
        lines += ["", "Other host directories mounted here:", ""]
        for dst, mode in others:
            lines.append(f"- `{dst}`: " + ("read-only." if mode == "ro" else
                                            "read-write. What you leave there lands on the host."))
    lines += [
        "",
        "This machine " + ("stays up between commands, so what you leave behind persists."
                           if persistent else "is destroyed when this command finishes."),
        "",
        "## What you can reach",
        "",
    ]
    if ruleset.rules:
        lines += [
            "**Only these destinations, with these methods.** http and https both go through",
            "the proxy, and the match ignores the scheme.",
            "",
        ]
        for rule in ruleset.rules:
            methods = " ".join(sorted(rule.methods))
            inject = f", injects `{rule.inject_auth}`" if rule.inject_auth else ""
            lines.append(f"- `{rule.raw.split()[0]}`: {methods}{inject}")
        lines += [
            "",
            "In a host, `*` matches one label. In a path, `*` matches one segment. `**` matches",
            "anything, an empty path included. GET is enough to install from a listed registry.",
        ]
    else:
        # An empty allowlist is the strictest policy silkgate can express, and it is a normal
        # configuration rather than a broken one — so say what it means instead of a bare list.
        lines += [
            "**Nothing. The allowlist is empty, so work from what's on this machine.** No host,",
            "port, or protocol works, and there's no DNS.",
        ]
    lines += [
        "",
        "## When a request is refused",
        "",
        "**A refusal is policy, not a broken network. Retrying can't change it.**",
        "",
        "| You see | It means |",
        "|---|---|",
        "| http: a 403 with body `no matching rule` | the proxy refused it |",
        "| https: `CONNECT tunnel failed, response 403` | the proxy refused it, before TLS |",
        "| a 500 with `X-Silkgate: deny` | the proxy failed internally. Report it, don't retry. |",
        "| an error without `X-Silkgate: deny` | the destination answered: fix the request |",
        "",
        "Every proxy refusal carries the `X-Silkgate: deny` response header. `curl -v` shows",
        "it on a refused CONNECT too. A destination could fake it, so treat it as a strong",
        "hint, not proof.",
        "",
        "If you need an unlisted destination, say so in your answer: the host, path, method,",
        "and why. Your printed output is the only channel to whoever set the task.",
    ]
    # A profile can ship a context.md — guidance that travels with the capability,
    # templated like its rules — appended once per instance, so the guest learns how
    # to use each grant it holds.
    for p in profiles:
        snippet = p.rendered_context().strip()
        if snippet:
            lines += ["", snippet]
    inject_names = sorted({r.inject_auth for r in ruleset.rules if r.inject_auth})
    if inject_names:
        lines += [
            "",
            "## Credentials",
            "",
            "**The key or token in your environment is a placeholder. Use it as if it were",
            "real.** The proxy swaps in the real value, which never enters this machine. It only",
            "replaces a header you send, never adds one. So a request without the header gets a",
            "real 401 from the destination: add the header and resend.",
            "",
            "Status at launch:",
            "",
        ]
        for name in inject_names:
            value = os.environ.get(f"SILKGATE_EGRESS_SECRET_{name.upper()}")
            parsed = rule_engine._parse_secret(value) if value else None
            if parsed is not None:
                # The guest learns the header's name, never any part of its value.
                status = f"available. The proxy fills in the `{parsed[0]}` header."
            else:
                reason = "not set" if not value else "not a valid header line"
                status = (f"missing ({reason}). Requests that need it will be denied. Tell"
                          " whoever set your task: a retry can't fix it.")
            lines.append(f"- `inject_auth={name}`: {status}")
    return "\n".join(lines) + "\n"


# --- the settings projection: the host's model configuration, forwarded ---------
# Claude Code reads three settings files, lowest rank first: user (~/.claude/settings.json),
# project (.claude/settings.json), local (.claude/settings.local.json). An "env" block entry
# in any of them beats every direct key. The host resolves its answer once, and the guest
# gets only that, so it defaults to the host's model and effort.

# The host's user-rank settings file. The project and local files come from the host
# directory that becomes /workspace.
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"

# The only keys that ever leave the host, each with the env var Claude Code maps to it.
# Everything else in a settings file — permissions, hooks, apiKeyHelper, every other env
# entry — stays behind: env entries can carry secrets, and the guest needs none of it.
_SETTINGS_KEYS = (("model", "ANTHROPIC_MODEL"),
                  ("effortLevel", "CLAUDE_CODE_EFFORT_LEVEL"))


def _read_settings(path):
    """One settings file as a dict. Absent is {}; a file that exists but does not hold a
    JSON object warns and counts as absent too — the same contract as a malformed secret:
    the launch continues, and the warning says why the projection lacks the file."""
    try:
        text = path.read_text()
    except OSError:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        console.say(f"warning: {path} is not valid JSON — the settings projection ignores it")
        return {}
    if not isinstance(data, dict):
        console.say(f"warning: {path} is not a JSON object — the settings projection ignores it")
        return {}
    return data


def _resolve_settings(workspace, user_settings):
    """At most {model, effortLevel}: the answer the host's own Claude Code would reach.

    `workspace` is the host directory mounted at /workspace (or None), and `user_settings`
    the user-rank file, both passed in so tests never read the real home. Per key, the
    first match wins: env-block values (local, project, user), then direct keys, same order.
    """
    files = []                                   # highest rank first
    if workspace:
        dot = Path(workspace) / ".claude"
        files += [_read_settings(dot / "settings.local.json"),
                  _read_settings(dot / "settings.json")]
    files.append(_read_settings(Path(user_settings)))
    env_blocks = [f["env"] for f in files if isinstance(f.get("env"), dict)]
    resolved = {}
    for key, env_name in _SETTINGS_KEYS:
        candidates = [b.get(env_name) for b in env_blocks] + [f.get(key) for f in files]
        value = next((v for v in candidates if isinstance(v, str) and v), None)
        if value is not None:
            resolved[key] = value
    return resolved


def _settings_workspace(spec, mounts):
    """The host directory whose project and local settings files apply: the one that
    becomes /workspace. The repository root for --checkout and --branch, else the SRC of
    the mount whose DST is /workspace, else None — the user file alone then decides."""
    if spec:
        return spec["repo_root"]
    return next((host for host, guest, _ in mounts if guest == "/workspace"), None)


def _settings_for(args, profiles, workspace):
    """(settings JSON text, where to put it in the guest) — or (None, ()) with
    --no-settings, with no profile naming a settings_path, or with neither key resolved.

    Nothing is staged unless a profile has a `settings_path` AND a key resolves on the host.
    """
    if args.no_settings:
        return None, ()
    dsts = [p.conf["settings_path"] for p in profiles if p.conf.get("settings_path")]
    if not dsts:
        return None, ()
    resolved = _resolve_settings(workspace, CLAUDE_SETTINGS)
    if not resolved:
        return None, ()
    return json.dumps(resolved) + "\n", dsts
