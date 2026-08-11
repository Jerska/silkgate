# Egress allowlist DSL — specification

Read this to write egress rules for a profile or a session.

The proxy enforces this rule language. The reference implementation is
[`mitmaddon/rule_engine.py`](../mitmaddon/rule_engine.py) (dependency-free —
`python3 mitmaddon/rule_engine.py` self-tests, 69/69). The design rationale is in
[THREAT-MODEL.md](./THREAT-MODEL.md). Rules live in `profiles/<name>/rules.txt`, one profile
per capability. A session's ruleset is the profiles it was started `--with`, concatenated,
and the proxy reads the composed snapshot at `~/.silkgate/sessions/<name>/rules.txt`.

## Grammar

**One allow-rule per line, and default-deny: anything no rule matches is blocked.** The
first match wins. Order is irrelevant for an allowlist, and stays so until deny-rules are
added. `#` starts a comment, and blank lines are ignored.

An empty ruleset is legal, and it is the tightest policy there is: default-deny with nothing
exempted. `run` and `up` with no `--with` and no `--rule` compose exactly that — a guest
that can reach nothing. Only the standalone `silkgate proxy` insists on at least one rule.

```
<host>[:<port>][/<path>]   [METHOD ...]   [option ...]
```

```
# pattern                       methods   options
api.anthropic.com/v1/messages   POST      inject_auth=anthropic h:anthropic-version=2023-06-01 max_body=10m
registry.npmjs.org/**           GET
files.pythonhosted.org/**       GET
github.com/your-org/**          GET POST  max_body=1m
*.internal.corp/**              GET POST
```

## Wildcards

**The pattern splits at the first `/`: the host is before it, the path after it.**

| Token | In host (before `/`) | In path (after `/`) |
|---|---|---|
| `*`  | `[^.]+` (one DNS label) | `[^/]+` (one path segment) |
| `**` | `.*` (any, dots included)  | `.*` (any, slashes or empty included) |
| `**.`| `(?:.*\.)?` — optional subdomain prefix, matches the apex too | — |

The consequences:

- `*.github.com` matches `api.github.com`, not `github.com` (the apex) and not
  `a.b.github.com`.
- `**.github.com` matches `github.com`, `api.github.com`, and `a.b.github.com` — but not
  `notgithub.com`.
- A pattern with no `/` matches any path. `api.anthropic.com` alone allows every path on
  that host.
- `github.com/**` matches `github.com`, `github.com/`, and any deeper path.
- `a/**` requires the `a/` prefix (a clean boundary). To also match bare `/a`, add a second
  rule. That is safer than `a**`, which also matches `a-organization`.

Wildcards bound capability and blast radius, not exfiltration bandwidth. A single `*`
segment still carries an arbitrary base64 blob. See the reframe in
[THREAT-MODEL.md](./THREAT-MODEL.md).

## Host normalization (the null-byte and homograph guard)

**Normalization lives in the engine and applies identically to the pattern host and the
request host.** The steps, in order:

1. Reject a host with null, space, tab, CR, LF, `%`, `@`, `[`, or `]`.
2. Split off and validate an optional `:port` (digits only).
3. Lowercase, and strip a trailing dot.
4. Reject non-ASCII: force punycode (`xn--…`), which kills homographs.
5. Reject raw IP literals, so only domains are allowlisted.
6. Require the strict form `^label(\.label)*$` with
   `label = [a-z0-9](?:[a-z0-9-]*[a-z0-9])?`, label ≤ 63, total ≤ 253.

`_` (underscore) is excluded by default — it is invalid in public DNS — and is opt-in for
internal names. Pattern hosts additionally permit `*`.

## Ports

**A host pattern can carry an optional `:port`, matched against the destination port the
proxy dials.**

| Pattern | Matched ports |
|---|---|
| no port | 80 and 443 only (the default) |
| `:8080`, or a comma list `:443,8080` | exactly those — the list replaces the default |
| `:*` | any port |

A non-default port on an allowed host is denied unless listed. For example,
`api.internal:8443/**` permits only `:8443`, and `foo.com/**` rejects `foo.com:8080`.

## Path normalization

**The engine normalizes the path before it matches.** It strips `#fragment` and `?query`,
percent-decodes once (`%2e%2e` becomes `..`), then resolves `.` and `..` with
`posixpath.normpath`. So `your-org/x/../../other` normalizes to `/other` and does not match
`your-org/**`. The decode is single: double-encoded input is a noted residual.

## Options

| Option | Effect | Default |
|---|---|---|
| `GET POST …` | allowed methods (bare uppercase tokens) | GET only |
| `max_body=<size>` | permit a request body up to `<size>` (bytes, or a `k`/`m` suffix) | no body |
| `q:*` | allow all query params (escape hatch — use sparingly) | params stripped |
| `q:<name>=<value>` | keep query param `<name>` only if its value equals `<value>` — all others stripped | params stripped |
| `q:<name>~<regex>` | keep query param `<name>` only if `<regex>` fullmatches — all others stripped | params stripped |
| `h:*` | allow all request headers, `Authorization` included (escape hatch — use sparingly) | headers stripped |
| `h:<name>=<value>` | forward the header only if its value equals `<value>` | — |
| `h:<name>~<regex>` | forward the header only if `<regex>` fullmatches (no spaces — use `\s`) | — |
| `inject_auth=<name>` | if the request already carries the header named in `SILKGATE_EGRESS_SECRET_<NAME>` (`header: value`), replace its value with the host-held secret — never added when absent | — |

Two notes. Per-rule body content rules are deferred — only the `max_body` size exists.
Option tokens are whitespace-split, so an option value cannot contain a space (use `\s` in
a regex).

## Header policy (deny-by-default, value-constrained)

**A header is stripped unless it appears in the effective policy and its value satisfies
the constraint.** The effective policy is the engine baseline plus the per-rule `h:`
overrides, and an override wins. The baseline is capped to shrink the residual channel —
override per rule for a stricter posture:

| Header | Constraint |
|---|---|
| `host` | hostname charset plus optional port, ≤253 (the already-allowlisted destination) |
| `content-type` | MIME-ish charset, ≤64 |
| `content-length` | digits, ≤10 |

`accept`, `accept-encoding`, `accept-language`, `user-agent`, and `range` are not baseline.
Opt in per rule with `h:` where a host needs them. `cookie`, `authorization`, and any
`x-*` or unknown header are stripped by default — allow one explicitly with `h:` if a host
needs it, because no header is special-cased. When a rule has `inject_auth`, the proxy
*replaces* the named header's value with the host-held secret, and only when the request
already carries that header. The real credential is therefore never present in the guest.

## Locked design decisions

1. A bare host (no `/`) matches any path. ✓
2. The default method is GET only. `POST` and the rest must be explicit. ✓
3. `**.` matches the apex. `*.` does not. ✓
4. A path `**` compiles to `.*` and matches an empty path or a bare host. ✓
5. Query params, headers, and bodies are deny-by-default and opt-in, uniform across methods.
   The GET-vs-POST difference falls out naturally: GET has no body, so `max_body` on a GET
   rule buys nothing. Header opt-in is value-constrained, not name-only. ✓
6. The host charset after normalization is `[a-z0-9.-]`, `_` is opt-in, and raw IPs are
   rejected. ✓

## What the engine does not do (the addon's job)

**The engine matches and carries configuration. Enforcement lives in the mitmproxy addon**
([`mitmaddon/proxy_addon.py`](../mitmaddon/proxy_addon.py)): TLS termination, SNI==Host,
header stripping, body-size rejection, query-param stripping, secret injection, the audit
log, and fail-closed treatment of anything undecryptable. [PROXY.md](./PROXY.md) covers how
that proxy runs and what it records.
