# Egress allowlist DSL — specification

> The rule language enforced by the proxy. Reference implementation:
> [`mitmaddon/rule_engine.py`](../mitmaddon/rule_engine.py) (dependency-free;
> `python3 mitmaddon/rule_engine.py` self-tests, 54/54). Design rationale:
> [THREAT-MODEL.md](./THREAT-MODEL.md).

## Grammar

One **allow**-rule per line. **Default-deny**: anything not matched is blocked. First match
wins (allowlist, so order is irrelevant until deny-rules are added).

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

`#` starts a comment; blank lines ignored.

## Wildcards

Split the pattern at the **first** `/`: host = before, path = after.

| Token | In host (before `/`) | In path (after `/`) |
|---|---|---|
| `*`  | `[^.]+` (one DNS label) | `[^/]+` (one path segment) |
| `**` | `.*` (any, incl. dots)  | `.*` (any, incl. slashes or empty) |
| `**.`| `(?:.*\.)?` — optional subdomain prefix, **matches the apex too** | — |

Consequences:
- `*.github.com` matches `api.github.com`, **not** `github.com` (apex) or `a.b.github.com`.
- `**.github.com` matches `github.com`, `api.github.com`, `a.b.github.com` — but not
  `notgithub.com`.
- A pattern with **no `/`** matches any path (`api.anthropic.com` ≡ any path on that host).
- `github.com/**` matches `github.com`, `github.com/`, and any deeper path.
- `a/**` requires the `a/` prefix (clean boundary) — to also match bare `/a`, add a second
  rule. (Safer than `a**`, which would also match `a-organization`.)

> ⚠️ Wildcards bound **capability/blast-radius**, not exfil bandwidth. A single `*` segment
> still carries an arbitrary base64 blob. See THREAT-MODEL.md → "the reframe."

## Host normalization (the null-byte / homograph guard)

Lives in the engine, applied identically to **pattern** and **request** host. Steps, in order:

1. reject if it contains null / space / tab / CR / LF / `%` / `@` / `[` / `]`
2. split off and validate optional `:port` (digits only)
3. lowercase, strip trailing dot
4. reject non-ASCII → **force punycode (`xn--…`)**; kills homographs
5. reject raw IP literals (force domain allowlisting)
6. strict form: `^label(\.label)*$`, `label = [a-z0-9](?:[a-z0-9-]*[a-z0-9])?`,
   label ≤ 63, total ≤ 253

`_` (underscore) is **excluded by default** (invalid in public DNS; opt-in for internal
names). Pattern hosts additionally permit `*`.

## Ports

A host pattern may carry an optional `:port`, matched against the request's destination port:
- **no port → 80 and 443 only** (default);
- `:8080` (or a comma list `:443,8080`) → exactly those ports — **replaces** the default;
- `:*` → any port.

So a non-default port on an allowed host is denied unless listed — e.g. `api.internal:8443/**`
permits only `:8443`, and `foo.com/**` rejects `foo.com:8080`.

## Path normalization

Before matching: strip `#fragment` and `?query`, percent-decode once (`%2e%2e` → `..`),
then `posixpath.normpath` to resolve `.`/`..`. So `your-org/x/../../other` normalizes to
`/other` and won't match `your-org/**`. (Single decode; double-encoding is a noted residual.)

## Options

| Option | Effect | Default |
|---|---|---|
| `GET POST …` | allowed methods (bare uppercase tokens) | **GET only** |
| `max_body=<size>` | permit a request body up to `<size>` (bytes; `k`/`m` suffix) | no body |
| `q:*` | allow **all** query params (escape hatch — use sparingly) | params stripped |
| `q:<name>=<value>` | keep query param `<name>` only if value **==** `<value>`; all others stripped | params stripped |
| `q:<name>~<regex>` | keep query param `<name>` only if `<regex>` **fullmatches**; all others stripped | params stripped |
| `h:*` | allow **all** request headers, incl. `Authorization` (escape hatch — use sparingly) | headers stripped |
| `h:<name>=<value>` | forward header only if value **==** `<value>` (exact) | — |
| `h:<name>~<regex>` | forward header only if `<regex>` **fullmatches** (no spaces; use `\s`) | — |
| `inject_auth=<name>` | if the request already carries the header named in `EGRESS_SECRET_<NAME>` (`header: value`), replace its value with the host-held secret; **never added when absent** (no forced header) | — |

Notes:
- Per-rule body *content* rules are deferred (only `max_body` size). Query params now have
  per-param constraints via `q:` (case-sensitive name); disallowed params are **stripped**.
- Tokens are whitespace-split, so option values can't contain spaces (use `\s` in regexes).

## Header policy (deny-by-default, value-constrained)

Headers are **stripped unless** they appear in the effective policy **and** their value
satisfies the constraint. Effective policy = engine **baseline** ∪ per-rule `h:` overrides
(overrides win).

Baseline (capped/regex'd to shrink the residual channel; override per rule for stricter):

| Header | Constraint |
|---|---|
| `host` | hostname charset + optional port, ≤253 (the already-allowlisted destination) |
| `content-type` | MIME-ish charset, ≤64 |
| `content-length` | digits, ≤10 |

`accept`, `accept-encoding`, `accept-language`, `user-agent`, and `range` are **not** baseline —
opt in per rule with `h:` where a host needs them.

`cookie`, `authorization`, and any `x-*`/unknown header → **stripped by default** (not in the
baseline); allow one explicitly with `h:` if a host needs it (no header is special-cased). When a
rule has `inject_auth`, the proxy *replaces* the named header's value with the host-held secret —
but only when the request already carries it — so the real credential is never present in the guest.

## Locked design decisions

1. Bare host (no `/`) = any path. ✓
2. Default method = **GET only**; `POST`/etc. must be explicit. ✓
3. `**.` matches the apex; `*.` does not. ✓
4. Path `**` = `.*` (matches empty / bare host). ✓
5. Query, headers, and bodies are **deny-by-default + opt-in**, uniform across methods
   (the GET-vs-POST difference falls out naturally: GET has no body, so you'd never set
   `max_body`). Header opt-in is value-constrained, not name-only. ✓
6. Host charset post-normalization ≈ `[a-z0-9.-]`; `_` opt-in; raw IPs rejected. ✓

## What the engine does *not* do (proxy addon's job)

The engine **matches** and carries config. Enforcement — TLS termination, SNI==Host, stripping
disallowed headers, body-size rejection, query-param stripping, secret injection, audit logging,
fail-closed on undecryptable — lives in the mitmproxy addon
([`mitmaddon/proxy_addon.py`](../mitmaddon/proxy_addon.py)).
