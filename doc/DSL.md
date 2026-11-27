# Egress rules

Read this to write the rules in a profile's `rules.txt`, or in `--rule`.

## A rule

**One allow rule per line. Anything no rule matches is denied.**

```text
<host>[:<port>][/<path>]   [METHOD ...]   [option ...]
```

```text
# pattern                       methods   options
api.anthropic.com/v1/messages   POST      inject_auth=anthropic h:anthropic-version=2023-06-01 max_body=10m
registry.npmjs.org/**           GET
github.com/acme/**              GET POST  max_body=1m
*.internal.corp/**              GET
```

- The first matching rule decides, options included. Composition order is in
  [PROFILES.md](./PROFILES.md#rule-order).
- `#` starts a comment. Blank lines are ignored.
- An empty ruleset is legal: the guest reaches nothing.
- Check a composed ruleset with `silkgate profiles --render <spec>`.

The engine is [`mitmaddon/rule_engine.py`](../mitmaddon/rule_engine.py). Run it directly for
its self-tests.

## Wildcards

**The pattern splits at the first `/`: host before it, path after it.**

| Token | In the host | In the path |
|---|---|---|
| `*` | one DNS label | one path segment |
| `**` | anything, dots included | anything, slashes included, or nothing |
| `**.` | an optional subdomain prefix: matches the apex too | — |

| Pattern | Matches | Doesn't match |
|---|---|---|
| `*.github.com` | `api.github.com` | `github.com`, `a.b.github.com` |
| `**.github.com` | `github.com`, `api.github.com`, `a.b.github.com` | `notgithub.com` |
| `api.anthropic.com` (no `/`) | every path on that host | |
| `github.com/**` | `github.com`, `github.com/`, `github.com/a/b` | |
| `github.com/acme/**` | `github.com/acme/x` | `github.com/acme`, `github.com/acme-evil` |

- To match bare `/acme` too, add a second rule. `acme**` would also match `acme-evil`.
- A host that's only wildcards (`**`, `*.*`) is legal, but warns: it matches everything.
- A narrow path limits what the agent can do, not what it can leak. One `*` segment still
  carries any base64 blob ([THREAT-MODEL.md](./THREAT-MODEL.md#allowlists-bound-who-not-what)).

## Ports

**No port means 80 and 443. Any other port must be listed.**

| Pattern | Ports |
|---|---|
| `foo.com/**` | 80, 443 |
| `foo.com:8443/**` | 8443 only |
| `foo.com:443,8080/**` | 443 and 8080 |
| `foo.com:*/**` | any |

## Options

**By default a rule allows GET only, with no body, no query params, and baseline headers.
Each option widens one of those.**

<!-- Mirrors the Options list in mitmaddon/rule_engine.py's docstring. Update both. -->
| Option | Allows | Default |
|---|---|---|
| `GET POST …` | these methods | GET |
| `max_body=<size>` | a request body up to `<size>`: bytes, or `k`/`m` | no body |
| `q:*` | every query param | all stripped |
| `q:<name>=<value>`, `q:<name>~<regex>` | that param, if its value matches. Others are stripped. | all stripped |
| `h:*` | every header, `Authorization` included | baseline only |
| `h:<name>=<value>`, `h:<name>~<regex>` | that header, if its value matches | baseline only |
| `inject_auth=<name>` | swaps in `SILKGATE_EGRESS_SECRET_<NAME>`, if the guest sends that header | no swap |
| `capture=anthropic` | records the response ([PROXY.md](./PROXY.md#capture)) | no capture |

- Options split on whitespace, so a value can't hold a space. Write `\s` in a regex.
- `inject_auth` never adds a header. It only replaces one the guest sent.

## Headers

**A header goes through only if the baseline or an `h:` option allows it, and its value
matches.**

<!-- Mirrors _BASELINE_SPECS in mitmaddon/rule_engine.py. Update both. -->
| Baseline header | Allowed value |
|---|---|
| `host` | a hostname and optional port, ≤ 253 chars |
| `content-type` | a MIME-like value, ≤ 64 chars |
| `content-length` | digits, ≤ 10 |
| `transfer-encoding` | exactly `chunked` |

Everything else is stripped unless a rule allows it: `user-agent`, `accept`, `range`,
`cookie`, `authorization`, any `x-*`. A `h:` option overrides the baseline for its rule.

For example, GitHub's REST API refuses requests without a `User-Agent`:

```text
api.github.com/repos/acme/app/**  GET  q:*  h:user-agent~.+  h:accept~.+
```

## Normalization

**The engine normalizes hosts and paths before it matches, the same way for patterns and
requests.**

Hosts:

1. Reject null, whitespace, CR, LF, `%`, `@`, `[`, `]`.
2. Split off an optional `:port` (digits only).
3. Lowercase, and strip a trailing dot.
4. Reject non-ASCII. Use punycode (`xn--…`), which blocks homographs.
5. Reject IP literals: only domains can be allowed.
6. Require strict DNS labels: `[a-z0-9-]`, ≤ 63 each, ≤ 253 total. `_` is opt-in, for
   internal names.

Paths: drop `#fragment` and `?query`, percent-decode once, then resolve `.` and `..`. So
`acme/x/../../other` becomes `/other`, and doesn't match `acme/**`. Double-encoded input
is a known residual.

## Settled decisions

**Don't change these without a test that proves the change safe.**

1. A host with no `/` matches every path.
2. The default method is GET.
3. `**.` matches the apex. `*.` doesn't.
4. A path `**` matches an empty path.
5. Query params, headers, and bodies are denied unless a rule allows them, for every method.
   Header allows constrain the value, not just the name.
6. Hosts normalize to `[a-z0-9.-]`, `_` is opt-in, and IP literals are refused.

## What the addon does

**The engine only matches. The mitmproxy addon enforces**
([`mitmaddon/proxy_addon.py`](../mitmaddon/proxy_addon.py)): TLS termination, SNI must equal
Host, header and query stripping, body caps, secret injection, the audit log, and refusal of
anything it can't decrypt.
