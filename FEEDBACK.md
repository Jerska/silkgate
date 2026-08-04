# Review findings

A blunt external review of the codebase, filtered: every claim below was re-verified against the
code or by running it, and anything that did not survive that is recorded in
[Not upheld](#not-upheld) rather than dropped, so the same ground isn't re-litigated later.

Reproductions live in [`test/repro/`](test/repro/) — each prints what it observed beside what it
should have. They are the seed for the test suite this codebase does not have; `addon_host_spoof.py`
in particular should become `test/test_addon.py` in CI.

Status labels: **verified** (I ran it), **code-read** (follows from the source, not executed),
**unproven** (plausible, and the reproduction does not yet demonstrate it).

---

## 1. Critical: policy is decided from a header the guest controls

**verified** · `mitmaddon/proxy_addon.py:278` · repro: `test/repro/addon_host_spoof.py`,
`test/repro/host_spoof_live.sh`

`request()` takes the host from `flow.request.pretty_host`, which prefers the client's `Host:`
header. mitmproxy connects to `flow.request.host`, which for an absolute-form request line comes
from the URL. Policy is computed about one host; the connection goes to another.

Live, through a real proxy carrying only the `node` profile's rules:

| request | result |
|---|---|
| `http://example.com/` | **403** — correctly denied |
| `http://example.com/` with `Host: registry.npmjs.org` | **301 from example.com** — allowed |

and the audit log recorded `{"decision":"allow","host":"registry.npmjs.org","path":"/"}` for the
second one: a line naming a host the request never reached.

In-process against the `claude` profile's rule, with a sentinel secret, a POST to
`evil.example:80` carrying `Host: api.anthropic.com` is **allowed and has the host-held credential
injected into it**. That falsifies the strongest claim in the docs — "Full code execution in the
guest cannot steal the API key — it isn't there" (`doc/ARCHITECTURE.md`) — because the guest does
not need to steal the key, it can ask the proxy to attach it to a request bound for anywhere.

Three consequences worth stating separately, because fixing the host check fixes all of them:

- **The allowlist is void**, not merely leaky: arbitrary host, path, method and body up to
  `max_body`, with the response returned to the guest. That is bidirectional C2, not just exfil.
- **The IP-literal guard in `normalize_host` is decorative** — a domain goes in the header and an
  IP in the URL, which also puts host loopback services in reach.
- **The audit trail is guest-forgeable**, so it cannot answer "where did this actually go".

The SNI check does not help here: it is skipped whenever there is no TLS connection to the proxy,
which is the normal case for a plaintext absolute-form request. Case 5 of the reproduction shows
the check working when SNI exists — so the guest simply chooses not to use TLS.

**Fix.** Match on the destination and require the claimed authority to agree with it:

```python
host = normalize_host(req.host)                       # what mitmproxy will dial
if host is None:                       deny("invalid host")
claimed = req.host_header
if claimed and normalize_host(claimed) != host:  deny("Host/destination mismatch")
if sni and normalize_host(sni) != host:          deny("SNI mismatch")
rule = ruleset.match(host, req.path, req.method, req.port)
```

The `Host`-agreement check subsumes the SNI check and closes the plaintext path that has no SNI to
compare. Then log `req.host` in the audit record, not the header.

`doc/THREAT-MODEL.md` predicted this exact bug class — "the matcher must normalize the host
identically to how the connection layer resolves it … **this is the most likely place this proxy
gets broken**". The normalizer is fine; the *input* to it was wrong, and no abstraction can catch
that. Hoisting `normalize_host` into the engine so it "cannot be skipped" defended the wrong step.

---

## 2. `CONNECT` is never evaluated and never logged

**verified** (unevaluated) · **unproven** (exploitable) · repro: `test/repro/connect_probe.sh`

The addon implements `request` and `responseheaders`. mitmproxy dispatches `CONNECT` through
`http_connect`, which nothing here implements, so a `CONNECT` to a host no rule allows is answered
`HTTP/1.1 200 Connection established` with **zero audit decisions recorded**. An unevaluated,
unlogged authority in the one component whose job is to evaluate and log authorities.

What I could not reproduce: bytes actually flowing through that tunnel. Two attempts — a
TLS-looking first byte and a plainly non-HTTP one — delivered nothing to a loopback listener, so
the escalations that would make this critical (a raw tunnel to any host:port, reaching another
session's listener, or host loopback services) are **unproven**. `rawtcp` does default to `True`,
so the exposure is real in principle; treat the severity as open until the repro shows data.

Fix regardless: implement `http_connect`, match `req.host:req.port` against the ruleset there, and
start mitmdump with `--set rawtcp=false`. `doc/THREAT-MODEL.md` already commits to this — "fail
closed on anything undecryptable … raw CONNECT tunnels" — so today the code contradicts the doc.

---

## 3. The proxy listens on every interface

**verified** · `cli/silkgate:603` (mode args)

`listen_host` defaults to `''` and nothing overrides it; our own startup log says
`HTTP(S) proxy listening at *:8090`. All 16 pool ports are open to the LAN, offering anyone on the
network the session's allowlist and, via finding 1, credential injection. The threat model
considers only the guest as adversary and never mentions the host's other interfaces.

Bind explicitly. One experiment is needed first: microsandbox reaches the host via
`host.microsandbox.internal`, so find which address that resolves to and bind that, not
`0.0.0.0` and probably not only `127.0.0.1`.

---

## 4. The enforcement code has no tests, and that is why 1–3 exist

**verified**

`rule_engine.py` self-tests the matcher (54/54) and `test/verify_guest.sh` tests Tier 1 in a real
guest. `proxy_addon.py` — every allow/deny decision, the credential injection, the audit record —
has never been executed by a test. The bypass in finding 1 took a 20-line harness to find.

The asymmetry is the root cause: **the layer that already works is the one with a test.** Wiring
`test/repro/addon_host_spoof.py` into CI as `test/test_addon.py`, with the honest allow, the honest
deny, the spoof, the spoof-with-injection, the SNI case, an oversized body, and header/query
stripping, is worth more than every other item in this document.

---

## 5. Command-line arguments become host code execution at build time

**verified** · `cli/silkgate:372` · repro: `test/repro/build_injection.py`

`Profile.__init__` validates the profile *name* and never the version. Both the version and
`--base` are interpolated into a generated Dockerfile:

```
--with 'node@1" ; echo PWNED-AT-BUILD-TIME ; #'
  ->  RUN VERSION="1" ; echo PWNED-AT-BUILD-TIME ; #" sh /silkgate/setup-node.sh

--base 'debian:bookworm-slim\nRUN echo INJECTED-DIRECTIVE'
  ->  FROM debian:bookworm-slim
      RUN echo INJECTED-DIRECTIVE
```

`docker build` runs as root on the host, with the host's network, outside the proxy. This matters
because these command lines are composed by agents for a human to approve, and `--with node@22.11.0`
is exactly the token a reviewer's eye slides over. Validate the version against
`[A-Za-z0-9][A-Za-z0-9._+-]*` and the base against an image-reference charset, at parse time.

---

## 6. `--with git` cannot clone

**verified** · `profiles/git/rules.txt` · repro: `test/repro/git_profile_clone.sh`

```
remote: GitHub.com no longer supports git over dumb-http
fatal: unable to access 'https://github.com/octocat/Hello-World/': error: 403
```

Smart-HTTP clone is `GET /org/repo/info/refs?service=git-upload-pack` then
`POST /org/repo/git-upload-pack`. The rule declares no `q:`, so every query parameter is stripped
and GitHub answers the resulting dumb-http request with 403; and phase two needs `POST` with a
body, which the rule denies twice over. A profile that installs a tool and forbids its primary use.

Worse, the guest sees *GitHub's* 403, which the generated sandbox brief teaches it to read as
silkgate policy — so the failure is misattributed. Keep push denied; that part of the comment is
right.

---

## 7. Rule-engine defects

**verified** · repro: `test/repro/engine_claims.py`

| finding | observed |
|---|---|
| `normalize_host` strips before the bad-character check | `"github.com\n"` → `"github.com"`, though `doc/DSL.md` says reject |
| compiled path patterns anchor with `$`, which matches before a trailing newline | `/your-org/repo\n` matches rule `github.com/your-org/repo` |
| `_parse_size` accepts negatives | `max_body=-5` parses, then denies *every* request with `body 0B > max_body -5B` |
| `_parse_ports` does not range-check | `a.com:99999999` parses into an unmatchable rule |
| two independent port strippers on one string | `foo.com:443:8080/**` silently parses as ports `{8080}` |
| a bare `**` host is a total allow-all | `--rule '**/** GET POST h:* q:* max_body=100m'` is a one-flag opt-out of the product, silently |

Use `fullmatch` with `\Z`, reject negative sizes and out-of-range ports at parse time, and warn
loudly when a composed ruleset contains a bare-glob host, `h:*`, or `q:*`.

---

## 8. Correctness and robustness, by inspection

**code-read** — plausible, not executed; each needs a test before and after any fix.

- **`pick_port` TOCTOU** (`cli/silkgate:664`). Ports are claimed by reading other sessions'
  `meta.json`, but the winner's meta is not written until later in `_provision_session`. Two
  concurrent `up`/`run` — precisely what a parent agent fanning out sandboxes does — can pick the
  same port; `SessionRegistry` then maps it to whichever directory `listdir` yields last, so one
  guest is policed by another's ruleset and can spend its secrets. This falsifies "the port is
  spoof-proof session identity" without any exotic technique. Claim the port by atomically
  creating the session directory *before* choosing, and retry on collision.
- **No locking on proxy lifecycle** (`_maybe_stop_proxy`, `ensure_proxy`). `down <last>` racing an
  `up` can kill the proxy under a starting session.
- **PID reuse** (`proxy_alive`, `stop_proxy`). `os.kill(pid, 0)` proves only that *something* holds
  that pid. After an unclean exit, `proxy.json` survives and the pid may be recycled — so
  `ensure_proxy` can believe a dead proxy is alive, and `stop_proxy` can SIGKILL an unrelated
  process. Verify identity via the control socket's `ping` before trusting or killing.
- **`exec`, `attach` and `down` skip `_validate_name`** (only `up` and `logs` call it, confirmed by
  grep), then trust whatever `meta.json` they find — including `meta["sandbox"]` passed to `msb`
  argv and `meta["name"]` passed to `rmtree`. `/workspace` is guest-writable, so a guest can plant
  a `meta.json`. One line in three places, plus asserting `meta["name"] == args.name`.
- **Session dir removed even when `msb rm` fails** (`_teardown_session` warns and continues),
  freeing the port for reuse while a live guest still has L3 access to it.
- **`msb create` failure leaves the sandbox behind**, so the next `up` with that name collides.
- **The catch-all in `request()` does work that can itself throw** — `_deny` → `_audit` →
  `json.dumps` → `Response.make`. mitmproxy logs an addon exception and continues, so anything
  escaping the hook **forwards the request unfiltered**. Set a static 500 response first, then log.
  `responseheaders` has no guard at all.
- **Control socket is chmod'ed after bind** (`proxy_addon.py:217`), leaving a window at the default
  umask. Bind inside a `0700` directory, or bind-then-rename.
- **`running()` unlinks the socket path unconditionally**, so a second proxy silently steals a live
  one's control channel, and the orphaned bind error is swallowed by `ensure_future`.
- **`set_secret` accepts any header name**, including `Host` — a mis-set secret could rewrite the
  routing-relevant header. Validate against a token charset, and cap the value length.
- **A missing secret returns 500 where everything else returns 403**, giving the guest an oracle
  for which secrets the host holds.

---

## 9. Design and documentation

- **The audit record is unfit for its stated purpose.** It carries decision, method, host, path and
  session. mitmdump prefixes each line with a time of day but **no date**, and the record has no
  destination-actually-dialed, no response status, no byte counts, and no client port. The docs
  accept exfil-within-an-allowed-channel as residual and lean on "full audit trail for
  post-incident review"; the trail cannot answer "how much left, and when". Fix the record before
  fixing `logs --since`, which is unusable for the same reason.
- **Secrets are process-global while sessions are not.** `SecretStore` lives in the shared
  mitmdump, so any later session whose rules name `inject_auth=anthropic` gets a key an earlier one
  pushed. Documented as a convenience; it is also a cross-session capability grant. Scope secrets
  per session.
- **Nothing asserts at runtime that Tier 1 is in effect**, in a design that stakes everything on an
  unpinned pre-1.0 `msb` flag grammar. If a future `msb` parses `--net-rule` but means something
  laxer, every session silently runs with no containment and silkgate reports success. A one-second
  in-guest probe after `create` (`exec 3<>/dev/tcp/1.1.1.1/443` must fail) turns the project's
  single load-bearing external assumption into an enforced invariant. **This is the highest-value
  item after finding 1.**
- **`--workspace` has no guard at all.** It is mounted rw and is the only host path; the skill's
  own gotchas explain that mounting a repo hands the guest `.git`, which is host code execution via
  hooks or `core.fsmonitor` the next time a human runs git there. Refuse `$HOME` and `/`, and
  refuse (or require a flag for) a directory containing `.git`. Documentation is not a control.
- **`profiles/claude/rules.txt` uses `h:* q:*`**, switching off the deny-by-default header and
  query machinery for the one profile that matters — so no shipped profile exercises it. `/**` also
  grants the Files and Batches APIs and anything added to that host later. Enumerate the headers
  the harness needs (`anthropic-version`, `anthropic-beta`, `content-type`, `accept`) and the paths
  it uses. Note deliberately that `platform.claude.com` receives the same injected key.
- **An empty allowlist is refused, though it is the safest policy silkgate can express.** `run` with
  no `--with` and no `--rule` dies with `no egress rules`, so the most locked-down guest the tool can
  offer — reach nothing — is the one configuration it will not start. Anyone wanting an offline guest
  has to invent a rule that matches nothing (`--rule 'example.invalid/** GET'`), and that artifact is
  strictly worse than an empty ruleset: it survives in shell history and README snippets reading like
  an allowance. Compose the empty ruleset and let default-deny do its job.
- **`probe` is quarantined by a comment only.** It opens the Debian mirrors; make `cmd_*` refuse it
  outside `verify`.
- **`cmd_verify` accepts any `passed > 0` with `failed == 0`**, so a run where five of seven checks
  SKIP still prints "containment holds" — and `verify_guest.sh` scores "blocked = PASS" on *any*
  failure, so a missing tool is indistinguishable from containment. Assert an expected check set:
  `--full` means exactly seven ran.
- **`test/linux/Dockerfile` installs mitmproxy and msb unpinned** (`curl … | sh`) in a repo whose
  docs insist on pinning msb, so "verified against 0.6.8" is not reproducible from it.
- **Docs contradict the code** in several places: `ARCHITECTURE.md` promises DLP and upload-size
  caps that do not exist, lists CA env vars (`SSL_CERT_FILE`, `PIP_CERT`) the base layer does not
  set, and its diagram grants `DNS → host resolver` while the README correctly warns never to open
  UDP/53. `rule_engine.py`'s docstring documents an option `query` that is spelled `q:*`.
- **`cli/silkgate` is one 1,500-line file** holding policy composition, image synthesis, a docker
  credential-helper workaround, proxy lifecycle, session state, a PTY/FIFO relay with an ANSI
  stripper, two log followers and a socket client. The relay is the most intricate code in the repo
  and the least security-relevant, and it sits beside secret handling. Split it so the
  security-relevant parts fit in one sitting.
- **`SessionRegistry` is over-built** for what it saves: two mtime-keyed caches, a failure cache,
  and a rescan-on-miss retry papering over a race, to avoid a stat and a small parse per request.
  Its cache is also keyed by `(name, mtime)`, so `down foo` + `up foo` inside one mtime tick serves
  the old ruleset.
- **Dead code:** `build_image(quiet=…)` is never passed `True`; `msb_argv(pull_never=True)` has no
  caller using the default; `Profile.requires` is handled but no profile declares it; `check_secrets`
  survives only for `cmd_proxy`, duplicating `_push_secrets`'s error message.
- **`_relay`'s `\x1e` tag is guest-forgeable**, so stream separation is a convenience, not a
  property: a guest can put lines on the parent's stderr or fabricate well-formed `stream-json`
  events on its stdout. The skill should say so, since it recommends parsing that stream.
- **`check_env` blocks the four proxy variables but not `NO_PROXY`/`no_proxy`**, which achieve the
  same footgun.

---

## Not upheld

Recorded so they are not re-investigated:

- **"The audit record has no timestamp."** The record has no timestamp *field*, but mitmdump
  prefixes every line with one. The real gap is narrower: time of day without a date.

### Withdrawn: two entries that were dismissed for a bad reason

Both of the mitmproxy-option entries that used to sit here were wrong, and wrong the same way. They
were dismissed on the grounds that the options "do not exist in 12.2.3", which came from
interrogating a bare `options.Options()`. Options are registered by the addons, so a bare `Options`
knows almost none of them; on a running `DumpMaster` all three are present:

```
rawtcp              = True
connection_strategy = 'eager'
body_size_limit     = None
stream_large_bodies = None
```

The lesson is about method, not mitmproxy: a claim of absence needs the interface the product
actually uses. What survives of each:

- **`connection_strategy` is `eager`,** but `HttpConnectHook` fires *before* the upstream connection
  is opened, so it was never true that the connection precedes every hook. The accurate statement is
  that with no `http_connect` hook, every CONNECT — allowed or not — reached an eager upstream
  connect and resolve. Denied CONNECTs now answer 403 without one (observed as 403 rather than 502).
- **`stream_large_bodies` is a live footgun, not an OOM concern.** If it is ever set,
  `check_body_size` sets `flow.request.stream = True` and `start_request_stream` sends the request
  headers upstream *before* `HttpRequestHook` — so for any body over the threshold, the host match,
  the credential injection, the header stripping and `max_body` are all bypassed and the request is
  already on the wire. Nothing sets it today and nothing should; a `configure` hook refusing to load
  when it is set would make that a control rather than a convention. `body_size_limit` is the
  opposite: it aborts with a protocol error, and is the knob that would enforce `max_body` before the
  bytes are buffered in the shared proxy.

---

## Found while fixing these

Discovered on the host while reconciling the fixes; each was observed, not reasoned.

- **A guest's TCP connect to the host proves nothing.** microsandbox's guest→host NAT completes the
  handshake inside the VMM, so `exec 3<>/dev/tcp/host.microsandbox.internal/8090` reports success
  with **no listener on the host at all** — the failure only appears once data flows (`curl` exit 56,
  connection reset). Any probe that concludes "the proxy is reachable" from a connect is unsound,
  which is how a new positive control in `verify_guest.sh` came to pass while the proxy was
  unreachable. Prove reachability with an answer, not a handshake.
- **The guest resolves the host alias to IPv6 first.** `/etc/hosts` in the guest maps
  `host.microsandbox.internal` to both `172.16.2.5` and an `fd42::` address, and `getaddrinfo`
  returns the v6 one first, so a modern `curl` uses it. A loopback bind must therefore cover both
  families — a `127.0.0.1`-only listener leaves guests connecting to `[::1]` on the host, where the
  VMM's local handshake turns "nothing is listening" into what looks like a proxy refusal.
- **msb intercepts all of TCP/53.** Every destination on port 53 — including unroutable TEST-NET
  addresses — returns an identical 31-byte `REFUSED` from msb's own stub, so port 53 is not an egress
  channel. It is also a trap for a containment probe: a reply arrives, and reading a reply as proof
  of egress inverts the conclusion.
- **Dropping `--net-default-egress deny` does not open egress**, so it is not a way to test that the
  Tier-1 assertion refuses a leaking guest: msb denies by default once any `--net-rule` is present,
  and the sandbox stays contained. `--net-default-egress allow` does open it, and the probe catches
  that — verified, session refused and torn down.
- **A denied HTTPS destination now fails at CONNECT, not in-band.** The guest sees
  `curl: (56) CONNECT tunnel failed, response 403` instead of a 403 body, because the authority is
  refused before a tunnel exists. Still legible — it names the 403 — but every consumer that reads
  a policy denial out of a response body needs to know it moved, `verify_guest.sh` check 2 included.

---

## Status

Findings 1–7, the Tier-1 assertion and the reachable parts of §8 are fixed, in six commits — one per
area, each carrying the test that fails against the code it replaces. `git log` is the detail; what
matters here is which claims are now closed and which are not.

Closed and verified live: the host spoof (the spoof returns 403 and the credential stays on the
host, and the audit line names the destination with the forged authority beside it), CONNECT
evaluated and logged, the proxy off the LAN, build-argument injection, session-name traversal, the
workspace guard, `probe` confined to `verify`, the port-claim race (five concurrent `up`s take five
distinct ports, repeatedly), the engine's six parse defects, `--with git` cloning while a push still
dies at phase one, an empty allowlist as a legal configuration, and the Tier-1 assertion in both
directions — a healthy session passes silently, a guest with `--net-default-egress allow` is refused
and torn down.

Still open, in the order they matter:

1. **The audit record** (§9) — no date, no response status, no byte counts. It now names the host
   actually dialled, which was the falsehood; the gaps that make it unfit for "how much left, and
   when" remain.
2. **Per-session secret scoping** (§9). `SecretStore` still lives in the shared mitmdump, so any
   later session naming `inject_auth=anthropic` gets a key an earlier one pushed.
3. **`profiles/claude/rules.txt` still uses `h:* q:*`** (§9), so no shipped profile exercises the
   deny-by-default header and query machinery. Tightening it needs the header set the harness
   actually sends, which is an experiment, not a guess.
4. **A `configure` hook refusing `stream_large_bodies`** — see the withdrawn entry above.
5. **CI.** Linux runners have KVM, so the four new test files, the engine self-tests and
   `silkgate verify` can all run on push. The tests exist now; nothing runs them automatically.
6. **The misattributed 403** (§6). A guest reads GitHub's own dumb-http 403 — and now a refused
   CONNECT — as silkgate policy, because the brief teaches it to. A denial the proxy issues and one
   the destination issues should not look alike.
7. The remaining §8 robustness items and the §9 documentation and structure list, including
   splitting `cli/silkgate`, which is now ~1,900 lines.

### Wanted, beyond the findings

Not review findings — work the project owner asked for, recorded here so it sits beside the rest.

- **One test suite.** Five test files, the engine's in-file self-tests, `test/repro/` and the in-guest
  `verify_guest.sh` are four genres with four entry points. One command should run everything runnable
  on the host, skipping rather than failing when mitmproxy is absent, and saying what it skipped. The
  engine's self-tests stay in the module — that is why the engine was the one component with tests and
  the one that worked.
- **Does `verify` check enough?** Seven checks plus a control. Not covered: TCP/53 (check 4 tests
  UDP-based *resolution*, so the interception this document records in *Found while fixing these* is
  itself unasserted), UDP egress other than 53, host ports other than the session's proxy port
  (§1 named host loopback services specifically), a LAN address on the proxy port now that the bind is
  loopback, the address family the guest actually picks, and msb's DNS-rebind protection. Cross-session
  isolation cannot be checked from a standalone guest and wants a session-level test instead.
- **`run` should be the documented default.** The skill presents `run` and sessions as peers. Boot is
  ~0.3s, so a warm VM buys little; `run` is one command rather than three and cannot leave a session
  behind. Two batches of parallel agents were run as sessions and neither used `--resume` or
  `silkgate logs`, so the machinery cost teardown and returned nothing.
- **A two-way conversation with the guest**, over `--input-format stream-json`, so a host agent can
  answer a guest mid-task rather than only reading its last message. One-off `run` stays the default.
  The blocking unknown is stdin, not the JSON: the relay deliberately runs the guest command with
  `</dev/null` (no isatty, no 3s stall, clean stream), and whether `msb exec` forwards stdin at all is
  unestablished — `silkgate logs` exists because `msb exec` does not stream *output* live either. The
  security framing needs settling first: the guest's output is already an injection channel and the
  relay's `\x1e` tag is guest-forgeable, so a conversational channel makes forgeable protocol
  structural. Either the framing resists forgery, or every event is untrusted data and never an
  instruction — and the skill has to say which.
