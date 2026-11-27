# Proxy operations

Read this to run, inspect, and debug the shared proxy, and to find what silkgate keeps on
the host.

## One proxy, many sessions

**All sessions share one `mitmdump` process with silkgate's addon loaded. Each session
claims one of its ports.**

- The first `up` or `run` starts it, detached. It's ready once every pool port accepts.
- The `down` that ends the last session stops it.
- It binds loopback only, `127.0.0.1` and `::1`. `SILKGATE_PROXY_BIND=<addr>[,<addr>]`
  replaces those addresses, if your platform routes guests through a bridge.
- It runs with `--set rawtcp=false`, so a tunnel that isn't TLS is refused, not passed
  through.

After you edit the addon, stop the proxy before the next launch: `down` the last session,
or kill the pid in `~/.silkgate/proxy.json`. mitmdump hot-reloads an edited addon into the
old process, with the old environment and old modules.

Pinned by: `test/test_proxy_lifecycle.py`.

## The port pool

<!-- Mirrors POOL_SIZE and DEFAULT_BASE_PORT in cli/silkgate. Update both. -->
**The proxy listens on 16 consecutive ports, normally 8090 to 8105.**

- The scan starts at 8090, or at `--port`. A taken port anywhere shifts the whole pool to
  the next free 16-port range.
- Each session claims its port with a marker file, so concurrent `up`s never collide.
- A guest's port is fixed at creation. So while any session survives, a proxy restart
  reuses the recorded pool exactly, and fails if one of its ports is now taken.

Pinned by: `test/test_proxy_lifecycle.py`.

## Port as session identity

**The port a request arrives on proves which session sent it.**

Each guest's Tier 1 rule allows only its own port:

```text
msb … --net-default-egress deny --net-rule "allow@host:tcp:<port>"
```

microsandbox enforces that on the host, so a guest can't reach another session's port.
The addon maps the port to that session's ruleset, `~/.silkgate/sessions/<name>/rules.txt`.

An unknown port, a missing session, or a broken ruleset denies the request with reason
`no session for port`. It never falls through to another session's rules.

Pinned by: `test/test_addon.py`.

## The control socket

**The CLI controls the proxy over `~/.silkgate/proxy.sock`, never over a network port.**

A guest can reach its proxy port, so a control endpoint there would need its own auth. No
guest can reach a host unix socket. The socket is mode `0600` and speaks line-delimited
JSON: `ping`, `set_secret`, `list_secrets`.

## Secrets

**A credential goes from your shell to proxy memory, scoped to one session. It never enters
a guest.**

```text
SILKGATE_EGRESS_SECRET_<NAME>="<Header>: <value>"      in your shell
  └─ up / secret set ──▶ set_secret over the socket, with the session name
       └─ proxy memory, keyed by session ──▶ a rule's inject_auth=<name> spends it
```

- The proxy replaces a header only when the guest already sends it. So the guest holds a
  dummy that sends that header, picked by the profile's `guest_credential` lines
  ([PROFILES.md](./PROFILES.md#profileconf-keys)).
- Each `up` reads the variable from its own environment. A session never inherits a
  secret another session pushed.
- The value never appears in argv, on disk, or in a log. `list_secrets` returns names.
- A missing or malformed secret warns at `up`. The session starts, and matching requests
  are denied.
- That deny looks like any policy miss to the guest. Only the audit record says
  `missing secret`.
- The standalone `silkgate proxy` reads `SILKGATE_EGRESS_SECRET_*` from its own environment.
  Sessions never do.

Pinned by: `test/test_addon.py`, `TestGuestCredential` in `test/test_cli_validation.py`.

### After a proxy restart

**Secrets live in proxy memory only, so a proxy restart loses them.**

Sessions survive the restart on disk, but their secrets don't. Requests that need one fail
closed. Recover in either of two ways:

```sh
silkgate down foo && silkgate up --name foo --with claude  # up re-pushes from its env
silkgate secret set anthropic --session foo                # or push into the live session
```

| You see | Cause |
|---|---|
| a 401 from upstream | the proxy injected a wrong value |
| a deny with reason `missing secret` | the proxy holds no value |

## The audit trail

**Every decision writes one JSON line. The proxy also mirrors it into a machine-only events
file.**

A request has one record (a deny) or two (an allow, then its `response`), joined by flow
id:

```json
{"decision": "allow", "session": "foo", "listen_port": 8091, "method": "POST",
 "host": "api.anthropic.com", "path": "/v1/messages", "injected": "anthropic", "exec": "239f1a6e"}
{"decision": "response", "id": "…", "status": 200, "duration_ms": 1840}
```

<!-- Mirrors _audit in mitmaddon/proxy_addon.py. Update both. -->
| Field | Meaning |
|---|---|
| `host`, `port` | where the proxy dials, never the guest's claim |
| `claimed` | a `Host:` header that disagrees with the destination |
| `injected` | the secret that replaced a header the guest sent |
| `inject_skipped` | a secret the rule names, unused because the guest sent no such header |
| `stripped_query`, `stripped_headers` | names the proxy removed |
| `exec` | the `silkgate exec` that sent it, from a header the proxy strips |
| `reason` | the rule that matched an allow, or why a deny happened |
| `status`, `duration_ms`, `ttfb_ms`, `request_bytes`, `response_bytes` | on the `response` record |

- Bodies and credential values are never written.
- A failed write to either file blocks the request: the trail isn't best-effort.
- `logs/proxy-*.log` mixes in mitmdump's own output. `logs/events-*.jsonl` holds request
  records only, and it's what `silkgate ui` reads.

Pinned by: `test/test_addon.py`.

## Capture

**A rule with `capture=anthropic` records the model's responses. Capture never changes a
flow.**

- Records go to `logs/capture-*.jsonl`: `turn_start` (model, tokens), `content_block`
  (text, tool calls), `turn_end` (stop reason).
- Thinking blocks are recorded as lengths only.
- A secret in a response is stored redacted, with a `secret_sighting` record that names the
  pattern.
- Any capture failure leaves the flow, its byte counts, and its audit record unchanged.

Pinned by: `test/test_cli_journal.py`, `test/test_capture_decoder.py`.

## Host state

**Everything lives under `~/.silkgate/`, created on the first `run` or `up`.**

| Path | Holds |
|---|---|
| `proxy.json` | the live proxy: pid, port pool, log and events paths |
| `proxy.sock`, `proxy.lock` | the control socket, and the start/stop lock |
| `sessions/<name>/` | a live session: `meta.json`, `rules.txt`, `context.md`, `settings.json` |
| `archive/<sid>/` | an ended session (below) |
| `ca/egress-ca.pem` | the proxy's CA certificate, never its key |
| `logs/proxy-*.log`, `logs/events-*.jsonl` | the audit trail, one pair per proxy start |
| `logs/capture-*.jsonl` | captured model responses |
| `logs/proxy-*.rules`, `logs/standalone-*.rules` | the ruleset a `verify` or `silkgate proxy` ran with |
| `docker/` | silkgate's own `DOCKER_CONFIG`, so builds never call your credential helper |

### The archive

**An ended session moves to `archive/<sid>/`. Nothing is silently deleted.**

The sid is a UTC stamp, the session name, and six hex characters, so sorting by name sorts
by time. `silkgate ls -a` lists archives, and the audit UI reads them.

<!-- Mirrors _teardown_session and _SNAPSHOT_TAIL_LINES in cli/silkgate. Update both. -->
| File | Holds |
|---|---|
| `meta.json` | the session's metadata, plus `sid`, `ended`, `last_rc` |
| `rules.txt` | the ruleset the proxy enforced |
| `journal.jsonl` | one record per event: `created`, `exec_start`, `exec_end`, `harvest`, `frozen`, `resumed`, `killed`, `down` |
| `output.log` | the last 20000 lines of guest output, at most 8 MiB |
| `brief.md`, `briefs/<exec_id>.md` | the session's brief, and each exec's |

- The journal records each exec's argv, prompt included: it exists to reconstruct a
  session. Env vars appear as names only.
- The journal is mode `0600`, and no guest can read `~/.silkgate`.
- A failed archive step warns, and the teardown completes. A sandbox that can't be removed
  keeps its session, and the command fails.
- `SILKGATE_SNAPSHOT_TAIL_LINES` and `SILKGATE_SNAPSHOT_MAX_BYTES` change the
  `output.log` bounds.

Pinned by: `test/test_cli_journal.py`.

### Retention

**A file goes only when it's both older than its age limit and beyond its newest-count
guard. Each removal prints a line.**

<!-- Mirrors LOG_RETAIN_*, CAPTURE_RETAIN_DAYS, and ARCHIVE_RETAIN_* in cli/silkgate. Update both. -->
| Kind | Age | Keeps at least | Knob (`0` keeps everything) |
|---|---|---|---|
| `proxy-*.log`, `events-*.jsonl`, `*.rules` | 30 days | newest 20 per kind | `SILKGATE_LOG_RETAIN_DAYS` |
| `capture-*.jsonl` | 7 days | newest 20 | `SILKGATE_CAPTURE_RETAIN_DAYS` |
| `archive/<sid>/` | 30 days | newest 50 | `SILKGATE_ARCHIVE_RETAIN_DAYS` |

- The live proxy's files are never removed.
- Capture keeps less, because it holds conversation content.

Pinned by: `test/test_cli_journal.py`, `test/test_cli_logs.py`.
