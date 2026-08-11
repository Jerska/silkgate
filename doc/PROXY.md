# Proxy operations

Read this to run, inspect, and debug the shared proxy that serves every session.

This document covers operations only. [ARCHITECTURE.md](./ARCHITECTURE.md) holds the concepts
and the glossary (guest, session, profile, Tier 1, Tier 2). [DSL.md](./DSL.md) holds the rule
language. [THREAT-MODEL.md](./THREAT-MODEL.md) holds the threat analysis.

## The shared-proxy model

**All sessions share one proxy process, and each session claims one listener port.** The
process is one `mitmdump` (mitmproxy's headless runner) with silkgate's addon
([`mitmaddon/proxy_addon.py`](../mitmaddon/proxy_addon.py)) loaded — "the addon" below.
`silkgate up` starts it the first time a session needs it, detached from the shell. It waits
until every pool port accepts connections, then records the proxy in
`~/.silkgate/proxy.json`. `silkgate down <name>` ends a session, and the `down` that ends
the last session also stops the proxy. `test/test_proxy_lifecycle.py` pins the lifecycle:
start, readiness, teardown, and the races between them.

The proxy binds loopback by default, on both address families (`127.0.0.1` and `::1`), and
never the LAN. If your platform routes guests through a real bridge address, set
`SILKGATE_PROXY_BIND=<address>[,<address>]` — the override replaces the default addresses.
The proxy also starts with `--set rawtcp=false`, so a tunnel it cannot read as TLS is
refused instead of passed through
(`test_start_shared_proxy_binds_loopback_and_disables_rawtcp`).

If you edit the addon or rename one of its env vars, retire the live proxy deliberately —
end the last session with `down`, or stop the pid recorded in `proxy.json` — so the next
launch starts a fresh process. mitmdump hot-reloads `-s` scripts when their mtime changes,
so a long-lived proxy silently picks up addon edits into a process that keeps its old
environment and its old `sys.modules`.

## The port pool

**The proxy listens on 16 consecutive ports, normally 8090 to 8105.** Each pool port gets
one `--mode regular@<addr>:<port>` listener per bind address. The scan starts at the base
port (normally 8090), so a squatter anywhere in a candidate range shifts the whole pool to
the first fully-free 16-port range above it
(`test_start_shared_proxy_skips_squatted_base_and_finds_next_range`). Each session claims
one port from the pool the moment the port is picked, by a marker file, so concurrent `up`
commands get distinct ports (`test_concurrent_pick_port_yields_distinct_ports`).

A restart re-picks the pool only when no session survives. A guest's port is fixed at
creation, because its proxy URL and its Tier-1 net-rule both name it, and a moved pool
strands every survivor on a port that any later process can bind and answer. While any
session or port claim survives, a proxy restart therefore reuses the recorded pool verbatim,
and dies if a port of it is now taken
(`test_restart_with_surviving_session_never_floats_the_pool`,
`test_restart_dies_naming_the_session_whose_port_is_squatted`).

## Port as session identity

**The listener port is the session identity, and a guest cannot forge it.** Each guest's
Tier-1 net-rule — a flag of microsandbox, the microVM runtime — allows egress to only its
own session's port (`--net-rule "allow@host:tcp:<port>"`, default-deny otherwise).
microsandbox enforces that rule on the host side, below the guest
([THREAT-MODEL.md](./THREAT-MODEL.md), Tier 1), so a connection to another session's port is
refused before a real socket opens. The port a request arrives on therefore proves which
session sent it, with the proof enforced outside the guest. No per-request tokens are needed
or used.

The addon reads the accepted port from `flow.client_conn.sockname[1]`, resolves the session
that claims that port, and applies that session's ruleset. The ruleset is a per-session
snapshot, composed at `up` time into `~/.silkgate/sessions/<name>/rules.txt` and cached per
port. The sessions-directory mtime and the per-session `rules.txt` mtime invalidate the cache.

Session resolution fails closed. An unknown port, a missing session, or an unparsable
ruleset denies the request with reason `no session for port`, and the addon never falls
through to another session's rules. Every audit record carries a `session` field.
`test/test_addon.py` pins the resolution and each fail-closed path.

## The control socket

**The host controls the proxy over a unix socket, never over a network port.** Every guest
can reach its own proxy port — that is the point of the proxy. A control endpoint on a
proxy port is therefore reachable by an adversarial guest, and needs its own authentication
to be safe. A unix socket in the host filesystem is unreachable from every guest by
construction: no host path is mounted into a guest, and no network route leads to it. It
therefore needs no authentication.

The addon serves line-delimited JSON on `~/.silkgate/proxy.sock` (mode `0600`) and unlinks a
stale socket file at start. The operations are `ping`, `set_secret`, and `list_secrets`. An
unknown operation or a malformed line is an error.

## The secrets flow

**A credential moves from the host environment into proxy memory, scoped to one session, and
never enters a guest.** The credential lives on the host only as
`SILKGATE_EGRESS_SECRET_<NAME>`, one `"<Header>: <value>"` line. `silkgate up` and
`silkgate secret set <name> --session <session>` read it from the local environment and push
it over the control socket with `set_secret`, with the session name attached. The addon holds
it in an in-memory dict keyed by session, and `inject_auth=<name>` resolves only within the
session the request arrived for.

Four properties, each pinned in `test/test_addon.py`:

- A later session cannot spend a key an earlier session pushed
  (`test_a_session_cannot_spend_anothers_secret`).
- The value never appears in a process argument, on disk, or in a log, and `list_secrets`
  returns names only (`test_list_secrets_never_echoes_a_value`).
- The `SILKGATE_EGRESS_SECRET_*` environment of the proxy process — what `mitmdump`
  inherited at start, not what an `up` shell holds — serves the standalone `silkgate proxy`
  only, where no sessions exist (`test_env_secrets_do_not_serve_named_sessions`).
- A request that matches an `inject_auth` rule whose secret is absent or unusable is
  denied, whether or not the guest sent the header, and the guest sees the same answer as
  for a request no rule matches
  (`test_missing_secret_is_indistinguishable_from_a_policy_miss`). Which secrets the host
  holds is not the guest's to learn. The audit record keeps the real reason.

A missing or malformed secret warns at `up` and never blocks startup. If a session's
ruleset names `inject_auth=<name>` and the variable is absent or not one
`"<Header>: <value>"` line, `_push_secrets` in [`cli/silkgate`](../cli/silkgate) prints a
warning and continues. The session comes up, requests that match that rule are denied, and
the guest reads the credential status in `/silkgate/CONTEXT.md`. The session scope above has
a cost: each `up` needs the variable in its own environment, because a session never inherits
a secret already in the proxy.

The store's lifetime is the proxy process. Secrets are pushed per launch and live in proxy
memory only, so they die when the proxy exits, while sessions and their ruleset snapshots
survive on disk. A proxy restart under a live session therefore leaves injection with no
value: a request that matches an `inject_auth` rule fails closed, with audit reason
`missing secret for inject_auth=<name>`. Recover on either path: relaunch the session
(`down`, then `up` — `up` re-pushes what its environment holds), or push into the live
session with `silkgate secret set <name> --session <name>`. A launch with an empty
allowlist pushes nothing, because no `inject_auth` name exists to serve. Two failure shapes
tell the diagnosis apart: a 401 from the upstream means injection happened with a bad
value, and a deny whose audit reason is `missing secret` means the proxy holds no value at
all.

## The audit trail

**Every decision writes one JSON line to the audit log, and the proxy mirrors the same line
into a machine-only events file.** A request tells its story in at most two records, joined
by mitmproxy's flow id. The first is the decision when it is made. The second, for an allow,
is a `response` record once the flow concludes. A deny record is the whole story, because
nothing went upstream. The `host` and `port` fields name the destination the proxy dials,
never the guest's claim about it. A `Host:` header that contradicts that destination is
recorded as `claimed`. Bodies and credential values are never written.

Action fields carry names, never values. An allow record holds what the proxy did on
the way through. `injected` names the secret whose value replaced the header the guest sent.
`inject_skipped` names the secret the proxy held but left unused because the guest did not
send that header — the two fields are exclusive. `stripped_query` and `stripped_headers`
hold the sorted names that lost at least one pair. `listen_port` rides every record kind, so
even a `session: null` deny stays attributable to a port. The `response` record adds status,
byte counts, and duration.

The events file is the machine-readable contract. Each proxy start creates one
`events-<stamp>.jsonl` beside the log: pure JSONL, free of mitmdump's own output. Every
request record lands in both sinks byte-identical. Control-socket activity is logged but
never mirrored (`test_control_records_not_mirrored` in `test/test_addon.py`), so the events
file holds request records only. The audit trail is required, not best-effort: a write that
fails on either sink blocks the request (`EventsFileTest` in `test/test_addon.py`).
`silkgate ui` serves a live, filterable view over these files on `127.0.0.1:8642`. It never
parses the mixed-format `proxy-*.log` files, so its history is exactly what the retained
events files record.

Retention deletes a file only when it is both older than 30 days and beyond the newest 20
of its kind. The live log and events files are never pruned: `proxy.json` names them and
the prune skips them, and a file under write keeps its mtime fresh anyway. Set
`SILKGATE_LOG_RETAIN_DAYS=0` to keep everything.

## On-disk layout of `~/.silkgate/`

**All host state lives under `~/.silkgate/`, created on the first `silkgate run` or
`silkgate up`.**

| Path | Holds |
|---|---|
| `proxy.json` | Shared-proxy metadata: pid, base port, the port pool, log path, events path, socket path |
| `proxy.sock` | The control socket (mode `0600`) |
| `proxy.lock` | The lock that serializes proxy start and stop |
| `sessions/<name>/meta.json` | Session metadata: sandbox name, port, image, profiles, command, mounts |
| `sessions/<name>/rules.txt` | The composed ruleset snapshot the proxy reads for that session |
| `sessions/<name>/context.md` | The guest context, copied into the guest at `/silkgate/CONTEXT.md` |
| `ca/egress-ca.pem` | The MITM certificate, baked into guest images and trusted by guests — never the private key |
| `logs/proxy-*.log` | The audit log, one file per proxy start |
| `logs/events-*.jsonl` | The events files: the same request records, machine-only |
| `logs/proxy-*.rules` | The one fixed ruleset a `verify` proxy ran with |
| `logs/standalone-*.rules` | The one fixed ruleset a `silkgate proxy` run enforced |
| `docker/` | Silkgate's own `DOCKER_CONFIG`, so image builds never call the user's credential helper |
