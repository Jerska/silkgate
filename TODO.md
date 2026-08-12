# TODO

Read this to pick up work the project deferred on purpose. Each entry names the work
and what parks it. Done work leaves the file — history lives in git.

## Containment proofs

**A check that has never failed proves nothing — six of the 15 have, nine have not.**

- Extend the negative controls. `verify --negative-control` boots a deliberately
  leaky guest, and six checks fail against it (doc/THREAT-MODEL.md names the set).
  Engineer one controlled violation for each remaining check.
- Re-audit verify coverage against the retired review's gap list, and add a probe for
  what still lacks one:
  - TCP/53 interception as an assertion, and UDP egress beyond port 53.
  - Host ports other than the session's proxy port, and a LAN address on that port.
  - The address family the guest actually picks.
  - msb's DNS-rebind protection.
  - Cross-session isolation, which needs a session-level test.
- Settle the `:ro` enforcement layer. Establish in libkrun and msb source whether a
  read-only mount is host-enforced or a guest mount option, for macOS/libkrun and for
  Linux/KVM msb. Record the answer in doc/THREAT-MODEL.md. Until then, no document
  claims that `:ro` holds against a hostile guest.
- Cover `_forbidden_mounts` nesting. Confirm that the guard and its tests refuse a
  mount of `<repo>/.silkgate/sandboxes/<name>`, not only the repository root. Add the
  refusal tests that are absent.

## Proxy policy

**No shipped profile exercises the deny-by-default header and query machinery.**

- Tighten `profiles/claude/rules.txt`. It grants `h:* q:*`. The fix needs the
  measured header set the harness sends, not a guess.
- Build the approval queue (`action=ask`): deny, queue, host-side grant, retry at the
  proxy. A full sketch is parked in the dashboard plan. A mid-run grant taints what
  the session already read — see the shared-state entry below.
- Add cost budgets per session or exec. Parked in the dashboard plan.

## Sandbox and git

**Shared writable state is an escalation channel unless keyed by trust domain.**

- Design shared state between guests. Content-addressed leaf data with verification
  on read (LFS objects) is safe to share read-write. Bytes that execute in the
  reader's guest (a compiler cache) are safe only inside one trust domain:
  `hash(image, composed ruleset, credential fingerprint)`. A warm store that no
  agent writes needs no such key.
- Build the local-LFS-mount versus real-remote hybrid: the guest pushes its branch
  itself, and no host git state is writable. The guest-side leg is unbuilt.
- Run the 57 GB engine repository end to end. A sparse-checkout recipe comes first.
- Add a `placeholder_env` conf key. The guest context cannot name the env var that
  holds a profile's baked placeholder credential, because no mapping exists from
  `inject_auth=<name>` to that variable. Add the key when a second credentialed
  profile needs it.

## CLI and operations

**Operational polish, each entry parked by an explicit decision.**

- Add an `image gc` subcommand. It keeps only the tags that match current profile
  hashes, with a way to run it periodically.
- Bound `run` and `exec` with `--timeout`. A wrapper `timeout` is safe today. Open:
  exec coverage, the exit-status contract, and teardown versus inspect on expiry.
- Open a two-way guest conversation over `--input-format stream-json`. Two unknowns
  block it: whether `msb exec` forwards stdin at all, and the framing — the relay's
  stream tag is guest-forgeable, so either the framing resists forgery or every
  event is data, never an instruction.
- Decide `_plain` versus `\r` repaints: flatten or keep. 22 tests ride `_plain`.
- Split `cli/silkgate` (about 6,000 lines). Deprioritized: only in a quiet tree.
- Simplify `SessionRegistry`. Two mtime-keyed caches and a rescan retry save one
  stat per request.
- Verify doc/PLUGIN.md against a real plugin install. It rests on a same-day docs
  mirror and describes an untested `bin/` symlink.

## Upstream (msb)

**Two msb defects have local workarounds and no upstream report yet.**

- Report the first-exec relay race, and re-check it on msb 0.6.x. The Tier-1 probe
  retries once as the workaround.
- Report that `msb exec` streams stdin and waits for EOF, so a caller with a
  never-closing pipe stalls forever.

## Inherited from the retired review

**These claims predate heavy refactors — verify each against current code first.**

The full review lived in FEEDBACK.md, which git history keeps. Its still-open
robustness items:

- No locks between proxy lifecycle operations: a `down` of the last session beside a
  concurrent `up` can kill the proxy under it.
- Proxy pid identity: `os.kill(pid, 0)` trusts a recorded pid that an unrelated
  process can hold after reuse. Verify identity over the control socket before a
  trust or a kill.
- `_teardown_session` removes the session directory even when `msb rm` fails, which
  frees the port while a live guest still holds L3 access to it.
- A failed `msb create` leaves the sandbox behind, so the next `up` with that name
  collides.
- The addon's deny path does work that can itself throw, and an exception that
  escapes a hook forwards the request unfiltered. `responseheaders` has no guard.
- The control socket receives its permissions only after bind, and `running()`
  unlinks the socket path unconditionally, so a second proxy steals a live one's
  control channel.
