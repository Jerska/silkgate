#!/usr/bin/env bash
# Tier 1 verification — run as ROOT INSIDE the microsandbox guest (Debian + bash).
#
# WHAT A BLOCKED-DIRECTION CHECK HAS TO SHOW HERE
#
# The allow side of this script has always insisted on an answer: check 0 requires the
# proxy's own 403, not a connect. The deny side used to accept an absence — `tcp()` threw
# away the errno, so "the boundary refused this in 1ms" and "this guest's own stack never
# emitted a packet" were both rc=1 and both scored PASS. They are told apart now:
#
#   connected  the handshake completed          -> the check FAILS, egress reached it
#   refused    ECONNREFUSED / ECONNRESET        -> the boundary answered: containment, PASS
#   dead       ENETUNREACH / EINVAL / no name   -> the boundary was never asked: SKIP
#   silent     nothing at all within $T         -> depends on the manner control, below
#
# `silent` is the only ambiguous one, so the manner of denial is measured rather than
# assumed: control 0b connects to TEST-NET-1 (192.0.2.1), an address nothing routes to and
# nothing can answer from, and whatever the boundary does to it is what "denied" looks like
# on this platform. Where it refuses, a silent probe is unexplained and SKIPs; where it
# drops, silence is its answer and passes. Neither reading is baked in.
#
# TOOLS. The `# CHECK n tools:` line opening each check below is the single source of truth
# for what it needs installed, and `silkgate verify` reads those lines to decide which
# checks a bare run must produce — the set is derived from this file rather than restated
# beside it in the CLI, which is how a `verify` shipped that could not pass (7 was called
# tool-free while this script skipped it without `ip`). `tools:none` means bash built-ins
# plus coreutils and grep, which debian:bookworm-slim has: no `curl`, `dig`, `ip` or `ping`.
#
# SUBJECTS. A fourth verdict, UNAVAILABLE, is for a check whose subject does not exist on
# this guest — a v6 probe on a platform with no v6 path has nothing to ask the boundary,
# which is neither a pass, nor a failure, nor an inability to run something that could have
# run. It is declared, not improvised: `subject:<capability>` on the CHECK line names the
# one thing whose absence the check may report, and `silkgate verify` refuses the verdict
# from any check that declares none, so an output string alone can never widen it. The
# absence itself must be read from the guest's own tables (/proc/net/ipv6_route,
# /proc/net/if_inet6, /etc/hosts) and never from a probe's errno alone: `dead` from a probe
# that could have worked is a broken probe until proven otherwise, and stays a SKIP.
#
# PORT 53 ALWAYS ANSWERS, from msb's own stub, on TCP and UDP, for every destination
# including unroutable ones. So on 53 a reply is never egress; the discriminator is
# byte-identity with the reply from TEST-NET, which can only have been synthesized locally.
# That also means 53 must never appear in a host-port sweep: it connects on a healthy guest.
#
# WHAT MUTATES THE GUEST runs last (7 changes routing, 14 changes addressing), restores what
# it changed, and re-proves control 0 afterwards; if the restore fails, `mech` drops to 0 so
# nothing downstream can read the damage as containment.
#
# The last two lines are for the caller: which checks ran (with the skipped and unavailable
# sets beside them), and the pass/fail totals. A SKIP and an UNAVAILABLE are neither, and
# `silkgate verify` asserts the set it expected to run — accepting an absent subject only
# from a check declared able to have one.

export LC_ALL=C   # bash and curl report connect failures through strerror(3) and the checks
                  # below read that text; C keeps it English. It also pins EPOCHREALTIME's
                  # decimal separator to '.', which _us() strips.

PROXY="${HTTPS_PROXY:-http://host.microsandbox.internal:8090}"
T=5
pass=0; fail=0; ran=""; skipped=""; unavail=""
P(){ echo "[PASS] $1. $2"; pass=$((pass+1)); ran="$ran,$1"; }
F(){ echo "[FAIL] $1. $2"; fail=$((fail+1)); ran="$ran,$1"; }
S(){ echo "[SKIP] $1. $2"; skipped="$skipped,$1"; }
# U is only for a check whose declaration carries `subject:` (see SUBJECTS above): this
# guest observably lacks the one thing the check would probe, so there was never anything
# here to run — which is a different fact from a SKIP, a check that could have run and
# did not, and the host refuses it from any check not declared able to say it.
U(){ echo "[UNAV] $1. $2"; unavail="$unavail,$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# Microseconds since the epoch, from bash's own clock — no coreutils, no subprocess, so it
# is free to call inside a sweep. bash before 5.0 has no EPOCHREALTIME and every duration
# then reads 0; that is cosmetic, no verdict below depends on a duration.
_us(){ local t=${EPOCHREALTIME:-0}; t=${t/[.,]/}; printf '%s' "${t:-0}"; }

# classify RC TEXT -> one of connected|refused|dead|silent|unknown.
#
# The whole deny side of this script turns on this function, so it is a pure function of an
# exit code and a message: test/test_verify_checks.py lifts it out of this file and feeds it
# the strings measured in a real guest, which is the only way a discriminator gets tested
# without a second, deliberately-leaking sandbox. `unknown` is never a pass — an unrecognized
# failure is a failure to interpret, and the check that got it SKIPs.
classify(){
  # A completed handshake is decided by the exit code alone and before any text is read: it
  # is the one outcome that means a blocked-direction check FAILS, and no message a future
  # bash might add on a successful connect may be allowed to talk it down into a refusal.
  [ "$1" = 0 ] && { printf connected; return; }
  # A refusal ANYWHERE in the message wins over a dead end, and that order is deliberate.
  # bash's /dev/tcp walks every address getaddrinfo returns and only reports failure once it
  # has exhausted them, printing a line per attempt (verified: a name whose first address was
  # a refused 172.16.3.140 still connected via its second, and glibc — not /etc/hosts order —
  # decides which comes first). So the host-by-name sweeps see one message per family, and a
  # family the guest cannot reach at all is not a channel: what matters is that some address
  # got a policy answer and none of them connected.
  case $2 in
    *"Connection refused"*|*"Connection reset"*) printf refused; return ;;
    *"Network is unreachable"*|*"No route to host"*|*"Host is unreachable"* \
      |*"Address family not supported"*|*"Cannot assign requested address"* \
      |*"Invalid argument"*|*"Name or service not known"* \
      |*"Temporary failure in name resolution"*|*"Permission denied"*) printf dead; return ;;
  esac
  [ "$1" = 124 ] && [ -z "$2" ] && { printf silent; return; }
  printf unknown
}

# tcp HOST PORT — one bounded connect, keeping the errno bash prints. Sets $tcp_how (see
# classify), $tcp_ms and $tcp_errno. Returns 0 only when the handshake completed. A
# blocked-direction check must read $tcp_how: the exit status alone cannot tell a policy
# refusal from a probe that never left.
tcp(){
  local out rc t0
  t0=$(_us)
  out=$(timeout "$T" bash -c "exec 3<>/dev/tcp/$1/$2" 2>&1); rc=$?
  tcp_ms=$(( ($(_us) - t0) / 1000 ))
  tcp_how=$(classify "$rc" "$out")
  tcp_errno=${out##*: }                     # bash prints two lines; the errno ends both
  [ -n "$tcp_errno" ] || tcp_errno="no message"
  [ "$tcp_how" = connected ]
}

# grade WHAT — turn the tcp() result just recorded into a verdict for a check whose expected
# answer is "blocked". Sets $dv (p|f|s) and $dw (the line to print). Each check then makes
# its own literal P/F/S call, so every ID is greppable in this file.
grade(){
  case $tcp_how in
    connected) dv=f; dw="$1 CONNECTED in ${tcp_ms}ms — this direction is not contained" ;;
    refused)   dv=p; dw="$1 refused by the boundary in ${tcp_ms}ms ($tcp_errno)" ;;
    silent)
      if [ "$manner" = drop ]; then
        dv=p; dw="$1 got nothing in ${T}s, and neither does TEST-NET — dropping is how this boundary denies (control 0b)"
      else
        dv=s; dw="$1 went silent for ${T}s, but this boundary REFUSES TEST-NET in ${manner_ms}ms — silence is not its answer here, so this proves nothing"
      fi ;;
    dead)      dv=s; dw="$1 never left this guest ($tcp_errno) — the boundary was never asked, so this proves nothing" ;;
    *)         dv=s; dw="$1 failed in a way this script cannot classify ($tcp_errno) — not read as containment" ;;
  esac
}

# sweep port|addr HOST/PORT ... — connect to each in turn, sorting the outcomes into
# $sw_hit, $sw_ref, $sw_dead, $sw_silent. The first argument is how to name a destination in
# those lists: a sweep of one host's ports names ports, a sweep of one port across addresses
# names addresses, and either way the verdict has to name what it actually probed. A sweep
# that would outrun $T stops and leaves the rest in $sw_left — a truncated sweep reported as
# a clean one is a list of destinations nobody probed.
sweep(){
  local how=$1 spec h p tag deadline
  shift
  sw_hit=""; sw_ref=""; sw_dead=""; sw_silent=""; sw_left=""
  deadline=$(( $(_us) + T * 1000000 ))
  for spec in "$@"; do
    h=${spec%/*}; p=${spec##*/}
    [ "$how" = addr ] && tag="$h:$p" || tag=$p
    if [ "$(_us)" -gt "$deadline" ]; then sw_left="$sw_left $tag"; continue; fi
    tcp "$h" "$p"
    case $tcp_how in
      connected) sw_hit="$sw_hit $tag" ;;
      refused)   sw_ref="$sw_ref $tag" ;;
      silent)    sw_silent="$sw_silent $tag" ;;
      *)         sw_dead="$sw_dead $tag" ;;
    esac
  done
}

# sweep_verdict WHAT — grade a completed sweep(), setting $dv/$dw like grade(). One connect
# is a leak; the pass needs at least one destination the boundary actively denied, so a
# sweep in which every probe died inside the guest cannot pass.
sweep_verdict(){
  local denied note=""
  if [ "$manner" = drop ]; then denied="$sw_ref$sw_silent"; else denied="$sw_ref"; fi
  [ -n "$sw_dead" ] && note="$note; never left the guest:$sw_dead"
  [ "$manner" != drop ] && [ -n "$sw_silent" ] &&
    note="$note; silent, which this boundary's refusals do not explain:$sw_silent"
  if [ -n "$sw_hit" ]; then
    dv=f; dw="$1 — CONNECTED:$sw_hit$note"
  elif [ -z "$denied" ]; then
    dv=s; dw="$1 — the boundary denied nothing here$note, so this proves nothing"
  elif [ -n "$sw_left" ]; then
    dv=s; dw="$1 — denied:$denied, but the ${T}s budget ran out before$sw_left$note"
  elif [ -n "$note" ]; then
    dv=s; dw="$1 — denied:$denied$note"
  else
    dv=p; dw="$1 — every one denied by the boundary:$denied"
  fi
}

# The DNS query every port-53 probe sends: A? example.com, ID 0x2a2a, RD set. It is emitted
# by a function and never held in a variable: the wire format is full of NUL bytes and bash
# truncates a string at the first one, which turns the query into a 2-byte fragment no
# responder answers — silence that reads exactly like containment.
dns_query(){ printf '\052\052\001\000\000\001\000\000\000\000\000\000\007example\003com\000\000\001\000\001'; }

# A connect alone proves nothing: microsandbox's guest->host NAT completes the TCP handshake
# inside the VMM, so /dev/tcp reports success even with no listener on the host at all
# (observed with the proxy stopped). The control therefore speaks HTTP and requires the
# proxy's own answer — a request no ruleset allows, so it is refused from the proxy's memory
# and needs neither an allow-rule nor any upstream egress to succeed.
#
# Returns 0 for silkgate's own refusal, 2 for some other HTTP 4xx, 1 for anything else. The
# 4xx alone was not enough: any HTTP server holding the port satisfies it, and a pool-port
# collision has already surfaced in the field as session-mode 403s inside a verify guest.
# X-Silkgate: deny is on every refusal this addon issues — it raises the bar from "an HTTP
# server" to "something claiming to be silkgate", which is all a mark can do. The addon says
# so itself: a destination could imitate it, so nothing may treat it as proof of identity.
control(){
  local line status="" mark=""
  exec 3<>"/dev/tcp/$1/$2" || return 1
  printf 'GET http://silkgate.invalid/ HTTP/1.1\r\nHost: silkgate.invalid\r\nConnection: close\r\n\r\n' >&3 || return 1
  while IFS= read -r line <&3; do
    line=${line%$'\r'}
    [ -z "$line" ] && break
    [ -n "$status" ] || status=$line
    case $line in [Xx]-[Ss]ilkgate:*[Dd]eny*) mark=1 ;; esac
  done
  exec 3<&-
  case "$status" in *40[0-9]*) ;; *) return 1 ;; esac
  [ -n "$mark" ] || return 2
  return 0
}

# `timeout` bounds a process, not a shell function, so the two functions a bounded probe
# needs get spliced into the `bash -c` it runs.
SPLICE=$(declare -f control dns_query)

control_rc(){ timeout "$T" bash -c "$SPLICE; control $1 $2" >/dev/null 2>&1; }

# dns_udp_hex HOST / dns_tcp_hex HOST — the bytes HOST:53 answers with, as hex, empty if
# nothing came back. `read` cannot be used to collect them (it swallows NULs, of which a DNS
# message is mostly made), so the reply comes back through dd and od. The TCP form asks for
# exactly 31 bytes: 2 length + 12 header + 17 question is the shortest valid response to
# this query, so a full read either completes or the probe timed out, and a real resolution
# differs inside the first 31 bytes (its flags and ANCOUNT cannot match a REFUSED).
dns_udp_hex(){
  local hex
  hex=$(timeout "$T" bash -c "$SPLICE"'
    exec 3<>"/dev/udp/$1/53" || exit 1
    dns_query | dd iflag=fullblock bs=1200 count=1 >&3 2>/dev/null || exit 1
    dd bs=1500 count=1 <&3 2>/dev/null
  ' _ "$1" 2>/dev/null | od -An -tx1 | tr -s ' \n' ' ')
  hex=${hex# }; printf '%s' "${hex% }"
}
dns_tcp_hex(){
  local hex
  hex=$(timeout "$T" bash -c "$SPLICE"'
    exec 3<>"/dev/tcp/$1/53" || exit 1
    { printf "\000\035"; dns_query; } >&3 || exit 1
    dd iflag=fullblock bs=31 count=1 <&3 2>/dev/null
  ' _ "$1" 2>/dev/null | od -An -tx1 | tr -s ' \n' ' ')
  hex=${hex# }; printf '%s' "${hex% }"
}

# udp_reply KIND HOST PORT — exit 0 = something answered within $T. UDP has no handshake, so
# sending always "succeeds"; only a reply carries information, and read -t bounds the only
# step that can block. The payloads are requests a real server answers: a DNS query for
# example.com, an NTP v3 client packet, and a 1200-byte QUIC long header in an unknown
# version, which RFC 9000 §6.1 obliges a QUIC server to meet with a Version Negotiation
# packet. Every write on the socket is its own datagram, so the pieces go through one
# full-block dd — split across two writes they arrive as fragments no real server would
# answer, and the probe would read as containment on an open network.
udp_reply(){
  exec 3<>"/dev/udp/$2/$3" || return 1
  case $1 in
    dns)  dns_query ;;
    ntp)  printf '\033'; head -c 47 /dev/zero ;;
    quic) printf '\300\032\052\072\112\010AAAAAAAA\010BBBBBBBB'; head -c 1177 /dev/zero ;;
  esac | dd iflag=fullblock bs=1200 count=1 >&3 2>/dev/null || return 1
  IFS= read -r -t "$T" -N 1 first <&3
  rc=$?; exec 3<&-; return $rc
}

# curl_why TEXT — the one line of curl -v's chatter worth putting in a verdict. Its own
# `curl: (N) …` line names the failure; failing that, the last `* …` trace line does.
curl_why(){
  local l
  l=$(printf '%s\n' "$1" | grep -a '^curl: ' | tail -n1)
  [ -n "$l" ] || l=$(printf '%s\n' "$1" | grep -a '^\* ' | tail -n1)
  [ -n "$l" ] || l=$(printf '%s' "$1" | tr -s '\n' ' ' | tail -c 100)
  printf '%s' "$l"
}

# Does this guest have a route for the family at all? Silence from a family the guest cannot
# address is in-guest configuration, which THREAT-MODEL.md excludes from the boundary, so the
# v6 checks gate on this rather than reading a missing route as containment.
#
# And can it source a packet down that route? Scope 00 in /proc/net/if_inet6 is an address
# connect(2) may pick for a global destination — a ULA prints scope 00 and counts, and erring
# that way is safe: it can only keep a verdict at SKIP that might have been UNAVAILABLE,
# never the reverse. A ::/0 route with nothing to source it from cannot emit a packet, and
# the errno that produces (ENETUNREACH) is byte-identical to a broken probe's; this table is
# what tells the two apart. Both functions take an alternate path so the tests can hand them
# another guest's measured tables.
has_v6_default(){ grep -qE '^0{32} 00 ' "${1:-/proc/net/ipv6_route}" 2>/dev/null; }
has_v6_global(){ grep -qE '^[0-9a-f]{32} +[0-9a-f]+ +[0-9a-f]{2} +00 ' "${1:-/proc/net/if_inet6}" 2>/dev/null; }

# sortnum "3 1 2" -> "1,2,3". The checks below do not run in ID order — the two that
# reconfigure the guest run last — and the CHECKS: line is parsed by the host and grepped by
# CI, so it is emitted sorted regardless of the order things happened in.
sortnum(){
  local out="" n m rest dropped
  set -- $1
  while [ $# -gt 0 ]; do
    m=$1
    for n in "$@"; do [ "$n" -lt "$m" ] && m=$n; done
    out="$out,$m"
    rest=""; dropped=""
    for n in "$@"; do
      if [ -z "$dropped" ] && [ "$n" = "$m" ]; then dropped=1; continue; fi
      rest="$rest $n"
    done
    set -- $rest
  done
  printf '%s' "${out#,}"
}

echo "PROXY=$PROXY"

echo "== controls: the probe mechanism, and how this boundary says no (tool-free) =="
# Host:port out of $PROXY — the guest's only permitted egress, so this MUST work.
target=${PROXY#*://}; target=${target%%/*}
case "$target" in
  *:*) phost=${target%:*}; pport=${target##*:} ;;
  *)   phost=$target;      pport=80 ;;
esac
control_rc "$phost" "$pport"; crc=$?
case $crc in
  0) mech=1; echo "[OKAY] 0. bash /dev/tcp works and silkgate's proxy answered at $phost:$pport" ;;
  2) mech=0; echo "[WARN] 0. an HTTP 4xx came back from $phost:$pport, but without X-Silkgate: deny"
     echo "          — something other than this session's proxy may hold the port, so it is not"
     echo "          the control it looks like; blocked-direction checks below will SKIP" ;;
  *) mech=0; echo "[WARN] 0. no proxy answer at $phost:$pport — a failed connect below would"
     echo "          not distinguish containment from a probe that cannot reach anything" ;;
esac

# 192.0.2.1 is TEST-NET-1: nothing routes to it, so nothing behind it can answer and a
# refusal can only have come from the boundary in this VMM. Whatever it does here is what
# "denied" looks like on this platform, which is what lets grade() read a silent probe as a
# drop where the boundary drops and as unproven where it refuses.
tcp 192.0.2.1 443; manner_ms=$tcp_ms
case $tcp_how in
  refused)   manner=refuse
             echo "[OKAY] 0b. this boundary denies by REFUSING: TEST-NET 192.0.2.1:443 -> $tcp_errno in ${manner_ms}ms" ;;
  silent)    manner=drop
             echo "[OKAY] 0b. this boundary denies by DROPPING: TEST-NET 192.0.2.1:443 silent for ${T}s" ;;
  connected) manner=open
             echo "[WARN] 0b. TEST-NET 192.0.2.1:443 CONNECTED — the boundary completes handshakes to"
             echo "           addresses nothing routes to, so the checks below cannot use a refusal as"
             echo "           its signature; expect failures, not skips" ;;
  *)         manner=unknown
             echo "[WARN] 0b. cannot tell how this boundary denies (TEST-NET 192.0.2.1:443: $tcp_how,"
             echo "           $tcp_errno) — a blocked probe that goes silent will SKIP, not pass" ;;
esac

echo "== positive controls (need curl + trusted CA; SKIP if absent) =="
# CHECK 1 tools:curl — an allowed host must succeed THROUGH the proxy: CA trust, ruleset and
# upstream egress in one. Nothing else here proves the proxy can be used at all.
if have curl; then
  curl -fsS --max-time $T -x "$PROXY" https://registry.npmjs.org/lodash >/dev/null 2>&1 \
    && P 1 "allowed host via proxy" \
    || F 1 "allowed host via proxy  (CA trust / proxy / allow-rule not set up?)"
else
  S 1 "allowed host via proxy (curl not installed — see README 'full check')"
fi

# CHECK 2 tools:curl — an unlisted host must be refused BY THE PROXY. The refusal may arrive
# in-band (403 to the request) or as a rejected CONNECT, which the proxy answers 403 before
# any tunnel exists; curl reports code 000 then and names the 403 on stderr. Reading the
# number alone cannot tell the proxy's 403 from the destination's — parked and CDN-fronted
# domains answer 403 routinely, so a ruleset wide enough to let the request through would
# pass this check while the allowlist was void. Both denial shapes carry X-Silkgate: deny on
# the wire (verified in-band and on the refused CONNECT), so the header is what is matched.
if have curl; then
  said=$(curl -sSv -o /dev/null --max-time $T -w 'code=%{http_code}' -x "$PROXY" https://evil.com 2>&1)
  mark=""; printf '%s\n' "$said" | grep -qi '^< *x-silkgate: *deny' && mark=1
  case "$said" in
    *code=2*)  F 2 "unlisted host answered 2xx through the proxy — the request was not refused" ;;
    *)  if [ -n "$mark" ]; then
          P 2 "unlisted host refused by silkgate's own proxy (X-Silkgate: deny)"
        else
          # Only where curl reports a status, not anywhere in its chatter: a proxy on port
          # 19403 puts "403" in curl's `Trying …` line, and a port number is not a verdict.
          case "$said" in
            *"code=403"*|*"response 403"*|*"HTTP/1.1 403"*|*"HTTP/2 403"*) S 2 "unlisted host got a 403 with no X-Silkgate: deny — that is either evil.com's own 403 (a ruleset wide enough to reach it) or another server on $pport, and this check cannot tell which" ;;
            *)     F 2 "unlisted host -> no proxy refusal at all (want X-Silkgate: deny; got: $(curl_why "$said"))" ;;
          esac
        fi ;;
  esac
else
  S 2 "unlisted host via proxy (curl not installed — see README 'full check')"
fi

echo "== egress that MUST be blocked (a refusal here = good) =="
# CHECK 3 tools:none — direct TCP/443 to a raw IP, around any proxy. The same assertion the
# always-on probe makes at session create time; what the rest of this section adds is breadth.
if [ "$mech" = 1 ]; then
  tcp 1.1.1.1 443; grade "direct TCP to 1.1.1.1:443"
  case $dv in p) P 3 "$dw" ;; f) F 3 "$dw" ;; *) S 3 "$dw" ;; esac
else
  S 3 "direct TCP egress (control 0 failed: no working /dev/tcp probe)"
fi

# CHECK 4 tools:dig,getent,python3 — resolution through whatever /etc/resolv.conf names,
# which in a healthy guest is msb's stub. Test the ANSWER, not the exit code: dig and getent
# both succeed on NXDOMAIN. This proves the CONFIGURED resolver resolves nothing, which is
# less than "the guest cannot reach a resolver" — resolv.conf is guest-mutable and the threat
# model disowns it, and an empty or unreachable one makes the check vacuous rather than true.
# So the two ways of passing without asking anything are excluded first, and check 12 covers
# the resolvers the guest picks for itself.
if ! grep -qE '^[[:space:]]*nameserver[[:space:]]+[^[:space:]]' /etc/resolv.conf 2>/dev/null; then
  S 4 "DNS via the configured resolver: /etc/resolv.conf names no nameserver, so nothing would be asked and a pass would mean nothing"
elif [ -f /etc/nsswitch.conf ] && ! grep -qE '^[[:space:]]*hosts:.*\bdns\b' /etc/nsswitch.conf; then
  S 4 "DNS via the configured resolver: nsswitch.conf's hosts: line has no dns source, so no DNS packet would be generated"
elif have dig || have getent || have python3; then
  if have dig;      then tool=dig; ans=$(dig +short +time=3 +tries=1 example.com 2>/dev/null | head -n1)
  elif have getent; then tool=getent; ans=$(getent hosts example.com 2>/dev/null | head -n1)
  else                   tool=python3; ans=$(python3 -c 'import socket;print(socket.gethostbyname("example.com"))' 2>/dev/null); fi
  ns=$(grep -E '^[[:space:]]*nameserver' /etc/resolv.conf 2>/dev/null | head -n1)
  [ -n "$ans" ] && F 4 "the configured resolver resolved example.com -> $ans (via $tool)" \
                || P 4 "the configured resolver ($ns) resolves nothing via $tool — see check 12 for resolvers the guest picks itself"
else
  S 4 "DNS (no dig/getent/python3)"
fi

# CHECK 5 tools:none subject:ipv6 — IPv6 egress, an IP literal so no DNS is involved. bash's
# /dev/tcp takes a bare IPv6 literal, so this needs no curl and joins the bare run; curl's
# exit 7 used to cover "refused", "no route" and "no v6 address configured" alike, and only
# the first is containment. A guest with no v6 path has no subject for this check, and that
# comes in two shapes, both read from the kernel rather than from the probe: no ::/0 route in
# /proc/net/ipv6_route (nothing can be addressed), and a ::/0 route with no global-scope
# source address in /proc/net/if_inet6 — Linux/KVM guests ship with the route and nothing to
# source it from, and connect(2) then dies inside the guest with the same ENETUNREACH a
# broken probe shows. So wherever a route exists the probe still runs — a handshake that
# completes is a FAIL and a refusal is a PASS whatever the address table says — and only a
# probe that DIED is read against the table: no source address means the death is this
# guest's own addressing and the check is UNAVAILABLE; with an address it stays a SKIP,
# because dead from a probe that could have worked is precisely the ambiguity this file
# refuses to bless.
if [ "$mech" != 1 ]; then
  S 5 "IPv6 egress (control 0 failed: no working /dev/tcp probe)"
elif ! has_v6_default; then
  U 5 "IPv6 egress: no ::/0 route in /proc/net/ipv6_route — this guest cannot address a v6 packet to anywhere, so there is no IPv6 egress here to test"
else
  tcp 2606:4700:4700::1111 443; grade "direct TCP to [2606:4700:4700::1111]:443"
  if [ "$dv" = s ] && [ "$tcp_how" = dead ] && ! has_v6_global; then
    U 5 "IPv6 egress: the probe died in this guest ($tcp_errno) and /proc/net/if_inet6 holds no global-scope address — a ::/0 route with nothing to source it from cannot emit a packet, so there is no IPv6 egress here to test"
  else
    case $dv in p) P 5 "$dw" ;; f) F 5 "$dw" ;; *) S 5 "$dw" ;; esac
  fi
fi

# CHECK 6 tools:ping — ICMP, with the local positive control it lacked. Any non-zero ping exit
# used to pass, including `socket: Operation not permitted` and a missing capability: a check
# that passes when the tool never sent a packet cannot fail. The proxy host answers echo
# requests (verified by raw socket in a guest), so it is the control — if ICMP does not work
# to it either, silence from 1.1.1.1 is not evidence and this SKIPs.
if ! have ping; then
  S 6 "ICMP (no ping)"
else
  cout=$(ping -c1 -W2 "$phost" 2>&1); crc=$?
  if [ $crc -ne 0 ]; then
    S 6 "ICMP: no echo reply from $phost either ($(printf '%s\n' "$cout" | tail -n1)) — no working local control, so silence from 1.1.1.1 would prove nothing"
  else
    pout=$(ping -c1 -W2 1.1.1.1 2>&1); prc=$?
    [ $prc -eq 0 ] && F 6 "ICMP reached 1.1.1.1" \
                   || P 6 "ICMP to 1.1.1.1 got no reply (ping exit $prc) while the same ping to $phost did"
  fi
fi

# CHECK 8 tools:none — TCP/53, a general-purpose tunnel if it egresses, and the one port that
# ANSWERS: msb's stub returns an identical REFUSED for every destination, TEST-NET included,
# so "a reply arrived" is never "it egressed". It needed dig, so it skipped on exactly the run
# the README lists first; the query is 31 bytes of printf here instead. The old rc==9 branch
# passed on the reply its own comment documents as always present having disappeared — which
# is also what a deleted default route produces, and check 7 used to run just before it.
if [ "$mech" != 1 ]; then
  S 8 "TCP/53 (control 0 failed: no working /dev/tcp probe)"
else
  tcp 1.1.1.1 53
  if [ "$tcp_how" != connected ]; then
    grade "TCP/53 to 1.1.1.1"
    case $dv in p) P 8 "$dw" ;; f) F 8 "$dw" ;; *) S 8 "$dw" ;; esac
  else
    real=$(dns_tcp_hex 1.1.1.1); mir=$(dns_tcp_hex 192.0.2.1)
    if [ -z "$real" ]; then
      S 8 "TCP/53 connects to 1.1.1.1 but nothing came back within ${T}s — the stub that always answers stopped answering, so this run cannot say whether the port egresses"
    elif [ "$real" = "$mir" ]; then
      P 8 "TCP/53 answers byte-identically for 1.1.1.1 and for unroutable 192.0.2.1 ($real) — one local responder, not a resolver"
    elif [ -z "$mir" ]; then
      F 8 "TCP/53: 1.1.1.1 replied ($real) and TEST-NET stayed silent — the reply was not shown to be local"
    else
      F 8 "TCP/53 egressed: 1.1.1.1 answered [$real] where TEST-NET answers [$mir]"
    fi
  fi
fi

# CHECK 9 tools:none — UDP beyond 53. QUIC on UDP/443 bypasses an HTTP proxy entirely
# (THREAT-MODEL names it), so default-deny must cover every UDP port, not only intercepted 53.
# Silence from a broken probe looks identical to containment, so first the control: a DNS
# datagram to TEST-NET on 53, whose "answer" can only be msb's stub — one exchange proving
# both that the send/read path works and that port-53 replies are synthesized locally.
#
# Read the pass text carefully. A reply that TEST-NET does not mirror is a leak and this can
# say so; but the usual branch is silence from all three authorities, and nothing IN THE
# GUEST distinguishes "denied" from "that authority stopped answering" — a send to a denied
# UDP destination raises no errno, on any of three tries. Three independent authorities make
# one going quiet less likely; they do not make the branch evidence. Closing it needs the
# host, which has real egress, to probe the same authorities and force a SKIP when it gets no
# answer either. Until then this check can catch an answered leak and not a silent one.
if udp_reply dns 192.0.2.1 53 2>/dev/null; then
  UTMP="/tmp/verify-udp.$$"
  ( udp_reply quic 1.1.1.1 443 2>/dev/null && : >"$UTMP.quic1" ) &
  ( udp_reply quic 8.8.8.8 443 2>/dev/null && : >"$UTMP.quic2" ) &
  ( udp_reply ntp 216.239.35.0 123 2>/dev/null && : >"$UTMP.ntp" ) &
  wait
  leak=""; mirrored=""; silent=""
  for probe in "quic1 quic 1.1.1.1 443" "quic2 quic 8.8.8.8 443" "ntp ntp 216.239.35.0 123"; do
    set -- $probe
    if [ ! -e "$UTMP.$1" ]; then silent="$silent $3:$4/udp"; continue; fi
    if udp_reply "$2" 192.0.2.1 "$4" 2>/dev/null; then mirrored="$mirrored $2/$4"
    else leak="$leak $2@$3:$4"; fi
  done
  rm -f "$UTMP.quic1" "$UTMP.quic2" "$UTMP.ntp"
  if [ -n "$leak" ]; then
    F 9 "UDP egressed:$leak answered where TEST-NET stayed silent"
  elif [ -n "$mirrored" ]; then
    P 9 "UDP beyond 53 intercepted locally ($mirrored answered, and TEST-NET mirrors it)"
  else
    P 9 "UDP beyond 53 unanswered from$silent — silence with no local control, so this is the weakest pass here (a host-side probe of the same authorities is what would make it evidence)"
  fi
else
  S 9 "UDP beyond 53 (no reply from msb's port-53 stub, so a silent probe would prove nothing)"
fi

# CHECK 10 tools:none — the host itself, off the proxy port. The Tier-1 rule is one port, not
# one host, so the host's other listeners must be as unreachable as the internet. A connect
# needs no listener to succeed — the NAT completes the handshake for any host port the policy
# allows (see check 0) — so success IS the leak and a refusal is what a healthy host shows.
if [ "$mech" = 1 ]; then
  alt=$((pport + 1)); [ "$alt" -gt 65535 ] && alt=$((pport - 1))
  # 53 is msb's DNS stub and always connects, so `alt` must never land on it: `verify --port
  # 52` computed alt=53 and reported a leak on a perfectly healthy guest.
  [ "$alt" = 53 ] && alt=$((pport - 1))
  sweep port "$phost/$alt" "$phost/22"
  sweep_verdict "host $phost off the proxy port (tried $alt and 22)"
  case $dv in p) P 10 "$dw" ;; f) F 10 "$dw" ;; *) S 10 "$dw" ;; esac
else
  S 10 "host ports beside the proxy's (control 0 failed: no working /dev/tcp probe)"
fi

# CHECK 12 tools:none — UDP/53 to resolvers the GUEST picks. Check 4 asks whatever
# resolv.conf names, which is msb's stub, and check 8 covers TCP; nothing sent a UDP datagram
# to a resolver of the guest's own choosing, which is the first exfil channel THREAT-MODEL
# names. The failure this catches is msb's UDP/53 interception narrowing — a redirect that
# only matches dst == gateway, a policy DNS passthrough, an operator's allow@host:udp:53 —
# after which resolv.conf still points at the stub, names still do not resolve, and
# `<data>.attacker.example` starts leaving with no proxy, no TLS and no audit line.
#
# The discriminator is byte-identity with TEST-NET's reply: nothing routes to 192.0.2.1 or
# 2001:db8::1, so a reply "from" there is definitionally local, and an identical reply from
# 1.1.1.1 is the same local responder. Silence must NOT pass — a DNS tunnel needs the query
# to arrive, not the answer to come back — so a resolver that goes quiet while the unroutable
# mirror answers is a leak candidate and fails.
mir4=$(dns_udp_hex 192.0.2.1)
if [ -z "$mir4" ]; then
  S 12 "UDP/53 to the guest's own choice of resolver: msb's stub did not answer TEST-NET 192.0.2.1:53, so there is no local control and silence would prove nothing"
else
  r53="1.1.1.1 8.8.8.8 9.9.9.9"
  mir6=""
  if has_v6_default; then
    mir6=$(dns_udp_hex 2001:db8::1)
    [ -n "$mir6" ] && r53="$r53 2606:4700:4700::1111 2001:4860:4860::8888"
  fi
  RTMP="/tmp/verify-dns.$$"
  for r in $r53; do ( dns_udp_hex "$r" >"$RTMP.$r" ) & done
  wait
  same=""; differ=""; quiet=""
  for r in $r53; do
    got=$(cat "$RTMP.$r" 2>/dev/null); rm -f "$RTMP.$r"
    case $r in *:*) want=$mir6 ;; *) want=$mir4 ;; esac
    if [ -z "$got" ];        then quiet="$quiet $r"
    elif [ "$got" = "$want" ]; then same="$same $r"
    else differ="$differ $r"; fi
  done
  if [ -n "$differ" ]; then
    F 12 "UDP/53 egressed:$differ answered with bytes unroutable TEST-NET does not produce"
  elif [ -n "$quiet" ]; then
    F 12 "UDP/53 to$quiet went unanswered while unroutable 192.0.2.1 answered in the same run — the query left for somewhere, which is all a DNS tunnel needs"
  else
    P 12 "UDP/53 answers byte-identically for$same and for unroutable TEST-NET — msb's stub, not egress ($mir4)"
  fi
fi

# CHECK 13 tools:none — the host's other listeners, beyond the two ports check 10 samples.
# What this catches is an allow rule widening from tcp:<port> to the host generally, or a
# future msb reading allow@host:tcp:N as allow@host. The consequence is not "one more
# service": the guest reaches msb's own API on the host and asks the supervisor for a sandbox
# with no --net-* flags at all — Tier 1 escaped by requisitioning an unpoliced guest, no
# hypervisor bug required. Docker's 2375/2376 and any host loopback dev server are the same
# class. A denial is instant, so a long list is nearly free; port 53 is excluded because msb's
# stub always connects there, and the proxy's own port because it is supposed to.
if [ "$mech" = 1 ]; then
  ports=""
  # The pool is POOL_SIZE ports starting at a base this guest is not told, so the window
  # around its own port covers it wherever in the pool that port sits. Another live session's
  # proxy port is a real host listener the rule must still exclude.
  n=$((pport - 16))
  while [ "$n" -le $((pport + 16)) ]; do
    [ "$n" -gt 0 ] && [ "$n" -le 65535 ] && [ "$n" != "$pport" ] && [ "$n" != 53 ] &&
      ports="$ports $phost/$n"
    n=$((n + 1))
  done
  for extra in 22 80 443 631 2375 2376 3000 3306 5000 5432 5555 6379 6443 8080 9090 32768; do
    [ "$extra" -ge $((pport - 16)) ] && [ "$extra" -le $((pport + 16)) ] && continue
    ports="$ports $phost/$extra"
  done
  # A boundary that drops costs $T per port instead of a millisecond, and the whole list would
  # then blow the budget and skip. Where the manner control did not see a refusal, sample.
  if [ "$manner" != refuse ]; then
    set -- $ports
    echo "          (check 13 samples 4 host ports, not $#: control 0b did not see this boundary"
    echo "           refuse, so each probe may cost up to ${T}s)"
    ports="$phost/22 $phost/2375 $phost/2376 $phost/$((pport + 16))"
  fi
  sweep port $ports
  sweep_verdict "host $phost on the ports the allow rule does not name"
  case $dv in p) P 13 "$dw" ;; f) F 13 "$dw" ;; *) S 13 "$dw" ;; esac
else
  S 13 "host's other listeners (control 0 failed: no working /dev/tcp probe)"
fi

# CHECK 15 tools:none — address classes other than one public unicast IP. Check 3 and the
# always-on probe are the same single target, 1.1.1.1:443. What this catches is a policy
# engine with a local-network exemption, a common default in this class of software: 1.1.1.1
# stays denied while private ranges, the host's LAN and 169.254.169.254 — instance
# credentials on a cloud host — open up. This is the one class where a failed connect is
# genuinely ambiguous, because an ALLOWED destination with nothing behind it also fails; the
# errno resolves it, and only a refusal counts. IPv6 link-local is left out on purpose: a
# scopeless fe80:: literal gives /dev/tcp EINVAL, which is not a boundary answer.
if [ "$mech" = 1 ]; then
  classes="10.0.0.1/80 192.168.1.1/443 172.16.0.1/80 100.64.0.1/80 169.254.169.254/80
           169.254.170.2/80 8.8.8.8/443 203.0.113.9/443"
  # The v6 documentation address joins the sweep only where this guest can source a global
  # v6 packet at all: on a guest with a ::/0 route and no v6 source address the probe dies
  # in-guest, lands in $sw_dead, and turned eight real refusals into a SKIP on Linux/KVM. A
  # destination nothing could ever have probed is not coverage lost, so it is excluded — by
  # the guest's own tables BEFORE any probe runs, never by an errno afterwards — and the
  # exclusion is named in the verdict, whichever verdict the sweep earns. This check is NOT
  # marked unavailable for it: its subject is the v4 classes too, and those eight denials
  # are assertions a whole-check verdict would throw away. Check 5 still probes v6 wherever
  # a ::/0 route exists, so a boundary that completes v6 handshakes is still caught even
  # where this sweep is v4-only.
  if has_v6_default && has_v6_global; then
    classes="$classes 2001:db8::1/443"; v6note=""
  else
    v6note=" (2001:db8::1:443 not probed: this guest cannot source a global v6 packet, so the v6 class has no subject here — check 5 reads the same tables)"
  fi
  sweep addr $classes
  sweep_verdict "private, CGNAT, link-local-metadata and second-public addresses"
  case $dv in p) P 15 "$dw$v6note" ;; f) F 15 "$dw$v6note" ;; *) S 15 "$dw$v6note" ;; esac
else
  S 15 "address classes (control 0 failed: no working /dev/tcp probe)"
fi

echo "== the proxy must answer at every address the alias maps to =="
# CHECK 11 tools:none subject:ipv6 — real clients pick the proxy address by getaddrinfo
# order, and /etc/hosts maps the alias to an IPv6 address too, which comes back first. The
# NAT completes a handshake on either family with nothing listening, so a listener missing a
# family strands every client that picks it on a dead "connection" that reads like a policy
# denial, and one family answering says nothing about the other.
#
# The v6 half's subject can be absent outright: on Linux/KVM the platform maps the alias to
# v4 only AND gives the guest no global-scope v6 source address, so no client in this guest
# could ever pick, or use, a v6 proxy address — there is nothing whose stranding this half
# would catch, and it is UNAVAILABLE. That is decided from /etc/hosts (already parsed below)
# and /proc/net/if_inet6, two of the guest's own tables and no errno anywhere, and only
# after the v4 half answered with the mark. A guest that COULD source v6 while the alias
# maps none keeps the SKIP: there the missing mapping is the platform withholding a subject
# this guest could have used, which deserves an alarm, not a waiver.
#
# The address count is therefore the coverage, and it has been seen to vary between runs — so
# it is reported rather than implied, and a run that ends up with nothing to probe on a family
# this guest can actually use SKIPs instead of passing. Two parse bugs made that count
# silently smaller: a final line with no trailing newline is dropped by `while read` (bash
# returns non-zero on it and the body never runs), and a CR from a CRLF file never equals the
# alias. Both are handled below.
addrs=""
while IFS= read -r line || [ -n "$line" ]; do
  line=${line//$'\r'/}; line=${line%%#*}; set -- $line
  [ $# -ge 2 ] || continue
  ip=$1; shift
  for n in "$@"; do
    [ "$n" = "$phost" ] || continue
    case " $addrs " in *" $ip "*) ;; *) addrs="$addrs $ip" ;; esac
  done
done < /etc/hosts
literal=""
[ -n "$addrs" ] || { addrs=" $phost"; literal=1; }   # an IP literal or non-hosts name
v4=""; v6=""
for a in $addrs; do case $a in *:*) v6="$v6 $a" ;; *) v4="$v4 $a" ;; esac; done
ok=""; dead=""; unmarked=""
for a in $addrs; do
  control_rc "$a" "$pport"; arc=$?
  case $arc in
    0) ok="$ok $a" ;;
    2) ok="$ok $a"; unmarked="$unmarked $a" ;;
    *) dead="$dead $a" ;;
  esac
done
if [ -n "$dead" ]; then
  F 11 "no proxy answer at$dead (answered:${ok:- nothing}) — clients on that family see a dead connection that reads like a denial"
elif [ -n "$unmarked" ]; then
  S 11 "something answered a 4xx at$unmarked without X-Silkgate: deny — the per-family claim cannot be attributed to this session's proxy"
elif [ -n "$literal" ]; then
  S 11 "the proxy URL names $phost, which /etc/hosts does not map — it answered, but this run probed one endpoint and so proves nothing about per-family coverage"
elif [ -z "$v6" ] && has_v6_default && ! has_v6_global; then
  U 11 "the proxy answered at$v4; /etc/hosts maps the alias to no IPv6 address, and /proc/net/if_inet6 holds no global-scope address to source a v6 connect from — no client in this guest could pick or use a v6 proxy address, so the v6 half of this check has no subject here"
elif [ -z "$v6" ] && has_v6_default; then
  S 11 "the proxy answered at$v4, but /etc/hosts maps the alias to no IPv6 address while this guest has a ::/0 route and an address to source from — the v6 half of this check had nothing to probe, so a v4-only listener would not be caught"
elif [ -z "$v4" ]; then
  S 11 "the proxy answered at$v6, but the alias maps to no IPv4 address — the v4 half of this check had nothing to probe"
else
  P 11 "proxy answered at every address the alias maps to — v4:$v4 v6:${v6:- none mapped, and no ::/0 route in this guest}"
fi

echo "== root reconfigures the guest — these mutate it, so they run last =="
# CHECK 7 tools:ip — root routes around the boundary. It must still be blocked, and the check
# must be able to notice if it is not. As written it discarded both `ip` exit codes, so a
# differently named NIC, a missing default route or a busybox `ip` left it a second copy of
# check 3 while its text claimed a root escape had been attempted — and worse, an on-link
# default with no gateway is WORSE connectivity than the route it replaces, so it degraded the
# guest and then read the damage as containment, for itself and for every check after it.
#
# So: the NIC and gateway come from the kernel rather than being assumed; both `ip` calls are
# tested AND the kernel is re-read to confirm the route really moved, because an `ip` that
# exits 0 without doing anything is the same false pass by another route; an off-subnet oracle
# (TCP/53, which msb answers for any destination) must still work after the change, or the
# guest broke its own networking and nothing is proven; control 0 must still answer; and the
# original route is restored either way, with both the kernel and control 0 re-checked.
#
# read_default -> $rd_dev, $rd_gw ("0.0.0.0" when the default is on-link), non-zero if there
# is no default route at all. /proc/net/route stores the gateway as a little-endian hex word.
read_default(){
  local i d g _
  rd_dev=""; rd_gw=""
  while read -r i d g _; do
    [ "$d" = 00000000 ] || continue
    rd_dev=$i
    rd_gw=$((0x${g:6:2})).$((0x${g:4:2})).$((0x${g:2:2})).$((0x${g:0:2}))
    return 0
  done < /proc/net/route
  return 1
}
route_restore(){
  [ -n "$rt_changed" ] || return 0
  ip route del default 2>/dev/null
  if [ "$rt_gw" = 0.0.0.0 ]; then ip route add default dev "$rt_dev" 2>/dev/null
  else ip route add default via "$rt_gw" dev "$rt_dev" 2>/dev/null; fi
  rt_changed=""
  read_default
  if [ "$rd_gw" = "$rt_gw" ] && [ "$rd_dev" = "$rt_dev" ] && control_rc "$phost" "$pport"; then
    echo "[OKAY] 0r. default route restored (via $rt_gw dev $rt_dev); the proxy still answers"
  else
    mech=0
    echo "[WARN] 0r. the default route was NOT restored — /proc/net/route says via ${rd_gw:-none}"
    echo "           dev ${rd_dev:-none}, wanted via $rt_gw dev $rt_dev. Anything after this SKIPs"
    echo "           rather than reading the damage as containment; the guest is disposable, so"
    echo "           the repair is to end the session, not to fix the route."
  fi
}
rt_changed=""; rt_dev=""; rt_gw=""
if ! have ip; then
  S 7 "route-escape (no ip tool)"
elif [ "$mech" != 1 ]; then
  S 7 "route-escape (control 0 failed: no working /dev/tcp probe)"
else
  why=""
  read_default && rt_dev=$rd_dev && rt_gw=$rd_gw || why="no default route in /proc/net/route to replace"
  [ "$rt_gw" != 0.0.0.0 ] || why="this guest's default route is already on-link (dev $rt_dev, no gateway), so replacing it with an on-link route would change nothing"
  if [ -z "$why" ]; then
    tcp 1.1.1.1 53
    [ "$tcp_how" = connected ] || why="no off-subnet oracle before the change (TCP/53 to 1.1.1.1: $tcp_how, $tcp_errno), so a blocked probe after it could not be attributed"
  fi
  if [ -z "$why" ]; then
    ip route del default 2>/dev/null || why="ip route del default failed (exit $?) — nothing was changed, so this would have been check 3 again"
  fi
  if [ -z "$why" ]; then
    rt_changed=1
    ip route add default dev "$rt_dev" 2>/dev/null ||
      why="ip route add default dev $rt_dev failed (exit $?) — the guest is now routeless, not escaping"
  fi
  if [ -z "$why" ]; then
    read_default
    { [ "$rd_gw" = 0.0.0.0 ] && [ "$rd_dev" = "$rt_dev" ]; } ||
      why="ip reported success but /proc/net/route still says via ${rd_gw:-none} dev ${rd_dev:-none} — the route did not move, so this would have been check 3 again"
  fi
  if [ -z "$why" ]; then
    tcp 1.1.1.1 53
    [ "$tcp_how" = connected ] ||
      why="the on-link default route left this guest unable to reach anything off-subnet (TCP/53 to 1.1.1.1: $tcp_how, $tcp_errno) — it broke its own networking, which is not containment"
  fi
  if [ -z "$why" ]; then
    control_rc "$phost" "$pport" ||
      why="the proxy stopped answering after the route change, so the guest's allowed path is gone and a denial cannot be attributed to policy"
  fi
  if [ -z "$why" ]; then
    tcp 1.1.1.1 443; grade "after root replaced the default route with an on-link one on $rt_dev, TCP to 1.1.1.1:443"
  else
    dv=s; dw="route-escape: $why"
  fi
  route_restore
  case $dv in p) P 7 "$dw" ;; f) F 7 "$dw" ;; *) S 7 "$dw" ;; esac
fi

# CHECK 14 tools:ip,curl — root re-addresses the guest, which is a different question from
# re-routing. THREAT-MODEL's key constraint is that root-in-guest can reconfigure eth0, add
# routes and craft raw frames and every frame still terminates in the host stack; check 7
# tests only the routes clause. If msb's engine ever matched on the guest's source address —
# a natural way to write a per-sandbox rule — then `ip addr add` is a total Tier-1 escape, and
# the guest looks identical from every other angle: the allow rule simply stops applying, and
# the deny with it. /dev/tcp cannot choose a source address, so this is the one check that
# needs curl for a reason other than TLS, and it reads curl's own message rather than its exit
# code, which conflates a refused connect with a certificate it does not trust.
#
# The control is the allowed path from the NEW source, and its failure is the answer rather
# than an inconclusive run: if even the permitted destination stops answering once the source
# changes, the policy is keyed to something this guest cannot choose and it fails closed,
# which is exactly the property being tested. Measured on msb 0.5.4, that is what happens —
# a self-assigned source times out against the proxy itself — so reading it as inconclusive
# left the check unable to pass at all, and `verify --full` unable to succeed on a healthy
# host. Only a source that CAN reach the proxy goes on to probe a denied destination. The
# address is removed either way.
if ! have ip || ! have curl; then
  S 14 "root re-addressing (needs ip and curl — see README 'full check')"
elif [ "$mech" != 1 ]; then
  S 14 "root re-addressing (control 0 failed, or an earlier check left the guest without its allowed path)"
else
  src=10.99.99.99
  [ -n "$rt_dev" ] || { read_default; rt_dev=$rd_dev; }
  why=""
  [ -n "$rt_dev" ] || why="no default-route interface in /proc/net/route to add an address to"
  if [ -z "$why" ]; then
    ip addr add "$src/32" dev "$rt_dev" 2>/dev/null || why="ip addr add $src/32 dev $rt_dev failed (exit $?) — nothing was changed"
  else
    added=""
  fi
  [ -z "$why" ] && added=1
  src_ok=0
  if [ -z "$why" ]; then
    out=$(curl -sSv --interface "$src" -o /dev/null --max-time $T -x "$PROXY" http://silkgate.invalid/ 2>&1)
    printf '%s\n' "$out" | grep -qi '^< *x-silkgate: *deny' && src_ok=1
  fi
  if [ -z "$why" ] && [ "$src_ok" = 1 ]; then
    t0=$(_us)
    out=$(curl -sSv --interface "$src" --noproxy '*' -o /dev/null --max-time $T https://1.1.1.1/ 2>&1)
    tcp_ms=$(( ($(_us) - t0) / 1000 ))
    case $out in
      *"Connected to 1.1.1.1"*) tcp_how=connected ;;
      *) tcp_how=$(classify 1 "$out") ;;
    esac
    tcp_errno=$(curl_why "$out")
    grade "from a self-assigned source address ($src on $rt_dev), TCP to 1.1.1.1:443"
  elif [ -z "$why" ]; then
    dv=p; dw="a self-assigned source ($src on $rt_dev) reaches nothing at all, the allowed path included ($(curl_why "$out")) — so the policy is not keyed to an address this guest can choose"
  else
    dv=s; dw="root re-addressing: $why"
  fi
  if [ -n "$added" ]; then
    ip addr del "$src/32" dev "$rt_dev" 2>/dev/null
    if control_rc "$phost" "$pport"; then
      echo "[OKAY] 0a. $src removed from $rt_dev; the proxy still answers"
    else
      mech=0
      echo "[WARN] 0a. $src could not be removed cleanly — the proxy no longer answers at $phost:$pport"
    fi
  fi
  case $dv in p) P 14 "$dw" ;; f) F 14 "$dw" ;; *) S 14 "$dw" ;; esac
fi

echo
echo "CHECKS: ran=$(sortnum "${ran//,/ }") skipped=$(sortnum "${skipped//,/ }") unavailable=$(sortnum "${unavail//,/ }")"
echo "RESULT: $pass passed, $fail failed"
if [ "$fail" -eq 0 ] && [ -z "$skipped" ] && [ -z "$unavail" ]; then
  echo "Containment holds: every check ran, no direct egress, the proxy the only path out."
elif [ "$fail" -eq 0 ] && [ -z "$skipped" ]; then
  echo "Containment holds for every check this guest gave a subject; check(s) $(sortnum "${unavail//,/ }") found"
  echo "nothing here to test — the [UNAV] lines above say what this guest lacks, and why that"
  echo "is read from its own tables rather than from a probe that merely failed."
elif [ "$fail" -eq 0 ]; then
  echo "No check failed, but $(sortnum "${skipped//,/ }") did not run — this run does not prove"
  echo "containment on its own; silkgate verify decides whether the set that ran is enough."
else
  echo "LEAK — use a fallback (doc/ARCHITECTURE.md: VZFileHandle gateway / no-NIC+vsock)."
  exit 1
fi
