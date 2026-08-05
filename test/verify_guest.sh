#!/usr/bin/env bash
# Tier 1 verification — run as ROOT INSIDE the microsandbox guest (Debian + bash).
#
# Containment checks 3, 7, 9, 10 and the family check 11 use bash /dev/tcp and /dev/udp
# built-ins plus coreutils, so they run on a BARE debian image with no installed tools
# and no network. The proxy-path checks (1,2) need curl + a trusted MITM CA, 4-6 need
# dig/ping/ip, 8 needs dig; each SKIPs when its tool is absent (see README "full check").
#
# Pass = the proxy answers its own checks (1, 2, 11) and no blocked probe reaches
# anything REAL — where "real" carries weight: port 53 always ANSWERS, from msb's own
# stub, so on that port only an actual resolution, or a reply that unroutable TEST-NET
# does not mirror, counts as egress. A blocked check that concludes containment from a
# probe that did NOT connect says nothing unless the probe works at all — so check 0 is
# a positive control for the tool-free TCP mechanism (the proxy port is the one thing
# Tier 1 allows) and 3/7/10/11 SKIP rather than PASS without it; check 9 carries its own
# UDP control, msb's port-53 stub, which answers even for TEST-NET destinations.
# The last two lines are for the caller: which checks ran, and the pass/fail totals. A
# SKIP is neither, and `silkgate verify` asserts the set it expected to run.

PROXY="${HTTPS_PROXY:-http://host.microsandbox.internal:8090}"
T=5
pass=0; fail=0; ran=""; skipped=""
P(){ echo "[PASS] $1. $2"; pass=$((pass+1)); ran="$ran,$1"; }
F(){ echo "[FAIL] $1. $2"; fail=$((fail+1)); ran="$ran,$1"; }
S(){ echo "[SKIP] $1. $2"; skipped="$skipped,$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }
tcp(){ timeout "$T" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }   # exit 0 = connected
# udp_reply KIND HOST PORT — exit 0 = something answered within $T. UDP has no handshake,
# so sending always "succeeds"; only a reply carries information, and read -t bounds the
# only step that can block. The payloads are requests a real server answers: a DNS query
# for example.com (ID 0x2a2a), an NTP v3 client packet, and a 1200-byte QUIC long header
# in an unknown version, which RFC 9000 §6.1 obliges a QUIC server to meet with a
# Version Negotiation packet. Every write on the socket is its own datagram, so the
# pieces go through one full-block dd — split across two writes they arrive as fragments
# no real server would answer, and the probe would read as containment on an open network.
udp_reply(){
  exec 3<>"/dev/udp/$2/$3" || return 1
  case $1 in
    dns)  printf '\052\052\001\000\000\001\000\000\000\000\000\000\007example\003com\000\000\001\000\001' ;;
    ntp)  printf '\033'; head -c 47 /dev/zero ;;
    quic) printf '\300\032\052\072\112\010AAAAAAAA\010BBBBBBBB'; head -c 1177 /dev/zero ;;
  esac | dd iflag=fullblock bs=1200 count=1 >&3 2>/dev/null || return 1
  IFS= read -r -t "$T" -N 1 first <&3
  rc=$?; exec 3<&-; return $rc
}

echo "PROXY=$PROXY"

echo "== control: the probe mechanism itself (tool-free) =="
# Host:port out of $PROXY — the guest's only permitted egress, so this MUST work.
target=${PROXY#*://}; target=${target%%/*}
case "$target" in
  *:*) phost=${target%:*}; pport=${target##*:} ;;
  *)   phost=$target;      pport=80 ;;
esac
# A connect alone proves nothing: microsandbox's guest->host NAT completes the TCP
# handshake inside the VMM, so /dev/tcp reports success even with no listener on the host
# at all (observed with the proxy stopped). The control therefore speaks HTTP and requires
# the proxy's own answer — a request no ruleset allows, so it is refused from the proxy's
# memory and needs neither an allow-rule nor any upstream egress to succeed.
control(){
  exec 3<>"/dev/tcp/$1/$2" || return 1
  printf 'GET http://silkgate.invalid/ HTTP/1.1\r\nHost: silkgate.invalid\r\n\r\n' >&3 || return 1
  IFS= read -r reply <&3 || return 1
  exec 3<&-
  case "$reply" in *40[0-9]*) return 0 ;; *) return 1 ;; esac
}
if timeout "$T" bash -c "$(declare -f control); control $phost $pport" 2>/dev/null; then
  mech=1; echo "[OKAY] 0. bash /dev/tcp works and the proxy answered at $phost:$pport"
else
  mech=0; echo "[WARN] 0. no proxy answer at $phost:$pport — a failed connect below would"
  echo "          not distinguish containment from a probe that cannot reach anything"
fi

echo "== positive controls (need curl + trusted CA; SKIP if absent) =="
if have curl; then
  curl -fsS --max-time $T -x "$PROXY" https://registry.npmjs.org/lodash >/dev/null 2>&1 \
    && P 1 "allowed host via proxy" \
    || F 1 "allowed host via proxy  (CA trust / proxy / allow-rule not set up?)"
  # The refusal may arrive in-band (403 to the request) or as a rejected CONNECT, which
  # the proxy answers 403 before any tunnel exists — curl then reports code 000 and names
  # the 403 on stderr. Both are the proxy denying an unlisted host, so both pass; what
  # must not pass is a 2xx, or a failure that never mentions a 403 (no CA trust, no proxy).
  said=$(curl -sS -o /dev/null --max-time $T -w '%{http_code}' -x "$PROXY" https://evil.com 2>&1)
  case "$said" in
    *403*) P 2 "unlisted host via proxy -> 403" ;;
    *)     F 2 "unlisted host -> '$said' (want a 403 from the proxy; '000' alone = never reached it)" ;;
  esac
else
  S 1 "allowed host via proxy (curl not installed — see README 'full check')"
  S 2 "unlisted host via proxy -> 403 (curl not installed — see README 'full check')"
fi

echo "== egress that MUST be blocked (a failure here = good) =="
# 3. direct TCP/443 to a raw IP, bypassing any proxy — tool-free (bash builtin)
if [ "$mech" = 1 ]; then
  tcp 1.1.1.1 443 && F 3 "direct TCP 1.1.1.1:443 connected" || P 3 "direct TCP egress blocked"
else
  S 3 "direct TCP egress (control 0 failed: no working /dev/tcp probe)"
fi

# 4. external DNS resolution (msb intercepts ALL UDP/53; test the ANSWER, not the exit code:
#    dig/getent return success even on NXDOMAIN, so check for a non-empty resolved address).
if have dig || have getent || have python3; then
  if have dig;      then tool=dig; ans=$(dig +short +time=3 +tries=1 example.com 2>/dev/null | head -n1)
  elif have getent; then tool=getent; ans=$(getent hosts example.com 2>/dev/null | head -n1)
  else                   tool=python3; ans=$(python3 -c 'import socket;print(socket.gethostbyname("example.com"))' 2>/dev/null); fi
  [ -n "$ans" ] && F 4 "external DNS resolved example.com -> $ans (via $tool)" \
                || P 4 "external DNS blocked (NXDOMAIN/empty via $tool)"
else
  S 4 "DNS (no dig/getent/python3)"
fi

# 5. IPv6 egress (IP literal, no DNS). curl's exit status is reported, so a usage or CA
#    error is distinguishable from a refused connection.
if have curl; then
  curl -s --noproxy '*' --max-time $T -g 'https://[2606:4700:4700::1111]/' >/dev/null 2>&1
  rc=$?
  [ $rc -eq 0 ] && F 5 "IPv6 egress got through" || P 5 "IPv6 egress blocked (curl exit $rc)"
else
  S 5 "IPv6 (no curl)"
fi

# 6. ICMP / raw
if have ping; then
  ping -c1 -W2 1.1.1.1 >/dev/null 2>&1
  rc=$?
  [ $rc -eq 0 ] && F 6 "ICMP reached 1.1.1.1" || P 6 "ICMP blocked (ping exit $rc)"
else
  S 6 "ICMP (no ping)"
fi

# 7. root tries to route around it — must STILL be blocked (tool-free)
if ! have ip; then
  S 7 "route-escape (no ip tool)"
elif [ "$mech" != 1 ]; then
  S 7 "route-escape (control 0 failed: no working /dev/tcp probe)"
else
  ip route del default 2>/dev/null
  ip route add default dev eth0 2>/dev/null
  tcp 1.1.1.1 443 && F 7 "escaped after root route change" || P 7 "still blocked after root route change"
fi

# 8. TCP/53 — a general-purpose tunnel if it egresses, and the one blocked port that
#    ANSWERS: msb's stub returns an identical REFUSED for every destination, TEST-NET
#    included, so "a reply arrived" must never be read as "it egressed". The leak is a
#    real resolution; a reply that resolves nothing passes only once 192.0.2.1 mirrors
#    it, because nothing routes to TEST-NET — an answer "from" there is proof the
#    responder is local.
if have dig; then
  out=$(dig +tcp +short +time=3 +tries=1 @1.1.1.1 example.com 2>/dev/null); rc=$?
  if [ $rc -eq 0 ] && [ -n "$out" ]; then
    F 8 "TCP/53 egressed: a real resolver answered example.com -> ${out%%$'\n'*}"
  elif [ $rc -eq 0 ]; then
    dig +tcp +time=3 +tries=1 @192.0.2.1 example.com >/dev/null 2>&1 \
      && P 8 "TCP/53 answers but resolves nothing — msb's stub (TEST-NET 'replies' too)" \
      || F 8 "TCP/53: 1.1.1.1 replied, TEST-NET stayed silent — reply not shown to be local"
  elif [ $rc -eq 9 ]; then
    P 8 "TCP/53 blocked (no reply from 1.1.1.1)"
  else
    F 8 "TCP/53: dig exit $rc is not containment evidence"
  fi
else
  S 8 "TCP/53 (no dig)"
fi

# 9. UDP beyond 53 — QUIC on UDP/443 bypasses an HTTP proxy entirely (THREAT-MODEL names
#    it), so default-deny must cover every UDP port, not only the intercepted 53. Silence
#    from a broken probe looks identical to containment, so first the control: a DNS
#    datagram to TEST-NET on 53, whose "answer" can only be msb's stub — one exchange
#    proving both that the send/read path works and that port-53 replies are synthesized
#    locally (the resolution those replies deny is check 4's job). The probes then run
#    concurrently, and a reply counts as egress only where TEST-NET does not mirror it.
if udp_reply dns 192.0.2.1 53 2>/dev/null; then
  UTMP="/tmp/verify-udp.$$"
  ( udp_reply quic 1.1.1.1 443 2>/dev/null && : >"$UTMP.quic" ) &
  ( udp_reply ntp 216.239.35.0 123 2>/dev/null && : >"$UTMP.ntp" ) &
  wait
  leak=""; mirrored=""
  for probe in "quic 1.1.1.1 443" "ntp 216.239.35.0 123"; do
    set -- $probe
    [ -e "$UTMP.$1" ] || continue
    if udp_reply "$1" 192.0.2.1 "$3" 2>/dev/null; then mirrored="$mirrored $1/$3"
    else leak="$leak $1@$2:$3"; fi
  done
  rm -f "$UTMP.quic" "$UTMP.ntp"
  if [ -n "$leak" ]; then
    F 9 "UDP egressed:$leak answered where TEST-NET stayed silent"
  elif [ -n "$mirrored" ]; then
    P 9 "UDP beyond 53 intercepted locally ($mirrored answered, and TEST-NET mirrors it)"
  else
    P 9 "UDP beyond 53 blocked (quic/443 and ntp/123 both silent)"
  fi
else
  S 9 "UDP beyond 53 (no reply from msb's port-53 stub, so a silent probe would prove nothing)"
fi

# 10. the host itself, off the proxy port — the Tier-1 rule is one port, not one host,
#     so the host's other listeners (an ssh daemon, a dev server) must be as unreachable
#     as the internet. A connect here needs no listener to succeed — the NAT completes
#     the handshake for any host port the policy allows (see check 0) — so success IS
#     the leak, and a denial is what a healthy host shows.
if [ "$mech" = 1 ]; then
  alt=$((pport + 1)); [ "$alt" -gt 65535 ] && alt=$((pport - 1))
  hit=""
  for hp in "$alt" 22; do tcp "$phost" "$hp" && hit="$hit $hp"; done
  if [ -n "$hit" ]; then
    F 10 "host port(s)$hit connected — the allow rule is wider than tcp:$pport"
  else
    P 10 "host unreachable off the proxy port (tried $alt and 22)"
  fi
else
  S 10 "host ports beside the proxy's (control 0 failed: no working /dev/tcp probe)"
fi

echo "== the proxy must answer at every address the alias maps to =="
# 11. real clients pick the proxy address by getaddrinfo order — /etc/hosts maps the
#     alias to an IPv6 address too, and that one comes back first — while the NAT
#     completes a handshake on either family with nothing listening. So a listener
#     missing a family strands every client that picks it on a dead "connection" that
#     reads like a policy denial, and one family answering says nothing about the other:
#     each mapped address must produce the proxy's own refusal itself.
addrs=""
while IFS= read -r line; do
  line=${line%%#*}; set -- $line
  [ $# -ge 2 ] || continue
  ip=$1; shift
  for n in "$@"; do
    [ "$n" = "$phost" ] || continue
    case " $addrs " in *" $ip "*) ;; *) addrs="$addrs $ip" ;; esac
  done
done < /etc/hosts
[ -n "$addrs" ] || addrs=" $phost"       # an IP literal or non-hosts name: probe it as-is
ok=""; dead=""
for a in $addrs; do
  if timeout "$T" bash -c "$(declare -f control); control $a $pport" 2>/dev/null
  then ok="$ok $a"; else dead="$dead $a"; fi
done
if [ -z "$dead" ]; then
  P 11 "proxy answered at every alias address:$ok"
elif [ -n "$ok" ] || [ "$mech" = 1 ]; then
  F 11 "no proxy answer at$dead (answered:${ok:- nothing}) — clients on that family see a dead connection that reads like a denial"
else
  S 11 "per-family proxy answer (nothing answered and control 0 failed: probe mechanism unproven)"
fi

echo
echo "CHECKS: ran=${ran#,} skipped=${skipped#,}"
echo "RESULT: $pass passed, $fail failed"
if [ "$fail" -eq 0 ]; then
  echo "Containment holds: no direct egress; the proxy is the only path out."
else
  echo "LEAK — use a fallback (doc/ARCHITECTURE.md: VZFileHandle gateway / no-NIC+vsock)."
  exit 1
fi
