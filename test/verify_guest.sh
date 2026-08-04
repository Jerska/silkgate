#!/usr/bin/env bash
# Tier 1 verification — run as ROOT INSIDE the microsandbox guest (Debian + bash).
#
# Containment checks (3,7) use bash /dev/tcp built-ins, so they run on a BARE debian
# image with no installed tools and no network. The proxy-path checks (1,2) need curl +
# a trusted MITM CA; they SKIP if curl is absent (see README "full check").
#
# Pass = only 1 & 2 succeed (when run); every blocked check fails to connect. A blocked
# check concludes containment from a probe that did NOT connect, which says nothing unless
# the probe works at all — so check 0 is a positive control for the tool-free mechanism
# (the proxy port is the one thing Tier 1 allows), and 3/7 SKIP rather than PASS without it.
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

echo
echo "CHECKS: ran=${ran#,} skipped=${skipped#,}"
echo "RESULT: $pass passed, $fail failed"
if [ "$fail" -eq 0 ]; then
  echo "Containment holds: no direct egress; the proxy is the only path out."
else
  echo "LEAK — use a fallback (doc/ARCHITECTURE.md: VZFileHandle gateway / no-NIC+vsock)."
  exit 1
fi
