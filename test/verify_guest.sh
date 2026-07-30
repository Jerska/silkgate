#!/usr/bin/env bash
# Tier 1 verification — run as ROOT INSIDE the microsandbox guest (Debian + bash).
#
# Containment checks (3,7) use bash /dev/tcp built-ins, so they run on a BARE debian
# image with no installed tools and no network. The proxy-path checks (1,2) need curl +
# a trusted MITM CA; they SKIP if curl is absent (see README "full check").
#
# Pass = only 1 & 2 succeed (when run); every blocked check fails to connect.

PROXY="${HTTPS_PROXY:-http://host.microsandbox.internal:8090}"
T=5
pass=0; fail=0
P(){ echo "[PASS] $1"; pass=$((pass+1)); }
F(){ echo "[FAIL] $1"; fail=$((fail+1)); }
S(){ echo "[SKIP] $1"; }
have(){ command -v "$1" >/dev/null 2>&1; }
tcp(){ timeout "$T" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }   # exit 0 = connected

echo "PROXY=$PROXY"
echo "== positive controls (need curl + trusted CA; SKIP if absent) =="
if have curl; then
  curl -fsS --max-time $T -x "$PROXY" https://registry.npmjs.org/lodash >/dev/null 2>&1 \
    && P "1. allowed host via proxy" \
    || F "1. allowed host via proxy  (CA trust / proxy / allow-rule not set up?)"
  code=$(curl -s -o /dev/null --max-time $T -w '%{http_code}' -x "$PROXY" https://evil.com 2>/dev/null)
  [ "$code" = "403" ] && P "2. unlisted host via proxy -> 403" \
                      || F "2. unlisted host -> got '$code' (want 403; '000' = CA not trusted)"
else
  S "1-2. proxy path (curl not installed — see README 'full check')"
fi

echo "== egress that MUST be blocked (a failure here = good) =="
# 3. direct TCP/443 to a raw IP, bypassing any proxy — tool-free (bash builtin)
tcp 1.1.1.1 443 && F "3. direct TCP 1.1.1.1:443 connected" || P "3. direct TCP egress blocked"

# 4. external DNS resolution (msb intercepts ALL UDP/53; test the ANSWER, not the exit code:
#    dig/getent return success even on NXDOMAIN, so check for a non-empty resolved address).
if have dig || have getent || have python3; then
  if have dig;      then ans=$(dig +short +time=3 +tries=1 example.com 2>/dev/null | head -n1)
  elif have getent; then ans=$(getent hosts example.com 2>/dev/null | head -n1)
  else                   ans=$(python3 -c 'import socket;print(socket.gethostbyname("example.com"))' 2>/dev/null); fi
  [ -n "$ans" ] && F "4. external DNS resolved example.com -> $ans" || P "4. external DNS blocked (NXDOMAIN/empty)"
else
  S "4. DNS (no dig/getent/python3)"
fi

# 5. IPv6 egress (IP literal, no DNS)
if have curl; then
  curl -s --noproxy '*' --max-time $T -g 'https://[2606:4700:4700::1111]/' >/dev/null 2>&1 \
    && F "5. IPv6 egress got through" || P "5. IPv6 egress blocked"
else
  S "5. IPv6 (no curl)"
fi

# 6. ICMP / raw
if have ping; then
  ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && F "6. ICMP reached 1.1.1.1" || P "6. ICMP blocked"
else
  S "6. ICMP (no ping)"
fi

# 7. root tries to route around it — must STILL be blocked (tool-free)
if have ip; then
  ip route del default 2>/dev/null
  ip route add default dev eth0 2>/dev/null
  tcp 1.1.1.1 443 && F "7. escaped after root route change" || P "7. still blocked after root route change"
else
  S "7. route-escape (no ip tool)"
fi

echo
echo "RESULT: $pass passed, $fail failed"
if [ "$fail" -eq 0 ]; then
  echo "Containment holds: no direct egress; the proxy is the only path out."
else
  echo "LEAK — use a fallback (../ARCHITECTURE.md: VZFileHandle gateway / no-NIC+vsock)."
fi
