#!/bin/sh
# The header-spoofing bypass, end to end, through a real proxy. No API key needed: the rules
# come from the node profile, which injects nothing.
#
# Expected if the bug is fixed: both requests return 403 and the audit log names example.com
# both times. Observed today: the second is allowed, reaches example.com, and the audit log
# records "allow registry.npmjs.org" for it.
#
#     sh test/repro/host_spoof_live.sh
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
PORT=8099
LOG=$(mktemp)

"$REPO/cli/silkgate" proxy --with node --port "$PORT" >"$LOG" 2>&1 &
sleep 6

printf '1. honest request to an unlisted host   : '
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -x "http://127.0.0.1:$PORT" http://example.com/

printf '2. same, claiming Host: registry.npmjs.org: '
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -x "http://127.0.0.1:$PORT" \
     -H 'Host: registry.npmjs.org' http://example.com/

echo '3. what the audit log says happened:'
grep '"decision"' "$LOG" | sed 's/^\[[^]]*\] /     /'

pkill -f "listen-port $PORT" 2>/dev/null
echo
echo 'A 301 (or anything but 403) on line 2 means policy was decided from the header while the'
echo 'connection went to example.com, and that the audit trail is guest-forgeable.'
