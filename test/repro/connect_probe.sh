#!/bin/sh
# CONNECT is answered without any policy decision and without an audit line.
#
# The addon implements `request` and `responseheaders` only. mitmproxy dispatches CONNECT
# through the `http_connect` hook, which nothing here implements, so the authority in a
# CONNECT is never matched against the ruleset and never logged.
#
# What this script shows (verified): "HTTP/1.1 200 Connection established" for a CONNECT to a
# host no rule allows, and zero audit decisions for it.
#
# What it does NOT show, and what a reviewer suspected: that the tunnel then carries bytes to
# an arbitrary host:port. Two attempts — a TLS-looking first byte and a plainly non-HTTP one —
# delivered nothing to a loopback listener. mitmproxy's `rawtcp` option does default to True,
# so the concern is worth closing anyway, but treat the exploitability as unproven until this
# script demonstrates data flowing.
#
#     sh test/repro/connect_probe.sh
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
PORT=8099
LOG=$(mktemp)

"$REPO/cli/silkgate" proxy --with node --port "$PORT" >"$LOG" 2>&1 &
sleep 6

python3 - "$PORT" <<'PY'
import socket, sys, threading, time

got = []
def listener():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 9099)); s.listen(1)
    conn, _ = s.accept()
    got.append(conn.recv(64)); conn.sendall(b"REPLY-FROM-LOOPBACK"); conn.close(); s.close()

threading.Thread(target=listener, daemon=True).start()
time.sleep(0.5)

p = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
p.sendall(b"CONNECT localhost:9099 HTTP/1.1\r\nHost: localhost:9099\r\n\r\n")
time.sleep(1)
print("   proxy answer to CONNECT localhost:9099 :", p.recv(64).split(b"\r\n")[0].decode())
p.sendall(b"\xff\xfe\xfd\xfc RAW-NOT-HTTP-NOT-TLS")
time.sleep(1.5)
print("   loopback listener received             :", got[0] if got else b"(nothing)")
p.close()
PY

echo "   audit decisions logged for the CONNECT :" "$(grep -c '"decision"' "$LOG")"
pkill -f "listen-port $PORT" 2>/dev/null
echo
echo 'Fix regardless of exploitability: implement http_connect, match req.host:req.port against'
echo 'the ruleset there, and start mitmdump with --set rawtcp=false.'
