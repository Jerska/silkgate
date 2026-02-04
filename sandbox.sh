#!/bin/bash
set -euo pipefail

# Claude Code Network Sandbox
# Runs Claude Code in an isolated network namespace with HTTP method/path filtering

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_PORT="8080"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_dependencies() {
    local missing=()

    command -v ip &>/dev/null || missing+=("iproute2")
    command -v iptables &>/dev/null || missing+=("iptables")
    command -v mitmdump &>/dev/null || missing+=("mitmproxy")
    command -v claude &>/dev/null || missing+=("claude-code")
    command -v jq &>/dev/null || missing+=("jq")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo "Install with:"
        echo "  apt install iproute2 iptables jq"
        echo "  pip install mitmproxy"
        exit 1
    fi
}

cleanup() {
    log_info "Cleaning up..."

    # Kill mitmproxy if running
    if [[ -f "$SESSION_DIR/mitmproxy.pid" ]]; then
        kill "$(cat "$SESSION_DIR/mitmproxy.pid")" 2>/dev/null || true
        rm -f "$SESSION_DIR/mitmproxy.pid"
    fi

    # Remove iptables rules
    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p tcp --dport 80 -j REDIRECT --to-port "$PROXY_PORT" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p tcp --dport 443 -j REDIRECT --to-port "$PROXY_PORT" 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -j DROP 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$SANDBOX_IP/32" -j MASQUERADE 2>/dev/null || true

    # Remove veth pair (removing one end removes both)
    ip link delete "$VETH_HOST" 2>/dev/null || true

    # Remove namespace
    ip netns delete "$NAMESPACE" 2>/dev/null || true

    # Remove namespace DNS config
    rm -rf "/etc/netns/$NAMESPACE" 2>/dev/null || true

    log_info "Cleanup complete (session $SESSION_ID kept for logs)"
}

setup_namespace() {
    log_info "Creating network namespace: $NAMESPACE"

    # Create namespace
    ip netns add "$NAMESPACE"

    # Create veth pair
    ip link add "$VETH_HOST" type veth peer name "$VETH_SANDBOX"

    # Move one end into namespace
    ip link set "$VETH_SANDBOX" netns "$NAMESPACE"

    # Configure host side
    ip addr add "$HOST_IP/24" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    # Configure sandbox side
    ip netns exec "$NAMESPACE" ip addr add "$SANDBOX_IP/24" dev "$VETH_SANDBOX"
    ip netns exec "$NAMESPACE" ip link set "$VETH_SANDBOX" up
    ip netns exec "$NAMESPACE" ip link set lo up

    # Set default route in sandbox to go through host
    ip netns exec "$NAMESPACE" ip route add default via "$HOST_IP"

    log_info "Namespace configured"
}

setup_routing() {
    log_info "Setting up traffic routing to proxy"

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Redirect HTTP/HTTPS to mitmproxy (transparent mode)
    iptables -t nat -A PREROUTING -i "$VETH_HOST" -p tcp --dport 80 -j REDIRECT --to-port "$PROXY_PORT"
    iptables -t nat -A PREROUTING -i "$VETH_HOST" -p tcp --dport 443 -j REDIRECT --to-port "$PROXY_PORT"

    # Allow only DNS and proxied HTTP/HTTPS, block everything else
    iptables -A FORWARD -i "$VETH_HOST" -p udp --dport 53 -j ACCEPT   # DNS
    iptables -A FORWARD -i "$VETH_HOST" -p tcp --dport 80 -j ACCEPT   # HTTP (to proxy)
    iptables -A FORWARD -i "$VETH_HOST" -p tcp --dport 443 -j ACCEPT  # HTTPS (to proxy)
    iptables -A FORWARD -i "$VETH_HOST" -j DROP                       # Block everything else

    # NAT for allowed traffic
    iptables -t nat -A POSTROUTING -s "$SANDBOX_IP/32" -j MASQUERADE

    log_info "Routing configured (non-HTTP blocked)"
}

setup_dns() {
    log_info "Setting up DNS in sandbox"

    # Create a resolv.conf for the namespace
    mkdir -p "/etc/netns/$NAMESPACE"
    echo "nameserver 8.8.8.8" > "/etc/netns/$NAMESPACE/resolv.conf"
    echo "nameserver 8.8.4.4" >> "/etc/netns/$NAMESPACE/resolv.conf"

    log_info "DNS configured"
}

install_ca_cert() {
    log_info "Setting up mitmproxy CA certificate"

    # Generate certs if they don't exist
    if [[ ! -f ~/.mitmproxy/mitmproxy-ca-cert.pem ]]; then
        log_info "Generating mitmproxy CA certificate..."
        # Run mitmproxy briefly to generate certs
        timeout 2 mitmdump || true
    fi

    MITMPROXY_CA="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
    SANDBOX_CA_DIR="$SESSION_DIR/ca-certs"
    SANDBOX_CA_BUNDLE="$SANDBOX_CA_DIR/ca-certificates.crt"

    # Start with system CA bundle
    if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
        # Debian/Ubuntu
        cp /etc/ssl/certs/ca-certificates.crt "$SANDBOX_CA_BUNDLE"
    elif [[ -f /etc/pki/tls/certs/ca-bundle.crt ]]; then
        # RHEL/Fedora
        cp /etc/pki/tls/certs/ca-bundle.crt "$SANDBOX_CA_BUNDLE"
    elif [[ -f /etc/ssl/cert.pem ]]; then
        # Alpine/others
        cp /etc/ssl/cert.pem "$SANDBOX_CA_BUNDLE"
    else
        log_warn "Could not find system CA bundle, creating new one"
        touch "$SANDBOX_CA_BUNDLE"
    fi

    # Append mitmproxy CA
    echo "" >> "$SANDBOX_CA_BUNDLE"
    echo "# mitmproxy CA for sandbox" >> "$SANDBOX_CA_BUNDLE"
    cat "$MITMPROXY_CA" >> "$SANDBOX_CA_BUNDLE"

    # Also copy the individual cert for tools that need it
    cp "$MITMPROXY_CA" "$SANDBOX_CA_DIR/mitmproxy-ca.crt"

    log_info "CA certificate bundle created at $SANDBOX_CA_BUNDLE"
}

start_proxy() {
    log_info "Starting mitmproxy with policy enforcement"

    # Start mitmproxy in transparent mode
    SANDBOX_SESSION_ID="$SESSION_ID" \
    SANDBOX_SESSION_DIR="$SESSION_DIR" \
    mitmdump \
        --mode transparent \
        --listen-host "$HOST_IP" \
        --listen-port "$PROXY_PORT" \
        --set block_global=false \
        --scripts "$SCRIPT_DIR/policy.py" \
        &> "$SESSION_DIR/mitmproxy.log" &

    echo $! > "$SESSION_DIR/mitmproxy.pid"

    # Wait for proxy to be ready
    sleep 2

    if ! kill -0 "$(cat "$SESSION_DIR/mitmproxy.pid")" 2>/dev/null; then
        log_error "Proxy failed to start. Check $SESSION_DIR/mitmproxy.log"
        cat "$SESSION_DIR/mitmproxy.log"
        exit 1
    fi

    log_info "Proxy running on $HOST_IP:$PROXY_PORT (PID: $(cat "$SESSION_DIR/mitmproxy.pid"))"
}

run_in_sandbox() {
    log_info "Running in sandbox: $*"

    local ca_bundle="$SESSION_DIR/ca-certs/ca-certificates.crt"
    local ca_cert="$SESSION_DIR/ca-certs/mitmproxy-ca.crt"

    # Enter network namespace, then create mount namespace and bind mount CA certs
    ip netns exec "$NAMESPACE" \
        unshare --mount bash -c '
            CA_BUNDLE="'"$ca_bundle"'"
            CA_CERT="'"$ca_cert"'"

            # Bind mount our CA bundle over system locations
            mount --bind "$CA_BUNDLE" /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
            mount --bind "$CA_BUNDLE" /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null || true
            mount --bind "$CA_BUNDLE" /etc/ssl/cert.pem 2>/dev/null || true

            # Set env vars as fallback for tools that dont use system store
            export SSL_CERT_FILE="$CA_BUNDLE"
            export NODE_EXTRA_CA_CERTS="$CA_CERT"
            export REQUESTS_CA_BUNDLE="$CA_BUNDLE"
            export CURL_CA_BUNDLE="$CA_BUNDLE"

            # Run the actual command
            exec "$@"
        ' -- "$@"
}

main() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi

    check_dependencies

    # Create a new session
    SESSION_ID=$("$SCRIPT_DIR/session.sh" create)
    SESSION_DIR=$("$SCRIPT_DIR/session.sh" path "$SESSION_ID")

    log_info "Created session: $SESSION_ID"

    # Derive unique names from session ID
    NAMESPACE="claude-$SESSION_ID"
    VETH_HOST="veth-$SESSION_ID-h"
    VETH_SANDBOX="veth-$SESSION_ID-s"

    # Use session-specific IP range (last octet from session ID)
    IP_OCTET=$(( 16#${SESSION_ID:0:2} % 200 + 10 ))  # Range 10-209 to avoid conflicts
    HOST_IP="10.200.$IP_OCTET.1"
    SANDBOX_IP="10.200.$IP_OCTET.2"

    # Set up cleanup trap
    trap cleanup EXIT

    setup_namespace
    setup_routing
    setup_dns
    install_ca_cert
    start_proxy

    echo ""
    log_info "Sandbox ready!"
    echo ""
    echo "Session ID: $SESSION_ID"
    echo ""
    echo "To run Claude Code in the sandbox:"
    echo "  sudo ip netns exec $NAMESPACE claude"
    echo ""
    echo "Blocked requests: SANDBOX_SESSION=$SESSION_ID ./logs.sh"
    echo "Press Ctrl+C to stop and cleanup"
    echo ""

    # If arguments provided, run them in sandbox
    if [[ $# -gt 0 ]]; then
        run_in_sandbox "$@"
    else
        # Keep running until interrupted
        wait
    fi
}

main "$@"
