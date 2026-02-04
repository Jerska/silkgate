#!/bin/bash
set -euo pipefail

# Test runner for network sandbox

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

log_pass() { echo -e "${GREEN}✓ PASS${NC} $1"; ((PASSED++)) || true; }
log_fail() { echo -e "${RED}✗ FAIL${NC} $1"; ((FAILED++)) || true; }
log_skip() { echo -e "${YELLOW}○ SKIP${NC} $1"; ((SKIPPED++)) || true; }
log_info() { echo -e "  $1"; }

# Start sandbox and capture session ID
start_sandbox() {
    echo "Starting sandbox..."

    # Start sandbox in background, capture output
    "$SANDBOX_DIR/sandbox.sh" &
    SANDBOX_PID=$!

    # Wait for sandbox to be ready
    sleep 5

    # Get session ID from session list
    SESSION_ID=$("$SANDBOX_DIR/session.sh" list | tail -1 | awk '{print $1}')
    SESSION_DIR=$("$SANDBOX_DIR/session.sh" path "$SESSION_ID")

    # Get namespace name
    NAMESPACE="sandbox-$SESSION_ID"

    # Get CA cert path
    CA_CERT="$SESSION_DIR/ca-certs/ca-certificates.crt"

    echo "Sandbox ready: session=$SESSION_ID namespace=$NAMESPACE"
}

stop_sandbox() {
    echo "Stopping sandbox..."
    kill $SANDBOX_PID 2>/dev/null || true
    wait $SANDBOX_PID 2>/dev/null || true
}

# Run a command in the sandbox
sandbox_exec() {
    ip netns exec "$NAMESPACE" \
        env SSL_CERT_FILE="$CA_CERT" \
        CURL_CA_BUNDLE="$CA_CERT" \
        "$@"
}

# Test HTTP request, expect success (2xx)
test_http_allow() {
    local description="$1"
    local method="$2"
    local url="$3"

    local status
    if ! status=$(sandbox_exec curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null); then
        status="000"
    fi

    if [[ "$status" =~ ^2 ]] || [[ "$status" =~ ^3 ]]; then
        log_pass "$description"
    else
        log_fail "$description (got HTTP $status)"
    fi
}

# Test HTTP request, expect block (403)
test_http_block() {
    local description="$1"
    local method="$2"
    local url="$3"

    local status
    status=$(sandbox_exec curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null) || status="000"

    if [[ "$status" == "403" ]]; then
        log_pass "$description"
    else
        log_fail "$description (expected 403, got HTTP $status)"
    fi
}

# Test TCP connection, expect success
test_tcp_allow() {
    local description="$1"
    local host="$2"
    local port="$3"

    if sandbox_exec timeout 5 bash -c "echo '' | nc -w 2 $host $port" &>/dev/null; then
        log_pass "$description"
    else
        log_fail "$description (connection failed)"
    fi
}

# Test TCP connection, expect block
test_tcp_block() {
    local description="$1"
    local host="$2"
    local port="$3"

    if sandbox_exec timeout 5 bash -c "echo '' | nc -w 2 $host $port" &>/dev/null; then
        log_fail "$description (connection succeeded, should be blocked)"
    else
        log_pass "$description"
    fi
}

# Test DNS resolution works
test_dns() {
    local description="$1"
    local domain="$2"

    if sandbox_exec dig +short "$domain" | grep -q .; then
        log_pass "$description"
    else
        log_fail "$description (DNS resolution failed)"
    fi
}

# Source test cases
source "$SCRIPT_DIR/test-cases.sh"

main() {
    echo "========================================"
    echo "Network Sandbox Test Suite"
    echo "========================================"

    trap stop_sandbox EXIT

    start_sandbox
    run_tests
}

main "$@"
