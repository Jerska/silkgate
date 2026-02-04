#!/bin/bash
set -euo pipefail

# Build and run silkgate tests in a container

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building test container..."
docker build -t silkgate-test -f "$SCRIPT_DIR/Dockerfile" "$SANDBOX_DIR"

echo ""
echo "Running tests..."
echo "(Container needs --privileged for network namespaces)"
echo ""

docker run --rm \
    --privileged \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    silkgate-test
