#!/bin/bash
# Read silkgate request logs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve real user's home when running under sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
fi
SESSIONS_DIR="$USER_HOME/.silkgate/sessions"

# Get session ID from env or argument
SESSION_ID="${SILKGATE_SESSION:-}"

usage() {
    echo "Usage: SILKGATE_SESSION=<id> $0 [-f]"
    echo "   or: $0 <session_id> [-f]"
    echo ""
    echo "Options:"
    echo "  -f    Follow log output"
    echo ""
    echo "Sessions:"
    "$SCRIPT_DIR/session.sh" list
    exit 1
}

# Parse arguments
FOLLOW=false
for arg in "$@"; do
    case "$arg" in
        -f) FOLLOW=true ;;
        -*) usage ;;
        *) SESSION_ID="$arg" ;;
    esac
done

if [[ -z "$SESSION_ID" ]]; then
    usage
fi

SESSION_DIR="$SESSIONS_DIR/$SESSION_ID"
LOG_FILE="$SESSION_DIR/requests.log"

if [[ ! -d "$SESSION_DIR" ]]; then
    echo "Session not found: $SESSION_ID" >&2
    exit 1
fi

if $FOLLOW; then
    touch "$LOG_FILE"
    exec tail -f "$LOG_FILE"
fi

if [[ -s "$LOG_FILE" ]]; then
    cat "$LOG_FILE"
else
    echo "No requests logged"
fi
