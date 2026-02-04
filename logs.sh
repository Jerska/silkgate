#!/bin/bash
# Read sandbox blocked logs in chronological order

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSIONS_DIR="/tmp/claude-sandbox-sessions"

# Get session ID from env or argument
SESSION_ID="${SANDBOX_SESSION:-}"

usage() {
    echo "Usage: SANDBOX_SESSION=<id> $0 [-f]"
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
LOG_DIR="$SESSION_DIR/logs"

if [[ ! -d "$SESSION_DIR" ]]; then
    echo "Session not found: $SESSION_ID" >&2
    exit 1
fi

LOG1="$LOG_DIR/blocked-1.log"
LOG2="$LOG_DIR/blocked-2.log"

# Ensure both files exist for tail -f to watch
touch "$LOG1" "$LOG2"

# Ensure LOG1 is older than LOG2 (swap if needed)
ts1="" ts2=""
[[ -s "$LOG1" ]] && ts1=$(head -1 "$LOG1" | cut -d' ' -f1)
[[ -s "$LOG2" ]] && ts2=$(head -1 "$LOG2" | cut -d' ' -f1)

if [[ -n "$ts1" && -n "$ts2" && "$ts1" > "$ts2" ]]; then
    tmp="$LOG1"; LOG1="$LOG2"; LOG2="$tmp"
fi

if $FOLLOW; then
    exec tail -f "$LOG1" "$LOG2"
fi

if [[ -z "$ts1" && -z "$ts2" ]]; then
    echo "No blocked requests logged"
else
    cat "$LOG1" "$LOG2" 2>/dev/null
fi
