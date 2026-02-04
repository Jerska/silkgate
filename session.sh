#!/bin/bash
# Session management for silkgate

# Resolve real user when running under sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_USER="$SUDO_USER"
    REAL_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    REAL_USER_GID=$(id -g "$SUDO_USER")
else
    REAL_USER=$(id -un)
    REAL_USER_HOME="$HOME"
    REAL_USER_GID=$(id -g)
fi
SILKGATE_DIR="$REAL_USER_HOME/.silkgate"
SESSIONS_DIR="$SILKGATE_DIR/sessions"

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  create              Create a new session, outputs session ID"
    echo "  list                List all sessions with status"
    echo "  delete <id>         Delete a session"
    echo "  path <id>           Output session directory path"
    echo "  touch <id>          Update last_activity timestamp"
    exit 1
}

generate_id() {
    head -c 4 /dev/urandom | xxd -p
}

cmd_create() {
    mkdir -p "$SESSIONS_DIR"

    local id
    id=$(generate_id)
    local session_dir="$SESSIONS_DIR/$id"

    mkdir -p "$session_dir/ca-certs"

    local now
    now=$(date -Iseconds)

    cat > "$session_dir/meta.json" <<EOF
{
  "id": "$id",
  "created_at": "$now"
}
EOF

    # Ensure directories are owned by the original user, not root
    chown -R "$REAL_USER:$REAL_USER_GID" "$SILKGATE_DIR"

    echo "$id"
}

cmd_list() {
    if [[ ! -d "$SESSIONS_DIR" ]]; then
        echo "No sessions"
        exit 0
    fi

    printf "%-10s %-22s %-22s %s\n" "ID" "CREATED" "LAST ACTIVITY" "STATUS"

    for session_dir in "$SESSIONS_DIR"/*/; do
        [[ -d "$session_dir" ]] || continue

        local id
        id=$(basename "$session_dir")
        local meta="$session_dir/meta.json"

        if [[ -f "$meta" ]]; then
            local created last_activity status

            created=$(jq -r '.created_at' "$meta" | cut -d'+' -f1 | tr 'T' ' ')

            # Get last activity from file mtime (touched on each request)
            if [[ -f "$session_dir/last_activity" ]]; then
                last_activity=$(stat -c '%y' "$session_dir/last_activity" 2>/dev/null | cut -d'.' -f1)
            else
                last_activity="$created"
            fi

            # Check if sandbox is running (pid file exists and process alive)
            if [[ -f "$session_dir/mitmproxy.pid" ]] && kill -0 "$(cat "$session_dir/mitmproxy.pid")" 2>/dev/null; then
                status="running"
            else
                status="stopped"
            fi

            printf "%-10s %-22s %-22s %s\n" "$id" "$created" "$last_activity" "$status"
        fi
    done
}

cmd_delete() {
    local id="$1"
    [[ -z "$id" ]] && usage

    local session_dir="$SESSIONS_DIR/$id"

    if [[ ! -d "$session_dir" ]]; then
        echo "Session not found: $id" >&2
        exit 1
    fi

    # Kill mitmproxy if running
    if [[ -f "$session_dir/mitmproxy.pid" ]]; then
        kill "$(cat "$session_dir/mitmproxy.pid")" 2>/dev/null || true
    fi

    rm -rf "$session_dir"
    echo "Deleted session: $id"
}

cmd_path() {
    local id="$1"
    [[ -z "$id" ]] && usage

    local session_dir="$SESSIONS_DIR/$id"

    if [[ ! -d "$session_dir" ]]; then
        echo "Session not found: $id" >&2
        exit 1
    fi

    echo "$session_dir"
}

cmd_touch() {
    local id="$1"
    [[ -z "$id" ]] && usage

    local session_dir="$SESSIONS_DIR/$id"

    if [[ ! -d "$session_dir" ]]; then
        echo "Session not found: $id" >&2
        exit 1
    fi

    touch "$session_dir/last_activity"
}

# Main
case "${1:-}" in
    create) cmd_create ;;
    list) cmd_list ;;
    delete) cmd_delete "$2" ;;
    path) cmd_path "$2" ;;
    touch) cmd_touch "$2" ;;
    *) usage ;;
esac
