# Claude Code's native binary: a pinned install, so the image hash means something.
# curl fetches it; libgcc/libstdc++/ripgrep are what it needs to run (both in profile.conf).
set -eu
curl -fsSL https://claude.ai/install.sh | bash -s "$VERSION"
install -d /root/.claude

# A sandbox-flavoured entry point. The flags it adds are the ones that are always right in
# here and easy to forget, so a caller writes `silkgate-claude -p "…"` and the approval
# prompt a human reads stays short. It adds nothing the caller already passed, and prints
# what it did add, so the effective flags are visible in the run's own output.
cat > /usr/local/bin/silkgate-claude <<'WRAPPER'
#!/bin/sh
# Claude Code, with the flags that are always right inside a silkgate sandbox.
add=""
case " $* " in
    *" --permission-mode "*) ;;
    *) add="$add --permission-mode bypassPermissions" ;;
esac
case " $* " in
    *" --append-system-prompt "*|*" --append-system-prompt-file "*|*" --system-prompt "*) ;;
    *) if [ -f /silkgate/CONTEXT.md ]; then
           add="$add --append-system-prompt-file /silkgate/CONTEXT.md"
       fi ;;
esac
if [ -n "$add" ]; then
    printf 'silkgate-claude: adding%s\n' "$add" >&2
fi
# IS_SANDBOX is what lets Claude Code skip its refusal to bypass permissions as root. It
# lives here rather than in the image's environment, so a plain `claude` in an image someone
# ran outside silkgate makes no claim about being sandboxed.
IS_SANDBOX=1 exec claude $add "$@"
WRAPPER
chmod +x /usr/local/bin/silkgate-claude
