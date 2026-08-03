# Claude Code's native binary: a pinned install, so the image hash means something.
# curl fetches it; libgcc/libstdc++/ripgrep are what it needs to run (both in profile.conf).
set -eu
curl -fsSL https://claude.ai/install.sh | bash -s "$VERSION"
install -d /root/.claude
