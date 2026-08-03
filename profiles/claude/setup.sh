# Claude Code's native binary: a pinned install, so the image hash means something.
# It needs curl to fetch, and libgcc/libstdc++/ripgrep at run time.
set -eu
apt-get update
apt-get install -y --no-install-recommends curl libgcc-s1 libstdc++6 ripgrep
rm -rf /var/lib/apt/lists/*
curl -fsSL https://claude.ai/install.sh | bash -s "$VERSION"
install -d /root/.claude
