set -eu
apt-get update
apt-get install -y --no-install-recommends git
rm -rf /var/lib/apt/lists/*
git --version
