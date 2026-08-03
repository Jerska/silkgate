# The distro's python3 — no version parameter, because pinning an exact CPython means
# building it or pulling a third-party distribution. Say so rather than pretend.
set -eu
apt-get update
apt-get install -y --no-install-recommends python3 python3-pip
rm -rf /var/lib/apt/lists/*
python3 -VV
