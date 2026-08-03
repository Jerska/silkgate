# A pinned CPython, the same idea as the node profile's pinned tarball: uv fetches a prebuilt
# standalone interpreter, so there's no compiler in the image and no distro version to inherit.
# uv itself is pinned too — the image hash covers this file, so it must not say "latest".
set -eu
UV_VERSION=0.5.14
curl -LsSf "https://astral.sh/uv/$UV_VERSION/install.sh" | sh
export PATH="/root/.local/bin:$PATH"
uv python install "$VERSION"
# Expose it as python3/python, so anything expecting a system python finds this one.
ln -sf "$(uv python find "$VERSION")" /usr/local/bin/python3
ln -sf /usr/local/bin/python3 /usr/local/bin/python
python3 -VV
uv --version
