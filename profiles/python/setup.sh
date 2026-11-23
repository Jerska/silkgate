# A pinned CPython, the same idea as the node profile's pinned tarball: uv fetches a prebuilt
# standalone interpreter, so there's no compiler in the image and no distro version to inherit.
# uv itself is pinned too — the image hash covers this file, so it must not say "latest".
set -eu
UV_VERSION=0.13.9
curl -LsSf "https://astral.sh/uv/$UV_VERSION/install.sh" | sh
export PATH="/root/.local/bin:$PATH"
uv python install "$VERSION"
# Expose it as python3/python, so anything expecting a system python finds this one.
# /opt/python is a stable name for its install root: the env file puts /opt/python/bin on
# PATH, which is where pip installs the commands a package ships.
ln -sfn "$(dirname "$(dirname "$(uv python find "$VERSION")")")" /opt/python
ln -sf "$(uv python find "$VERSION")" /usr/local/bin/python3
ln -sf /usr/local/bin/python3 /usr/local/bin/python
# uv marks the interpreter externally managed (PEP 668), so a bare `pip install` refuses. The
# marker guards a distro package manager, and none manages this python: it is the only python3
# in a disposable guest, so pip installs into it directly.
rm "$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')/EXTERNALLY-MANAGED"
test "$(python3 -c 'import platform; print(platform.python_version())')" = "$VERSION"
case "$(uv --version)" in "uv $UV_VERSION"|"uv $UV_VERSION "*) ;; *) uv --version >&2; exit 1 ;; esac
python3 -m pip --version
