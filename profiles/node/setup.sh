# One pinned tarball, so two projects can want two Node versions and each gets its own
# cached image over the same base.
set -eu
case "$(uname -m)" in
    aarch64|arm64) arch=arm64 ;;
    x86_64|amd64)  arch=x64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac
curl -fsSL "https://nodejs.org/dist/v$VERSION/node-v$VERSION-linux-$arch.tar.xz" \
    | tar -xJ -C /usr/local --strip-components=1
node --version
