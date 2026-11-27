# Linux verification environment — for hosts whose glibc is older than what the
# msb release binaries require (built on Ubuntu 24.04, glibc 2.39; check with
# `ldd --version`). Runs the proxy and msb inside a noble container with the
# host's /dev/kvm passed through: the microVM boundary is unchanged (host KVM),
# the container only supplies the newer userland. Hosts with glibc >= 2.39 can
# skip this and run silkgate natively.
#
#   docker build -t silkgate-verify test/linux/
#   docker run --rm -it --device /dev/kvm -v "$PWD:/silkgate" silkgate-verify \
#     /silkgate/cli/silkgate verify --full
#
# Add --network=host to both commands if DNS fails inside containers (hosts whose
# resolv.conf points at a localhost stub resolver).
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl pipx python3 tar \
    && rm -rf /var/lib/apt/lists/*

# mitmproxy is the version the addon is verified against (test/test_addon.py; the addon
# reads mitmproxy internals, so a floating version here would un-verify the container).
RUN pipx install mitmproxy==12.3.1

# msb is the version the docs cite as verified on Linux (README, "Install microsandbox").
# The installed binary is checked, not trusted: if the installer fetches another version,
# the build fails here.
RUN curl -fsSL https://install.microsandbox.dev | sh -s -- --version 0.6.8 \
    && /root/.microsandbox/bin/msb --version | grep -F 0.6.8

ENV PATH=/root/.local/bin:/root/.microsandbox/bin:$PATH
WORKDIR /silkgate
