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

RUN pipx install mitmproxy
RUN curl -fsSL https://install.microsandbox.dev | sh

ENV PATH=/root/.local/bin:/root/.microsandbox/bin:$PATH
WORKDIR /silkgate
