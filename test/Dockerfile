FROM ubuntu:24.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    jq \
    netcat-openbsd \
    dnsutils \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Install mitmproxy
RUN python3 -m venv /opt/mitmproxy && \
    /opt/mitmproxy/bin/pip install mitmproxy
ENV PATH="/opt/mitmproxy/bin:$PATH"

# Copy sandbox files
WORKDIR /sandbox
COPY sandbox.sh policy.py policy.txt session.sh logs.sh ./

# Copy test files
COPY test/run-tests.sh test/test-cases.sh ./test/

# Need privileged mode for network namespaces
CMD ["/sandbox/test/run-tests.sh"]
