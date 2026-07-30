# Claude Code in a microsandbox guest, behind the TLS-terminating egress proxy.
# Build for Apple Silicon, then load into msb (msb has no Docker-store integration).
# From the repo root:
#   cp ~/.mitmproxy/mitmproxy-ca-cert.pem image/egress-ca.pem
#   docker build --platform linux/arm64 -t claude-sandbox:poc image/
#   docker save claude-sandbox:poc | msb load
FROM node:20-bookworm-slim

# CA tooling + git for the agent + the probes verify_guest.sh uses.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git iproute2 dnsutils iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Trust the egress proxy's MITM CA so the agent's TLS to api.anthropic.com verifies.
COPY egress-ca.pem /usr/local/share/ca-certificates/egress.crt
RUN update-ca-certificates

RUN npm install -g @anthropic-ai/claude-code

# Dummy key ONLY — the proxy injects the real x-api-key for api.anthropic.com.
# Non-essential traffic disabled (the allowlist would block it anyway).
ENV HOME=/root \
    ANTHROPIC_API_KEY=sk-ant-DUMMY-replaced-by-egress-proxy \
    NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/egress.crt \
    REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/egress.crt \
    GIT_SSL_CAINFO=/usr/local/share/ca-certificates/egress.crt \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_TELEMETRY=1 \
    DISABLE_ERROR_REPORTING=1 \
    DISABLE_UPDATES=1
RUN mkdir -p /root/.claude
WORKDIR /workspace
CMD ["bash"]
