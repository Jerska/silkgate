"""Where silkgate finds its own files, and where it keeps its host state."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ADDON = REPO / "mitmaddon" / "proxy_addon.py"
PROFILE_DIR = REPO / "profiles"
MITM_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
SILK_DIR = Path.home() / ".silkgate"
LOG_DIR = SILK_DIR / "logs"
SESSIONS_DIR = SILK_DIR / "sessions"
ARCHIVE_DIR = SILK_DIR / "archive"            # ended sessions, one dir per sid
CA_DIR = SILK_DIR / "ca"                      # public MITM cert only, never the key
DOCKER_CFG_DIR = SILK_DIR / "docker"          # our own DOCKER_CONFIG — see docker_env()
PROXY_JSON = SILK_DIR / "proxy.json"          # shared-proxy meta (pid/ports/log/sock)
PROXY_SOCK = SILK_DIR / "proxy.sock"          # control socket (line-delimited JSON)
