"""The silkgate CLI. Its rule_engine is shared with the proxy addon, in mitmaddon/."""
import sys

from . import paths

sys.path.insert(0, str(paths.REPO / "mitmaddon"))
