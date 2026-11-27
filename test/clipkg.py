"""Load a private copy of the cli/silkgate_cli package for one test module.

    sg = clipkg.load("silkgate_cli_relay").core

Several test modules repoint the CLI's state paths at a scratch tree when they import it,
for example `sg.SESSIONS_DIR = ...`. Each module loads its own copy, under its own package
name, so those assignments stay private to it even when one process runs the whole suite.
"""
import importlib
import importlib.util
import sys
from pathlib import Path

CLI_DIR = Path(__file__).resolve().parent.parent / "cli"
PKG_DIR = CLI_DIR / "silkgate_cli"


def load(name):
    """Import cli/silkgate_cli afresh as the package `name`, with every module in it."""
    spec = importlib.util.spec_from_file_location(
        name, PKG_DIR / "__init__.py", submodule_search_locations=[str(PKG_DIR)])
    pkg = importlib.util.module_from_spec(spec)
    sys.modules[name] = pkg
    spec.loader.exec_module(pkg)
    for path in sorted(PKG_DIR.glob("*.py")):
        if path.stem != "__init__":
            importlib.import_module(f"{name}.{path.stem}")
    return pkg
