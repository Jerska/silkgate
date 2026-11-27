"""Load a private copy of the cli/silkgate_cli package for one test module.

    pkg = clipkg.load("sg_relay")
    vm = pkg.vm

Each copy imports with $HOME at a scratch directory, so every path it derives from the home
directory (~/.silkgate, the mitmproxy CA, ~/.claude/settings.json) starts out there, never
in the real one. A test that needs a fresh tree calls use_home() in its setUp.

Each test module gets its own copy, under its own package name, so what one module patches
at module level, or what the package reads from the environment at import, stays private
to that module even when one process runs the whole suite.
"""
import atexit
import importlib
import importlib.util
import os
import runpy
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

CLI_DIR = Path(__file__).resolve().parent.parent / "cli"
PKG_DIR = CLI_DIR / "silkgate_cli"


def load(name, home=None):
    """Import cli/silkgate_cli afresh as the package `name`, with every module in it.

    `home` is the $HOME it imports under. Without one, it gets a scratch directory that is
    removed when the process exits.
    """
    if home is None:
        home = tempfile.mkdtemp(prefix=f"{name}-home-")
        atexit.register(shutil.rmtree, home, True)
    spec = importlib.util.spec_from_file_location(
        name, PKG_DIR / "__init__.py", submodule_search_locations=[str(PKG_DIR)])
    pkg = importlib.util.module_from_spec(spec)
    sys.modules[name] = pkg
    with mock.patch.dict(os.environ, {"HOME": str(home)}):
        spec.loader.exec_module(pkg)
        for path in sorted(PKG_DIR.glob("*.py")):
            if path.stem != "__init__":
                importlib.import_module(f"{name}.{path.stem}")
    return pkg


def use_home(case, pkg, home):
    """Repoint every path in pkg.paths that lives under the home directory at `home`, for
    the duration of the test `case`. paths.py itself derives the values, so none is missed."""
    with mock.patch.dict(os.environ, {"HOME": str(home)}):
        values = runpy.run_path(str(PKG_DIR / "paths.py"))
    for name, value in values.items():
        if name.isupper() and Path(home) in value.parents:
            case.enterContext(mock.patch.object(pkg.paths, name, value))
