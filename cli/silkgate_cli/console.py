"""How silkgate speaks on the host, and the host tools it needs."""
import shutil
import sys

from . import paths


_ERR_TAG = b"\x1e"          # RS: a stderr line, and the mark on silkgate's own voice (say)
_OUT_TAG = b"\x1f"          # US: a stdout line


def die(msg, code=1):
    say(msg)
    sys.exit(code)


def say(msg):
    # RS opens every line silkgate speaks as itself: it's the one byte relayed guest output
    # can't carry (_relay spends a leading one on routing, _plain strips the rest). So a
    # `silkgate:` line without it is a guest's imitation. Terminals draw nothing for RS.
    # Under --tty the guest writes to the screen directly, and no mark holds.
    mark = _ERR_TAG.decode()
    try:
        print(mark + f"silkgate: {msg}".replace("\n", "\n" + mark), file=sys.stderr)
    except (OSError, ValueError):
        # stderr can be a closed pipe or a vanished terminal by the time a teardown
        # speaks; losing the line is fine, losing the rest of the cleanup is not.
        pass


# Every binary the toolchain can need, with its install hint. preflight() and which() both
# read this table, so they can't name different remedies. A hint passed to which() loses
# to the table for a binary the table knows.
_TOOL_HINTS = {
    "docker": "images are built with docker, then loaded into msb",
    "msb": "curl -fsSL https://install.microsandbox.dev | sh",
    "mitmdump": "pip install mitmproxy",
    "git": "--checkout/--branch drive the host repository with it",
}


def which(binary, hint=None):
    """Resolve one binary or die naming the remedy — the last line of defence, at the
    moment of use, for a tool that vanished after preflight() let the command start."""
    path = shutil.which(binary)
    if path is None:
        die(f"{binary} not found — {_TOOL_HINTS.get(binary, hint)}")
    return path


def preflight(*binaries):
    """Die naming every absent tool at once, before a command does any work.

    which() checks one tool when it's needed, so a user missing several would learn them
    one failed run at a time. This reports them together, for one PATH lookup each.
    Whether containment holds is `silkgate verify`'s question.
    """
    missing = [b for b in dict.fromkeys(binaries) if shutil.which(b) is None]
    if not missing:
        return
    lines = "\n".join(f"  {b} — {_TOOL_HINTS[b]}" for b in missing)
    die(f"missing {len(missing)} of the tools this command needs:\n{lines}")


def _build_tools():
    """What building an image dials: docker and msb (build_image), plus mitmdump while
    the mitmproxy CA does not exist yet — write_build_context runs ensure_ca, which
    shells out to mitmdump only to generate that CA."""
    return ("docker", "msb") + (() if paths.MITM_CA.is_file() else ("mitmdump",))


def tail(path, lines=10):
    return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
