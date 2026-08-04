#!/usr/bin/env python3
"""`--with name@VERSION` and `--base` reach a generated Dockerfile unquoted.

Profile.__init__ validates the profile *name* against a charset and never validates the
version; write_build_context interpolates both the version and the base image into shell and
Dockerfile text. `docker build` then runs as root on the host, with the host's network and
outside the proxy — so this is the one place where an argument on a silkgate command line
becomes host code execution.

It matters because these command lines are composed by agents for a human to approve, and
`--with node@22.11.0` is exactly the token a reviewer's eye slides over.

Nothing is executed here: the script only prints the Dockerfile that would be built.

    python3 test/repro/build_injection.py
"""
import pathlib
import shutil
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]

# cli/silkgate has no .py suffix; copy it somewhere importable and repoint its data dirs.
tmp = pathlib.Path(tempfile.mkdtemp())
shutil.copyfile(REPO / "cli" / "silkgate", tmp / "sgmod.py")
sys.path.insert(0, str(tmp))
sys.path.insert(0, str(REPO / "mitmaddon"))
import sgmod as sg                                            # noqa: E402

sg.PROFILE_DIR = REPO / "profiles"


def render(label, profile, base):
    with tempfile.TemporaryDirectory() as out:
        d = pathlib.Path(out)
        sg.write_build_context(d, [profile], base)
        print(f"{label}")
        for line in (d / "Dockerfile").read_text().splitlines():
            if line.startswith(("FROM", "RUN VERSION", "RUN echo")):
                print(f"     {line}")


render("1. version carrying shell metacharacters — the echo runs during docker build:",
       sg.Profile("node", '1" ; echo PWNED-AT-BUILD-TIME ; #'), "debian:bookworm-slim")

render("2. base carrying a newline — arbitrary Dockerfile directives:",
       sg.Profile("git"), "debian:bookworm-slim\nRUN echo INJECTED-DIRECTIVE")

print("\nExpected instead: reject a version that is not [A-Za-z0-9][A-Za-z0-9._+-]* and a base")
print("that is not a valid image reference, both at parse time, before anything is written.")
