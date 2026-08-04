#!/usr/bin/env python3
"""`--with name@VERSION` and `--base` reach a generated Dockerfile — guarded at parse time.

Both used to arrive unquoted: the version as shell text inside `RUN VERSION="<v>" sh setup.sh`,
the base as a `FROM` line, and `docker build` runs as root on the host, with the host's network,
outside the proxy. The fix is a charset check in the argument parser itself, so a rejection
names the flag it came from. That is also why this script drives the real CLI in a subprocess
instead of calling write_build_context directly: the guard lives at the one door a user or an
agent actually walks through, and a repro that slips in behind it proves nothing about the fix.

It matters because these command lines are composed by agents for a human to approve, and
`--with node@22.11.0` is exactly the token a reviewer's eye slides over.

Each case prints observed vs expected and the script exits nonzero on any mismatch. Nothing is
built and nothing under ~/.silkgate is touched: argparse rejects the bad cases before any state
exists, and the clean control dies at `run`'s own "nothing to run" gate, before docker, msb or
the proxy come into it.

    python3 test/repro/build_injection.py
"""
import pathlib
import subprocess
import sys

CLI = pathlib.Path(__file__).resolve().parents[2] / "cli" / "silkgate"

fails = 0


def show(label, observed, expected):
    global fails
    ok = observed == expected
    fails += 0 if ok else 1
    print(f"{'  ' if ok else '!!'} {label}\n     observed={observed!r}  expected={expected!r}")


def cli(argv, needle, flag):
    """One CLI invocation -> (exit code, error names the defect, error names the flag)."""
    proc = subprocess.run([sys.executable, str(CLI)] + argv, capture_output=True, text=True)
    return proc.returncode, needle in proc.stderr, flag in proc.stderr


# Exit code 2 is argparse's usage error: the injection died at the parser, not somewhere
# down in the build. (needle seen, flag named) must both hold, so the human who composed
# the command line is told which token to look at.
show("build --with 'node@1\" ; echo PWNED-AT-BUILD-TIME ; #' — refused at parse time",
     cli(["build", "--with", 'node@1" ; echo PWNED-AT-BUILD-TIME ; #'],
         "invalid version", "--with"),
     (2, True, True))

show("build --base 'debian:bookworm-slim\\nRUN echo INJECTED-DIRECTIVE' — refused at parse time",
     cli(["build", "--base", "debian:bookworm-slim\nRUN echo INJECTED-DIRECTIVE"],
         "invalid image reference", "--base"),
     (2, True, True))

# run honours --base too (it builds the same image build would), so its door is guarded
# the same way — the flag must not be a way past the check build enforces.
show("run --base 'debian:bookworm-slim\\nRUN echo INJECTED-DIRECTIVE' — refused at parse time",
     cli(["run", "--base", "debian:bookworm-slim\nRUN echo INJECTED-DIRECTIVE", "--", "true"],
         "invalid image reference", "--base"),
     (2, True, True))

# The control: a clean version and base survive the parser and die much later, at run's
# "nothing to run" gate (exit 1, no command given) — proof the guard rejects the payload,
# not everything.
show("run --with node@22.11.0 --base debian:bookworm-slim (no command) — parses, dies later",
     cli(["run", "--with", "node@22.11.0", "--base", "debian:bookworm-slim"],
         "nothing to run", "--"),
     (1, True, True))

sys.exit(1 if fails else 0)
