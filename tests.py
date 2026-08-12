#!/usr/bin/env python3
"""Run the unit suite sharded across parallel processes, in seconds not minutes.

The suite spends its wall time waiting on sockets and subprocesses, not
computing, so shards overlap well even on one CPU. Two levers carry the
speedup:

- A poll shim: servers the tests start take up to serve_forever's default
  0.5 s poll interval to notice shutdown(). Each worker shrinks that default
  to 0.01 s before it imports any test module.
- Shards: SHARDS below splits the suite into groups balanced by measured
  wall time, one worker process per group.

Usage:

    python3 tests.py               # all shards at once
    python3 tests.py --workers 2   # at most 2 shard processes at a time

The runner refuses to start when SHARDS and discovery disagree, so a new test
file must be named in SHARDS before the runner accepts it. A plain
`python3 -m unittest discover -s test` still runs the identical tests,
unsharded.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

# The shard layout, balanced by measured wall time (Linux guest, 8 vCPUs). An
# entry is a module or a module.Class; the class entry wins when both match.
# Rebalance by moving entries between shards. The three rest-* shards hold
# small tests balanced by test count instead: on macOS their cost is per-test
# process spawn overhead (~35 ms each), not the seconds measured here. The
# test_proxy_lifecycle shards need the disjoint port floors run_shard_process
# passes (see port_floor below).
SHARDS = {
    "guest-probe": ["test_verify_oracles.GuestProbeScript"],  # ~10 s, the
    # floor: one test waits out a 10 s silent proxy, irreducible by design
    "interrupts": ["test_proxy_lifecycle.InterruptTest"],  # ~9 s
    "verify-wiring": ["test_verify_oracles.VerifyWiring"],  # ~9 s
    "oracles-rest": ["test_verify_oracles"],  # the module's remainder, ~5 s
    "lifecycle": ["test_proxy_lifecycle"],  # the module's remainder, ~4 s
    "rest-validation": ["test_cli_validation"],  # 160 tests, ~0.6 s
    "rest-checks": ["test_addon", "test_verify_checks"],  # 155 tests, ~0.1 s
    "rest-misc": [  # 126 tests, ~1.3 s
        "test_cli_branch_ingest",
        "test_cli_logs",
        "test_relay",
        "test_scripts",
        "test_tier1_probe",
        "test_ui",
    ],
}

ROOT = os.path.dirname(os.path.abspath(__file__))
SUMMARY_MARK = "TESTS-SUMMARY "


def shrink_poll_interval():
    """Make the servers the tests start notice shutdown() fast.

    serve_forever polls for shutdown every 0.5 s by default, and the suite
    starts enough servers that those waits add about 19 s. Call this before
    any test module is imported.
    """
    import socketserver

    socketserver.BaseServer.serve_forever.__defaults__ = (0.01,)


def discover():
    """Collect every test exactly as `unittest discover -s test` does."""
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(ROOT, "test"))
    if loader.errors:
        for message in loader.errors:
            print(message, file=sys.stderr)
        sys.exit(2)
    tests = []

    def flatten(item):
        if isinstance(item, unittest.TestSuite):
            for child in item:
                flatten(child)
        else:
            tests.append(item)

    flatten(suite)
    return tests


def assign(tests):
    """Map every discovered test id to its shard, or abort explaining why not.

    The union of the shards must equal discovery exactly: a test no entry
    claims, or an entry no test matches, kills the run before any test runs.
    A module that raises SkipTest at import (test_addon without mitmproxy)
    reaches discovery as one synthetic ModuleSkipped case named after the
    module, so the module's entry claims that case and the gate still holds.
    """
    entry_to_shard = {}
    for shard, entries in SHARDS.items():
        for entry in entries:
            if entry in entry_to_shard:
                sys.exit(f"tests.py: entry {entry!r} appears in two shards")
            entry_to_shard[entry] = shard
    assignment = {}
    matched = set()
    problems = []
    for test in tests:
        cls = test.__class__
        keys = (f"{cls.__module__}.{cls.__qualname__}", cls.__module__)
        if cls.__module__ == "unittest.loader":
            # A skipped module's synthetic case; its method name is the module.
            keys = (test.id().rsplit(".", 1)[-1],)
        for key in keys:
            if key in entry_to_shard:
                assignment[test.id()] = entry_to_shard[key]
                matched.add(key)
                break
        else:
            problems.append(f"no shard claims {test.id()}")
    problems += [
        f"entry {entry!r} matches no discovered test"
        for entry in sorted(set(entry_to_shard) - matched)
    ]
    if problems:
        print("tests.py: SHARDS does not match discovery:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        sys.exit(2)
    return assignment


def run_shard(name):
    """Worker mode: run one shard in this process and print a summary line."""
    if name not in SHARDS:
        sys.exit(f"tests.py: unknown shard {name!r}")
    shrink_poll_interval()
    tests = discover()
    assignment = assign(tests)
    suite = unittest.TestSuite(t for t in tests if assignment[t.id()] == name)
    start = time.monotonic()
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
    summary = {
        "shard": name,
        "tests": result.testsRun,
        "failures": [test.id() for test, _ in result.failures],
        "errors": [test.id() for test, _ in result.errors],
        "unexpected": [test.id() for test in result.unexpectedSuccesses],
        "skipped": len(result.skipped),
        "seconds": round(time.monotonic() - start, 1),
    }
    print(SUMMARY_MARK + json.dumps(summary))
    sys.exit(0 if result.wasSuccessful() else 1)


def port_floor(name):
    """A disjoint free-port scan floor for each shard worker.

    test_proxy_lifecycle probes free-port ranges bind-then-release, so two
    workers scanning from one floor can both see a range free before either
    binds it for real. Each worker gets its own floor through
    TESTS_PORT_FLOOR (honored by that module's _free_pool_base), which is
    what lets InterruptTest run in a shard apart from the rest of the module.
    """
    return 23000 + 2000 * list(SHARDS).index(name)


def run_shard_process(name):
    return subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--shard", name],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=dict(os.environ, TESTS_PORT_FLOOR=str(port_floor(name))),
    )


def main():
    parser = argparse.ArgumentParser(
        description="Run the unit suite sharded across parallel processes."
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=len(SHARDS),
        help="max shard processes at once (default: %(default)s, all of them)",
    )
    parser.add_argument("--shard", help=argparse.SUPPRESS)  # worker mode
    args = parser.parse_args()
    if args.shard:
        run_shard(args.shard)
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    shrink_poll_interval()
    assignment = assign(discover())
    expected = {name: 0 for name in SHARDS}
    for shard in assignment.values():
        expected[shard] += 1
    print(
        f"tests.py: {len(assignment)} tests in {len(SHARDS)} shards, "
        f"workers={min(args.workers, len(SHARDS))}"
    )

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        procs = dict(zip(SHARDS, pool.map(run_shard_process, SHARDS)))
    wall = time.monotonic() - start

    failed = False
    rows = []
    totals = {"tests": 0, "bad": 0, "skipped": 0}
    for name, proc in procs.items():
        summary = None
        for line in proc.stdout.splitlines():
            if line.startswith(SUMMARY_MARK):
                summary = json.loads(line[len(SUMMARY_MARK):])
        if summary is None:
            failed = True
            print(f"tests.py: shard {name} died without a summary:", file=sys.stderr)
            sys.stderr.write(proc.stdout)
            sys.stderr.write(proc.stderr)
            rows.append((name, "?", "?", "?", "?", "?"))
            continue
        bad = summary["failures"] + summary["errors"] + summary["unexpected"]
        if summary["tests"] != expected[name]:
            failed = True
            print(
                f"tests.py: shard {name} ran {summary['tests']} tests, "
                f"discovery assigned it {expected[name]}",
                file=sys.stderr,
            )
        if proc.returncode != 0 or bad:
            failed = True
            sys.stderr.write(proc.stderr)
        rows.append(
            (
                name,
                summary["tests"],
                len(summary["failures"]) + len(summary["unexpected"]),
                len(summary["errors"]),
                summary["skipped"],
                summary["seconds"],
            )
        )
        totals["tests"] += summary["tests"]
        totals["bad"] += len(bad)
        totals["skipped"] += summary["skipped"]

    print()
    print(f"{'shard':<14}{'tests':>6}{'fail':>6}{'error':>7}{'skip':>6}{'seconds':>9}")
    for row in rows:
        name, tests_n, fails, errors, skipped, seconds = (str(v) for v in row)
        print(f"{name:<14}{tests_n:>6}{fails:>6}{errors:>7}{skipped:>6}{seconds:>9}")
    print(
        f"{'total':<14}{totals['tests']:>6}"
        f"{'':>13}{totals['skipped']:>6}{wall:>9.1f} wall"
    )
    print()
    if failed:
        print(f"FAILED ({totals['bad']} failing or erroring tests)")
        sys.exit(1)
    print(f"OK ({totals['tests']} tests, {totals['skipped']} skipped, {wall:.1f}s)")


if __name__ == "__main__":
    main()
