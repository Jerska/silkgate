#!/usr/bin/env python3
"""Run every suite sharded across parallel processes, in seconds not minutes.

The python suite spends its wall time waiting on sockets and subprocesses,
not computing, so shards overlap well even on one CPU. Two levers carry the
speedup:

- A poll shim: servers the tests start take up to serve_forever's default
  0.5 s poll interval to notice shutdown(). Each worker shrinks that default
  to 0.01 s before it imports any test module.
- Shards: SHARDS below splits the suite into groups balanced by measured
  wall time, one worker process per group.

The node ui suite (`ui/*.test.js`, the `node:test` runner) runs as one more
job beside the shard processes, in the same worker pool. Its row in the
summary is `ui-node`. When node is not on PATH the row records one skip,
the way test_addon skips without mitmproxy.

Usage:

    python3 tests.py               # all shards at once
    python3 tests.py --workers 2   # at most 2 jobs at a time

The runner refuses to start when SHARDS and discovery disagree, so a new test
file must be named in SHARDS before the runner accepts it. SHARDS is
python-only. A plain `python3 -m unittest discover -s test` still runs the
identical python tests, unsharded, without the ui suite.
"""

import argparse
import glob
import json
import os
import shutil
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
    "rest-validation": [  # 215 tests, ~0.6 s
        "test_cli_settings",
        "test_cli_validation",
    ],
    "rest-checks": [  # 194 tests, ~1.3 s
        "test_addon",
        "test_capture_decoder",
        "test_capture_tap",
        "test_verify_checks",
    ],
    "rest-misc": [  # 206 tests, ~1.3 s
        "test_cli_branch_ingest",
        "test_cli_journal",
        "test_cli_logs",
        "test_relay",
        "test_scripts",
        "test_tier1_probe",
        "test_ui",
    ],
}

ROOT = os.path.dirname(os.path.abspath(__file__))
SUMMARY_MARK = "TESTS-SUMMARY "
NODE_SUITE = "ui-node"


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


def node_test_files():
    """The ui suite's files, or abort when the glob matches nothing.

    node treats a directory argument as one failing test, so the runner names
    each file. An empty glob means the ui suite silently vanished, which
    kills the run before any test starts, like the SHARDS gate.
    """
    files = sorted(glob.glob(os.path.join(ROOT, "ui", "*.test.js")))
    if not files:
        print("tests.py: ui/*.test.js matches no files", file=sys.stderr)
        sys.exit(2)
    return files


def run_node_process(files):
    """Run the node ui suite as one job. Returns (proc, wall seconds).

    The reporter is pinned to tap because the default reporter depends on a
    TTY. parse_tap_counts reads the summary out of the tap trailer.
    """
    start = time.monotonic()
    proc = subprocess.run(
        ["node", "--test", "--test-reporter=tap", *files],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return proc, round(time.monotonic() - start, 1)


def parse_tap_counts(stdout):
    """The trailing `# <name> <number>` count lines of a tap run, as a dict."""
    counts = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "#":
            try:
                counts[parts[1]] = int(float(parts[2]))
            except ValueError:
                pass
    return counts


def main():
    parser = argparse.ArgumentParser(
        description="Run every suite sharded across parallel processes."
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=len(SHARDS) + 1,
        help="max jobs at once (default: %(default)s, all of them)",
    )
    parser.add_argument("--shard", help=argparse.SUPPRESS)  # worker mode
    args = parser.parse_args()
    if args.shard:
        run_shard(args.shard)
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    shrink_poll_interval()
    assignment = assign(discover())
    node_files = node_test_files()
    node = shutil.which("node")
    expected = {name: 0 for name in SHARDS}
    for shard in assignment.values():
        expected[shard] += 1
    jobs = len(SHARDS) + (1 if node else 0)
    print(
        f"tests.py: {len(assignment)} tests in {len(SHARDS)} shards "
        f"plus the node ui suite, workers={min(args.workers, jobs)}"
    )

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        node_future = pool.submit(run_node_process, node_files) if node else None
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

    if node_future is None:
        # Mirror the missing-mitmproxy path: one skip, a note, an honest OK.
        print("tests.py: node is not on PATH, the ui suite records as one skip")
        rows.append((NODE_SUITE, 1, 0, 0, 1, 0.0))
        totals["tests"] += 1
        totals["skipped"] += 1
    else:
        proc, seconds = node_future.result()
        counts = parse_tap_counts(proc.stdout)
        if not {"tests", "fail", "cancelled"} <= counts.keys():
            failed = True
            print("tests.py: the node suite died without tap counts:", file=sys.stderr)
            sys.stderr.write(proc.stdout)
            sys.stderr.write(proc.stderr)
            rows.append((NODE_SUITE, "?", "?", "?", "?", "?"))
        else:
            bad = counts["fail"] + counts["cancelled"]
            skipped = counts.get("skipped", 0) + counts.get("todo", 0)
            if proc.returncode != 0 or bad:
                failed = True
                sys.stderr.write(proc.stdout)
                sys.stderr.write(proc.stderr)
            rows.append(
                (
                    NODE_SUITE,
                    counts["tests"],
                    counts["fail"],
                    counts["cancelled"],
                    skipped,
                    seconds,
                )
            )
            totals["tests"] += counts["tests"]
            totals["bad"] += bad
            totals["skipped"] += skipped

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
