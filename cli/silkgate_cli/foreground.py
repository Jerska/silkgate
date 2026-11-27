"""Children in the foreground: stopping them, the terminal they borrow, and the interrupts
held off around them."""
import os
import signal
import subprocess
import sys
import termios

from . import console


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


class _guarded_terminal:
    """Restore this terminal's settings afterwards, whatever the child did to them.

    A child may put the terminal in raw mode (msb does), and one that dies without restoring
    it leaves the shell mangled until `stty sane`. So: snapshot before, restore after. Does
    nothing when stdout isn't a terminal.
    """

    def __enter__(self):
        self.saved = None
        try:
            if sys.stdout.isatty():
                self.saved = termios.tcgetattr(sys.stdout)
        except (OSError, termios.error):
            pass
        return self

    def __exit__(self, *exc):
        if self.saved is not None:
            try:
                termios.tcsetattr(sys.stdout, termios.TCSADRAIN, self.saved)
            except (OSError, termios.error):
                pass
        return False


def wait_foreground(proc):
    """Wait for a child that owns the terminal. Ctrl-C reaches it directly, so the parent
    survives SIGINT to clean up. A Python handler isn't inherited across exec, so the child's
    SIGINT behavior is untouched. A signal death returns 128 plus the signal, as a shell
    would, since sys.exit mangles proc.wait()'s negative code."""
    previous = signal.signal(signal.SIGINT, lambda *a: None)
    try:
        rc = proc.wait()
        return rc if rc >= 0 else 128 - rc
    finally:
        signal.signal(signal.SIGINT, previous)


class _deferred_interrupts:
    """Hold SIGINT/SIGTERM/SIGHUP while an unwind runs, restoring them after.

    A second Ctrl-C mid-teardown would leave a session half-removed, worse than up or
    gone. So stop signals are acknowledged once on stderr and dropped: the unwind already
    does what they ask. That's safe only because everything under it is bounded: the msb
    calls in _remove_sandbox time out and run outside the terminal's process group, and
    stop_proxy escalates to SIGKILL after 5 s. The note uses os.write, because print into a
    buffer mid-flush raises."""

    _SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)

    def __enter__(self):
        self._noted = False
        self._prev = []

        def hold(signum, frame):
            if not self._noted:
                self._noted = True
                try:
                    os.write(2, console._ERR_TAG + b"silkgate: interrupt noted "
                                b"- finishing cleanup first (it is bounded)\n")
                except OSError:
                    pass
        try:
            for s in self._SIGNALS:
                self._prev.append((s, signal.signal(s, hold)))
        except ValueError:           # not the main thread: nothing can be deferred
            pass
        return self

    def __exit__(self, *exc):
        for s, previous in self._prev:
            signal.signal(s, previous)
        return False
