#!/usr/bin/env python3
"""Hermetic signal-path regression test (plain Python, no pytest).

Verifies the graceful-shutdown wiring on the current (v0.4) lifecycle:

  1. SIGTERM during browser startup -> the process exits 0 instead of
     being killed by the default handler (signal handlers are installed
     BEFORE browser startup), and the browser session is closed.
  2. SIGTERM while serving         -> serve_forever returns, the shutdown
     path runs (server_close + controller.close + session close), process
     exits 0.

Each case spawns a real subprocess that runs the real
``headful_auth_tunnel.server.main()`` with the Scrapling browser stack
stubbed out (no Xvfb / browser / network needed). Servers bind to
127.0.0.1 on an ephemeral port. Every wait is bounded, so this script
cannot hang.

Run:  python3 tests/test_graceful_shutdown.py
Exit: 0 on PASS, 1 on FAIL.
"""

from __future__ import annotations

import http.client
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The server runs in a subprocess (python -c) with cwd=REPO_ROOT so the
# package is importable. scrapling is always stubbed: the signal path is
# what is under test, and the stub keeps the run hermetic and fast.
DRIVER = r"""
import os
import sys
import time
import types
from pathlib import Path


class _FakePage:
    def __init__(self):
        self.url = "https://example.com"

    def set_viewport_size(self, viewport):
        pass

    def goto(self, url, wait_until=None, timeout=None):
        pass

    def is_closed(self):
        return False

    def title(self):
        return "Hermetic Fake Page"

    def bring_to_front(self):
        pass


class _FakeContext:
    def __init__(self):
        self.pages = []

    def route(self, *args):
        pass

    def route_web_socket(self, *args):
        pass

    def on(self, *args):
        pass

    def new_page(self):
        return _FakePage()


class _FakeStealthySession:
    def __init__(self, **kwargs):
        self.context = _FakeContext()

    def start(self):
        start_marker = os.environ.get("HUT_TEST_START_MARKER", "")
        if start_marker:
            Path(start_marker).write_text("starting")
        hold = float(os.environ.get("HUT_TEST_HOLD_START", "0"))
        if hold > 0:
            time.sleep(hold)

    def close(self):
        close_marker = os.environ.get("HUT_TEST_CLOSE_MARKER", "")
        if close_marker:
            Path(close_marker).write_text("closed")


_scrapling = types.ModuleType("scrapling")
_fetchers = types.ModuleType("scrapling.fetchers")
_fetchers.StealthySession = _FakeStealthySession
sys.modules["scrapling"] = _scrapling
sys.modules["scrapling.fetchers"] = _fetchers

from headful_auth_tunnel.server import main  # noqa: E402

main()
"""


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _spawn_server(tmpdir: Path, hold_start: float, port: int) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "AUTH_TOKEN": "x" * 32,
            "BASE_URL": "https://example.com",
            "ALLOWED_HOSTS": "example.com",
            "PROFILE_DIR": str(tmpdir / "profile"),
            "PORT": str(port),
            "PYTHONPATH": str(REPO_ROOT),
            "HUT_TEST_HOLD_START": str(hold_start),
            "HUT_TEST_START_MARKER": str(tmpdir / "start.marker"),
            "HUT_TEST_CLOSE_MARKER": str(tmpdir / "close.marker"),
        }
    )
    return subprocess.Popen(
        [sys.executable, "-c", DRIVER],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _read_output(proc, lines, ready_events):
    for line in proc.stdout:
        lines.append(line)
        for marker, event in ready_events:
            if marker in line and not event.is_set():
                event.set()


def _finish(proc, lines, reader, close_marker: Path):
    """SIGTERM the child, wait (bounded), and check the shutdown path ran."""
    os.kill(proc.pid, signal.SIGTERM)
    try:
        returncode = proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return False, "child did not exit within 30s of SIGTERM"
    reader.join(timeout=5)
    output = "".join(lines)
    if returncode != 0:
        return False, f"exit code {returncode} (expected 0)\n--- output ---\n{output[-1500:]}"
    if "graceful shutdown" not in output:
        return False, ("graceful-shutdown log line missing\n--- output ---\n" + output[-1500:])
    if not close_marker.exists():
        return False, "session-close marker missing (shutdown path incomplete)"
    return True, "exit 0, graceful shutdown logged, session closed"


def _scenario_sigterm_during_startup(tmpdir: Path):
    """SIGTERM while the browser worker is still starting."""
    proc = _spawn_server(tmpdir, hold_start=2.5, port=_free_port())
    lines: list[str] = []
    reader = threading.Thread(target=_read_output, args=(proc, lines, []), daemon=True)
    reader.start()
    start_marker = tmpdir / "start.marker"
    deadline = time.monotonic() + 20
    while not start_marker.exists():
        if proc.poll() is not None:
            reader.join(timeout=5)
            return False, ("child exited before browser startup:\n" + "".join(lines[-20:]))
        if time.monotonic() > deadline:
            proc.kill()
            proc.wait()
            return False, "timed out waiting for the browser-startup marker"
        time.sleep(0.05)
    return _finish(proc, lines, reader, tmpdir / "close.marker")


def _scenario_sigterm_while_serving(tmpdir: Path):
    """SIGTERM while the HTTP server is serving requests."""
    port = _free_port()
    proc = _spawn_server(tmpdir, hold_start=0, port=port)
    lines: list[str] = []
    listening = threading.Event()
    reader = threading.Thread(
        target=_read_output,
        args=(proc, lines, [("listening on", listening)]),
        daemon=True,
    )
    reader.start()
    if not listening.wait(timeout=20):
        proc.kill()
        proc.wait()
        reader.join(timeout=5)
        return False, ("server never reported listening:\n" + "".join(lines[-20:]))
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", "/health")
        response = connection.getresponse()
        response.read()
        status = response.status
        connection.close()
    except Exception as exc:
        proc.kill()
        proc.wait()
        reader.join(timeout=5)
        return False, f"health probe failed: {exc}"
    if status != 200:
        proc.kill()
        proc.wait()
        reader.join(timeout=5)
        return False, f"health probe returned {status} (expected 200)"
    return _finish(proc, lines, reader, tmpdir / "close.marker")


def main() -> int:
    scenarios = [
        ("SIGTERM during browser startup", _scenario_sigterm_during_startup),
        ("SIGTERM while serving", _scenario_sigterm_while_serving),
    ]
    failures = 0
    for name, scenario in scenarios:
        with tempfile.TemporaryDirectory(prefix="hut-shutdown-test-") as raw:
            tmpdir = Path(raw)
            (tmpdir / "profile").mkdir()
            ok, detail = scenario(tmpdir)
        if ok:
            print(f"PASS: {name} ({detail})")
        else:
            failures += 1
            print(f"FAIL: {name}\n{detail}")
    if failures:
        print(f"RESULT: {failures} scenario(s) FAILED")
        return 1
    print("RESULT: all scenarios PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
