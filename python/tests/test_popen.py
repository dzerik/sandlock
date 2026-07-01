# SPDX-License-Identifier: Apache-2.0
"""Tests for the streaming-stdio Sandbox.popen / Process API (RFC #67).

These drive real confined processes and read/write their pipe streams while
they run — the Python counterpart of crates/sandlock-ffi/tests/popen.rs.
"""

from __future__ import annotations

import sys
import threading

import pytest

from sandlock import Sandbox, StdioMode, Process


_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev", sys.prefix,
]))


def _policy(**overrides):
    defaults = {"fs_readable": _READABLE}
    defaults.update(overrides)
    return Sandbox(**defaults)


def _sandbox_works() -> bool:
    """Probe whether a sandbox can actually start on this host (Landlock/ABI)."""
    try:
        return bool(_policy().run(["true"]).success)
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _sandbox_works(), reason="sandbox cannot start on this host (Landlock/ABI)"
)


def test_popen_streams_stdout_and_collects_exit():
    proc = _policy().popen(["echo", "ffi-hi"], stdout=StdioMode.PIPED)
    assert proc.stdin is None, "stdin inherited → no stream"
    assert proc.stdout is not None, "stdout piped → stream present"
    assert proc.stderr is None, "stderr inherited → no stream"

    assert proc.stdout.read() == b"ffi-hi\n"
    result = proc.wait()
    assert result.success
    assert result.exit_code == 0


def test_popen_stdin_stdout_roundtrip():
    proc = _policy().popen(["cat"], stdin=StdioMode.PIPED, stdout=StdioMode.PIPED)
    assert proc.stdin is not None and proc.stdout is not None

    proc.stdin.write(b"ping\n")
    proc.stdin.close()  # EOF → cat exits
    assert proc.stdout.read() == b"ping\n"

    result = proc.wait()
    assert result.success
    assert result.exit_code == 0


def test_wait_closes_unclosed_piped_stdin_so_reader_exits():
    # cat reads stdin to EOF. If the caller pipes stdin but never closes it,
    # wait() must close it to deliver EOF — otherwise cat blocks forever and
    # wait() (no timeout) hangs. Run wait() under a watchdog so a regression
    # surfaces as a failure, not a hung CI job.
    proc = _policy().popen(["cat"], stdin=StdioMode.PIPED, stdout=StdioMode.PIPED)
    proc.stdin.write(b"data\n")
    # Deliberately DO NOT close stdin here — wait() is responsible for the EOF.

    box = {}

    def _run():
        box["result"] = proc.wait()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=10)
    if t.is_alive():
        proc.kill()  # unblock the child so the worker thread can unwind
        t.join(timeout=5)
        pytest.fail("wait() did not close unclosed piped stdin → cat blocked forever")

    assert box["result"].success
    assert box["result"].exit_code == 0


def test_popen_stderr_piped():
    proc = _policy().popen(
        ["sh", "-c", "echo err 1>&2"],
        stdout=StdioMode.INHERIT,
        stderr=StdioMode.PIPED,
    )
    assert proc.stdout is None, "stdout inherited → no stream"
    assert proc.stderr is not None, "stderr piped → stream present"

    assert proc.stderr.read() == b"err\n"
    assert proc.wait().success


def test_popen_null_stdout_yields_no_stream():
    proc = _policy().popen(["echo", "discarded"], stdout=StdioMode.NULL)
    assert proc.stdout is None, "Null stdout → no caller stream"
    assert proc.wait().exit_code == 0


def test_popen_kill_then_wait_is_not_success():
    proc = _policy().popen(["sleep", "100"])
    proc.kill()
    result = proc.wait()
    assert not result.success, "a killed process is not success"


def test_popen_kill_is_idempotent():
    proc = _policy().popen(["sleep", "100"])
    proc.kill()
    proc.kill()  # second kill on a dying/exited process must not raise
    proc.wait()


def test_process_context_manager_reaps_child_and_closes_streams():
    sandbox = _policy()
    with sandbox.popen(
        ["sleep", "100"], stdout=StdioMode.PIPED
    ) as proc:
        assert proc.pid is not None
        assert sandbox.is_running
        stdout = proc.stdout
    # Leaving the block must terminate + reap the child and close every stream.
    assert not sandbox.is_running, "context exit must reap the child"
    assert proc.pid is None
    assert stdout.closed, "context exit must close piped streams"
    # The sandbox is reusable after the process is reaped.
    assert _policy_reusable(sandbox)


def _policy_reusable(sandbox) -> bool:
    result = sandbox.run(["true"])
    return bool(result.success)


def test_wait_is_idempotent_and_cached():
    proc = _policy().popen(["echo", "hi"], stdout=StdioMode.PIPED)
    assert proc.stdout.read() == b"hi\n"
    first = proc.wait()
    second = proc.wait()  # handle already freed → cached result, no double-free
    assert first is second
    assert first.exit_code == 0


def test_popen_unknown_stdio_mode_raises():
    # An out-of-range discriminant is rejected in Python (StdioMode(99)) before
    # crossing the FFI — a clear ValueError, no opaque null handle.
    with pytest.raises(ValueError):
        _policy().popen(["echo", "x"], stdout=99)  # type: ignore[arg-type]


def test_popen_accepts_int_discriminant_for_stdio_mode():
    # The int discriminant is accepted (normalized to StdioMode) for callers that
    # pass a raw 0/1/2 rather than the enum.
    proc = _policy().popen(["echo", "raw"], stdout=1)  # 1 == StdioMode.PIPED
    assert proc.stdout is not None
    assert proc.stdout.read() == b"raw\n"
    assert proc.wait().success


def test_popen_rejects_second_process_on_same_sandbox():
    sandbox = _policy()
    proc = sandbox.popen(["sleep", "100"])
    try:
        with pytest.raises(RuntimeError):
            sandbox.popen(["echo", "x"])
    finally:
        proc.kill()
        proc.wait()


def test_wait_timeout_kills_and_returns_nonsuccess():
    # A child that never exits within the timeout: wait(timeout) must RETURN (not
    # hang), killing the child and yielding a non-success result — parity with
    # Sandbox.run(timeout=...). Run under a watchdog so a regression (ignored
    # timeout → hang) surfaces as a failure, not a stuck job.
    proc = _policy().popen(["sleep", "100"])

    box = {}

    def _run():
        box["result"] = proc.wait(timeout=0.5)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=10)
    if t.is_alive():
        proc.kill()
        t.join(timeout=5)
        pytest.fail("wait(timeout) did not return — timeout was ignored")

    assert not box["result"].success, "a timed-out (killed) process is not success"


def test_wait_without_timeout_completes_for_quick_child():
    # timeout=None keeps the indefinite-wait behavior for a child that exits.
    proc = _policy().popen(["echo", "quick"], stdout=StdioMode.PIPED)
    assert proc.stdout.read() == b"quick\n"
    assert proc.wait().success


def test_popen_stdout_and_stderr_both_piped():
    # Both streams piped at once: each is handed back and drained independently.
    proc = _policy().popen(
        ["sh", "-c", "echo out; echo err 1>&2"],
        stdout=StdioMode.PIPED,
        stderr=StdioMode.PIPED,
    )
    assert proc.stdin is None
    assert proc.stdout is not None and proc.stderr is not None
    assert proc.stdout.read() == b"out\n"
    assert proc.stderr.read() == b"err\n"
    assert proc.wait().success


def test_abandoned_process_is_reaped_by_del():
    # A Process dropped without wait()/context must not leak: __del__ reaps the
    # child (freeing the handle) and warns. Assert both the ResourceWarning and
    # that the sandbox is released for reuse.
    import gc

    sandbox = _policy()
    with pytest.warns(ResourceWarning):
        proc = sandbox.popen(["sleep", "100"])
        del proc
        gc.collect()
    assert not sandbox.is_running, "__del__ must reap an abandoned child"
    assert _policy_reusable(sandbox), "sandbox is reusable after __del__ reap"
