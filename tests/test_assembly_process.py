import sys
import time

import pytest

from factoryline.assembly_process import run_cli


def test_success_preserves_both_streams(tmp_path):
    ok, output = run_cli(sys.executable, ["-c", "import sys; print('proof'); print('error', file=sys.stderr)"], tmp_path)
    assert ok
    assert "proof" in output and "error" in output


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_overflow_cannot_pass(tmp_path, stream):
    ok, output = run_cli(sys.executable, ["-c", f"import sys; sys.{stream}.write('x'*100000)"], tmp_path, max_stream_bytes=1024)
    assert not ok
    assert "output limit" in output
    assert len(output) < 1400


@pytest.mark.parametrize("cancel", [False, True])
def test_deadline_and_cancellation_are_bounded(tmp_path, cancel):
    start = time.monotonic()
    ok, output = run_cli(sys.executable, ["-c", "import time; time.sleep(30)"], tmp_path,
                         timeout=0.2, heartbeat=(lambda: False) if cancel else None)
    assert not ok
    assert ("stop requested" if cancel else "timed out") in output
    assert time.monotonic() - start < 10


def test_nonzero_exit_and_invalid_bytes(tmp_path):
    ok, output = run_cli(sys.executable, ["-c", "import sys; sys.stdout.buffer.write(b'\\xff'); sys.exit(3)"], tmp_path)
    assert not ok and "\ufffd" in output


def test_heartbeat_exception_is_not_success(tmp_path):
    def broken():
        raise RuntimeError("monitor failed")
    with pytest.raises(RuntimeError, match="monitor failed"):
        run_cli(sys.executable, ["-c", "import time; time.sleep(30)"], tmp_path, heartbeat=broken)


def test_missing_cli_is_failure(tmp_path):
    assert run_cli(str(tmp_path / "missing-cli"), [], tmp_path)[0] is False


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), 0, -1])
def test_invalid_deadlines_cannot_disable_bounds(tmp_path, deadline):
    with pytest.raises(ValueError):
        run_cli(sys.executable, ["-c", "pass"], tmp_path, timeout=deadline)


def test_inherited_pipe_does_not_hang_caller(tmp_path):
    # A short-lived descendant inherits pipes after its parent exits. Even if
    # Windows cannot find that exited parent, caller cleanup remains bounded.
    code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(1)'])"
    start = time.monotonic()
    ok, output = run_cli(sys.executable, ["-c", code], tmp_path, timeout=0.2)
    assert not ok and "timed out" in output
    assert time.monotonic() - start < 10
