import os
import signal
import sys
import time
from pathlib import Path

import pytest

from factoryline.assembly_process import MAX_STREAM_BYTES, run_cli_detailed


def test_ci_runs_native_python_matrix_on_all_supported_host_families() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "os: [ubuntu-latest, windows-latest, macos-latest]" in workflow
    assert 'python: ["3.10", "3.11", "3.12"]' in workflow
    assert "runs-on: ${{ matrix.os }}" in workflow
    assert "native-process-parity:" in workflow
    assert "os: [ubuntu-latest, macos-latest]" in workflow
    assert "native-process-parity-${{ matrix.os }}" in workflow
    assert "--junitxml=native-process-parity.junit.xml" in workflow


@pytest.mark.skipif(os.name == "nt", reason="native POSIX parity executes in Linux/macOS CI")
def test_native_timeout_returns_closed_receipt(tmp_path) -> None:
    result = run_cli_detailed(sys.executable, ["-c", "import time; time.sleep(30)"], tmp_path, timeout=1)
    assert result["ok"] is False
    assert result["reason"] == "stage timed out"
    assert result["cleanup_confirmed"] is True
    assert result["streams_closed"] is True


@pytest.mark.skipif(os.name == "nt", reason="native POSIX parity executes in Linux/macOS CI")
def test_native_output_limit_returns_closed_receipt(tmp_path) -> None:
    code = f"import sys; sys.stdout.buffer.write(b'x' * {MAX_STREAM_BYTES + 1})"
    result = run_cli_detailed(sys.executable, ["-c", code], tmp_path, timeout=10)
    assert result["ok"] is False
    assert result["reason"] == "output limit exceeded or stream read failed"
    assert result["cleanup_confirmed"] is True
    assert result["streams_closed"] is True


@pytest.mark.skipif(os.name == "nt", reason="native POSIX parity executes in Linux/macOS CI")
def test_native_cancellation_returns_closed_receipt(tmp_path) -> None:
    result = run_cli_detailed(sys.executable, ["-c", "import time; time.sleep(30)"], tmp_path,
                              timeout=10, heartbeat=lambda: False)
    assert result["ok"] is False
    assert result["reason"] == "stop requested through the local Studio"
    assert result["cleanup_confirmed"] is True
    assert result["streams_closed"] is True


@pytest.mark.skipif(os.name == "nt", reason="native POSIX parity executes in Linux/macOS CI")
def test_native_surviving_child_is_unconfirmed(tmp_path) -> None:
    """A child that starts a new session is known but outside our cleanup unit."""
    pid_file = tmp_path / "escaped-child.pid"
    child = (
        "import os,pathlib,sys,time; os.setsid(); "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='utf-8'); time.sleep(30)"
    )
    parent = (
        "import pathlib,subprocess,sys,time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(30)"
    )
    result = run_cli_detailed(sys.executable, ["-c", parent, str(pid_file), child], tmp_path, timeout=1)
    assert result["ok"] is False
    assert result["reason"] == "stage timed out"
    assert result["cleanup_confirmed"] is False
    assert "cleanup could not be confirmed" in result["output"]

    deadline = time.monotonic() + 2
    while not pid_file.is_file() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert pid_file.is_file()
    escaped_pid = int(pid_file.read_text(encoding="utf-8"))
    try:
        os.kill(escaped_pid, 0)
    finally:
        try:
            os.kill(escaped_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
