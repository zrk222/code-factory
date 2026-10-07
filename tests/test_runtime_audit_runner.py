from __future__ import annotations

import json
import io
from pathlib import Path
import sys
import threading

from factoryline.runtime_audit_process import _drain_stream, _stop, run_bounded_command
from factoryline.runtime_audit_runner import run_runtime_audit_plan


def test_runner_uses_exact_argv_separate_artifacts_and_no_worktree_home(tmp_path):
    writer = tmp_path / "writer.py"
    writer.write_text(
        "import json,sys; json.dump({'schema':'fixture','mode':sys.argv[1]},open(sys.argv[2],'w'))\n",
        encoding="utf-8",
    )
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 5,
        "target_argv": [sys.executable, str(writer), "target", "{artifact}"],
        "known_bad_argv": [sys.executable, str(writer), "known_bad", "{artifact}"],
    }
    result = run_runtime_audit_plan({"lanes": [lane]}, tmp_path, tmp_path / "out")
    execution = result["executions"][0]
    assert execution["target"]["artifact"]["mode"] == "target"
    assert execution["known_bad"]["artifact"]["mode"] == "known_bad"
    assert (
        execution["target"]["artifact_sha256"]
        != execution["known_bad"]["artifact_sha256"]
    )
    homes = list((tmp_path / "out").rglob("runtime-home"))
    assert len(homes) == 2
    assert all(
        path.is_dir() and path.is_relative_to(tmp_path / "out") for path in homes
    )
    target_artifact = Path(result["run_root"]) / "lane" / "target" / "artifact.json"
    known_bad_artifact = (
        Path(result["run_root"]) / "lane" / "known_bad" / "artifact.json"
    )
    assert target_artifact.is_file()
    assert known_bad_artifact.is_file()
    assert target_artifact != known_bad_artifact
    assert not (tmp_path / "runtime-home").exists()


def test_runner_supports_bounded_parallel_lanes_with_isolated_scratch(tmp_path):
    writer = tmp_path / "writer.py"
    writer.write_text(
        "import json,sys; json.dump({'schema':'fixture','mode':sys.argv[1]},open(sys.argv[2],'w'))\n",
        encoding="utf-8",
    )
    lanes = [
        {
            "id": f"lane-{suffix}",
            "kind": "stateful_invariant",
            "timeout_seconds": 5,
            "target_argv": [sys.executable, str(writer), "target", "{artifact}"],
            "known_bad_argv": [sys.executable, str(writer), "known_bad", "{artifact}"],
        }
        for suffix in ("a", "b")
    ]
    result = run_runtime_audit_plan(
        {"lanes": lanes}, tmp_path, tmp_path / "out", max_parallelism=2
    )
    assert result["execution_policy"]["max_parallelism"] == 2
    assert [item["id"] for item in result["executions"]] == ["lane-a", "lane-b"]
    assert all(item["target"]["artifact"] for item in result["executions"])


def test_missing_artifact_error_does_not_disclose_absolute_path(tmp_path):
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 5,
        "target_argv": [sys.executable, "-c", "pass", "{artifact}"],
        "known_bad_argv": [sys.executable, "-c", "pass", "{artifact}"],
    }
    result = run_runtime_audit_plan({"lanes": [lane]}, tmp_path, tmp_path / "out")

    assert str(tmp_path) not in json.dumps(result)
    assert result["executions"][0]["target"]["artifact_error"] == {
        "code": "E_ARTIFACT_MISSING"
    }


def test_supervisor_times_out_and_hashes_output_without_retaining_it(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    result = run_bounded_command(
        [sys.executable, "-c", "import time; print('safe'); time.sleep(2)"],
        tmp_path,
        1,
        scratch,
    )
    assert result["timed_out"] is True
    assert result["cleanup_confirmed"] is True
    assert result["timeout_seconds"] == 1
    assert result["duration_ms"] >= 1
    assert result["termination_reason"] == "timeout"
    assert "safe" not in json.dumps(result)


def test_supervisor_times_out_before_a_late_child_exit_is_polled(monkeypatch):
    from factoryline.runtime_audit_process import _wait_for_exit_or_limit

    class Child:
        def __init__(self):
            self.wait_calls = 0
            self.exit_code = None

        def wait(self, timeout):
            self.wait_calls += 1
            if self.wait_calls == 2:
                # Exit races the deadline: the bounded wait reports timeout,
                # then the supervisor observes the child's exit.
                self.exit_code = 0
            raise __import__("subprocess").TimeoutExpired("late", timeout)

    clock = iter((10.0, 10.5, 10.99, 11.01))
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.time.monotonic", lambda: next(clock)
    )
    child = Child()

    assert _wait_for_exit_or_limit(child, 1, threading.Event()) is True
    assert child.wait_calls == 2
    assert child.exit_code == 0


def test_supervisor_deadline_includes_launch_and_stream_setup(monkeypatch, tmp_path):
    class Child:
        returncode = 0

    monkeypatch.setattr("factoryline.runtime_audit_process._launch", lambda *a: Child())
    monkeypatch.setattr(
        "factoryline.runtime_audit_process._start_stream_readers",
        lambda *a: [],
    )
    monkeypatch.setattr(
        "factoryline.runtime_audit_process._await_cleanup", lambda *a: (True, True)
    )
    monkeypatch.setattr(
        "factoryline.runtime_audit_process._cleanup_is_confirmed",
        lambda *a: True,
    )
    clock = iter((10.0, 10.0, 11.01, 11.02))
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.time.monotonic", lambda: next(clock)
    )

    result = run_bounded_command(
        [sys.executable, "-c", "pass"], tmp_path, 1, tmp_path / "scratch"
    )

    assert result["timed_out"] is True
    assert result["duration_ms"] == 1020
    assert result["exit_code"] == 0


def test_windows_cleanup_timeout_is_contained(monkeypatch):
    class Child:
        pid = 42

        def poll(self):
            return None

        def kill(self):
            return None

    monkeypatch.setattr("factoryline.runtime_audit_process.os.name", "nt")
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            __import__("subprocess").TimeoutExpired("taskkill", 10)
        ),
    )
    assert _stop(Child()) is False


def test_windows_cleanup_failure_is_not_reported_as_confirmed(monkeypatch):
    class Child:
        pid = 42

        def poll(self):
            return None

        def kill(self):
            return None

    class FailedTaskkill:
        returncode = 1

    monkeypatch.setattr("factoryline.runtime_audit_process.os.name", "nt")
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.subprocess.run",
        lambda *args, **kwargs: FailedTaskkill(),
    )
    assert _stop(Child()) is False


def test_stream_drainer_hashes_and_counts_without_retaining_payload():
    streams: dict[str, tuple[str, int]] = {}
    _drain_stream("stdout", io.BytesIO(b"receipt-only"), threading.Event(), streams)
    digest, size = streams["stdout"]
    assert size == len(b"receipt-only")
    assert len(digest) == 64
