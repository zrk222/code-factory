from __future__ import annotations

import json
import io
from pathlib import Path
import sys
import threading
import pytest

from factoryline.runtime_audit_process import _drain_stream, _stop, run_bounded_command
from factoryline.runtime_audit_runner import run_runtime_audit_plan
from factoryline.runtime_audit_contract import verify_runtime_audit_plan
from test_runtime_audit_contract import D, signed_plan


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
    target_artifact = (
        tmp_path / result["run_root"] / "lane" / "target" / "artifact.json"
    )
    known_bad_artifact = (
        tmp_path / result["run_root"] / "lane" / "known_bad" / "artifact.json"
    )
    assert target_artifact.is_file()
    assert known_bad_artifact.is_file()
    assert target_artifact != known_bad_artifact
    assert not (tmp_path / "runtime-home").exists()


def test_runner_supports_bounded_parallel_lanes_with_isolated_scratch(
    tmp_path, monkeypatch
):
    plan_path, trust, trust_sha, _ = signed_plan(
        tmp_path,
        execution_policy={
            "max_parallelism": 2,
            "non_mutating": True,
            "resource_safe": True,
        },
    )
    verified = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    calls = []

    def fake_leg(lane, command_name, argv_key, run_root, workspace):
        calls.append((lane["id"], command_name))
        return {"artifact": {"ok": True}}

    monkeypatch.setattr("factoryline.runtime_audit_runner._run_one_guarded", fake_leg)
    plan = verified["plan"]
    result = run_runtime_audit_plan(
        plan,
        tmp_path,
        tmp_path / "out",
        plan_sha256=verified["payload_sha256"],
        max_parallelism=2,
        execution_admission=verified["execution_admission"],
    )
    assert result["execution_policy"]["max_parallelism"] == 2
    assert [item["id"] for item in result["executions"]] == [
        item["id"] for item in plan["lanes"]
    ]
    assert calls == [
        (lane["id"], leg) for lane in plan["lanes"] for leg in ("target", "known_bad")
    ]


def test_parallel_runner_requires_signed_policy_before_launch(tmp_path):
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 1,
        "target_argv": [sys.executable, "-c", "raise SystemExit(9)", "{artifact}"],
        "known_bad_argv": [sys.executable, "-c", "raise SystemExit(9)", "{artifact}"],
    }
    from factoryline.runtime_audit_common import RuntimeAuditError

    with pytest.raises(RuntimeAuditError, match="E_PARALLELISM_POLICY"):
        run_runtime_audit_plan(
            {"lanes": [lane]}, tmp_path, tmp_path / "out", max_parallelism=2
        )
    assert not list((tmp_path / "out").glob("run-*"))


def test_parallel_prelaunch_source_growth_reads_only_signed_budget_plus_one(
    tmp_path, monkeypatch
):
    from factoryline.runtime_audit_contract import _hash_regular_file_bounded
    from factoryline.runtime_audit_common import RuntimeAuditError

    plan_path, trust, trust_sha, _ = signed_plan(
        tmp_path,
        execution_policy={
            "max_parallelism": 2,
            "non_mutating": True,
            "resource_safe": True,
        },
    )
    verified = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    source = tmp_path / "candidate.txt"
    source.write_bytes(b"g" * 4096)
    calls = []
    original_open = Path.open

    class CountingStream:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            block = self.stream.read(size)
            calls.append(len(block))
            return block

    def counting_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        return CountingStream(stream) if path == source else stream

    monkeypatch.setattr(Path, "open", counting_open)

    with pytest.raises(RuntimeAuditError, match="E_SOURCE_SIZE"):
        run_runtime_audit_plan(
            verified["plan"],
            tmp_path,
            tmp_path / "out",
            plan_sha256=verified["payload_sha256"],
            max_parallelism=2,
            execution_admission=verified["execution_admission"],
        )
    assert sum(calls) == len(b"candidate") + 1
    assert not list((tmp_path / "out").glob("run-*"))


def test_parallel_runner_rejects_unsafe_or_over_limit_policy(tmp_path):
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 1,
        "target_argv": [sys.executable, "-c", "pass", "{artifact}"],
        "known_bad_argv": [sys.executable, "-c", "pass", "{artifact}"],
    }
    from factoryline.runtime_audit_common import RuntimeAuditError

    for policy in (
        {"max_parallelism": 2, "non_mutating": False, "resource_safe": True},
        {"max_parallelism": 2, "non_mutating": True, "resource_safe": False},
        {"max_parallelism": 1, "non_mutating": True, "resource_safe": True},
    ):
        with pytest.raises(RuntimeAuditError, match="E_PARALLELISM_POLICY"):
            run_runtime_audit_plan(
                {"lanes": [lane], "execution_policy": policy},
                tmp_path,
                tmp_path / "out",
                max_parallelism=2,
            )


@pytest.mark.parametrize(
    "mutation", ["lane", "source", "source_bytes", "environment", "policy"]
)
def test_parallel_runner_rejects_plan_changed_after_admission(tmp_path, mutation):
    from factoryline.runtime_audit_common import RuntimeAuditError

    plan_path, trust, trust_sha, plan = signed_plan(
        tmp_path,
        execution_policy={
            "max_parallelism": 2,
            "non_mutating": True,
            "resource_safe": True,
        },
    )
    verified = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    admission = verified["execution_admission"]
    if mutation == "lane":
        plan["lanes"][0]["timeout_seconds"] = 2
    elif mutation == "source":
        plan["sources"][0]["sha256"] = "b" * 64
    elif mutation == "source_bytes":
        (tmp_path / "candidate.txt").write_bytes(b"changed")
    elif mutation == "environment":
        plan["environment"]["digest"] = "f" * 64
    else:
        plan["execution_policy"]["max_parallelism"] = 3
    with pytest.raises(RuntimeAuditError, match="E_PARALLELISM_POLICY"):
        run_runtime_audit_plan(
            plan,
            tmp_path,
            tmp_path / "out",
            plan_sha256=verified["payload_sha256"],
            max_parallelism=2,
            execution_admission=admission,
        )
    assert not list((tmp_path / "out").glob("run-*"))


def test_missing_artifact_error_does_not_disclose_absolute_path(tmp_path):
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 5,
        "target_argv": [sys.executable, "-c", "pass", "{artifact}"],
        "known_bad_argv": [sys.executable, "-c", "pass", "{artifact}"],
    }
    result = run_runtime_audit_plan({"lanes": [lane]}, tmp_path, tmp_path / "out")

    decoded = json.loads(json.dumps(result))

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    assert all(str(tmp_path) not in item for item in strings(decoded))
    assert decoded["run_root"].startswith("out/run-")
    assert not Path(decoded["run_root"]).is_absolute()
    assert str(tmp_path) not in decoded["run_root"]
    for leg in decoded["executions"][0].values():
        if isinstance(leg, dict):
            assert str(tmp_path) not in str(leg.get("artifact_error"))
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
