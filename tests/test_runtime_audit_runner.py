from __future__ import annotations

import json
import io
from pathlib import Path
import sys
import threading
import pytest

from factoryline.runtime_audit_process import (
    _drain_stream,
    _stop,
    create_bounded_temp_directory,
    remove_bounded_temp_directory,
    run_bounded_command,
    validate_production_mutation_process,
)
from factoryline.runtime_audit_runner import (
    capture_local_production_mutation,
    run_runtime_audit_plan,
)
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
    active = 0
    peak_active = 0
    lock = threading.Lock()
    overlap = threading.Barrier(2, timeout=5)

    def fake_leg(lane, command_name, argv_key, run_root, workspace):
        nonlocal active, peak_active
        command_root = run_root / lane["id"] / command_name
        command_root.mkdir(parents=True, exist_ok=False)
        with lock:
            active += 1
            peak_active = max(peak_active, active)
            calls.append((lane["id"], command_name, command_root))
        try:
            overlap.wait()
            return {"artifact": {"ok": True}}
        finally:
            with lock:
                active -= 1

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
    expected = {
        (lane["id"], leg) for lane in plan["lanes"] for leg in ("target", "known_bad")
    }
    assert {(lane_id, leg) for lane_id, leg, _ in calls} == expected
    assert len(calls) == len(expected)
    assert peak_active == 2
    scratch = [path for _, _, path in calls]
    assert len(set(scratch)) == len(expected)
    assert all(
        path.is_dir() and path.is_relative_to(tmp_path / "out") for path in scratch
    )


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


def _mutation_project(root, *, parameterized=False):
    (root / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\npython_files = ['test_*.py']\n",
        encoding="utf-8",
    )
    production = root / "app.py"
    production.write_text("def value():\n    return 1\n", encoding="utf-8")
    test = root / "test_app.py"
    decorator = (
        "@__import__('pytest').mark.parametrize('value', [1, 1], ids=['a', 'b'])\n"
        if parameterized
        else ""
    )
    expected = "value" if parameterized else "1"
    test.write_text(
        "import app\n"
        + decorator
        + f"def test_value({'' if not parameterized else 'value'}):\n    assert app.value() == {expected}\n",
        encoding="utf-8",
    )
    return test, 4 if parameterized else 3


def test_local_production_mutation_capture_records_real_all_case_failure(tmp_path):
    from hashlib import sha256

    test, assertion_line = _mutation_project(tmp_path, parameterized=True)
    original_test = test.read_bytes()
    original_source = (tmp_path / "app.py").read_bytes()
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-one",
        timeout_seconds=30,
    )

    assert result["schema"] == "factory.local-production-mutation-capture.v1"
    assert result["status"] == "OBSERVED"
    assert result["signature_status"] == "UNSIGNED"
    assert result["authority"] == "none"
    assert result["source_unchanged"] is True
    assert test.read_bytes() == original_test
    assert (tmp_path / "app.py").read_bytes() == original_source
    assert (
        result["production_mutation"]["original_sha256"]
        == sha256(original_source).hexdigest()
    )
    assert result["baseline_observation"]["collected"] == [
        "test_app.py::test_value[a]",
        "test_app.py::test_value[b]",
    ]
    baseline_context = result["baseline_observation"]
    mutant_context = result["mutant_observation"]
    assert (
        baseline_context["runtime_context_before"]
        == baseline_context["runtime_context_after"]
    )
    assert (
        baseline_context["runtime_context_normalized_before"]
        == mutant_context["runtime_context_normalized_before"]
    )
    for trial in (result["baseline"], result["mutant"]):
        identity = trial["execution_identity"]
        assert identity["command_template"].startswith("python -c ")
        assert identity["argument_roles"][-1] == "observation-output"
        assert len(identity["argv_sha256"]) == 64
        assert len(identity["interpreter_sha256"]) == 64
        assert identity["interpreter_version"]
        assert str(tmp_path) not in json.dumps(identity)
    for trial_name in ("baseline_observation", "mutant_observation"):
        observation = result[trial_name]
        assert observation["collection_incomplete"] is False
        assert observation["collection_report_sha256"]
        assert {row["hits"] for row in observation["assertion_observations"]} == {1}
    assert all(
        row["outcome"] == "FAIL" and row["failure_visible"] is True
        for row in result["mutant_observation"]["assertion_observations"]
    )
    assert result["cleanup"]["removed"] is True
    saved = json.loads((tmp_path / ".factory/capture-one/capture.json").read_text())
    assert saved["schema"] == "factory.local-production-mutation-capture.v1"
    assert saved["signature_status"] == "UNSIGNED"
    assert str(tmp_path) not in json.dumps(saved)


def test_local_production_mutation_rejects_unrelated_assertion_failure(tmp_path):
    test, _ = _mutation_project(tmp_path)
    test.write_text(
        "import app\n"
        "def test_value():\n"
        "    assert app.value() == 1\n"
        "    assert app.other() == 1\n",
        encoding="utf-8",
    )
    production = tmp_path / "app.py"
    production.write_text(
        "def value():\n    return 1\n\ndef other():\n    return 1  # other\n",
        encoding="utf-8",
    )
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        3,
        "app.py",
        "other",
        "return 1  # other",
        "return 0",
        ".factory/capture-unrelated",
        timeout_seconds=30,
    )

    assert result["status"] == "INCOMPLETE"
    observation = result["mutant_observation"]
    assert observation["case_hits"]["test_app.py::test_value"] == 1
    assert observation["assertion_observations"] == [
        {
            "case_id": "test_app.py::test_value",
            "callback_qualname": "test_value",
            "line": 3,
            "assertion_kind": "assert",
            "hits": 1,
            "outcome": "FAIL",
            "failure_visible": False,
        }
    ]


def test_local_production_mutation_capture_rejects_unbound_patch(tmp_path):
    from factoryline.runtime_audit_common import RuntimeAuditError

    _, assertion_line = _mutation_project(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_MUTATION_INPUT"):
        capture_local_production_mutation(
            tmp_path,
            "test_app.py::test_value",
            assertion_line,
            "app.py",
            "value",
            "return 3",
            "return 0",
            ".factory/capture-invalid",
            timeout_seconds=10,
        )
    assert not (tmp_path / ".factory/capture-invalid").exists()


def test_local_production_mutation_capture_rejects_duplicate_patch_bytes(tmp_path):
    from factoryline.runtime_audit_common import RuntimeAuditError

    _, assertion_line = _mutation_project(tmp_path)
    (tmp_path / "app.py").write_text(
        "def value():\n    return 1\n\ndef other():\n    return 1\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeAuditError, match="E_MUTATION_INPUT"):
        capture_local_production_mutation(
            tmp_path,
            "test_app.py::test_value",
            assertion_line,
            "app.py",
            "value",
            "return 1",
            "return 0",
            ".factory/capture-invalid",
            timeout_seconds=10,
        )
    assert not (tmp_path / ".factory/capture-invalid").exists()


def test_local_production_mutation_does_not_credit_assertion_error_from_production(
    tmp_path,
):
    test, assertion_line = _mutation_project(tmp_path)
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "raise AssertionError('from production')",
        ".factory/capture-production-assertion",
        timeout_seconds=30,
    )
    observation = result["mutant_observation"]
    assert result["status"] == "INCOMPLETE"
    assert observation["assertion_observations"][0]["hits"] == 1
    assert observation["assertion_observations"][0]["failure_visible"] is False


def test_local_production_mutation_keeps_pytest_deselection_incomplete(tmp_path):
    test, assertion_line = _mutation_project(tmp_path, parameterized=True)
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\npython_files = ['test_*.py']\naddopts = '-k b'\n",
        encoding="utf-8",
    )
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-deselected",
        timeout_seconds=30,
    )
    assert result["status"] == "INCOMPLETE"
    assert result["baseline_observation"]["collection_incomplete"] is True
    saved = json.loads(
        (tmp_path / ".factory/capture-deselected/capture.json").read_text()
    )
    assert saved["status"] == "INCOMPLETE"
    assert saved["baseline_observation"]["collection_incomplete"] is True


def test_production_mutation_requires_identical_case_catalogs():
    from factoryline.runtime_audit_process import same_mutation_case_catalogs

    baseline = {"data": {"collected": ["test_app.py::test_value[a]"]}}
    mutant = {"data": {"collected": ["test_app.py::test_value[b]"]}}
    assert not same_mutation_case_catalogs(baseline, mutant)
    mutant["data"]["collected"] = baseline["data"]["collected"]
    assert same_mutation_case_catalogs(baseline, mutant)


def test_local_production_mutation_config_drift_is_incomplete(tmp_path):
    test, assertion_line = _mutation_project(tmp_path)
    test.write_text(
        "from pathlib import Path\n"
        "import app\n"
        "def test_value():\n"
        "    Path('pyproject.toml').write_text('[tool.pytest.ini_options]\\n', encoding='utf-8')\n"
        "    assert app.value() == 1\n",
        encoding="utf-8",
    )
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        5,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-config-drift",
        timeout_seconds=30,
    )
    assert result["status"] == "INCOMPLETE"
    saved = json.loads(
        (tmp_path / ".factory/capture-config-drift/capture.json").read_text()
    )
    assert saved["status"] == "INCOMPLETE"
    assert saved["baseline_observation"] is not None


def test_local_production_mutation_rejects_target_symlink_after_baseline(
    tmp_path, monkeypatch
):
    import os

    import factoryline.runtime_audit_runner as runner

    test, assertion_line = _mutation_project(tmp_path)
    original = tmp_path / "app.py"
    original_bytes = original.read_bytes()
    run_trial = runner._run_local_mutation_trial

    def replace_copy_target_after_baseline(*args, **kwargs):
        result = run_trial(*args, **kwargs)
        if args[7] == "baseline":
            copied_target = args[0] / "app.py"
            copied_target.unlink()
            try:
                os.symlink(original, copied_target)
            except OSError as exc:
                pytest.skip(f"symlink unavailable for CAP06 control: {exc}")
        return result

    monkeypatch.setattr(
        runner, "_run_local_mutation_trial", replace_copy_target_after_baseline
    )
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-linked-target",
        timeout_seconds=30,
    )
    assert result["status"] == "INCOMPLETE"
    assert original.read_bytes() == original_bytes


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


def test_validate_production_mutation_source_binds_complete_named_function():
    from factoryline.runtime_audit_common import (
        RuntimeAuditError,
        validate_production_mutation_source,
    )

    source = b"def value():\n    return 1\n"
    assert validate_production_mutation_source(source, "value", b"return 1") == (
        2,
        "value",
    )
    with pytest.raises(RuntimeAuditError, match="E_MUTATION_INPUT"):
        validate_production_mutation_source(source, "other", b"return 1")


def test_validate_production_mutation_collection_requires_exact_complete_catalog():
    from factoryline.runtime_audit_common import (
        validate_production_mutation_collection,
    )

    observation = {
        "collection_incomplete": False,
        "collected": ["test_app.py::test_value[a]", "test_app.py::test_value[b]"],
        "collection_reports": [
            {"outcome": "passed", "failed": False, "skipped": False},
            {"outcome": "passed", "failed": False, "skipped": False},
        ],
    }
    assert validate_production_mutation_collection(
        observation, "test_app.py::test_value"
    )
    observation["collection_incomplete"] = True
    assert not validate_production_mutation_collection(
        observation, "test_app.py::test_value"
    )


def test_validate_production_mutation_trial_requires_hit_and_visible_failure():
    from factoryline.runtime_audit_common import validate_production_mutation_trial

    case = "test_app.py::test_value"
    observation = {
        "collection_incomplete": False,
        "collected": [case],
        "collection_reports": [
            {"outcome": "passed", "failed": False, "skipped": False}
        ],
        "reports": [
            {"nodeid": case, "phase": phase, "outcome": outcome, "xfail": False}
            for phase, outcome in (
                ("setup", "passed"),
                ("call", "failed"),
                ("teardown", "passed"),
            )
        ],
        "assertion_observations": [
            {
                "case_id": case,
                "line": 3,
                "hits": 1,
                "outcome": "FAIL",
                "failure_visible": True,
            }
        ],
    }
    assert validate_production_mutation_trial(
        observation, "test_app.py::test_value", 3, "failed", True
    )
    observation["assertion_observations"][0]["failure_visible"] = False
    assert not validate_production_mutation_trial(
        observation, "test_app.py::test_value", 3, "failed", True
    )


def test_validate_production_mutation_origins_requires_per_case_source_frames(
    tmp_path,
):
    from hashlib import sha256

    from factoryline.runtime_audit_common import validate_production_mutation_origins

    test_path = tmp_path / "test_app.py"
    production_path = tmp_path / "app.py"
    test_path.write_bytes(b"def test_value(): pass\n")
    production_path.write_bytes(b"def value(): return 1\n")
    case = "test_app.py::test_value"
    manifest = {
        "test_app.py": sha256(test_path.read_bytes()).hexdigest(),
        "app.py": sha256(production_path.read_bytes()).hexdigest(),
    }
    rows = [
        {
            "path": path,
            "origin": path,
            "nodeid": case,
            "phase": "call",
            "observation_kind": "executed_frame",
            "source_sha256": digest,
            "status": "BOUND",
        }
        for path, digest in manifest.items()
    ]
    observation = {
        "origin_status": "BOUND",
        "origin_limit_exceeded": False,
        "collected": [case],
        "executed_modules": rows,
    }
    assert validate_production_mutation_origins(
        observation, tmp_path, manifest, production_path
    )
    rows[0]["observation_kind"] = "imported_module"
    assert not validate_production_mutation_origins(
        observation, tmp_path, manifest, production_path
    )
    observation["executed_modules"] = [None]
    assert not validate_production_mutation_origins(
        observation, tmp_path, manifest, production_path
    )


def test_validate_production_mutation_process_requires_confirmed_supervision():
    facts = {
        "timed_out": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "launch_error": False,
        "exit_code": 1,
    }
    assert validate_production_mutation_process(facts)
    facts["cleanup_confirmed"] = False
    assert not validate_production_mutation_process(facts)


def test_bounded_file_hash_rejects_oversized_input(tmp_path):
    from factoryline.runtime_audit_process import bounded_file_sha256

    path = tmp_path / "small.bin"
    path.write_bytes(b"123")
    assert len(bounded_file_sha256(path, 3)) == 64
    with pytest.raises(ValueError, match="size limit"):
        bounded_file_sha256(path, 2)


def test_tree_and_target_path_helpers_reject_escape_and_accept_regular_files(tmp_path):
    from factoryline.runtime_audit_process import (
        new_output_path_inside,
        path_chain_has_no_links,
        regular_target_within,
        tree_has_no_links_or_reparse_points,
    )

    root = tmp_path / "root"
    root.mkdir()
    source = root / "source.py"
    source.write_text("x = 1\n", encoding="utf-8")
    assert tree_has_no_links_or_reparse_points(root)
    assert regular_target_within(root, source)
    assert path_chain_has_no_links(root, root / ".factory/output.json")
    assert not path_chain_has_no_links(root, tmp_path / "outside")
    assert (
        new_output_path_inside(root, Path(".factory/output"))
        == root / ".factory/output"
    )
    with pytest.raises(ValueError, match="escapes"):
        new_output_path_inside(root, tmp_path / "outside")


def test_bounded_temp_directory_stays_under_system_parent_and_is_removed():
    parent, root = create_bounded_temp_directory("cf-capture-test-")
    try:
        assert root.parent == parent
        assert root.is_dir()
    finally:
        assert remove_bounded_temp_directory(root, parent, "cf-capture-test-")
    assert not root.exists()


def test_mutation_trial_observed_rejects_context_drift_with_bound_phase_evidence(
    tmp_path,
):
    import hashlib

    from factoryline.runtime_audit_process import mutation_trial_observed

    root = tmp_path.resolve()
    test_path = root / "test_app.py"
    target = root / "app.py"
    test_path.write_bytes(b"def test_value():\n    pass\n")
    target.write_bytes(b"def value():\n    return 1\n")
    case = "test_app.py::test_value"
    manifest = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (test_path, target)
    }
    observation = {
        "collection_incomplete": False,
        "collection_reports": [
            {"outcome": "passed", "failed": False, "skipped": False}
        ],
        "collected": [case],
        "reports": [
            {"nodeid": case, "phase": phase, "outcome": outcome, "xfail": False}
            for phase, outcome in (
                ("setup", "passed"),
                ("call", "failed"),
                ("teardown", "passed"),
            )
        ],
        "assertion_observations": [
            {
                "case_id": case,
                "line": 3,
                "hits": 1,
                "outcome": "FAIL",
                "failure_visible": True,
            }
        ],
        "origin_status": "BOUND",
        "origin_limit_exceeded": False,
        "executed_modules": [
            {
                "path": name,
                "origin": name,
                "nodeid": case,
                "phase": "call",
                "observation_kind": "executed_frame",
                "source_sha256": digest,
                "status": "BOUND",
            }
            for name, digest in manifest.items()
        ],
        "runtime_context_before": "raw-context",
        "runtime_context_after": "raw-context",
        "runtime_context_normalized_before": "normalized-context",
        "runtime_context_normalized_after": "normalized-context",
    }
    trial = {
        "process": {
            "timed_out": False,
            "output_limit_exceeded": False,
            "cleanup_confirmed": True,
            "launch_error": False,
            "exit_code": 1,
        },
        "data": observation,
    }
    prepared = {"selector": case, "line": 3}

    assert mutation_trial_observed(
        trial, prepared, root, target, manifest, "failed", True
    )
    observation["runtime_context_after"] = "changed-context"
    assert not mutation_trial_observed(
        trial, prepared, root, target, manifest, "failed", True
    )
