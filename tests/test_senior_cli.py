import hashlib
import json

from factoryline.benchmark_lab import SCHEMA as BENCHMARK_SCHEMA
from factoryline.cli import main
from factoryline.incremental_scheduler import SCHEMA as SCHEDULE_SCHEMA
from factoryline.benchmark_lab import load_benchmark_json
from factoryline.incremental_scheduler import load_schedule_json
from factoryline.senior_assurance import REUSE_REQUEST_SCHEMA


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def test_senior_schedule_cli_emits_json(tmp_path, capsys):
    manifest = {"schema": SCHEDULE_SCHEMA, "plan_id": "cli-plan", "assurance_level": "isolated_worker", "changed_paths": ["src/a.py"], "dependency_closure": {"lint": ["src/a.py"]}, "gates": [{"id": "lint", "depends_on": [], "side_effects": False, "proof": None}]}
    path = tmp_path / "schedule.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert main(["senior", "schedule", str(path), "--root", str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "INCREMENTAL_PLAN_COMPACT"
    assert result["findings"]["lint"]["disposition"] == "RUN"


def test_senior_benchmark_cli_blocks_bad_observation(tmp_path, capsys):
    manifest = {"schema": BENCHMARK_SCHEMA, "benchmark_id": "cli", "version": "1", "cases": [{"id": "bug", "category": "failure_recovery", "source": "fixtures/bug", "source_sha256": _digest("a"), "expected_finding": "timeout", "replay_argv": ["pytest", "tests/bug.py"], "buggy_sha256": _digest("b"), "fixed_sha256": _digest("c")}]}
    observations = {"bug": {"buggy": {"state": "PASS", "finding": ""}, "fixed": {"state": "PASS", "finding": ""}}}
    manifest_path = tmp_path / "manifest.json"
    observations_path = tmp_path / "observations.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    observations_path.write_text(json.dumps(observations), encoding="utf-8")
    assert main(["senior", "benchmark", str(manifest_path), "--observations", str(observations_path)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "BLOCKED"


def test_senior_json_loaders_are_bounded_cli_inputs(tmp_path):
    benchmark = tmp_path / "benchmark.json"
    schedule = tmp_path / "schedule.json"
    benchmark.write_text(json.dumps({"schema": BENCHMARK_SCHEMA}), encoding="utf-8")
    schedule.write_text(json.dumps({"schema": SCHEDULE_SCHEMA}), encoding="utf-8")
    assert load_benchmark_json(benchmark)["schema"] == BENCHMARK_SCHEMA
    assert load_schedule_json(schedule)["schema"] == SCHEDULE_SCHEMA


def test_senior_brief_cli_emits_actionable_evidence(tmp_path, capsys):
    receipt = tmp_path / "failed.json"
    receipt.write_text(json.dumps({"schema": "factory.replay-receipt.v1", "state": "FAIL", "failure_reason": "EXIT_MISMATCH", "source_root": "src", "argv": ["python", "run.py"], "receipt_sha256": _digest("receipt")}), encoding="utf-8")
    assert main(["senior", "brief", str(receipt)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "FAILURE_BRIEF_EVIDENCE_LINKED"
    assert result["what_broke"][0]["evidence"] == _digest("receipt")


def test_senior_reuse_cli_explains_missing_evidence_as_run(tmp_path, capsys):
    request = tmp_path / "reuse.json"
    request.write_text(json.dumps({"schema": REUSE_REQUEST_SCHEMA, "request_id": "r", "policy_sha256": _digest("policy"), "dependencies_sha256": _digest("deps"), "gates": [{"id": "lint", "read_only": True, "side_effects": False}]}), encoding="utf-8")
    assert main(["senior", "reuse", str(request), "--root", str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["gates"][0]["decision"] == "RUN"
    assert result["gates"][0]["reason"] == "UNKNOWN_INPUT_REQUIRES_EXECUTION"
