from __future__ import annotations
import json
from pathlib import Path
from factoryline.runtime_audit import (
    EVALUATORS,
    execute_runtime_audit,
    evaluate_runtime_audit,
    runtime_audit_status,
)
from factoryline.runtime_audit_common import canonical_bytes, sha256_bytes
from factoryline.runtime_audit_contract import LANES
from factoryline.runtime_attestation import capture_supervised_attestation
import runpy
import subprocess
import pytest
from factoryline.runtime_audit_common import (
    MAX_ARTIFACT_BYTES,
    RuntimeAuditError,
    exact_keys,
    lane_result,
    parse_json_bytes,
    read_stable_json,
    reject_secret_material,
    require_bool,
    require_digest,
    require_int,
    require_number,
    require_str,
    require_unique_strings,
)
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from factoryline.runtime_coverage import (
    MAX_GAP_LOCATIONS,
    REPORT_PATH,
    RECEIPT_PATH,
    LOCAL_COVERAGE_COMMAND,
    read_runtime_coverage_report,
    source_code_digest,
    digest_test_sources,
)


def _plan():
    return {
        "id": "p",
        "candidate_sha256": "c" * 64,
        "counterfactual_mesh": {
            "id": "shared",
            "scenario_sha256": "d" * 64,
            "relations": ["same_business_operation", "same_runtime_environment"],
            "origin": "human_confirmed",
        },
        "lanes": [
            {
                "id": kind,
                "kind": kind,
                "engine": "fixture",
                "engine_version": "1",
                "target_argv": ["fixture", "{artifact}"],
                "known_bad_argv": ["fixture", "bad", "{artifact}"],
                "timeout_seconds": 3,
                "expected_negative_code": f"NEG_{kind}",
                "config": {},
            }
            for kind in LANES
        ],
    }


def _command(kind, bad=False):
    artifact = {"kind": kind, "bad": bad, "scenario_sha256": "d" * 64}
    return {
        "artifact": artifact,
        "artifact_sha256": sha256_bytes(canonical_bytes(artifact)),
        "normalized_artifact_sha256": sha256_bytes(canonical_bytes(artifact)),
        "artifact_error": None,
        "execution": {
            "timed_out": False,
            "launch_error": False,
            "output_limit_exceeded": False,
            "cleanup_confirmed": True,
            "exit_code": 1 if bad else 0,
            "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64,
        },
    }


def test_six_lane_join_requires_real_negative_controls(monkeypatch, tmp_path):
    for kind in LANES:
        monkeypatch.setitem(
            EVALUATORS,
            kind,
            lambda artifact, config, engine, engine_version, k=kind: {
                "lane": k,
                "state": "FAIL" if artifact["bad"] else "PASS",
                "finding": f"NEG_{k}" if artifact["bad"] else "HELD",
                "consequence": "caught" if artifact["bad"] else "held",
                "details": {},
            },
        )
    executions = {
        "executions": [
            {
                "id": kind,
                "kind": kind,
                "target": _command(kind),
                "known_bad": _command(kind, True),
            }
            for kind in LANES
        ]
    }
    receipt = evaluate_runtime_audit(_plan(), executions, tmp_path)
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert len(receipt["lanes"]) == 6 and receipt["release_approval"] is False
    assert receipt["cross_lane_assurance"]["scenario_id"] == "shared"
    assert receipt["repair_queue"] == []
    assert receipt["fact_index"]["mutable"] is False
    keys = [item["key"] for item in receipt["fact_index"]["values"]]
    assert (
        len(keys) == 28
        and keys == sorted(keys)
        and "lane.tenant_isolation.finding" in keys
    )
    assert all("secret" not in key and "prompt" not in key for key in keys)
    executions["executions"][0]["known_bad"]["execution"]["exit_code"] = 0
    blocked = evaluate_runtime_audit(_plan(), executions, tmp_path)
    assert blocked["decision"] == "BLOCKED"
    assert blocked["lanes"][0]["finding"] == "HOLLOW_RUNTIME_AUDIT"
    assert blocked["repair_queue"][0]["lane"] == "stateful_invariant"


def test_cross_lane_scenario_mismatch_is_incomplete(monkeypatch, tmp_path):
    for kind in LANES:
        monkeypatch.setitem(
            EVALUATORS,
            kind,
            lambda artifact, config, engine, engine_version, k=kind: {
                "lane": k,
                "state": "FAIL" if artifact["bad"] else "PASS",
                "finding": f"NEG_{k}" if artifact["bad"] else "HELD",
                "consequence": "caught",
                "details": {},
            },
        )
    executions = {
        "executions": [
            {
                "id": kind,
                "kind": kind,
                "target": _command(kind),
                "known_bad": _command(kind, True),
            }
            for kind in LANES
        ]
    }
    executions["executions"][2]["target"]["artifact"]["scenario_sha256"] = "e" * 64
    receipt = evaluate_runtime_audit(_plan(), executions, tmp_path)
    lane = next(item for item in receipt["lanes"] if item["lane"] == "failure_recovery")
    assert lane["finding"] == "CROSS_LANE_SCENARIO_MISMATCH"
    assert receipt["decision"] == "BLOCKED"


def test_runtime_boundary_is_joined_without_promoting_supervision(
    monkeypatch, tmp_path
):
    for kind in LANES:
        monkeypatch.setitem(
            EVALUATORS,
            kind,
            lambda artifact, config, engine, engine_version, k=kind: {
                "lane": k,
                "state": "FAIL" if artifact["bad"] else "PASS",
                "finding": f"NEG_{k}" if artifact["bad"] else "HELD",
                "consequence": "caught",
                "details": {},
            },
        )
    plan = _plan()
    plan["environment"] = {
        "kind": "local_test",
        "digest": "e" * 64,
        "origins": ["http://127.0.0.1"],
    }
    plan["runtime_boundary"] = {
        "requested_isolation": "supervised_subprocess",
        "attestation_required": True,
    }
    executions = {
        "executions": [
            {
                "id": kind,
                "kind": kind,
                "target": _command(kind),
                "known_bad": _command(kind, True),
            }
            for kind in LANES
        ]
    }
    plan_digest = sha256_bytes(canonical_bytes(plan))
    executions["plan_sha256"] = plan_digest
    executions["runtime_boundary"] = capture_supervised_attestation(
        attestation_id="run",
        candidate_sha256=plan["candidate_sha256"],
        plan_sha256=plan_digest,
        environment_sha256=plan["environment"]["digest"],
    )
    receipt = evaluate_runtime_audit(plan, executions, tmp_path)
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert receipt["runtime_boundary"]["state"] == "SUPERVISED_ONLY"

    plan["runtime_boundary"]["requested_isolation"] = "hardened_vm"
    blocked = evaluate_runtime_audit(plan, executions, tmp_path)
    assert blocked["decision"] == "BLOCKED"
    assert blocked["runtime_boundary"]["finding"] == "E_ISOLATION_UNPROVEN"


def test_execute_runtime_audit_binds_verified_plan_digest(monkeypatch, tmp_path):
    plan = {"id": "plan", "candidate_sha256": "c" * 64}
    run_root = tmp_path / "run"
    run_root.mkdir()
    observed = {}

    def verify(*args, **kwargs):
        return {"plan": plan, "payload_sha256": "p" * 64}

    def run(current, workspace, output, *, plan_sha256=None):
        observed["plan_sha256"] = plan_sha256
        return {"run_root": str(run_root), "executions": [], "plan_sha256": plan_sha256}

    monkeypatch.setattr("factoryline.runtime_audit.verify_runtime_audit_plan", verify)
    monkeypatch.setattr("factoryline.runtime_audit.run_runtime_audit_plan", run)
    monkeypatch.setattr(
        "factoryline.runtime_audit.evaluate_runtime_audit",
        lambda current, execution, workspace: {
            "schema": "factory.runtime-audit-receipt.v1",
            "decision": "BLOCKED",
            "lanes": [],
            "authority": "none",
            "release_approval": False,
        },
    )
    result = execute_runtime_audit(
        tmp_path / "plan.json",
        tmp_path / "trust.json",
        "t" * 64,
        tmp_path,
        "e" * 64,
        run_root,
    )
    assert observed["plan_sha256"] == "p" * 64
    assert result["receipt_path"].endswith("runtime-audit-receipt.json")
    assert len(result["receipt"]["receipt_sha256"]) == 64


def test_status_rejects_tampered_receipt(tmp_path):
    run = tmp_path / ".factory/runtime-audits/run-x"
    run.mkdir(parents=True)
    payload = {
        "schema": "factory.runtime-audit-receipt.v1",
        "decision": "READY_FOR_HUMAN_REVIEW",
        "authority": "none",
        "release_approval": False,
        "lanes": [{"id": kind, "lane": kind, "state": "PASS"} for kind in LANES],
    }
    payload["receipt_sha256"] = sha256_bytes(canonical_bytes(payload))
    (run / "runtime-audit-receipt.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    assert runtime_audit_status(tmp_path)["state"] == "READY_FOR_HUMAN_REVIEW"
    payload["decision"] = "BLOCKED"
    (run / "runtime-audit-receipt.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    assert runtime_audit_status(tmp_path)["state"] == "INCOMPLETE"


def test_status_contains_receipt_stat_race(tmp_path, monkeypatch):
    run = tmp_path / ".factory/runtime-audits/run-x"
    run.mkdir(parents=True)
    receipt = run / "runtime-audit-receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    original = Path.stat

    def raced(path, *args, **kwargs):
        if path == receipt:
            raise FileNotFoundError(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", raced)
    assert runtime_audit_status(tmp_path)["state"] == "INCOMPLETE"


# Consolidated tests from tests/test_ci_runtime_coverage.py


_WRITER_PATH = Path(__file__).parents[1] / "scripts" / "write_ci_runtime_coverage.py"


def _git_fixture(root: Path) -> str:
    (root / ".gitignore").write_text(
        ".factory/\n__pycache__/\n*.py[cod]\n", encoding="utf-8"
    )
    (root / "factoryline").mkdir()
    (root / "factoryline" / "demo.py").write_text("value = 1\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_demo.py").write_text(
        "def test_demo():\n    assert True\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    for key, value in (
        ("user.name", "CI Fixture"),
        ("user.email", "ci@example.invalid"),
    ):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
    subprocess.run(
        ["git", "-C", str(root), "add", ".gitignore", "factoryline", "tests"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "--quiet", "-m", "fixture"], check=True
    )
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _reports(root: Path) -> None:
    directory = root / ".factory" / "test-reports"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pytest.xml").write_text("<testsuites/>\n", encoding="utf-8")
    (directory / "coverage.json").write_text("{}\n", encoding="utf-8")
    (directory / "coverage.xml").write_text("<coverage/>\n", encoding="utf-8")


def _writer(root: Path, monkeypatch, commit: str, outcome: str):
    writer = runpy.run_path(str(_WRITER_PATH))
    for key, value in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "example/repo",
        "GITHUB_WORKFLOW": "CI",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REF": "refs/pull/1/merge",
        "GITHUB_SHA": commit,
        "TEST_OUTCOME": outcome,
    }.items():
        monkeypatch.setenv(key, value)
    return writer


def test_ci_runtime_coverage_keeps_default_data_file_in_ignored_reports_dir() -> None:
    import yaml

    workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    runtime_step = next(
        step
        for step in workflow["jobs"]["test"]["steps"]
        if step.get("id") == "runtime-tests"
    )

    assert runtime_step["env"]["COVERAGE_FILE"] == ".factory/test-reports/.coverage"


def test_ci_receipt_binds_clean_commit_exact_command_and_required_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    commit = _git_fixture(tmp_path)
    writer = _writer(tmp_path, monkeypatch, commit, "success")

    assert writer["ROOT"] == _WRITER_PATH.parents[1]
    assert writer["_start"](tmp_path) == 0
    _reports(tmp_path)
    assert writer["_finish"](tmp_path) == 0

    receipt = json.loads(
        (tmp_path / ".factory/test-reports/coverage.run.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["runner"] == "github-actions"
    assert receipt["authentication"] == "UNAUTHENTICATED"
    assert receipt["commit"] == commit
    assert receipt["dirty_tree"] is False
    assert receipt["exit_code"] == 0
    assert receipt["command"].endswith(
        "--cov-report=xml:.factory/test-reports/coverage.xml"
    )
    assert receipt["github_actions"]["run_id"] == "12345"
    assert set(receipt["artifacts"]) == {"junit_xml", "coverage_json", "coverage_xml"}


def test_failed_ci_run_writes_a_nonpassing_receipt(tmp_path: Path, monkeypatch) -> None:
    commit = _git_fixture(tmp_path)
    writer = _writer(tmp_path, monkeypatch, commit, "failure")

    assert writer["_start"](tmp_path) == 0
    _reports(tmp_path)
    assert writer["_finish"](tmp_path) == 1

    receipt = json.loads(
        (tmp_path / ".factory/test-reports/coverage.run.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["exit_code"] == 1
    assert (
        receipt["failure_reason"]
        == "test, clean-checkout, commit, or source binding failed"
    )


# Consolidated tests from tests/test_runtime_audit_common_attribution.py


def _error_code(error: pytest.ExceptionInfo[RuntimeAuditError]) -> str:
    return error.value.code


def test_exact_keys_accepts_declared_fields_and_ignores_only_verdict_labels():
    exact_keys(
        {"id": "case-1", "mode": "strict", "passed": True},
        {"id"},
        {"mode"},
    )

    with pytest.raises(RuntimeAuditError) as missing:
        exact_keys({"mode": "strict"}, {"id"})
    assert _error_code(missing) == "E_ARTIFACT_FIELDS"

    with pytest.raises(RuntimeAuditError) as unknown:
        exact_keys({"id": "case-1", "authority": "approve"}, {"id"})
    assert _error_code(unknown) == "E_ARTIFACT_FIELDS"

    with pytest.raises(RuntimeAuditError) as wrong_type:
        exact_keys([("id", "case-1")], {"id"})  # type: ignore[arg-type]
    assert _error_code(wrong_type) == "E_ARTIFACT_FIELDS"


@pytest.mark.parametrize(
    ("value", "minimum", "maximum"),
    [("x", 1, 1), (" evidence ", 1, 10)],
)
def test_require_str_accepts_printable_strings_at_declared_bounds(
    value: str, minimum: int, maximum: int
):
    assert require_str(value, "label", minimum=minimum, maximum=maximum) == value


@pytest.mark.parametrize("value", [None, 5, "", "  ", "a\nb"])
def test_require_str_rejects_wrong_type_blank_and_control_text(value: object):
    with pytest.raises(RuntimeAuditError) as error:
        require_str(value, "label", maximum=4)
    assert _error_code(error) == "E_FIELD"


def test_require_digest_accepts_canonical_sha256_and_rejects_noncanonical_values():
    digest = "a" * 64
    assert require_digest(digest, "sha256") == digest
    for invalid in ("A" * 64, "a" * 63, "g" * 64, 123):
        with pytest.raises(RuntimeAuditError) as error:
            require_digest(invalid, "sha256")
        assert _error_code(error) == "E_DIGEST"


def test_require_bool_refuses_integer_truthiness_and_strings():
    assert require_bool(False, "enabled") is False
    with pytest.raises(RuntimeAuditError) as error:
        require_bool(1, "enabled")
    assert _error_code(error) == "E_FIELD"


def test_require_int_enforces_inclusive_range_without_accepting_bool():
    assert require_int(3, "attempts", minimum=1, maximum=3) == 3
    for invalid in (True, 0, 4, 3.0, "3"):
        with pytest.raises(RuntimeAuditError) as error:
            require_int(invalid, "attempts", minimum=1, maximum=3)
        assert _error_code(error) == "E_FIELD"


def test_require_number_accepts_finite_values_and_rejects_bool_nan_and_floor():
    assert require_number(2, "ratio", minimum=1.5) == 2.0
    for invalid in (True, float("nan"), float("inf"), 1.4, "2"):
        with pytest.raises(RuntimeAuditError) as error:
            require_number(invalid, "ratio", minimum=1.5)
        assert _error_code(error) == "E_FIELD"


def test_require_unique_strings_preserves_values_and_rejects_duplicate_or_invalid_items():
    assert require_unique_strings(["alpha", "beta"], "ids", minimum=1, maximum=2) == [
        "alpha",
        "beta",
    ]
    for invalid in (["alpha", "alpha"], ["alpha", ""], [], ["a", "b", "c"]):
        with pytest.raises(RuntimeAuditError) as error:
            require_unique_strings(invalid, "ids", minimum=1, maximum=2)
        assert _error_code(error) in {"E_FIELD", "E_DUPLICATE_ID"}


def test_reject_secret_material_checks_nested_keys_depth_numbers_and_string_size():
    reject_secret_material({"audit": [{"finding": "bounded"}]})
    for value, expected_code in (
        ({"audit": {"token": "hidden"}}, "E_SECRET_MATERIAL"),
        ({"audit": float("nan")}, "E_NONFINITE"),
        ({"audit": "x" * 5}, "E_FIELD_SIZE"),
    ):
        with pytest.raises(RuntimeAuditError) as error:
            reject_secret_material(value, max_string_length=4)
        assert _error_code(error) == expected_code

    nested: object = "leaf"
    for _ in range(34):
        nested = [nested]
    with pytest.raises(RuntimeAuditError) as error:
        reject_secret_material(nested)
    assert _error_code(error) == "E_ARTIFACT_DEPTH"


def test_parse_json_bytes_accepts_safe_object_and_rejects_ambiguous_or_unsafe_json():
    parsed = parse_json_bytes(b'{"id":"audit-1","count":2}')
    assert parsed == {"id": "audit-1", "count": 2}

    invalid_documents = (
        (b'{"id":1,"id":2}', "E_DUPLICATE_FIELD"),
        (b"[]", "E_ARTIFACT_JSON"),
        (b"{", "E_ARTIFACT_JSON"),
        (b'{"token":"hidden"}', "E_SECRET_MATERIAL"),
        (b"\xff", "E_ARTIFACT_JSON"),
        (b"{}" + b" " * MAX_ARTIFACT_BYTES, "E_ARTIFACT_SIZE"),
    )
    for raw, expected_code in invalid_documents:
        with pytest.raises(RuntimeAuditError) as error:
            parse_json_bytes(raw)
        assert _error_code(error) == expected_code


def test_read_stable_json_returns_exact_bytes_digest_and_rejects_missing_file(tmp_path):
    raw = json.dumps({"schema": "factory.audit.v1"}, separators=(",", ":")).encode()
    artifact = tmp_path / "receipt.json"
    artifact.write_bytes(raw)

    parsed, digest = read_stable_json(artifact)
    assert parsed == {"schema": "factory.audit.v1"}
    assert digest == __import__("hashlib").sha256(raw).hexdigest()

    with pytest.raises(RuntimeAuditError) as error:
        read_stable_json(tmp_path / "missing.json")
    assert _error_code(error) == "E_ARTIFACT_MISSING"


def test_lane_result_only_emits_closed_states_and_keeps_advisory_details():
    result = lane_result(
        "security", "FAIL", "UNSAFE_INPUT", "review the finding", details={"count": 1}
    )
    assert result == {
        "lane": "security",
        "state": "FAIL",
        "finding": "UNSAFE_INPUT",
        "consequence": "review the finding",
        "details": {"count": 1},
    }

    with pytest.raises(RuntimeAuditError) as error:
        lane_result("security", "APPROVED", "NONE", "not an authority")
    assert _error_code(error) == "E_STATE"


# Consolidated tests from tests/test_runtime_coverage.py


def _summary(
    *, covered: int, total: int, branches_covered: int = 0, branches_total: int = 0
) -> dict:
    missing = total - covered
    branch_missing = branches_total - branches_covered
    return {
        "covered_lines": covered,
        "num_statements": total,
        "missing_lines": missing,
        "percent_statements_covered": covered * 100 / total if total else 100,
        "covered_branches": branches_covered,
        "num_branches": branches_total,
        "missing_branches": branch_missing,
        "percent_branches_covered": (
            branches_covered * 100 / branches_total if branches_total else 100
        ),
    }


def _fixture(root: Path, *, missing_lines: list[int] | None = None) -> dict:
    source = root / "factoryline" / "demo.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    contents = "def demo(value):\n    if value:\n        return 1\n    return 0\n"
    if missing_lines:
        contents += "\n" + "\n".join("# gap" for _ in range(max(missing_lines))) + "\n"
    source.write_text(contents, encoding="utf-8")
    total = 3 if missing_lines is None else len(missing_lines) + 1
    covered = total - 1
    row = {
        "summary": _summary(
            covered=covered, total=total, branches_covered=1, branches_total=2
        ),
        "executed_lines": [1, 2],
        "missing_lines": [3] if missing_lines is None else missing_lines,
        "executed_branches": [[2, 3]],
        "missing_branches": [[2, -4]],
    }
    totals = _summary(
        covered=covered, total=total, branches_covered=1, branches_total=2
    )
    return {
        "meta": {
            "format": 3,
            "version": "7.13.0",
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "branch_coverage": True,
        },
        "totals": totals,
        "files": {"factoryline/demo.py": row},
    }


def _write_report(root: Path, report: dict) -> Path:
    path = root / REPORT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _initialize_git(root: Path) -> str:
    (root / ".gitignore").write_text(".factory/\n", encoding="utf-8")
    tests = root / "tests" / "test_demo.py"
    tests.parent.mkdir(parents=True, exist_ok=True)
    tests.write_text("def test_demo():\n    assert True\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    for key, value in (
        ("user.name", "Coverage Fixture"),
        ("user.email", "coverage@example.invalid"),
    ):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
    subprocess.run(
        ["git", "-C", str(root), "add", ".gitignore", "factoryline", "tests"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "--quiet", "-m", "fixture"], check=True
    )
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_missing_runtime_coverage_is_not_reported_as_zero(tmp_path: Path) -> None:
    observed = read_runtime_coverage_report(tmp_path)

    assert observed["state"] == "NOT_RUN"
    assert observed["statements"] is None
    assert observed["branches"] is None
    assert observed["file_count"] is None
    assert observed["files"] == []


def test_valid_coverage_reports_separate_lines_branches_and_module_gaps(
    tmp_path: Path,
) -> None:
    _write_report(tmp_path, _fixture(tmp_path))

    summary = read_runtime_coverage_report(tmp_path)
    detail = read_runtime_coverage_report(tmp_path, include_files=True)

    assert summary["schema"] == "factory.runtime-coverage.v1"
    assert summary["state"] == "OBSERVED"
    assert summary["statements"] == {
        "covered": 2,
        "total": 3,
        "missing": 1,
        "percent": 200 / 3,
    }
    assert summary["branches"] == {
        "covered": 1,
        "total": 2,
        "missing": 1,
        "percent": 50.0,
    }
    assert summary["files"] == []
    assert detail["files"][0]["path"] == "factoryline/demo.py"
    assert detail["files"][0]["missing_lines"] == [3]
    assert detail["files"][0]["missing_branches"] == [[2, -4]]
    assert detail["candidate_binding"] == "UNBOUND"
    assert detail["RUNTIME_COVERAGE_LIMITATION"].startswith("Executed-line counts")


def test_zero_branch_inventory_uses_unavailable_rate(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    row = report["files"]["factoryline/demo.py"]
    row["summary"] = _summary(covered=2, total=3)
    row["executed_branches"] = []
    row["missing_branches"] = []
    report["totals"] = _summary(covered=2, total=3)
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path)

    assert observed["state"] == "OBSERVED"
    assert observed["branches"]["percent"] is None


def test_invalid_report_hides_file_details_and_returns_actionable_code(
    tmp_path: Path,
) -> None:
    report = _fixture(tmp_path)
    report["totals"]["covered_lines"] = 99
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["reason_code"] == "RUNTIME_COVERAGE_INVALID"
    assert observed["files"] == []
    assert "counts" in observed["reason"] or "differs" in observed["reason"]


def test_report_outside_factoryline_fails_closed(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["files"]["other/secret.py"] = report["files"].pop("factoryline/demo.py")
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "outside factoryline" in observed["reason"]


def test_missing_branch_flag_fails_closed(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["meta"]["branch_coverage"] = False
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path)

    assert observed["state"] == "INCOMPLETE"
    assert "branch coverage enabled" in observed["reason"]


def test_oversized_report_fails_closed_with_no_details(
    tmp_path: Path, monkeypatch
) -> None:
    import factoryline.runtime_coverage as coverage_module

    path = tmp_path / REPORT_PATH
    path.parent.mkdir(parents=True)
    path.write_text("{}" * 20, encoding="utf-8")
    monkeypatch.setattr(coverage_module, "MAX_REPORT_BYTES", 8)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "16 MiB" in observed["reason"]


def test_report_file_count_limit_fails_closed(tmp_path: Path, monkeypatch) -> None:
    import factoryline.runtime_coverage as coverage_module

    report = _fixture(tmp_path)
    source = tmp_path / "factoryline" / "other.py"
    source.write_text("value = 1\n", encoding="utf-8")
    first = report["files"]["factoryline/demo.py"]
    report["files"]["factoryline/other.py"] = first
    monkeypatch.setattr(coverage_module, "MAX_FILES", 1)
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "5,000 files" in observed["reason"]


def test_report_rejects_disagreeing_executed_locations(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["files"]["factoryline/demo.py"]["executed_lines"] = [1]
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "line locations" in observed["reason"]


def test_report_rejects_executed_line_beyond_source_file(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["files"]["factoryline/demo.py"]["executed_lines"] = [1, 999]
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "beyond the current source file" in observed["reason"]


def test_report_rejects_branch_location_beyond_source_file(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["files"]["factoryline/demo.py"]["missing_branches"] = [[2, 999]]
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "invalid branch location" in observed["reason"]


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / REPORT_PATH
    path.parent.mkdir(parents=True)
    path.write_text('{"meta":{},"meta":{},"totals":{},"files":{}}', encoding="utf-8")

    observed = read_runtime_coverage_report(tmp_path)

    assert observed["state"] == "INCOMPLETE"
    assert observed["reason_code"] == "RUNTIME_COVERAGE_INVALID"
    assert "duplicate JSON object key" in observed["reason"]


def test_report_must_cover_the_exact_factoryline_source_inventory(
    tmp_path: Path,
) -> None:
    report = _fixture(tmp_path)
    (tmp_path / "factoryline" / "second.py").write_text("value = 2\n", encoding="utf-8")
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "1 missing" in observed["reason"]


def test_missing_gap_details_are_bounded_and_marked(tmp_path: Path) -> None:
    missing = list(range(2, 28))
    report = _fixture(tmp_path, missing_lines=missing)
    report["files"]["factoryline/demo.py"]["summary"] = _summary(
        covered=1, total=len(missing) + 1, branches_covered=1, branches_total=2
    )
    report["files"]["factoryline/demo.py"]["executed_lines"] = [1]
    report["totals"] = report["files"]["factoryline/demo.py"]["summary"]
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)
    module = observed["files"][0]

    assert observed["state"] == "OBSERVED"
    assert len(module["missing_lines"]) == MAX_GAP_LOCATIONS
    assert module["detail_truncated"] is True
    assert observed["truncated"] is True


def test_matching_local_receipt_reports_source_hash_match_but_not_authenticity(
    tmp_path: Path,
) -> None:
    _write_report(tmp_path, _fixture(tmp_path))
    artifacts = {
        "junit_xml": ".factory/test-reports/pytest.xml",
        "coverage_json": REPORT_PATH.as_posix(),
        "coverage_xml": ".factory/test-reports/coverage.xml",
    }
    hashed_artifacts = {}
    for name, relative in artifacts.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if name != "coverage_json":
            target.write_text("<testsuites/>\n", encoding="utf-8")
        hashed_artifacts[name] = {
            "path": relative,
            "sha256": sha256(target.read_bytes()).hexdigest(),
        }
    commit = _initialize_git(tmp_path)
    code_hash = source_code_digest(tmp_path)
    started = datetime.now(timezone.utc) - timedelta(minutes=1)
    finished = datetime.now(timezone.utc)
    receipt = {
        "schema": "factory.runtime-coverage-run.v1",
        "runner": "local-powershell",
        "authentication": "UNAUTHENTICATED",
        "commit": commit,
        "dirty_tree": False,
        "command": LOCAL_COVERAGE_COMMAND,
        "exit_code": 0,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "source_code_sha256_before": code_hash,
        "source_code_sha256_after": code_hash,
        "test_code_sha256_before": digest_test_sources(tmp_path),
        "test_code_sha256_after": digest_test_sources(tmp_path),
        "environment": {
            "python": "Python 3.11.9",
            "pytest_plugin_autoload": "disabled",
            "pytest_cov": "7.0.0",
        },
        "artifacts": hashed_artifacts,
    }
    receipt_path = tmp_path / RECEIPT_PATH
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    observed = read_runtime_coverage_report(tmp_path)

    assert observed["candidate_binding"] == "LOCAL_SOURCE_HASH_MATCH"
    assert observed["receipt_status"] == "MATCHED_UNAUTHENTICATED"
    assert "unsigned" in observed["receipt_reason"]
    receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_data["finished_at"] = (
        datetime.now(timezone.utc) - timedelta(hours=25)
    ).isoformat()
    receipt_data["started_at"] = (
        datetime.now(timezone.utc) - timedelta(hours=25, minutes=1)
    ).isoformat()
    receipt_path.write_text(json.dumps(receipt_data), encoding="utf-8")
    stale = read_runtime_coverage_report(tmp_path)
    assert stale["candidate_binding"] == "UNBOUND"
    assert stale["receipt_status"] == "MISMATCHED"
    assert "older than 24 hours" in stale["receipt_reason"]
    receipt_data["finished_at"] = datetime.now(timezone.utc).isoformat()
    receipt_data["started_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()
    receipt_path.write_text(json.dumps(receipt_data), encoding="utf-8")
    target = tmp_path / "factoryline" / "demo.py"
    target.write_text(
        target.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8"
    )

    changed = read_runtime_coverage_report(tmp_path)

    assert changed["state"] == "OBSERVED"
    assert changed["candidate_binding"] == "UNBOUND"
    assert changed["receipt_status"] == "MISMATCHED"
    assert "current Python source" in changed["receipt_reason"]
