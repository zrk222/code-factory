from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from factoryline.adoption import (
    AdoptionError,
    adoption_status,
    export_adoption_status,
    proof_card_from_receipt,
    record_adoption_event,
    run_first_proof,
    run_repo_scan,
    verify_proof_card,
    write_proof_card,
)
from factoryline.cli import main


def test_first_proof_catches_the_deliberately_hollow_check_and_writes_a_private_card(
    tmp_path: Path,
) -> None:
    result = run_first_proof(
        tmp_path, observed_at=datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
    )

    assert result["activation"]["marker"] == "HOLLOW_TEST_DETECTED"
    assert result["proof"]["marker"] == "HOLLOW_E2E_TEST"
    assert result["proof_card"]["card"]["hollow_test_detected"] is True
    assert result["proof_card"]["card"]["negative_case_rejected"] is False
    assert Path(result["proof_card"]["paths"]["svg"]).is_file()
    assert result["adoption_status"]["milestones"] == {
        "first_proof_completed": 1,
        "proof_card_saved": 1,
        "proof_receipt_saved": 1,
        "seven_day_return": 0,
    }

    svg = Path(result["proof_card"]["paths"]["svg"]).read_text(encoding="utf-8")
    assert "HOLLOW_TEST_DETECTED" in svg
    assert str(tmp_path) not in svg
    assert "raise SystemExit" not in svg
    assert "local-first-proof-user" not in svg


def test_proof_card_reuses_only_verified_receipt_facts_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    first = run_first_proof(tmp_path)
    receipt_path = Path(first["proof_artifacts"]["paths"]["json"])
    result = proof_card_from_receipt(tmp_path, receipt_path, Path("share-again"))

    assert result["card"]["source_receipt_sha256"] == first["proof"]["receipt_sha256"]
    tampered = dict(result["card"])
    tampered["headline"] = "Everything is production ready"
    with pytest.raises(AdoptionError, match="hash does not match"):
        verify_proof_card(tampered)


def test_direct_proof_card_writer_exports_the_same_verified_receipt(tmp_path: Path):
    first = run_first_proof(tmp_path)
    saved = write_proof_card(first["proof"], tmp_path / "direct-card")
    assert saved["card"]["source_receipt_sha256"] == first["proof"]["receipt_sha256"]
    assert Path(saved["paths"]["json"]).is_file()
    assert Path(saved["paths"]["svg"]).is_file()


def test_local_adoption_funnel_withholds_provider_metrics_and_never_stores_identity(
    tmp_path: Path,
) -> None:
    observed = datetime(2026, 8, 1, tzinfo=timezone.utc)
    record_adoption_event(tmp_path, "first_proof_completed", observed_at=observed)
    record_adoption_event(
        tmp_path, "seven_day_return", observed_at=observed + timedelta(days=8)
    )
    exported = export_adoption_status(tmp_path, Path(".factory/public-adoption.json"))

    assert exported["status"]["funnel"]["page_visit"] is None
    assert exported["status"]["funnel"]["install"] is None
    assert exported["status"]["funnel"]["first_proof"] == 1
    assert exported["status"]["funnel"]["seven_day_return"] == 1
    serialized = json.dumps(exported, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "user_id" not in serialized
    assert "repository" not in serialized


def test_adoption_event_rejects_unknown_milestones_and_bad_evidence(
    tmp_path: Path,
) -> None:
    with pytest.raises(AdoptionError, match="milestone must be"):
        record_adoption_event(tmp_path, "clicked_everything")
    with pytest.raises(AdoptionError, match="lowercase SHA-256"):
        record_adoption_event(
            tmp_path, "proof_card_saved", evidence_sha256="not-a-digest"
        )


def test_first_proof_cli_is_successful_because_detection_is_the_demo_outcome(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["first-proof", "--root", str(tmp_path), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 0
    assert output["activation"]["demo"] is True
    assert output["activation"]["marker"] == "HOLLOW_TEST_DETECTED"
    assert output["activation"]["assessment"]["state"] == "INCOMPLETE"


def test_repo_scan_is_zero_config_and_fails_closed_without_project_contract(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    result = run_repo_scan(tmp_path)

    assert result["schema"] == "factory.repo-scan.v1"
    assert result["assessment"]["files_discovered"] == 1
    assert result["assessment"]["file_types"]["python"] == 1
    assert result["state"] == "INCOMPLETE"
    assert result["verdict"] == "INCOMPLETE"
    assert result["static_security"]["state"] == "NOT_RUN"
    assert any("tenant-read-contract" in action for action in result["next_actions"])


def test_repo_scan_cli_reports_a_real_workspace_assessment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "README.md").write_text("# sample\n", encoding="utf-8")
    assert main(["scan", "--root", str(tmp_path), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["assessment"]["files_discovered"] == 1
    assert output["verdict"] == "INCOMPLETE"


def test_repo_scan_deep_runs_static_lane_on_small_workspace(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    result = run_repo_scan(tmp_path, deep=True)

    assert result["static_security"]["state"] in {"CLEAN", "INCOMPLETE"}
    assert result["deep_audit"]["schema"] == "factory.deep-repository-audit.v1"
    assert result["deep_audit"]["scope"]["python_source_limit"] == 460
    lane_ids = {lane["measurement_id"] for lane in result["deep_audit"]["lanes"]}
    assert {
        "candidate_inventory",
        "python_ast_security",
        "scanner_self_evaluation",
        "runtime_coverage",
        "dependencies_and_supply_chain",
    } <= lane_ids
    assert result["deep_audit"]["state"] in {"INCOMPLETE", "BLOCKED"}


def test_repo_scan_deep_exposes_non_python_and_supply_chain_gaps(
    tmp_path: Path,
) -> None:
    (tmp_path / "package.json").write_text('{"name":"sample"}\n', encoding="utf-8")
    (tmp_path / "app.ts").write_text("export const value = 1;\n", encoding="utf-8")

    result = run_repo_scan(tmp_path, deep=True)
    lanes = {lane["measurement_id"]: lane for lane in result["deep_audit"]["lanes"]}

    assert lanes["python_ast_security"]["state"] == "NOT_APPLICABLE"
    assert lanes["non_python_security"]["state"] == "NOT_MEASURED"
    assert lanes["dependencies_and_supply_chain"]["state"] == "NOT_MEASURED"
    assert result["deep_audit"]["coverage"]["audit_rate"] < 1


def test_repo_scan_deep_blocks_when_python_limit_is_exceeded(tmp_path: Path) -> None:
    for index in range(461):
        (tmp_path / f"module_{index:03d}.py").write_text(
            "value = 1\n", encoding="utf-8"
        )

    result = run_repo_scan(tmp_path, deep=True)
    lanes = {lane["measurement_id"]: lane for lane in result["deep_audit"]["lanes"]}

    assert result["deep_audit"]["scope"]["python_source_limit"] == 460
    assert lanes["python_ast_security"]["state"] == "BLOCKED"
    assert (
        lanes["python_ast_security"]["result"]["audit_coverage"]["files_discovered"]
        == 461
    )
    assert result["deep_audit"]["state"] == "BLOCKED"


def test_adoption_cli_reports_local_counts_without_claiming_conversion(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "adoption",
                "record",
                "first_proof_completed",
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["adoption", "status", "--root", str(tmp_path), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)

    assert status["events"] == 1
    assert status["funnel"]["first_proof"] == 1
    assert status["measurement"] == "local_opt_in_events_only"


def test_adoption_status_fails_closed_for_a_tampered_event(tmp_path: Path) -> None:
    event = record_adoption_event(tmp_path, "first_proof_completed")
    path = Path(event["path"])
    value = json.loads(path.read_text(encoding="utf-8"))
    value["milestone"] = "seven_day_return"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(AdoptionError, match="malformed or tampered"):
        adoption_status(tmp_path)


def test_native_worker_configuration_requires_explicit_deep(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires --deep"):
        run_repo_scan(tmp_path, worker_config="worker.json")


def test_native_worker_configuration_rejects_unknown_fields(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("export const x = 1;", encoding="utf-8")
    (tmp_path / "worker.json").write_text('{"command":"arbitrary"}', encoding="utf-8")
    result = run_repo_scan(tmp_path, deep=True, worker_config="worker.json")
    lane = next(
        row
        for row in result["deep_audit"]["lanes"]
        if row["measurement_id"] == "native_worker_execution"
    )
    assert lane["state"] == "BLOCKED"
    assert str(tmp_path) not in json.dumps(lane)


def test_native_worker_executes_existing_engine_without_granting_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline import deep_audit

    (tmp_path / "app.rs").write_text("fn main() {}", encoding="utf-8")
    for name in ("manifest.json", "auth.json", "trust.json"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    settings = {
        "manifest": "manifest.json",
        "manifest_sha256": "a" * 64,
        "authorization": "auth.json",
        "trust_root": "trust.json",
        "trust_root_sha256": "b" * 64,
    }
    (tmp_path / "worker.json").write_text(json.dumps(settings), encoding="utf-8")
    calls = []

    def observe(*args, **kwargs):
        calls.append((args, kwargs))
        return {
            "state": "INCOMPLETE",
            "analysis_complete": True,
            "review": "REQUIRED",
            "run_id": "sample",
        }

    monkeypatch.setattr(deep_audit, "scan_deep_audit", observe)
    result = run_repo_scan(tmp_path, deep=True, worker_config="worker.json")
    lane = next(
        row
        for row in result["deep_audit"]["lanes"]
        if row["measurement_id"] == "native_worker_execution"
    )
    assert len(calls) == 1
    assert lane["measurement_state"] == "REVIEW_REQUIRED"
    assert result["state"] != "PASS"
    assert result["assessment"]["file_types"]["rust"] == 1
