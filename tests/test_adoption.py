from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


import pytest

from factoryline.adoption import (
    AdoptionError,
    _sha,
    _scan_identity_projection,
    adoption_status,
    export_adoption_status,
    proof_card_from_receipt,
    record_adoption_event,
    run_first_proof,
    run_deep_repository_audit,
    run_repo_scan,
    _repo_scan_state,
    _state_for_findings,
    _workspace_inventory,
    verify_proof_card,
    write_proof_card,
)
from factoryline.cli import main


def test_receipt_inventory_skips_stat_for_unmatched_files(tmp_path, monkeypatch):
    from factoryline.adoption import _receipt_inventory

    evidence = tmp_path / ".factory"
    evidence.mkdir()
    for index in range(100):
        (evidence / f"unrelated-{index}.log").write_text("unrelated")
    receipt = evidence / "native.sarif"
    receipt.write_text('{"schema":"native-control"}')
    original = Path.is_file
    inspected = []

    def tracked(path):
        inspected.append(path.name)
        return original(path)

    monkeypatch.setattr(Path, "is_file", tracked)
    result = _receipt_inventory(tmp_path, patterns=("*.sarif",))
    assert [row["path"] for row in result] == [".factory/native.sarif"]
    assert not any(name.startswith("unrelated-") for name in inspected)
    assert result[0]["verification"] == "PRESENT_UNVERIFIED"


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


def test_repo_scan_is_zero_config_without_inventing_tenant_contract_advice(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    result = run_repo_scan(tmp_path)

    assert result["schema"] == "factory.repo-scan.v1"
    assert result["assessment"]["files_discovered"] == 1
    assert result["assessment"]["file_types"]["python"] == 1
    assert result["state"] == "INCOMPLETE"
    assert result["verdict"] == "INCOMPLETE"
    assert result["static_security"]["state"] == "CLEAN"
    assert result["deep_audit"] is not None
    assert any(
        lane["measurement_id"] == "native_worker_execution"
        for lane in result["deep_audit"]["lanes"]
    )
    assert not any(
        "tenant-read-contract" in action for action in result["next_actions"]
    )


def test_repo_scan_identity_is_stable_and_run_receipt_binds_telemetry(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    first = run_repo_scan(tmp_path)
    second = run_repo_scan(tmp_path)

    assert first["scan_sha256"] == second["scan_sha256"]
    assert first["run_receipt_sha256"] != second["run_receipt_sha256"]
    for result in (first, second):
        receipt = {
            key: value for key, value in result.items() if key != "run_receipt_sha256"
        }
        assert result["run_receipt_sha256"] == _sha(receipt)
        assert result["deep_audit"]["telemetry"]["trace_id"]
        assert result["deep_audit"]["audit_sha256"]


def test_repo_scan_phase_telemetry_preserves_source_and_no_source_results(tmp_path):
    from factoryline.ops_telemetry import _phase_telemetry

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    expected = run_repo_scan(tmp_path, deep=False)
    with _phase_telemetry(0) as telemetry:
        observed = run_repo_scan(tmp_path, deep=False)
    assert observed["scan_sha256"] == expected["scan_sha256"]
    phases = {phase["phase"]: phase for phase in telemetry.snapshot()["phases"]}
    assert phases["source_inventory"]["completed"] == 1
    assert phases["source_audit"]["completed"] == 1
    assert str(tmp_path) not in json.dumps(telemetry.snapshot())

    empty = tmp_path / "empty"
    empty.mkdir()
    with _phase_telemetry(0) as telemetry:
        no_sources = run_repo_scan(empty, deep=False)
    assert no_sources["static_security"]["state"] == "NO_SOURCES"
    assert no_sources["state"] == "INCOMPLETE"
    phases = {phase["phase"]: phase for phase in telemetry.snapshot()["phases"]}
    assert phases["source_inventory"]["completed"] == 1
    assert phases["source_audit"]["completed"] == 1


def test_repo_scan_inventory_phase_error_is_re_raised_without_error_text(
    tmp_path, monkeypatch
):
    from factoryline import adoption
    from factoryline.ops_telemetry import _phase_telemetry

    def fail_inventory(*args, **kwargs):
        raise RuntimeError("PRIVATE SOURCE PATH")

    monkeypatch.setattr(adoption, "_workspace_inventory", fail_inventory)
    with _phase_telemetry(0) as telemetry:
        with pytest.raises(RuntimeError, match="PRIVATE SOURCE PATH"):
            run_repo_scan(tmp_path, deep=False)
    snapshot = telemetry.snapshot()
    assert snapshot["status"] == "incomplete"
    assert snapshot["phases"] == [
        {
            "phase": "source_inventory",
            "elapsed_ms": snapshot["phases"][0]["elapsed_ms"],
            "calls": 1,
            "completed": 0,
            "incomplete": 1,
        }
    ]
    assert "PRIVATE SOURCE PATH" not in json.dumps(snapshot)


def test_repo_scan_identity_changes_when_source_finding_changes(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    clean = run_repo_scan(tmp_path, deep=False)

    source.write_text("def execute(value):\n    return eval(value)\n", encoding="utf-8")
    finding = run_repo_scan(tmp_path, deep=False)

    assert clean["scan_sha256"] != finding["scan_sha256"]
    assert (
        clean["static_security"]["findings"] != finding["static_security"]["findings"]
    )
    assert finding["run_receipt_sha256"] == _sha(
        {key: value for key, value in finding.items() if key != "run_receipt_sha256"}
    )


def test_scan_identity_projection_drops_run_envelopes_but_keeps_semantic_fields():
    def run_result(run_id, event_hash, action_id):
        return {
            "run_id": run_id,
            "parent_run": "parent-" + run_id,
            "sequence": 12,
            "event_sha256": event_hash,
            "updated_at": "2026-10-15T10:00:00Z",
            "review_evidence": {
                "packet_sha256": "stable-packet-hash",
                "evidence": [{"id": "evidence-1", "provenance": {"sha256": "1" * 64}}],
                "claims": [{"id": "claim-1", "text": "observed"}],
            },
            "review_evidence_path": ".factory/analysis-evidence/" + run_id,
            "action_enrollment": {
                "actions_sha256": event_hash,
                "actions": [{"run_id": run_id, "action_id": action_id}],
            },
            "lanes": [{"action_id": action_id}],
            "findings": [{"run_id": "source-finding-id", "code": "RULE_X"}],
        }

    def report(run_id, event_hash, action_id):
        return {
            "deep_audit": {
                "audit_sha256": event_hash,
                "telemetry": {"trace_id": run_id},
                "lanes": [
                    {
                        "measurement_id": "native_worker_execution",
                        "result": run_result(run_id, event_hash, action_id),
                    },
                    {
                        "measurement_id": "other_lane",
                        "result": {
                            "candidate_sha256": "c" * 64,
                            "config_sha256": "f" * 64,
                            "findings": [
                                {
                                    "code": "RULE_X",
                                    "severity": "HIGH",
                                    "duration_ms": 12,
                                    "timestamp": "2026-10-15T10:00:00Z",
                                    "sha256": "1" * 64,
                                }
                            ],
                        },
                    },
                ],
                "native_domains": {
                    "domains": [{"result": {"run_id": run_id}}],
                    "findings": [{"run_id": run_id, "code": "RULE_X"}],
                },
            }
        }

    first = report("run-one", "a" * 64, "action-one")
    second = report("run-two", "b" * 64, "action-two")
    assert _scan_identity_projection(first) == _scan_identity_projection(second)

    result_finding = second["deep_audit"]["lanes"][0]["result"]["findings"][0]
    result_finding["run_id"] = "different-source-value"
    assert _scan_identity_projection(first) != _scan_identity_projection(second)
    result_finding["run_id"] = "source-finding-id"

    review_evidence = second["deep_audit"]["lanes"][0]["result"]["review_evidence"]
    for key, changed in (
        ("claims", [{"id": "claim-2", "text": "changed"}]),
        ("evidence", [{"id": "evidence-2", "provenance": {"sha256": "2" * 64}}]),
        ("packet_sha256", "changed-packet-hash"),
    ):
        original = review_evidence[key]
        review_evidence[key] = changed
        assert _scan_identity_projection(first) != _scan_identity_projection(second)
        review_evidence[key] = original

    deterministic = second["deep_audit"]["lanes"][1]["result"]
    deterministic["config_sha256"] = "0" * 64
    assert _scan_identity_projection(first) != _scan_identity_projection(second)
    deterministic["config_sha256"] = "f" * 64
    finding = deterministic["findings"][0]
    for key, value in (
        ("severity", "CRITICAL"),
        ("duration_ms", 13),
        ("timestamp", "2026-10-15T10:00:01Z"),
        ("sha256", "2" * 64),
    ):
        finding[key] = value
        assert _scan_identity_projection(first) != _scan_identity_projection(second)
        finding[key] = {
            "severity": "HIGH",
            "duration_ms": 12,
            "timestamp": "2026-10-15T10:00:00Z",
            "sha256": "1" * 64,
        }[key]


def test_repo_scan_native_trace_covers_every_reported_lane(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    result = run_repo_scan(tmp_path)
    audit = result["deep_audit"]
    spans = audit["telemetry"]["spans"]
    roots = [span for span in spans if span["parent_span_id"] is None]
    assert len(roots) == 1
    by_id = {span["span_id"]: span for span in spans}
    assert all(span["parent_span_id"] in by_id for span in spans if span not in roots)
    observed = {
        span["name"]: span
        for span in spans
        if span["attributes"].get("kind") == "lane_result_observation"
    }
    assert set(observed) == {row["measurement_id"] for row in audit["lanes"]}
    assert all(
        len(span["attributes"]["result_sha256"]) == 64 for span in observed.values()
    )


def test_repo_scan_native_trace_preserves_analyzer_failure_without_raw_error(
    tmp_path, monkeypatch
):
    from factoryline import adoption

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    def failed(*args):
        raise RuntimeError("PRIVATE ERROR CONTENT")

    monkeypatch.setattr(adoption, "_architecture_health_lane", failed)
    result = run_repo_scan(tmp_path)
    spans = result["deep_audit"]["telemetry"]["spans"]
    assert any(
        span["name"] == "architecture" and span["status"] == "ERROR" for span in spans
    )
    assert result["state"] == "BLOCKED"
    assert "PRIVATE ERROR CONTENT" not in json.dumps(result)


def test_repo_scan_recommends_tenant_contract_for_observed_orm_reads(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from sqlalchemy.orm import Session\n"
        "def users(session: Session):\n"
        "    return session.query(User).all()\n",
        encoding="utf-8",
    )
    result = run_repo_scan(tmp_path)
    assert any(
        finding["code"] == "SECURITY_TENANT_READ_UNDECLARED"
        for finding in result["static_security"]["findings"]
    )
    assert any("tenant-read-contract" in action for action in result["next_actions"])


@pytest.mark.parametrize("deep", [False, True])
@pytest.mark.parametrize(
    "options",
    [
        {"oracle_evidence": "evidence.json"},
        {"unexpected": "value"},
        {
            "oracle_evidence": "x",
            "oracle_trust_root": "x",
            "oracle_trust_sha256": "x",
            "oracle_environment_sha256": "",
        },
    ],
)
def test_unified_scan_rejects_partial_oracle_options(tmp_path, deep, options):
    (tmp_path / "app.py").write_text("value = 1\n")
    with pytest.raises(ValueError, match="all four"):
        run_repo_scan(tmp_path, deep=deep, oracle_options=options)


def test_unified_scan_rejects_unused_evidence_without_python(tmp_path):
    from factoryline.adoption import _validated_oracle_options

    options = {
        name: "value"
        for name in (
            "oracle_evidence",
            "oracle_trust_root",
            "oracle_trust_sha256",
            "oracle_environment_sha256",
        )
    }
    assert _validated_oracle_options(None, 0) == {}
    assert _validated_oracle_options(options, 1) == options
    with pytest.raises(ValueError, match="Python sources"):
        run_repo_scan(tmp_path, oracle_options=options)
    with pytest.raises(ValueError, match="Python sources"):
        run_deep_repository_audit(
            tmp_path, _workspace_inventory(tmp_path), oracle_options=options
        )


@pytest.mark.parametrize("deep", [False, True])
def test_unified_scan_cli_partial_evidence_is_invalid(tmp_path, capsys, deep):
    (tmp_path / "app.py").write_text("value = 1\n")
    command = [
        "scan",
        "--root",
        str(tmp_path),
        "--json",
        "--oracle-evidence",
        "missing.json",
    ]
    if deep:
        command.append("--deep")
    assert main(command) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "INVALID"
    assert "all four" in result["message"]


@pytest.mark.parametrize("deep", [False, True])
def test_unified_scan_invalid_signed_evidence_cannot_clear_findings(tmp_path, deep):
    (tmp_path / "test_app.py").write_text("def test_behavior():\n    validate(1)\n")
    options = {
        "oracle_evidence": "missing.json",
        "oracle_trust_root": "missing-trust.json",
        "oracle_trust_sha256": "0" * 64,
        "oracle_environment_sha256": "1" * 64,
    }
    result = run_repo_scan(tmp_path, deep=deep, oracle_options=options)
    assert result["state"] == "BLOCKED"
    assert result["static_security"]["state"] == "INVALID"


@pytest.mark.parametrize("deep", [False, True])
def test_unified_scan_limit_reports_requested_but_unused_oracles(tmp_path, deep):
    for index in range(461):
        (tmp_path / f"source_{index}.py").write_text("value = 1\n")
    options = {
        "oracle_evidence": "missing.json",
        "oracle_trust_root": "missing-trust.json",
        "oracle_trust_sha256": "0" * 64,
        "oracle_environment_sha256": "1" * 64,
    }
    result = run_repo_scan(tmp_path, deep=deep, oracle_options=options)
    assert result["state"] == "BLOCKED"
    oracle = result["static_security"]["runtime_oracles"]
    assert oracle["state"] == "NOT_VERIFIED"
    assert oracle["reason"] == "SOURCE_LIMIT_EXCEEDED"
    assert oracle["requested"] is True
    assert oracle["reconciled_count"] == 0
    assert oracle["reconciled"] == []


def test_repo_scan_cli_reports_a_real_workspace_assessment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "README.md").write_text("# sample\n", encoding="utf-8")
    assert main(["scan", "--root", str(tmp_path), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["assessment"]["files_discovered"] == 1
    assert output["verdict"] == "INCOMPLETE"
    assert output["static_security"]["state"] == "NO_SOURCES"


def test_default_repo_scan_reads_python_and_keeps_quality_findings_advisory(
    tmp_path: Path,
) -> None:
    (tmp_path / "test_app.py").write_text("def test_behavior():\n    assert True\n")
    result = run_repo_scan(tmp_path)
    assert result["static_security"]["state"] == "FINDINGS"
    assert result["static_security"]["findings"][0]["code"] == "QUALITY_HOLLOW_TEST"
    assert result["state"] == "INCOMPLETE"
    assert result["verdict"] == "INCOMPLETE"


def test_default_repo_scan_blocks_high_severity_security_findings(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("def execute(value):\n    eval(value)\n")
    result = run_repo_scan(tmp_path)
    assert result["static_security"]["state"] == "BLOCKED"
    assert result["state"] == "BLOCKED"
    assert result["verdict"] == "BLOCKED"


def test_repo_scan_deep_runs_static_lane_on_small_workspace(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    inventory = _workspace_inventory(tmp_path)
    result = run_deep_repository_audit(tmp_path, inventory)

    assert result["schema"] == "factory.deep-repository-audit.v1"
    assert result["scope"]["python_source_limit"] == 460
    lane_ids = {lane["measurement_id"] for lane in result["lanes"]}
    assert {
        "candidate_inventory",
        "python_ast_security",
        "scanner_self_evaluation",
        "runtime_coverage",
        "dependencies_and_supply_chain",
    } <= lane_ids
    assert result["state"] in {"INCOMPLETE", "BLOCKED"}


def test_repo_scan_deep_quality_only_finding_is_advisory(tmp_path: Path) -> None:
    (tmp_path / "test_behavior.py").write_text(
        "def test_behavior():\n    assert True\n"
    )
    result = run_repo_scan(tmp_path, deep=True)
    lanes = {lane["measurement_id"]: lane for lane in result["deep_audit"]["lanes"]}
    lane = lanes["python_ast_security"]
    assert lane["result"]["state"] == "FINDINGS"
    assert lane["state"] == "REVIEW_REQUIRED"
    assert lane["measurement_state"] == "REVIEW_REQUIRED"
    assert result["deep_audit"]["state"] != "BLOCKED"


def test_repo_scan_deep_high_severity_security_pattern_blocks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def execute(value):\n    eval(value)\n")
    result = run_repo_scan(tmp_path, deep=True)
    lanes = {lane["measurement_id"]: lane for lane in result["deep_audit"]["lanes"]}
    assert lanes["python_ast_security"]["result"]["state"] == "BLOCKED"
    assert lanes["python_ast_security"]["measurement_state"] == "BLOCKED"
    assert result["deep_audit"]["state"] == "BLOCKED"


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


@pytest.mark.parametrize(
    "finding",
    [
        {"code": "QUALITY_HOLLOW_TEST", "severity": "MEDIUM"},
        {"code": "SECURITY_PATTERN", "severity": "LOW"},
    ],
)
def test_findings_require_review_without_claiming_a_security_block(finding):
    result = {"state": "FINDINGS", "findings": [finding]}
    assert _state_for_findings(result, advisory_findings=True) == "REVIEW_REQUIRED"


def test_security_block_and_invalid_analysis_remain_blocked():
    assert (
        _state_for_findings({"state": "BLOCKED", "findings": [{"severity": "HIGH"}]})
        == "BLOCKED"
    )
    assert _state_for_findings({"state": "INVALID", "findings": []}) == "BLOCKED"


def test_repo_scan_advisory_findings_require_review_but_security_state_blocks():
    inventory = {"files_discovered": 1}
    assert _repo_scan_state(
        None,
        {"state": "FINDINGS", "findings": [{"severity": "MEDIUM"}]},
        True,
        inventory,
    ) == ("INCOMPLETE", "INCOMPLETE")
    assert _repo_scan_state(
        None,
        {"state": "BLOCKED", "findings": [{"severity": "HIGH"}]},
        True,
        inventory,
    ) == ("BLOCKED", "BLOCKED")


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
        run_repo_scan(tmp_path, deep=False, worker_config="worker.json")


def test_repo_scan_static_only_does_not_discover_or_execute_workers(tmp_path, capsys):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory/native-worker-config.json").write_text("{}")
    assert main(["scan", "--static-only", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["deep_audit"] is None
    assert result["static_security"]["state"] == "CLEAN"


def test_native_worker_discovery_rejects_unsigned_or_malformed_configuration(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory/native-worker-config.json").write_text("{}")
    result = run_repo_scan(tmp_path)
    lane = next(
        row
        for row in result["deep_audit"]["lanes"]
        if row["measurement_id"] == "native_worker_execution"
    )
    assert lane["state"] == "BLOCKED"
    assert result["state"] == "BLOCKED"


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


@pytest.mark.parametrize("discover", [False, True])
def test_native_worker_executes_existing_engine_without_granting_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, discover: bool
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
    if discover:
        (tmp_path / ".factory").mkdir()
        (tmp_path / ".factory/native-worker-config.json").write_text(
            json.dumps(settings), encoding="utf-8"
        )
    calls = []

    def observe(*args, **kwargs):
        calls.append((args, kwargs))
        return {
            "state": "INCOMPLETE",
            "analysis_complete": True,
            "review": "REQUIRED",
            "run_id": "sample",
            "candidate_sha256": "c" * 64,
            "lanes": [
                {
                    "family": family,
                    "engine": "bounded-scanner",
                    "state": "OBSERVED",
                    "gaps": [],
                    "findings": [],
                }
                for family in (
                    "static",
                    "secrets",
                    "configuration",
                    "dependencies",
                    "runtime",
                    "fuzz",
                )
            ],
        }

    monkeypatch.setattr(deep_audit, "scan_deep_audit", observe)
    result = (
        run_repo_scan(tmp_path)
        if discover
        else run_repo_scan(tmp_path, deep=True, worker_config="worker.json")
    )
    lane = next(
        row
        for row in result["deep_audit"]["lanes"]
        if row["measurement_id"] == "native_worker_execution"
    )
    assert len(calls) == 1
    assert lane["measurement_state"] == "REVIEW_REQUIRED"
    assert result["state"] != "PASS"
    assert result["assessment"]["file_types"]["rust"] == 1
    domains = result["deep_audit"]["native_domains"]["domains"]
    assert len(domains) == 6
    assert all(row["state"] == "REVIEW_REQUIRED" for row in domains)
    assert all(row["result"]["candidate_sha256"] == "c" * 64 for row in domains)


@pytest.mark.parametrize(
    "family", ["static", "secrets", "configuration", "dependencies", "runtime", "fuzz"]
)
@pytest.mark.parametrize("worker_state", ["OBSERVED", "INCOMPLETE"])
def test_native_domains_preserve_scoped_evidence(family, worker_state):
    from factoryline.adoption import _native_domain_projection

    worker = {
        "lane_id": "bounded-worker",
        "engine": "scanner",
        "family": family,
        "state": worker_state,
        "gaps": [] if worker_state == "OBSERVED" else ["MUTATION_SURVIVED"],
        "report_sha256": "a" * 64,
        "coverage_sha256": "b" * 64,
        "challenge_sha256": "c" * 64,
        "covered_paths": ["app.ts"],
        "obligations": ["security-boundary"],
        "findings": [
            {
                "finding_id": "finding",
                "path": "app.ts",
                "line": 4,
                "remediation": "Repair the boundary",
                "source_sha256": "d" * 64,
            }
        ],
    }
    lanes = [
        {
            "measurement_id": "native_worker_execution",
            "result": {
                "run_id": "run",
                "candidate_sha256": "e" * 64,
                "manifest_sha256": "f" * 64,
                "lanes": [worker],
                "gaps": [],
            },
        },
        {
            "measurement_id": "dependencies_and_supply_chain",
            "state": "NOT_MEASURED",
            "result": {},
        },
        {"measurement_id": "runtime_coverage", "state": "NOT_MEASURED", "result": {}},
    ]
    report = _native_domain_projection(lanes)
    domain = next(
        row for row in report["domains"] if row["measurement_id"] == "native_" + family
    )
    assert domain["state"] == (
        "REVIEW_REQUIRED" if worker_state == "OBSERVED" else "INCOMPLETE"
    )
    assert domain["result"]["workers"] == [worker]
    assert domain["result"]["candidate_sha256"] == "e" * 64
    assert report["findings"][0]["remediation"] == "Repair the boundary"
    assert report["findings"][0]["engine"] == "scanner"
    assert report["authority"] == "none"
    assert all(row["state"] == "NOT_RUN" for row in report["domains"] if row != domain)
    assert lanes[1]["state"] == lanes[2]["state"] == "NOT_MEASURED"


@pytest.mark.parametrize(
    "drift", ["SOURCE_CHANGED_DURING_RUN", "CANDIDATE_DRIFT", "SNAPSHOT_DRIFT"]
)
def test_native_domains_do_not_promote_stale_or_partial_workers(drift):
    from factoryline.adoption import _native_domain_projection

    lanes = [
        {
            "measurement_id": "native_worker_execution",
            "result": {
                "lanes": [
                    {
                        "family": "static",
                        "engine": "scanner",
                        "state": "OBSERVED",
                        "gaps": [],
                    }
                ],
                "gaps": [{"code": drift}],
            },
        },
        {"measurement_id": "dependencies_and_supply_chain", "result": {}},
        {"measurement_id": "runtime_coverage", "result": {}},
    ]
    report = _native_domain_projection(lanes)
    assert report["domains"][0]["state"] == "INCOMPLETE"
    assert report["domains"][0]["result"]["observed_workers"] == 0
    assert report["domains"][0]["result"]["source_current"] is False
    lanes[0]["result"]["gaps"] = []
    lanes[0]["result"]["lanes"].append(
        {"family": "static", "state": "INCOMPLETE", "gaps": ["coverage"]}
    )
    assert _native_domain_projection(lanes)["domains"][0]["state"] == "INCOMPLETE"
