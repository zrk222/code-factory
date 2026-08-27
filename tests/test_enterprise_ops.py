from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.enterprise_ops import (
    EnterpriseOpsError,
    evaluate_required_checks,
    evaluate_sla,
    export_evidence,
    export_otel,
    initialize_workspace,
    outcome_summary,
    provision_identity,
    put_evidence,
    record_outcome,
    run_proof,
    verify_workspace,
    workspace_status,
)


def _init(tmp_path: Path) -> Path:
    initialize_workspace(tmp_path, "acme", "owner@example.com")
    return tmp_path


def test_workspace_identity_and_evidence_are_tenant_bound(tmp_path: Path):
    root = _init(tmp_path)
    provision_identity(root, "acme", "operator@example.com", "operator", actor="owner@example.com")
    evidence = put_evidence(root, "acme", "operator@example.com", {"schema": "factory.test.v1", "tenant_id": "acme", "verdict": "PASS"})
    assert evidence["marker"] == "EVIDENCE_RECORDED"
    assert evidence["eops_marker"] == "EOPS_EVIDENCE_READY"
    assert verify_workspace(root)["eops_marker"] == "EOPS_EVIDENCE_READY"
    assert verify_workspace(root)["valid"] is True
    with pytest.raises(EnterpriseOpsError, match="tenant"):
        put_evidence(root, "other", "operator@example.com", {"schema": "factory.test.v1", "tenant_id": "other"})


def test_suspended_identity_is_denied_before_mutation(tmp_path: Path):
    root = _init(tmp_path)
    provision_identity(root, "acme", "operator@example.com", "operator", actor="owner@example.com", status="suspended")
    with pytest.raises(EnterpriseOpsError) as error:
        put_evidence(root, "acme", "operator@example.com", {"schema": "factory.test.v1", "tenant_id": "acme"})
    assert error.value.code == "E_IDENTITY_INACTIVE"
    assert verify_workspace(root)["evidence"] == 0


def test_evidence_tamper_is_detected(tmp_path: Path):
    root = _init(tmp_path)
    put_evidence(root, "acme", "owner@example.com", {"schema": "factory.test.v1", "tenant_id": "acme", "verdict": "PASS"})
    db = root / ".factory" / "ops" / "evidence.db"
    import sqlite3
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE evidence SET payload_json = ?", ('{"schema":"factory.test.v1","tenant_id":"acme","verdict":"FAIL"}',))
    result = verify_workspace(root)
    assert result["marker"] == "OPS_WORKSPACE_TAMPERED"
    assert any("payload hash mismatch" in item for item in result["errors"])


def test_process_runner_requires_explicit_boundary_and_is_labelled(tmp_path: Path):
    root = _init(tmp_path)
    with pytest.raises(EnterpriseOpsError) as error:
        run_proof(root, ["python", "-c", "print('ok')"], backend="process")
    assert error.value.code == "E_RUNNER_ISOLATION_REQUIRED"
    receipt = run_proof(root, ["python", "-c", "print('ok')"], backend="process", allow_process_boundary=True)
    assert receipt["marker"] == "RUNNER_NOT_ISOLATED"
    assert receipt["eops_marker"] == "EOPS_RUNNER_READY"
    assert receipt["status"] == "passed"
    assert receipt["authority"]["deploy"] is False


def test_docker_unavailable_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    root = _init(tmp_path)
    monkeypatch.setattr("factoryline.enterprise_ops.shutil.which", lambda name: None)
    with pytest.raises(EnterpriseOpsError) as error:
        run_proof(root, ["python", "-c", "print('ok')"], backend="docker")
    assert error.value.code == "E_RUNNER_BACKEND_UNAVAILABLE"


def test_required_checks_report_missing_and_ready(tmp_path: Path):
    root = _init(tmp_path)
    changed = root / "src.py"
    changed.write_text("print('x')", encoding="utf-8")
    missing = evaluate_required_checks(root, ["src.py"])
    assert missing["decision"] == "REVIEW_REQUIRED"
    assert missing["eops_marker"] == "EOPS_CHECK_READY"
    receipt = root / "receipt.json"
    receipt.write_text(json.dumps({"verified": True, "changed_paths": ["src.py"], "created_at": "2999-01-01T00:00:00+00:00"}), encoding="utf-8")
    ready = evaluate_required_checks(root, ["src.py"], proof_receipts=[str(receipt)])
    assert ready["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert ready["authority"]["merge"] is False


def test_outcomes_are_hash_linked_and_otel_export_is_metadata_only(tmp_path: Path):
    root = _init(tmp_path)
    record_outcome(root, "acme", "owner@example.com", service="api", environment="prod", result="deployed", duration_ms=42, deployed=True)
    record_outcome(root, "acme", "owner@example.com", service="api", environment="prod", result="rolled_back", duration_ms=12, rollback=True)
    summary = outcome_summary(root)
    assert summary["integrity"]["valid"] is True
    assert summary["deployments"] == 1
    assert summary["rollbacks"] == 1
    assert record_outcome(root, "acme", "owner@example.com", service="api", environment="prod", result="success", duration_ms=1)["eops_marker"] == "EOPS_OUTCOME_READY"
    exported = export_otel(root, root / "otel.json")
    assert exported["events"] == 3
    assert "prompts" in exported["disclosure"]


def test_sla_requires_all_seven_explicit_gates(tmp_path: Path):
    root = _init(tmp_path)
    proposed = evaluate_sla(root)
    assert proposed["status"] == "PROPOSED"
    assert proposed["eops_marker"] == "EOPS_SLA_READY"
    assert len(proposed["missing_gates"]) == 7
    manifest = {"gates": {name: {"verified": True, "evidence": f"receipt-{name}"} for name in proposed["gates"]}}
    manifest["gates"]["signed_acceptance"]["signature_sha256"] = "a" * 64
    path = tmp_path / "sla.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    ready = evaluate_sla(root, path)
    assert ready["status"] == "READY_FOR_CONTRACT"
    assert ready["active"] is False


def test_export_and_status_keep_authority_explicit(tmp_path: Path):
    root = _init(tmp_path)
    output = export_evidence(root, tmp_path / "evidence-export.json")
    assert output["marker"] == "OPS_EXPORT_WRITTEN"
    status = workspace_status(root)
    assert status["marker"] == "OPS_STATUS_READY"
    assert status["eops_marker"] == "EOPS_GOLDEN_READY"
    assert set(status["markers"]) == {
        "EOPS_EVIDENCE_READY",
        "EOPS_IDENTITY_READY",
        "EOPS_RUNNER_READY",
        "EOPS_CHECK_READY",
        "EOPS_OUTCOME_READY",
        "EOPS_SLA_READY",
        "EOPS_GOLDEN_READY",
    }
    assert status["checks"]["decision"] == "NOT_EVALUATED"
    assert status["authority"]["merge"] is False
    assert status["authority"]["sla_activation"] is False
