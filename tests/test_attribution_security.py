"""Behavior-focused tests for security and admission APIs with weak attribution."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from factoryline.appforge_mobile_evidence import verify_mobile_evidence_receipt
from factoryline.appforge_quality_audit import quality_audit_projection
from factoryline.assurance import policy_mutations
from factoryline.capability_packs import pack_payload, sign_pack
from factoryline.counterexample import (
    CounterexampleError,
    validate_counterexample_source,
)
from factoryline.e2e_proof import run_supervised_command
from factoryline.first_lap import (
    verify_activation_receipt,
    verify_promoted_incident_gates,
)
from factoryline.github_proof_review import (
    GitHubProofReviewError,
    validate_github_proof_review_payload,
)
from factoryline.guardrails import GuardrailError, validate_guardrail_manifest
from factoryline.oracle_firewall import (
    OracleFirewallError,
    admission_oracle_decision,
    oracle_incidents_for_agent,
)
from factoryline.plan_proof_review import (
    PlanProofReviewError,
    validate_plan_proof_review,
)
from factoryline.repair_sandbox import (
    RepairSandboxError,
    validate_repair_scope_envelope,
)
from factoryline.runtime_audit_common import RuntimeAuditError
from factoryline.runtime_audit_integrity import validate_receipt_decision
from factoryline.runtime_audit_policy import validate_lane_policy
from factoryline.supply_chain import SupplyChainError, validate_attestation


def test_runtime_receipt_decision_rejects_incomplete_lanes() -> None:
    with pytest.raises(RuntimeAuditError) as error:
        validate_receipt_decision({})

    assert error.value.code == "E_RECEIPT_LANES"


def test_lane_policy_rejects_unknown_kind_before_execution() -> None:
    with pytest.raises(RuntimeAuditError) as error:
        validate_lane_policy("unrecognized", {})

    assert error.value.code == "E_LANES"


def test_counterexample_source_requires_exact_schema() -> None:
    with pytest.raises(CounterexampleError) as error:
        validate_counterexample_source({"schema": "wrong", "requirements": []})

    assert error.value.code == "COUNTEREXAMPLE_SOURCE_INVALID"


def test_guardrail_manifest_rejects_missing_scope_and_identity() -> None:
    with pytest.raises(GuardrailError) as error:
        validate_guardrail_manifest({"schema": "factory.guardrails.v1"})

    assert error.value.code == "GUARDRAIL_MANIFEST_INVALID"


def test_repair_scope_envelope_rejects_unsealed_empty_scope() -> None:
    with pytest.raises(RepairSandboxError) as error:
        validate_repair_scope_envelope({})

    assert error.value.code == "REPAIR_SCOPE_INVALID"
    assert "scope is missing required fields" in str(error.value)


def test_github_proof_review_payload_rejects_unbound_delivery_fields() -> None:
    with pytest.raises(GitHubProofReviewError) as error:
        validate_github_proof_review_payload({})

    assert error.value.code == "GITHUB_PROOF_REVIEW_INPUT_INVALID"


def test_plan_proof_review_requires_canonical_schema() -> None:
    with pytest.raises(PlanProofReviewError) as error:
        validate_plan_proof_review({"schema": "untrusted"})

    assert error.value.code == "PLAN_TO_PROOF_REVIEW_INVALID"


def test_oracle_incident_projection_is_empty_for_unmatched_identity(
    tmp_path: Path,
) -> None:
    result = oracle_incidents_for_agent(
        tmp_path,
        {"subject": "agent:reviewer", "identity_sha256": "a" * 64},
    )

    assert result == []


def test_oracle_admission_pauses_when_contract_is_missing(tmp_path: Path) -> None:
    with pytest.raises(OracleFirewallError) as error:
        admission_oracle_decision(
            tmp_path, tmp_path / "missing-contract.json", "supervised", []
        )

    assert error.value.code == "ORACLE_ADMISSION_PAUSED"


def test_promoted_incident_gate_reports_verified_empty_state_without_authority(
    tmp_path: Path,
) -> None:
    result = verify_promoted_incident_gates(tmp_path)

    assert result["state"] == "VERIFIED"
    assert result["verified"] == []
    assert result["invalid"] == []
    assert result["authority"] == "none"


def test_activation_receipt_fails_closed_when_absent(tmp_path: Path) -> None:
    result = verify_activation_receipt(tmp_path)

    assert result["state"] == "BLOCKED"
    assert result["code"] == "E_FIRST_LAP_ACTIVATION_MISSING"
    assert result["authority"] == "none"


def test_policy_mutations_cover_delete_and_boolean_inversion() -> None:
    mutations = policy_mutations({"rules": [{"id": "tenant-check", "enabled": True}]})

    assert {item["mutation"]["kind"] for item in mutations} == {"delete", "invert"}
    assert {item["mutation"]["rule_id"] for item in mutations} == {"tenant-check"}


def test_supply_chain_attestation_rejects_incomplete_manifest(tmp_path: Path) -> None:
    with pytest.raises(SupplyChainError) as error:
        validate_attestation(tmp_path, {})

    assert error.value.code == "E_FIELDS"


def test_capability_pack_payload_hashes_pack_files(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir()
    manifest_path = pack_root / "pack.yaml"
    manifest_path.write_text(
        json.dumps({"id": "sample", "version": "1.2.3"}), encoding="utf-8"
    )

    payload = pack_payload(pack_root)

    assert payload["schema"] == "factory.capability_pack.payload.v1"
    assert payload["pack_id"] == "sample"
    assert payload["version"] == "1.2.3"
    assert (
        payload["files"]["pack.yaml"]
        == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    )


def test_capability_pack_signing_writes_dsse_for_canonical_payload(
    tmp_path: Path,
) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir()
    (pack_root / "pack.yaml").write_text(
        json.dumps({"id": "signed-sample", "version": "2.0.0"}), encoding="utf-8"
    )
    private_key_path = tmp_path / "signing-key.pem"
    private_key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    result = sign_pack(
        pack_root,
        private_key_path,
        keyid="test-key",
        identity="test-suite",
        issuer="local-test",
    )

    envelope_path = pack_root / "pack.signature.json"
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    assert Path(result["path"]) == envelope_path.resolve()
    assert (
        result["payload_sha256"]
        == hashlib.sha256(
            json.dumps(
                pack_payload(pack_root), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
    )
    assert envelope["payloadType"] == "application/vnd.factory.capability-pack.v1+json"
    assert envelope["signatures"][0]["keyid"] == "test-key"


def test_mobile_evidence_verifier_reports_missing_receipt_for_review(
    tmp_path: Path,
) -> None:
    result = verify_mobile_evidence_receipt(tmp_path, tmp_path / "missing.json")

    assert result["ok"] is False
    assert result["marker"] == "APPFORGE_MOBILE_EVIDENCE_REVIEW_REQUIRED"
    assert result["reason"] == "input must be a regular workspace file"


def test_supervised_command_returns_exit_and_output_digests(tmp_path: Path) -> None:
    result = run_supervised_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('supervised-ok')"],
        cwd=tmp_path,
        timeout_seconds=5,
    )

    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["launch_error"] is False
    assert result["stdout_sha256"] == hashlib.sha256(b"supervised-ok").hexdigest()
    assert result["stderr_sha256"] == hashlib.sha256(b"").hexdigest()


def test_quality_audit_projection_returns_empty_read_only_state(tmp_path: Path) -> None:
    result = quality_audit_projection(tmp_path)

    assert result["marker"] == "APPFORGE_QUALITY_AUDIT_READ_ONLY"
    assert result["current_count"] == 0
    assert result["invalid_count"] == 0
    assert result["latest"] is None
    assert all(value is False for value in result["authority"].values())
