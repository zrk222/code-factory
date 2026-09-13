from __future__ import annotations

import pytest

import factoryline.mcp as mcp
from factoryline.mcp_mrt import McpMrtError, release_gate_completed, release_gate_input_required


def test_release_gate_input_required_is_deterministic_and_authority_free() -> None:
    card = {
        "feature": "payments",
        "state": "LOCAL_EVIDENCE_BLOCKED",
        "classification": "local_evidence_failure",
        "blockers": [{"source": "strict_release_verification", "code": "RELEASE_CONTRACT_MISSING", "detail": "contract absent"}],
        "next_action": {"action": "create_or_restore_release_contract"},
    }
    first = release_gate_input_required(card)
    second = release_gate_input_required(card)
    assert first == second
    assert first["type"] == "input_required"
    assert first["toolCallId"].startswith("release-gate:")
    assert first["context"]["proofCardHash"].startswith("sha256:")
    assert first["context"]["hasUnresolvedProofDebt"] is True
    assert first["context"]["proofDebt"] == ["RELEASE_CONTRACT_MISSING"]
    assert first["inputSchema"]["required"] == ["decision", "reviewerIdentity"]
    assert all(value is False for value in first["authority"].values())
    assert "does not" in first["claim_boundary"]


def test_release_gate_input_required_preserves_empty_proof_debt() -> None:
    card = {"feature": "payments", "state": "EXTERNAL_GATES_UNOBSERVED", "next_action": {"action": "review_external_publish_gates"}}
    result = release_gate_input_required(card)
    assert result["context"]["hasUnresolvedProofDebt"] is False
    assert result["context"]["proofDebt"] == []
    assert result["context"]["nextFactDerivedAction"] == "review_external_publish_gates"


def test_release_gate_input_required_projects_explicit_failed_lane() -> None:
    card = {
        "feature": "payments",
        "state": "LOCAL_EVIDENCE_BLOCKED",
        "blockers": [{
            "lane": "authorization_tenant_isolation",
            "rejectionCondition": "CF-RULE-AUTH-04",
            "evidenceDigest": "sha256:evidence_456",
            "riskSeverity": "HIGH",
            "code": "AUTH_TENANT_SCOPE",
        }],
    }
    result = release_gate_input_required(card)
    assert "1 failed audit lane(s)" in result["prompt"]
    assert result["context"]["failedLanes"] == [{
        "lane": "authorization_tenant_isolation",
        "rejectionCondition": "CF-RULE-AUTH-04",
        "evidenceDigest": "sha256:evidence_456",
        "riskSeverity": "HIGH",
    }]


def test_release_gate_completed_is_deterministic_and_authority_free() -> None:
    card = {"feature": "payments", "state": "EXTERNAL_GATES_UNOBSERVED"}
    challenge = release_gate_input_required(card)
    human_input = {
        "decision": "APPROVE_RELEASE",
        "reviewerIdentity": "dev-lead@company.com",
        "reviewerNotes": "Local evidence reviewed.",
    }
    first = release_gate_completed(
        card,
        human_input,
        tool_call_id=challenge["toolCallId"],
        proof_card_hash=challenge["context"]["proofCardHash"],
    )
    second = release_gate_completed(
        card,
        human_input,
        tool_call_id=challenge["toolCallId"],
        proof_card_hash=challenge["context"]["proofCardHash"],
    )
    assert first == second
    assert first["type"] == "completed"
    assert first["status"] == "RELEASE_APPROVED"
    assert first["receiptHash"].startswith("sha256:")
    assert "permanently sealed by dev-lead@company.com" in first["summary"]
    assert all(value is False for value in first["authority"].values())
    assert "does not approve" in first["claim_boundary"]


def test_release_gate_completed_requires_proof_debt_acknowledgement() -> None:
    card = {
        "feature": "payments",
        "state": "LOCAL_EVIDENCE_BLOCKED",
        "blockers": [{"code": "RELEASE_CONTRACT_MISSING"}],
    }
    with pytest.raises(McpMrtError, match="acknowledgement") as exc_info:
        release_gate_completed(card, {"decision": "APPROVE_RELEASE", "reviewerIdentity": "lead"})
    assert exc_info.value.marker == "MCP2_RELEASE_DEBT_UNACKNOWLEDGED"
    result = release_gate_completed(card, {
        "decision": "APPROVE_RELEASE",
        "reviewerIdentity": "lead",
        "acknowledgedProofDebt": ["RELEASE_CONTRACT_MISSING"],
    })
    assert result["status"] == "RELEASE_APPROVED"


def test_release_gate_completed_rejects_invalid_input_and_binding_mismatch() -> None:
    card = {"feature": "payments", "state": "EXTERNAL_GATES_UNOBSERVED"}
    with pytest.raises(McpMrtError, match="decision"):
        release_gate_completed(card, {"decision": "INVALID", "reviewerIdentity": "lead"})
    with pytest.raises(McpMrtError) as exc_info:
        release_gate_completed(
            card,
            {"decision": "REJECT_RELEASE", "reviewerIdentity": "lead"},
            tool_call_id="release-gate:wrong",
        )
    assert exc_info.value.marker == "MCP2_RELEASE_GATE_BINDING_MISMATCH"


def test_factory_release_decision_bridges_both_stateless_mrt_legs(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    card = {"feature": "payments", "state": "EXTERNAL_GATES_UNOBSERVED"}
    monkeypatch.setattr(mcp, "release_decision_card", lambda _root, _feature: card)
    challenge = mcp._release_decision_status(tmp_path, {"feature": "payments"})
    challenge_payload = challenge["mcp2"]
    completed = mcp._release_decision_status(tmp_path, {
        "feature": "payments",
        "tool_call_id": challenge_payload["toolCallId"],
        "proof_card_hash": challenge_payload["context"]["proofCardHash"],
        "human_input": {"decision": "REJECT_RELEASE", "reviewerIdentity": "lead"},
    })
    assert challenge["marker"] == "MCP_RELEASE_DECISION_READ_ONLY"
    assert completed["marker"] == "MCP_RELEASE_DECISION_COMPLETED"
    assert completed["mcp2"]["status"] == "RELEASE_REJECTED"
