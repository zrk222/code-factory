from __future__ import annotations

from factoryline.mcp_mrt import release_gate_input_required


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
