from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path

import pytest

from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.semantic_authority import (
    SemanticAuthorityError,
    _now,
    authorize_semantic_action,
    record_semantic_action_decision,
    seal_authority_lease,
    seal_semantic_handoff,
    semantic_authority_projection,
    verify_authority_lease,
    verify_semantic_binding,
    verify_semantic_handoff,
)


SENDER = {"schema": "factory.agent-identity.v1", "subject": "planner", "provider": "local", "model": "model-a"}
RECEIVER = {"schema": "factory.agent-identity.v1", "subject": "worker", "provider": "local", "model": "model-b"}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    intent = root / "brief.md"
    intent.write_text("A restore must not create a second purchase.", encoding="utf-8")
    handoff = capture_intent_handoff(root, intent, SENDER, "intake", Path(".factory/oracles/handoffs/intake.json"))
    source = _write(root / "contract-input.json", {
        "schema": "factory.oracle-contract-input.v1", "id": "restore", "version": 1, "approved_by": "Owner", "approval_rationale": "Lock the restore safety rule.", "scope_paths": ["."], "handoff": handoff["path"], "sources": [],
        "requirements": [{"id": "restore", "statement": "Restore succeeds only for an entitlement.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "forbidden_behaviors": [{"id": "charge", "statement": "Restore never creates a purchase.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "gates": [{"id": "rate", "statement": "Evidence is present.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "comparison": "present", "value": True}],
        "exceptions": [{"id": "offline", "statement": "Offline is advisory.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}],
        "negative_cases": [{"id": "expired", "statement": "Expired access is refused.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "invariants": [{"id": "candidate", "statement": "Evidence binds the candidate.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "tests": [{"id": "restore-test", "statement": "The test fails on expired access.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "path": "tests/test_restore.py"}],
    })
    return root / seal_oracle_contract(root, source, Path(".factory/oracles/contracts/restore.json"))["path"]


def _handoff(root: Path, contract: Path) -> Path:
    payload = _write(root / "semantic-input.json", {
        "schema": "factory.semantic-handoff-input.v1", "id": "restore-proof", "oracle_contract": contract.relative_to(root).as_posix(), "sender": SENDER, "receiver": RECEIVER,
        "performative": "REQUEST", "goal": "Verify that restore preserves the entitlement boundary.", "context_urn": "urn:factory:subscription-restore:v1", "context_source_id": "original-intent", "scope_paths": ["src", "tests"], "allowed_actions": ["inspect", "test"],
        "sensitivities": [{"id": "expired", "when": "entitlement is expired", "impact": "the negative case must reject the action"}],
        "epistemic": {"known": [{"id": "intent", "statement": "The sealed intent prohibits a second purchase.", "source_id": "original-intent"}], "unknown": [{"id": "provider-state", "statement": "The current provider entitlement state is not in the local receipt.", "impact": "Do not claim a live restore succeeded.", "blocking": True}], "uncertain": [{"id": "sandbox-parity", "statement": "Sandbox behavior may differ from a provider environment.", "impact": "Independent runtime evidence remains required."}], "capability_limits": ["This local worker cannot inspect a provider account or approve a release."]},
    })
    return root / seal_semantic_handoff(root, payload, Path(".factory/semantic-authority/handoffs/restore.json"))["path"]


def _lease(root: Path, handoff: Path, *, expires_at: str | None = None, actions: list[str] | None = None) -> Path:
    payload = _write(root / "lease-input.json", {
        "schema": "factory.authority-lease-input.v1", "id": "restore-worker", "handoff": handoff.relative_to(root).as_posix(), "delegatee": RECEIVER,
        "scope_paths": ["src", "tests"], "allowed_actions": actions or ["inspect", "test"], "expires_at": expires_at or (_now() + timedelta(minutes=20)).isoformat().replace("+00:00", "Z"),
        "approval_origin": "human_confirmed", "approved_by": "Owner", "rationale": "Bound a local verifier to the original restore task.",
    })
    return root / seal_authority_lease(root, payload, Path(".factory/semantic-authority/leases/restore.json"))["path"]


def _request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {"action_id": "check-restore", "actor": RECEIVER, "action": "test", "scope_paths": ["tests"], "context_urn": "urn:factory:subscription-restore:v1"}
    request.update(overrides)
    return request


def test_handoff_and_lease_only_admit_exact_bound_context_scope_and_actor(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, _contract(tmp_path))
    lease = _lease(tmp_path, handoff)
    assert verify_semantic_handoff(tmp_path, handoff)["ok"] is True
    assert verify_authority_lease(tmp_path, lease)["ok"] is True
    allowed = authorize_semantic_action(tmp_path, lease, _request())
    assert allowed["allowed"] is True
    assert allowed["authority"]["execution"] is False
    lease_value = json.loads(lease.read_text(encoding="utf-8"))
    binding = {"lease_path": lease.relative_to(tmp_path).as_posix(), "lease_sha256": lease_value["lease_sha256"], "action_id": "bound-restore-check", "action": "test", "context_urn": "urn:factory:subscription-restore:v1"}
    assert verify_semantic_binding(tmp_path, binding, RECEIVER, ["tests"])["action"] == "test"
    assert authorize_semantic_action(tmp_path, lease, _request(scope_paths=["outside"]))["reason"] == "scope_escape"
    assert authorize_semantic_action(tmp_path, lease, _request(context_urn="urn:factory:other:v1"))["reason"] == "context_mismatch"
    other = {**RECEIVER, "subject": "untrusted"}
    assert authorize_semantic_action(tmp_path, lease, _request(actor=other))["reason"] == "lease_subject_mismatch"


def test_lease_rejects_expiration_ungranted_and_external_actions(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, _contract(tmp_path))
    with pytest.raises(SemanticAuthorityError, match="next 24 hours") as expired:
        _lease(tmp_path, handoff, expires_at=(_now() - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"))
    assert expired.value.code == "E_SEMANTIC_AUTHORIZATION"
    with pytest.raises(SemanticAuthorityError) as forbidden:
        _lease(tmp_path, handoff, actions=["deploy"])
    assert forbidden.value.code == "SEMANTIC_ACTION_FORBIDDEN"
    lease = _lease(tmp_path, handoff)
    assert authorize_semantic_action(tmp_path, lease, _request(action="repair"))["reason"] == "action_not_granted"


def test_recorded_action_is_immutable_and_replay_is_blocked(tmp_path: Path) -> None:
    lease = _lease(tmp_path, _handoff(tmp_path, _contract(tmp_path)))
    recorded = record_semantic_action_decision(tmp_path, lease, _request(), Path(".factory/semantic-authority/decisions/first.json"))
    assert recorded["marker"] == "SEMANTIC_ACTION_DECISION_RECORDED"
    with pytest.raises(SemanticAuthorityError) as replay:
        record_semantic_action_decision(tmp_path, lease, _request(), Path(".factory/semantic-authority/decisions/replay.json"))
    assert replay.value.code == "E_SEMANTIC_REPLAY"
    projection = semantic_authority_projection(tmp_path)
    assert projection["current_handoff_count"] == 1
    assert projection["active_lease_count"] == 1
    assert projection["decision_count"] == 1
    assert all(value is False for value in projection["authority"].values())
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["semantic_authority"]["active_lease_count"] == 1
    assert snapshot["facts"]["semantic_unknown_count"] == 1
    assert "GRAPH_OPS_SEMANTIC_AUTHORITY_READ_ONLY" in snapshot["markers"]
    assert {"semantic_handoff", "authority_lease", "semantic_decision"} <= {node["kind"] for node in snapshot["nodes"]}


def test_agent_proposed_source_cannot_become_semantic_authority(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    input_path = _write(tmp_path / "bad-semantic-input.json", {
        "schema": "factory.semantic-handoff-input.v1", "id": "bad", "oracle_contract": contract.relative_to(tmp_path).as_posix(), "sender": SENDER, "receiver": RECEIVER,
        "performative": "REQUEST", "goal": "Inspect the restore flow.", "context_urn": "urn:factory:subscription-restore:v1", "context_source_id": "missing-agent-source", "scope_paths": ["src"], "allowed_actions": ["inspect"],
        "epistemic": {"known": [{"id": "intent", "statement": "A source was supplied.", "source_id": "original-intent"}], "unknown": [{"id": "state", "statement": "Provider state is unknown.", "impact": "No live conclusion.", "blocking": True}], "uncertain": [{"id": "runtime", "statement": "Runtime parity is unknown.", "impact": "Need evidence."}], "capability_limits": ["No provider access."]},
    })
    with pytest.raises(SemanticAuthorityError) as rejected:
        seal_semantic_handoff(tmp_path, input_path, Path(".factory/semantic-authority/handoffs/bad.json"))
    assert rejected.value.code == "E_SEMANTIC_AUTHORIZATION"
