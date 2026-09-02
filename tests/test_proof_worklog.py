from __future__ import annotations

import json
from pathlib import Path

from factoryline.proof_worklog import MARKER, create_proof_worklog, proof_worklog_projection, verify_proof_worklog
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract


AGENT = {"schema": "factory.agent-identity.v1", "subject": "worklog-owner", "provider": "declared", "model": "declared-model"}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    intent = root / "briefs" / "intent.md"
    source = root / "src" / "checkout.py"
    intent.parent.mkdir(parents=True, exist_ok=True)
    source.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text("Checkout completes valid orders and never exposes private account data.\n", encoding="utf-8")
    source.write_text("def checkout(order):\n    return bool(order)\n", encoding="utf-8")
    handoff = capture_intent_handoff(root, intent, AGENT, "worklog-intake", Path(".factory/oracles/handoffs/worklog-intake.json"))
    payload = {
        "schema": "factory.oracle-contract-input.v1", "id": "worklog-checkout", "version": 1,
        "approved_by": "Release Owner", "approval_rationale": "Original intent reviewed.", "scope_paths": ["src"], "handoff": handoff["path"], "sources": [],
        "requirements": [{"id": "complete", "statement": "Valid checkout completes.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "forbidden_behaviors": [{"id": "private", "statement": "Private account data is never exposed.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "gates": [{"id": "quality", "statement": "Quality reaches approved threshold.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True, "comparison": "gte", "value": 95}],
        "exceptions": [{"id": "offline", "statement": "Offline evidence remains advisory until review.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}], "negative_cases": [{"id": "bad-order", "statement": "Invalid order does not complete.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "invariants": [{"id": "scope", "statement": "Only sealed scope changes.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "tests": [{"id": "checkout-test", "statement": "Rejected-order path is tested.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "path": "tests/test_checkout.py"}],
    }
    return root / seal_oracle_contract(root, _write(root / "oracle-input.json", payload), Path(".factory/oracles/contracts/worklog-checkout.json"))["path"]


def test_worklog_is_bound_to_current_contract_and_never_claims_external_post(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    draft = create_proof_worklog(tmp_path, contract.relative_to(tmp_path))

    assert draft["marker"] == MARKER
    assert draft["review_required"] is True
    assert "has not been posted" in draft["markdown"]
    assert "Valid checkout completes." in draft["markdown"]
    assert "Private account data is never exposed." in draft["markdown"]
    assert all(value is False for value in draft["authority"].values())
    assert verify_proof_worklog(tmp_path, Path(draft["path"]))["ok"] is True
    projection = proof_worklog_projection(tmp_path)
    assert projection["draft_count"] == 1
    assert projection["invalid_count"] == 0
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["facts"]["proof_worklog_draft_count"] == 1
    assert any(node["kind"] == "proof_worklog" for node in snapshot["nodes"])


def test_worklog_fails_closed_when_contract_changes(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    draft = create_proof_worklog(tmp_path, contract.relative_to(tmp_path))
    value = json.loads(contract.read_text(encoding="utf-8"))
    value["contract_sha256"] = "0" * 64
    contract.write_text(json.dumps(value), encoding="utf-8")

    checked = verify_proof_worklog(tmp_path, Path(draft["path"]))
    assert checked["ok"] is False
    assert checked["reason"] == "oracle_binding_stale"
