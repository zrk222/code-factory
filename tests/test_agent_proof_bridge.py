from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from factoryline.agent_proof_bridge import (
    BOUND_MARKER,
    MCP_MARKER,
    AgentProofBridgeError,
    agent_handoff_brief,
    agent_proof_projection,
    import_agent_proof,
    provider_template,
    verify_agent_proof,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.semantic_authority import seal_authority_lease, seal_semantic_handoff


AGENT = {"schema": "factory.agent-identity.v1", "subject": "portable-worker", "provider": "declared", "model": "declared-model"}


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    existing = root / ".factory" / "oracles" / "contracts" / "bridge-checkout.json"
    if existing.is_file():
        return existing
    intent = root / "briefs" / "intent.md"
    source = root / "src" / "checkout.py"
    intent.parent.mkdir(parents=True, exist_ok=True)
    source.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text("Checkout completes valid orders and never exposes private account data.\n", encoding="utf-8")
    source.write_text("def checkout(order):\n    return bool(order)\n", encoding="utf-8", newline="\n")
    handoff = capture_intent_handoff(root, intent, AGENT, "bridge-intake", Path(".factory/oracles/handoffs/bridge-intake.json"))
    payload = {
        "schema": "factory.oracle-contract-input.v1", "id": "bridge-checkout", "version": 1,
        "approved_by": "Release Owner", "approval_rationale": "Original intent and negative boundary reviewed.",
        "scope_paths": ["src"], "handoff": handoff["path"], "sources": [],
        "requirements": [{"id": "complete", "statement": "Valid checkout completes.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "forbidden_behaviors": [{"id": "private", "statement": "Private account data is never exposed.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "gates": [{"id": "quality", "statement": "Quality reaches approved threshold.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True, "comparison": "gte", "value": 95}],
        "exceptions": [{"id": "offline", "statement": "Offline evidence remains advisory until review.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}],
        "negative_cases": [{"id": "bad-order", "statement": "Invalid order does not complete.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "invariants": [{"id": "scope", "statement": "Only sealed scope changes.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "tests": [{"id": "checkout-test", "statement": "Rejected-order path is tested.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "path": "tests/test_checkout.py"}],
    }
    return root / seal_oracle_contract(root, _write(root / "oracle-input.json", payload), Path(".factory/oracles/contracts/bridge-checkout.json"))["path"]


def _workflow() -> dict[str, object]:
    nodes = [{"id": "plan", "kind": "planner"}, {"id": "build", "kind": "worker"}, {"id": "verify", "kind": "validator"}]
    edges = [{"from": "plan", "to": "build"}, {"from": "build", "to": "verify"}]
    return {"id": "portable-checkout", "definition_sha256": _digest("definition"), "topology_sha256": _sha({"nodes": sorted(nodes, key=lambda item: item["id"]), "edges": sorted(edges, key=lambda item: (item["from"], item["to"]))}), "nodes": nodes, "edges": edges}


def _profile(provider: str) -> dict[str, object]:
    value: dict[str, object] = {"session_id": "session-1", "runtime_sha256": _digest("runtime"), "tool_manifest_sha256": _digest("tools")}
    if provider == "eve":
        value.update({"workflow_id": "eve-flow", "checkpoint_id": "checkpoint-1", "checkpoint_sha256": _digest("checkpoint-1"), "deployment_commit_sha": "a" * 40})
    elif provider == "junie":
        value.update({"mission_sha256": _digest("mission"), "action_policy_sha256": _digest("actions"), "change_list_sha256": _digest("change-list")})
    elif provider == "grok_build":
        value.update({"stream_sha256": _digest("stream"), "mode": "headless", "permission_policy_sha256": _digest("policy")})
    elif provider == "coderabbit":
        value.update({"review_output_sha256": _digest("review-jsonl"), "review_mode": "agent", "base_commit_sha": "b" * 40, "head_commit_sha": "c" * 40, "finding_count": 2})
    elif provider == "devin":
        value.update({"task_sha256": _digest("task"), "result_sha256": _digest("result"), "base_commit_sha": "d" * 40, "head_commit_sha": "e" * 40, "permission_profile_sha256": _digest("permissions")})
    return value


def _envelope(root: Path, *, provider: str = "eve", run_id: str = "run-1", surface: str = "visual") -> dict[str, object]:
    contract = _contract(root)
    value = json.loads(contract.read_text(encoding="utf-8"))
    before, after = root / ".factory" / "evidence" / f"{run_id}-before.txt", root / ".factory" / "evidence" / f"{run_id}-after.txt"
    before.parent.mkdir(parents=True, exist_ok=True)
    before.write_text("before\n", encoding="utf-8")
    after.write_text("after\n", encoding="utf-8")
    return {
        "schema": "factory.agent-proof-envelope.v1", "envelope_id": f"envelope-{run_id}", "provider": provider, "run_id": run_id, "status": "completed", "agent": AGENT,
        "autonomy": "supervised", "isolation": "declared_worktree", "scope_paths": ["src"], "surface": surface,
        "oracle": {"contract_path": contract.relative_to(root).as_posix(), "contract_sha256": value["contract_sha256"]},
        "workflow": _workflow(), "source_preconditions": [{"path": "src/checkout.py", "sha256": _digest("def checkout(order):\n    return bool(order)\n")}],
        "evidence_pairs": [{"id": "before-after", "kind": "visual" if surface == "visual" else "logic", "before_path": before.relative_to(root).as_posix(), "after_path": after.relative_to(root).as_posix(), "before_sha256": hashlib.sha256(before.read_bytes()).hexdigest(), "after_sha256": hashlib.sha256(after.read_bytes()).hexdigest(), "claim_sha256": _digest("claim")}],
        "provider_receipt": _profile(provider),
    }


def _import(root: Path, envelope: dict[str, object], filename: str = "envelope.json") -> dict[str, object]:
    source = _write(root / filename, envelope)
    return import_agent_proof(root, source.relative_to(root))


def _semantic_binding(root: Path, suffix: str = "bridge") -> dict[str, str]:
    contract = _contract(root)
    contract_value = json.loads(contract.read_text(encoding="utf-8"))
    handoff_input = _write(root / "semantic-handoff-input.json", {
        "schema": "factory.semantic-handoff-input.v1", "id": "bridge-handoff", "oracle_contract": contract.relative_to(root).as_posix(), "sender": AGENT, "receiver": AGENT,
        "performative": "REQUEST", "goal": "Inspect the exact checkout evidence envelope.", "context_urn": "urn:factory:checkout:v1", "context_source_id": "original-intent", "scope_paths": ["src"], "allowed_actions": ["inspect"],
        "epistemic": {"known": [{"id": "intent", "statement": "The source-bound contract forbids private-data exposure.", "source_id": "original-intent"}], "unknown": [{"id": "provider", "statement": "Provider runtime state is not in the local receipt.", "impact": "No provider claim.", "blocking": False}], "uncertain": [{"id": "sandbox", "statement": "Declared isolation is not verified sandbox proof.", "impact": "Keep runtime proof separate."}], "capability_limits": ["This local envelope reader cannot call the provider or release code."]},
    })
    handoff = seal_semantic_handoff(root, handoff_input, Path(f".factory/semantic-authority/handoffs/{suffix}.json"))
    lease_input = _write(root / "semantic-lease-input.json", {
        "schema": "factory.authority-lease-input.v1", "id": "bridge-lease", "handoff": handoff["path"], "delegatee": AGENT, "scope_paths": ["src"], "allowed_actions": ["inspect"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "approval_origin": "human_confirmed", "approved_by": "Release Owner", "rationale": "Bound evidence intake only.",
    })
    lease = seal_authority_lease(root, lease_input, Path(f".factory/semantic-authority/leases/{suffix}.json"))
    assert lease["handoff"]["oracle_contract_sha256"] == contract_value["contract_sha256"]
    return {"lease_path": lease["path"], "lease_sha256": lease["lease_sha256"], "action_id": "inspect-envelope", "action": "inspect", "context_urn": "urn:factory:checkout:v1"}


@pytest.mark.parametrize("provider", ["eve", "junie", "grok_build", "coderabbit", "devin", "generic"])
def test_profiles_bind_hash_only_portable_evidence(provider: str, tmp_path: Path) -> None:
    receipt = _import(tmp_path, _envelope(tmp_path, provider=provider))
    assert receipt["marker"] == BOUND_MARKER
    assert receipt["provider"] == provider
    assert all(value is False for value in receipt["authority"].values())
    assert verify_agent_proof(tmp_path, Path(receipt["path"]))["ok"] is True
    projection = agent_proof_projection(tmp_path)
    assert projection["marker"] == MCP_MARKER
    assert projection["providers"][provider] == 1


def test_graph_ops_projects_agent_bridge_as_read_only_handoff_evidence(tmp_path: Path) -> None:
    _import(tmp_path, _envelope(tmp_path, provider="junie"))

    snapshot = graph_ops_snapshot(tmp_path)

    assert snapshot["agent_proof_bridge"]["bound_count"] == 1
    assert snapshot["facts"]["agent_bridge_bound_count"] == 1
    assert "GRAPH_OPS_AGENT_PROOF_BRIDGE_READ_ONLY" in snapshot["markers"]
    kinds = {node["kind"] for node in snapshot["nodes"]}
    assert {"agent_contract", "agent_provider", "agent_workflow", "agent_run", "agent_evidence"} <= kinds
    assert all(node["facts"]["authority"]["execution"] is False for node in snapshot["nodes"] if node["kind"].startswith("agent_"))


def test_agent_bridge_can_bind_imported_evidence_to_an_active_semantic_lease(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path, provider="junie")
    envelope["semantic_authority"] = _semantic_binding(tmp_path)
    receipt = _import(tmp_path, envelope)
    assert receipt["semantic_authority"]["bound"] is True
    assert agent_proof_projection(tmp_path)["semantic_authority_bound_count"] == 1

    invalid = _envelope(tmp_path, provider="junie", run_id="invalid")
    binding = _semantic_binding(tmp_path, "invalid")
    binding["action"] = "repair"
    invalid["semantic_authority"] = binding
    with pytest.raises(AgentProofBridgeError) as rejected:
        _import(tmp_path, invalid, "invalid-semantic.json")
    assert rejected.value.code == "E_AGENT_BRIDGE_SEMANTIC_AUTHORITY"


def test_agent_bridge_rejects_a_receipt_when_its_semantic_lease_is_expired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    envelope = _envelope(tmp_path, provider="junie")
    envelope["semantic_authority"] = _semantic_binding(tmp_path)
    receipt = _import(tmp_path, envelope)
    assert verify_agent_proof(tmp_path, Path(receipt["path"]))["ok"] is True
    import factoryline.semantic_authority as semantic_module
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    monkeypatch.setattr(semantic_module, "_now", lambda: future)
    checked = verify_agent_proof(tmp_path, Path(receipt["path"]))
    assert checked["ok"] is False
    assert checked["reason"] == "semantic_authority_stale"


def test_bridge_fails_closed_for_private_content_scope_and_visual_proof_gaps(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    envelope["raw_prompt"] = "not allowed"
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_PRIVATE_FIELD"

    envelope = _envelope(tmp_path)
    envelope["scope_paths"] = ["admin"]
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_SCOPE_ESCAPE"

    envelope = _envelope(tmp_path)
    envelope["evidence_pairs"][0]["kind"] = "logic"
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED"
    assert not (tmp_path / ".factory" / "agent-bridges").exists()


def test_bridge_rejects_missing_or_hash_mismatched_before_after_artifacts(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    envelope["evidence_pairs"][0]["after_path"] = "evidence/missing.png"
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED"

    envelope = _envelope(tmp_path, run_id="changed")
    (tmp_path / envelope["evidence_pairs"][0]["after_path"]).write_text("tampered\n", encoding="utf-8")
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED"


def test_eve_resume_requires_exact_provider_checkpoint_and_oracle_binding(tmp_path: Path) -> None:
    first = _import(tmp_path, _envelope(tmp_path, provider="eve", run_id="run-1"), "first.json")
    resumed = _envelope(tmp_path, provider="eve", run_id="run-2")
    profile = resumed["provider_receipt"]
    resumed["resume"] = {"prior_receipt": first["path"], "prior_run_id": "run-1", "checkpoint_id": profile["checkpoint_id"], "checkpoint_sha256": profile["checkpoint_sha256"], "provider_receipt_sha256": _sha(first["provider_receipt"])}
    receipt = _import(tmp_path, resumed, "resumed.json")
    assert receipt["resume"]["recovery_action"] == "human_reviewed_fork"

    divergent = copy.deepcopy(resumed)
    divergent["run_id"] = "run-3"
    divergent["envelope_id"] = "envelope-run-3"
    divergent["resume"]["checkpoint_sha256"] = _digest("other")
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, divergent, "divergent.json")
    assert raised.value.code == "E_AGENT_BRIDGE_RESUME_DIVERGENCE"


def test_templates_are_secret_free_and_no_provider_runtime_dependency() -> None:
    for provider in ("eve", "junie", "grok_build", "coderabbit", "devin", "generic"):
        template = provider_template(provider)
        assert template["provider"] == provider
        assert all(value is False for value in template["authority"].values())
    source = (Path(__file__).parents[1] / "factoryline" / "agent_proof_bridge.py").read_text(encoding="utf-8")
    for forbidden in ("import subprocess", "import requests", "import httpx", "import socket"):
        assert forbidden not in source


def test_handoff_brief_replays_sealed_intent_for_worker_and_human_without_authority(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    brief = agent_handoff_brief(tmp_path, contract.relative_to(tmp_path))

    assert brief["marker"] == "AGENT_HANDOFF_BRIEF_READ_ONLY"
    assert brief["contract"]["contract_sha256"] == json.loads(contract.read_text(encoding="utf-8"))["contract_sha256"]
    assert brief["intended_outcomes"][0]["id"] == "complete"
    assert brief["forbidden_outcomes"][0]["id"] == "private"
    assert brief["negative_cases"][0]["id"] == "bad-order"
    assert all(value is False for value in brief["authority"].values())
