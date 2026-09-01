from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from factoryline.atomic_proof_adapter import (
    BOUND_MARKER,
    MCP_MARKER,
    AtomicProofAdapterError,
    atomic_proof_projection,
    import_atomic_run,
    verify_atomic_receipt,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract


AGENT = {
    "schema": "factory.agent-identity.v1",
    "subject": "atomic-worker",
    "provider": "atomic-exporter",
    "model": "declared-model",
}


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    existing = root / ".factory/oracles/contracts/atomic-checkout.json"
    if existing.is_file():
        return existing
    intent = root / "briefs" / "original-intent.md"
    intent.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text("Checkout must preserve a valid order and never expose private account data.\n", encoding="utf-8")
    source_file = root / "src" / "checkout.py"
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text("def checkout(order):\n    return bool(order)\n", encoding="utf-8", newline="\n")
    handoff = capture_intent_handoff(root, intent, AGENT, "atomic-intake", Path(".factory/oracles/handoffs/atomic-intake.json"))
    rules = {
        "requirements": [{"id": "complete-checkout", "statement": "The approved checkout completes for a valid order.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "forbidden_behaviors": [{"id": "private-data", "statement": "Checkout must not expose private account data.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "gates": [{"id": "checkout-proof", "statement": "Checkout evidence reaches the approved threshold.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True, "comparison": "gte", "value": 95}],
        "exceptions": [{"id": "offline-note", "statement": "Offline evidence remains advisory until a human review.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}],
        "negative_cases": [{"id": "bad-order", "statement": "An invalid order must not complete checkout.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "invariants": [{"id": "scope-bound", "statement": "The candidate must remain inside the sealed source scope.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "tests": [{"id": "checkout-test", "statement": "Checkout tests exercise the rejected order path.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "path": "tests/test_checkout.py"}],
    }
    payload = {
        "schema": "factory.oracle-contract-input.v1",
        "id": "atomic-checkout",
        "version": 1,
        "approved_by": "Release Owner",
        "approval_rationale": "The release owner approved the original checkout intent and its strict negative boundary.",
        "scope_paths": ["src"],
        "handoff": handoff["path"],
        "sources": [],
        **rules,
    }
    source = _write(root / "oracle-input.json", payload)
    return root / seal_oracle_contract(root, source, Path(".factory/oracles/contracts/atomic-checkout.json"))["path"]


def _workflow() -> dict[str, object]:
    nodes = [
        {"id": "plan", "kind": "planner"},
        {"id": "build", "kind": "worker"},
        {"id": "verify", "kind": "validator"},
    ]
    edges = [{"from": "plan", "to": "build"}, {"from": "build", "to": "verify"}]
    return {
        "id": "checkout-proof-workflow",
        "definition_sha256": _digest("atomic-workflow-definition"),
        "topology_sha256": _sha({"nodes": sorted(nodes, key=lambda item: item["id"]), "edges": sorted(edges, key=lambda item: (item["from"], item["to"]))}),
        "nodes": nodes,
        "edges": edges,
    }


def _stage(identifier: str, kind: str, capabilities: list[str]) -> dict[str, object]:
    source_preconditions = [{"path": "src/checkout.py", "sha256": _digest("def checkout(order):\n    return bool(order)\n")}]
    return {
        "id": identifier,
        "kind": kind,
        "status": "completed",
        "scope_paths": ["src"],
        "capabilities": capabilities,
        "input_sha256": _digest(f"{identifier}-input"),
        "output_sha256": _digest(f"{identifier}-output"),
        "artifact_sha256": _digest(f"{identifier}-artifact"),
        "tool_manifest_sha256": _digest(f"{identifier}-tools"),
        "checkpoint": {"id": f"checkpoint-{identifier}", "sha256": _digest(f"checkpoint-{identifier}-v1")},
        "source_preconditions": source_preconditions,
    }


def _handoff(identifier: str, source: dict[str, object], target: dict[str, object], contract_sha: str) -> dict[str, object]:
    return {
        "id": identifier,
        "from_stage": source["id"],
        "to_stage": target["id"],
        "capability": "handoff",
        "scope_paths": ["src"],
        "contract_sha256": contract_sha,
        "source_preconditions_sha256": _sha(source["source_preconditions"]),
        "artifact_sha256": source["artifact_sha256"],
        "tool_manifest_sha256": source["tool_manifest_sha256"],
    }


def _envelope(root: Path, *, run_id: str = "atomic-run-1") -> tuple[dict[str, object], Path]:
    contract = _contract(root)
    contract_value = json.loads(contract.read_text(encoding="utf-8"))
    plan = _stage("plan", "planner", ["read_workspace", "handoff"])
    build = _stage("build", "worker", ["read_workspace", "write_workspace", "handoff"])
    verify = _stage("verify", "validator", ["read_workspace", "verify", "handoff"])
    payload = {
        "schema": "factory.atomic-run-envelope.v1",
        "envelope_id": f"envelope-{run_id}",
        "run_id": run_id,
        "status": "completed",
        "agent": AGENT,
        "autonomy": "supervised",
        "isolation": "declared_worktree",
        "oracle": {"contract_path": contract.relative_to(root).as_posix(), "contract_sha256": contract_value["contract_sha256"]},
        "workflow": _workflow(),
        "stages": [plan, build, verify],
        "handoffs": [
            _handoff("plan-to-build", plan, build, contract_value["contract_sha256"]),
            _handoff("build-to-verify", build, verify, contract_value["contract_sha256"]),
        ],
    }
    return payload, contract


def _import(root: Path, envelope: dict[str, object], *, filename: str = "atomic-envelope.json") -> dict[str, object]:
    path = _write(root / filename, envelope)
    return import_atomic_run(root, path.relative_to(root))


def test_import_binds_typed_dag_handoffs_checkpoints_and_read_only_projection(tmp_path: Path) -> None:
    envelope, _ = _envelope(tmp_path)
    receipt = _import(tmp_path, envelope)

    assert receipt["marker"] == BOUND_MARKER
    assert receipt["authority"] == {key: False for key in receipt["authority"]}
    checked = verify_atomic_receipt(tmp_path, Path(receipt["path"]))
    projection = atomic_proof_projection(tmp_path)
    assert checked["ok"] is True
    assert projection["marker"] == MCP_MARKER
    assert projection["bound_count"] == 1
    assert projection["latest"]["handoff_count"] == 2


def test_import_rejects_private_fields_and_scope_escape_without_adapter_receipt(tmp_path: Path) -> None:
    envelope, _ = _envelope(tmp_path)
    envelope["raw_prompt"] = "not allowed"
    with pytest.raises(AtomicProofAdapterError, match="unsupported") as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_PRIVATE_FIELD"
    assert not (tmp_path / ".factory" / "atomic").exists()

    envelope, _ = _envelope(tmp_path)
    envelope["stages"][1]["scope_paths"] = ["admin"]
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_SCOPE_ESCAPE"
    assert not (tmp_path / ".factory" / "atomic").exists()


def test_import_rejects_cyclic_or_unbound_workflow_evidence_without_receipt(tmp_path: Path) -> None:
    envelope, _ = _envelope(tmp_path)
    workflow = envelope["workflow"]
    workflow["edges"].append({"from": "verify", "to": "plan"})
    workflow["topology_sha256"] = _sha({"nodes": sorted(workflow["nodes"], key=lambda item: item["id"]), "edges": sorted(workflow["edges"], key=lambda item: (item["from"], item["to"]))})
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_EVIDENCE_UNVERIFIED"
    assert not (tmp_path / ".factory" / "atomic").exists()


def test_import_rejects_source_precondition_that_does_not_match_workspace_bytes(tmp_path: Path) -> None:
    envelope, _ = _envelope(tmp_path)
    (tmp_path / "src" / "checkout.py").write_text("def checkout(order):\n    return True\n", encoding="utf-8", newline="\n")
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_EVIDENCE_UNVERIFIED"
    assert not (tmp_path / ".factory" / "atomic").exists()


def test_import_rejects_handoff_drift_and_history_drift(tmp_path: Path) -> None:
    envelope, _ = _envelope(tmp_path)
    envelope["handoffs"][0]["artifact_sha256"] = _digest("drifted-artifact")
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_HANDOFF_DRIFT"

    original, _ = _envelope(tmp_path)
    _import(tmp_path, original, filename="first.json")
    changed, _ = _envelope(tmp_path, run_id="atomic-run-2")
    changed["stages"][0]["artifact_sha256"] = _digest("new-plan-artifact")
    changed["handoffs"][0]["artifact_sha256"] = changed["stages"][0]["artifact_sha256"]
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, changed, filename="second.json")
    assert raised.value.code == "E_ATOMIC_HANDOFF_DRIFT"


def test_import_requires_hash_equal_checkpoint_for_human_reviewed_resume(tmp_path: Path) -> None:
    first, _ = _envelope(tmp_path, run_id="atomic-run-1")
    first_receipt = _import(tmp_path, first, filename="first.json")
    resumed, _ = _envelope(tmp_path, run_id="atomic-run-2")
    worker = next(stage for stage in resumed["stages"] if stage["id"] == "build")
    resumed["resume"] = {
        "prior_receipt": first_receipt["path"],
        "prior_run_id": "atomic-run-1",
        "checkpoint_id": worker["checkpoint"]["id"],
        "checkpoint_sha256": worker["checkpoint"]["sha256"],
    }
    receipt = _import(tmp_path, resumed, filename="resumed.json")
    assert receipt["resume"]["recovery_action"] == "human_reviewed_fork"

    divergent = copy.deepcopy(resumed)
    divergent["run_id"] = "atomic-run-3"
    divergent["envelope_id"] = "envelope-atomic-run-3"
    divergent["resume"]["checkpoint_sha256"] = _digest("different-checkpoint")
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, divergent, filename="divergent.json")
    assert raised.value.code == "E_ATOMIC_RESUME_DIVERGENCE"


def test_adapter_has_no_runtime_or_network_dependency(tmp_path: Path) -> None:
    source = (Path(__file__).parents[1] / "factoryline" / "atomic_proof_adapter.py").read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "import requests" not in source
    assert "import httpx" not in source
    assert "import socket" not in source
    assert atomic_proof_projection(tmp_path)["receipt_count"] == 0


def test_cli_and_graph_ops_expose_atomic_facts_without_an_execution_surface(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    envelope, _ = _envelope(tmp_path)
    source = _write(tmp_path / "atomic-envelope.json", envelope)
    from factoryline.cli import main

    assert main(["atomic", "import", "--root", str(tmp_path), "--envelope", source.relative_to(tmp_path).as_posix(), "--json"]) == 0
    imported = json.loads(capsys.readouterr().out)
    assert imported["marker"] == BOUND_MARKER
    assert main(["atomic", "status", "--root", str(tmp_path), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["marker"] == MCP_MARKER
    graph = graph_ops_snapshot(tmp_path)
    assert graph["facts"]["atomic_bound_count"] == 1
    assert "GRAPH_OPS_ATOMIC_PROOF_ADAPTER_READ_ONLY" in graph["markers"]
    assert {node["kind"] for node in graph["nodes"]} >= {"atomic_contract", "atomic_workflow", "atomic_run", "atomic_stage", "atomic_handoff"}
    assert all(value is False for value in graph["atomic_proof_adapter"].get("authority", {}).values()) or graph["atomic_proof_adapter"]["invalid_count"] == 0
