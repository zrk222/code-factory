from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.mcp import dispatch
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.proof_continuity_ledger import ProofContinuityError, proof_continuity_projection, record_proof_continuity_observation, seal_proof_continuity


AGENT = {"schema": "factory.agent-identity.v1", "subject": "worker-alpha", "provider": "local", "model": "model-a"}
REVISION = "a" * 40


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _oracle(root: Path) -> Path:
    intent = root / "briefs" / "intent.md"; intent.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text("Restore must never create a duplicate charge.", encoding="utf-8")
    handoff = capture_intent_handoff(root, intent, AGENT, "restore", Path(".factory/oracles/handoffs/restore.json"))
    rules = {
        "requirements": [{"id": "restore", "statement": "Restore succeeds for an entitled account.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "forbidden_behaviors": [{"id": "double-charge", "statement": "Restore never creates a new charge.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "gates": [{"id": "restore-rate", "statement": "Restore evidence meets the approved floor.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "comparison": "gte", "value": 95}],
        "exceptions": [{"id": "none", "statement": "No exception is approved.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}],
        "negative_cases": [{"id": "expired", "statement": "Expired access must not restore paid access.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "invariants": [{"id": "revision", "statement": "Evidence binds to the reviewed revision.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "tests": [{"id": "restore-flow", "statement": "The restore test fails if expired access is accepted.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "path": "tests/test_restore.py"}],
    }
    payload = {"schema": "factory.oracle-contract-input.v1", "id": "restore-audit", "version": 1, "approved_by": "Release Owner", "approval_rationale": "The owner reviewed the exact restoration safety boundary.", "scope_paths": ["."], "handoff": handoff["path"], "sources": [], **rules}
    source = _write(root / "oracle-input.json", payload)
    return root / seal_oracle_contract(root, source, Path(".factory/oracles/contracts/restore.json"))["path"]


def _evidence(root: Path) -> Path:
    core = {"schema": "factory.test-evidence.v1", "marker": "TEST_EVIDENCE_READY", "candidate": {"source_commit": REVISION}, "result": "declared local evidence"}
    return _write(root / "evidence.json", {**core, "receipt_sha256": _sha(core)})


def _input(root: Path, oracle: Path, evidence: Path) -> Path:
    payload = {
        "schema": "factory.proof-continuity-contract-input.v1",
        "id": "restore-senior-audit",
        "subject": {"repository": "zrk222/example", "revision": REVISION, "scope": "services/billing"},
        "oracle_contract": oracle.relative_to(root).as_posix(),
        "evidence": [{"id": "restore-evidence", "kind": "test", "path": evidence.relative_to(root).as_posix(), "schema": "factory.test-evidence.v1", "marker": "TEST_EVIDENCE_READY", "sha_field": "receipt_sha256"}],
        "obligations": [{"id": "restore-proof", "source_id": "original-intent", "requirement_id": "restore", "forbidden_behavior_id": "double-charge", "gate_id": "restore-rate", "test_id": "restore-flow", "evidence_id": "restore-evidence"}],
        "approved_by": "Release Owner",
        "approval_rationale": "A senior review bound the release evidence to the approved source chain.",
        "autonomy": "supervised",
    }
    return _write(root / "continuity-input.json", payload)


def test_proof_continuity_seals_a_repository_level_chain_and_projects_graph_mcp(tmp_path: Path) -> None:
    oracle = _oracle(tmp_path); evidence = _evidence(tmp_path)
    receipt = seal_proof_continuity(tmp_path, _input(tmp_path, oracle, evidence), Path(".factory/proof-continuity/contracts/restore.json"))

    assert receipt["marker"] == "PROOF_CONTINUITY_SEALED"
    assert receipt["subject"]["repository"] == "zrk222/example"
    assert receipt["autonomy"]["automatic_release"] is False
    assert receipt["obligations"][0]["test_id"] == "restore-flow"
    graph = graph_ops_snapshot(tmp_path)
    assert graph["facts"]["proof_continuity_contract_count"] == 1
    assert graph["facts"]["proof_continuity_active_contract_count"] == 1
    assert any(node["kind"] == "proof_continuity_audit" for node in graph["nodes"])
    mcp = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "factory.proof_continuity_status", "arguments": {}}}, tmp_path)
    status = json.loads(mcp["result"]["content"][0]["text"])
    assert status["marker"] == "MCP_PROOF_CONTINUITY_READ_ONLY"
    assert status["status"]["contract_count"] == 1


def test_proof_continuity_reopens_on_later_contradiction_and_demands_supervision(tmp_path: Path) -> None:
    oracle = _oracle(tmp_path); evidence = _evidence(tmp_path)
    contract = seal_proof_continuity(tmp_path, _input(tmp_path, oracle, evidence), Path(".factory/proof-continuity/contracts/restore.json"))
    later = tmp_path / "runtime-observation.log"; later.write_text("duplicate charge observed", encoding="utf-8")
    observed = _write(tmp_path / "observation.json", {"schema": "factory.proof-continuity-observation-input.v1", "id": "duplicate-charge", "contract_sha256": contract["receipt_sha256"], "obligation_id": "restore-proof", "outcome": "contradicted", "kind": "runtime", "evidence_path": "runtime-observation.log", "evidence_sha256": hashlib.sha256(later.read_bytes()).hexdigest(), "observed_at": "2026-09-03T12:00:00Z", "reviewed_by": "Release Owner", "consequence": "Charge boundary needs a named remediation review."})
    receipt = record_proof_continuity_observation(tmp_path, Path(contract["path"]), observed, Path(".factory/proof-continuity/observations/duplicate-charge.json"))

    assert receipt["marker"] == "E_PROOF_CONTINUITY_REOPENED"
    assert receipt["verdict"] == "BLOCKED"
    assert receipt["incident"] == {"open": True, "failure_class": "proof_continuity_contradiction", "required_next_action": "named_human_review", "autonomy_mode": "supervised"}
    projection = proof_continuity_projection(tmp_path)
    assert projection["active_contract_count"] == 0
    assert projection["reopened_count"] == 1
    assert graph_ops_snapshot(tmp_path)["facts"]["proof_continuity_reopened_count"] == 1


def test_proof_continuity_rejects_agent_provenance_gaps_stale_evidence_and_unknown_obligations(tmp_path: Path) -> None:
    oracle = _oracle(tmp_path); evidence = _evidence(tmp_path); contract_input = _input(tmp_path, oracle, evidence)
    value = json.loads(contract_input.read_text(encoding="utf-8")); value["obligations"][0]["gate_id"] = "missing"; _write(contract_input, value)
    with pytest.raises(ProofContinuityError) as missing:
        seal_proof_continuity(tmp_path, contract_input, Path(".factory/proof-continuity/contracts/rejected.json"))
    assert missing.value.code == "PROOF_CONTINUITY_CHAIN_INVALID"
    contract_input = _input(tmp_path, oracle, evidence)
    value = json.loads(contract_input.read_text(encoding="utf-8")); value["subject"]["revision"] = "b" * 40; _write(contract_input, value)
    with pytest.raises(ProofContinuityError) as stale:
        seal_proof_continuity(tmp_path, contract_input, Path(".factory/proof-continuity/contracts/revision-mismatch.json"))
    assert stale.value.code == "PROOF_CONTINUITY_EVIDENCE_REVISION_MISMATCH"


def test_proof_continuity_cli_keeps_observation_and_status_local(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    oracle = _oracle(tmp_path); evidence = _evidence(tmp_path); source = _input(tmp_path, oracle, evidence)
    assert main(["proof-continuity", "seal", "--root", str(tmp_path), "--input", str(source), "--out", ".factory/proof-continuity/contracts/cli.json", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "PROOF_CONTINUITY_SEALED"
    assert main(["proof-continuity", "status", "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "PROOF_CONTINUITY_READ_ONLY"
