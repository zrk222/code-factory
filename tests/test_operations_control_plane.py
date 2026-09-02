from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from factoryline.domain_ontology import validate_domain_ontology
from factoryline.lifecycle_ledger import LifecycleLedgerError, lifecycle_projection, record_lifecycle_event
from factoryline.mission_control_status import mission_control_status
from factoryline.operations_control import assess_operations_control, operations_control_projection
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.repair_loop import assess_repair_loop, repair_loop_projection
from factoryline.repo_coordination import coordinate_repositories
from factoryline.service_boundaries import check_service_boundaries


AGENT = {"schema": "factory.agent-identity.v1", "subject": "control-worker", "provider": "local", "model": "declared-model"}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(root: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _init_repo(root: Path, branch: str = "main") -> str:
    subprocess.run(["git", "init", "-b", branch, str(root)], check=True, capture_output=True, text=True)
    _git(root, "config", "user.email", "tests@example.invalid")
    _git(root, "config", "user.name", "Tests")
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src/service.py").write_text("def status():\n    return 'old'\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "base")
    return _git(root, "rev-parse", "HEAD")


def _contract(root: Path) -> Path:
    intent = root / "intent.md"
    intent.write_text("A paid entitlement must restore and an expired entitlement must stay blocked.\n", encoding="utf-8")
    handoff = capture_intent_handoff(root, intent, AGENT, "control-intake", Path(".factory/oracles/handoffs/control.json"))
    source = _write(root / "oracle.json", {
        "schema": "factory.oracle-contract-input.v1", "id": "control-contract", "version": 1, "approved_by": "ReleaseOwner", "approval_rationale": "Strict restore outcome and negative path were reviewed.", "scope_paths": ["src"], "handoff": handoff["path"], "sources": [],
        "requirements": [{"id": "restore", "statement": "A valid entitlement restores.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "forbidden_behaviors": [{"id": "expired", "statement": "Expired access never restores.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "gates": [{"id": "restore-proof", "statement": "Observed restore proof meets the approved floor.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True, "comparison": "gte", "value": 95}],
        "exceptions": [{"id": "offline", "statement": "Offline behavior remains advisory until separately approved.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}],
        "negative_cases": [{"id": "expired-case", "statement": "Expired access is rejected.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "invariants": [{"id": "candidate", "statement": "Evidence binds the exact candidate.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "tests": [{"id": "restore-test", "statement": "The expired path fails.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "path": "tests/test_restore.py"}],
    })
    return root / seal_oracle_contract(root, source, Path(".factory/oracles/contracts/control.json"))["path"]


def test_operations_control_binds_isolation_repro_scope_and_local_heads(tmp_path: Path) -> None:
    base = _init_repo(tmp_path)
    _git(tmp_path, "checkout", "-b", "agent/control")
    (tmp_path / "src/service.py").write_text("def status():\n    return 'new'\n", encoding="utf-8")
    _git(tmp_path, "add", "src/service.py")
    _git(tmp_path, "commit", "-m", "candidate")
    head = _git(tmp_path, "rev-parse", "HEAD")
    _write(tmp_path / ".factory/journey-proof/failure.json", {"schema": "factory.failure-capsule.v1", "marker": "FAILURE_CAPSULE_BOUND"})
    _write(tmp_path / ".factory/e2e/repro.json", {"schema": "factory.e2e_proof_receipt.v1", "marker": "E2E_POSITIVE_FAILED", "ok": False})
    evidence = (tmp_path / "evidence.txt"); evidence.write_text("observed", encoding="utf-8")
    core_check = _write(tmp_path / "core-check.json", {"ok": True})
    manifest = _write(tmp_path / "operations.json", {"schema": "factory.operations-control-manifest.v1", "id": "control", "work_kind": "bug_fix", "base": base, "scope_paths": ["src"], "isolation": {"expected_branch": "agent/control", "expected_base_sha": base, "require_clean": False}, "reproduction": {"failure_capsule": ".factory/journey-proof/failure.json", "execution_receipt": ".factory/e2e/repro.json", "max_attempts": 2, "attempts_used": 1, "token_budget": 100, "observed_tokens": 10}, "change_envelope": {"purpose": "repair one behavior", "max_changed_files": 2, "max_changed_lines": 10}, "evidence": {"task_kind": "logic", "tier": "logs_metrics", "artifacts": ["evidence.txt"]}, "architecture": {"core_paths": ["src"], "interface_paths": ["web"], "core_check_receipts": ["core-check.json"]}, "coordination": {"repositories": [{"id": "primary", "path": ".", "expected_head_sha": head, "dependencies": []}]}})
    receipt = assess_operations_control(tmp_path, manifest)
    assert receipt["marker"] == "OPS_CONTROL_READY"
    assert receipt["reproduction"]["execution_receipt"]["reproduced"] is True
    assert operations_control_projection(tmp_path)["ready_count"] == 1


def test_lifecycle_requires_sealed_contract_hash_chain_and_explicit_session_trace(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    contract = _contract(tmp_path)
    contract_sha = json.loads(contract.read_text(encoding="utf-8"))["contract_sha256"]
    event = _write(tmp_path / "event.json", {"schema": "factory.lifecycle-event.v1", "event_id": "e1", "run_id": "run1", "sequence": 1, "event": "created", "actor": {"kind": "agent", "id": "control-worker"}, "oracle": {"contract_path": contract.relative_to(tmp_path).as_posix(), "contract_sha256": contract_sha}, "session_trace": {"session_id": "session1", "harness": "codex", "stage": "intake", "input_sha256": hashlib.sha256(b"input").hexdigest(), "output_sha256": hashlib.sha256(b"output").hexdigest()}, "evidence": [], "previous_receipt_sha256": None})
    first = record_lifecycle_event(tmp_path, event)
    assert first["session_trace_sha256"]
    second_payload = json.loads(event.read_text(encoding="utf-8")); second_payload.update({"event_id": "e2", "sequence": 2, "event": "isolated", "previous_receipt_sha256": first["receipt_sha256"]}); second_payload["session_trace"]["stage"] = "planning"; _write(event, second_payload)
    record_lifecycle_event(tmp_path, event)
    status = lifecycle_projection(tmp_path)
    assert status["latest"]["latest_session_trace"]["session_id"] == "session1"
    second_payload["sequence"] = 3; second_payload["event"] = "completed"; second_payload["previous_receipt_sha256"] = "0" * 64; _write(event, second_payload)
    with pytest.raises(LifecycleLedgerError) as raised:
        record_lifecycle_event(tmp_path, event)
    assert raised.value.code == "E_LIFECYCLE_CONTINUITY"


def test_mission_control_keeps_human_and_agent_paths_separate(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    state = mission_control_status(tmp_path)
    assert state["marker"] == "MISSION_CONTROL_READ_ONLY"
    assert state["human_control_plane"]["can_approve_here"] is False
    assert state["agent_control_plane"]["state"] == "supervised_only"
    assert all(value is False for value in state["authority"].values())


def test_repair_loop_binds_exact_issue_consequences_and_independent_rechecks(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    contract = _contract(tmp_path)
    files = {}
    for name in ("repro.json", "candidate.patch", "challenge.json", "positive.json", "negative.json"):
        path = tmp_path / name; path.write_text(name, encoding="utf-8"); files[name] = {"path": name, "sha256": _digest(path)}
    manifest = _write(tmp_path / "repair.json", {"schema": "factory.repair-loop-manifest.v1", "id": "restore-fix", "oracle": {"contract_path": contract.relative_to(tmp_path).as_posix(), "contract_sha256": json.loads(contract.read_text(encoding="utf-8"))["contract_sha256"]}, "issue": {"failure_code": "E_RESTORE_EXPIRED", "summary": "Expired accounts restore paid access.", "affected_obligations": ["restore", "expired-case"]}, "consequences": [{"kind": "security", "severity": "high", "rationale": "Expired users may receive paid access."}], "reproduction": files["repro.json"], "repair": {"candidate": files["candidate.patch"], "allowed_paths": ["src"]}, "independent_recheck": {"challenge_plan": files["challenge.json"], "positive_receipt": files["positive.json"], "negative_receipt": files["negative.json"]}, "human_review": {"required": True, "reviewer": "ReleaseOwner"}})
    receipt = assess_repair_loop(tmp_path, manifest)
    assert receipt["marker"] == "REPAIR_LOOP_READY"
    assert repair_loop_projection(tmp_path)["latest"]["highest_severity"] == "high"


def test_service_boundaries_ontology_and_multi_repo_plan_fail_closed(tmp_path: Path) -> None:
    for name in ("src/actions", "src/services", "src/adapters", "src/core"):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    (tmp_path / "src/actions/route.py").write_text("call_service()", encoding="utf-8")
    boundary = _write(tmp_path / "boundaries.json", {"schema": "factory.service-boundary-manifest.v1", "id": "layers", "actions_paths": ["src/actions"], "services_paths": ["src/services"], "adapters_paths": ["src/adapters"], "core_paths": ["src/core"], "forbidden_literals": [{"zone": "actions", "literal": "direct-db-client"}]})
    assert check_service_boundaries(tmp_path, boundary, ["src/actions/route.py"])["marker"] == "SERVICE_BOUNDARY_READY"
    ontology = _write(tmp_path / "ontology.json", {"schema": "factory.domain-ontology.v1", "id": "billing", "concepts": [{"id": "refund", "definition": "A reversal.", "owner": "billing", "invariants": ["Not proof of revocation."]}, {"id": "entitlement", "definition": "Access right.", "owner": "billing", "invariants": ["Revocation removes access."]}], "relationships": [{"subject": "refund", "predicate": "requires", "object": "entitlement"}]})
    assert validate_domain_ontology(tmp_path, ontology, ["refund"])["marker"] == "ONTOLOGY_READY"
    assert validate_domain_ontology(tmp_path, ontology, ["refund", "chargeback"])["marker"] == "ONTOLOGY_UNKNOWN_CONCEPT_BLOCKED"
    repos = tmp_path / "repos"; first, second = repos / "foundation", repos / "app"; foundation_head, app_head = _init_repo(first), _init_repo(second)
    plan = _write(tmp_path / "repos.json", {"schema": "factory.repo-coordination-manifest.v1", "id": "stack", "repositories": [{"id": "foundation", "path": "repos/foundation", "expected_head_sha": foundation_head, "depends_on": []}, {"id": "app", "path": "repos/app", "expected_head_sha": app_head, "depends_on": ["foundation"]}]})
    result = coordinate_repositories(tmp_path, plan)
    assert result["marker"] == "REPO_COORDINATION_READY"
    assert [item["id"] for item in result["sequence"]] == ["foundation", "app"]
