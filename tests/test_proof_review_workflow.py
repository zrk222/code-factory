from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.proof_reuse import record_proof
from factoryline.proof_review_workflow import (
    ProofReviewError,
    create_intent_contract,
    create_proof_card,
    create_quick_review,
    install_hook_pack,
    promote_regression,
    prove_trajectory,
    team_proof_inbox,
    verify_intent_contract,
    verify_proof_card,
    verify_quick_review,
    verify_trajectory,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _workspace(root: Path) -> tuple[Path, Path]:
    changed = root / "src" / "service.py"
    changed.parent.mkdir(parents=True, exist_ok=True)
    changed.write_text("answer = 42\n", encoding="utf-8")
    output = root / "proof.txt"
    output.write_text("passed\n", encoding="utf-8")
    _write_json(root / "coverage" / "requirements.json", {"requirements": [{"id": "REQ_SERVICE"}]})
    _write_json(root / "smoke" / "service.json", {"checks": [{"covers": ["REQ_SERVICE"], "must_fail_on_stub": True}]})
    record_proof(root, {
        "name": "service-unit", "command": ["python", "-m", "pytest"], "read_only": True,
        "inputs": ["src/service.py"], "outputs": ["proof.txt"],
    }, elapsed_ms=10, replace=True)
    draft = _write_json(root / "intent-draft.json", {
        "outcome": "Return the declared answer.",
        "acceptance": ["The service returns 42."],
        "rejection": ["The service returns any other value."],
        "validators": ["service-unit"],
        "allowed_paths": ["src"],
        "non_goals": ["Deploy the service."],
    })
    return changed, draft


def _contract(root: Path, contract_id: str = "service-intent") -> dict:
    _, draft = _workspace(root)
    return create_intent_contract(root, contract_id, draft, "Reviewer One")


def _session(root: Path, *, passed: bool) -> Path:
    directory = root / ".factory" / "session-recorder" / ("passed-run" if passed else "failed-run")
    directory.mkdir(parents=True, exist_ok=True)
    result_path = directory / "result.json"
    result_path.write_bytes(_canonical({
        "schema": "factory.session-recorder.result.v1",
        "workspace_delta": [{"path": "src/service.py", "status": "modified", "after_sha256": _sha(root / "src" / "service.py")}],
    }) + b"\n")
    verification_path = directory / "verification.json"
    verification_path.write_bytes(_canonical({"schema": "factory.session-recorder.validation.v1", "passed": passed}) + b"\n")
    core = {
        "schema": "factory.observed-session.v1", "marker": "OBSERVED_SESSION_RECORDED",
        "run_id": directory.name, "recorded_at": "2026-08-29T12:00:00Z", "previous_session_sha256": None,
        "result": {"path": result_path.relative_to(root).as_posix(), "sha256": _sha(result_path)},
        "verification": {"path": verification_path.relative_to(root).as_posix(), "sha256": _sha(verification_path)},
        "agent_event": {"path": ".factory/agent-licenses/events/fake.json", "sha256": "0" * 64},
        "passed": passed, "failure_classes": [] if passed else ["wrong_output"], "authority": {}, "scope_limits": [],
    }
    receipt = {**core, "session_sha256": sha256(_canonical(core)).hexdigest()}
    path = directory / "session.json"
    path.write_bytes(_canonical(receipt) + b"\n")
    return path


def _trajectory(root: Path, trajectory_id: str = "agent-run", *, independent: bool = True) -> dict:
    trace = _write_json(root / f"{trajectory_id}-trace.json", {
        "worker_actor": "worker",
        "events": [
            {"type": "intent_loaded", "actor": "worker"},
            {"type": "tool_used", "actor": "worker", "tool": "editor", "path": "src/service.py"},
            {"type": "validation_observed", "actor": "worker", "tool": "pytest"},
            {"type": "independent_audit", "actor": "verifier" if independent else "worker"},
        ],
    })
    policy = _write_json(root / f"{trajectory_id}-policy.json", {
        "max_steps": 20,
        "required_events": ["intent_loaded", "tool_used", "validation_observed", "independent_audit"],
        "allowed_tools": ["editor", "pytest"], "forbidden_tools": ["deploy"], "allowed_paths": ["src"],
    })
    return prove_trajectory(root, trace, policy, trajectory_id)


def test_req_pr_001_intent_contract_is_complete_confirmed_bound_and_immutable(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    assert verify_intent_contract(tmp_path, Path(contract["artifact"]))["ok"] is True
    assert contract["human_confirmed"] is True and contract["final_approval"] is False
    with pytest.raises(ProofReviewError, match="immutable"):
        create_intent_contract(tmp_path, "service-intent", tmp_path / "intent-draft.json", "Reviewer One")
    (tmp_path / "intent-draft.json").write_text("{}", encoding="utf-8")
    assert verify_intent_contract(tmp_path, Path(contract["artifact"]))["marker"] == "INTENT_CONTRACT_STALE"


def test_req_pr_002_five_minute_review_has_exact_fail_closed_routes(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    missing = create_quick_review(tmp_path, "missing-evidence", Path(contract["artifact"]), ["src/service.py"])
    assert missing["route"] == "evidence_required"
    passed = create_quick_review(tmp_path, "passing-evidence", Path(contract["artifact"]), ["src/service.py"], session_path=_session(tmp_path, passed=True))
    assert passed["route"] == "review_ready"
    assert passed["final_approval"] is False
    assert verify_quick_review(tmp_path, Path(passed["artifact"]))["ok"] is True


def test_req_pr_003_hook_pack_writes_five_templates_without_vendor_mutation(tmp_path: Path) -> None:
    vendor = _write_json(tmp_path / ".cursor" / "hooks.json", {"keep": True})
    before = vendor.read_bytes()
    pack = install_hook_pack(tmp_path)
    assert pack["adapters"] == ["github-copilot", "claude-code", "codex", "cursor", "generic-jsonl"]
    assert pack["installed_vendor_config"] is False and vendor.read_bytes() == before
    target = tmp_path / ".factory" / "proof-review" / "hooks" / "cursor.json"
    target.write_text("changed", encoding="utf-8")
    with pytest.raises(ProofReviewError, match="refusing to overwrite"):
        install_hook_pack(tmp_path)


def test_req_pr_004_failure_learning_requires_human_and_is_immutable(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    failed = create_quick_review(tmp_path, "failed-evidence", Path(contract["artifact"]), ["src/service.py"], session_path=_session(tmp_path, passed=False))
    with pytest.raises(ProofReviewError, match="named confirmer"):
        promote_regression(tmp_path, Path(failed["artifact"]), "wrong-answer", "", "Wrong answer")
    capsule = promote_regression(tmp_path, Path(failed["artifact"]), "wrong-answer", "Reviewer Two", "Wrong answer")
    assert capsule["failure_classes"] == ["wrong_output"] and capsule["human_confirmed"] is True
    with pytest.raises(ProofReviewError, match="immutable"):
        promote_regression(tmp_path, Path(failed["artifact"]), "wrong-answer", "Reviewer Two", "Wrong answer")


def test_req_pr_005_team_inbox_prioritizes_human_work_and_keeps_claim_limits(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    create_quick_review(tmp_path, "needs-evidence", Path(contract["artifact"]), ["src/service.py"])
    create_quick_review(tmp_path, "failed-evidence", Path(contract["artifact"]), ["src/service.py"], session_path=_session(tmp_path, passed=False))
    inbox = team_proof_inbox(tmp_path)
    assert inbox["current_count"] == 2 and inbox["next_item"]["route"] == "human_required"
    assert "not unique users" in inbox["claim_limits"][0]


def test_req_pr_006_trajectory_enforces_order_scope_tools_and_independent_audit(tmp_path: Path) -> None:
    _workspace(tmp_path)
    passed = _trajectory(tmp_path)
    assert passed["passed"] is True and verify_trajectory(tmp_path, Path(passed["artifact"]))["passed"] is True
    failed = _trajectory(tmp_path, "self-audited", independent=False)
    assert failed["passed"] is False
    assert "independent_audit" in {item["kind"] for item in failed["violations"]}


def test_req_pr_007_card_is_public_safe_and_offline_tamper_evident(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    review = create_quick_review(tmp_path, "card-review", Path(contract["artifact"]), ["src/service.py"])
    card = create_proof_card(tmp_path, Path(review["artifact"]), "public-card")
    assert set(card["artifacts"]) == {"json", "markdown", "svg"}
    assert verify_proof_card(Path(card["artifacts"]["json"]))["ok"] is True
    path = Path(card["artifacts"]["json"])
    value = json.loads(path.read_text(encoding="utf-8"))
    value["route"] = "review_ready"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert verify_proof_card(path)["ok"] is False


def test_req_pr_008_graph_ops_projects_read_only_team_inbox(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    create_quick_review(tmp_path, "graph-review", Path(contract["artifact"]), ["src/service.py"])
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["proof_review"]["current_count"] == 1
    assert snapshot["facts"]["proof_review_current_count"] == 1
    assert "GRAPH_OPS_PROOF_REVIEW_READ_ONLY" in snapshot["markers"]


def test_req_pr_009_paths_are_workspace_contained_and_large_inputs_fail_closed(tmp_path: Path) -> None:
    _workspace(tmp_path)
    outside = tmp_path.parent / "outside-intent.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ProofReviewError, match="inside the workspace"):
        create_intent_contract(tmp_path, "outside", outside, "Reviewer")
    large = tmp_path / "large.json"
    large.write_bytes(b"x" * 1_048_577)
    with pytest.raises(ProofReviewError, match="no larger"):
        create_intent_contract(tmp_path, "large", large, "Reviewer")


def test_req_pr_010_cli_is_one_machine_readable_front_door_without_regression(tmp_path: Path, capsys) -> None:
    _, draft = _workspace(tmp_path)
    assert main(["proof-review", "contract", "--root", str(tmp_path), "--id", "cli-intent", "--draft", str(draft), "--confirmed-by", "Reviewer", "--json"]) == 0
    contract = json.loads(capsys.readouterr().out)
    assert main(["proof-review", "quick", "--root", str(tmp_path), "--id", "cli-review", "--contract", contract["artifact"], "--changed", "src/service.py", "--json"]) == 0
    review = json.loads(capsys.readouterr().out)
    assert review["route"] == "evidence_required"
    assert main(["proof-review", "verify", review["artifact"], "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
