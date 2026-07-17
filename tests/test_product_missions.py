from __future__ import annotations

from pathlib import Path
import json

import pytest

from factoryline.product_missions import (
    ProductMissionError,
    compile_product_prd,
    close_mission,
    create_mission,
    decide_mission,
    draft_pr,
    outcome_summary,
    plan_value_slices,
    record_outcome,
    verify_mission,
    verify_mission_completion,
    verify_product_graph,
)
from factoryline.meter import MeterLog, StageTiming, live_snapshot
from factoryline.cli import main


PRD = """# Signal Desk

## Actors
- Operator: reviews customer signals.

## Outcomes
- Reduce signal triage time below five minutes.

## Jobs and pains
- Job: prioritize incoming customer signals.
- Pain: fragmented context slows the operator.

## Journeys and business rules
- Journey: capture a signal, review its priority reason, then export the audit report.
- Business rule: private signals require an authenticated operator.

## Data ownership and trust boundaries
- Data ownership: the workspace owner controls retention, export, and deletion.
- Trust boundary: signal content stays inside the selected workspace.

## External effects and approvals
- External effect: exporting a report writes a user-selected local file.
- Approval: publishing, deployment, credentials, and external messages require a human owner.

## Success events
- signal_review_completed within five minutes.

## Requirements
- REQ-LOGIN: The operator must log in before viewing private signals.
- REQ-DASH: The dashboard must show prioritized signals and depends on REQ-LOGIN.
- REQ-EXPORT: The operator must export an audit report for a selected signal.

## Experience states
- Loading: show progress without moving the dashboard layout.
- Empty: explain how to connect the first signal source.
- Error: preserve the last safe view and offer retry.
- Success: confirm the completed action.
- Permission: explain which role is required.
- Offline: preserve read-only cached signals.
- Recovery: resume the interrupted action without duplication.
- Accessibility: expose names, roles, focus order, and keyboard operation.

## Acceptance
Scenario: Review the most important signal
  Given an authenticated operator with prioritized signals
  When the operator opens the dashboard
  Then the highest-priority signal is visible with its reason
"""


def _pipeline(tmp_path: Path):
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD, encoding="utf-8")
    graph = compile_product_prd(prd, tmp_path)
    slices = plan_value_slices(Path(graph["path"]), tmp_path, max_requirements=2)
    mission = create_mission(Path(slices["path"]), slices["slices"][-1]["id"], tmp_path, "release-owner")
    return graph, slices, mission


def test_product_graph_is_stable_bound_and_ux_complete(tmp_path: Path):
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD, encoding="utf-8")
    first = compile_product_prd(prd, tmp_path)
    second = compile_product_prd(prd, tmp_path)
    assert second["idempotent"] is True
    assert first["graph_sha256"] == second["graph_sha256"]
    assert [item["id"] for item in first["requirements"]] == ["REQ-LOGIN", "REQ-DASH", "REQ-EXPORT"]
    assert set(first["ux_states"].values()) == {"declared"}
    assert first["journeys"] and first["business_rules"]
    assert first["data_ownership"] and first["trust_boundaries"]
    assert first["external_effects"] and first["approval_requirements"]
    assert first["success_events"] == ["signal_review_completed within five minutes."]
    assert verify_product_graph(Path(first["path"]))["valid"] is True


def _validation_for(mission: dict, creator: str, verifier: str, evidence: Path) -> dict:
    criteria = []
    for item in mission["completion_contract"]["criteria"]:
        proof = evidence
        if item.get("verification_kind") == "browser_control":
            screenshot = evidence.parent / "browser-flow.png"
            screenshot.write_bytes(b"png evidence")
            proof = evidence.parent / "browser-flow.json"
            proof.write_text(json.dumps({
                "schema": "factory.browser-flow.evidence.v1",
                "mission_id": mission["id"],
                "criterion_id": item["id"],
                "verifier_id": verifier,
                "start_url": "http://127.0.0.1:3000/",
                "expected_url": "http://127.0.0.1:3000/dashboard",
                "observed_url": "http://127.0.0.1:3000/dashboard",
                "clicks": 2,
                "steps": [{"action": "open", "passed": True}, {"action": "submit", "passed": True}],
                "assertions": [{"name": "dashboard visible", "passed": True}],
                "artifacts": [str(screenshot)],
            }), encoding="utf-8")
        criteria.append({"id": item["id"], "passed": True, "evidence": [str(proof)]})
    return {
        "schema": "factory.mission.validation-input.v1",
        "creator_id": creator,
        "verifier_id": verifier,
        "verifier_context": ["mission.json", "candidate_diff", "evidence_manifest"],
        "criteria": criteria,
    }


def test_mission_completion_requires_fresh_context_and_all_evidence(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    assert mission["orchestration"]["context_wall"]["same_identity_allowed"] is False
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n')
    validation = tmp_path / "validation.json"
    validation.write_text(json.dumps(_validation_for(mission, "worker-1", "worker-1", evidence)))
    with pytest.raises(ProductMissionError, match="VERIFIER_IDENTITY_DISTINCT"):
        close_mission(Path(mission["path"]), validation, tmp_path)
    assert not (Path(mission["path"]).parent / "completion.json").exists()

    incomplete = _validation_for(mission, "worker-1", "verifier-1", evidence)
    incomplete["criteria"].pop()
    validation.write_text(json.dumps(incomplete))
    with pytest.raises(ProductMissionError, match="NO_FINISH_CONTRACT"):
        close_mission(Path(mission["path"]), validation, tmp_path)

    validation.write_text(json.dumps(_validation_for(mission, "worker-1", "verifier-1", evidence)))
    completion = close_mission(Path(mission["path"]), validation, tmp_path)
    assert completion["status"] == "completed"
    assert completion["creator_id"] != completion["verifier_id"]
    assert verify_mission_completion(Path(completion["path"]))["valid"] is True
    evidence.write_text('{"passed": false}\n')
    check = verify_mission_completion(Path(completion["path"]))
    assert check["valid"] is False
    assert check["marker"] == "MISSION_COMPLETION_DRIFT"


def test_browser_control_is_a_bounded_no_finish_criterion(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    browser = next(item for item in mission["completion_contract"]["criteria"] if item["verification_kind"] == "browser_control")
    assert browser["evidence_contract"]["max_clicks"] == 3
    assert mission["completion_contract"]["hypotheses"]
    assert mission["orchestration"]["attempt_policy"]["fresh_session_required"] is True
    assert mission["orchestration"]["routing_policy"]["provider_binding"] == "external_adapter_required"
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n')
    payload = _validation_for(mission, "worker", "verifier", evidence)
    browser_row = next(item for item in payload["criteria"] if item["id"] == browser["id"])
    browser_path = Path(browser_row["evidence"][0])
    receipt = json.loads(browser_path.read_text(encoding="utf-8"))
    receipt["clicks"] = 4
    receipt["steps"].extend([{"action": "extra", "passed": True}] * 2)
    browser_path.write_text(json.dumps(receipt), encoding="utf-8")
    validation = tmp_path / "validation-browser.json"
    validation.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ProductMissionError, match="BROWSER_FLOW_INVALID"):
        close_mission(Path(mission["path"]), validation, tmp_path)


def test_mission_decision_is_owner_bound_and_cannot_authorize_release(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    with pytest.raises(ProductMissionError, match="MISSION_DECISION_OWNER_MISMATCH"):
        decide_mission(
            Path(mission["path"]), tmp_path, owner="someone-else",
            decision="approved_execution", rationale="Approve.",
        )
    decision = decide_mission(
        Path(mission["path"]), tmp_path, owner="release-owner",
        decision="approved_execution", rationale="The bounded slice is ready for its executor.",
    )
    assert decision["execution_authorized"] is True
    assert decision["authority"] == {
        "execute_bounded_mission": True,
        "merge": False,
        "publish": False,
        "deploy": False,
        "external_message": False,
        "connector_grant": False,
        "credential_access": False,
    }


def test_product_graph_blocks_slicing_when_acceptance_is_missing(tmp_path: Path):
    prd = tmp_path / "thin.md"
    prd.write_text("# Thin\n\n## Requirements\n- The system must save a draft.\n", encoding="utf-8")
    graph = compile_product_prd(prd, tmp_path)
    assert graph["status"] == "needs_input"
    with pytest.raises(ProductMissionError, match="MISSION_BLOCKED_BY_PRODUCT_GAPS"):
        plan_value_slices(Path(graph["path"]), tmp_path)
    assert not list((tmp_path / ".factory" / "missions").glob("**/*"))


def test_value_slices_cover_every_requirement_once_and_preserve_dependencies(tmp_path: Path):
    graph, slices, _mission = _pipeline(tmp_path)
    assigned = [req for item in slices["slices"] for req in item["requirement_ids"]]
    assert sorted(assigned) == sorted(item["id"] for item in graph["requirements"])
    assert len(assigned) == len(set(assigned))
    owner = {req: item["id"] for item in slices["slices"] for req in item["requirement_ids"]}
    dash = next(item for item in slices["slices"] if "REQ-DASH" in item["requirement_ids"])
    if owner["REQ-DASH"] != owner["REQ-LOGIN"]:
        assert owner["REQ-LOGIN"] in dash["depends_on"]
    assert all(set(item["score"]) == {
        "user_value", "uncertainty_retired", "dependency_unlock",
        "security_change_risk", "implementation_review_cost", "priority",
    } for item in slices["slices"])
    assert all(set(item["vertical_contract"]) == {
        "ui", "behavior", "api_data", "tests", "observability", "rollback",
    } for item in slices["slices"])
    assert [item["score"]["priority"] for item in slices["slices"]] == sorted(
        (item["score"]["priority"] for item in slices["slices"]), reverse=True,
    )


def test_mission_is_supervised_budgeted_and_hash_bound(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    assert mission["approval_state"] == "required_before_execution"
    assert mission["authority"] == {
        "execute": "human_approval", "merge": False, "publish": False,
        "deploy": False, "external_message": False,
    }
    assert mission["loop"]["verdict"] == "VERIFIED"
    assert mission["workspace_contract"]["mode"] == "worktree"
    assert mission["workspace_contract"]["count"] == 1
    assert mission["workspace_contract"]["branch"].startswith("codex/")
    assert set(mission["role_permissions"]) == {"builder", "checker", "ux_reviewer"}
    assert mission["context_packet"]["requirement_ids"] == mission["slice"]["requirement_ids"]
    assert verify_mission(Path(mission["path"]))["valid"] is True


def test_mission_refuses_excess_budget_and_detects_input_drift(tmp_path: Path):
    _graph, slices, mission = _pipeline(tmp_path)
    with pytest.raises(ProductMissionError, match="MISSION_BUDGET_INVALID"):
        create_mission(Path(slices["path"]), slices["slices"][0]["id"], tmp_path, "owner", max_tokens=100001)
    graph_path = Path(mission["inputs"]["graph_path"])
    graph_path.write_text(graph_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    result = verify_mission(Path(mission["path"]))
    assert result["valid"] is False
    assert result["marker"] == "MISSION_INPUT_DRIFT"


def test_pr_draft_links_local_evidence_but_has_no_promotion_authority(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    draft = draft_pr(Path(mission["path"]), tmp_path, [evidence])
    assert draft["evidence"][0]["sha256"]
    assert draft["before_after"]["before"] != draft["before_after"]["after"]
    assert draft["requirement_coverage"]["added"] == draft["requirements"]
    assert draft["architecture_changes"] and draft["data_contract_changes"]
    assert draft["budget_consumption"]["measured"] is None
    assert set(draft["review_evidence"]) == {
        "screenshots", "responsive", "accessibility", "tests", "mutations", "gates", "traces",
    }
    assert draft["outcome_events"] == ["signal_review_completed within five minutes."]
    assert all(value is False for key, value in draft["authority"].items() if key != "draft_only")
    assert draft["authority"]["draft_only"] is True
    outside = tmp_path.parent / "outside-evidence.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        with pytest.raises(ProductMissionError, match="EVIDENCE_OUTSIDE_ROOT"):
            draft_pr(Path(mission["path"]), tmp_path, [outside], force=True)
    finally:
        outside.unlink(missing_ok=True)


def test_outcomes_preserve_evidence_class_and_hash_chain(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    with pytest.raises(ProductMissionError, match="MEASURED_SOURCE_REQUIRED"):
        record_outcome(Path(mission["path"]), tmp_path, "completion_rate", 0.8, 0.7, "measured")
    first = record_outcome(Path(mission["path"]), tmp_path, "completion_rate", 0.8, 0.7, "measured", "analytics/run-42")
    second = record_outcome(Path(mission["path"]), tmp_path, "qualitative_fit", None, None, "observed", "research/session-7")
    assert second["previous_sha256"] == first["record_sha256"]
    summary = outcome_summary(tmp_path, mission["id"])
    assert summary["chain_valid"] is True
    assert summary["evidence_classes"]["measured"] == 1
    log = Path(first["path"])
    rows = log.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(rows[0])
    tampered["value"] = 0.1
    rows[0] = json.dumps(tampered, sort_keys=True)
    log.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert outcome_summary(tmp_path, mission["id"])["chain_valid"] is False


def test_requirement_change_invalidates_existing_mission(tmp_path: Path):
    graph, _slices, mission = _pipeline(tmp_path)
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD.replace("prioritized signals", "ranked customer signals"), encoding="utf-8")
    changed = compile_product_prd(prd, tmp_path, force=True)
    assert changed["graph_sha256"] != graph["graph_sha256"]
    assert verify_mission(Path(mission["path"]))["valid"] is False


def test_requirement_change_invalidates_stale_slice_plan_before_new_mission(tmp_path: Path):
    graph, slices, _mission = _pipeline(tmp_path)
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD.replace("REQ-EXPORT:", "REQ-ARCHIVE:"), encoding="utf-8")
    changed = compile_product_prd(prd, tmp_path, force=True)
    assert changed["graph_sha256"] != graph["graph_sha256"]
    with pytest.raises(ProductMissionError, match="MISSION_INPUT_DRIFT"):
        create_mission(Path(slices["path"]), slices["slices"][0]["id"], tmp_path, "owner")


def test_meter_v2_preserves_unknowns_and_computes_complete_flow(tmp_path: Path):
    MeterLog(tmp_path).record(StageTiming(
        "factoryline", "compile-product", 100, 1, 600, 400, True,
        mission_id="mission-1", queue_ms=50, human_review_ms=25,
        rework_lines=3, cache_hits=2, invalidated_stages=1,
        outcome_status="achieved", usage_quality="exact",
        agent_ms=60, deterministic_tool_ms=40, changed_lines=30,
        replay_hits=1, model_calls_avoided=2, first_pass=True,
        retry_count=0, requirements_accepted=2, cost_usd=0.02,
        cost_quality="exact", escaped_defects=0, releases=1, rollbacks=0,
    ))
    snapshot = live_snapshot(tmp_path)
    flow = snapshot["summary"]["flow"]
    assert snapshot["schema"] == "factory.meter.live.v2"
    assert flow["flow_efficiency"] == 0.5714
    assert flow["queue_ms"] == {"value": 50, "known": 1, "unknown": 0}
    assert flow["agent_ms"]["value"] == 60
    assert flow["deterministic_tool_ms"]["value"] == 40
    assert flow["rework_ratio"] == 0.1
    assert flow["first_pass_gate_rate"]["value"] == 1.0
    assert flow["requirements_per_token"] == 0.002
    assert flow["requirements_per_engineering_hour"] == 57600.0
    assert flow["rollback_rate"] == 0.0
    assert flow["token_quality"] == {"exact": 1, "estimated": 0, "unknown": 0}
    assert flow["cost_quality"] == {"exact": 1, "estimated": 0, "unknown": 0}
    legacy = tmp_path / "legacy"
    MeterLog(legacy).record(StageTiming("factoryline", "legacy", 10, 0, 0, 0, True))
    assert live_snapshot(legacy)["summary"]["flow"]["queue_ms"]["value"] is None


def test_product_mission_cli_runs_the_local_compile_chain(tmp_path: Path, capsys):
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD, encoding="utf-8")
    assert main(["product", "compile", str(prd), "--root", str(tmp_path), "--json"]) == 0
    graph = json.loads(capsys.readouterr().out)
    assert main(["product", "verify", graph["path"], "--json"]) == 0
    capsys.readouterr()
    assert main(["product", "slices", graph["path"], "--root", str(tmp_path), "--json"]) == 0
    slices = json.loads(capsys.readouterr().out)
    assert main([
        "mission", "create", slices["path"], slices["slices"][0]["id"],
        "--root", str(tmp_path), "--owner", "cli-owner", "--executor", "codex", "--json",
    ]) == 0
    mission = json.loads(capsys.readouterr().out)
    assert main(["mission", "verify", mission["path"], "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
