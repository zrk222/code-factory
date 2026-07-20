from __future__ import annotations

from pathlib import Path
import json

import pytest

from factoryline.mission_graph import (
    MissionGraphError,
    apply_mission_event,
    build_langgraph_adapter,
    export_mission_graph,
    init_mission_graph,
    langgraph_doctor,
    mission_graph_history,
    mission_graph_status,
    recommend_mission_route,
    verify_mission_graph,
)
from factoryline.product_missions import (
    close_mission,
    compile_product_prd,
    create_mission,
    decide_mission,
    plan_value_slices,
)


PRD = """# Graph Runtime Fixture

## Actors
- Maintainer: owns the migration contract.

## Outcomes
- Preserve deterministic package behavior.

## Requirements
- REQ-COMPILE: The compiler must preserve deterministic package behavior.

## Acceptance
Scenario: Compile the migrated package
  Given a clean source tree
  When the package is compiled twice
  Then both artifact hashes are identical
"""


def _pipeline(tmp_path: Path, **budgets):
    tmp_path.mkdir(parents=True, exist_ok=True)
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD, encoding="utf-8")
    graph = compile_product_prd(prd, tmp_path)
    slices = plan_value_slices(Path(graph["path"]), tmp_path)
    return create_mission(
        Path(slices["path"]), slices["slices"][0]["id"], tmp_path,
        "mission-owner", **budgets,
    )


def _receipt(tmp_path: Path, name: str, schema: str, mission_id: str, **values) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"schema": schema, "mission_id": mission_id, **values}), encoding="utf-8")
    return path


def _completion(tmp_path: Path, mission: dict, creator: str, verifier: str) -> Path:
    evidence = tmp_path / f"evidence-{creator}.json"
    evidence.write_text('{"passed":true}\n', encoding="utf-8")
    validation = tmp_path / f"validation-{creator}.json"
    validation.write_text(json.dumps({
        "schema": "factory.mission.validation-input.v1",
        "creator_id": creator,
        "verifier_id": verifier,
        "verifier_context": ["mission.json", "candidate_diff", "evidence_manifest"],
        "criteria": [
            {"id": item["id"], "passed": True, "evidence": [str(evidence)]}
            for item in mission["completion_contract"]["criteria"]
        ],
    }), encoding="utf-8")
    return Path(close_mission(Path(mission["path"]), validation, tmp_path)["path"])


def _approve(tmp_path: Path, mission: dict) -> Path:
    return Path(decide_mission(
        Path(mission["path"]), tmp_path, owner="mission-owner",
        decision="approved_execution", rationale="The bounded plan is ready.",
    )["path"])


def test_native_graph_resumes_through_correction_and_completion(tmp_path: Path):
    mission = _pipeline(tmp_path)
    initialized = init_mission_graph(Path(mission["path"]), tmp_path)
    assert initialized["state"] == "planned"
    assert initialized["marker"] == "MISSION_GRAPH_INITIALIZED"
    assert initialized["milestone_progress"]["total"] == len(mission["completion_contract"]["criteria"])

    approved = apply_mission_event(
        Path(mission["path"]), tmp_path, "approve", "mission-owner", "owner", "approve-1", _approve(tmp_path, mission),
    )
    assert approved["state"] == "creator_running"
    candidate_1 = _receipt(tmp_path, "candidate-1.json", "factory.mission.candidate.v1", mission["id"])
    apply_mission_event(
        Path(mission["path"]), tmp_path, "candidate_ready", "worker-1", "worker", "candidate-1", candidate_1,
    )
    failed = _receipt(tmp_path, "failed.json", "factory.mission.validation-failure.v1", mission["id"])
    criterion_id = mission["completion_contract"]["criteria"][0]["id"]
    result = apply_mission_event(
        Path(mission["path"]), tmp_path, "validation_failed", "verifier-1", "validator", "failed-1", failed,
        {"criterion_id": criterion_id},
    )
    assert result["state"] == "correction_required"
    retry = _receipt(tmp_path, "retry.json", "factory.mission.retry.v1", mission["id"])
    result = apply_mission_event(
        Path(mission["path"]), tmp_path, "retry", "mission-owner", "owner", "retry-1", retry,
        {"fresh_context": True},
    )
    assert result["state"] == "creator_running"
    assert result["attempts"] == 2
    candidate_2 = _receipt(tmp_path, "candidate-2.json", "factory.mission.candidate.v1", mission["id"])
    apply_mission_event(
        Path(mission["path"]), tmp_path, "candidate_ready", "worker-2", "worker", "candidate-2", candidate_2,
    )
    completion = _completion(tmp_path, mission, "worker-2", "verifier-2")
    result = apply_mission_event(
        Path(mission["path"]), tmp_path, "validation_passed", "verifier-2", "validator", "passed-2", completion,
    )
    assert result["state"] == "completion_receipted"
    assert result["milestone_progress"]["passed"] == result["milestone_progress"]["total"]
    assert mission_graph_status(Path(mission["path"]), tmp_path)["version"] == 6
    assert len(mission_graph_history(Path(mission["path"]), tmp_path)["events"]) == 6
    assert verify_mission_graph(Path(mission["path"]), tmp_path)["valid"] is True


def test_native_graph_rejects_replay_role_confusion_and_receipt_drift(tmp_path: Path):
    mission = _pipeline(tmp_path)
    decision = _approve(tmp_path, mission)
    first = apply_mission_event(
        Path(mission["path"]), tmp_path, "approve", "mission-owner", "owner", "same-key", decision,
    )
    duplicate = apply_mission_event(
        Path(mission["path"]), tmp_path, "approve", "mission-owner", "owner", "same-key", decision,
    )
    assert duplicate["marker"] == "MISSION_GRAPH_IDEMPOTENT"
    assert duplicate["version"] == first["version"]
    candidate = _receipt(tmp_path, "candidate.json", "factory.mission.candidate.v1", mission["id"])
    with pytest.raises(MissionGraphError, match="MISSION_GRAPH_IDEMPOTENCY_CONFLICT"):
        apply_mission_event(
            Path(mission["path"]), tmp_path, "candidate_ready", "worker", "worker", "same-key", candidate,
        )
    apply_mission_event(
        Path(mission["path"]), tmp_path, "candidate_ready", "worker", "worker", "candidate", candidate,
    )
    failure = _receipt(tmp_path, "failure.json", "factory.mission.validation-failure.v1", mission["id"])
    with pytest.raises(MissionGraphError, match="MISSION_GRAPH_VERIFIER_NOT_DISTINCT"):
        apply_mission_event(
            Path(mission["path"]), tmp_path, "validation_failed", "worker", "validator", "self-verify", failure,
            {"criterion_id": mission["completion_contract"]["criteria"][0]["id"]},
        )
    candidate.write_text('{"schema":"factory.mission.candidate.v1","mission_id":"tampered"}', encoding="utf-8")
    assert verify_mission_graph(Path(mission["path"]), tmp_path)["marker"] == "MISSION_GRAPH_DRIFT"


def test_native_budget_kill_switch_and_route_are_measured(tmp_path: Path):
    mission = _pipeline(tmp_path, max_cost_usd=1.0)
    apply_mission_event(
        Path(mission["path"]), tmp_path, "approve", "mission-owner", "owner", "approve", _approve(tmp_path, mission),
    )
    usage = _receipt(
        tmp_path, "usage.json", "factory.mission.usage.v1", mission["id"],
        evidence_class="measured", tokens=None, cost_usd=1.0, wall_seconds=2.0,
    )
    result = apply_mission_event(
        Path(mission["path"]), tmp_path, "usage_recorded", "worker", "worker", "usage", usage,
    )
    assert result["state"] == "budget_exhausted"
    assert result["marker"] == "MISSION_GRAPH_BUDGET_ENFORCED"
    candidate = _receipt(tmp_path, "candidate.json", "factory.mission.candidate.v1", mission["id"])
    with pytest.raises(MissionGraphError, match="MISSION_GRAPH_TRANSITION_INVALID"):
        apply_mission_event(
            Path(mission["path"]), tmp_path, "candidate_ready", "worker", "worker", "candidate", candidate,
        )

    fresh = _pipeline(tmp_path / "route")
    route = recommend_mission_route(Path(fresh["path"]), tmp_path / "route", "high")
    assert route["tier"] == "frontier"
    assert route["provider_or_model"] is None
    assert route["marker"] == "MISSION_GRAPH_ROUTING_EXPLAINED"


def test_native_owner_can_pause_bind_a_plan_and_resume_fresh(tmp_path: Path):
    mission = _pipeline(tmp_path)
    apply_mission_event(
        Path(mission["path"]), tmp_path, "approve", "mission-owner", "owner", "approve", _approve(tmp_path, mission),
    )
    pause = _receipt(tmp_path, "pause.json", "factory.mission.human-interrupt.v1", mission["id"])
    result = apply_mission_event(
        Path(mission["path"]), tmp_path, "pause", "mission-owner", "owner", "pause", pause,
    )
    assert result["state"] == "paused_for_review"
    plan = _receipt(tmp_path, "plan.json", "factory.mission.plan-revision.v1", mission["id"])
    apply_mission_event(
        Path(mission["path"]), tmp_path, "plan_revised", "mission-owner", "owner", "plan", plan,
    )
    result = apply_mission_event(
        Path(mission["path"]), tmp_path, "resume", "mission-owner", "owner", "resume", plan,
        {"fresh_context": True},
    )
    assert result["state"] == "creator_running"
    assert result["creator_id"] is None
    assert result["plan_receipt"]["sha256"]
    exported = export_mission_graph(Path(mission["path"]), tmp_path)
    assert exported["marker"] == "MISSION_GRAPH_MERMAID_EXPORTED"
    assert Path(exported["path"]).is_file()


def test_langgraph_adapter_checkpoints_native_transition(tmp_path: Path):
    mission = _pipeline(tmp_path)
    doctor = langgraph_doctor()
    if not doctor["ready"]:
        pytest.skip("requires both langgraph and langgraph-checkpoint-sqlite")
    graph = build_langgraph_adapter(Path(mission["path"]), tmp_path)
    config = {"configurable": {"thread_id": mission["id"]}}
    result = graph.invoke({
        "event": "approve",
        "actor": "mission-owner",
        "role": "owner",
        "idempotency_key": "langgraph-approve",
        "receipt_path": str(_approve(tmp_path, mission)),
        "payload": {},
    }, config=config)
    assert result["result"]["state"] == "creator_running"
    assert result["result"]["adapter_marker"] == "LANGGRAPH_ADAPTER_BOUND"
    assert graph.get_state(config).values["result"]["version"] == 1
    assert mission_graph_status(Path(mission["path"]), tmp_path)["version"] == 1
