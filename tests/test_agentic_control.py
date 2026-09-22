from __future__ import annotations

import subprocess
import json
import hashlib

import pytest
from factoryline.cli import main

from factoryline.agentic_control import (
    AgenticControlError,
    agentic_control_projection,
    build_extended_assurance_receipt,
    compare_agentic_control_drift,
    compile_reusable_workflow,
    create_route_trace,
    create_sandbox_boundary,
    create_typed_handoff,
    load_cookbook_recipe,
    new_swimlane_event,
    route_model,
    verify_model_route,
    verify_route_trace,
    verify_reusable_workflow,
    verify_sandbox_boundary,
    verify_swimlane,
    verify_typed_handoff,
    verify_extended_assurance_receipt,
    verify_agentic_control_drift,
    create_capability_registry,
    verify_capability_registry,
    create_task_card,
    transition_task_card,
    verify_task_card,
    project_task_board,
    verify_task_board,
    bind_task_card_handoff,
    verify_task_card_handoff,
    align_candidate_to_task,
    verify_candidate_alignment,
    create_orchestrator_plan,
    verify_orchestrator_plan,
)


SHA = "a" * 64


def test_model_route_is_deterministic_and_tiered() -> None:
    route = route_model("routine", latency_budget_ms=1000)
    assert route["tier"] == "lightweight"
    assert verify_model_route(route)["route_sha256"] == route["route_sha256"]
    assert route_model("standard")["tier"] == "workhorse"
    assert route_model("critical", risk="critical")["tier"] == "frontier"
    assert route_model("standard") == route_model("standard")


def test_model_route_receipt_rejects_tampering_and_unknown_tiers() -> None:
    route = route_model("standard")
    tampered = dict(route, tier="frontier")
    with pytest.raises(AgenticControlError, match="digest"):
        verify_model_route(tampered)
    with pytest.raises(AgenticControlError, match="model_tier"):
        create_orchestrator_plan(
            {
                "goal": "route a bounded repair",
                "intent_digest": SHA,
                "capability_registry_sha256": SHA,
                "workflow_ids": ["workflow:repair"],
                "recipe_names": ["quality-audit"],
                "task_ids": ["task:repair"],
                "model_tier": "unbounded",
                "stop_condition": "stop at missing approval",
                "approval_required": True,
            }
        )


def test_capability_registry_is_hash_bound_and_cannot_grant_authority() -> None:
    registry = create_capability_registry(
        "factory-core", "1.0.0", [
            {
                "id": "planner",
                "role": "planner",
                "risk_class": "medium",
                "allowed_tools": ["factory plan verify"],
                "forbidden_tools": ["git push"],
                "allowed_paths": ["plans/", "specs/"],
                "model_tier": "frontier",
                "stop_condition": "Stop after a reviewed plan is emitted.",
                "approval_required": True,
                "required_evidence": ["intent", "plan"],
            }
        ],
    )
    assert verify_capability_registry(registry)["registry_sha256"] == registry["registry_sha256"]
    assert all(value is False for value in registry["authority"].values())
    tampered = dict(registry)
    tampered["capabilities"] = [dict(registry["capabilities"][0], allowed_tools=["git push"])]
    with pytest.raises(AgenticControlError, match="digest"):
        verify_capability_registry(tampered)


def test_task_card_lease_checkpoint_and_completion_are_deterministic() -> None:
    registry = create_capability_registry(
        "factory-core", "1.0.0", [{
            "id": "builder", "role": "builder", "risk_class": "high",
            "allowed_tools": ["factory build"], "forbidden_tools": ["git push"],
            "allowed_paths": ["src/"], "model_tier": "workhorse",
            "stop_condition": "Stop when the bounded change is ready for verification.",
            "approval_required": True, "required_evidence": ["test"],
        }],
    )
    card = create_task_card(
        "task-1", "wf-1", "builder", registry["registry_sha256"], SHA,
        allowed_paths=["src/"], stop_condition="Stop at verification.",
        next_action="Run the declared checks.", created_at="2026-09-21T00:00:00Z",
    )
    leased = transition_task_card(card, "leased", lease_id="lease-1", lease_expires_at="2026-09-21T01:00:00Z")
    running = transition_task_card(leased, "running")
    checkpointed = transition_task_card(running, "checkpointed", checkpoint_digest=SHA)
    verifying_without_evidence = transition_task_card(checkpointed, "verifying")
    with pytest.raises(AgenticControlError, match="evidence"):
        transition_task_card(verifying_without_evidence, "completed")
    verifying = transition_task_card(checkpointed, "verifying", evidence_digest=SHA)
    completed = transition_task_card(verifying, "completed")
    assert verify_task_card(completed)["state"] == "completed"
    malformed = dict(completed, unexpected="metadata")
    malformed["task_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in malformed.items() if key not in {"task_sha256", "marker"}},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with pytest.raises(AgenticControlError, match="fields are not exact"):
        verify_task_card(malformed)
    with pytest.raises(AgenticControlError, match="cannot move"):
        transition_task_card(completed, "running")


def test_task_board_projects_dependencies_and_rejects_cycles() -> None:
    base = {
        "workflow_id": "wf-1",
        "capability_id": "builder",
        "registry_sha256": SHA,
        "intent_digest": SHA,
        "allowed_paths": ["src/"],
        "stop_condition": "Stop at verification.",
        "next_action": "Run the declared checks.",
        "created_at": "2026-09-21T00:00:00Z",
    }
    first = create_task_card("task-1", **base, dependencies=())
    second = create_task_card("task-2", **base, dependencies=("task-1",))
    board = project_task_board([second, first])
    assert board["lanes"]["ready"] == ["task-1"]
    assert board["lanes"]["triage"] == ["task-2"]
    assert board["dispatcher"] == {"poll_interval_seconds": 60, "started": False}
    assert verify_task_board(board)["board_sha256"] == board["board_sha256"]

    completed = transition_task_card(first, "leased", lease_id="lease-1", lease_expires_at="2026-09-21T01:00:00Z")
    completed = transition_task_card(completed, "running")
    completed = transition_task_card(completed, "verifying", evidence_digest=SHA)
    completed = transition_task_card(completed, "completed")
    ready_board = project_task_board([completed, second])
    assert ready_board["lanes"]["done"] == ["task-1"]
    assert ready_board["lanes"]["ready"] == ["task-2"]

    cycle_a = create_task_card("cycle-a", **base, dependencies=("cycle-b",))
    cycle_b = create_task_card("cycle-b", **base, dependencies=("cycle-a",))
    with pytest.raises(AgenticControlError, match="cycle"):
        project_task_board([cycle_a, cycle_b])


def test_task_handoff_binding_preserves_original_intent_and_scope() -> None:
    card = create_task_card(
        "task-bind", "wf-bind", "builder", SHA, SHA,
        allowed_paths=["src/", "tests/"], dependencies=(),
        stop_condition="Stop at verification.",
        next_action="Run the declared checks.", created_at="2026-09-21T00:00:00Z",
    )
    handoff = create_typed_handoff(
        "wf-bind", "build", "planner", "builder", SHA, SHA,
        allowed_paths=["src/"], next_action="Build only the approved scope.",
        created_at="2026-09-21T00:00:00Z",
    )
    binding = bind_task_card_handoff(card, handoff)
    assert binding["scope_verdict"] == "WITHIN_TASK_SCOPE"
    assert verify_task_card_handoff(binding)["binding_sha256"] == binding["binding_sha256"]

    wrong_intent = create_typed_handoff(
        "wf-bind", "build", "planner", "builder", "b" * 64, SHA,
        allowed_paths=["src/"], next_action="Build only the approved scope.",
        created_at="2026-09-21T00:00:00Z",
    )
    with pytest.raises(AgenticControlError, match="intent"):
        bind_task_card_handoff(card, wrong_intent)


def test_candidate_alignment_rejects_scope_drift() -> None:
    card = create_task_card(
        "task-candidate", "wf-candidate", "builder", SHA, SHA,
        allowed_paths=["src/"], dependencies=(),
        stop_condition="Stop at verification.",
        next_action="Run the declared checks.", created_at="2026-09-21T00:00:00Z",
    )
    handoff = create_typed_handoff(
        "wf-candidate", "build", "planner", "builder", SHA, SHA,
        allowed_paths=["src/"], next_action="Build only the approved scope.",
        created_at="2026-09-21T00:00:00Z",
    )
    receipt = align_candidate_to_task(card, handoff, SHA, ["src/app.py"])
    assert verify_candidate_alignment(receipt)["scope_verdict"] == "ALIGNED"
    with pytest.raises(AgenticControlError, match="scope"):
        align_candidate_to_task(card, handoff, SHA, ["docs/README.md"])


def test_typed_handoff_is_hash_bound_and_secret_free() -> None:
    packet = create_typed_handoff(
        "release-1",
        "plan",
        "planner",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/app.py"],
        next_action="Build only the approved scope.",
        created_at="2026-09-17T00:00:00+00:00",
    )
    assert verify_typed_handoff(packet)["handoff_sha256"] == packet["handoff_sha256"]
    assert "prompt" not in packet and all(
        value is False for value in packet["authority"].values()
    )
    packet["next_action"] = "Changed"
    with pytest.raises(AgenticControlError, match="digest"):
        verify_typed_handoff(packet)


def test_route_trace_binds_route_workflow_handoff_and_swimlanes() -> None:
    route = route_model("standard", risk="medium", token_budget=8000)
    workflow = compile_reusable_workflow(
        "route-workflow", [{"stage": "scout", "recipe": "first-proof"}]
    )
    handoff = create_typed_handoff(
        "route-workflow",
        "scout",
        "planner",
        "builder",
        "a" * 64,
        "b" * 64,
        next_action="inspect the repository",
        created_at="2026-09-17T00:00:00+00:00",
    )
    event = new_swimlane_event(
        "route-workflow",
        "stateful_workflows",
        "scout",
        "started",
        sequence=0,
    )
    trace = create_route_trace(route, workflow, handoff, [event])
    assert verify_route_trace(trace)["trace_id"] == trace["trace_id"]

    tampered = dict(trace)
    tampered["event_count"] = 2
    with pytest.raises(AgenticControlError, match="digest"):
        verify_route_trace(tampered)


def test_control_drift_receipt_blocks_removed_feature_and_detects_tampering(
    tmp_path,
) -> None:
    baseline = agentic_control_projection(tmp_path)
    current = agentic_control_projection(tmp_path)
    current["features"].pop("route_tracing")
    receipt = compare_agentic_control_drift(baseline, current)
    assert receipt["verdict"] == "BLOCKED"
    assert any(
        item["code"] == "AGENTIC_FEATURE_REMOVED" for item in receipt["findings"]
    )
    assert verify_agentic_control_drift(receipt)["verdict"] == "BLOCKED"

    tampered = dict(receipt)
    tampered["verdict"] = "CLEAR"
    with pytest.raises(AgenticControlError, match="digest"):
        verify_agentic_control_drift(tampered)


def test_control_drift_requires_review_for_added_feature(tmp_path) -> None:
    baseline = agentic_control_projection(tmp_path)
    current = agentic_control_projection(tmp_path)
    current["features"]["new_feature"] = {"status": "available"}
    receipt = compare_agentic_control_drift(baseline, current)
    assert receipt["verdict"] == "REVIEW_REQUIRED"
    assert receipt["summary"]["review_required"] == 1


def test_swimlane_chain_detects_order_and_tampering() -> None:
    first = new_swimlane_event("wf", "build", "build", "started", sequence=0)
    second = new_swimlane_event(
        "wf",
        "verify",
        "verify",
        "passed",
        sequence=1,
        previous_event_digest=first["event_digest"],
        artifact_digest=SHA,
        elapsed_ms=12,
    )
    assert verify_swimlane([first, second])["events"] == 2
    second["status"] = "failed"
    with pytest.raises(AgenticControlError, match="digest"):
        verify_swimlane([first, second])


def test_cookbook_is_lazy_and_bounded() -> None:
    recipe = load_cookbook_recipe("pr-review")
    assert recipe["name"] == "pr-review"
    assert "raw_prompt" not in recipe
    with pytest.raises(AgenticControlError, match="unknown"):
        load_cookbook_recipe("does-not-exist")


def test_reusable_workflow_requires_order_and_digest() -> None:
    manifest = compile_reusable_workflow(
        "review",
        [
            {"stage": "scout", "recipe": "first-proof"},
            {"stage": "plan", "recipe": "pr-review"},
            {"stage": "review", "recipe": "pr-review"},
        ],
    )
    assert (
        verify_reusable_workflow(manifest)["workflow_sha256"]
        == manifest["workflow_sha256"]
    )
    with pytest.raises(AgenticControlError, match="order"):
        compile_reusable_workflow(
            "bad",
            [
                {"stage": "review", "recipe": "pr-review"},
                {"stage": "plan", "recipe": "pr-review"},
            ],
        )


def test_sandbox_boundary_is_read_only_and_pinned(tmp_path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "README.md"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=test",
            "commit",
            "-qm",
            "init",
        ],
        check=True,
    )
    head = subprocess.check_output(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True
    ).strip()
    boundary = create_sandbox_boundary(tmp_path, expected_head_sha=head)
    assert verify_sandbox_boundary(boundary)["merge"] == "human_confirmation_required"
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == "ok\n"
    boundary["merge"] = "allowed"
    with pytest.raises(AgenticControlError, match="digest"):
        verify_sandbox_boundary(boundary)


def test_projection_exposes_all_six_controls_without_authority(tmp_path) -> None:
    projection = agentic_control_projection(tmp_path)
    assert len(projection["features"]) == 13
    assert all(value is False for value in projection["authority"].values())


def test_orchestrator_plan_is_typed_and_human_gated() -> None:
    plan = create_orchestrator_plan(
        {
            "goal": "route a bounded repair through independent verification",
            "intent_digest": SHA,
            "capability_registry_sha256": SHA,
            "workflow_ids": ["workflow:repair"],
            "recipe_names": ["quality-audit"],
            "task_ids": ["task:repair"],
            "model_tier": "workhorse",
            "stop_condition": "stop when evidence is stale or approval is missing",
            "approval_required": True,
        }
    )
    assert verify_orchestrator_plan(plan)["status"] == "PLANNED"
    tampered = dict(plan)
    tampered["approval_required"] = False
    with pytest.raises(AgenticControlError, match="digest"):
        verify_orchestrator_plan(tampered)


def test_orchestrator_plan_cli_writes_a_sealed_plan(tmp_path, capsys) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "goal": "compile a bounded route",
                "intent_digest": SHA,
                "capability_registry_sha256": SHA,
                "workflow_ids": ["workflow:demo"],
                "recipe_names": ["demo"],
                "task_ids": ["task:demo"],
                "model_tier": "lightweight",
                "stop_condition": "stop at missing approval",
                "approval_required": True,
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "plan.json"
    assert main(["agent", "plan", str(request), "--out", str(out), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "factory.orchestrator-plan.v1"
    assert json.loads(out.read_text(encoding="utf-8"))["plan_id"] == payload["plan_id"]


def test_agent_route_cli_emits_hash_bound_receipt(capsys) -> None:
    assert main(
        [
            "agent",
            "route",
            "routine",
            "--risk",
            "low",
            "--latency-budget-ms",
            "1000",
            "--json",
        ]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "factory.model-route.v1"
    assert verify_model_route(payload)["tier"] == "lightweight"


def test_extended_assurance_is_opt_in_and_receipt_v2_compatible() -> None:
    skipped = build_extended_assurance_receipt(
        "demo", extended_assurance=False, timestamp="2026-09-17T00:00:00+00:00"
    )
    assert skipped["ok"] is True
    assert all(
        item["status"] == "NOT_REQUESTED" for item in skipped["extended_lanes"].values()
    )
    evidence = {
        "supply_chain_provenance": {
            "source_sha256": SHA,
            "builder_id": "ci-build-1",
            "artifact_sha256": SHA,
            "dependencies_sha256": SHA,
            "challenge": {"provenance_mutation_rejected": True},
        },
        "semantic_robustness": {
            "cases": [
                {
                    "case_id": "empty-input",
                    "expected": "reject",
                    "observed": "reject",
                    "matched": True,
                }
            ],
            "challenge": {"mutations_attempted": 3, "mutations_caught": 3},
        },
    }
    receipt = build_extended_assurance_receipt(
        "demo",
        extended_assurance=True,
        evidence=evidence,
        timestamp="2026-09-17T00:00:00+00:00",
    )
    assert receipt["schema"] == "factory.receipt.v2"
    assert verify_extended_assurance_receipt(receipt)["ok"] is True


def test_extended_assurance_blocks_required_missing_evidence() -> None:
    receipt = build_extended_assurance_receipt(
        "demo",
        extended_assurance=True,
        evidence={},
        required_lanes=("supply_chain_provenance", "semantic_robustness"),
        timestamp="2026-09-17T00:00:00+00:00",
    )
    assert receipt["ok"] is False
    assert set(receipt["blocking_lanes"]) == {
        "supply_chain_provenance",
        "semantic_robustness",
    }
    assert verify_extended_assurance_receipt(receipt)["ok"] is False


def test_extended_assurance_challenges_cannot_be_weakened() -> None:
    supply = {
        "source_sha256": SHA,
        "builder_id": "ci-build-1",
        "artifact_sha256": SHA,
        "dependencies_sha256": SHA,
        "challenge": {"provenance_mutation_rejected": False},
    }
    semantic = {
        "cases": [
            {"case_id": "x", "expected": "ok", "observed": "ok", "matched": True}
        ],
        "challenge": {"mutations_attempted": 2, "mutations_caught": 1},
    }
    receipt = build_extended_assurance_receipt(
        "demo",
        extended_assurance=True,
        evidence={"supply_chain_provenance": supply, "semantic_robustness": semantic},
        required_lanes=("supply_chain_provenance", "semantic_robustness"),
        timestamp="2026-09-17T00:00:00+00:00",
    )
    assert receipt["ok"] is False
    assert set(receipt["blocking_lanes"]) == set(
        ("supply_chain_provenance", "semantic_robustness")
    )


def test_extended_assurance_cli_emits_receipt_v2(tmp_path) -> None:
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({}), encoding="utf-8")
    run = subprocess.run(
        [
            "python",
            "-m",
            "factoryline.cli",
            "agent",
            "extended",
            "demo",
            "--root",
            str(tmp_path),
            "--evidence",
            str(evidence),
            "--extended-assurance",
            "--required-lane",
            "supply_chain_provenance",
            "--required-lane",
            "semantic_robustness",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0
    payload = json.loads(run.stdout)
    assert payload["schema"] == "factory.receipt.v2"
    assert payload["ok"] is False
