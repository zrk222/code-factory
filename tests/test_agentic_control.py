from __future__ import annotations

import subprocess
import json
import hashlib
from pathlib import Path

import pytest
from factoryline.cli import main

from factoryline.agentic_control import (
    AgenticControlError,
    audit_model_route_policy,
    audit_a2a_agent_card,
    agentic_control_projection,
    build_extended_assurance_receipt,
    compare_agentic_control_drift,
    compile_reusable_workflow,
    create_route_trace,
    create_sandbox_boundary,
    create_typed_handoff,
    load_cookbook_recipe,
    list_cookbook_recipes,
    new_swimlane_event,
    route_model,
    verify_model_route,
    verify_model_route_policy_audit,
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
    candidate_digest_for_paths,
    verify_candidate_alignment,
    create_task_evidence,
    verify_task_evidence,
    complete_task_with_evidence,
    SENIOR_CONTROL_SLICES,
    build_senior_control_bundle,
    verify_senior_control_bundle,
    create_orchestrator_plan,
    verify_orchestrator_plan,
)


SHA = "a" * 64


def _valid_agent_card() -> dict[str, object]:
    return {
        "protocolVersion": "0.3.0",
        "name": "Example verifier",
        "description": "Validates submitted evidence declarations.",
        "url": "https://agents.example.test/a2a",
        "preferredTransport": "JSONRPC",
        "version": "1.2.3",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "securitySchemes": {"access": {"type": "http", "scheme": "bearer"}},
        "security": [{"access": []}],
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "verify-evidence",
                "name": "Verify evidence",
                "description": "Checks an evidence bundle structure.",
                "tags": ["verification", "evidence"],
            }
        ],
    }


def test_a2a_agent_card_audit_is_structural_and_never_claims_trust() -> None:
    card = _valid_agent_card()

    result = audit_a2a_agent_card(card)

    assert result["valid"] is True
    assert result["card_sha256"] == audit_a2a_agent_card(card)["card_sha256"]
    assert result["trust_checks"] == {
        "publisher_identity_verified": False,
        "endpoint_reached": False,
        "behavior_verified": False,
    }
    assert all(value is False for value in result["authority"].values())


def test_a2a_agent_card_audit_reports_endpoint_security_and_skill_drift() -> None:
    card = _valid_agent_card()
    card["url"] = "http://agents.example.test/a2a"
    card["security"] = [{"missing": []}]
    card["skills"] = [card["skills"][0], dict(card["skills"][0])]

    result = audit_a2a_agent_card(card)

    codes = {finding["code"] for finding in result["findings"]}
    assert result["valid"] is False
    assert "E_A2A_CARD_ENDPOINT" in codes
    assert "E_A2A_CARD_SECURITY" in codes
    assert "E_A2A_CARD_SKILLS" in codes


def test_a2a_card_audit_cli_reads_declaration_without_contacting_agent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "agent-card.json"
    path.write_text(json.dumps(_valid_agent_card()), encoding="utf-8")

    assert main(["agent", "card-audit", str(path), "--json"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "factory.a2a-agent-card-audit.v1"
    assert result["valid"] is True
    assert result["trust_checks"]["endpoint_reached"] is False


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


def test_model_route_policy_audit_binds_current_rule_and_rejects_tampering() -> None:
    audit = audit_model_route_policy(route_model("routine", latency_budget_ms=1000))
    assert audit["status"] == "MATCH"
    assert verify_model_route_policy_audit(audit) == audit
    with pytest.raises(AgenticControlError, match="digest"):
        verify_model_route_policy_audit({**audit, "audit_sha256": "0" * 64})


def test_cookbook_catalog_loads_only_the_requested_recipe() -> None:
    names = list_cookbook_recipes()
    assert names == sorted(set(names))
    assert "pr-review" in names
    recipe = load_cookbook_recipe("pr-review")
    assert recipe["name"] == "pr-review"
    assert recipe["marker"] == "COOKBOOK_CONTEXT_LAZY"


def test_capability_registry_is_hash_bound_and_cannot_grant_authority() -> None:
    registry = create_capability_registry(
        "factory-core",
        "1.0.0",
        [
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
    assert (
        verify_capability_registry(registry)["registry_sha256"]
        == registry["registry_sha256"]
    )
    assert all(value is False for value in registry["authority"].values())
    tampered = dict(registry)
    tampered["capabilities"] = [
        dict(registry["capabilities"][0], allowed_tools=["git push"])
    ]
    with pytest.raises(AgenticControlError, match="digest"):
        verify_capability_registry(tampered)


def test_task_card_lease_checkpoint_and_completion_are_deterministic() -> None:
    registry = create_capability_registry(
        "factory-core",
        "1.0.0",
        [
            {
                "id": "builder",
                "role": "builder",
                "risk_class": "high",
                "allowed_tools": ["factory build"],
                "forbidden_tools": ["git push"],
                "allowed_paths": ["src/"],
                "model_tier": "workhorse",
                "stop_condition": "Stop when the bounded change is ready for verification.",
                "approval_required": True,
                "required_evidence": ["test"],
            }
        ],
    )
    card = create_task_card(
        "task-1",
        "wf-1",
        "builder",
        registry["registry_sha256"],
        SHA,
        allowed_paths=["src/"],
        stop_condition="Stop at verification.",
        next_action="Run the declared checks.",
        created_at="2026-09-21T00:00:00Z",
    )
    leased = transition_task_card(
        card, "leased", lease_id="lease-1", lease_expires_at="2026-09-21T01:00:00Z"
    )
    running = transition_task_card(leased, "running")
    checkpointed = transition_task_card(running, "checkpointed", checkpoint_digest=SHA)
    verifying_without_evidence = transition_task_card(checkpointed, "verifying")
    with pytest.raises(AgenticControlError, match="evidence"):
        transition_task_card(verifying_without_evidence, "completed")
    verifying = transition_task_card(checkpointed, "verifying", evidence_digest=SHA)
    handoff = create_typed_handoff(
        "wf-1",
        "build",
        "planner",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/"],
        next_action="Build.",
        created_at="2026-09-21T00:00:00Z",
    )
    alignment = align_candidate_to_task(verifying, handoff, SHA, ["src/app.py"])
    evidence = create_task_evidence(
        verifying, SHA, SHA, "pytest", "independent-verifier", alignment=alignment
    )
    completed = complete_task_with_evidence(verifying, evidence, alignment)
    assert verify_task_card(completed)["state"] == "completed"
    malformed = dict(completed, unexpected="metadata")
    malformed["task_sha256"] = hashlib.sha256(
        json.dumps(
            {
                key: value
                for key, value in malformed.items()
                if key not in {"task_sha256", "marker"}
            },
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

    completed = transition_task_card(
        first, "leased", lease_id="lease-1", lease_expires_at="2026-09-21T01:00:00Z"
    )
    completed = transition_task_card(completed, "running")
    completed = transition_task_card(completed, "verifying", evidence_digest=SHA)
    handoff = create_typed_handoff(
        "wf-1",
        "build",
        "planner",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/"],
        next_action="Build.",
        created_at="2026-09-21T00:00:00Z",
    )
    alignment = align_candidate_to_task(completed, handoff, SHA, ["src/app.py"])
    evidence = create_task_evidence(
        completed, SHA, SHA, "pytest", "independent-verifier", alignment=alignment
    )
    completed = complete_task_with_evidence(completed, evidence, alignment)
    ready_board = project_task_board([completed, second])
    assert ready_board["lanes"]["done"] == ["task-1"]
    assert ready_board["lanes"]["ready"] == ["task-2"]

    cycle_a = create_task_card("cycle-a", **base, dependencies=("cycle-b",))
    cycle_b = create_task_card("cycle-b", **base, dependencies=("cycle-a",))
    with pytest.raises(AgenticControlError, match="cycle"):
        project_task_board([cycle_a, cycle_b])


def test_task_handoff_binding_preserves_original_intent_and_scope() -> None:
    card = create_task_card(
        "task-bind",
        "wf-bind",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/", "tests/"],
        dependencies=(),
        stop_condition="Stop at verification.",
        next_action="Run the declared checks.",
        created_at="2026-09-21T00:00:00Z",
    )
    handoff = create_typed_handoff(
        "wf-bind",
        "build",
        "planner",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/"],
        next_action="Build only the approved scope.",
        created_at="2026-09-21T00:00:00Z",
    )
    binding = bind_task_card_handoff(card, handoff)
    assert binding["scope_verdict"] == "WITHIN_TASK_SCOPE"
    assert (
        verify_task_card_handoff(binding)["binding_sha256"] == binding["binding_sha256"]
    )

    wrong_intent = create_typed_handoff(
        "wf-bind",
        "build",
        "planner",
        "builder",
        "b" * 64,
        SHA,
        allowed_paths=["src/"],
        next_action="Build only the approved scope.",
        created_at="2026-09-21T00:00:00Z",
    )
    with pytest.raises(AgenticControlError, match="intent"):
        bind_task_card_handoff(card, wrong_intent)


def test_candidate_alignment_rejects_scope_drift() -> None:
    card = create_task_card(
        "task-candidate",
        "wf-candidate",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/"],
        dependencies=(),
        stop_condition="Stop at verification.",
        next_action="Run the declared checks.",
        created_at="2026-09-21T00:00:00Z",
    )
    handoff = create_typed_handoff(
        "wf-candidate",
        "build",
        "planner",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/"],
        next_action="Build only the approved scope.",
        created_at="2026-09-21T00:00:00Z",
    )
    receipt = align_candidate_to_task(card, handoff, SHA, ["src/app.py"])
    assert verify_candidate_alignment(receipt)["scope_verdict"] == "ALIGNED"
    with pytest.raises(AgenticControlError, match="scope"):
        align_candidate_to_task(card, handoff, SHA, ["docs/README.md"])


def test_task_evidence_binds_verifier_and_controls_completion() -> None:
    card = create_task_card(
        "task-evidence",
        "wf-evidence",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/"],
        dependencies=(),
        stop_condition="Stop at verification.",
        next_action="Run the declared checks.",
        created_at="2026-09-21T00:00:00Z",
    )
    leased = transition_task_card(
        card,
        "leased",
        lease_id="lease-evidence",
        lease_expires_at="2026-09-21T01:00:00Z",
    )
    running = transition_task_card(leased, "running")
    verifying = transition_task_card(running, "verifying")
    handoff = create_typed_handoff(
        "wf-evidence",
        "build",
        "planner",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/"],
        next_action="Build.",
        created_at="2026-09-21T00:00:00Z",
    )
    alignment = align_candidate_to_task(verifying, handoff, SHA, ["src/app.py"])
    evidence = create_task_evidence(
        verifying,
        SHA,
        SHA,
        "pytest",
        "independent-verifier",
        source_paths=["tests/"],
        alignment=alignment,
    )
    assert verify_task_evidence(evidence)["outcome"] == "passed"
    assert (
        complete_task_with_evidence(verifying, evidence, alignment)["state"]
        == "completed"
    )
    failed = create_task_evidence(
        verifying,
        SHA,
        SHA,
        "pytest",
        "independent-verifier",
        outcome="failed",
    )
    with pytest.raises(AgenticControlError, match="failed evidence"):
        complete_task_with_evidence(verifying, failed, alignment)


def test_senior_control_bundle_requires_all_six_slices(tmp_path) -> None:
    import json

    def receipt(name: str) -> dict:
        payload = {
            "candidate_hash": SHA,
            "evidence_digest": SHA,
            "outcome": "passed",
            "authority": {"merge": False},
        }
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return {
            "receipt_path": path.name,
            "receipt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    slices = {
        name: {
            "status": "PASSED",
            "evidence_digest": SHA,
            "source": f"engine:{name}",
            **receipt(name),
        }
        for name in SENIOR_CONTROL_SLICES
    }
    bundle = build_senior_control_bundle(SHA, slices)
    assert bundle["readiness"] == "READY_FOR_HUMAN_REVIEW"
    assert bundle["blocking_slices"] == []
    assert (
        verify_senior_control_bundle(bundle, tmp_path)["bundle_sha256"]
        == bundle["bundle_sha256"]
    )

    blocked = dict(slices)
    blocked["policy_simulation"] = {
        "status": "BLOCKED",
        "evidence_digest": None,
        "source": "policy-engine",
        "receipt_path": None,
        "receipt_sha256": None,
    }
    blocked_bundle = build_senior_control_bundle(SHA, blocked)
    assert blocked_bundle["readiness"] == "BLOCKED"
    assert blocked_bundle["blocking_slices"] == ["policy_simulation"]
    with pytest.raises(AgenticControlError, match="six"):
        build_senior_control_bundle(
            SHA, {name: slices[name] for name in SENIOR_CONTROL_SLICES[:-1]}
        )

    with pytest.raises(AgenticControlError, match="receipt-backed"):
        verify_senior_control_bundle(bundle)


def test_completion_requires_alignment_and_handoff_scope_is_narrowest(tmp_path) -> None:
    card = create_task_card(
        "task-strict",
        "wf-strict",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/", "tests/"],
        dependencies=(),
        stop_condition="Stop.",
        next_action="Verify.",
        created_at="2026-09-21T00:00:00Z",
    )
    handoff = create_typed_handoff(
        "wf-strict",
        "build",
        "planner",
        "builder",
        SHA,
        SHA,
        allowed_paths=["src/"],
        next_action="Build.",
        created_at="2026-09-21T00:00:00Z",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.py").write_text("value = 1\n", encoding="utf-8")
    candidate_hash = candidate_digest_for_paths(tmp_path, ["src/app.py"])
    alignment = align_candidate_to_task(
        card, handoff, candidate_hash, ["src/app.py"], candidate_root=tmp_path
    )
    with pytest.raises(AgenticControlError, match="scope"):
        align_candidate_to_task(card, handoff, candidate_hash, ["tests/test_app.py"])
    leased = transition_task_card(
        card, "leased", lease_id="lease-strict", lease_expires_at="2026-09-21T01:00:00Z"
    )
    running = transition_task_card(leased, "running")
    verifying = transition_task_card(running, "verifying")
    alignment = align_candidate_to_task(
        verifying, handoff, candidate_hash, ["src/app.py"], candidate_root=tmp_path
    )
    evidence = create_task_evidence(
        verifying,
        candidate_hash,
        SHA,
        "pytest",
        "independent-verifier",
        alignment=alignment,
    )
    assert (
        complete_task_with_evidence(verifying, evidence, alignment)["state"]
        == "completed"
    )


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
    assert len(projection["features"]) == 15
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
    assert (
        main(
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
        )
        == 0
    )
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


def test_agent_card_private_stages_respect_complexity_limit():
    import ast
    import inspect
    import textwrap
    import factoryline.agentic_control as module

    for name, value in vars(module).items():
        if not (
            name.startswith("_a2a_") or name == "audit_a2a_agent_card"
        ) or not callable(value):
            continue
        tree = ast.parse(textwrap.dedent(inspect.getsource(value)))
        count = 1
        for node in ast.walk(tree):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                count += 1
            elif isinstance(node, ast.BoolOp):
                count += len(node.values) - 1
        assert count <= 10, (name, count)


@pytest.fixture
def workflow_source():
    return {
        "provider": "github",
        "account": "account-1",
        "repository": "owner/repo",
        "kind": "issue",
        "external_id": "17",
        "revision": 1,
        "head_sha": None,
        "state": "open",
        "title": "Fix boundary",
    }


def workflow_store(root, clock=None, **options):
    from factoryline.agentic_control import WorkflowEventStore

    return WorkflowEventStore(
        root, [("github", "account-1", "owner/repo")], clock=clock, **options
    )


def test_runtime_source_events_survive_store_restart_and_duplicate(
    tmp_path, workflow_source
):
    store = workflow_store(tmp_path)
    first = store.intake("delivery-one", workflow_source)
    restarted = workflow_store(tmp_path)
    duplicate = restarted.intake("delivery-one", workflow_source)
    assert first["status"] == "created"
    assert duplicate["status"] == "duplicate"
    assert duplicate["item"] == first["item"]
    assert not any(duplicate["authority"].values())
    assert duplicate["item"]["phase"] == "intake"


def test_runtime_duplicate_event_cannot_change_source_bytes(tmp_path, workflow_source):
    store = workflow_store(tmp_path)
    store.intake("delivery-one", workflow_source)
    with pytest.raises(AgenticControlError) as error:
        store.intake("delivery-one", {**workflow_source, "title": "different"})
    assert error.value.code == "E_WORKFLOW_EVENT_REUSE"


def test_runtime_source_revisions_do_not_roll_back(tmp_path, workflow_source):
    store = workflow_store(tmp_path)
    newer = store.intake("delivery-two", {**workflow_source, "revision": 2})
    stale = store.intake("delivery-old", workflow_source)
    assert stale["status"] == "stale"
    assert stale["item"] == newer["item"]
    with pytest.raises(AgenticControlError) as error:
        store.intake(
            "delivery-conflict", {**workflow_source, "revision": 2, "title": "changed"}
        )
    assert error.value.code == "E_WORKFLOW_REVISION"


@pytest.mark.parametrize(
    "change",
    [
        {"account": "another"},
        {"repository": "other/repo"},
        {"provider": "gitlab"},
        {"revision": True},
        {"revision": -1},
        {"head_sha": "bad"},
        {"state": "approved"},
        {"kind": "comment"},
        {"state": "merged"},
        {"token": "must-not-store"},
    ],
)
def test_runtime_source_requires_scoped_exact_adapter_observation(
    tmp_path, workflow_source, change
):
    with pytest.raises(AgenticControlError):
        workflow_store(tmp_path).intake("delivery-one", {**workflow_source, **change})


def test_runtime_account_switch_needs_explicit_migration(tmp_path):
    from factoryline.agentic_control import WorkflowEventStore

    workflow_store(tmp_path)
    with pytest.raises(AgenticControlError) as error:
        WorkflowEventStore(tmp_path, [("github", "another", "owner/repo")])
    assert error.value.code == "E_WORKFLOW_SCOPE"


def test_runtime_owner_expiry_is_not_proof_of_termination(tmp_path, workflow_source):
    clock = [100.0]
    store = workflow_store(tmp_path, lambda: clock[0])
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    claimed = store.claim(key, "worker-a", ttl=1)["item"]
    clock[0] = 200.0
    with pytest.raises(AgenticControlError) as error:
        workflow_store(tmp_path, lambda: clock[0]).claim(key, "worker-b")
    assert error.value.code == "E_WORKFLOW_RECOVERY_REQUIRED"
    with pytest.raises(AgenticControlError):
        store.heartbeat(key, "worker-a", claimed["epoch"])
    for state in ("live", "unknown"):
        result = store.reconcile_run(
            key,
            lambda run: {"run_id": run["id"], "handle": run["handle"], "state": state},
        )
        assert result["item"]["run"]["id"] == claimed["run"]["id"]
        assert result["status"] == state


@pytest.mark.parametrize("state", ["terminal", "missing"])
def test_runtime_authoritative_terminal_observation_retires_owner(
    tmp_path, workflow_source, state
):
    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    first = store.claim(key, "worker-a")["item"]
    retired = store.reconcile_run(
        key, lambda run: {"run_id": run["id"], "handle": run["handle"], "state": state}
    )
    assert retired["item"]["run"] is None
    assert retired["item"]["phase"] == "triage"
    second = store.claim(key, "worker-b")["item"]
    assert second["epoch"] > first["epoch"]
    with pytest.raises(AgenticControlError) as error:
        store.heartbeat(key, "worker-a", first["epoch"])
    assert error.value.code == "E_WORKFLOW_FENCED"


def test_runtime_new_head_fences_owner_until_retirement(tmp_path, workflow_source):
    store = workflow_store(tmp_path)
    source = {**workflow_source, "kind": "pull_request", "head_sha": "a" * 40}
    key = store.intake("delivery-one", source)["item"]["source_key"]
    first = store.claim(key, "worker-a")["item"]
    store.heartbeat(key, "worker-a", first["epoch"], handle="provider-run-1")
    changed = store.intake(
        "delivery-two", {**source, "revision": 2, "head_sha": "b" * 40}
    )
    assert changed["item"]["phase"] == "retirement_required"
    with pytest.raises(AgenticControlError):
        store.claim(key, "worker-b")
    with pytest.raises(AgenticControlError):
        store.heartbeat(key, "worker-a", first["epoch"])
    store.reconcile_run(
        key,
        lambda run: {"run_id": run["id"], "handle": run["handle"], "state": "terminal"},
    )
    assert store.get(key)["phase"] == "intake"
    assert store.claim(key, "worker-b")["item"]["source"]["head_sha"] == "b" * 40


def test_runtime_reconciliation_rechecks_ownership_after_probe(
    tmp_path, workflow_source
):
    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    store.claim(key, "worker-a")

    def observer(run):
        workflow_store(tmp_path).intake(
            "delivery-two", {**workflow_source, "revision": 2}
        )
        return {"run_id": run["id"], "handle": run["handle"], "state": "terminal"}

    with pytest.raises(AgenticControlError) as error:
        store.reconcile_run(key, observer)
    assert error.value.code == "E_WORKFLOW_FENCED"
    assert store.get(key)["run"] is not None


@pytest.mark.parametrize("state", ["closed", "merged", "missing"])
def test_runtime_external_state_never_certifies_cf_completion(
    tmp_path, workflow_source, state
):
    source = {
        **workflow_source,
        "kind": "pull_request",
        "head_sha": "a" * 40,
        "state": state,
    }
    store = workflow_store(tmp_path)
    item = store.intake("delivery-one", source)["item"]
    assert item["phase"] != "completed"
    with pytest.raises(AgenticControlError):
        store.claim(item["source_key"], "worker-a")


def test_runtime_handle_cannot_be_replaced(tmp_path, workflow_source):
    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    item = store.claim(key, "worker-a")["item"]
    store.heartbeat(key, "worker-a", item["epoch"], handle="run-1")
    with pytest.raises(AgenticControlError):
        store.heartbeat(key, "worker-a", item["epoch"], handle="run-2")
    with pytest.raises(AgenticControlError):
        store.reconcile_run(
            key,
            lambda run: {"run_id": run["id"], "handle": "other", "state": "terminal"},
        )


def test_runtime_retry_budget_cannot_be_bypassed_by_reopening_store(
    tmp_path, workflow_source
):
    key = workflow_store(tmp_path).intake("delivery-one", workflow_source)["item"][
        "source_key"
    ]
    for _ in range(3):
        store = workflow_store(tmp_path)
        store.claim(key, "worker-a")
        store.reconcile_run(
            key,
            lambda run: {
                "run_id": run["id"],
                "handle": run["handle"],
                "state": "missing",
            },
        )
    with pytest.raises(AgenticControlError) as error:
        workflow_store(tmp_path).claim(key, "worker-b")
    assert error.value.code == "E_WORKFLOW_RETRY"


def test_runtime_stored_hash_drift_is_rejected(tmp_path, workflow_source):
    import sqlite3

    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE items SET sha=? WHERE key=?", ("0" * 64, key))
    with pytest.raises(AgenticControlError) as error:
        store.get(key)
    assert error.value.code == "E_WORKFLOW_INTEGRITY"


def test_runtime_two_processes_cannot_claim_same_item(tmp_path, workflow_source):
    import sys

    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    script = """import json,sys
from factoryline.agentic_control import WorkflowEventStore,AgenticControlError
store=WorkflowEventStore(sys.argv[1], [('github','account-1','owner/repo')])
try:
 store.claim(sys.argv[2],sys.argv[3]); print('CLAIMED')
except AgenticControlError as e:
 print(e.code)
"""
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(tmp_path), key, owner],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for owner in ("worker-a", "worker-b")
    ]
    outputs = [worker.communicate(timeout=15) for worker in workers]
    assert all(worker.returncode == 0 for worker in workers), outputs
    assert sorted(out.strip() for out, _ in outputs) == [
        "CLAIMED",
        "E_WORKFLOW_RECOVERY_REQUIRED",
    ]
    assert workflow_store(tmp_path).get(key)["run"]["owner"] in {"worker-a", "worker-b"}


def test_runtime_interrupted_event_write_rolls_back_atomically(
    tmp_path, workflow_source, monkeypatch
):
    import sqlite3

    store = workflow_store(tmp_path)
    original = store._write

    def fail_after_write(db, item, action):
        original(db, item, action)
        raise RuntimeError("simulated interruption")

    monkeypatch.setattr(store, "_write", fail_after_write)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        store.intake("delivery-one", workflow_source)
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM items").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM ingress").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM journal").fetchone()[0] == 0
    monkeypatch.setattr(store, "_write", original)
    assert store.intake("delivery-one", workflow_source)["status"] == "created"


def test_runtime_linked_storage_is_rejected(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace
    from factoryline.agentic_control import _runtime_path

    directory = tmp_path / ".factory"
    directory.mkdir()
    original = Path.lstat

    def fake_junction(path, *args, **kwargs):
        if path == directory:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", fake_junction)
    with pytest.raises(AgenticControlError) as error:
        _runtime_path(tmp_path)
    assert error.value.code == "E_WORKFLOW_PATH"


def github_intake_payload():
    return {
        "number": 172,
        "html_url": "https://github.com/owner/repo/pull/172",
        "base": {"repo": {"full_name": "owner/repo"}},
        "head": {"sha": "a" * 40},
        "state": "open",
        "merged": False,
        "updated_at": "2026-10-11T09:00:00Z",
        "title": "Review candidate",
    }


def test_sync_github_workflow_source_reads_bound_pr_and_deduplicates(
    tmp_path, monkeypatch
):
    from factoryline.agentic_control import sync_github_workflow_source

    calls = []

    def read(endpoint):
        calls.append(endpoint)
        return {"login": "account-1"} if endpoint == "user" else github_intake_payload()

    monkeypatch.setattr("factoryline.agentic_control._github_runtime_read", read)
    store = workflow_store(tmp_path)
    result = sync_github_workflow_source(store, "owner/repo", 172, kind="pull_request")
    assert result["item"]["source"]["head_sha"] == "a" * 40
    assert result["item"]["source"]["revision"] > 0
    assert (
        sync_github_workflow_source(store, "owner/repo", 172, kind="pull_request")[
            "status"
        ]
        == "duplicate"
    )
    assert calls == ["user", "repos/owner/repo/pulls/172"] * 2
    assert not any(result["authority"].values())


@pytest.mark.parametrize(
    "change",
    [
        {"html_url": "https://github.com/other/repo/pull/172"},
        {"number": True},
        {"updated_at": "2026-10-11T09:00:00"},
        {"head": None},
        {"head": {"sha": None}},
        {"base": {"repo": {"full_name": "other/repo"}}},
    ],
)
def test_sync_github_workflow_source_rejects_provider_mismatch(
    tmp_path, monkeypatch, change
):
    from factoryline.agentic_control import sync_github_workflow_source

    payload = {**github_intake_payload(), **change}
    monkeypatch.setattr(
        "factoryline.agentic_control._github_runtime_read",
        lambda endpoint: {"login": "account-1"} if endpoint == "user" else payload,
    )
    with pytest.raises(AgenticControlError):
        sync_github_workflow_source(
            workflow_store(tmp_path), "owner/repo", 172, kind="pull_request"
        )


def test_sync_github_workflow_source_rejects_account_before_repo_read(
    tmp_path, monkeypatch
):
    from factoryline.agentic_control import sync_github_workflow_source

    calls = []

    def read(endpoint):
        calls.append(endpoint)
        return {"login": "other-account"}

    monkeypatch.setattr("factoryline.agentic_control._github_runtime_read", read)
    with pytest.raises(AgenticControlError):
        sync_github_workflow_source(workflow_store(tmp_path), "owner/repo", 172)
    assert calls == ["user"]


def finish_workflow_phase(store, key):
    from factoryline.agentic_control import _sha

    claim = store.claim(key, "worker-a")["item"]
    run = claim["run"]
    store.heartbeat(key, "worker-a", run["epoch"], handle="driver:" + run["id"])
    store.reconcile_run(
        key,
        lambda current: dict(
            run_id=current["id"], handle=current["handle"], state="terminal"
        ),
    )
    kind = {
        "triage": "triage",
        "planning": "approved_plan",
        "building": "isolated_build",
        "auditing": "six_lane_audit",
        "reviewing": "independent_review",
    }[claim["phase"]]
    return dict(
        source_sha256=_sha(claim["source"]),
        run_id=run["id"],
        phase=claim["phase"],
        kind=kind,
        artifact_sha256="b" * 64,
        verifier_id="trusted-host",
    )


def test_runtime_advance_requires_each_verified_phase_and_never_merges(
    tmp_path, workflow_source
):
    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    seen = []

    def verify(value):
        seen.append(value["kind"])
        return value

    store = workflow_store(
        tmp_path,
        phase_verifiers={"trusted-host": verify},
        source_observer=lambda source: source,
    )
    for target in ("planning", "building", "auditing", "reviewing", "ready_for_merge"):
        evidence = finish_workflow_phase(store, key)
        result = store.advance(key, target, evidence)
        assert result["item"]["phase"] == target
        assert result["item"]["attempts"] == 0
        assert not any(result["authority"].values())
        store = workflow_store(
            tmp_path,
            phase_verifiers={"trusted-host": verify},
            source_observer=lambda source: source,
        )
    assert seen == [
        "triage",
        "approved_plan",
        "isolated_build",
        "six_lane_audit",
        "independent_review",
    ]
    with pytest.raises(AgenticControlError):
        store.advance(key, "merged", evidence)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_sha256", "c" * 64),
        ("run_id", "wrong-run"),
        ("phase", "planning"),
        ("kind", "approved_plan"),
        ("artifact_sha256", "bad"),
    ],
)
def test_runtime_advance_rejects_mismatched_evidence(
    tmp_path, workflow_source, field, value
):
    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    evidence = {**finish_workflow_phase(store, key), field: value}
    with pytest.raises(AgenticControlError):
        store.advance(key, "planning", evidence)
    assert store.get(key)["phase"] == "triage"


def test_runtime_advance_rejects_absent_or_unverified_run(tmp_path, workflow_source):
    store = workflow_store(
        tmp_path,
        phase_verifiers={"trusted-host": lambda value: {**value, "kind": "invented"}},
        source_observer=lambda source: source,
    )
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    evidence = finish_workflow_phase(store, key)
    with pytest.raises(AgenticControlError):
        store.advance(key, "planning", evidence)
    run = store.claim(key, "worker-b")["item"]["run"]
    store.reconcile_run(
        key,
        lambda current: dict(
            run_id=current["id"], handle=current["handle"], state="missing"
        ),
    )
    with pytest.raises(AgenticControlError):
        store.advance(
            key,
            "planning",
            {**evidence, "run_id": run["id"]},
        )


def test_runtime_advance_fences_source_change_during_verification(
    tmp_path, workflow_source
):
    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    evidence = finish_workflow_phase(store, key)

    def verify(supplied):
        store.intake("delivery-two", {**workflow_source, "revision": 2})
        return supplied

    store = workflow_store(
        tmp_path,
        phase_verifiers={"trusted-host": verify},
        source_observer=lambda source: source,
    )
    with pytest.raises(AgenticControlError) as error:
        store.advance(key, "planning", evidence)
    assert error.value.code == "E_WORKFLOW_FENCED"


def test_runtime_advance_without_registered_host_verifier_is_rejected(
    tmp_path, workflow_source
):
    store = workflow_store(tmp_path)
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    evidence = finish_workflow_phase(store, key)
    with pytest.raises(AgenticControlError) as error:
        store.advance(key, "planning", evidence)
    assert error.value.code == "E_WORKFLOW_TRUST"


def test_runtime_advance_remote_drift_without_ingress_is_reconciled(
    tmp_path, workflow_source
):
    store = workflow_store(
        tmp_path,
        phase_verifiers={"trusted-host": lambda value: value},
        source_observer=lambda source: {
            **source,
            "revision": 2,
            "title": "Changed remotely",
        },
    )
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    evidence = finish_workflow_phase(store, key)
    with pytest.raises(AgenticControlError) as error:
        store.advance(key, "planning", evidence)
    assert error.value.code == "E_WORKFLOW_FENCED"
    assert store.get(key)["source"]["revision"] == 2


def test_runtime_advance_live_run_cannot_use_previous_phase_evidence(
    tmp_path, workflow_source
):
    store = workflow_store(
        tmp_path,
        phase_verifiers={"trusted-host": lambda value: value},
        source_observer=lambda source: source,
    )
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    evidence = finish_workflow_phase(store, key)
    store.claim(key, "worker-b")
    with pytest.raises(AgenticControlError):
        store.advance(key, "planning", evidence)
    assert store.get(key)["run"]["owner"] == "worker-b"


def test_runtime_advance_requires_bound_handle_and_run_source(
    tmp_path, workflow_source
):
    from factoryline.agentic_control import _sha

    store = workflow_store(
        tmp_path,
        phase_verifiers={"trusted-host": lambda value: value},
        source_observer=lambda source: source,
    )
    key = store.intake("delivery-one", workflow_source)["item"]["source_key"]
    item = store.claim(key, "worker-a")["item"]
    run = item["run"]
    assert run["source_sha256"] == _sha(workflow_source)
    store.reconcile_run(
        key, lambda current: dict(run_id=current["id"], handle=None, state="terminal")
    )
    evidence = dict(
        source_sha256=_sha(workflow_source),
        run_id=run["id"],
        phase="triage",
        kind="triage",
        artifact_sha256="b" * 64,
        verifier_id="trusted-host",
    )
    with pytest.raises(AgenticControlError):
        store.advance(key, "planning", evidence)


@pytest.mark.parametrize("registry", [{}, {"host": None}, []])
def test_runtime_host_verifier_registration_rejects_invalid_registry(
    tmp_path, registry
):
    with pytest.raises(AgenticControlError) as error:
        workflow_store(tmp_path, phase_verifiers=registry)
    assert error.value.code == "E_WORKFLOW_TRUST"


def test_github_runtime_transport_forces_host_and_hides_provider_errors(monkeypatch):
    from factoryline.agentic_control import _github_runtime_read
    from types import SimpleNamespace

    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=1, stdout="", stderr="sensitive provider response"
        )

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(AgenticControlError) as error:
        _github_runtime_read("user")
    assert "sensitive" not in str(error.value)
    assert calls[0][0] == ["gh", "api", "--hostname", "github.com", "user"]
    assert calls[0][1]["timeout"] == 30


@pytest.mark.parametrize(
    "repository,number,kind",
    [
        ("../repo", 172, "issue"),
        ("owner/repo", True, "issue"),
        ("owner/repo", 0, "issue"),
        ("owner/repo", 172, "merge"),
    ],
)
def test_sync_github_workflow_source_bad_selector_never_reads_provider(
    tmp_path, monkeypatch, repository, number, kind
):
    from factoryline.agentic_control import sync_github_workflow_source

    def unexpected(endpoint):
        pytest.fail("invalid selector must not query provider")

    monkeypatch.setattr("factoryline.agentic_control._github_runtime_read", unexpected)
    with pytest.raises(AgenticControlError):
        sync_github_workflow_source(
            workflow_store(tmp_path), repository, number, kind=kind
        )


def test_sync_github_workflow_source_malformed_account_fails_closed(
    tmp_path, monkeypatch
):
    from factoryline.agentic_control import sync_github_workflow_source

    monkeypatch.setattr(
        "factoryline.agentic_control._github_runtime_read",
        lambda endpoint: {"login": []},
    )
    with pytest.raises(AgenticControlError):
        sync_github_workflow_source(workflow_store(tmp_path), "owner/repo", 172)
