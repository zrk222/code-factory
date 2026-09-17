from __future__ import annotations

import subprocess
import json

import pytest

from factoryline.agentic_control import (
    AgenticControlError,
    agentic_control_projection,
    build_extended_assurance_receipt,
    compile_reusable_workflow,
    create_route_trace,
    create_sandbox_boundary,
    create_typed_handoff,
    load_cookbook_recipe,
    new_swimlane_event,
    route_model,
    verify_route_trace,
    verify_reusable_workflow,
    verify_sandbox_boundary,
    verify_swimlane,
    verify_typed_handoff,
    verify_extended_assurance_receipt,
)


SHA = "a" * 64


def test_model_route_is_deterministic_and_tiered() -> None:
    assert route_model("routine", latency_budget_ms=1000)["tier"] == "lightweight"
    assert route_model("standard")["tier"] == "workhorse"
    assert route_model("critical", risk="critical")["tier"] == "frontier"
    assert route_model("standard") == route_model("standard")


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
    assert len(projection["features"]) == 7
    assert all(value is False for value in projection["authority"].values())


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
