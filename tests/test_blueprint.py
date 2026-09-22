from __future__ import annotations

import pytest

from factoryline.blueprint import (
    BlueprintError,
    access_profile,
    build_artifact_chain,
    blueprint_projection,
    librarian_promotion,
    recall_observations,
    reflect_observations,
    retain_observation,
    signal_intent_proposal,
    team_plan,
    verify_artifact_chain,
)
from factoryline.signal_loop import capture_signal


def _observation(**overrides):
    payload = {
        "source": "run-1",
        "source_digest": "a" * 64,
        "project": "factory",
        "subject": "release gate",
        "classification": "fact",
        "entities": ["cadence"],
        "tags": ["release"],
        "observed_at": "2026-09-22T12:00:00Z",
        "summary": "The release cadence gate is enforced during preflight.",
    }
    payload.update(overrides)
    return retain_observation(**payload)


def test_memory_retain_recall_reflect_and_librarian_promotion() -> None:
    observation = _observation()
    recalled = recall_observations([observation], project="factory", query="cadence")
    assert recalled["marker"] == "BLUEPRINT_MEMORY_RECALLED"
    assert len(recalled["matches"]) == 1
    reflection = reflect_observations([observation])
    assert reflection["projects"][0]["classes"] == {"fact": 1}
    gold = librarian_promotion(
        observation,
        reviewer="human-release-authority",
        stage="gold",
        source_digest="a" * 64,
        feedback="Confirmed against the release receipt.",
    )
    assert gold["stage"] == "gold"
    assert gold["human_approved"] is True


def test_librarian_rejects_source_drift_and_contested_gold() -> None:
    observation = _observation()
    with pytest.raises(BlueprintError, match="source digest"):
        librarian_promotion(
            observation,
            reviewer="reviewer",
            stage="silver",
            source_digest="b" * 64,
        )
    with pytest.raises(BlueprintError, match="contested"):
        librarian_promotion(
            observation,
            reviewer="reviewer",
            stage="gold",
            source_digest="a" * 64,
            contested=True,
        )


def test_signal_becomes_agent_proposed_intent_not_an_automatic_task(tmp_path) -> None:
    signal = capture_signal(
        tmp_path,
        source="sentry",
        title="Checkout timeout",
        body="Observed timeout in the checkout journey.",
        authorization="owner_supplied",
        outcomes=["Restore checkout completion"],
    )
    proposal = signal_intent_proposal(signal, owner="product-owner")
    assert proposal["status"] == "agent_proposed"
    assert proposal["requires_human_confirmation"] is True
    assert proposal["authority"]["create_intent"] is False


def test_access_profile_is_disjoint_and_explicitly_non_enforcing() -> None:
    profile = access_profile(
        workspace="repo",
        read_write=["src"],
        read_only=["reference"],
        masked=["strategy"],
    )
    assert profile["enforcement"] == "declaration_only"
    with pytest.raises(BlueprintError, match="disjoint"):
        access_profile(workspace="repo", read_write=["src"], masked=["src"])


def test_team_plan_is_typed_and_never_dispatches() -> None:
    plan = team_plan(
        plan_id="release-review",
        intent_digest="c" * 64,
        workers=[
            {"id": "planner", "kind": "bot", "model_tier": "frontier", "tools": ["spec"]},
            {"id": "builder", "kind": "subagent", "model_tier": "workhorse", "tools": ["edit"]},
        ],
        tasks=[
            {"id": "plan", "worker_id": "planner", "acceptance": "sealed plan exists"},
            {"id": "build", "worker_id": "builder", "dependencies": ["plan"], "acceptance": "candidate exists"},
        ],
    )
    assert plan["dispatcher"]["started"] is False
    assert all(value is False for value in plan["authority"].values())
    with pytest.raises(BlueprintError, match="worker_id"):
        team_plan(
            plan_id="bad",
            intent_digest="c" * 64,
            workers=[{"id": "planner", "model_tier": "frontier"}],
            tasks=[{"id": "build", "worker_id": "missing", "acceptance": "x"}],
        )


def test_projection_counts_only_hash_valid_receipts(tmp_path) -> None:
    directory = tmp_path / ".factory" / "blueprint"
    directory.mkdir(parents=True)
    (directory / "memory.json").write_text(__import__("json").dumps(_observation()), encoding="utf-8")
    (directory / "bad.json").write_text("{}", encoding="utf-8")
    projection = blueprint_projection(tmp_path)
    assert projection["counts"]["factory.blueprint-memory.v1"] == 1
    assert projection["invalid_count"] == 1


def test_artifact_chain_binds_intent_spec_and_plan_and_detects_drift() -> None:
    chain = build_artifact_chain(
        intent="# Intent\nShip a safe checkout.",
        spec="# Spec\nThe checkout must be idempotent.",
        plan="# Plan\nRun the six audit lanes.",
        author="product-owner",
        project="checkout",
        intent_status="approved",
        files_changed=["src/checkout.py"],
        work_order=["implement", "audit", "review"],
        risks=["duplicate charge"],
        proof_of_completion=["pytest tests/test_checkout.py", "factory proof-review"],
    )
    verified = verify_artifact_chain(chain)
    assert verified["marker"] == "BLUEPRINT_ARTIFACT_CHAIN_VERIFIED"
    assert verified["lineage"] == "intent -> spec -> plan"
    assert all(value is False for value in verified["authority"].values())
    chain["documents"]["plan"]["text"] = "changed"
    with pytest.raises(BlueprintError, match="TAMPERED|drift"):
        verify_artifact_chain(chain)


def test_artifact_chain_requires_proof_contract() -> None:
    with pytest.raises(BlueprintError, match="required"):
        build_artifact_chain(
            intent="intent",
            spec="spec",
            plan="plan",
            author="owner",
            project="demo",
            files_changed=[],
            work_order=["build"],
            proof_of_completion=[],
        )
