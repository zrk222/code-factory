from __future__ import annotations

from pathlib import Path

import pytest

from factoryline.intake_grill import (
    confirm_intake,
    grill_intake,
    intake_status,
    verify_intake_confirmation,
    verify_intake_grill,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.product_missions import (
    ProductMissionError,
    compile_product_prd,
    create_mission,
    plan_value_slices,
    verify_mission,
)


PRD = """# Intake proof

## Actors
- Reviewer

## Requirements
- REQ-1: When a reviewer submits a local Python CLI request, the system shall record a visible receipt.

## Acceptance
Scenario: record receipt
  Given a reviewer has a valid request
  When the reviewer runs the CLI
  Then a receipt is visible in the workspace
"""


def _prd(tmp_path: Path) -> Path:
    path = tmp_path / "PRD.md"
    path.write_text(PRD, encoding="utf-8")
    return path


def _confirmation(tmp_path: Path) -> dict:
    grilled = grill_intake(_prd(tmp_path), tmp_path)
    assert grilled["status"] == "needs_confirmation"
    assert grilled["framework_shortlist"][0]["id"] == "python-service"
    assert verify_intake_grill(tmp_path, Path(grilled["path"]))["valid"] is True
    return confirm_intake(
        tmp_path, Path(grilled["path"]), "python-service",
        "A reviewer can create a local receipt from one valid request.",
        "A Given/When/Then CLI scenario produces a hash-bound receipt under .factory.",
        "local_only", "release-owner", "Python CLI is the declared first delivery surface.",
        "The delivery surface changes or the acceptance scenario changes.",
    )


def test_intake_is_source_bound_idempotent_and_has_no_execution_authority(tmp_path: Path):
    first = grill_intake(_prd(tmp_path), tmp_path)
    second = grill_intake(_prd(tmp_path), tmp_path)

    assert second["idempotent"] is True
    assert first["intake_sha256"] == second["intake_sha256"]
    assert first["authority"]["implementation"] == "not_authorized"
    assert "INTAKE_DECISION_TREE" in first["markers"]
    assert not (tmp_path / ".factory" / "missions").exists()


def test_intake_explicitly_grills_forbidden_outcomes_negative_cases_and_pr_proof(tmp_path: Path):
    grilled = grill_intake(_prd(tmp_path), tmp_path)
    question_ids = {question["id"] for question in grilled["questions"]}

    assert {"Q-FORBIDDEN", "Q-NEGATIVE-CASE", "Q-PR-REVIEW"} <= question_ids
    assert "Before code, seal the intent as an Oracle Contract" in Path(grilled["markdown"]).read_text(encoding="utf-8")


def test_confirmed_intake_binds_product_graph_and_required_mission(tmp_path: Path):
    confirmation = _confirmation(tmp_path)
    verified = verify_intake_confirmation(tmp_path, Path(confirmation["path"]))
    assert verified["valid"] is True
    assert verified["confirmation"]["decision"]["framework"] == "python-service"

    graph = compile_product_prd(_prd(tmp_path), tmp_path, intake_path=Path(confirmation["path"]))
    assert graph["intake"]["framework"] == "python-service"
    assert "PRODUCT_INTAKE_CONFIRMATION_BOUND" in graph["markers"]
    slices = plan_value_slices(Path(graph["path"]), tmp_path)
    mission = create_mission(Path(slices["path"]), slices["slices"][0]["id"], tmp_path, "release-owner", require_intake=True)

    assert "INTAKE_CONFIRMATION_BOUND" in mission["markers"]
    assert verify_mission(Path(mission["path"]))["valid"] is True
    snapshot = graph_ops_snapshot(tmp_path)
    intake_nodes = [node for node in snapshot["nodes"] if node["kind"] == "intake"]
    assert len(intake_nodes) == 1
    assert intake_nodes[0]["status"] == "confirmed"
    assert "GRAPH_OPS_INTAKE_DECISIONS_READ_ONLY" in snapshot["markers"]
    status = intake_status(tmp_path, _prd(tmp_path))
    assert status["found"] is True
    assert status["latest"]["framework"] == "python-service"


def test_required_intake_fails_closed_and_mismatched_prd_cannot_bind(tmp_path: Path):
    graph = compile_product_prd(_prd(tmp_path), tmp_path)
    slices = plan_value_slices(Path(graph["path"]), tmp_path)
    with pytest.raises(ProductMissionError, match="INTAKE_CONFIRMATION_REQUIRED"):
        create_mission(Path(slices["path"]), slices["slices"][0]["id"], tmp_path, "release-owner", require_intake=True)

    confirmation = _confirmation(tmp_path)
    changed = tmp_path / "PRD.md"
    changed.write_text(PRD + "\n- Updated after confirmation\n", encoding="utf-8")
    with pytest.raises(ProductMissionError, match="INTAKE_SOURCE_MISMATCH"):
        compile_product_prd(changed, tmp_path, force=True, intake_path=Path(confirmation["path"]))


def test_intake_rejects_unshortlisted_framework_and_secret_like_decisions(tmp_path: Path):
    grilled = grill_intake(_prd(tmp_path), tmp_path)
    with pytest.raises(ProductMissionError, match="INTAKE_FRAMEWORK_NOT_SHORTLISTED"):
        confirm_intake(tmp_path, Path(grilled["path"]), "jetbrains-plugin", "A reviewer has a receipt outcome.", "A receipt is visible from the CLI.", "local_only", "owner", "A bounded reason.")
    with pytest.raises(ProductMissionError, match="INTAKE_DECISION_INVALID"):
        confirm_intake(tmp_path, Path(grilled["path"]), "python-service", "sk-abcdefghijklmnop", "A receipt is visible from the CLI.", "local_only", "owner", "A bounded reason.")


def test_intake_rejects_vague_intent_and_non_observable_acceptance_before_writing(tmp_path: Path):
    grilled = grill_intake(_prd(tmp_path), tmp_path)
    with pytest.raises(ProductMissionError, match="INTAKE_INTENT_UNCLEAR"):
        confirm_intake(tmp_path, Path(grilled["path"]), "python-service", "Make it better for users.", "The task works.", "local_only", "owner", "A bounded reason.")
    assert not (tmp_path / ".factory" / "intake-confirmations").exists()
