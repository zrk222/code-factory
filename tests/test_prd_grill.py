from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.product_missions import ProductMissionError, analyze_product_text, compile_product_text
from factoryline.prd_grill import grill_prd, verify_prd_grill


THIN_PRD = "# Draft\n\nA useful idea without a product contract.\n"

COMPLETE_PRD = """# Signal Desk

## Actors
- Operator: reviews customer signals.

## Outcomes
- Reduce signal triage time below five minutes.

## Journeys and business rules
- Journey: an operator captures a signal, reviews its priority reason, then exports an audit report.
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
- REQ-DASH: The operator must see prioritized signals and their reasons.

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


def test_prd_grill_writes_a_bounded_frontier_without_mutating_source(tmp_path: Path) -> None:
    prd = tmp_path / "PRD.md"
    prd.write_text(THIN_PRD, encoding="utf-8")

    result = grill_prd(prd, tmp_path, mode="quick")

    assert prd.read_text(encoding="utf-8") == THIN_PRD
    assert result["status"] == "needs_input"
    assert len(result["questions"]) == 3
    assert [question["id"] for question in result["questions"]] == ["Q-REQUIREMENTS", "Q-ACTORS", "Q-OUTCOMES"]
    deferred = {question["id"]: question for question in result["deferred_questions"]}
    assert deferred["Q-ACCEPTANCE"]["deferred_by"] == ["Q-REQUIREMENTS"]
    assert deferred["Q-JOURNEY"]["deferred_by"] == ["Q-ACTORS"]
    assert deferred["Q-SUCCESS-EVENT"]["deferred_by"] == ["Q-OUTCOMES"]
    assert result["authority"] == {"implementation": "not_authorized", "external_effects": "not_authorized"}
    assert Path(result["markdown"]).read_text(encoding="utf-8").count("**Answer:**") == 3
    assert verify_prd_grill(Path(result["path"]))["valid"] is True

    replay = grill_prd(prd, tmp_path, mode="quick")
    assert replay["idempotent"] is True
    assert replay["generated_at"] == result["generated_at"]


def test_prd_grill_confirms_only_a_complete_reviewed_contract(tmp_path: Path) -> None:
    prd = tmp_path / "PRD.md"
    prd.write_text(COMPLETE_PRD, encoding="utf-8")

    analysis = analyze_product_text(COMPLETE_PRD, source_name="PRD.md")
    assert analysis["gaps"] == []
    assert not (tmp_path / ".factory" / "products").exists()

    result = grill_prd(prd, tmp_path, mode="deep", confirm=True)

    assert result["status"] == "confirmed"
    assert result["questions"] == []
    assert "PRD_GRILL_SHARED_UNDERSTANDING_CONFIRMED" in result["markers"]


def test_compile_product_text_still_writes_the_reviewable_product_graph(tmp_path: Path) -> None:
    graph = compile_product_text(COMPLETE_PRD, root=tmp_path, source_name="PRD.md")

    assert graph["schema"] == "factory.product_graph.v1"
    assert Path(graph["path"]).is_file()


def test_prd_grill_refuses_confirmation_while_decisions_remain(tmp_path: Path) -> None:
    prd = tmp_path / "PRD.md"
    prd.write_text(THIN_PRD, encoding="utf-8")

    with pytest.raises(ProductMissionError, match="PRD_GRILL_UNRESOLVED"):
        grill_prd(prd, tmp_path, confirm=True)
    assert not (tmp_path / ".factory" / "prd-grills").exists()


def test_prd_grill_cli_is_machine_readable_and_verifiable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    prd = tmp_path / "PRD.md"
    prd.write_text(THIN_PRD, encoding="utf-8")

    assert main(["prd", "grill", str(prd), "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert main(["prd", "verify", result["path"], "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "PRD_GRILL_VERIFIED"


def test_prd_grill_rejects_invalid_source_without_artifacts(tmp_path: Path) -> None:
    broken = tmp_path / "broken.md"
    broken.write_bytes(b"\xff")

    with pytest.raises(ProductMissionError, match="PRD_ENCODING_INVALID"):
        grill_prd(broken, tmp_path)
    assert not (tmp_path / ".factory" / "prd-grills").exists()
