from __future__ import annotations

from pathlib import Path

from factoryline.grill_engine import (
    answer_question,
    confirm_grill,
    next_question,
    start_grill,
)


def test_grill_is_one_question_at_a_time_and_requires_confirmation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "PRD.md"
    source.write_text("A bounded audit workflow for a developer.", encoding="utf-8")
    started = start_grill(tmp_path, "audit-slice", source)
    assert started["next"]["id"] == "intent"
    assert next_question(tmp_path, "audit-slice")["status"] == "QUESTION_REQUIRED"
    for question in started["questions"]:
        if question["required"]:
            answer_question(
                tmp_path,
                "audit-slice",
                question["id"],
                f"Human answer for {question['id']}",
                answered_by="owner",
            )
    assert next_question(tmp_path, "audit-slice")["status"] == "CONFIRMATION_REQUIRED"
    confirmed = confirm_grill(tmp_path, "audit-slice", approved_by="owner")
    assert confirmed["status"] == "confirmed"
    assert confirmed["confirmation_sha256"]
    assert next_question(tmp_path, "audit-slice")["status"] == "COMPLETE"
