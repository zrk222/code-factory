from pathlib import Path
import json

import pytest

from factoryline.appforge_design import (
    appforge_design_projection,
    compile_appforge_design,
)
from factoryline.revenueforge import RevenueForgeError
import factoryline.revenue_evidence as revenue_evidence


def test_compiles_story_led_seven_discipline_workspace(tmp_path: Path) -> None:
    brief = {
        "app_name": "Calm Ledger",
        "audience": "independent professionals",
        "primary_job": "understand recurring income",
        "desired_emotion": "calm control",
        "screens": [
            {
                "id": "home",
                "user_goal": "see current position",
                "primary_action": "review forecast",
            },
            {
                "id": "detail",
                "user_goal": "understand one change",
                "primary_action": "accept plan",
            },
        ],
    }
    source = tmp_path / "brief.json"
    source.write_text(json.dumps(brief), encoding="utf-8")
    result = compile_appforge_design(tmp_path, source, Path(".factory/appforge/design"))
    assert result["marker"] == "APPFORGE_DESIGN_WORKSPACE_WRITTEN"
    contract = json.loads(
        (tmp_path / result["artifacts"]["contract"]).read_text(encoding="utf-8")
    )
    assert len(contract["disciplines"]) == 7
    assert contract["storyboard"][0]["narrative_beat"] == "mission"
    assert contract["palette"]["constraints"]["normal_text_contrast"] == "4.5:1"
    assert all(contract["gates"].values())
    assert contract["authority"]["design_intent_override"] is False
    assert contract["action_summary"].startswith("Turn confirmed user intent")
    skill = (tmp_path / result["artifacts"]["skill"]).read_text(encoding="utf-8")
    assert "## Ten-second value" in skill
    assert "## Recognizable actions" in skill
    assert "## Stop and recovery" in skill
    assert "unknown never becomes pass" in skill
    assert "Before executing any action" in skill
    projection = appforge_design_projection(tmp_path)
    assert projection["marker"] == "APPFORGE_DESIGN_READ_ONLY"
    assert projection["current_count"] == 1
    assert projection["invalid_count"] == 0
    assert projection["latest"]["receipt_sha256"] == result["receipt_sha256"]
    assert projection["init"]["marker"] == "APPFORGE_INIT_READ_ONLY"
    assert all(value is False for value in projection["authority"].values())


def test_design_brief_rejects_unknown_prohibited_pattern(tmp_path: Path) -> None:
    source = tmp_path / "brief.json"
    source.write_text(
        json.dumps(
            {
                "app_name": "A",
                "audience": "B",
                "primary_job": "C",
                "desired_emotion": "D",
                "screens": [{"id": "home", "user_goal": "act"}],
                "prohibited_patterns": ["invented"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RevenueForgeError) as error:
        compile_appforge_design(tmp_path, source, Path("out"))
    assert error.value.code == "APPFORGE_DESIGN_BRIEF_INVALID"


def test_appforge_projection_rejects_a_tampered_receipt(tmp_path: Path) -> None:
    directory = tmp_path / ".factory" / "appforge" / "design"
    directory.mkdir(parents=True)
    (directory / "appforge-design-receipt.json").write_text(
        json.dumps(
            {"schema": "factory.appforge.design-receipt.v1", "receipt_sha256": "0" * 64}
        ),
        encoding="utf-8",
    )
    projection = appforge_design_projection(tmp_path)
    assert projection["current_count"] == 0
    assert projection["invalid_count"] == 1
    assert projection["latest"] is None


def test_repeated_compile_skips_replacing_identical_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    brief = {
        "app_name": "Calm Ledger",
        "audience": "independent professionals",
        "primary_job": "understand recurring income",
        "desired_emotion": "calm control",
        "screens": [{"id": "home", "user_goal": "see current position"}],
    }
    source = tmp_path / "brief.json"
    source.write_text(json.dumps(brief), encoding="utf-8")
    result = compile_appforge_design(tmp_path, source, Path(".factory/appforge/design"))
    paths = [tmp_path / relative for relative in result["artifacts"].values()]
    original = {path: path.read_bytes() for path in paths}
    skill_path = tmp_path / result["artifacts"]["skill"]
    original_write_text = Path.write_text

    def reject_replace(*_args: object, **_kwargs: object) -> None:
        pytest.fail("an unchanged AppForge artifact was replaced")

    def reject_skill_rewrite(
        path: Path, *args: object, **kwargs: object
    ) -> int:
        if path == skill_path:
            pytest.fail("an unchanged AppForge skill was rewritten")
        return original_write_text(path, *args, **kwargs)

    monkeypatch.setattr(revenue_evidence.os, "replace", reject_replace)
    monkeypatch.setattr(Path, "write_text", reject_skill_rewrite)
    repeated = compile_appforge_design(tmp_path, source, Path(".factory/appforge/design"))

    assert repeated["receipt_sha256"] == result["receipt_sha256"]
    assert {path: path.read_bytes() for path in paths} == original
