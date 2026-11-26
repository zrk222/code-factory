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


def test_design_status_preserves_depth_limit_and_isolates_bad_receipts(
    tmp_path: Path,
) -> None:
    from factoryline import canonical_sha

    base = tmp_path / ".factory/appforge"
    for number in range(105):
        path = base / f"design-{number:03}" / "appforge-design-receipt.json"
        path.parent.mkdir(parents=True)
        core = {"schema": "factory.appforge.design-receipt.v1", "number": number}
        path.write_text(
            json.dumps({**core, "receipt_sha256": canonical_sha(core)}),
            encoding="utf-8",
        )
    malformed = base / "design-000" / "appforge-design-receipt.json"
    malformed.write_bytes(b"\xff")
    nested = base / "archive" / "nested" / malformed.name
    nested.parent.mkdir(parents=True)
    nested.write_text("null", encoding="utf-8")

    full = appforge_design_projection(tmp_path)
    focus = appforge_design_projection(tmp_path, stage="design")["status"]
    assert full["current_count"] == focus["current_count"] == 99
    assert full["invalid_count"] == focus["invalid_count"] == 1
    assert full["latest"] == focus["latest"]
    assert full["latest"]["number"] == 99


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

    def reject_skill_rewrite(path: Path, *args: object, **kwargs: object) -> int:
        if path == skill_path:
            pytest.fail("an unchanged AppForge skill was rewritten")
        return original_write_text(path, *args, **kwargs)

    monkeypatch.setattr(revenue_evidence.os, "replace", reject_replace)
    monkeypatch.setattr(Path, "write_text", reject_skill_rewrite)
    repeated = compile_appforge_design(
        tmp_path, source, Path(".factory/appforge/design")
    )

    assert repeated["receipt_sha256"] == result["receipt_sha256"]
    assert {path: path.read_bytes() for path in paths} == original


def _cli(*argv):
    from factoryline.cli import main

    return main(list(argv))


def _af_workspace(tmp_path: Path, monkeypatch, *, kit: bool = True, build: str = "42") -> Path:
    monkeypatch.chdir(tmp_path)
    out = f".factory/appforge/init-{build}"
    assert _cli("revenue", "appforge-init", "--root", ".", "--out-dir", out, "--app-name", "A",
                "--bundle-identifier", "com.e.a", "--version", "1.0", "--build-number", build,
                "--source-commit", "a" * 40, "--audience", "x", "--primary-job", "y", "--desired-emotion", "z",
                "--json") == 0
    assert _cli("revenue", "appforge-design", "--root", ".", "--brief", f"{out}/appforge-design-brief.json",
                "--out-dir", ".factory/appforge/design", "--json") == 0
    if kit:
        assert _cli("revenue", "evidence-kit", "--root", ".", "--candidate", f"{out}/release-candidate.json",
                    "--design-input", f"{out}/user-design-input.md", "--out-dir", f".factory/appforge/evidence-{build}",
                    "--json") == 0
    return tmp_path


def test_appforge_next_walks_the_chain(tmp_path: Path, monkeypatch, capsys) -> None:
    from factoryline.appforge_design import appforge_next

    assert appforge_next(tmp_path)["stage"] == "init"
    assert appforge_next(tmp_path)["human_required"] is True
    _af_workspace(tmp_path, monkeypatch, kit=False)
    capsys.readouterr()
    step = appforge_next(tmp_path)
    assert step["stage"] == "evidence-kit"
    assert "--candidate" in step["argv"] and ".factory/appforge/init-42/release-candidate.json" in step["argv"]
    assert _cli(*step["argv"][1:]) == 0  # the printed command runs as-is
    capsys.readouterr()
    step = appforge_next(tmp_path)
    assert step["stage"] == "native-surface" and step["inputs_missing"] == ["--contract", "--evidence"]


def test_appforge_next_reports_a_blocked_stage_and_all_done(tmp_path: Path, monkeypatch) -> None:
    import factoryline.appforge_design as design

    statuses = {name: {"current_count": 1, "latest": {"ok": True, "marker": "OK"}} for name, *_ in design._NEXT_CHAIN}
    statuses["quality_audit"] = {"current_count": 1, "latest": {"ok": False, "marker": "QUALITY_BLOCKED",
                                                                 "findings": [{"detail": "contrast below 4.5"}]}}
    monkeypatch.setattr(design, "appforge_design_projection", lambda _root: {**statuses["design"], **statuses})
    monkeypatch.setattr(design, "_receipt_only_status", lambda _w, _p: statuses["store_media"])
    step = design.appforge_next(tmp_path)
    assert step["stage"] == "quality-audit" and step["state"] == "blocked" and "contrast below 4.5" in step["why"]
    statuses["quality_audit"] = {"current_count": 1, "latest": {"ok": True, "marker": "OK"}}
    assert design.appforge_next(tmp_path)["stage"] == "complete"


def test_new_build_number_marks_downstream_receipts_stale(tmp_path: Path, monkeypatch, capsys) -> None:
    from factoryline.appforge_design import appforge_next

    _af_workspace(tmp_path, monkeypatch)
    assert appforge_next(tmp_path)["stale_for_candidate"] == []
    _cli("revenue", "appforge-init", "--root", ".", "--out-dir", ".factory/appforge/init-43", "--app-name", "A",
         "--bundle-identifier", "com.e.a", "--version", "1.0", "--build-number", "43", "--source-commit", "a" * 40,
         "--audience", "x", "--primary-job", "y", "--desired-emotion", "z", "--json")
    capsys.readouterr()
    assert "evidence-kit" in appforge_next(tmp_path)["stale_for_candidate"]


def test_status_after_kit_has_no_stale_lines_and_a_next_line(tmp_path: Path, monkeypatch, capsys) -> None:
    _af_workspace(tmp_path, monkeypatch)
    capsys.readouterr()
    assert _cli("revenue", "appforge-status", "--root", ".") == 0
    text = capsys.readouterr().out
    assert "Stale or invalid" not in text and "needs evidence review" not in text
    assert sum(line.startswith("next: ") for line in text.splitlines()) == 1
    assert _cli("revenue", "appforge-status", "--root", ".", "--brief", "--json") == 0
    assert len(capsys.readouterr().out.splitlines()) < 40


def test_appforge_group_matches_revenue_spelling_and_status_writes_nothing(tmp_path: Path, monkeypatch, capsys):
    _af_workspace(tmp_path, monkeypatch)
    capsys.readouterr()
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert _cli("appforge", "status", "--root", ".", "--json") == 0
    short = capsys.readouterr().out
    assert _cli("revenue", "appforge-status", "--root", ".", "--json") == 0
    assert capsys.readouterr().out == short
    assert _cli("appforge", "next", "--root", ".", "--json") == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "APPFORGE_NEXT_READ_ONLY"
    assert {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


def test_stage_inputs_default_to_the_producers_outputs() -> None:
    import argparse

    from factoryline.cli_revenue import APPFORGE_SHORT_NAMES, _STAGE_INPUT_DEFAULTS, add_parser

    parser = argparse.ArgumentParser(prog="factory")
    add_parser(parser.add_subparsers(dest="cmd"))
    args = parser.parse_args(["revenue", "submission-assurance", "--contract", "c.json", "--saas-proof", "s.json"])
    assert args.app_review == ".factory/appforge/app-review.json" and args.quality_audit.endswith("quality-audit.json")
    explicit = parser.parse_args(["revenue", "submission-assurance", "--contract", "c", "--saas-proof", "s",
                                  "--app-review", "mine.json"])
    assert explicit.app_review == "mine.json"
    assert parser.parse_args(["appforge", "kit", "--candidate", "c", "--design-input", "d", "--out-dir", "o"]).revenue_cmd == "evidence-kit"
    assert set(APPFORGE_SHORT_NAMES.values()) >= {command for command, _ in _STAGE_INPUT_DEFAULTS}
