from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.appforge_evidence_kit import CANDIDATE_SCHEMA, appforge_init_projection, create_evidence_kit, initialize_appforge
from factoryline.cli import main
from factoryline.revenueforge import RevenueForgeError


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _candidate(tmp_path: Path) -> Path:
    return _write(tmp_path / "candidate.json", {"schema": CANDIDATE_SCHEMA, "candidate": {"bundle_identifier": "com.example.app", "version": "1.2.3", "build_number": "123", "source_commit": "a" * 40}})


def test_evidence_kit_binds_templates_to_one_candidate_and_user_design_input(tmp_path: Path) -> None:
    design = tmp_path / "design-intent.md"
    design.write_text("The user wants a calm, accessible daily planning experience.", encoding="utf-8")
    receipt = create_evidence_kit(tmp_path, _candidate(tmp_path), design, Path(".factory/appforge/kit-123"))
    kit = tmp_path / ".factory/appforge/kit-123"
    assert receipt["marker"] == "APPFORGE_EVIDENCE_KIT_WRITTEN"
    assert receipt["user_design_input"]["sha256"] == hashlib.sha256(design.read_bytes()).hexdigest()
    media = json.loads((kit / "store-media-contract.json").read_text(encoding="utf-8"))
    quality = json.loads((kit / "quality-contract.json").read_text(encoding="utf-8"))
    evidence = json.loads((kit / "quality-evidence.json").read_text(encoding="utf-8"))
    device_journeys = json.loads((kit / "device-reality-journeys.json").read_text(encoding="utf-8"))
    device_evidence = json.loads((kit / "device-reality-evidence.json").read_text(encoding="utf-8"))
    assert media["candidate"] == quality["candidate"] == receipt["candidate"]
    assert media["intent_sha256"] == quality["user_design_input_sha256"] == receipt["user_design_input"]["sha256"]
    assert [item["min_count"] for item in media["media_sets"]] == [10, 3]
    assert evidence["design_review"]["user_design_input_considered"] is False
    assert len(device_journeys["required_journeys"]) == 13
    assert device_evidence["user_design_input_sha256"] == receipt["user_design_input"]["sha256"]
    assert "credentials" in (kit / "README.md").read_text(encoding="utf-8").lower()


def test_evidence_kit_refuses_overwrite_and_invalid_candidate_schema(tmp_path: Path) -> None:
    design = tmp_path / "design.json"
    design.write_text("{}", encoding="utf-8")
    candidate = _candidate(tmp_path)
    create_evidence_kit(tmp_path, candidate, design, Path("kit"))
    with pytest.raises(RevenueForgeError, match="destination already exists"):
        create_evidence_kit(tmp_path, candidate, design, Path("kit"))
    invalid = _write(tmp_path / "invalid.json", {"candidate": {}})
    with pytest.raises(RevenueForgeError, match="factory.appforge.release-candidate.v1"):
        create_evidence_kit(tmp_path, invalid, design, Path("other-kit"))


def test_appforge_init_captures_user_mission_without_claiming_evidence(tmp_path: Path) -> None:
    receipt = initialize_appforge(
        tmp_path, Path(".factory/appforge/init-123"), app_name="Calm Plan",
        bundle_identifier="com.example.calm", version="1.0.0", build_number="100",
        source_commit="c" * 40, audience="Busy parents", primary_job="Plan a calmer day",
        desired_emotion="calm confidence",
    )
    initial = tmp_path / ".factory/appforge/init-123"
    assert receipt["marker"] == "APPFORGE_INIT_WRITTEN"
    assert receipt["candidate"]["build_number"] == "100"
    assert "not a design approval" in receipt["claim_boundary"]
    candidate = json.loads((initial / "release-candidate.json").read_text(encoding="utf-8"))
    assert candidate["schema"] == CANDIDATE_SCHEMA
    assert "user's actual constraints" in (initial / "NEXT.md").read_text(encoding="utf-8")
    projection = appforge_init_projection(tmp_path)
    assert projection["current_count"] == 1
    assert projection["latest"]["candidate"]["build_number"] == "100"


def test_appforge_status_is_a_read_only_projection_for_ide_adapters(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["revenue", "appforge-status", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "factory.appforge.design-projection.v1"
    assert result["marker"] == "APPFORGE_DESIGN_READ_ONLY"
    assert result["current_count"] == 0
    assert all(value is False for value in result["authority"].values())
