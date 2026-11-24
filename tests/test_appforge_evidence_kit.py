from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.appforge_evidence_kit import (
    CANDIDATE_SCHEMA,
    appforge_init_projection,
    create_evidence_kit,
    initialize_appforge,
)
from factoryline.cli import main
from factoryline.revenueforge import RevenueForgeError


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _candidate(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "candidate.json",
        {
            "schema": CANDIDATE_SCHEMA,
            "candidate": {
                "bundle_identifier": "com.example.app",
                "version": "1.2.3",
                "build_number": "123",
                "source_commit": "a" * 40,
            },
        },
    )


def test_evidence_kit_binds_templates_to_one_candidate_and_user_design_input(
    tmp_path: Path,
) -> None:
    design = tmp_path / "design-intent.md"
    design.write_text(
        "The user wants a calm, accessible daily planning experience.", encoding="utf-8"
    )
    receipt = create_evidence_kit(
        tmp_path, _candidate(tmp_path), design, Path(".factory/appforge/kit-123")
    )
    kit = tmp_path / ".factory/appforge/kit-123"
    assert receipt["marker"] == "APPFORGE_EVIDENCE_KIT_WRITTEN"
    assert (
        receipt["user_design_input"]["sha256"]
        == hashlib.sha256(design.read_bytes()).hexdigest()
    )
    media = json.loads((kit / "store-media-contract.json").read_text(encoding="utf-8"))
    quality = json.loads((kit / "quality-contract.json").read_text(encoding="utf-8"))
    evidence = json.loads((kit / "quality-evidence.json").read_text(encoding="utf-8"))
    device_journeys = json.loads(
        (kit / "device-reality-journeys.json").read_text(encoding="utf-8")
    )
    device_evidence = json.loads(
        (kit / "device-reality-evidence.json").read_text(encoding="utf-8")
    )
    assert media["candidate"] == quality["candidate"] == receipt["candidate"]
    assert (
        media["intent_sha256"]
        == quality["user_design_input_sha256"]
        == receipt["user_design_input"]["sha256"]
    )
    assert [item["min_count"] for item in media["media_sets"]] == [10, 3]
    assert evidence["design_review"]["user_design_input_considered"] is False
    assert len(device_journeys["required_journeys"]) == 13
    assert (
        device_evidence["user_design_input_sha256"]
        == receipt["user_design_input"]["sha256"]
    )
    assert "credentials" in (kit / "README.md").read_text(encoding="utf-8").lower()


def test_evidence_kit_refuses_overwrite_and_invalid_candidate_schema(
    tmp_path: Path,
) -> None:
    design = tmp_path / "design.json"
    design.write_text("{}", encoding="utf-8")
    candidate = _candidate(tmp_path)
    create_evidence_kit(tmp_path, candidate, design, Path("kit"))
    with pytest.raises(RevenueForgeError, match="destination already exists"):
        create_evidence_kit(tmp_path, candidate, design, Path("kit"))
    invalid = _write(tmp_path / "invalid.json", {"candidate": {}})
    with pytest.raises(
        RevenueForgeError, match="factory.appforge.release-candidate.v1"
    ):
        create_evidence_kit(tmp_path, invalid, design, Path("other-kit"))


def test_appforge_init_captures_user_mission_without_claiming_evidence(
    tmp_path: Path,
) -> None:
    receipt = initialize_appforge(
        tmp_path,
        Path(".factory/appforge/init-123"),
        app_name="Calm Plan",
        bundle_identifier="com.example.calm",
        version="1.0.0",
        build_number="100",
        source_commit="c" * 40,
        audience="Busy parents",
        primary_job="Plan a calmer day",
        desired_emotion="calm confidence",
    )
    initial = tmp_path / ".factory/appforge/init-123"
    assert receipt["marker"] == "APPFORGE_INIT_WRITTEN"
    assert receipt["candidate"]["build_number"] == "100"
    assert "not a design approval" in receipt["claim_boundary"]
    candidate = json.loads(
        (initial / "release-candidate.json").read_text(encoding="utf-8")
    )
    assert candidate["schema"] == CANDIDATE_SCHEMA
    assert "user's actual constraints" in (initial / "NEXT.md").read_text(
        encoding="utf-8"
    )
    projection = appforge_init_projection(tmp_path)
    assert projection["current_count"] == 1
    assert projection["latest"]["candidate"]["build_number"] == "100"


def test_appforge_status_is_a_read_only_projection_for_ide_adapters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["revenue", "appforge-status", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "factory.appforge.design-projection.v1"
    assert result["marker"] == "APPFORGE_DESIGN_READ_ONLY"
    assert result["current_count"] == 0
    assert all(value is False for value in result["authority"].values())


def test_appforge_stage_status_is_actionable_and_does_not_scan_other_stages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from factoryline import canonical_sha
    from factoryline.appforge_design import appforge_status_lines

    root = tmp_path / ".factory" / "appforge"
    path = root / "submission-assurance.json"
    core = {
        "schema": "factory.appforge.submission-assurance-receipt.v1",
        "marker": "APPFORGE_SUBMISSION_DOSSIER_BLOCKED",
        "ok": False,
        "findings": [
            {"gate": "Store media truth", "detail": "Capture evidence is missing"}
        ],
    }
    _write(path, {**core, "receipt_sha256": canonical_sha(core)})
    _write(root / "quality-audit-corrupt.json", 42)
    calls = []
    rglob = Path.rglob

    def recording_glob(directory, pattern):
        calls.append(pattern)
        return rglob(directory, pattern)

    monkeypatch.setattr(Path, "rglob", recording_glob)
    invocation = ["revenue", "appforge-status", "--root", str(tmp_path)]
    focus = [*invocation, "--stage", "submission-assurance"]
    original = path.read_bytes()
    assert main([*focus, "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["schema"] == "factory.appforge.stage-projection.v1"
    assert summary["status"]["latest"]["ok"] is False
    assert summary["help_command"] == [
        "factory",
        "revenue",
        "submission-assurance",
        "--help",
    ]
    assert "Capture evidence is missing" in list(appforge_status_lines(summary))
    assert calls == ["submission-assurance*.json"]

    assert main(focus) == 0
    output = capsys.readouterr().out
    assert "Capture evidence is missing" in output
    assert "factory revenue submission-assurance --help" in output
    assert "quality-audit" not in output
    assert path.read_bytes() == original

    calls.clear()
    assert main([*invocation, "--stage", "unknown", "--json"]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["code"] == "APPFORGE_STATUS_STAGE_UNKNOWN"
    assert "submission-assurance" in error["message"]
    assert calls == []

    assert main([*invocation, "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert calls == ["*.json"]
    assert summary["quality_audit"]["invalid_count"] == 1
    assert summary["submission_assurance"]["latest"]["ok"] is False


def test_shared_receipt_discovery_and_reader_preserve_workspace_scope(
    tmp_path: Path,
) -> None:
    from factoryline.revenue_evidence import read_receipt, receipt_paths

    root = tmp_path / "workspace"
    evidence = root / ".factory/appforge/reports"
    target = _write(evidence / "receipt.json", {"current": True})
    malformed = _write(evidence / "invalid.json", [])
    _write(evidence / "receipt.log", {"irrelevant": True})
    outside = _write(tmp_path / "outside.json", {"outside": True})
    inventory = tuple(receipt_paths(root, "*.json"))
    assert list(receipt_paths(root, "receipt*.json", inventory)) == [target]
    assert read_receipt(root, target) == {"current": True}
    with pytest.raises(ValueError, match="JSON object"):
        read_receipt(root, malformed)
    with pytest.raises(ValueError):
        read_receipt(root, outside)


@pytest.mark.parametrize("stage", ["app-review", "quality-audit"])
def test_focused_status_shows_recorded_repair_guidance(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    stage: str,
) -> None:
    from factoryline import canonical_sha, compat_sha
    from factoryline.app_review_gate import SCHEMA as REVIEW_SCHEMA
    from factoryline.appforge_quality_audit import RECEIPT_SCHEMA as QUALITY_SCHEMA

    current = {
        "schema": REVIEW_SCHEMA if stage == "app-review" else QUALITY_SCHEMA,
        "marker": "APP_REVIEW_BLOCKED"
        if stage == "app-review"
        else "APPFORGE_QUALITY_AUDIT_BLOCKED",
        "ok": False,
        "findings": [{"remediation": "Publish a reachable privacy policy."}],
    }
    digest = canonical_sha if stage == "app-review" else compat_sha
    _write(
        tmp_path / ".factory/appforge" / f"{stage}.json",
        {**current, "receipt_sha256": digest(current)},
    )
    args = ["revenue", "appforge-status", "--root", str(tmp_path), "--stage", stage]
    assert main([*args, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["repair_messages"] == ["Publish a reachable privacy policy."]
    assert main(args) == 0
    assert "Publish a reachable privacy policy." in capsys.readouterr().out

    if stage == "quality-audit":
        assert (
            main(["revenue", "appforge-status", "--root", str(tmp_path), "--json"]) == 0
        )
        full = json.loads(capsys.readouterr().out)
        assert "findings" not in full["quality_audit"]["latest"]
