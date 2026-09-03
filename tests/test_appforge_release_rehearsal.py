from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import factoryline.appforge_release_rehearsal as rehearsal_module
from factoryline.appforge_evidence_kit import CANDIDATE_SCHEMA
from factoryline.appforge_release_rehearsal import PROFILE_SCHEMA, ZEALOT_MANIFEST_SCHEMA, create_release_rehearsal, release_rehearsal_projection
from factoryline.appforge_submission_assurance import RECEIPT_SCHEMA as ASSURANCE_SCHEMA
from factoryline.cli import main
from factoryline.revenueforge import RevenueForgeError


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _candidate(root: Path) -> tuple[dict[str, str], Path]:
    candidate = {"bundle_identifier": "com.example.app", "version": "1.2.3", "build_number": "42", "source_commit": "a" * 40}
    return candidate, _write(root / "candidate.json", {"schema": CANDIDATE_SCHEMA, "candidate": candidate})


def _assurance(root: Path, candidate: dict[str, str]) -> Path:
    core = {"schema": ASSURANCE_SCHEMA, "ok": True, "candidate": candidate}
    return _write(root / "assurance.json", {**core, "receipt_sha256": _sha(core)})


def _profile(root: Path, candidate: dict[str, str], *, provider: str = "asc_cli", channel: str = "testflight_external") -> Path:
    if provider == "asc_cli":
        config = {"app_store_connect_app_id": "123456789"}
    elif provider == "fastlane":
        config = {"lane": "beta_release"}
    elif provider == "cider":
        _write(root / "Cider.yml", "release:\n  track: app_store\n")
        config = {"manifest_path": "Cider.yml"}
    elif provider == "swiftlane":
        _write(root / "Release.swift", "import Swiftlane\nlet workflow = Workflow()\nlet build = Build()\nlet test = Test()\nlet archive = Archive()\nlet export = ExportArchive()\n")
        config = {"workflow_path": "Release.swift"}
    else:
        _write(root / "beta-distribution.json", {"schema": ZEALOT_MANIFEST_SCHEMA, "candidate": candidate, "platform": "ios", "artifact": {"sha256": "b" * 64}, "distribution": {"channel": "internal-qa", "audience_ref": "ios-qa"}})
        config = {"manifest_path": "beta-distribution.json"}
    return _write(root / "profile.json", {"schema": PROFILE_SCHEMA, "candidate": candidate, "provider": provider, "release_channel": channel, "provider_config": config})


def test_release_rehearsal_seals_exact_candidate_and_preserves_external_state_boundaries(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    receipt = create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), _profile(tmp_path, candidate), Path(".factory/appforge/release-rehearsal.json"))
    assert receipt["marker"] == "APPFORGE_RELEASE_REHEARSAL_READY"
    assert receipt["stage_count"] == 9
    states = {item["stage"]: item["status"] for item in receipt["state_matrix"]}
    assert states["local_readiness"] == "ready"
    assert states["upload"] == "not_attempted"
    assert states["provider_processing"] == "not_attempted"
    assert states["tester_group_assignment"] == "not_attempted"
    assert states["app_review_submission"] == "not_applicable"
    assert receipt["authority"]["execution"] is False
    assert release_rehearsal_projection(tmp_path)["latest"]["receipt_sha256"] == receipt["receipt_sha256"]


def test_release_rehearsal_cli_writes_only_the_local_sealed_receipt(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    output = tmp_path / ".factory" / "appforge" / "cli-release-rehearsal.json"
    assert main([
        "revenue", "appforge-rehearse", "--root", str(tmp_path), "--candidate", str(candidate_path),
        "--submission-assurance", str(_assurance(tmp_path, candidate)), "--profile", str(_profile(tmp_path, candidate)),
        "--out", str(output.relative_to(tmp_path)), "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == "APPFORGE_RELEASE_REHEARSAL_READY"
    assert output.is_file()


@pytest.mark.parametrize(("channel", "not_applicable"), [
    ("testflight_internal", {"external_beta_review_submission", "app_review_submission", "app_review_decision"}),
    ("testflight_external", {"app_review_submission", "app_review_decision"}),
    ("app_store", {"tester_group_assignment", "tester_invitation_readback", "external_beta_review_submission"}),
    ("beta_distribution", {"external_beta_review_submission", "app_review_submission", "app_review_decision"}),
])
def test_release_rehearsal_keeps_channel_specific_external_states_not_applicable(tmp_path: Path, channel: str, not_applicable: set[str]) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    receipt = create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), _profile(tmp_path, candidate, provider="fastlane", channel=channel), Path(f".factory/appforge/{channel}-release-rehearsal.json"))
    states = {item["stage"]: item["status"] for item in receipt["state_matrix"]}
    assert {stage for stage, status in states.items() if status == "not_applicable"} == not_applicable
    assert receipt["provider"]["lane"] == "beta_release"


def test_release_rehearsal_binds_a_credential_free_cider_manifest_without_parsing_or_running_it(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    receipt = create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), _profile(tmp_path, candidate, provider="cider", channel="app_store"), Path(".factory/appforge/cider-release-rehearsal.json"))
    assert receipt["provider"]["provider"] == "cider"
    assert receipt["provider"]["manifest_path"] == "Cider.yml"
    assert len(receipt["provider"]["manifest_sha256"]) == 64
    assert receipt["authority"]["execution"] is False
    manifest = tmp_path / "Cider.yml"
    manifest.write_text("api_token: unsafe\n", encoding="utf-8")
    profile = _profile(tmp_path, candidate, provider="cider", channel="app_store")
    manifest.write_text("api_token: unsafe\n", encoding="utf-8")
    with pytest.raises(RevenueForgeError) as raised:
        create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), profile, Path(".factory/appforge/cider-secret.json"))
    assert raised.value.code == "APPFORGE_REHEARSAL_SECRET_IN_PROFILE"


def test_release_rehearsal_binds_a_complete_swiftlane_source_workflow_without_executing_it(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    receipt = create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), _profile(tmp_path, candidate, provider="swiftlane", channel="app_store"), Path(".factory/appforge/swiftlane-release-rehearsal.json"))
    assert receipt["provider"]["provider"] == "swiftlane"
    assert receipt["provider"]["declared_source_steps"] == {"build": True, "test": True, "archive": True, "export_archive": True}
    workflow = tmp_path / "Release.swift"
    workflow.write_text("import Swiftlane\nlet workflow = Workflow()\nlet build = Build()\nlet archive = Archive()\nlet export = ExportArchive()\n", encoding="utf-8")
    profile = _profile(tmp_path, candidate, provider="swiftlane", channel="app_store")
    workflow.write_text("import Swiftlane\nlet workflow = Workflow()\nlet build = Build()\nlet archive = Archive()\nlet export = ExportArchive()\n", encoding="utf-8")
    with pytest.raises(RevenueForgeError) as raised:
        create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), profile, Path(".factory/appforge/swiftlane-incomplete.json"))
    assert raised.value.code == "APPFORGE_REHEARSAL_PROVIDER_INVALID"


def test_release_rehearsal_binds_zealot_style_artifact_channel_and_audience_without_claiming_delivery(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    receipt = create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), _profile(tmp_path, candidate, provider="zealot", channel="beta_distribution"), Path(".factory/appforge/zealot-release-rehearsal.json"))
    assert receipt["provider"]["provider"] == "zealot"
    assert receipt["provider"]["artifact_sha256"] == "b" * 64
    assert receipt["provider"]["distribution_channel"] == "internal-qa"
    states = {item["stage"]: item["status"] for item in receipt["state_matrix"]}
    assert states["tester_group_assignment"] == "not_attempted"
    assert states["app_review_submission"] == "not_applicable"
    with pytest.raises(RevenueForgeError) as raised:
        create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), _profile(tmp_path, candidate, provider="zealot", channel="app_store"), Path(".factory/appforge/zealot-channel-invalid.json"))
    assert raised.value.code == "APPFORGE_REHEARSAL_CHANNEL_INVALID"


def test_release_rehearsal_rejects_any_future_matrix_that_promotes_or_blurs_external_states(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    matrix = rehearsal_module._matrix("testflight_external")
    matrix[2]["status"] = "ready"
    monkeypatch.setattr(rehearsal_module, "_matrix", lambda _: matrix)
    with pytest.raises(RevenueForgeError) as raised:
        create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), _profile(tmp_path, candidate), Path(".factory/appforge/invalid.json"))
    assert raised.value.code == "APPFORGE_REHEARSAL_STATE_INVALID"
    assert not (tmp_path / ".factory" / "appforge" / "invalid.json").exists()


def test_release_rehearsal_rejects_tampered_assurance_and_credential_like_profile(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    tampered = _assurance(tmp_path, candidate)
    value = json.loads(tampered.read_text(encoding="utf-8"))
    value["ok"] = False
    _write(tampered, value)
    with pytest.raises(RevenueForgeError) as assurance_error:
        create_release_rehearsal(tmp_path, candidate_path, tampered, _profile(tmp_path, candidate), Path(".factory/appforge/a.json"))
    assert assurance_error.value.code == "APPFORGE_REHEARSAL_ASSURANCE_TAMPERED"
    profile = _profile(tmp_path, candidate)
    value = json.loads(profile.read_text(encoding="utf-8"))
    value["provider_config"]["api_token"] = "do-not-store"
    _write(profile, value)
    with pytest.raises(RevenueForgeError) as profile_error:
        create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), profile, Path(".factory/appforge/b.json"))
    assert profile_error.value.code == "APPFORGE_REHEARSAL_SECRET_IN_PROFILE"
    profile = _profile(tmp_path, candidate)
    value = json.loads(profile.read_text(encoding="utf-8"))
    value["provider_config"]["skip_submission"] = True
    _write(profile, value)
    with pytest.raises(RevenueForgeError) as unsupported_error:
        create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), profile, Path(".factory/appforge/c.json"))
    assert unsupported_error.value.code == "APPFORGE_REHEARSAL_PROVIDER_INVALID"


def test_release_rehearsal_rejects_provider_and_candidate_scope_drift(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path)
    profile = _profile(tmp_path, candidate, provider="fastlane")
    value = json.loads(profile.read_text(encoding="utf-8"))
    value["provider_config"]["lane"] = "release-lane"
    _write(profile, value)
    with pytest.raises(RevenueForgeError) as provider_error:
        create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), profile, Path(".factory/appforge/a.json"))
    assert provider_error.value.code == "APPFORGE_REHEARSAL_PROVIDER_INVALID"
    profile = _profile(tmp_path, candidate)
    value = json.loads(profile.read_text(encoding="utf-8"))
    value["candidate"]["version"] = "9.9.9"
    _write(profile, value)
    with pytest.raises(RevenueForgeError) as candidate_error:
        create_release_rehearsal(tmp_path, candidate_path, _assurance(tmp_path, candidate), profile, Path(".factory/appforge/b.json"))
    assert candidate_error.value.code == "APPFORGE_REHEARSAL_CANDIDATE_MISMATCH"
