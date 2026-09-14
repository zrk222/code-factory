from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from factoryline.cli import main
from factoryline.full_stack_ux_spec import (
    FullStackUXSpecError,
    validate_ux_harness_spec,
    verify_ux_harness_spec_receipt,
)


def _direct_spec(root: Path) -> Path:
    for path in (root / "storyboard.json", root / "screens" / "iphone.png", root / "screens" / "ipad.png", root / "fastlane.json"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"evidence")
    digest = hashlib.sha256(b"evidence").hexdigest()
    value = {
        "apiVersion": "code-factory.io/v1alpha1",
        "kind": "FullStackUXHarness",
        "metadata": {"name": "demo", "targetAppId": "com.example.demo", "version": "1.2.3"},
        "harnessConfig": {
            "visualMedia": {"storyboardManifest": "storyboard.json", "screenshotPaths": ["screens/iphone.png", "screens/ipad.png"]},
            "privacyToListing": {"declaredPermissions": ["camera"], "appStorePrivacyLabelHash": digest},
            "releaseChain": {"xcodeSigningVerified": True, "fastlaneReceiptPath": "fastlane.json"},
            "designSystem": {"designTokensHash": digest, "hierarchyRulesVerified": True},
            "productionSignal": {"telemetryProvider": "local-export", "crashReportingVerified": True},
            "androidParity": {"gradleBuildVariant": "release", "adbDeviceLogsHash": digest},
        },
        "triageRules": [{"ruleId": "visual-001", "category": "visual_media", "severity": "BLOCKER", "failureMessage": "iPad media is missing"}],
    }
    path = root / "full-stack-ux-harness-v1.ssat.yaml"
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return path


def test_current_legacy_ssat_projects_to_all_six_mobile_categories(tmp_path: Path):
    source = tmp_path / "full-stack-ux-harness-v1.ssat.yaml"
    source.write_text((Path(__file__).parents[1] / "full-stack-ux-harness-v1.ssat.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    result = validate_ux_harness_spec(tmp_path, source, out=tmp_path / "receipt.json")
    assert result["ok"] is True
    assert result["marker"] == "FULL_STACK_UX_HARNESS_SPEC_VALIDATED"
    assert [item["category"] for item in result["mobile_categories"]] == [
        "visual_media", "privacy_to_listing", "release_chain", "design_system", "production_signal", "android_parity"
    ]
    assert result["normalized_spec"]["legacy"]["feature"] == "full-stack-ux-harness-v1"


def test_direct_contract_validates_hashes_paths_and_replays(tmp_path: Path):
    source = _direct_spec(tmp_path)
    result = validate_ux_harness_spec(tmp_path, source)
    assert result["ok"] is True
    assert result["normalized_spec"]["metadata"]["specFile"] == source.name
    assert verify_ux_harness_spec_receipt(tmp_path, result["path"])["ok"] is True


def test_direct_contract_blocks_unknown_category_and_receipt_is_immutable(tmp_path: Path):
    source = _direct_spec(tmp_path)
    value = yaml.safe_load(source.read_text(encoding="utf-8"))
    value["triageRules"][0]["category"] = "unsupported"
    source.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    result = validate_ux_harness_spec(tmp_path, source, out=tmp_path / "blocked.json")
    assert result["ok"] is False
    assert result["marker"] == "FULL_STACK_UX_HARNESS_SPEC_BLOCKED"
    assert result["findings"][0]["code"] == "E_UX_SPEC_SCHEMA"
    try:
        validate_ux_harness_spec(tmp_path, source, out=tmp_path / "blocked.json")
    except FullStackUXSpecError as error:
        assert error.code == "E_UX_SPEC_OUTPUT_EXISTS"
    else:
        raise AssertionError("expected immutable receipt refusal")


def test_duplicate_yaml_keys_fail_closed(tmp_path: Path):
    source = tmp_path / "duplicate.yaml"
    source.write_text("feature: full-stack-ux-harness-v1\nfeature: other\n", encoding="utf-8")
    try:
        validate_ux_harness_spec(tmp_path, source, out=tmp_path / "receipt.json")
    except FullStackUXSpecError as error:
        assert error.code == "E_UX_SPEC_DUPLICATE_KEY"
    else:
        raise AssertionError("expected duplicate-key refusal")


def test_cli_spec_validate_and_verify_are_read_only_replay_commands(tmp_path: Path, capsys):
    source = _direct_spec(tmp_path)
    assert main(["quality-harness", "spec-validate", source.name, "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert main(["quality-harness", "spec-verify", result["path"], "--root", str(tmp_path), "--json"]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["ok"] is True
