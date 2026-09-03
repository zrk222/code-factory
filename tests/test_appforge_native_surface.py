from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.appforge_native_surface import CONTRACT_SCHEMA, EVIDENCE_SCHEMA, native_surface_projection, verify_native_surface
from factoryline.cli import main
from factoryline.revenueforge import RevenueForgeError


CANDIDATE = {"bundle_identifier": "app.example.calm", "version": "1.0", "build_number": "42", "source_commit": "abc123"}


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _candidate(root: Path) -> Path:
    return _write(root / "candidate.json", {"schema": "factory.appforge.release-candidate.v1", "candidate": CANDIDATE})


def _contract(root: Path, source: Path) -> Path:
    return _write(root / "contract.json", {
        "schema": CONTRACT_SCHEMA,
        "candidate": CANDIDATE,
        "user_design_input_sha256": "a" * 64,
        "platforms": ["iphone", "ipad"],
        "source_files": [source.relative_to(root).as_posix()],
        "adaptive": {"iphone_navigation": "tabs_or_stack", "ipad_navigation": "split_or_sidebar", "independent_destination_paths": True, "hardcoded_screen_geometry_allowed": False},
        "accessibility": {"dynamic_type": True, "reduce_motion": True, "reduce_transparency": True, "icon_labels": True},
        "materials": {"system_components_preferred": True, "content_layer_glass_allowed": False, "max_custom_glass_controls": 1},
        "storyboard": [
            {"id": "iphone-home", "platform": "iphone", "journey": "first value", "user_value": "understand today"},
            {"id": "ipad-workspace", "platform": "ipad", "journey": "core workspace", "user_value": "work with context"},
        ],
    })


def _evidence(root: Path, contract: Path) -> Path:
    return _write(root / "evidence.json", {
        "schema": EVIDENCE_SCHEMA,
        "candidate": CANDIDATE,
        "contract_sha256": _sha(contract.read_bytes()),
        "review": {"reviewed_by": "Design Owner", "confirmed_at": "2026-09-02T12:00:00Z", "adaptive_navigation": True, "accessibility_fallbacks": True, "material_hierarchy": True, "storyboard_truth": True},
    })


def _source(root: Path, text: str | None = None) -> Path:
    source = root / "App" / "HomeView.swift"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(text or """import SwiftUI
struct HomeView: View {
  @Environment(\\.dynamicTypeSize) private var typeSize
  @Environment(\\.accessibilityReduceMotion) private var reduceMotion
  @Environment(\\.accessibilityReduceTransparency) private var reduceTransparency
  var body: some View {
    NavigationSplitView { Text(\"Menu\") } detail: { Image(systemName: \"plus\").accessibilityLabel(\"Add\") }
  }
}
""", encoding="utf-8")
    return source


def test_native_surface_binds_intent_source_platform_and_storyboard(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    source = _source(tmp_path)
    contract = _contract(tmp_path, source)
    evidence = _evidence(tmp_path, contract)
    receipt = verify_native_surface(tmp_path, candidate, contract, evidence, Path(".factory/appforge/native-surface.json"))
    assert receipt["marker"] == "APPFORGE_NATIVE_SURFACE_READY"
    assert receipt["platforms"] == ["ipad", "iphone"]
    assert receipt["static_observations"][0]["path"] == "App/HomeView.swift"
    assert receipt["authority"]["apple_asset_download"] is False
    assert native_surface_projection(tmp_path)["current_count"] == 1


def test_native_surface_blocks_geometry_glass_and_icon_shortcuts(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    source = _source(tmp_path, """import SwiftUI
struct HomeView: View { var body: some View { Text(String(UIScreen.main.bounds.width)); Image(systemName: \"plus\"); Image(systemName: \"minus\").glassEffect() } }
""")
    contract = _contract(tmp_path, source)
    evidence = _evidence(tmp_path, contract)
    receipt = verify_native_surface(tmp_path, candidate, contract, evidence, Path(".factory/appforge/native-surface.json"))
    codes = {item["code"] for item in receipt["findings"]}
    assert receipt["marker"] == "APPFORGE_NATIVE_SURFACE_BLOCKED"
    assert {"APPFORGE_NATIVE_FIXED_SCREEN_GEOMETRY", "APPFORGE_NATIVE_ADAPTIVE_API_MISSING", "APPFORGE_NATIVE_ICON_LABEL_REVIEW_REQUIRED"} <= codes


def test_native_surface_rejects_tampered_contract_binding_and_cli_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    candidate = _candidate(tmp_path)
    source = _source(tmp_path)
    contract = _contract(tmp_path, source)
    evidence = _evidence(tmp_path, contract)
    evidence_raw = json.loads(evidence.read_text(encoding="utf-8"))
    evidence_raw["contract_sha256"] = "0" * 64
    _write(evidence, evidence_raw)
    with pytest.raises(RevenueForgeError, match="exact native-surface contract"):
        verify_native_surface(tmp_path, candidate, contract, evidence, Path(".factory/appforge/native-surface.json"))
    _evidence(tmp_path, contract)
    assert main(["revenue", "appforge-native-surface", "--root", str(tmp_path), "--candidate", "candidate.json", "--contract", "contract.json", "--evidence", "evidence.json", "--out", ".factory/appforge/cli-native-surface.json", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "APPFORGE_NATIVE_SURFACE_READY"


def test_native_surface_projection_excludes_tampered_receipt(tmp_path: Path) -> None:
    directory = tmp_path / ".factory" / "appforge"
    directory.mkdir(parents=True)
    (directory / "native-surface.json").write_text(json.dumps({"schema": "factory.appforge.native-surface-receipt.v1", "receipt_sha256": "0" * 64}), encoding="utf-8")
    projection = native_surface_projection(tmp_path)
    assert projection["current_count"] == 0
    assert projection["invalid_count"] == 1
