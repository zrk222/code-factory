from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.appforge_evidence_kit import CANDIDATE_SCHEMA
from factoryline.appforge_fastlane_capture import CONTRACT_SCHEMA, create_fastlane_capture_contract, fastlane_capture_projection
from factoryline.appforge_storefront_story import RECEIPT_SCHEMA as STORY_SCHEMA
from factoryline.appforge_surface_matrix import RECEIPT_SCHEMA as MATRIX_SCHEMA
from factoryline.cli import main
from factoryline.graph_ops import graph_ops_snapshot
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


def _sealed(root: Path, name: str, core: dict[str, object]) -> Path:
    return _write(root / name, {**core, "receipt_sha256": _sha(core)})


def _receipts(root: Path, candidate: dict[str, str]) -> tuple[Path, Path, list[dict[str, str]]]:
    matrix_core: dict[str, object] = {
        "schema": MATRIX_SCHEMA,
        "marker": "APPFORGE_SURFACE_MATRIX_WRITTEN",
        "candidate": candidate,
        "scenarios": [{"platform": "iphone", "configuration": "default appearance"}, {"platform": "ipad", "configuration": "Split View / compact width"}],
    }
    matrix = _sealed(root, "surface-matrix.json", matrix_core)
    scenes = [
        {"set_id": "iphone", "capture_id": "home", "journey": "Home"},
        {"set_id": "ipad_13", "capture_id": "workspace", "journey": "Workspace"},
    ]
    story_core: dict[str, object] = {
        "schema": STORY_SCHEMA,
        "marker": "APPFORGE_STOREFRONT_STORY_READY",
        "ok": True,
        "candidate": candidate,
        "scenes": scenes,
    }
    return matrix, _sealed(root, "storefront-story.json", story_core), scenes


def _fastlane_sources(root: Path, names: list[str], *, framing: str = "raw_only") -> None:
    (root / "fastlane").mkdir(exist_ok=True)
    (root / "fastlane" / "Snapfile").write_text(
        'devices(["iPhone 17 Pro Max", "iPad Pro 13-inch (M4)"])\n'
        'languages(["en-US"])\n'
        'scheme("ExampleUITests")\n'
        'output_directory("./fastlane/screenshots")\n'
        'clear_previous_screenshots(true)\n'
        'override_status_bar(true)\n'
        'stop_after_first_error(true)\n', encoding="utf-8")
    action = "capture_screenshots" if framing == "raw_only" else "capture_screenshots\n  frame_screenshots"
    (root / "fastlane" / "Fastfile").write_text(f"lane :appforge_capture do\n  {action}\nend\n", encoding="utf-8")
    (root / "AppForgeScreenshots.swift").write_text(
        "import XCTest\nfinal class Screenshots: XCTestCase {\n"
        "let app = XCUIApplication()\noverride func setUp() { continueAfterFailure = false; setupSnapshot(app); app.launch() }\n"
        + "\n".join(f'func test{index}() {{ snapshot("{name}") }}' for index, name in enumerate(names))
        + "\n}\n", encoding="utf-8")


def _contract(root: Path, candidate: dict[str, str], matrix: Path, story: Path, scenes: list[dict[str, str]], *, framing: str = "raw_only") -> Path:
    captures = [{"set_id": scene["set_id"], "capture_id": scene["capture_id"], "snapshot_name": f"{index + 1:02d}-{scene['capture_id'].title()}"} for index, scene in enumerate(scenes)]
    value = {
        "schema": CONTRACT_SCHEMA,
        "candidate": candidate,
        "surface_matrix_receipt_sha256": json.loads(matrix.read_text(encoding="utf-8"))["receipt_sha256"],
        "storefront_story_receipt_sha256": json.loads(story.read_text(encoding="utf-8"))["receipt_sha256"],
        "fastlane": {"snapfile_path": "fastlane/Snapfile", "fastfile_path": "fastlane/Fastfile", "ui_test_path": "AppForgeScreenshots.swift", "capture_lane": "appforge_capture", "framing": framing},
        "captures": captures,
    }
    return _write(root / "capture-contract.json", value)


def test_fastlane_capture_contract_seals_sources_and_exact_story_coverage(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path); matrix, story, scenes = _receipts(tmp_path, candidate)
    names = ["01-Home", "02-Workspace"]; _fastlane_sources(tmp_path, names)
    receipt = create_fastlane_capture_contract(tmp_path, candidate_path, matrix, story, _contract(tmp_path, candidate, matrix, story, scenes), Path(".factory/appforge/fastlane-capture.json"))
    assert receipt["marker"] == "APPFORGE_FASTLANE_CAPTURE_READY"
    assert receipt["capture_mode"] == "fastlane_snapshot_capture_only"
    assert receipt["sources"]["snapfile"]["settings"]["override_status_bar"] is True
    assert receipt["sources"]["fastfile"]["capture_only"] is True
    assert receipt["authority"]["fastlane_execution"] is False
    assert receipt["windows_operation"]["local_preflight_supported"] is True
    assert receipt["windows_operation"]["external_execution_requires_macos_xcode"] is True
    assert fastlane_capture_projection(tmp_path)["latest"]["capture_count"] == 2
    graph = graph_ops_snapshot(tmp_path)
    assert graph["facts"]["appforge_fastlane_capture_current_count"] == 1
    assert graph["facts"]["appforge_fastlane_capture_invalid_count"] == 0


def test_fastlane_capture_contract_cli_writes_only_local_receipt(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    candidate, candidate_path = _candidate(tmp_path); matrix, story, scenes = _receipts(tmp_path, candidate)
    _fastlane_sources(tmp_path, ["01-Home", "02-Workspace"]); contract = _contract(tmp_path, candidate, matrix, story, scenes)
    assert main(["revenue", "appforge-fastlane-capture", "--root", str(tmp_path), "--candidate", str(candidate_path), "--surface-matrix", str(matrix), "--storefront-story", str(story), "--contract", str(contract), "--out", ".factory/appforge/cli-fastlane-capture.json", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "APPFORGE_FASTLANE_CAPTURE_READY"


def test_fastlane_capture_contract_rejects_missing_snapshot_and_coverage_drift(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path); matrix, story, scenes = _receipts(tmp_path, candidate)
    _fastlane_sources(tmp_path, ["01-Home"]); contract = _contract(tmp_path, candidate, matrix, story, scenes)
    with pytest.raises(RevenueForgeError) as raised:
        create_fastlane_capture_contract(tmp_path, candidate_path, matrix, story, contract, Path(".factory/appforge/rejected.json"))
    assert raised.value.code == "APPFORGE_FASTLANE_CAPTURE_UI_TEST_COVERAGE_MISSING"
    value = json.loads(contract.read_text(encoding="utf-8")); value["captures"] = value["captures"][:1]; _write(contract, value)
    with pytest.raises(RevenueForgeError) as coverage:
        create_fastlane_capture_contract(tmp_path, candidate_path, matrix, story, contract, Path(".factory/appforge/coverage.json"))
    assert coverage.value.code == "APPFORGE_FASTLANE_CAPTURE_COVERAGE_MISSING"


@pytest.mark.parametrize(("mutate", "code"), [
    (lambda root: (root / "fastlane" / "Fastfile").write_text("lane :appforge_capture do\n  capture_screenshots\n  upload_to_app_store\nend\n", encoding="utf-8"), "APPFORGE_FASTLANE_CAPTURE_LANE_INVALID"),
    (lambda root: (root / "fastlane" / "Snapfile").write_text('devices(["iPhone 17 Pro Max", "iPad Pro 13-inch (M4)"])\n', encoding="utf-8"), "APPFORGE_FASTLANE_CAPTURE_SNAPFILE_INVALID"),
    (lambda root: (root / "AppForgeScreenshots.swift").write_text("setupSnapshot(app)\napp.launch()\ncontinueAfterFailure = true\nsnapshot(\"01-Home\")\nsnapshot(\"02-Workspace\")", encoding="utf-8"), "APPFORGE_FASTLANE_CAPTURE_UI_TEST_INVALID"),
])
def test_fastlane_capture_contract_fails_closed_on_unsafe_lane_or_weak_config(tmp_path: Path, mutate: object, code: str) -> None:
    candidate, candidate_path = _candidate(tmp_path); matrix, story, scenes = _receipts(tmp_path, candidate)
    _fastlane_sources(tmp_path, ["01-Home", "02-Workspace"]); mutate(tmp_path)  # type: ignore[operator]
    with pytest.raises(RevenueForgeError) as raised:
        create_fastlane_capture_contract(tmp_path, candidate_path, matrix, story, _contract(tmp_path, candidate, matrix, story, scenes), Path(".factory/appforge/unsafe.json"))
    assert raised.value.code == code


@pytest.mark.parametrize("source", [
    'password = "value"',
    'api_key("value")',
    'ENV["MATCH_PASSWORD"]',
])
def test_fastlane_capture_contract_rejects_credential_like_ruby_forms(tmp_path: Path, source: str) -> None:
    candidate, candidate_path = _candidate(tmp_path); matrix, story, scenes = _receipts(tmp_path, candidate)
    _fastlane_sources(tmp_path, ["01-Home", "02-Workspace"])
    fastfile = tmp_path / "fastlane" / "Fastfile"
    fastfile.write_text(fastfile.read_text(encoding="utf-8").replace("capture_screenshots", f"capture_screenshots\n  {source}"), encoding="utf-8")
    with pytest.raises(RevenueForgeError) as raised:
        create_fastlane_capture_contract(tmp_path, candidate_path, matrix, story, _contract(tmp_path, candidate, matrix, story, scenes), Path(".factory/appforge/secret.json"))
    assert raised.value.code == "APPFORGE_FASTLANE_CAPTURE_SECRET_IN_SOURCE"


def test_fastlane_capture_contract_detects_unsafe_action_after_nested_block(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path,); matrix, story, scenes = _receipts(tmp_path, candidate)
    _fastlane_sources(tmp_path, ["01-Home", "02-Workspace"])
    (tmp_path / "fastlane" / "Fastfile").write_text("lane :appforge_capture do\n  if true\n    capture_screenshots\n  end\n  upload_to_app_store\nend\n", encoding="utf-8")
    with pytest.raises(RevenueForgeError) as raised:
        create_fastlane_capture_contract(tmp_path, candidate_path, matrix, story, _contract(tmp_path, candidate, matrix, story, scenes), Path(".factory/appforge/nested-unsafe.json"))
    assert raised.value.code == "APPFORGE_FASTLANE_CAPTURE_LANE_INVALID"


def test_fastlane_capture_contract_allows_only_reviewed_framefile_lane(tmp_path: Path) -> None:
    candidate, candidate_path = _candidate(tmp_path); matrix, story, scenes = _receipts(tmp_path, candidate)
    _fastlane_sources(tmp_path, ["01-Home", "02-Workspace"], framing="reviewed_framefile")
    receipt = create_fastlane_capture_contract(tmp_path, candidate_path, matrix, story, _contract(tmp_path, candidate, matrix, story, scenes, framing="reviewed_framefile"), Path(".factory/appforge/framed-fastlane-capture.json"))
    assert receipt["framing"] == "reviewed_framefile"
