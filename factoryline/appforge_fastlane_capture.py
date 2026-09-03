"""Sealed Fastlane screenshot-capture contracts for AppForge.

This is deliberately a local, static preflight.  It binds the *planned*
Fastlane snapshot test and capture lane to already-reviewed AppForge device and
story receipts, but cannot invoke Xcode, boot a simulator, run Fastlane,
generate media, reach App Store Connect, or publish anything.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .appforge_evidence_kit import _read_candidate
from .appforge_surface_matrix import RECEIPT_SCHEMA as MATRIX_SCHEMA
from .appforge_storefront_story import RECEIPT_SCHEMA as STORY_SCHEMA
from .revenueforge import AUTHORITY, RevenueForgeError


CONTRACT_SCHEMA = "factory.appforge.fastlane-capture-contract.v1"
RECEIPT_SCHEMA = "factory.appforge.fastlane-capture-receipt.v1"
MAX_BYTES = 1_048_576
_SECRET_HINTS = ("token", "password", "secret", "private_key", "privatekey", "api_key", "apikey", "credential")
_UNSAFE_LANE_ACTIONS = ("upload_to_app_store", "deliver", "pilot", "upload_to_testflight", "match", "sync_code_signing")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(value: object, field: str, limit: int = 300) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_CONTRACT_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _read_json(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _sealed(value: dict[str, Any], schema: str, marker: str) -> bool:
    supplied = value.get("receipt_sha256")
    return (
        value.get("schema") == schema
        and value.get("marker") == marker
        and isinstance(supplied, str)
        and len(supplied) == 64
        and _sha({key: item for key, item in value.items() if key != "receipt_sha256"}) == supplied
    )


def _read_text(root: Path, path_value: object, field: str) -> tuple[Path, str]:
    path = _local(root, Path(_text(path_value, field, 512)))
    if path.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_INPUT_TOO_LARGE", f"{field} exceeds 1 MiB")
    try:
        return path, path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_INPUT_INVALID", f"{field} must be UTF-8 text") from exc


def _source_has_secret(text: str) -> bool:
    return bool(re.search(r"(?im)^\s*[^#\n]*(?:" + "|".join(_SECRET_HINTS) + r")[^:\n]*:\s*\S+", text))


def _lane_body(fastfile: str, lane: str) -> str:
    match = re.search(rf"(?ms)^\s*lane\s*:\s*{re.escape(lane)}\s+do\b(.*?)^\s*end\s*$", fastfile)
    if not match:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_LANE_INVALID", "Fastfile must contain the declared capture-only lane")
    return match.group(1)


def _validate_snapfile(text: str) -> dict[str, bool]:
    checks = {
        "devices": bool(re.search(r"(?is)devices\s*\(.*?iPhone.*?iPad.*?\)", text)) and bool(re.search(r"(?i)iPad[^\n\"]*13|13[^\n\"]*iPad", text)),
        "languages": bool(re.search(r"(?is)languages\s*\(.*?(?:en-US|en_US).*?\)", text)),
        "scheme": bool(re.search(r"(?i)scheme\s*\(\s*[\"']", text)),
        "output_directory": bool(re.search(r"(?i)output_directory\s*\(", text)),
        "clear_previous_screenshots": bool(re.search(r"(?i)clear_previous_screenshots\s*\(\s*true\s*\)", text)),
        "override_status_bar": bool(re.search(r"(?i)override_status_bar\s*\(\s*true\s*\)", text)),
        "stop_after_first_error": bool(re.search(r"(?i)stop_after_first_error\s*\(\s*true\s*\)", text)),
    }
    if not all(checks.values()):
        missing = ", ".join(key for key, value in checks.items() if not value)
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_SNAPFILE_INVALID", f"Snapfile is missing required deterministic capture settings: {missing}")
    return checks


def _validate_contract(value: dict[str, Any], candidate: dict[str, str], matrix_sha: str, story_sha: str, scene_keys: set[tuple[str, str]]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    expected = {"schema", "candidate", "surface_matrix_receipt_sha256", "storefront_story_receipt_sha256", "fastlane", "captures"}
    if set(value) != expected or value.get("candidate") != candidate or value.get("surface_matrix_receipt_sha256") != matrix_sha or value.get("storefront_story_receipt_sha256") != story_sha:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_CONTRACT_INVALID", "contract must bind the exact candidate, surface matrix, and storefront story")
    fastlane = value.get("fastlane")
    if not isinstance(fastlane, dict) or set(fastlane) != {"snapfile_path", "fastfile_path", "ui_test_path", "capture_lane", "framing"}:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_CONTRACT_INVALID", "fastlane must contain only declared capture inputs")
    lane = _text(fastlane.get("capture_lane"), "fastlane.capture_lane", 80)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", lane):
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_CONTRACT_INVALID", "fastlane.capture_lane must be alphanumeric with underscores")
    framing = _text(fastlane.get("framing"), "fastlane.framing", 40)
    if framing not in {"raw_only", "reviewed_framefile"}:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_CONTRACT_INVALID", "fastlane.framing must be raw_only or reviewed_framefile")
    captures = value.get("captures")
    if not isinstance(captures, list) or not captures or len(captures) > 20:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_CONTRACT_INVALID", "captures must contain 1-20 named outputs")
    seen: set[tuple[str, str]] = set(); names: set[str] = set(); normalized: list[dict[str, str]] = []
    for item in captures:
        if not isinstance(item, dict) or set(item) != {"set_id", "capture_id", "snapshot_name"}:
            raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_CONTRACT_INVALID", "each capture must have set_id, capture_id, and snapshot_name")
        key = (_text(item.get("set_id"), "captures[].set_id", 80), _text(item.get("capture_id"), "captures[].capture_id", 80))
        name = _text(item.get("snapshot_name"), "captures[].snapshot_name", 120)
        if key not in scene_keys or key in seen or name in names or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]*", name):
            raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_COVERAGE_INVALID", "capture references must cover each known scene exactly once with unique safe snapshot names")
        seen.add(key); names.add(name); normalized.append({"set_id": key[0], "capture_id": key[1], "snapshot_name": name})
    if seen != scene_keys:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_COVERAGE_MISSING", "every reviewed storefront scene must map to exactly one Fastlane snapshot")
    return {"snapfile_path": _text(fastlane.get("snapfile_path"), "fastlane.snapfile_path", 512), "fastfile_path": _text(fastlane.get("fastfile_path"), "fastlane.fastfile_path", 512), "ui_test_path": _text(fastlane.get("ui_test_path"), "fastlane.ui_test_path", 512), "capture_lane": lane, "framing": framing}, normalized


def _validate_sources(root: Path, fastlane: dict[str, Any], captures: list[dict[str, str]]) -> dict[str, Any]:
    snapfile_path, snapfile = _read_text(root, fastlane["snapfile_path"], "fastlane.snapfile_path")
    fastfile_path, fastfile = _read_text(root, fastlane["fastfile_path"], "fastlane.fastfile_path")
    ui_test_path, ui_test = _read_text(root, fastlane["ui_test_path"], "fastlane.ui_test_path")
    if any(_source_has_secret(text) for text in (snapfile, fastfile, ui_test)):
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_SECRET_IN_SOURCE", "declared capture sources must not contain credential-like values")
    settings = _validate_snapfile(snapfile)
    body = _lane_body(fastfile, fastlane["capture_lane"])
    if not re.search(r"\b(?:capture_screenshots|snapshot)\b", body) or any(re.search(rf"\b{action}\b", body) for action in _UNSAFE_LANE_ACTIONS):
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_LANE_INVALID", "capture lane must invoke capture_screenshots or snapshot and cannot sign, upload, deliver, invite, or submit")
    if fastlane["framing"] == "reviewed_framefile" and not re.search(r"\bframe_screenshots\b", body):
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_LANE_INVALID", "reviewed_framefile requires frame_screenshots in the capture lane")
    if fastlane["framing"] == "raw_only" and re.search(r"\bframe_screenshots\b", body):
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_LANE_INVALID", "raw_only capture lane cannot frame media")
    if not re.search(r"\bsetupSnapshot\s*\(", ui_test) or not re.search(r"\bapp\.launch\s*\(", ui_test) or re.search(r"continueAfterFailure\s*=\s*true", ui_test):
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_UI_TEST_INVALID", "UI test must set up Snapshot, launch the app, and stop after failure")
    missing = [item["snapshot_name"] for item in captures if not re.search(rf"\bsnapshot\s*\(\s*[\"']{re.escape(item['snapshot_name'])}[\"']\s*\)", ui_test)]
    if missing:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_UI_TEST_COVERAGE_MISSING", "UI test is missing sealed snapshot calls: " + ", ".join(missing))
    return {
        "snapfile": {"path": snapfile_path.relative_to(root).as_posix(), "sha256": _file_sha(snapfile_path), "settings": settings},
        "fastfile": {"path": fastfile_path.relative_to(root).as_posix(), "sha256": _file_sha(fastfile_path), "capture_lane": fastlane["capture_lane"], "capture_only": True},
        "ui_test": {"path": ui_test_path.relative_to(root).as_posix(), "sha256": _file_sha(ui_test_path), "sealed_snapshot_count": len(captures), "static_source_check_only": True},
    }


def _atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True); handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def create_fastlane_capture_contract(root: Path, candidate_path: Path, surface_matrix_path: Path, storefront_story_path: Path, contract_path: Path, out_path: Path) -> dict[str, Any]:
    """Seal a capture-only Fastlane handoff without invoking any external tool."""
    workspace = Path(root).resolve(); candidate, candidate_source = _read_candidate(workspace, candidate_path)
    matrix, matrix_source = _read_json(workspace, surface_matrix_path, MATRIX_SCHEMA)
    story, story_source = _read_json(workspace, storefront_story_path, STORY_SCHEMA)
    if not _sealed(matrix, MATRIX_SCHEMA, "APPFORGE_SURFACE_MATRIX_WRITTEN") or matrix.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_MATRIX_INVALID", "surface matrix must be hash-valid and bound to the exact candidate")
    if not _sealed(story, STORY_SCHEMA, "APPFORGE_STOREFRONT_STORY_READY") or story.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_STORY_INVALID", "storefront story must be hash-valid, ready, and bound to the exact candidate")
    scenes = story.get("scenes")
    if not isinstance(scenes, list) or not scenes:
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_STORY_INVALID", "storefront story must contain reviewed scenes")
    scene_keys = {(str(scene.get("set_id")), str(scene.get("capture_id"))) for scene in scenes if isinstance(scene, dict)}
    if len(scene_keys) != len(scenes):
        raise RevenueForgeError("APPFORGE_FASTLANE_CAPTURE_STORY_INVALID", "storefront story scenes must be unique")
    contract, contract_source = _read_json(workspace, contract_path, CONTRACT_SCHEMA)
    fastlane, captures = _validate_contract(contract, candidate, matrix["receipt_sha256"], story["receipt_sha256"], scene_keys)
    sources = _validate_sources(workspace, fastlane, captures)
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_FASTLANE_CAPTURE_READY",
        "ok": True,
        "action_summary": "Seal a capture-only Fastlane Snapshot plan to the exact AppForge candidate, reviewed device matrix, and truthful storefront scenes before a separately authorized macOS/Xcode run.",
        "candidate": candidate,
        "sources": {
            "candidate": {"path": candidate_source.relative_to(workspace).as_posix(), "sha256": _file_sha(candidate_source)},
            "surface_matrix": {"path": matrix_source.relative_to(workspace).as_posix(), "receipt_sha256": matrix["receipt_sha256"], "sha256": _file_sha(matrix_source)},
            "storefront_story": {"path": story_source.relative_to(workspace).as_posix(), "receipt_sha256": story["receipt_sha256"], "sha256": _file_sha(story_source)},
            "capture_contract": {"path": contract_source.relative_to(workspace).as_posix(), "sha256": _file_sha(contract_source)},
            **sources,
        },
        "capture_mode": "fastlane_snapshot_capture_only",
        "framing": fastlane["framing"],
        "captures": captures,
        "scenario_count": len(matrix.get("scenarios", [])),
        "windows_operation": {
            "local_preflight_supported": True,
            "local_cli_style": "py -3 -m factoryline.cli revenue appforge-fastlane-capture",
            "external_execution_requires_macos_xcode": True,
            "reason": "Apple XCUITest and iOS Simulator execution require a separately authorized macOS/Xcode environment; Windows never substitutes an emulator claim.",
        },
        "human_handoff": [
            "Use an approved macOS/Xcode environment and review the sealed source hashes before any Fastlane command.",
            "Run only the declared capture lane after separate action-time authority; do not add sign, upload, delivery, review, or submission actions to that lane.",
            "Hash and review resulting captures through AppForge Store Media and Device Reality before any provider upload.",
        ],
        "authority": {**AUTHORITY, "execution": False, "macos_access": False, "xcode_access": False, "simulator_control": False, "fastlane_execution": False, "media_generation": False, "credential_access": False, "app_store_connect_write": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "Static local configuration and source binding only. The contract, hashing, audit, receipt, CLI, Graph Ops, and MCP status are Windows-operable. It does not establish that Xcode, simulators, devices, Fastlane, UI tests, accessibility, raw captures, frames, screenshots, Store media, TestFlight, App Review, or Apple approval work. Framing is presentation-only and cannot substantiate a product claim; output must be reviewed against the sealed storefront story separately.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    target = _local(workspace, out_path, exists=False); _atomic(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}


def fastlane_capture_projection(root: Path) -> dict[str, Any]:
    """Read hash-valid Fastlane capture contracts without running Fastlane."""
    workspace = Path(root).resolve(); current: list[dict[str, Any]] = []; invalid: list[str] = []
    base = workspace / ".factory" / "appforge"
    if base.exists():
        for path in sorted(base.rglob("*fastlane-capture*.json"))[:100]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if _sealed(value, RECEIPT_SCHEMA, "APPFORGE_FASTLANE_CAPTURE_READY"):
                    current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "candidate": value.get("candidate"), "receipt_sha256": value.get("receipt_sha256"), "capture_count": len(value.get("captures", [])), "framing": value.get("framing")})
                elif isinstance(value, dict) and value.get("schema") == RECEIPT_SCHEMA:
                    invalid.append(path.relative_to(workspace).as_posix())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.fastlane-capture-projection.v1", "marker": "APPFORGE_FASTLANE_CAPTURE_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": {**AUTHORITY, "execution": False, "macos_access": False, "xcode_access": False, "simulator_control": False, "fastlane_execution": False, "app_store_connect_write": False, "app_review_submit": False, "apple_approval_claim": False}, "claim_boundary": "Read-only local capture-plan status; not Fastlane execution, a simulator/device run, screenshots, framing, Store media, TestFlight, App Review, or Apple approval evidence."}
