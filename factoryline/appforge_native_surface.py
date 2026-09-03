"""Static, source-bound Apple native-surface preflight for AppForge.

The gate is intentionally narrower than a device or App Store review.  It
binds confirmed design intent to local Swift source, checks a small set of
high-signal adaptive/accessibility/material patterns, and keeps the resulting
receipt separate from device, Store media, TestFlight, and Apple evidence.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .appforge_evidence_kit import CANDIDATE_SCHEMA, _read_candidate
from .revenueforge import AUTHORITY, RevenueForgeError


CONTRACT_SCHEMA = "factory.appforge.native-surface-contract.v1"
EVIDENCE_SCHEMA = "factory.appforge.native-surface-evidence.v1"
RECEIPT_SCHEMA = "factory.appforge.native-surface-receipt.v1"
MAX_BYTES = 1_048_576
PLATFORMS = frozenset({"iphone", "ipad"})
ADAPTIVE_APIS = ("NavigationSplitView", "horizontalSizeClass", "ViewThatFits", "AnyLayout", "containerRelativeFrame", "GeometryReader")
FORBIDDEN_SCREEN_GEOMETRY = ("UIScreen.main.bounds", "UIApplication.shared.windows")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(value: object, field: str, *, limit: int = 500) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", result):
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_INVALID", f"{field} must be a SHA-256 hex digest")
    return result


def _timestamp(value: object, field: str) -> str:
    result = _text(value, field, limit=60)
    try:
        datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_INVALID", f"{field} must be RFC3339") from exc
    return result


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _read_json(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _sealed(value: object) -> bool:
    if not isinstance(value, dict) or value.get("schema") != RECEIPT_SCHEMA:
        return False
    supplied = value.get("receipt_sha256")
    return isinstance(supplied, str) and len(supplied) == 64 and _sha({key: item for key, item in value.items() if key != "receipt_sha256"}) == supplied


def _contract(root: Path, value: dict[str, Any], candidate: dict[str, str]) -> tuple[dict[str, Any], list[Path]]:
    required = {"schema", "candidate", "user_design_input_sha256", "platforms", "source_files", "adaptive", "accessibility", "materials", "storyboard"}
    if set(value) != required or value.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "contract must contain only the native-surface fields and match the exact candidate")
    design_hash = _digest(value.get("user_design_input_sha256"), "user_design_input_sha256")
    platforms = value.get("platforms")
    if not isinstance(platforms, list) or not platforms or len(platforms) > 2 or set(platforms) - PLATFORMS or len(platforms) != len(set(platforms)):
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "platforms must be a unique non-empty iphone/ipad list")
    source_files = value.get("source_files")
    if not isinstance(source_files, list) or not 1 <= len(source_files) <= 100:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "source_files must contain 1-100 Swift source paths")
    sources: list[Path] = []
    for item in source_files:
        path = _local(root, Path(_text(item, "source_files[]", limit=600)))
        if path.suffix.lower() != ".swift" or path in sources:
            raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "source_files must be unique Swift files")
        if path.stat().st_size > MAX_BYTES:
            raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_INPUT_TOO_LARGE", "Swift source exceeds 1 MiB")
        sources.append(path)
    adaptive = value.get("adaptive")
    if not isinstance(adaptive, dict) or set(adaptive) != {"iphone_navigation", "ipad_navigation", "independent_destination_paths", "hardcoded_screen_geometry_allowed"}:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "adaptive must have the fixed navigation fields")
    if adaptive.get("iphone_navigation") not in {"tabs_or_stack", "stack"} or adaptive.get("ipad_navigation") not in {"split_or_sidebar", "not_supported"}:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "adaptive navigation values are unsupported")
    if adaptive.get("independent_destination_paths") is not True or adaptive.get("hardcoded_screen_geometry_allowed") is not False:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "adaptive navigation must retain destination paths and reject hardcoded screen geometry")
    if ("ipad" in platforms) != (adaptive.get("ipad_navigation") == "split_or_sidebar"):
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "iPad support must declare split_or_sidebar, and iPhone-only apps must declare not_supported")
    accessibility = value.get("accessibility")
    expected_accessibility = {"dynamic_type", "reduce_motion", "reduce_transparency", "icon_labels"}
    if not isinstance(accessibility, dict) or set(accessibility) != expected_accessibility or any(accessibility.get(item) is not True for item in expected_accessibility):
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "all native accessibility expectations must be explicitly true")
    materials = value.get("materials")
    if not isinstance(materials, dict) or set(materials) != {"system_components_preferred", "content_layer_glass_allowed", "max_custom_glass_controls"}:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "materials must have the fixed usage fields")
    if materials.get("system_components_preferred") is not True or materials.get("content_layer_glass_allowed") is not False or not isinstance(materials.get("max_custom_glass_controls"), int) or not 0 <= materials["max_custom_glass_controls"] <= 3:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "materials must prefer system components, disallow content glass, and cap custom glass at 0-3")
    storyboard = value.get("storyboard")
    if not isinstance(storyboard, list) or not storyboard or len(storyboard) > 20:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "storyboard must contain 1-20 platform-bound scenes")
    seen: set[str] = set()
    represented: set[str] = set()
    for scene in storyboard:
        if not isinstance(scene, dict) or set(scene) != {"id", "platform", "journey", "user_value"}:
            raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "each storyboard scene must use the fixed fields")
        identifier = _text(scene.get("id"), "storyboard.id", limit=80)
        platform = _text(scene.get("platform"), "storyboard.platform", limit=16)
        if identifier in seen or platform not in platforms:
            raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "storyboard ids must be unique and bind declared platforms")
        seen.add(identifier); represented.add(platform)
        _text(scene.get("journey"), "storyboard.journey", limit=120)
        _text(scene.get("user_value"), "storyboard.user_value", limit=180)
    if represented != set(platforms):
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_CONTRACT_INVALID", "storyboard must show every declared platform")
    return {"candidate": candidate, "user_design_input_sha256": design_hash, "platforms": sorted(platforms), "source_files": [item.relative_to(root).as_posix() for item in sources], "adaptive": adaptive, "accessibility": accessibility, "materials": materials, "storyboard": storyboard}, sources


def _evidence(value: dict[str, Any], candidate: dict[str, str], contract_sha: str) -> dict[str, str]:
    if set(value) != {"schema", "candidate", "contract_sha256", "review"} or value.get("candidate") != candidate or _digest(value.get("contract_sha256"), "evidence.contract_sha256") != contract_sha:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_EVIDENCE_INVALID", "evidence must match the candidate and exact native-surface contract")
    review = value.get("review")
    if not isinstance(review, dict) or set(review) != {"reviewed_by", "confirmed_at", "adaptive_navigation", "accessibility_fallbacks", "material_hierarchy", "storyboard_truth"}:
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_EVIDENCE_INVALID", "review must contain the fixed named confirmations")
    if any(review.get(key) is not True for key in ("adaptive_navigation", "accessibility_fallbacks", "material_hierarchy", "storyboard_truth")):
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_REVIEW_REQUIRED", "all named native-surface review confirmations are required")
    return {"reviewed_by": _text(review.get("reviewed_by"), "review.reviewed_by", limit=120), "confirmed_at": _timestamp(review.get("confirmed_at"), "review.confirmed_at")}


def _scan(root: Path, sources: list[Path], contract: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    observations: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    all_text = ""
    for source in sources:
        try:
            text = source.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_INPUT_INVALID", "Swift source must be UTF-8") from exc
        all_text += "\n" + text
        observations.append({"path": source.relative_to(root).as_posix(), "sha256": _file_sha(source), "system_icons": text.count("Image(systemName:"), "explicit_icon_labels": text.count(".accessibilityLabel(") + text.count("Label("), "custom_glass_effects": text.count("glassEffect("), "adaptive_api_hits": [api for api in ADAPTIVE_APIS if api in text], "observed_accessibility_signals": {"dynamic_type": any(signal in text for signal in ("dynamicTypeSize", "DynamicTypeSize")), "reduce_motion": "accessibilityReduceMotion" in text, "reduce_transparency": "accessibilityReduceTransparency" in text}})
    forbidden = [token for token in FORBIDDEN_SCREEN_GEOMETRY if token in all_text]
    if forbidden:
        findings.append({"code": "APPFORGE_NATIVE_FIXED_SCREEN_GEOMETRY", "detail": f"source references non-adaptive screen geometry: {', '.join(forbidden)}"})
    if "ipad" in contract["platforms"] and not any(api in all_text for api in ADAPTIVE_APIS):
        findings.append({"code": "APPFORGE_NATIVE_ADAPTIVE_API_MISSING", "detail": "iPad support has no recognized adaptive SwiftUI API in the sealed sources"})
    accessibility_signals = {
        "dynamic_type": any(signal in all_text for signal in ("dynamicTypeSize", "DynamicTypeSize")),
        "reduce_motion": "accessibilityReduceMotion" in all_text,
        "reduce_transparency": "accessibilityReduceTransparency" in all_text,
    }
    for name, observed in accessibility_signals.items():
        if contract["accessibility"][name] and not observed:
            findings.append({"code": "APPFORGE_NATIVE_ACCESSIBILITY_SIGNAL_MISSING", "detail": f"sealed source has no recognized {name} accessibility signal"})
    glass_count = all_text.count("glassEffect(")
    if glass_count > contract["materials"]["max_custom_glass_controls"]:
        findings.append({"code": "APPFORGE_NATIVE_GLASS_OVERUSE", "detail": f"sealed source declares {glass_count} custom glass effects; contract allows {contract['materials']['max_custom_glass_controls']}"})
    icons = all_text.count("Image(systemName:")
    labels = all_text.count(".accessibilityLabel(") + all_text.count("Label(")
    if icons and labels < icons:
        findings.append({"code": "APPFORGE_NATIVE_ICON_LABEL_REVIEW_REQUIRED", "detail": f"sealed source has {icons} system-icon declarations but only {labels} explicit label signals; verify every custom icon with VoiceOver"})
    return observations, findings


def _atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True); handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def verify_native_surface(root: Path, candidate_path: Path, contract_path: Path, evidence_path: Path, out_path: Path) -> dict[str, Any]:
    """Verify a source-bound native-surface preflight without building or running iOS."""
    workspace = Path(root).resolve()
    candidate, _candidate_source = _read_candidate(workspace, candidate_path)
    contract_raw, contract_source = _read_json(workspace, contract_path, CONTRACT_SCHEMA)
    contract, sources = _contract(workspace, contract_raw, candidate)
    evidence, evidence_source = _read_json(workspace, evidence_path, EVIDENCE_SCHEMA)
    review = _evidence(evidence, candidate, _file_sha(contract_source))
    observations, findings = _scan(workspace, sources, contract)
    result: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_NATIVE_SURFACE_READY" if not findings else "APPFORGE_NATIVE_SURFACE_BLOCKED",
        "ok": not findings,
        "action_summary": "Bind one user-approved Apple design direction to local Swift source, adaptive-layout signals, accessibility fallbacks, restrained custom glass, and a platform storyboard; do not build, run, render, access Apple, upload media, or claim device or App Review approval.",
        "candidate": candidate,
        "contract_sha256": _file_sha(contract_source),
        "evidence_sha256": _file_sha(evidence_source),
        "user_design_input_sha256": contract["user_design_input_sha256"],
        "platforms": contract["platforms"],
        "storyboard": contract["storyboard"],
        "review": review,
        "static_observations": observations,
        "findings": findings,
        "authority": {**AUTHORITY, "execution": False, "device_access": False, "apple_asset_download": False, "app_store_connect_write": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "Static local source and human-review evidence only. It does not prove runtime layout, VoiceOver behavior, contrast, material hierarchy, screenshot authenticity, device compatibility, TestFlight state, App Review submission, or Apple approval.",
    }
    result["receipt_sha256"] = _sha(result)
    destination = _local(workspace, out_path, exists=False)
    if destination.exists():
        raise RevenueForgeError("APPFORGE_NATIVE_SURFACE_OUTPUT_COLLISION", "receipt output path already exists")
    _atomic(destination, result)
    return {**result, "path": destination.relative_to(workspace).as_posix()}


def native_surface_projection(root: Path) -> dict[str, Any]:
    """Read only hash-valid native-surface receipts for Graph Ops/editor adapters."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "appforge").rglob("*native-surface*.json"))[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            invalid.append(path.relative_to(workspace).as_posix()); continue
        if _sealed(value):
            current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "receipt_sha256": value.get("receipt_sha256"), "candidate": value.get("candidate"), "platforms": value.get("platforms"), "findings": value.get("findings", [])})
        else:
            invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.native-surface-projection.v1", "marker": "APPFORGE_NATIVE_SURFACE_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": {**AUTHORITY, "execution": False, "device_access": False, "apple_asset_download": False, "app_store_connect_write": False, "app_review_submit": False, "apple_approval_claim": False}, "claim_boundary": "Read-only local static preflight status; not a device, accessibility, screenshot, App Store Connect, TestFlight, App Review, or Apple approval result."}
