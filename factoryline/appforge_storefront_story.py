"""Source-bound App Store screenshot story and claim discipline for AppForge."""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .appforge_evidence_kit import _read_candidate
from .appforge_store_media import RECEIPT_SCHEMA as MEDIA_RECEIPT_SCHEMA
from .revenueforge import AUTHORITY, RevenueForgeError


CONTRACT_SCHEMA = "factory.appforge.storefront-story-contract.v1"
EVIDENCE_SCHEMA = "factory.appforge.storefront-story-evidence.v1"
RECEIPT_SCHEMA = "factory.appforge.storefront-story-receipt.v1"
MAX_BYTES = 1_048_576
BEATS = frozenset({"mission", "tension", "guidance", "agency", "transformation", "celebration"})
CLAIM_KINDS = frozenset({"experience", "feature", "measured"})
HIGH_RISK_CLAIM = re.compile(r"\b(?:guarantee(?:d)?|apple\s+approved|never\s+reject(?:ed)?|save\s+(?:\d+|many)\s+(?:hours?|days?)|\d+\s*%)\b", re.IGNORECASE)


def _canonical(value: object) -> bytes: return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
def _sha(value: object) -> str: return hashlib.sha256(_canonical(value)).hexdigest()
def _file_sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(value: object, field: str, limit: int) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _timestamp(value: object) -> str:
    result = _text(value, "review.confirmed_at", 60)
    try: datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_INVALID", "review.confirmed_at must be RFC3339") from exc
    return result


def _local(root: Path, path: Path, exists: bool = True) -> Path:
    workspace = Path(root).resolve(); target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try: target.relative_to(workspace)
    except ValueError as exc: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file(): raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _read(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_INPUT_TOO_LARGE", "input exceeds 1 MiB")
    try: value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _sealed(value: dict[str, Any], schema: str, marker: str) -> bool:
    supplied = value.get("receipt_sha256")
    return value.get("schema") == schema and value.get("marker") == marker and isinstance(supplied, str) and len(supplied) == 64 and _sha({key: item for key, item in value.items() if key != "receipt_sha256"}) == supplied


def _captures(media: dict[str, Any]) -> dict[tuple[str, str], str]:
    sets = media.get("media_sets")
    if not isinstance(sets, dict): raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_MEDIA_INVALID", "store-media receipt has no media sets")
    found: dict[tuple[str, str], str] = {}
    for set_id, values in sets.items():
        captures = values.get("captures") if isinstance(values, dict) else None
        if not isinstance(captures, list): raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_MEDIA_INVALID", "store-media capture list is invalid")
        for capture in captures:
            if not isinstance(capture, dict): raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_MEDIA_INVALID", "store-media capture is invalid")
            key = (str(set_id), _text(capture.get("id"), "media.capture.id", 80))
            if key in found: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_MEDIA_INVALID", "store-media capture id is not unique")
            found[key] = _text(capture.get("journey"), "media.capture.journey", 120)
    return found


def _contract(root: Path, value: dict[str, Any], candidate: dict[str, str], media_sha: str, captures: dict[tuple[str, str], str]) -> list[dict[str, Any]]:
    if set(value) != {"schema", "candidate", "store_media_receipt_sha256", "scenes"} or value.get("candidate") != candidate or value.get("store_media_receipt_sha256") != media_sha:
        raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_CONTRACT_INVALID", "contract must bind the exact candidate and store-media receipt")
    scenes = value.get("scenes")
    if not isinstance(scenes, list) or not scenes or len(scenes) > 20: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_CONTRACT_INVALID", "scenes must contain 1-20 entries")
    normalized: list[dict[str, Any]] = []; seen: set[tuple[str, str]] = set()
    for scene in scenes:
        if not isinstance(scene, dict) or set(scene) != {"set_id", "capture_id", "story_beat", "headline", "supporting_copy", "claim_kind", "evidence_refs"}:
            raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_CONTRACT_INVALID", "each scene must use the fixed storyboard fields")
        key = (_text(scene.get("set_id"), "scene.set_id", 80), _text(scene.get("capture_id"), "scene.capture_id", 80))
        if key not in captures or key in seen: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_CONTRACT_INVALID", "each scene must reference one unique known store-media capture")
        seen.add(key)
        beat = _text(scene.get("story_beat"), "scene.story_beat", 30)
        kind = _text(scene.get("claim_kind"), "scene.claim_kind", 20)
        if beat not in BEATS or kind not in CLAIM_KINDS: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_CONTRACT_INVALID", "scene story_beat or claim_kind is unsupported")
        refs = scene.get("evidence_refs")
        if not isinstance(refs, list) or len(refs) > 8 or (kind != "experience" and not refs): raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_CONTRACT_INVALID", "feature or measured claims require 1-8 evidence references")
        normalized.append({"set_id": key[0], "capture_id": key[1], "journey": captures[key], "story_beat": beat, "headline": _text(scene.get("headline"), "scene.headline", 80), "supporting_copy": _text(scene.get("supporting_copy"), "scene.supporting_copy", 180), "claim_kind": kind, "evidence_refs": refs})
    if seen != set(captures): raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_COVERAGE_MISSING", "every ready store-media capture must have one truthful story scene")
    return normalized


def _evidence(root: Path, value: dict[str, Any], candidate: dict[str, str], contract_sha: str, scenes: list[dict[str, Any]]) -> dict[str, str]:
    if set(value) != {"schema", "candidate", "contract_sha256", "review"} or value.get("candidate") != candidate or value.get("contract_sha256") != contract_sha:
        raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_EVIDENCE_INVALID", "evidence must bind the exact candidate and story contract")
    review = value.get("review")
    if not isinstance(review, dict) or set(review) != {"reviewed_by", "confirmed_at", "storyboard_truth", "claims_checked"} or review.get("storyboard_truth") is not True or review.get("claims_checked") is not True:
        raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_REVIEW_REQUIRED", "named review must confirm storyboard truth and claims")
    for scene in scenes:
        for reference in scene["evidence_refs"]:
            path = _local(root, Path(_text(reference, "scene.evidence_refs[]", 600)))
            if path.stat().st_size > MAX_BYTES: raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_INPUT_TOO_LARGE", "claim evidence exceeds 1 MiB")
    return {"reviewed_by": _text(review.get("reviewed_by"), "review.reviewed_by", 120), "confirmed_at": _timestamp(review.get("confirmed_at"))}


def _atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle: json.dump(payload, handle, indent=2, sort_keys=True); handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def verify_storefront_story(root: Path, candidate_path: Path, store_media_path: Path, contract_path: Path, evidence_path: Path, out_path: Path) -> dict[str, Any]:
    """Verify screenshot story coverage and local claim provenance without publishing media."""
    workspace = Path(root).resolve(); candidate, _candidate_source = _read_candidate(workspace, candidate_path)
    media, media_source = _read(workspace, store_media_path, MEDIA_RECEIPT_SCHEMA)
    if not _sealed(media, MEDIA_RECEIPT_SCHEMA, "APPFORGE_STORE_MEDIA_READY") or media.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_STOREFRONT_STORY_MEDIA_INVALID", "store-media receipt must be hash-valid, ready, and bound to the exact candidate")
    captures = _captures(media); contract_raw, contract_source = _read(workspace, contract_path, CONTRACT_SCHEMA)
    scenes = _contract(workspace, contract_raw, candidate, media["receipt_sha256"], captures)
    evidence, evidence_source = _read(workspace, evidence_path, EVIDENCE_SCHEMA); review = _evidence(workspace, evidence, candidate, _file_sha(contract_source), scenes)
    findings: list[dict[str, str]] = []
    for scene in scenes:
        copy = f"{scene['headline']} {scene['supporting_copy']}"
        if HIGH_RISK_CLAIM.search(copy) and scene["claim_kind"] != "measured": findings.append({"code": "APPFORGE_STOREFRONT_STORY_UNSOURCED_CLAIM", "detail": f"{scene['capture_id']} contains a high-risk factual claim without measured provenance"})
    result: dict[str, Any] = {"schema": RECEIPT_SCHEMA, "marker": "APPFORGE_STOREFRONT_STORY_READY" if not findings else "APPFORGE_STOREFRONT_STORY_BLOCKED", "ok": not findings, "action_summary": "Bind each ready App Store capture to one distinct user journey, concise story beat, and locally reviewed claim posture; do not generate imagery, add frames, upload media, contact Apple, or claim marketing or App Review approval.", "candidate": candidate, "store_media_receipt_sha256": media["receipt_sha256"], "store_media_path_sha256": _file_sha(media_source), "contract_sha256": _file_sha(contract_source), "evidence_sha256": _file_sha(evidence_source), "scenes": scenes, "review": review, "findings": findings, "authority": {**AUTHORITY, "execution": False, "media_generation": False, "apple_asset_download": False, "app_store_connect_write": False, "app_review_submit": False, "apple_approval_claim": False}, "claim_boundary": "Local screenshot-story and file-reference evidence only. It does not verify what an image depicts, prove an external evidence file supports the claim text, generate frames, upload Store media, or establish App Review approval."}
    result["receipt_sha256"] = _sha(result); destination = _local(workspace, out_path, exists=False); _atomic(destination, result)
    return {**result, "path": destination.relative_to(workspace).as_posix()}


def storefront_story_projection(root: Path) -> dict[str, Any]:
    workspace = Path(root).resolve(); current: list[dict[str, Any]] = []; invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "appforge").rglob("*storefront-story*.json"))[:100]:
        try: value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): invalid.append(path.relative_to(workspace).as_posix()); continue
        supplied = value.get("receipt_sha256") if isinstance(value, dict) else None
        if isinstance(value, dict) and value.get("schema") == RECEIPT_SCHEMA and isinstance(supplied, str) and _sha({key: item for key, item in value.items() if key != "receipt_sha256"}) == supplied: current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "receipt_sha256": supplied, "candidate": value.get("candidate"), "scene_count": len(value.get("scenes", [])), "findings": value.get("findings", [])})
        else: invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.storefront-story-projection.v1", "marker": "APPFORGE_STOREFRONT_STORY_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": {**AUTHORITY, "execution": False, "media_generation": False, "apple_asset_download": False, "app_store_connect_write": False, "app_review_submit": False, "apple_approval_claim": False}, "claim_boundary": "Read-only local screenshot-story status; not image semantic verification, claim substantiation, App Store Connect state, App Review, or Apple approval."}
