"""Hash-bound App Store media verification for AppForge.

This module validates supplied local media only.  It deliberately does not
contact App Store Connect, generate screenshots, or claim Apple approval.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
import hashlib
import json
import os
import struct
import tempfile
import zlib


CONTRACT_SCHEMA = "factory.appforge.store-media-contract.v1"
EVIDENCE_SCHEMA = "factory.appforge.store-media-evidence.v1"
RECEIPT_SCHEMA = "factory.appforge.store-media-receipt.v1"
MAX_BYTES = 1_048_576
MAX_MEDIA_BYTES = 30 * 1024 * 1024
AUTHORITY = {
    "media_generation": False,
    "app_store_connect_read": False,
    "app_store_connect_write": False,
    "testflight_upload": False,
    "app_review_submit": False,
    "apple_approval_claim": False,
}


class StoreMediaError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, field: str, *, limit: int = 300) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _sha256(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(char not in "0123456789abcdef" for char in result):
        raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"{field} must be a SHA-256 hex digest")
    return result


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = root.resolve()
    resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise StoreMediaError("APPFORGE_MEDIA_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not resolved.is_file():
        raise StoreMediaError("APPFORGE_MEDIA_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return resolved


def _read_json(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise StoreMediaError("APPFORGE_MEDIA_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StoreMediaError("APPFORGE_MEDIA_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise StoreMediaError("APPFORGE_MEDIA_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _candidate(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise StoreMediaError("APPFORGE_MEDIA_CANDIDATE_INVALID", f"{label} must be an object")
    return {key: _text(value.get(key), f"{label}.{key}") for key in ("bundle_identifier", "version", "build_number", "source_commit")}


def _dimensions(value: object, field: str) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"{field} must be an object")
    width, height = value.get("width"), value.get("height")
    if any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 or item > 10000 for item in (width, height)):
        raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"{field} must contain positive bounded dimensions")
    return width, height


def _sets(value: object) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", "media_sets must contain 1-8 sets")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"media_sets[{index}] must be an object")
        set_id = _text(item.get("id"), f"media_sets[{index}].id", limit=80)
        if set_id in result:
            raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", "media set ids must be unique")
        minimum, maximum = item.get("min_count"), item.get("max_count")
        if any(isinstance(number, bool) or not isinstance(number, int) for number in (minimum, maximum)) or not 1 <= minimum <= maximum <= 10:
            raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"media_sets[{index}] counts must be between 1 and 10")
        raw_dimensions = item.get("accepted_dimensions")
        if not isinstance(raw_dimensions, list) or not raw_dimensions or len(raw_dimensions) > 12:
            raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"media_sets[{index}].accepted_dimensions must contain 1-12 dimensions")
        dimensions = {_dimensions(entry, f"media_sets[{index}].accepted_dimensions") for entry in raw_dimensions}
        journeys = item.get("required_journeys")
        if not isinstance(journeys, list) or not journeys or len(journeys) > 10:
            raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"media_sets[{index}].required_journeys must contain 1-10 values")
        journey_values = {_text(entry, f"media_sets[{index}].required_journeys", limit=80) for entry in journeys}
        sources = item.get("allowed_capture_sources")
        if not isinstance(sources, list) or not sources or len(sources) > 8:
            raise StoreMediaError("APPFORGE_MEDIA_CONTRACT_INVALID", f"media_sets[{index}].allowed_capture_sources must contain 1-8 values")
        source_values = {_text(entry, f"media_sets[{index}].allowed_capture_sources", limit=80) for entry in sources}
        result[set_id] = {"min_count": minimum, "max_count": maximum, "dimensions": dimensions, "journeys": journey_values, "sources": source_values}
    return result


def _image_info(path: Path) -> tuple[str, int, int, bool]:
    raw = path.read_bytes()
    if len(raw) > MAX_MEDIA_BYTES:
        raise StoreMediaError("APPFORGE_MEDIA_FILE_TOO_LARGE", f"{path.name} exceeds {MAX_MEDIA_BYTES} bytes")
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        offset, width, height, color_type = 8, None, None, None
        saw_idat = False
        while offset + 12 <= len(raw):
            length = struct.unpack(">I", raw[offset:offset + 4])[0]
            chunk_type = raw[offset + 4:offset + 8]
            end = offset + 12 + length
            if end > len(raw):
                break
            data = raw[offset + 8:offset + 8 + length]
            supplied_crc = struct.unpack(">I", raw[offset + 8 + length:end])[0]
            if zlib.crc32(chunk_type + data) & 0xFFFFFFFF != supplied_crc:
                break
            if chunk_type == b"IHDR":
                if width is not None or length != 13:
                    break
                width, height, _bit_depth, color_type, _compression, _filter, _interlace = struct.unpack(">IIBBBBB", data)
            elif chunk_type == b"IDAT":
                saw_idat = True
            elif chunk_type == b"IEND":
                if length == 0 and width and height and color_type is not None and saw_idat and end == len(raw):
                    return "png", width, height, color_type in {4, 6}
                break
            offset = end
        raise StoreMediaError("APPFORGE_MEDIA_UNSUPPORTED_IMAGE", f"{path.name} must be a structurally valid PNG")
    if raw.startswith(b"\xff\xd8"):
        offset = 2
        sof_markers = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
        while offset + 9 <= len(raw):
            if raw[offset] != 0xFF:
                offset += 1
                continue
            while offset < len(raw) and raw[offset] == 0xFF:
                offset += 1
            if offset >= len(raw):
                break
            marker = raw[offset]
            offset += 1
            if marker in {0xD8, 0xD9}:
                continue
            if offset + 2 > len(raw):
                break
            length = struct.unpack(">H", raw[offset:offset + 2])[0]
            if length < 2 or offset + length > len(raw):
                break
            if marker in sof_markers and length >= 7:
                height, width = struct.unpack(">HH", raw[offset + 3:offset + 7])
                return "jpeg", width, height, False
            offset += length
    raise StoreMediaError("APPFORGE_MEDIA_UNSUPPORTED_IMAGE", f"{path.name} must be a parseable PNG or JPEG")


def _timestamp(value: object) -> str:
    result = _text(value, "review.confirmed_at", limit=40)
    try:
        datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StoreMediaError("APPFORGE_MEDIA_EVIDENCE_INVALID", "review.confirmed_at must be RFC3339") from exc
    return result


def verify_store_media(root: Path, contract_path: Path, evidence_path: Path, out_path: Path) -> dict[str, Any]:
    """Verify image artifacts, candidate binding, and stated journey coverage."""
    workspace = Path(root).resolve()
    contract, contract_source = _read_json(workspace, contract_path, CONTRACT_SCHEMA)
    evidence, evidence_source = _read_json(workspace, evidence_path, EVIDENCE_SCHEMA)
    candidate = _candidate(contract.get("candidate"), "contract.candidate")
    observed = _candidate(evidence.get("candidate"), "evidence.candidate")
    intent = _sha256(contract.get("intent_sha256"), "contract.intent_sha256")
    review = evidence.get("review")
    if not isinstance(review, dict):
        raise StoreMediaError("APPFORGE_MEDIA_EVIDENCE_INVALID", "review must be an object")
    reviewer = _text(review.get("representative_confirmed_by"), "review.representative_confirmed_by")
    storyboard_reviewer = _text(review.get("storyboard_confirmed_by"), "review.storyboard_confirmed_by")
    confirmed_at = _timestamp(review.get("confirmed_at"))
    sets = _sets(contract.get("media_sets"))
    require_no_alpha = contract.get("require_no_alpha") is True
    captures = evidence.get("captures")
    if not isinstance(captures, list) or not captures or len(captures) > 80:
        raise StoreMediaError("APPFORGE_MEDIA_EVIDENCE_INVALID", "captures must contain 1-80 entries")

    findings: list[dict[str, str]] = []
    if observed != candidate:
        findings.append({"code": "APPFORGE_MEDIA_BUILD_BINDING_MISMATCH", "detail": "media evidence does not match the reviewed candidate"})
    if _sha256(evidence.get("intent_sha256"), "evidence.intent_sha256") != intent:
        findings.append({"code": "APPFORGE_MEDIA_INTENT_BINDING_MISMATCH", "detail": "media evidence does not match the confirmed storyboard intent"})
    grouped: dict[str, list[dict[str, str]]] = {set_id: [] for set_id in sets}
    ids, hashes = set(), set()
    for index, capture in enumerate(captures):
        if not isinstance(capture, dict):
            findings.append({"code": "APPFORGE_MEDIA_CAPTURE_INVALID", "detail": f"capture {index} is not an object"}); continue
        try:
            capture_id = _text(capture.get("id"), f"captures[{index}].id", limit=80)
            set_id = _text(capture.get("set_id"), f"captures[{index}].set_id", limit=80)
            route = _text(capture.get("route"), f"captures[{index}].route", limit=300)
            journey = _text(capture.get("journey"), f"captures[{index}].journey", limit=80)
            source = _text(capture.get("capture_source"), f"captures[{index}].capture_source", limit=80)
            supplied_hash = _sha256(capture.get("sha256"), f"captures[{index}].sha256")
            if capture_id in ids:
                raise StoreMediaError("APPFORGE_MEDIA_CAPTURE_INVALID", "capture ids must be unique")
            ids.add(capture_id)
            if set_id not in sets:
                raise StoreMediaError("APPFORGE_MEDIA_CAPTURE_INVALID", f"capture {capture_id} refers to an unknown media set")
            if source not in sets[set_id]["sources"]:
                raise StoreMediaError("APPFORGE_MEDIA_CAPTURE_SOURCE_REJECTED", f"capture {capture_id} uses an unapproved source")
            image = _local(workspace, Path(_text(capture.get("path"), f"captures[{index}].path", limit=600)))
            actual_hash = hashlib.sha256(image.read_bytes()).hexdigest()
            if actual_hash != supplied_hash:
                raise StoreMediaError("APPFORGE_MEDIA_HASH_MISMATCH", f"capture {capture_id} does not match its declared hash")
            if actual_hash in hashes:
                raise StoreMediaError("APPFORGE_MEDIA_DUPLICATE", f"capture {capture_id} duplicates another image")
            hashes.add(actual_hash)
            _format, width, height, has_alpha = _image_info(image)
            if (width, height) not in sets[set_id]["dimensions"]:
                raise StoreMediaError("APPFORGE_MEDIA_DIMENSIONS_INVALID", f"capture {capture_id} has unsupported dimensions {width}x{height}")
            if require_no_alpha and has_alpha:
                raise StoreMediaError("APPFORGE_MEDIA_ALPHA_REJECTED", f"capture {capture_id} contains an alpha channel")
            grouped[set_id].append({"id": capture_id, "route": route, "journey": journey, "path": image.relative_to(workspace).as_posix(), "sha256": actual_hash})
        except StoreMediaError as error:
            findings.append({"code": error.code, "detail": str(error)})
    for set_id, policy in sets.items():
        actual = grouped[set_id]
        if not policy["min_count"] <= len(actual) <= policy["max_count"]:
            findings.append({"code": "APPFORGE_MEDIA_COUNT_INVALID", "detail": f"{set_id} requires {policy['min_count']}-{policy['max_count']} captures, found {len(actual)}"})
        present = {item["journey"] for item in actual}
        missing = sorted(policy["journeys"] - present)
        if missing:
            findings.append({"code": "APPFORGE_MEDIA_JOURNEY_COVERAGE_MISSING", "detail": f"{set_id} is missing journeys: {', '.join(missing)}"})
        routes = [item["route"] for item in actual]
        if len(routes) != len(set(routes)):
            findings.append({"code": "APPFORGE_MEDIA_ROUTE_DUPLICATE", "detail": f"{set_id} contains duplicate route coverage"})
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_STORE_MEDIA_READY" if not findings else "APPFORGE_STORE_MEDIA_BLOCKED",
        "ok": not findings,
        "action_summary": "Verify exact-build Store media files, dimensions, hashes, journey coverage, and named human representation confirmation; do not generate media, contact App Store Connect, or submit an app.",
        "candidate": candidate,
        "intent_sha256": intent,
        "contract_sha256": hashlib.sha256(contract_source.read_bytes()).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence_source.read_bytes()).hexdigest(),
        "review": {"representative_confirmed_by": reviewer, "storyboard_confirmed_by": storyboard_reviewer, "confirmed_at": confirmed_at},
        "media_sets": {set_id: {"count": len(values), "captures": values} for set_id, values in grouped.items()},
        "findings": findings,
        "authority": AUTHORITY,
        "claim_boundary": "hash-bound local media evidence only; not App Store Connect upload state, Apple policy certification, App Review submission, or approval.",
    }
    core["receipt_sha256"] = _sha(core)
    destination = _local(workspace, out_path, exists=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(core, handle, indent=2, sort_keys=True); handle.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    return {**core, "path": destination.relative_to(workspace).as_posix()}
