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
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, field: str, *, limit: int = 300) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID",
            f"{field} must be a non-empty bounded string",
        )
    return result


def _sha256(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(char not in "0123456789abcdef" for char in result):
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID", f"{field} must be a SHA-256 hex digest"
        )
    return result


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = root.resolve()
    resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise StoreMediaError(
            "APPFORGE_MEDIA_PATH_REJECTED", "paths must remain inside the workspace"
        ) from exc
    if exists and not resolved.is_file():
        raise StoreMediaError(
            "APPFORGE_MEDIA_INPUT_UNAVAILABLE", "input must be a regular workspace file"
        )
    return resolved


def _read_json(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise StoreMediaError(
            "APPFORGE_MEDIA_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB"
        )
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StoreMediaError(
            "APPFORGE_MEDIA_INPUT_INVALID", "input must be valid JSON"
        ) from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise StoreMediaError("APPFORGE_MEDIA_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _candidate(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise StoreMediaError(
            "APPFORGE_MEDIA_CANDIDATE_INVALID", f"{label} must be an object"
        )
    return {
        key: _text(value.get(key), f"{label}.{key}")
        for key in ("bundle_identifier", "version", "build_number", "source_commit")
    }


def _dimensions(value: object, field: str) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID", f"{field} must be an object"
        )
    width, height = value.get("width"), value.get("height")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item <= 0 or item > 10000
        for item in (width, height)
    ):
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID",
            f"{field} must contain positive bounded dimensions",
        )
    return width, height


def _media_set_counts(item: dict[str, Any], index: int) -> tuple[int, int]:
    minimum, maximum = item.get("min_count"), item.get("max_count")
    if (
        any(
            isinstance(number, bool) or not isinstance(number, int)
            for number in (minimum, maximum)
        )
        or not 1 <= minimum <= maximum <= 10
    ):
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID",
            f"media_sets[{index}] counts must be between 1 and 10",
        )
    return minimum, maximum


def _media_set_dimensions(item: dict[str, Any], index: int) -> set[tuple[int, int]]:
    values = item.get("accepted_dimensions")
    if not isinstance(values, list) or not values or len(values) > 12:
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID",
            f"media_sets[{index}].accepted_dimensions must contain 1-12 dimensions",
        )
    return {
        _dimensions(entry, f"media_sets[{index}].accepted_dimensions")
        for entry in values
    }


def _media_set_journeys(item: dict[str, Any], index: int) -> set[str]:
    values = item.get("required_journeys")
    if not isinstance(values, list) or not values or len(values) > 10:
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID",
            f"media_sets[{index}].required_journeys must contain 1-10 values",
        )
    return {
        _text(entry, f"media_sets[{index}].required_journeys", limit=80)
        for entry in values
    }


def _media_set_sources(item: dict[str, Any], index: int) -> set[str]:
    values = item.get("allowed_capture_sources")
    if not isinstance(values, list) or not values or len(values) > 8:
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID",
            f"media_sets[{index}].allowed_capture_sources must contain 1-8 values",
        )
    return {
        _text(entry, f"media_sets[{index}].allowed_capture_sources", limit=80)
        for entry in values
    }


def _media_set_policy(item: dict[str, Any], index: int) -> dict[str, Any]:
    minimum, maximum = _media_set_counts(item, index)
    dimensions = _media_set_dimensions(item, index)
    journeys = _media_set_journeys(item, index)
    sources = _media_set_sources(item, index)
    return {
        "min_count": minimum,
        "max_count": maximum,
        "dimensions": dimensions,
        "journeys": journeys,
        "sources": sources,
    }


def _sets(value: object) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise StoreMediaError(
            "APPFORGE_MEDIA_CONTRACT_INVALID", "media_sets must contain 1-8 sets"
        )
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise StoreMediaError(
                "APPFORGE_MEDIA_CONTRACT_INVALID",
                f"media_sets[{index}] must be an object",
            )
        set_id = _text(item.get("id"), f"media_sets[{index}].id", limit=80)
        if set_id in result:
            raise StoreMediaError(
                "APPFORGE_MEDIA_CONTRACT_INVALID", "media set ids must be unique"
            )
        result[set_id] = _media_set_policy(item, index)
    return result


def _png_chunk(raw: bytes, offset: int) -> tuple[int, bytes, bytes, int] | None:
    length = struct.unpack(">I", raw[offset : offset + 4])[0]
    chunk_type = raw[offset + 4 : offset + 8]
    end = offset + 12 + length
    if end > len(raw):
        return None
    data = raw[offset + 8 : offset + 8 + length]
    supplied_crc = struct.unpack(">I", raw[offset + 8 + length : end])[0]
    if zlib.crc32(chunk_type + data) & 0xFFFFFFFF != supplied_crc:
        return None
    return length, chunk_type, data, end


def _png_header(
    width: int | None, length: int, data: bytes
) -> tuple[int, int, int] | None:
    if width is not None or length != 13:
        return None
    parsed_width, height, _bit_depth, color_type, _compression, _filter, _interlace = (
        struct.unpack(">IIBBBBB", data)
    )
    return parsed_width, height, color_type


def _png_end(
    length: int,
    width: int | None,
    height: int | None,
    color_type: int | None,
    saw_idat: bool,
    end: int,
    raw: bytes,
) -> tuple[str, int, int, bool] | None:
    if not (
        length == 0
        and width
        and height
        and color_type is not None
        and saw_idat
        and end == len(raw)
    ):
        return None
    return "png", width, height, color_type in {4, 6}


def _png_info(path: Path, raw: bytes) -> tuple[str, int, int, bool]:
    offset, width, height, color_type = 8, None, None, None
    saw_idat = False
    while offset + 12 <= len(raw):
        chunk = _png_chunk(raw, offset)
        if chunk is None:
            break
        length, chunk_type, data, end = chunk
        if chunk_type == b"IHDR":
            header = _png_header(width, length, data)
            if header is None:
                break
            width, height, color_type = header
        elif chunk_type == b"IDAT":
            saw_idat = True
        elif chunk_type == b"IEND":
            image = _png_end(length, width, height, color_type, saw_idat, end, raw)
            if image is not None:
                return image
            break
        offset = end
    raise StoreMediaError(
        "APPFORGE_MEDIA_UNSUPPORTED_IMAGE",
        f"{path.name} must be a structurally valid PNG",
    )


def _jpeg_marker(raw: bytes, offset: int) -> tuple[int | None, int | None]:
    if raw[offset] != 0xFF:
        return None, offset + 1
    while offset < len(raw) and raw[offset] == 0xFF:
        offset += 1
    if offset >= len(raw):
        return None, None
    return raw[offset], offset + 1


def _jpeg_segment(
    raw: bytes, offset: int, marker: int, sof_markers: set[int]
) -> tuple[tuple[int, int] | None, int] | None:
    if offset + 2 > len(raw):
        return None
    length = struct.unpack(">H", raw[offset : offset + 2])[0]
    if length < 2 or offset + length > len(raw):
        return None
    dimensions = None
    if marker in sof_markers and length >= 7:
        height, width = struct.unpack(">HH", raw[offset + 3 : offset + 7])
        dimensions = (width, height)
    return dimensions, offset + length


def _jpeg_info(path: Path, raw: bytes) -> tuple[str, int, int, bool]:
    offset = 2
    sof_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    while offset + 9 <= len(raw):
        marker, after_marker = _jpeg_marker(raw, offset)
        if after_marker is None:
            break
        if marker is None or marker in {0xD8, 0xD9}:
            offset = after_marker
            continue
        segment = _jpeg_segment(raw, after_marker, marker, sof_markers)
        if segment is None:
            break
        dimensions, offset = segment
        if dimensions is not None:
            width, height = dimensions
            return "jpeg", width, height, False
    raise StoreMediaError(
        "APPFORGE_MEDIA_UNSUPPORTED_IMAGE",
        f"{path.name} must be a parseable PNG or JPEG",
    )


def _image_info(path: Path) -> tuple[str, int, int, bool]:
    raw = path.read_bytes()
    if len(raw) > MAX_MEDIA_BYTES:
        raise StoreMediaError(
            "APPFORGE_MEDIA_FILE_TOO_LARGE",
            f"{path.name} exceeds {MAX_MEDIA_BYTES} bytes",
        )
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return _png_info(path, raw)
    if raw.startswith(b"\xff\xd8"):
        return _jpeg_info(path, raw)
    raise StoreMediaError(
        "APPFORGE_MEDIA_UNSUPPORTED_IMAGE",
        f"{path.name} must be a parseable PNG or JPEG",
    )


def _timestamp(value: object) -> str:
    result = _text(value, "review.confirmed_at", limit=40)
    try:
        datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StoreMediaError(
            "APPFORGE_MEDIA_EVIDENCE_INVALID", "review.confirmed_at must be RFC3339"
        ) from exc
    return result


def _media_review_facts(
    contract: dict[str, Any], evidence: dict[str, Any]
) -> tuple[dict[str, str], dict[str, str], str, str, str, str]:
    candidate = _candidate(contract.get("candidate"), "contract.candidate")
    observed = _candidate(evidence.get("candidate"), "evidence.candidate")
    intent = _sha256(contract.get("intent_sha256"), "contract.intent_sha256")
    review = evidence.get("review")
    if not isinstance(review, dict):
        raise StoreMediaError(
            "APPFORGE_MEDIA_EVIDENCE_INVALID", "review must be an object"
        )
    reviewer = _text(
        review.get("representative_confirmed_by"), "review.representative_confirmed_by"
    )
    storyboard_reviewer = _text(
        review.get("storyboard_confirmed_by"), "review.storyboard_confirmed_by"
    )
    confirmed_at = _timestamp(review.get("confirmed_at"))
    return candidate, observed, intent, reviewer, storyboard_reviewer, confirmed_at


def _media_bindings(
    evidence: dict[str, Any],
    candidate: dict[str, str],
    observed: dict[str, str],
    intent: str,
) -> list[dict[str, str]]:
    findings = []
    if observed != candidate:
        findings.append(
            {
                "code": "APPFORGE_MEDIA_BUILD_BINDING_MISMATCH",
                "detail": "media evidence does not match the reviewed candidate",
            }
        )
    if _sha256(evidence.get("intent_sha256"), "evidence.intent_sha256") != intent:
        findings.append(
            {
                "code": "APPFORGE_MEDIA_INTENT_BINDING_MISMATCH",
                "detail": "media evidence does not match the confirmed storyboard intent",
            }
        )
    return findings


def _capture_values(capture: dict[str, Any], index: int) -> dict[str, str]:
    return {
        "id": _text(capture.get("id"), f"captures[{index}].id", limit=80),
        "set_id": _text(capture.get("set_id"), f"captures[{index}].set_id", limit=80),
        "route": _text(capture.get("route"), f"captures[{index}].route", limit=300),
        "journey": _text(
            capture.get("journey"), f"captures[{index}].journey", limit=80
        ),
        "source": _text(
            capture.get("capture_source"),
            f"captures[{index}].capture_source",
            limit=80,
        ),
        "sha256": _sha256(capture.get("sha256"), f"captures[{index}].sha256"),
    }


def _verify_capture_media(
    workspace: Path,
    capture: dict[str, Any],
    values: dict[str, str],
    index: int,
    sets: dict[str, dict[str, Any]],
    require_no_alpha: bool,
    grouped: dict[str, list[dict[str, str]]],
    hashes: set[str],
) -> None:
    capture_id, set_id = values["id"], values["set_id"]
    if set_id not in sets:
        raise StoreMediaError(
            "APPFORGE_MEDIA_CAPTURE_INVALID",
            f"capture {capture_id} refers to an unknown media set",
        )
    if values["source"] not in sets[set_id]["sources"]:
        raise StoreMediaError(
            "APPFORGE_MEDIA_CAPTURE_SOURCE_REJECTED",
            f"capture {capture_id} uses an unapproved source",
        )
    image = _local(
        workspace,
        Path(_text(capture.get("path"), f"captures[{index}].path", limit=600)),
    )
    actual_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    if actual_hash != values["sha256"]:
        raise StoreMediaError(
            "APPFORGE_MEDIA_HASH_MISMATCH",
            f"capture {capture_id} does not match its declared hash",
        )
    if actual_hash in hashes:
        raise StoreMediaError(
            "APPFORGE_MEDIA_DUPLICATE", f"capture {capture_id} duplicates another image"
        )
    hashes.add(actual_hash)
    _format, width, height, has_alpha = _image_info(image)
    if (width, height) not in sets[set_id]["dimensions"]:
        raise StoreMediaError(
            "APPFORGE_MEDIA_DIMENSIONS_INVALID",
            f"capture {capture_id} has unsupported dimensions {width}x{height}",
        )
    if require_no_alpha and has_alpha:
        raise StoreMediaError(
            "APPFORGE_MEDIA_ALPHA_REJECTED",
            f"capture {capture_id} contains an alpha channel",
        )
    grouped[set_id].append(
        {
            "id": capture_id,
            "route": values["route"],
            "journey": values["journey"],
            "path": image.relative_to(workspace).as_posix(),
            "sha256": actual_hash,
        }
    )


def _capture_finding(
    workspace: Path,
    capture: object,
    index: int,
    sets: dict[str, dict[str, Any]],
    require_no_alpha: bool,
    grouped: dict[str, list[dict[str, str]]],
    ids: set[str],
    hashes: set[str],
) -> dict[str, str] | None:
    if not isinstance(capture, dict):
        return {
            "code": "APPFORGE_MEDIA_CAPTURE_INVALID",
            "detail": f"capture {index} is not an object",
        }
    try:
        values = _capture_values(capture, index)
        if values["id"] in ids:
            raise StoreMediaError(
                "APPFORGE_MEDIA_CAPTURE_INVALID", "capture ids must be unique"
            )
        ids.add(values["id"])
        _verify_capture_media(
            workspace, capture, values, index, sets, require_no_alpha, grouped, hashes
        )
    except StoreMediaError as error:
        return {"code": error.code, "detail": str(error)}
    return None


def _capture_findings(
    workspace: Path,
    captures: list[Any],
    sets: dict[str, dict[str, Any]],
    require_no_alpha: bool,
) -> tuple[dict[str, list[dict[str, str]]], list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {set_id: [] for set_id in sets}
    findings: list[dict[str, str]] = []
    ids: set[str] = set()
    hashes: set[str] = set()
    for index, capture in enumerate(captures):
        finding = _capture_finding(
            workspace, capture, index, sets, require_no_alpha, grouped, ids, hashes
        )
        if finding is not None:
            findings.append(finding)
    return grouped, findings


def _media_coverage_findings(
    sets: dict[str, dict[str, Any]],
    grouped: dict[str, list[dict[str, str]]],
) -> list[dict[str, str]]:
    findings = []
    for set_id, policy in sets.items():
        actual = grouped[set_id]
        if not policy["min_count"] <= len(actual) <= policy["max_count"]:
            findings.append(
                {
                    "code": "APPFORGE_MEDIA_COUNT_INVALID",
                    "detail": f"{set_id} requires {policy['min_count']}-{policy['max_count']} captures, found {len(actual)}",
                }
            )
        present = {item["journey"] for item in actual}
        missing = sorted(policy["journeys"] - present)
        if missing:
            findings.append(
                {
                    "code": "APPFORGE_MEDIA_JOURNEY_COVERAGE_MISSING",
                    "detail": f"{set_id} is missing journeys: {', '.join(missing)}",
                }
            )
        routes = [item["route"] for item in actual]
        if len(routes) != len(set(routes)):
            findings.append(
                {
                    "code": "APPFORGE_MEDIA_ROUTE_DUPLICATE",
                    "detail": f"{set_id} contains duplicate route coverage",
                }
            )
    return findings


def _media_receipt_core(
    candidate: dict[str, str],
    intent: str,
    contract_source: Path,
    evidence_source: Path,
    reviewer: str,
    storyboard_reviewer: str,
    confirmed_at: str,
    grouped: dict[str, list[dict[str, str]]],
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_STORE_MEDIA_READY"
        if not findings
        else "APPFORGE_STORE_MEDIA_BLOCKED",
        "ok": not findings,
        "action_summary": "Verify exact-build Store media files, dimensions, hashes, journey coverage, and named human representation confirmation; do not generate media, contact App Store Connect, or submit an app.",
        "candidate": candidate,
        "intent_sha256": intent,
        "contract_sha256": hashlib.sha256(contract_source.read_bytes()).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence_source.read_bytes()).hexdigest(),
        "review": {
            "representative_confirmed_by": reviewer,
            "storyboard_confirmed_by": storyboard_reviewer,
            "confirmed_at": confirmed_at,
        },
        "media_sets": {
            set_id: {"count": len(values), "captures": values}
            for set_id, values in grouped.items()
        },
        "findings": findings,
        "authority": AUTHORITY,
        "claim_boundary": "hash-bound local media evidence only; not App Store Connect upload state, Apple policy certification, App Review submission, or approval.",
    }


def _write_media_receipt(
    workspace: Path, out_path: Path, core: dict[str, Any]
) -> dict[str, Any]:
    core["receipt_sha256"] = _sha(core)
    destination = _local(workspace, out_path, exists=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(core, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {**core, "path": destination.relative_to(workspace).as_posix()}


def verify_store_media(
    root: Path, contract_path: Path, evidence_path: Path, out_path: Path
) -> dict[str, Any]:
    """Verify image artifacts, candidate binding, and stated journey coverage."""
    workspace = Path(root).resolve()
    contract, contract_source = _read_json(workspace, contract_path, CONTRACT_SCHEMA)
    evidence, evidence_source = _read_json(workspace, evidence_path, EVIDENCE_SCHEMA)
    (
        candidate,
        observed,
        intent,
        reviewer,
        storyboard_reviewer,
        confirmed_at,
    ) = _media_review_facts(contract, evidence)
    sets = _sets(contract.get("media_sets"))
    require_no_alpha = contract.get("require_no_alpha") is True
    captures = evidence.get("captures")
    if not isinstance(captures, list) or not captures or len(captures) > 80:
        raise StoreMediaError(
            "APPFORGE_MEDIA_EVIDENCE_INVALID", "captures must contain 1-80 entries"
        )

    findings = _media_bindings(evidence, candidate, observed, intent)
    grouped, capture_errors = _capture_findings(
        workspace, captures, sets, require_no_alpha
    )
    findings.extend(capture_errors)
    findings.extend(_media_coverage_findings(sets, grouped))
    core = _media_receipt_core(
        candidate,
        intent,
        contract_source,
        evidence_source,
        reviewer,
        storyboard_reviewer,
        confirmed_at,
        grouped,
        findings,
    )
    return _write_media_receipt(workspace, out_path, core)
