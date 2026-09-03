"""Strict, zero-authority primitives for runtime assurance artifacts."""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 1_048_576
IGNORED_VERDICT_FIELDS = {"passed", "ok", "verdict", "decision"}
FORBIDDEN_SECRET_FIELDS = {"body", "headers", "token", "password", "secret"}


class RuntimeAuditError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def canonical_bytes(value: object) -> bytes:
    """Serialize a JSON-compatible value into the single canonical byte representation used for digests."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return a lowercase SHA-256 digest for already bounded bytes without assigning any trust authority."""
    return hashlib.sha256(value).hexdigest()


def exact_keys(value: dict[str, Any], required: set[str], optional: set[str] | None = None) -> None:
    """Reject missing or unknown object fields while ignoring only explicitly non-authoritative verdict labels."""
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_ARTIFACT_FIELDS", "expected an object")
    optional = (optional or set()) | IGNORED_VERDICT_FIELDS
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        raise RuntimeAuditError("E_ARTIFACT_FIELDS", f"missing fields: {sorted(missing)}")
    if unknown:
        raise RuntimeAuditError("E_ARTIFACT_FIELDS", f"unknown fields: {sorted(unknown)}")


def require_str(value: object, field: str, *, minimum: int = 1, maximum: int = 256) -> str:
    """Validate a printable bounded string and return it without coercing another input type."""
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or not value.strip() or any(ord(c) < 32 for c in value):
        raise RuntimeAuditError("E_FIELD", f"{field} must be a string of {minimum}..{maximum} characters")
    return value


def require_digest(value: object, field: str) -> str:
    """Validate and return one canonical lowercase SHA-256 hexadecimal digest string."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RuntimeAuditError("E_DIGEST", f"{field} must be a lowercase SHA-256 hex digest")
    return value


def require_bool(value: object, field: str) -> bool:
    """Require a real JSON boolean rather than accepting integer truthiness or string approximations."""
    if type(value) is not bool:
        raise RuntimeAuditError("E_FIELD", f"{field} must be boolean")
    return value


def require_int(value: object, field: str, *, minimum: int, maximum: int) -> int:
    """Validate a bounded integer while explicitly refusing booleans and implicit numeric coercion."""
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RuntimeAuditError("E_FIELD", f"{field} must be an integer in {minimum}..{maximum}")
    return value


def require_number(value: object, field: str, *, minimum: float = 0.0) -> float:
    """Validate a finite numeric observation above the declared floor and return a float."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeAuditError("E_FIELD", f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise RuntimeAuditError("E_FIELD", f"{field} must be finite and >= {minimum}")
    return result


def require_unique_strings(value: object, field: str, *, minimum: int, maximum: int) -> list[str]:
    """Validate a bounded list of distinct printable strings without silently deduplicating evidence."""
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise RuntimeAuditError("E_FIELD", f"{field} must contain {minimum}..{maximum} items")
    items = [require_str(item, f"{field}[]") for item in value]
    if len(items) != len(set(items)):
        raise RuntimeAuditError("E_DUPLICATE_ID", f"{field} contains duplicates")
    return items


def reject_secret_material(value: object, *, path: str = "artifact", depth: int = 0, max_string_length: int = 4096) -> None:
    """Recursively reject secret-shaped fields, excessive depth, non-finite numbers, and oversized strings."""
    if depth > 32:
        raise RuntimeAuditError("E_ARTIFACT_DEPTH", "maximum nesting depth is 32")
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_SECRET_FIELDS:
                raise RuntimeAuditError("E_SECRET_MATERIAL", f"forbidden field at {path}.{key}")
            reject_secret_material(child, path=f"{path}.{key}", depth=depth + 1, max_string_length=max_string_length)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_material(child, path=f"{path}[{index}]", depth=depth + 1, max_string_length=max_string_length)
    elif isinstance(value, float) and not math.isfinite(value):
        raise RuntimeAuditError("E_NONFINITE", f"non-finite number at {path}")
    elif isinstance(value, str) and len(value) > max_string_length:
        raise RuntimeAuditError("E_FIELD_SIZE", f"string too long at {path}")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeAuditError("E_DUPLICATE_FIELD", key)
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, *, max_string_length: int = 4096) -> dict[str, Any]:
    """Strictly decode one bounded JSON object while rejecting duplicate keys and unsafe evidence values."""
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise RuntimeAuditError("E_ARTIFACT_SIZE", "artifact too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeAuditError("E_ARTIFACT_JSON", "invalid bounded JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_ARTIFACT_JSON", "artifact must be a JSON object")
    reject_secret_material(value, max_string_length=max_string_length)
    return value


def read_stable_json(path: Path, *, max_string_length: int = 4096) -> tuple[dict[str, Any], str]:
    """Read a non-symlink JSON artifact twice and return its parsed object plus exact-byte digest."""
    if not path.is_file():
        raise RuntimeAuditError("E_ARTIFACT_MISSING", str(path))
    if path.is_symlink():
        raise RuntimeAuditError("E_ARTIFACT_LINK", "symlink artifacts are forbidden")
    with path.open("rb") as stream:
        first = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(first) > MAX_ARTIFACT_BYTES:
        raise RuntimeAuditError("E_ARTIFACT_SIZE", f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
    with path.open("rb") as stream:
        second = stream.read(MAX_ARTIFACT_BYTES + 1)
    if first != second:
        raise RuntimeAuditError("E_ARTIFACT_CHANGED", str(path))
    return parse_json_bytes(first, max_string_length=max_string_length), sha256_bytes(first)


def lane_result(
    lane: str,
    state: str,
    finding: str,
    consequence: str,
    *,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct one closed-state audit result from independently computed facts and bounded details."""
    if state not in {"PASS", "FAIL", "INCOMPLETE"}:
        raise RuntimeAuditError("E_STATE", state)
    return {
        "lane": lane,
        "state": state,
        "finding": finding,
        "consequence": consequence,
        "details": details or {},
    }
