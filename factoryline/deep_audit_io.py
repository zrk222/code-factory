"""Bounded local input primitives for non-authoritative deep analysis evidence."""
from __future__ import annotations

import json
import stat
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote

from .runtime_audit_common import RuntimeAuditError, canonical_bytes, require_digest, require_str, sha256_bytes

LIMIT = 10_000_000


def digest(value: object) -> str:
    """Fingerprint normalized JSON using the existing canonical receipt encoding without assigning any authority."""
    return sha256_bytes(canonical_bytes(value))


def relative_path(value: object) -> str:
    """Require a canonical workspace path, rejecting ambiguous URI, Windows and traversal spellings."""
    text = require_str(value, "path", maximum=512)
    parts = text.split("/")
    forbidden = ("\\", ":", "?", "#")
    if any(char in text for char in forbidden) or unquote(text) != text:
        raise RuntimeAuditError("E_PATH_ESCAPE", "noncanonical path")
    if PureWindowsPath(text).drive or any(part in {"", ".", ".."} for part in parts):
        raise RuntimeAuditError("E_PATH_ESCAPE", "path must be workspace-relative")
    if any(part.endswith((" ", ".")) or PureWindowsPath(part).is_reserved() for part in parts):
        raise RuntimeAuditError("E_PATH_ESCAPE", "ambiguous Windows path")
    return text


def local_file(root: Path, value: object) -> Path:
    """Resolve one regular workspace file while rejecting symlinks and Windows reparse points throughout."""
    root = Path(root).resolve()
    candidate = root
    for part in relative_path(value).split("/"):
        candidate = candidate / part
        try:
            info = candidate.lstat()
        except OSError as exc:
            raise RuntimeAuditError("E_SOURCE_MISSING", "regular file required") from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeAuditError("E_PATH_ESCAPE", "linked evidence is not supported")
    candidate.resolve().relative_to(root)
    if not candidate.is_file():
        raise RuntimeAuditError("E_SOURCE_MISSING", "regular file required")
    return candidate


def bound_bytes(root: Path, binding: dict) -> bytes:
    """Read at most the evidence byte budget and verify its caller-supplied SHA-256 binding."""
    expected = require_digest(binding["sha256"], "sha256")
    path = local_file(root, binding["path"])
    with path.open("rb") as stream:
        before = path.stat()
        raw = stream.read(LIMIT + 1)
        after = path.stat()
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_REPORT_SIZE", "evidence exceeds byte budget")
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeAuditError("E_INPUT_CHANGED", "evidence changed during read")
    if sha256_bytes(raw) != expected:
        raise RuntimeAuditError("E_REPORT_DRIFT", "evidence hash mismatch")
    return raw


def _object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeAuditError("E_DUPLICATE_FIELD", "duplicate JSON key")
        result[key] = value
    return result


def _finite(value: str) -> None:
    raise RuntimeAuditError("E_NONFINITE", "non-finite JSON number")


def strict_json(raw: bytes) -> dict:
    """Decode bounded JSON, rejecting duplicate fields, nonfinite values and excessive parser recursion."""
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_REPORT_SIZE", "JSON exceeds byte budget")
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_finite)
        canonical_bytes(value)  # Reject exponent overflow such as 1e999, too.
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, RuntimeAuditError):
            raise
        raise RuntimeAuditError("E_REPORT_JSON", "invalid bounded JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_REPORT_JSON", "object required")
    return value
