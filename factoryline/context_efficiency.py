"""Deterministic, bounded context packets for fast agent hand-offs.

The packet is a read-only view of already-authorized local sources.  It is not a
gate, an approval token, or an instruction to execute anything.  Sources are
content-addressed and re-checked before use; cache reuse is exact and the token
figure is explicitly an estimate (four UTF-8 bytes per token), never a usage
claim.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from math import ceil
from pathlib import Path
import re
from typing import Any


REQUEST_SCHEMA = "factory.context-efficiency-request.v1"
PACKET_SCHEMA = "factory.context-efficiency-packet.v1"
VERIFICATION_SCHEMA = "factory.context-efficiency-verification.v1"
STATUS_SCHEMA = "factory.context-efficiency-status.v1"
MODULE_VERSION = "1"
MAX_SOURCES = 128
MAX_CHANGED_PATHS = 128
MAX_CACHE_FILES = 100
MAX_SOURCE_BYTES = 1_048_576
MIN_TOKENS = 256
MAX_TOKENS = 12_000
MIN_FILE_TOKENS = 32
MAX_FILE_TOKENS = 2_000
_SECRET_NAME = re.compile(
    r"(?:^|[._-])(secret|token|password|passwd|credential|credentials|private[-_]?key|api[-_]?key)(?:$|[._-])",
    re.I,
)
_SECRET_BYTES = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?:ghp_|github_pat_|pypi-|vsce[_-]?pat)[A-Za-z0-9_-]{8,}"),
    re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
)
_REDACT = (
    re.compile(
        r"(?i)(\b(?:token|password|passwd|secret|api[_-]?key|authorization)\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(r"(?i)(\b(?:bearer)\s+)([^\s]+)"),
)


class ContextEfficiencyError(ValueError):
    """Stable fail-closed error raised for malformed or changed context."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContextEfficiencyError(
            "E_CANONICAL", "value is not canonical JSON"
        ) from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_text(value: Any, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise ContextEfficiencyError(
            "E_FIELD",
            f"{field} must be a non-empty printable string of at most {maximum} characters",
        )
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ContextEfficiencyError(
            "E_DIGEST", f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ContextEfficiencyError(
            "E_FIELD", f"{field} must be an integer in {minimum}..{maximum}"
        )
    return value


def _reject_secret_keys(value: Any, path: str = "request", depth: int = 0) -> None:
    if depth > 16:
        raise ContextEfficiencyError("E_DEPTH", "request nesting exceeds 16")
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_NAME.search(str(key)):
                raise ContextEfficiencyError(
                    "E_SECRET_MATERIAL", f"secret-shaped field at {path}.{key}"
                )
            _reject_secret_keys(child, f"{path}.{key}", depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}[{index}]", depth + 1)


def _relative_path(root: Path, raw: Any, field: str) -> tuple[Path, str]:
    value = _safe_text(raw, field, 512).replace("\\", "/")
    candidate_raw = Path(value)
    if candidate_raw.is_absolute() or re.match(r"^[A-Za-z]:/", value):
        raise ContextEfficiencyError(
            "E_PATH_BOUNDARY", f"{field} must be relative to the workspace"
        )
    if any(part in {"", ".", ".."} for part in candidate_raw.parts):
        raise ContextEfficiencyError(
            "E_PATH_BOUNDARY", f"{field} contains traversal or empty components"
        )
    workspace = Path(root).resolve()
    candidate = workspace.joinpath(candidate_raw)
    ancestor = workspace
    for part in candidate_raw.parts:
        ancestor = ancestor / part
        if ancestor.is_symlink():
            raise ContextEfficiencyError(
                "E_PATH_LINK", f"{field} may not traverse a symlink"
            )
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ContextEfficiencyError(
            "E_PATH_BOUNDARY", f"{field} escapes the workspace"
        ) from exc
    if candidate.is_symlink() or resolved.is_symlink():
        raise ContextEfficiencyError("E_PATH_LINK", f"{field} may not be a symlink")
    return resolved, resolved.relative_to(workspace).as_posix()


def _stable_file(path: Path) -> tuple[bytes, str, dict[str, int]]:
    try:
        before = path.stat()
        if not path.is_file() or path.is_symlink() or before.st_size > MAX_SOURCE_BYTES:
            raise ContextEfficiencyError(
                "E_SOURCE_BOUNDARY",
                f"source is missing, a symlink, or exceeds {MAX_SOURCE_BYTES} bytes",
            )
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                chunks.append(chunk)
        after = path.stat()
    except ContextEfficiencyError:
        raise
    except OSError as exc:
        raise ContextEfficiencyError(
            "E_SOURCE_READ", f"cannot read source: {path}"
        ) from exc
    identity_before = {
        "size": int(before.st_size),
        "mtime_ns": int(before.st_mtime_ns),
        "ino": int(getattr(before, "st_ino", 0)),
    }
    identity_after = {
        "size": int(after.st_size),
        "mtime_ns": int(after.st_mtime_ns),
        "ino": int(getattr(after, "st_ino", 0)),
    }
    if identity_before != identity_after:
        raise ContextEfficiencyError(
            "E_SOURCE_CHANGED", f"source changed while reading: {path}"
        )
    raw = b"".join(chunks)
    return raw, digest.hexdigest(), identity_before


def _validate_request_fields(request: Any) -> None:
    if not isinstance(request, dict):
        raise ContextEfficiencyError(
            "E_REQUEST_FIELDS", "request has missing or unknown fields"
        )
    _reject_secret_keys(request)
    if set(request) != {
        "schema",
        "mission_id",
        "contract_digest",
        "changed_paths",
        "sources",
        "max_tokens",
        "per_file_tokens",
    }:
        raise ContextEfficiencyError(
            "E_REQUEST_FIELDS", "request has missing or unknown fields"
        )
    if request["schema"] != REQUEST_SCHEMA:
        raise ContextEfficiencyError("E_SCHEMA", "unsupported request schema")


def _normalize_changed_paths(root: Path, raw_paths: Any) -> list[str]:
    changed: list[str] = []
    if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= MAX_CHANGED_PATHS:
        raise ContextEfficiencyError(
            "E_FIELD", f"changed_paths must contain 1..{MAX_CHANGED_PATHS} paths"
        )
    for index, item in enumerate(raw_paths):
        _, relative = _relative_path(root, item, f"changed_paths[{index}]")
        if relative in changed:
            raise ContextEfficiencyError(
                "E_DUPLICATE_PATH", f"duplicate changed path: {relative}"
            )
        changed.append(relative)
    return changed


def _normalize_request_sources(root: Path, raw_sources: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_sources, list) or not 1 <= len(raw_sources) <= MAX_SOURCES:
        raise ContextEfficiencyError(
            "E_FIELD", f"sources must contain 1..{MAX_SOURCES} entries"
        )
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw_sources):
        if not isinstance(entry, dict) or set(entry) != {"path", "role", "priority"}:
            raise ContextEfficiencyError(
                "E_SOURCE_FIELDS", f"sources[{index}] has missing or unknown fields"
            )
        _, relative = _relative_path(root, entry["path"], f"sources[{index}].path")
        if relative in seen:
            raise ContextEfficiencyError(
                "E_DUPLICATE_PATH", f"duplicate source path: {relative}"
            )
        seen.add(relative)
        sources.append(
            {
                "path": relative,
                "role": _safe_text(entry["role"], f"sources[{index}].role", 80),
                "priority": _bounded_int(
                    entry["priority"], f"sources[{index}].priority", 0, 100
                ),
            }
        )
    sources.sort(key=lambda item: (-item["priority"], item["role"], item["path"]))
    return sources


def _validate_request(root: Path, request: Any) -> dict[str, Any]:
    _validate_request_fields(request)
    mission_id = _safe_text(request["mission_id"], "mission_id", 120)
    contract_digest = _digest(request["contract_digest"], "contract_digest")
    changed = _normalize_changed_paths(root, request["changed_paths"])
    sources = _normalize_request_sources(root, request["sources"])
    return {
        "schema": REQUEST_SCHEMA,
        "mission_id": mission_id,
        "contract_digest": contract_digest,
        "changed_paths": sorted(changed),
        "sources": sources,
        "max_tokens": _bounded_int(
            request["max_tokens"], "max_tokens", MIN_TOKENS, MAX_TOKENS
        ),
        "per_file_tokens": _bounded_int(
            request["per_file_tokens"],
            "per_file_tokens",
            MIN_FILE_TOKENS,
            MAX_FILE_TOKENS,
        ),
    }


def _redact(text: str) -> str:
    for pattern in _REDACT:
        text = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", text)
    return text


def _selection(
    raw: bytes,
    per_file_tokens: int,
    remaining_bytes: int,
    *,
    sensitive_name: bool = False,
) -> tuple[str | None, str, int, int]:
    budget = max(0, min(per_file_tokens * 4, remaining_bytes))
    if not raw or budget == 0:
        return None, "digest_only", 0, len(raw)
    if sensitive_name or any(pattern.search(raw) for pattern in _SECRET_BYTES):
        return None, "digest_only", 0, len(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "digest_only", 0, len(raw)
    if len(raw) <= budget:
        selected = _redact(text)
        selected_bytes = len(selected.encode("utf-8"))
        if selected_bytes <= budget:
            return selected, "full", selected_bytes, max(0, len(raw) - selected_bytes)
        selected = selected.encode("utf-8")[:budget].decode("utf-8", "ignore")
        selected_bytes = len(selected.encode("utf-8"))
        return selected, "head_tail", selected_bytes, max(0, len(raw) - selected_bytes)
    # Keep both the beginning (intent/configuration) and the end (results/errors)
    # so a compact packet remains useful without pretending to be complete.
    half = max(1, budget // 2)
    head = raw[:half].decode("utf-8", "ignore")
    tail = raw[-half:].decode("utf-8", "ignore")
    selected = _redact(head) + "\n…[context omitted]…\n" + _redact(tail)
    selected_bytes = len(selected.encode("utf-8"))
    if selected_bytes > budget:
        selected = selected.encode("utf-8")[:budget].decode("utf-8", "ignore")
        selected_bytes = len(selected.encode("utf-8"))
    return selected, "head_tail", selected_bytes, max(0, len(raw) - selected_bytes)


def _packet_digest(packet: dict[str, Any]) -> str:
    body = {key: value for key, value in packet.items() if key != "packet_sha256"}
    return _sha(body)


def _cache_dir(root: Path) -> Path:
    return Path(root) / ".factory" / "context-efficiency"


def _read_source_rows(
    workspace: Path, normalized: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    source_digests: list[dict[str, Any]] = []
    for source in normalized["sources"]:
        path = workspace / source["path"]
        raw, digest, identity = _stable_file(path)
        source_digests.append(
            {"path": source["path"], "sha256": digest, "identity": identity}
        )
        rows.append(
            {"source": source, "raw": raw, "sha256": digest, "identity": identity}
        )
    return rows, source_digests


def _load_cached_packet(cache_path: Path) -> dict[str, Any] | None:
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if (
            not isinstance(cached, dict)
            or cached.get("schema") != PACKET_SCHEMA
            or _packet_digest(cached) != cached.get("packet_sha256")
        ):
            return None
        cache = cached.get("cache", {})
        cached["cache"] = {
            **cache,
            "hit": False,
            "reuse_count": int(cache.get("reuse_count", 0)) + 1,
        }
        cached["packet_sha256"] = _packet_digest(cached)
        cache_path.write_text(
            json.dumps(cached, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return cached
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ContextEfficiencyError,
        TypeError,
        ValueError,
    ):
        return None


def _write_packet(path: Path, packet: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(packet, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _assemble_packet(
    normalized: dict[str, Any],
    rows: list[dict[str, Any]],
    cache_key: str,
    cache_path: Path,
) -> dict[str, Any]:
    max_bytes = normalized["max_tokens"] * 4
    remaining = max_bytes
    selected_rows: list[dict[str, Any]] = []
    total_source_bytes = 0
    selected_bytes = 0
    truncated = 0
    digest_only = 0
    for row in rows:
        raw = row["raw"]
        total_source_bytes += len(raw)
        excerpt, inclusion, used, omitted = _selection(
            raw,
            normalized["per_file_tokens"],
            remaining,
            sensitive_name=bool(_SECRET_NAME.search(row["source"]["path"])),
        )
        remaining -= used
        selected_bytes += used
        truncated += int(inclusion == "head_tail")
        digest_only += int(inclusion == "digest_only")
        item: dict[str, Any] = {
            "path": row["source"]["path"],
            "role": row["source"]["role"],
            "priority": row["source"]["priority"],
            "source_sha256": row["sha256"],
            "source_bytes": len(raw),
            "selected_bytes": used,
            "omitted_bytes": omitted,
            "inclusion": inclusion,
            "identity": row["identity"],
        }
        if excerpt is not None:
            item["excerpt"] = excerpt
        selected_rows.append(item)
    packet: dict[str, Any] = {
        "schema": PACKET_SCHEMA,
        "module_version": MODULE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "request": normalized,
        "sources": selected_rows,
        "budget": {
            "max_tokens": normalized["max_tokens"],
            "max_bytes": max_bytes,
            "estimated_tokens": ceil(selected_bytes / 4),
            "selected_bytes": selected_bytes,
            "source_bytes": total_source_bytes,
            "omitted_bytes": max(0, total_source_bytes - selected_bytes),
            "decision": "TRUNCATED"
            if truncated or digest_only or selected_bytes < total_source_bytes
            else "WITHIN_BUDGET",
            "truncated_files": truncated,
            "digest_only_files": digest_only,
            "token_quality": "estimated_from_utf8_bytes_not_provider_usage",
        },
        "cache": {
            "key": cache_key,
            "hit": False,
            "reuse_count": 0,
            "path": cache_path.relative_to(cache_path.parents[2]).as_posix(),
        },
        "authority": {
            "execution": False,
            "approval": False,
            "repair": False,
            "publication": False,
            "credential": False,
        },
        "claim_boundary": "Read-only bounded context selection. Token counts are estimates; this packet does not authorize execution, approval, repair, merge, publication, deployment, or credential access.",
    }
    packet["packet_sha256"] = _packet_digest(packet)
    return packet


def build_context_packet(
    root: Path, request: dict[str, Any], out: Path | None = None
) -> dict[str, Any]:
    """Build or exactly reuse one bounded packet; never executes a source."""
    workspace = Path(root).resolve()
    normalized = _validate_request(workspace, request)
    rows, source_digests = _read_source_rows(workspace, normalized)
    cache_key = _sha(
        {
            "module_version": MODULE_VERSION,
            "request": normalized,
            "sources": source_digests,
        }
    )
    cache_path = _cache_dir(workspace) / f"{cache_key}.json"
    if cache_path.is_file():
        cached = _load_cached_packet(cache_path)
        if cached is not None:
            result = deepcopy(cached)
            result["cache"] = {**result.get("cache", {}), "hit": True}
            result["packet_sha256"] = _packet_digest(result)
            if out is not None:
                _write_packet(Path(out), result)
            return result
    packet = _assemble_packet(normalized, rows, cache_key, cache_path)
    _write_packet(cache_path, packet)
    if out is not None:
        _write_packet(Path(out), packet)
    return packet


def _validate_source_row_binding(
    row: Any, expected: dict[str, Any], allowed: set[str]
) -> None:
    if (
        not isinstance(row, dict)
        or set(row) - allowed
        or row.get("path") != expected["path"]
        or row.get("role") != expected["role"]
        or row.get("priority") != expected["priority"]
    ):
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source row is not bound to the request"
        )


def _validate_source_row_accounting(row: dict[str, Any]) -> None:
    if row.get("inclusion") not in {"full", "head_tail", "digest_only"}:
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source inclusion is invalid"
        )
    sizes = ("source_bytes", "selected_bytes", "omitted_bytes")
    if any(not isinstance(row.get(field), int) for field in sizes):
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source byte accounting is invalid"
        )
    if (
        row["selected_bytes"] < 0
        or row["selected_bytes"] > row["source_bytes"]
        or row["omitted_bytes"] != row["source_bytes"] - row["selected_bytes"]
    ):
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source byte accounting is invalid"
        )


def _validate_source_rows(
    packet_sources: Any, expected_sources: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not isinstance(packet_sources, list) or len(packet_sources) != len(
        expected_sources
    ):
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source rows do not match the request"
        )
    allowed = {
        "path",
        "role",
        "priority",
        "source_sha256",
        "source_bytes",
        "selected_bytes",
        "omitted_bytes",
        "inclusion",
        "identity",
        "excerpt",
    }
    for row, expected in zip(packet_sources, expected_sources):
        _validate_source_row_binding(row, expected, allowed)
        _validate_source_row_accounting(row)
    return packet_sources


def _source_identity_rows(
    packet_sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "path": item["path"],
            "sha256": item["source_sha256"],
            "identity": item["identity"],
        }
        for item in packet_sources
    ]


def _validate_packet_cache(
    packet: dict[str, Any],
    request: dict[str, Any],
    source_identities: list[dict[str, Any]],
) -> None:
    cache = packet.get("cache")
    expected_key = _sha(
        {
            "module_version": MODULE_VERSION,
            "request": request,
            "sources": source_identities,
        }
    )
    if not isinstance(cache, dict) or cache.get("key") != expected_key:
        raise ContextEfficiencyError(
            "E_CACHE_KEY", "cache key does not match request and source identities"
        )


def _verify_packet_header(
    workspace: Path, packet: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if packet.get("schema") != PACKET_SCHEMA or packet.get(
        "packet_sha256"
    ) != _packet_digest(packet):
        raise ContextEfficiencyError(
            "E_PACKET_DIGEST", "packet schema or digest is invalid"
        )
    request = _validate_request(workspace, packet.get("request"))
    packet_sources = _validate_source_rows(packet.get("sources"), request["sources"])
    source_identities = _source_identity_rows(packet_sources)
    _validate_packet_cache(packet, request, source_identities)
    return request, packet_sources


def _verify_packet_sources(
    workspace: Path, packet_sources: list[dict[str, Any]]
) -> int:
    checked = 0
    for item in packet_sources:
        source_path, relative = _relative_path(
            workspace, item.get("path"), "packet.sources.path"
        )
        raw, digest, identity = _stable_file(source_path)
        if (
            relative != item.get("path")
            or digest != item.get("source_sha256")
            or identity != item.get("identity")
            or len(raw) != item.get("source_bytes")
        ):
            raise ContextEfficiencyError(
                "E_SOURCE_DRIFT", f"source changed: {relative}"
            )
        checked += 1
    return checked


def _verify_packet_budget(packet: dict[str, Any]) -> None:
    budget = packet.get("budget")
    if (
        not isinstance(budget, dict)
        or budget.get("selected_bytes", -1) > budget.get("max_bytes", -2)
        or budget.get("token_quality") != "estimated_from_utf8_bytes_not_provider_usage"
    ):
        raise ContextEfficiencyError("E_BUDGET", "packet budget is invalid")


def verify_context_packet(root: Path, packet_path: Path) -> dict[str, Any]:
    """Verify packet identity and every selected source without executing it."""
    workspace = Path(root).resolve()
    path = (
        Path(packet_path)
        if Path(packet_path).is_absolute()
        else workspace / packet_path
    )
    try:
        packet = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(packet, dict):
            raise ContextEfficiencyError("E_SCHEMA", "packet must be an object")
        _, packet_sources = _verify_packet_header(workspace, packet)
        checked = _verify_packet_sources(workspace, packet_sources)
        _verify_packet_budget(packet)
        return {
            "schema": VERIFICATION_SCHEMA,
            "state": "READY",
            "valid": True,
            "packet_sha256": packet["packet_sha256"],
            "source_count": checked,
            "cache_key": packet["cache"]["key"],
            "claim_boundary": "Packet and source digests match; this is read-only evidence and estimated token accounting, not an approval or usage receipt.",
        }
    except (
        ContextEfficiencyError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
    ) as exc:
        return {
            "schema": VERIFICATION_SCHEMA,
            "state": "BLOCKED",
            "valid": False,
            "code": getattr(exc, "code", "E_PACKET_READ"),
            "message": getattr(exc, "message", str(exc)),
            "claim_boundary": "Verification failed closed; no execution or approval authority is granted.",
        }


def context_efficiency_status(root: Path) -> dict[str, Any]:
    """Fast bounded status projection over cached packets (no source reread)."""
    workspace = Path(root).resolve()
    directory = _cache_dir(workspace)
    files = (
        sorted(directory.glob("*.json"))[:MAX_CACHE_FILES] if directory.is_dir() else []
    )
    rows: list[dict[str, Any]] = []
    invalid = 0
    cache_hits = 0
    estimated_tokens = 0
    for path in files:
        try:
            packet = json.loads(path.read_text(encoding="utf-8"))
            valid = (
                isinstance(packet, dict)
                and packet.get("schema") == PACKET_SCHEMA
                and packet.get("packet_sha256") == _packet_digest(packet)
            )
            if not valid:
                invalid += 1
                continue
            budget = packet.get("budget", {})
            estimated_tokens += int(budget.get("estimated_tokens", 0))
            cache_hits += int(packet.get("cache", {}).get("reuse_count", 0))
            rows.append(
                {
                    "path": path.relative_to(workspace).as_posix(),
                    "packet_sha256": packet["packet_sha256"],
                    "state": "READY",
                    "estimated_tokens": budget.get("estimated_tokens", 0),
                    "source_count": len(packet.get("sources", [])),
                }
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
            invalid += 1
    state = "BLOCKED" if invalid else "READY" if rows else "MISSING"
    return {
        "schema": STATUS_SCHEMA,
        "state": state,
        "marker": "CONTEXT_EFFICIENCY_READ_ONLY",
        "packet_count": len(rows),
        "invalid_count": invalid,
        "cache_hits": cache_hits,
        "estimated_tokens": estimated_tokens,
        "packets": rows,
        "claim_boundary": "Bounded cache metadata only; estimated token counts are not provider usage or guaranteed savings, and no source is executed or approved.",
        "authority": {
            "execution": False,
            "approval": False,
            "repair": False,
            "publication": False,
            "credential": False,
        },
    }
