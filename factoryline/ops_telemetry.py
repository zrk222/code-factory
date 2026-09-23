"""Privacy-safe lifecycle telemetry for FactoryLine CLI operations.

The recorder is deliberately local and aggregate-friendly.  It captures command
family, lifecycle status, timing, exit code, and immutable package provenance,
but never prompts, paths, arguments, source, or logs.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from threading import RLock
from typing import Any, Iterable

from . import __version__
from .provenance import provenance
from .receipt_index import indexed_receipt_paths


LIFECYCLE_SCHEMA = "factory.ops-lifecycle.v1"
LIFECYCLE_DIR = Path(".factory") / "ops" / "lifecycle"
_LIFECYCLE_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_LIFECYCLE_CACHE_LOCK = RLock()
_LIFECYCLE_CACHE_LIMIT = 256
_LIFECYCLE_CACHE_MAX_BYTES = 65_536
_LIFECYCLE_RECEIPT_MAX_BYTES = 1_048_576
_LIFECYCLE_READ_WORKERS = 8


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _command_family(argv: Iterable[str]) -> str:
    """Return a bounded command label without retaining user arguments."""
    values = [str(item) for item in argv]
    if not values:
        return "home"
    # Only the top-level command is retained.  A second positional token may
    # be a free-form prompt, path, feature name, or user-supplied identifier;
    # retaining it would leak arguments and defeat the privacy boundary.
    return next((item for item in values if not item.startswith("-")), "unknown")


def _digest(payload: dict[str, Any]) -> str:
    body = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _root_from_argv(argv: list[str], fallback: Path) -> Path:
    for index, value in enumerate(argv[:-1]):
        if value == "--root":
            candidate = Path(argv[index + 1])
            return (
                candidate if candidate.is_absolute() else fallback / candidate
            ).resolve()
    return Path(fallback).resolve()


def is_read_only_command(argv: Iterable[str]) -> bool:
    """Identify commands whose existing contract guarantees zero workspace writes."""
    prefix: list[str] = []
    for item in argv:
        value = str(item)
        if value.startswith("-"):
            break
        prefix.append(value)
        if len(prefix) == 2:
            break
    return tuple(prefix) in {
        ("memory", "brief"),
        ("graph", "ops"),
        ("graph", "portfolio"),
        ("intent", "inspect"),
        ("judgment", "safety-case"),
        ("mcp", "request"),
        ("agent", "control"),
        ("agent", "contract"),
        ("agent", "attestation"),
        ("agent", "route"),
        ("agent", "route-audit"),
        ("workspace", "inspect"),
    }


@lru_cache(maxsize=1)
def _cached_provenance() -> dict[str, Any]:
    return provenance()


def record_lifecycle(
    root: Path,
    argv: list[str],
    *,
    started_monotonic: float,
    exit_code: int,
    status: str,
    error_code: str | None = None,
) -> Path:
    """Write one immutable, privacy-safe CLI lifecycle receipt."""
    workspace = Path(root).resolve()
    started_at = datetime.now(timezone.utc)
    identity = _cached_provenance()
    payload: dict[str, Any] = {
        "schema": LIFECYCLE_SCHEMA,
        "run_id": uuid.uuid4().hex,
        "command_family": _command_family(argv),
        "status": status,
        "exit_code": int(exit_code),
        "elapsed_ms": max(0, round((time.monotonic() - started_monotonic) * 1000)),
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "provenance": {
            "package": "factoryline-code-factory",
            "version": __version__,
            "build_hash": identity.get("build_hash"),
            "source_commit": identity.get("source_commit"),
            "install_origin": identity.get("install_origin"),
            "identity_complete": bool(identity.get("identity_complete")),
        },
        "scope_limits": [
            "local CLI lifecycle only",
            "command arguments, prompts, paths, source, and logs are excluded",
            "does not measure provider usage or prove productivity savings",
        ],
    }
    if error_code:
        payload["error_code"] = str(error_code)[:120]
    payload["receipt_sha256"] = _digest(payload)
    destination = workspace / LIFECYCLE_DIR / f"{payload['run_id']}.json"
    _atomic_json(destination, payload)
    return destination


def _read_lifecycle_receipt(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read, content-cache, and validate one bounded immutable receipt."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(_LIFECYCLE_RECEIPT_MAX_BYTES + 1)
        if len(raw) > _LIFECYCLE_RECEIPT_MAX_BYTES:
            return None, "receipt_too_large"
        digest = hashlib.sha256(raw).hexdigest()
        value = None
        with _LIFECYCLE_CACHE_LOCK:
            value = _LIFECYCLE_CACHE.get(digest)
            if value is not None:
                _LIFECYCLE_CACHE.move_to_end(digest)
        if value is None:
            parsed = json.loads(raw.decode("utf-8-sig"))
            value = parsed if isinstance(parsed, dict) else None
            if value is not None and len(raw) <= _LIFECYCLE_CACHE_MAX_BYTES:
                with _LIFECYCLE_CACHE_LOCK:
                    _LIFECYCLE_CACHE[digest] = value
                    _LIFECYCLE_CACHE.move_to_end(digest)
                    while len(_LIFECYCLE_CACHE) > _LIFECYCLE_CACHE_LIMIT:
                        _LIFECYCLE_CACHE.popitem(last=False)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "unreadable_or_invalid_json"
    if not isinstance(value, dict) or value.get("schema") != LIFECYCLE_SCHEMA:
        return None, "schema_mismatch"
    receipt_digest = value.get("receipt_sha256")
    core = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if not isinstance(receipt_digest, str) or receipt_digest != _digest(core):
        return None, "receipt_digest_mismatch"
    elapsed = value.get("elapsed_ms")
    if isinstance(elapsed, bool) or not isinstance(elapsed, int) or elapsed < 0:
        return None, "invalid_elapsed_ms"
    return value, None


def lifecycle_inventory(root: Path) -> dict[str, Any]:
    """Aggregate lifecycle receipts without exposing command arguments."""
    workspace = Path(root).resolve()
    rows: list[dict[str, Any]] = []
    invalid = 0
    invalid_reasons: dict[str, int] = {}
    paths = indexed_receipt_paths(
        workspace,
        max_files=10_000,
        max_scan_files=100_000,
        suffixes={".json"},
        under=LIFECYCLE_DIR,
        # Every file is read and SHA-256 checked below; we need fresh directory
        # membership, not filesystem-mtime ordering, for this aggregate.
        validate_file_metadata=False,
    )
    scan_bounded = len(paths) >= 10_000
    workers = min(_LIFECYCLE_READ_WORKERS, len(paths))
    if workers:
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="cf-lifecycle"
        ) as pool:
            verified_rows = pool.map(_read_lifecycle_receipt, paths)
            for value, reason in verified_rows:
                if reason is not None:
                    invalid += 1
                    invalid_reasons[reason] = invalid_reasons.get(reason, 0) + 1
                elif value is not None:
                    rows.append(value)
    statuses: dict[str, int] = {}
    commands: dict[str, int] = {}
    for row in rows:
        statuses[str(row.get("status", "unknown"))] = (
            statuses.get(str(row.get("status", "unknown")), 0) + 1
        )
        commands[str(row.get("command_family", "unknown"))] = (
            commands.get(str(row.get("command_family", "unknown")), 0) + 1
        )
    elapsed_values = sorted(int(row["elapsed_ms"]) for row in rows)
    elapsed = sum(elapsed_values)

    def percentile(values: list[int], percentile_value: int) -> int | None:
        if not values:
            return None
        # Nearest-rank percentile is deterministic and avoids interpolation
        # that could imply precision beyond integer-millisecond observations.
        position = max(0, (len(values) * percentile_value + 99) // 100 - 1)
        return values[min(position, len(values) - 1)]

    latency_by_command: dict[str, dict[str, int | None]] = {}
    for command in sorted(commands):
        values = sorted(
            int(row["elapsed_ms"])
            for row in rows
            if str(row.get("command_family", "unknown")) == command
        )
        latency_by_command[command] = {
            "count": len(values),
            "p50_ms": percentile(values, 50),
            "p95_ms": percentile(values, 95),
            "max_ms": values[-1] if values else None,
        }
    return {
        "schema": LIFECYCLE_SCHEMA,
        "receipt_count": len(rows),
        "invalid_count": invalid,
        "coverage": {
            "status": "partial" if scan_bounded or invalid else "complete_within_bound",
            "file_limit": 10_000,
        },
        "statuses": dict(sorted(statuses.items())),
        "commands": dict(sorted(commands.items())),
        "total_elapsed_ms": elapsed,
        "average_elapsed_ms": round(elapsed / len(rows), 1) if rows else None,
        "latency_ms": {
            "p50": percentile(elapsed_values, 50),
            "p95": percentile(elapsed_values, 95),
            "max": elapsed_values[-1] if elapsed_values else None,
        },
        "latency_by_command": latency_by_command,
        "invalid_reasons": dict(sorted(invalid_reasons.items())),
        "provenance_complete": sum(
            bool(
                isinstance(row.get("provenance"), dict)
                and row["provenance"].get("identity_complete") is True
            )
            for row in rows
        ),
        "claim_boundary": "Local lifecycle observations only; no provider, token, cost, or productivity claim.",
    }
