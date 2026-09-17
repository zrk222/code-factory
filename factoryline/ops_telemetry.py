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
from functools import lru_cache
from typing import Any, Iterable

from . import __version__
from .provenance import provenance


LIFECYCLE_SCHEMA = "factory.ops-lifecycle.v1"
LIFECYCLE_DIR = Path(".factory") / "ops" / "lifecycle"


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


def lifecycle_inventory(root: Path) -> dict[str, Any]:
    """Aggregate lifecycle receipts without exposing command arguments."""
    directory = Path(root).resolve() / LIFECYCLE_DIR
    rows: list[dict[str, Any]] = []
    invalid = 0
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                invalid += 1
                continue
            if not isinstance(value, dict) or value.get("schema") != LIFECYCLE_SCHEMA:
                invalid += 1
                continue
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
    elapsed = sum(int(row.get("elapsed_ms", 0)) for row in rows)
    return {
        "schema": LIFECYCLE_SCHEMA,
        "receipt_count": len(rows),
        "invalid_count": invalid,
        "statuses": dict(sorted(statuses.items())),
        "commands": dict(sorted(commands.items())),
        "total_elapsed_ms": elapsed,
        "average_elapsed_ms": round(elapsed / len(rows), 1) if rows else None,
        "provenance_complete": sum(
            bool(row.get("provenance", {}).get("identity_complete")) for row in rows
        ),
        "claim_boundary": "Local lifecycle observations only; no provider, token, cost, or productivity claim.",
    }
