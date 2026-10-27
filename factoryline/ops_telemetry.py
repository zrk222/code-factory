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
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache, wraps
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
_PHASE_RECORD_LIMIT = 12
_PHASE_NAMES = frozenset(
    {
        "entrypoint_startup",
        "cli_parse",
        "cli_dispatch",
        "source_inventory",
        "source_audit",
        "proof_evaluation",
        "proof_verification",
        "child_execution",
        "child_launch",
        "child_wait",
        "child_cleanup",
        "receipt_payload",
        "source_read",
        "source_hash",
        "source_parse",
        "source_index",
    }
)
_SOURCE_PHASE_NAMES = frozenset(
    {"source_read", "source_hash", "source_parse", "source_index"}
)
_ACTIVE_PHASE_TELEMETRY: ContextVar["_PhaseTelemetry | None"] = ContextVar(
    "factory_lifecycle_phase_telemetry", default=None
)


class _PhaseTelemetry:
    """One bounded, invocation-local phase summary for a lifecycle receipt."""

    def __init__(self, started_monotonic: float) -> None:
        self.started_monotonic = started_monotonic
        self._phases: dict[str, dict[str, Any]] = {}
        self._dropped_calls = 0
        self._dropped_phase_names: set[str] = set()

    def record(self, name: str, elapsed_ns: int, *, completed: bool) -> None:
        """Accumulate one recognized phase without retaining operation inputs."""
        if name not in _PHASE_NAMES or elapsed_ns < 0:
            return
        phase = self._phases.get(name)
        if phase is None:
            if len(self._phases) >= _PHASE_RECORD_LIMIT:
                self._dropped_calls = min(self._dropped_calls + 1, 2**31 - 1)
                self._dropped_phase_names.add(name)
                return
            phase = {
                "phase": name,
                "elapsed_ns": 0,
                "calls": 0,
                "completed": 0,
                "incomplete": 0,
            }
            self._phases[name] = phase
        phase["elapsed_ns"] += elapsed_ns
        phase["calls"] += 1
        phase["completed" if completed else "incomplete"] += 1

    def snapshot(self) -> dict[str, Any]:
        """Copy observed phase totals and report whether any measured call failed."""
        phases = []
        for name in sorted(self._phases):
            phase = self._phases[name].copy()
            phase["elapsed_ms"] = round(phase.pop("elapsed_ns") / 1_000_000)
            phases.append(phase)
        observed = {item["phase"] for item in phases}
        source_observed = observed & _SOURCE_PHASE_NAMES
        missing = sorted(_SOURCE_PHASE_NAMES - source_observed)
        source_failed = any(
            item["phase"] in _SOURCE_PHASE_NAMES and item["incomplete"]
            for item in phases
        )
        if source_failed or self._dropped_calls:
            source_status = "incomplete"
        elif not source_observed:
            source_status = "not_observed"
        elif missing:
            source_status = "incomplete"
        else:
            source_status = "complete"
        return {
            "phases": phases,
            "status": "incomplete"
            if self._dropped_calls or any(item["incomplete"] for item in phases)
            else "complete",
            "dropped_calls": self._dropped_calls,
            "dropped_phase_names": sorted(self._dropped_phase_names),
            "source_attribution": {
                "status": source_status,
                "coverage_scope": "selected_static_scan_operations",
                "covered_operations": [
                    "review_audits Python source byte reads",
                    "review_audits SHA-256 bindings and freshness rechecks",
                    "review_audits oracle and per-file AST parsing",
                    "implementation_audit stable import-index construction",
                ],
                "excluded_operations": [
                    "configuration and runtime-input reads, parsing, and hashing",
                    "AST parsing outside the selected static-scan boundaries",
                    "BoundSourceBytes fallback byte-identity hashing",
                ],
                "expected_phases": sorted(_SOURCE_PHASE_NAMES),
                "observed_phases": sorted(source_observed),
                "missing_phases": missing,
            },
        }


def _measure_call(name: str, operation, *args, **kwargs):
    with _measure_phase(name):
        return operation(*args, **kwargs)


def _measure_hash(name: str, hasher, data: bytes) -> str:
    return _measure_call(name, lambda: hasher(data).hexdigest())


def _measure_parse(parser, data: bytes, root: Path, path: Path):
    filename = path.relative_to(root).as_posix()
    try:
        return _measure_call("source_parse", parser, data, filename=filename)
    except ValueError as exc:
        if type(exc) is not ValueError or b"\x00" not in data:
            raise
        # Python 3.10 reports null-byte source as ValueError, later versions
        # as SyntaxError. Normalize only the parser's malformed-source case.
        raise SyntaxError(str(exc), (filename, None, None, None)) from exc


def _measured_phase(name: str):
    def decorate(operation):
        @wraps(operation)
        def measured(*args, **kwargs):
            return _measure_call(name, operation, *args, **kwargs)

        return measured

    return decorate


def _measured_source_read(operation):
    @wraps(operation)
    def measured(workspace, relative, *args, **kwargs):
        if not str(relative).casefold().endswith(".py"):
            return operation(workspace, relative, *args, **kwargs)
        return _measure_call(
            "source_read", operation, workspace, relative, *args, **kwargs
        )

    return measured


@contextmanager
def _phase_telemetry(started_monotonic: float):
    telemetry = _PhaseTelemetry(started_monotonic)
    token = _ACTIVE_PHASE_TELEMETRY.set(telemetry)
    try:
        yield telemetry
    finally:
        _ACTIVE_PHASE_TELEMETRY.reset(token)


@contextmanager
def _measure_phase(name: str):
    telemetry = _ACTIVE_PHASE_TELEMETRY.get()
    if telemetry is None or name not in _PHASE_NAMES:
        yield
        return
    started = time.monotonic_ns()
    try:
        yield
    except BaseException:
        telemetry.record(name, time.monotonic_ns() - started, completed=False)
        raise
    else:
        telemetry.record(name, time.monotonic_ns() - started, completed=True)


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
    argv = tuple(argv)
    if not argv:
        return True
    prefix: list[str] = []
    for item in argv:
        value = str(item)
        if value.startswith("-"):
            break
        prefix.append(value)
        if len(prefix) == 2:
            break
    return tuple(prefix) in {
        ("home",),
        ("memory", "brief"),
        ("github", "overview"),
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
    phase_telemetry = _ACTIVE_PHASE_TELEMETRY.get()
    if phase_telemetry is not None:
        started_monotonic = phase_telemetry.started_monotonic
    payload_started = time.monotonic_ns()
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
    if phase_telemetry is not None:
        phase_telemetry.record(
            "receipt_payload",
            time.monotonic_ns() - payload_started,
            completed=True,
        )
        payload["phase_telemetry"] = phase_telemetry.snapshot()
    payload["receipt_sha256"] = _digest(payload)
    destination = workspace / LIFECYCLE_DIR / f"{payload['run_id']}.json"
    _atomic_json(destination, payload)
    return destination


def _cached_lifecycle_payload(raw: bytes, digest: str) -> dict[str, Any] | None:
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
    return value


def _lifecycle_receipt_schema_error(value: object) -> str | None:
    if not isinstance(value, dict) or value.get("schema") != LIFECYCLE_SCHEMA:
        return "schema_mismatch"
    return None


def _lifecycle_receipt_digest_error(value: dict[str, Any]) -> str | None:
    receipt_digest = value.get("receipt_sha256")
    core = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if not isinstance(receipt_digest, str) or receipt_digest != _digest(core):
        return "receipt_digest_mismatch"
    return None


def _lifecycle_receipt_elapsed_error(value: dict[str, Any]) -> str | None:
    elapsed = value.get("elapsed_ms")
    if isinstance(elapsed, bool) or not isinstance(elapsed, int) or elapsed < 0:
        return "invalid_elapsed_ms"
    return None


def _read_lifecycle_receipt(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read, content-cache, and validate one bounded immutable receipt."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(_LIFECYCLE_RECEIPT_MAX_BYTES + 1)
        if len(raw) > _LIFECYCLE_RECEIPT_MAX_BYTES:
            return None, "receipt_too_large"
        digest = hashlib.sha256(raw).hexdigest()
        value = _cached_lifecycle_payload(raw, digest)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "unreadable_or_invalid_json"
    error = _lifecycle_receipt_schema_error(value)
    if error:
        return None, error
    error = _lifecycle_receipt_digest_error(value)
    if error:
        return None, error
    error = _lifecycle_receipt_elapsed_error(value)
    if error:
        return None, error
    return value, None


def _read_lifecycle_inventory(
    workspace: Path,
) -> tuple[list[dict[str, Any]], int, dict[str, int], bool]:
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
    return rows, invalid, invalid_reasons, scan_bounded


def _lifecycle_counts(
    rows: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, int]]:
    statuses: dict[str, int] = {}
    commands: dict[str, int] = {}
    for row in rows:
        statuses[str(row.get("status", "unknown"))] = (
            statuses.get(str(row.get("status", "unknown")), 0) + 1
        )
        commands[str(row.get("command_family", "unknown"))] = (
            commands.get(str(row.get("command_family", "unknown")), 0) + 1
        )

    return statuses, commands


def _percentile(values: list[int], percentile_value: int) -> int | None:
    if not values:
        return None
    # Nearest-rank percentile is deterministic and avoids interpolation
    # that could imply precision beyond integer-millisecond observations.
    position = max(0, (len(values) * percentile_value + 99) // 100 - 1)
    return values[min(position, len(values) - 1)]


def _latency_by_command(
    rows: list[dict[str, Any]], commands: dict[str, int]
) -> dict[str, dict[str, int | None]]:
    latency_by_command: dict[str, dict[str, int | None]] = {}
    for command in sorted(commands):
        values = sorted(
            int(row["elapsed_ms"])
            for row in rows
            if str(row.get("command_family", "unknown")) == command
        )
        latency_by_command[command] = {
            "count": len(values),
            "p50_ms": _percentile(values, 50),
            "p95_ms": _percentile(values, 95),
            "max_ms": values[-1] if values else None,
        }
    return latency_by_command


def _lifecycle_inventory_result(
    rows: list[dict[str, Any]],
    invalid: int,
    invalid_reasons: dict[str, int],
    scan_bounded: bool,
    statuses: dict[str, int],
    commands: dict[str, int],
) -> dict[str, Any]:
    elapsed_values = sorted(int(row["elapsed_ms"]) for row in rows)
    elapsed = sum(elapsed_values)
    latency_by_command = _latency_by_command(rows, commands)
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
            "p50": _percentile(elapsed_values, 50),
            "p95": _percentile(elapsed_values, 95),
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


def lifecycle_inventory(root: Path) -> dict[str, Any]:
    """Aggregate lifecycle receipts without exposing command arguments."""
    workspace = Path(root).resolve()
    rows, invalid, invalid_reasons, scan_bounded = _read_lifecycle_inventory(workspace)
    statuses, commands = _lifecycle_counts(rows)
    return _lifecycle_inventory_result(
        rows, invalid, invalid_reasons, scan_bounded, statuses, commands
    )
