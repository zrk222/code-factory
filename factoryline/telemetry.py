"""Reconcile local FactoryLine telemetry into a privacy-safe inventory.

Telemetry is intentionally an inventory, not an outcome claim.  It joins the
receipt, run, trace, and meter ledgers by stable run ids, preserves unknowns,
and marks conflicting observations instead of silently choosing one.
"""

from __future__ import annotations

from collections import Counter
from collections import OrderedDict
from hashlib import sha256
import json
from pathlib import Path
from threading import RLock
from typing import Any

from .run_metrics import RUN_SCHEMA
from .receipt_index import indexed_receipt_paths


TELEMETRY_SCHEMA = "factory.telemetry-inventory.v1"
_PARSED_JSON_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_PARSED_JSON_CACHE_LOCK = RLock()
_PARSED_JSON_CACHE_SIZE = 256
_PARSED_JSON_CACHE_MAX_BYTES = 65_536
_LEDGER_FILE_LIMIT = 10_000
_LEDGER_SCAN_LIMIT = 100_000
_TELEMETRY_JSON_MAX_BYTES = 1_048_576
_METER_LEDGER_MAX_BYTES = 16_777_216


def _digest(payload: Any) -> str:
    data = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256(data).hexdigest()


def _ledger_scope(ledger: Path) -> tuple[Path | None, Path | None]:
    workspace: Path | None = None
    relative_ledger: Path | None = None
    if ledger.name in {"receipts", "traces"}:
        workspace = ledger.parent
        relative_ledger = Path(ledger.name)
    else:
        for parent in ledger.parents:
            if parent.name == ".factory":
                workspace = parent.parent
                relative_ledger = ledger.relative_to(workspace)
                break
    return workspace, relative_ledger


def _ledger_candidates(
    ledger: Path,
) -> tuple[list[Path], bool]:
    workspace, relative_ledger = _ledger_scope(ledger)
    if workspace is not None and relative_ledger is not None:
        candidates = indexed_receipt_paths(
            workspace,
            max_files=_LEDGER_FILE_LIMIT,
            max_scan_files=_LEDGER_SCAN_LIMIT,
            suffixes={".json"},
            under=relative_ledger,
            # Inventory consumes every selected file by bytes+SHA-256 below;
            # it needs a fresh path set, not an mtime-based recency ordering.
            validate_file_metadata=False,
        )
        bounded = len(candidates) >= _LEDGER_FILE_LIMIT
    else:
        all_candidates = sorted(ledger.rglob("*.json"))
        bounded = len(all_candidates) > _LEDGER_FILE_LIMIT
        candidates = all_candidates[:_LEDGER_FILE_LIMIT]
    return candidates, bounded


def _cached_json_file(item: Path) -> dict[str, Any] | None:
    raw = item.read_bytes()
    digest = "json:" + sha256(raw).hexdigest()
    value = None
    if len(raw) <= _PARSED_JSON_CACHE_MAX_BYTES:
        with _PARSED_JSON_CACHE_LOCK:
            value = _PARSED_JSON_CACHE.get(digest)
            if value is not None:
                _PARSED_JSON_CACHE.move_to_end(digest)
    if value is None:
        parsed = json.loads(raw.decode("utf-8-sig"))
        value = parsed if isinstance(parsed, dict) else None
        if value is not None and len(raw) <= _PARSED_JSON_CACHE_MAX_BYTES:
            _cache_json_value(digest, value)
    return value


def _cache_json_value(digest: str, value: dict[str, Any]) -> None:
    with _PARSED_JSON_CACHE_LOCK:
        _PARSED_JSON_CACHE[digest] = value
        _PARSED_JSON_CACHE.move_to_end(digest)
        while len(_PARSED_JSON_CACHE) > _PARSED_JSON_CACHE_SIZE:
            _PARSED_JSON_CACHE.popitem(last=False)


def _read_ledger_row(item: Path) -> dict[str, Any] | None:
    if item.stat().st_size > _TELEMETRY_JSON_MAX_BYTES:
        return None
    return _cached_json_file(item)


def _rows(path: Path) -> tuple[list[tuple[Path, dict[str, Any]]], bool, int]:
    if not path.exists():
        return [], False, 0
    ledger = Path(path).resolve()
    candidates, bounded = _ledger_candidates(ledger)
    output: list[tuple[Path, dict[str, Any]]] = []
    invalid = 0
    for item in candidates:
        try:
            value = _read_ledger_row(item)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            invalid += 1
            continue
        if isinstance(value, dict):
            output.append((item, value))
        else:
            invalid += 1
    return output, bounded, invalid


def _meter_bytes(path: Path) -> tuple[bytes | None, bool, int]:
    try:
        if path.stat().st_size > _METER_LEDGER_MAX_BYTES:
            return None, True, 1
        return path.read_bytes(), False, 0
    except OSError:
        return None, False, 1


def _cached_meter_rows(raw: bytes) -> tuple[list[dict[str, Any]], int]:
    digest = "jsonl:" + sha256(raw).hexdigest()
    cached_rows = None
    if len(raw) <= _PARSED_JSON_CACHE_MAX_BYTES:
        with _PARSED_JSON_CACHE_LOCK:
            cached = _PARSED_JSON_CACHE.get(digest)
            if cached is not None:
                cached_rows = cached.get("rows")
                _PARSED_JSON_CACHE.move_to_end(digest)
    if not isinstance(cached_rows, list):
        parsed_rows, invalid = _parse_meter_lines(raw)
        cached_rows = parsed_rows
        if len(raw) <= _PARSED_JSON_CACHE_MAX_BYTES:
            _cache_meter_value(digest, cached_rows, invalid)
    else:
        invalid = int(cached.get("invalid_count", 0))
    return cached_rows, invalid


def _parse_meter_lines(raw: bytes) -> tuple[list[dict[str, Any]], int]:
    parsed_rows, invalid = [], 0
    for line_no, line in enumerate(
        raw.decode("utf-8", errors="replace").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if isinstance(value, dict):
            parsed_rows.append({"line": line_no, "value": value})
        else:
            invalid += 1
    return parsed_rows, invalid


def _cache_meter_value(digest: str, rows: list[dict[str, Any]], invalid: int) -> None:
    with _PARSED_JSON_CACHE_LOCK:
        _PARSED_JSON_CACHE[digest] = {"rows": rows, "invalid_count": invalid}
        _PARSED_JSON_CACHE.move_to_end(digest)
        while len(_PARSED_JSON_CACHE) > _PARSED_JSON_CACHE_SIZE:
            _PARSED_JSON_CACHE.popitem(last=False)


def _meter_rows_from_cache(
    rows: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    output: list[tuple[str, dict[str, Any]]] = []
    for row in rows:
        if (
            isinstance(row, dict)
            and isinstance(row.get("line"), int)
            and isinstance(row.get("value"), dict)
        ):
            output.append((f"meter:{row['line']}", row["value"]))
    return output


def _meter_rows(root: Path) -> tuple[list[tuple[str, dict[str, Any]]], bool, int]:
    path = root / ".factory" / "meter.jsonl"
    if not path.exists():
        return [], False, 0
    raw, bounded, invalid = _meter_bytes(path)
    if raw is None:
        return [], bounded, invalid
    cached_rows, parsed_invalid = _cached_meter_rows(raw)
    if parsed_invalid:
        invalid = parsed_invalid
    output = _meter_rows_from_cache(cached_rows)
    return output, False, invalid


def _add_observation(
    source: str,
    source_id: str,
    value: dict[str, Any],
    observations: list[dict[str, Any]],
    run_payloads: dict[str, list[str]],
    source_counts: Counter[str],
    status_counts: Counter[str],
) -> None:
    digest = _digest(value)
    run_id = value.get("run_id") if isinstance(value.get("run_id"), str) else None
    status = value.get("status", value.get("terminal", "unknown"))
    observations.append(
        {
            "source": source,
            "source_id": source_id,
            "run_id": run_id,
            "digest": digest,
            "status": status,
        }
    )
    source_counts[source] += 1
    status_counts[str(status)] += 1
    if run_id and source in {"runs", "traces"}:
        run_payloads.setdefault(run_id, []).append(digest)


def _consume_ledger(
    root: Path,
    directory: str,
    source: str,
    invalid_key: str,
    observations: list[dict[str, Any]],
    run_payloads: dict[str, list[str]],
    source_counts: Counter[str],
    status_counts: Counter[str],
    bounded_sources: list[str],
    invalid_records: dict[str, int],
    *,
    schema: str | None = None,
) -> None:
    rows, bounded, invalid = _rows(root / directory)
    if invalid:
        invalid_records[invalid_key] = invalid
    if bounded:
        bounded_sources.append(invalid_key)
    for path, value in rows:
        if schema is None or value.get("schema") == schema:
            _add_observation(
                source,
                path.name,
                value,
                observations,
                run_payloads,
                source_counts,
                status_counts,
            )


def _consume_meter(
    root: Path,
    observations: list[dict[str, Any]],
    run_payloads: dict[str, list[str]],
    source_counts: Counter[str],
    status_counts: Counter[str],
    unknown_fields: Counter[str],
    bounded_sources: list[str],
    invalid_records: dict[str, int],
) -> None:
    rows, bounded, invalid = _meter_rows(root)
    if bounded:
        bounded_sources.append("meter")
    if invalid:
        invalid_records["meter"] = invalid
    for source_id, value in rows:
        _add_observation(
            "meter",
            source_id,
            value,
            observations,
            run_payloads,
            source_counts,
            status_counts,
        )
        for field in ("tokens_in", "tokens_out", "cost_usd", "queue_ms", "cache_hits"):
            if value.get(field) is None:
                unknown_fields[field] += 1


def _collect_telemetry(root: Path) -> dict[str, Any]:
    observations, run_payloads = [], {}
    source_counts, status_counts, unknown_fields = Counter(), Counter(), Counter()
    bounded_sources, invalid_records = [], {}
    ledgers = (
        ("receipts", "receipts", "receipts", None),
        (".factory/runs", "runs", "runs", RUN_SCHEMA),
        (".factory/traces", "traces", "factory_traces", None),
        ("traces", "traces", "root_traces", None),
    )
    for directory, source, invalid_key, schema in ledgers:
        _consume_ledger(
            root,
            directory,
            source,
            invalid_key,
            observations,
            run_payloads,
            source_counts,
            status_counts,
            bounded_sources,
            invalid_records,
            schema=schema,
        )
    _consume_meter(
        root,
        observations,
        run_payloads,
        source_counts,
        status_counts,
        unknown_fields,
        bounded_sources,
        invalid_records,
    )
    return {
        "observations": observations,
        "run_payloads": run_payloads,
        "source_counts": source_counts,
        "status_counts": status_counts,
        "unknown_fields": unknown_fields,
        "bounded_sources": bounded_sources,
        "invalid_records": invalid_records,
    }


def _run_reconciliation(
    run_payloads: dict[str, list[str]],
) -> tuple[list[str], list[str], int]:
    conflicts = sorted(
        run_id for run_id, digests in run_payloads.items() if len(set(digests)) > 1
    )
    run_ids = sorted(run_payloads)
    exact = sum(1 for run_id in run_ids if len(set(run_payloads[run_id])) == 1)
    return conflicts, run_ids, exact


def _inventory_quality(conflicts: list[str], observations: list[dict[str, Any]]) -> str:
    if conflicts:
        return "conflicted"
    return "exact" if observations else "unknown"


def telemetry_inventory(root: Path) -> dict[str, Any]:
    """Read bounded local telemetry ledgers and produce a reconciled inventory."""
    root = Path(root).resolve()
    collected = _collect_telemetry(root)
    conflicts, run_ids, exact_runs = _run_reconciliation(collected["run_payloads"])
    observations = collected["observations"]
    bounded_sources = collected["bounded_sources"]
    invalid_records = collected["invalid_records"]
    return {
        "schema": TELEMETRY_SCHEMA,
        "markers": [
            "TELEMETRY_INVENTORY_RECONCILED",
            "TELEMETRY_PUBLIC_AGGREGATE_SAFE",
        ],
        "root_bound": True,
        "coverage": {
            "status": "partial"
            if bounded_sources or invalid_records
            else "complete_within_scanned_sources",
            "bounded_sources": sorted(bounded_sources),
            "per_source_file_limit": _LEDGER_FILE_LIMIT,
            "claim_boundary": "Complete only within the scanned source set and configured per-source file bound.",
        },
        "invalid_records": dict(sorted(invalid_records.items())),
        "sources": dict(sorted(collected["source_counts"].items())),
        "observations": len(observations),
        "runs": {
            "distinct": len(run_ids),
            "exact": exact_runs,
            "conflicted": len(conflicts),
        },
        "statuses": dict(sorted(collected["status_counts"].items())),
        "unknown_fields": dict(sorted(collected["unknown_fields"].items())),
        "conflicts": conflicts,
        "quality": _inventory_quality(conflicts, observations),
    }


def public_inventory_summary(root: Path) -> dict[str, Any]:
    """Return only aggregate counts suitable for public metrics surfaces."""
    inventory = telemetry_inventory(root)
    return {
        "schema": TELEMETRY_SCHEMA,
        "quality": inventory["quality"],
        "observations": inventory["observations"],
        "runs": inventory["runs"],
        "sources": inventory["sources"],
        "conflicts": len(inventory["conflicts"]),
        "unknown_fields": inventory["unknown_fields"],
        "invalid_records": inventory["invalid_records"],
        "markers": ["TELEMETRY_PUBLIC_AGGREGATE_SAFE"],
        "coverage": inventory["coverage"],
    }
