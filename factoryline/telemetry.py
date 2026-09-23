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


def _rows(path: Path) -> tuple[list[tuple[Path, dict[str, Any]]], bool, int]:
    if not path.exists():
        return [], False, 0
    ledger = Path(path).resolve()
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
    output: list[tuple[Path, dict[str, Any]]] = []
    invalid = 0
    for item in candidates:
        try:
            if item.stat().st_size > _TELEMETRY_JSON_MAX_BYTES:
                invalid += 1
                continue
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
                    with _PARSED_JSON_CACHE_LOCK:
                        _PARSED_JSON_CACHE[digest] = value
                        _PARSED_JSON_CACHE.move_to_end(digest)
                        while len(_PARSED_JSON_CACHE) > _PARSED_JSON_CACHE_SIZE:
                            _PARSED_JSON_CACHE.popitem(last=False)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            invalid += 1
            continue
        if isinstance(value, dict):
            output.append((item, value))
        else:
            invalid += 1
    return output, bounded, invalid


def _meter_rows(root: Path) -> tuple[list[tuple[str, dict[str, Any]]], bool, int]:
    path = root / ".factory" / "meter.jsonl"
    if not path.exists():
        return [], False, 0
    try:
        if path.stat().st_size > _METER_LEDGER_MAX_BYTES:
            return [], True, 1
        raw = path.read_bytes()
    except OSError:
        return [], False, 1
    digest = "jsonl:" + sha256(raw).hexdigest()
    cached_rows = None
    if len(raw) <= _PARSED_JSON_CACHE_MAX_BYTES:
        with _PARSED_JSON_CACHE_LOCK:
            cached = _PARSED_JSON_CACHE.get(digest)
            if cached is not None:
                cached_rows = cached.get("rows")
                _PARSED_JSON_CACHE.move_to_end(digest)
    if not isinstance(cached_rows, list):
        parsed_rows: list[dict[str, Any]] = []
        invalid = 0
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
        cached_rows = parsed_rows
        if len(raw) <= _PARSED_JSON_CACHE_MAX_BYTES:
            with _PARSED_JSON_CACHE_LOCK:
                _PARSED_JSON_CACHE[digest] = {
                    "rows": cached_rows,
                    "invalid_count": invalid,
                }
                _PARSED_JSON_CACHE.move_to_end(digest)
                while len(_PARSED_JSON_CACHE) > _PARSED_JSON_CACHE_SIZE:
                    _PARSED_JSON_CACHE.popitem(last=False)
    else:
        invalid = int(cached.get("invalid_count", 0))
    output: list[tuple[str, dict[str, Any]]] = []
    for row in cached_rows:
        if (
            isinstance(row, dict)
            and isinstance(row.get("line"), int)
            and isinstance(row.get("value"), dict)
        ):
            output.append((f"meter:{row['line']}", row["value"]))
    return output, False, invalid


def telemetry_inventory(root: Path) -> dict[str, Any]:
    """Read bounded local telemetry ledgers and produce a reconciled inventory."""
    root = Path(root).resolve()
    observations: list[dict[str, Any]] = []
    run_payloads: dict[str, list[str]] = {}
    source_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    unknown_fields: Counter[str] = Counter()
    bounded_sources: list[str] = []
    invalid_records: dict[str, int] = {}

    def add(source: str, source_id: str, value: dict[str, Any]) -> None:
        digest = _digest(value)
        run_id = value.get("run_id") if isinstance(value.get("run_id"), str) else None
        observations.append(
            {
                "source": source,
                "source_id": source_id,
                "run_id": run_id,
                "digest": digest,
                "status": value.get("status", value.get("terminal", "unknown")),
            }
        )
        source_counts[source] += 1
        status_counts[str(value.get("status", value.get("terminal", "unknown")))] += 1
        # A run receipt is the identity-bearing ledger.  Stage receipts and
        # meter rows legitimately share its run_id but are not competing run
        # payloads, so they must not manufacture a false conflict.
        if run_id and source in {"runs", "traces"}:
            run_payloads.setdefault(run_id, []).append(digest)

    receipt_rows, receipt_bounded, receipt_invalid = _rows(root / "receipts")
    if receipt_invalid:
        invalid_records["receipts"] = receipt_invalid
    if receipt_bounded:
        bounded_sources.append("receipts")
    for path, value in receipt_rows:
        add("receipts", path.name, value)
    run_rows, runs_bounded, runs_invalid = _rows(root / ".factory" / "runs")
    if runs_invalid:
        invalid_records["runs"] = runs_invalid
    if runs_bounded:
        bounded_sources.append("runs")
    for path, value in run_rows:
        if value.get("schema") == RUN_SCHEMA:
            add("runs", path.name, value)
    factory_trace_rows, factory_traces_bounded, factory_traces_invalid = _rows(
        root / ".factory" / "traces"
    )
    if factory_traces_invalid:
        invalid_records["factory_traces"] = factory_traces_invalid
    if factory_traces_bounded:
        bounded_sources.append("factory_traces")
    for path, value in factory_trace_rows:
        add("traces", path.name, value)
    root_trace_rows, root_traces_bounded, root_traces_invalid = _rows(root / "traces")
    if root_traces_invalid:
        invalid_records["root_traces"] = root_traces_invalid
    if root_traces_bounded:
        bounded_sources.append("root_traces")
    for path, value in root_trace_rows:
        add("traces", path.name, value)
    meter_rows, meter_bounded, meter_invalid = _meter_rows(root)
    if meter_bounded:
        bounded_sources.append("meter")
    if meter_invalid:
        invalid_records["meter"] = meter_invalid
    for source_id, value in meter_rows:
        add("meter", source_id, value)
        for field in ("tokens_in", "tokens_out", "cost_usd", "queue_ms", "cache_hits"):
            if value.get(field) is None:
                unknown_fields[field] += 1

    conflicts = sorted(
        run_id for run_id, digests in run_payloads.items() if len(set(digests)) > 1
    )
    run_ids = sorted(run_payloads)
    exact_runs = sum(1 for run_id in run_ids if len(set(run_payloads[run_id])) == 1)
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
        "sources": dict(sorted(source_counts.items())),
        "observations": len(observations),
        "runs": {
            "distinct": len(run_ids),
            "exact": exact_runs,
            "conflicted": len(conflicts),
        },
        "statuses": dict(sorted(status_counts.items())),
        "unknown_fields": dict(sorted(unknown_fields.items())),
        "conflicts": conflicts,
        "quality": "conflicted"
        if conflicts
        else "exact"
        if observations
        else "unknown",
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
