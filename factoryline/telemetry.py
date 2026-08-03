"""Reconcile local FactoryLine telemetry into a privacy-safe inventory.

Telemetry is intentionally an inventory, not an outcome claim.  It joins the
receipt, run, trace, and meter ledgers by stable run ids, preserves unknowns,
and marks conflicting observations instead of silently choosing one.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable

from .run_metrics import RUN_SCHEMA, load_run_receipts


TELEMETRY_SCHEMA = "factory.telemetry-inventory.v1"


def _digest(payload: Any) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256(data).hexdigest()


def _rows(path: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    if not path.exists():
        return
    for item in sorted(path.rglob("*.json")):
        try:
            value = json.loads(item.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            yield item, value


def _meter_rows(root: Path) -> Iterable[tuple[str, dict[str, Any]]]:
    path = root / ".factory" / "meter.jsonl"
    if not path.exists():
        return
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            yield f"meter:{line_no}", value


def telemetry_inventory(root: Path) -> dict[str, Any]:
    """Read every local telemetry ledger and produce a reconciled inventory."""
    root = Path(root).resolve()
    observations: list[dict[str, Any]] = []
    run_payloads: dict[str, list[str]] = {}
    source_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    unknown_fields: Counter[str] = Counter()

    def add(source: str, source_id: str, value: dict[str, Any]) -> None:
        digest = _digest(value)
        run_id = value.get("run_id") if isinstance(value.get("run_id"), str) else None
        observations.append({"source": source, "source_id": source_id, "run_id": run_id,
                             "digest": digest, "status": value.get("status", value.get("terminal", "unknown"))})
        source_counts[source] += 1
        status_counts[str(value.get("status", value.get("terminal", "unknown")))] += 1
        # A run receipt is the identity-bearing ledger.  Stage receipts and
        # meter rows legitimately share its run_id but are not competing run
        # payloads, so they must not manufacture a false conflict.
        if run_id and source in {"runs", "traces"}:
            run_payloads.setdefault(run_id, []).append(digest)

    for path, value in _rows(root / "receipts"):
        add("receipts", path.name, value)
    for path, value in _rows(root / ".factory" / "runs"):
        if value.get("schema") == RUN_SCHEMA:
            add("runs", path.name, value)
    for path, value in _rows(root / ".factory" / "traces"):
        add("traces", path.name, value)
    for path, value in _rows(root / "traces"):
        add("traces", path.name, value)
    for source_id, value in _meter_rows(root):
        add("meter", source_id, value)
        for field in ("tokens_in", "tokens_out", "cost_usd", "queue_ms", "cache_hits"):
            if value.get(field) is None:
                unknown_fields[field] += 1

    conflicts = sorted(run_id for run_id, digests in run_payloads.items() if len(set(digests)) > 1)
    run_ids = sorted(run_payloads)
    exact_runs = sum(1 for run_id in run_ids if len(set(run_payloads[run_id])) == 1)
    return {
        "schema": TELEMETRY_SCHEMA,
        "markers": ["TELEMETRY_INVENTORY_RECONCILED", "TELEMETRY_PUBLIC_AGGREGATE_SAFE"],
        "root_bound": True,
        "sources": dict(sorted(source_counts.items())),
        "observations": len(observations),
        "runs": {"distinct": len(run_ids), "exact": exact_runs, "conflicted": len(conflicts)},
        "statuses": dict(sorted(status_counts.items())),
        "unknown_fields": dict(sorted(unknown_fields.items())),
        "conflicts": conflicts,
        "quality": "conflicted" if conflicts else "exact" if observations else "unknown",
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
        "markers": ["TELEMETRY_PUBLIC_AGGREGATE_SAFE"],
    }
