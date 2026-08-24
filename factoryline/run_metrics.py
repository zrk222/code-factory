"""Privacy-safe run receipts and aggregates for Assembly continuation."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any


RUN_SCHEMA = "factory.assembly-run.v1"
PUBLIC_SCHEMA = "factory.assembly-metrics.public.v1"


def _runs_dir(root: Path, *, create: bool = True) -> Path:
    path = Path(root).resolve() / ".factory" / "runs"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
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


def load_run_receipts(root: Path) -> list[dict[str, Any]]:
    """Load valid Assembly run receipts while ignoring corrupt or unrelated files."""
    rows = []
    for path in sorted(_runs_dir(root, create=False).glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == RUN_SCHEMA:
            rows.append(value)
    return rows


def retry_count(root: Path, feature: str) -> int:
    """Count prior valid continuation receipts for one exact internal feature name."""
    return sum(row.get("feature") == feature for row in load_run_receipts(root))


def write_run_receipt(root: Path, payload: dict[str, Any]) -> Path:
    """Validate and atomically persist one private continuation run receipt."""
    usage = payload.get("usage")
    if usage is None:
        usage = {
            "quality": "unknown",
            "model_calls": None,
            "tokens_in": None,
            "tokens_out": None,
            "cost_usd": None,
        }
    elif not isinstance(usage, dict) or usage.get("quality") != "exact":
        raise ValueError("usage must be absent or an exact usage object")
    else:
        for key in ("model_calls", "tokens_in", "tokens_out"):
            value = usage.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"usage.{key} must be a non-negative integer")
        cost = usage.get("cost_usd")
        if cost is not None and (not isinstance(cost, (int, float)) or isinstance(cost, bool) or cost < 0):
            raise ValueError("usage.cost_usd must be a non-negative number or null")
    receipt = {
        "schema": RUN_SCHEMA,
        "marker": "ASSEMBLY_RUN_RECEIPTED",
        "created_at": datetime.now(timezone.utc).isoformat(),
        **payload,
        "usage": usage,
    }
    run_id = receipt.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id is required")
    path = _runs_dir(root) / f"{run_id}.json"
    _atomic_json(path, receipt)
    return path


def public_metrics(root: Path) -> dict[str, Any]:
    """Aggregate receipts without exposing features, paths, prompts, or logs."""
    rows = load_run_receipts(root)
    terminals = Counter(str(row.get("terminal", "unknown")) for row in rows)
    exact = [row["usage"] for row in rows if isinstance(row.get("usage"), dict) and row["usage"].get("quality") == "exact"]
    all_exact = bool(rows) and len(exact) == len(rows)
    completed = terminals.get("completed", 0)
    from .telemetry import public_inventory_summary

    return {
        "schema": PUBLIC_SCHEMA,
        "marker": "PUBLIC_METRICS_AGGREGATE_SAFE",
        "runs": len(rows),
        "terminals": dict(sorted(terminals.items())),
        "completion_rate": completed / len(rows) if rows else None,
        "totals": {
            "elapsed_ms": sum(int(row.get("elapsed_ms", 0)) for row in rows),
            "commands": sum(int(row.get("command_count", 0)) for row in rows),
            "retries": sum(int(row.get("retry_count", 0)) for row in rows),
            "result_bytes": sum(int(row.get("result_bytes", 0)) for row in rows),
        },
        "usage": {
            "quality": "exact" if all_exact else "unknown",
            "observed_runs": len(exact),
            "model_calls": sum(item["model_calls"] for item in exact) if all_exact else None,
            "tokens_in": sum(item["tokens_in"] for item in exact) if all_exact else None,
            "tokens_out": sum(item["tokens_out"] for item in exact) if all_exact else None,
            "cost_usd": (
                sum(float(item["cost_usd"]) for item in exact if item.get("cost_usd") is not None)
                if all_exact and all(item.get("cost_usd") is not None for item in exact)
                else None
            ),
        },
        "savings": {
            "quality": "unknown",
            "time_saved_ms": None,
            "tokens_saved": None,
            "reason": "A measured counterfactual baseline is required before savings can be claimed.",
        },
        "telemetry_reconciliation": public_inventory_summary(root),
    }


def export_public_metrics(root: Path, output: Path) -> Path:
    """Atomically write a privacy-safe aggregate suitable for public sample data."""
    destination = Path(output).resolve()
    _atomic_json(destination, public_metrics(root))
    return destination
