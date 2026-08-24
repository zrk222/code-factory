"""Exact paired savings receipts and publication-safe aggregates."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .run_metrics import _atomic_json


PAIR_SCHEMA = "factory.savings-pair.v1"
PUBLIC_SCHEMA = "factory.savings-report.public.v1"
PAIR_ID = re.compile(r"^[a-z\d][a-z\d._-]*$")
MAX_PAIR_ID_LENGTH = 80
MAX_PAIRS = 10_000


class SavingsError(ValueError):
    """A typed invalid or conflicting savings observation."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _observation(value: dict[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SavingsError("OBSERVATION_INVALID", f"{label} must be an object")
    elapsed = value.get("elapsed_ms")
    if not isinstance(elapsed, int) or isinstance(elapsed, bool) or elapsed <= 0:
        raise SavingsError("ELAPSED_INVALID", f"{label}.elapsed_ms must be a positive integer")
    result: dict[str, Any] = {"elapsed_ms": elapsed}
    tokens = value.get("tokens")
    if tokens is not None and (not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0):
        raise SavingsError("TOKENS_INVALID", f"{label}.tokens must be a non-negative integer or null")
    result["tokens"] = tokens
    cost = value.get("cost_usd")
    if cost is not None and (
        not isinstance(cost, (int, float)) or isinstance(cost, bool) or cost < 0
    ):
        raise SavingsError("COST_INVALID", f"{label}.cost_usd must be non-negative or null")
    result["cost_usd"] = float(cost) if cost is not None else None
    return result


def _exact(value: Any) -> Any:
    """Lift a float to Decimal through str so 0.1 is exactly 0.1.

    Binary floats cannot represent most decimal cash amounts, so 0.10 - 0.04
    yields 0.060000000000000005. A savings receipt is a public auditable
    artifact; that artifact must not contain arithmetic noise it cannot defend.
    Ints are already exact and pass through untouched.
    """
    return Decimal(str(value)) if isinstance(value, float) else value


def _plain(value: Any) -> Any:
    """Return a JSON-native number. Decimals become floats, preserving type."""
    return float(value) if isinstance(value, Decimal) else value


def _ratio(numerator: Any, denominator: Any) -> float | None:
    """Divide exactly when possible. Returns None on a non-positive divisor."""
    if denominator is None or denominator <= 0:
        return None
    return float(_exact(numerator) / _exact(denominator))


def _delta(baseline: dict[str, Any], factory: dict[str, Any], key: str) -> tuple[Any, Any]:
    before, after = baseline.get(key), factory.get(key)
    if before is None or after is None:
        return None, None
    saved = _exact(before) - _exact(after)
    return _plain(saved), _ratio(saved, before)


def _savings_dir(root: Path, *, create: bool = True) -> Path:
    directory = Path(root).resolve() / ".factory" / "savings"
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


def _evidence_digest(equivalent_outcome: bool, evidence: Path | None) -> str | None:
    if not equivalent_outcome:
        return None
    if evidence is None or not Path(evidence).is_file():
        raise SavingsError("EQUIVALENCE_EVIDENCE_REQUIRED", "an existing evidence file is required")
    return hashlib.sha256(Path(evidence).read_bytes()).hexdigest()


def _pair_markers(
    evidence_digest: str | None,
    values: tuple[Any, ...],
    has_unknown: bool,
) -> list[str]:
    markers = [
        "SAVINGS_RECORD_COMMAND", "PAIR_ID_VALIDATED", "SIGNED_DELTA_COMPUTED",
        "TIME_SAVINGS_RATE_EXACT", "SAVINGS_PAIR_RECEIPTED",
    ]
    markers.append("EQUIVALENCE_EVIDENCE_HASHED" if evidence_digest else "PRODUCTIVITY_GAIN_WITHHELD")
    if evidence_digest:
        markers.append("PRODUCTIVITY_GAIN_EXACT")
    if has_unknown:
        markers.append("UNKNOWN_PAIR_FIELD_PRESERVED")
    if any(value is not None and value < 0 for value in values):
        markers.append("SAVINGS_NEGATIVE_VISIBLE")
    return markers


def record_savings_pair(
    root: Path,
    pair_id: str,
    baseline: dict[str, Any],
    factory: dict[str, Any],
    *,
    equivalent_outcome: bool = False,
    evidence: Path | None = None,
    replace: bool = False,
) -> dict[str, Any]:
    """Atomically record one exact baseline-versus-Factory observation."""
    if (
        not isinstance(pair_id, str)
        or len(pair_id) > MAX_PAIR_ID_LENGTH
        or not PAIR_ID.fullmatch(pair_id)
    ):
        raise SavingsError("PAIR_ID_INVALID", "pair id must match [a-z0-9][a-z0-9._-]{0,79}")
    before, after = _observation(baseline, "baseline"), _observation(factory, "factory")
    destination = _savings_dir(root) / f"{pair_id}.json"
    if destination.exists() and not replace:
        raise SavingsError("PAIR_OVERWRITE_REFUSED", "pair already exists; pass --replace explicitly")
    evidence_digest = _evidence_digest(equivalent_outcome, evidence)
    time_saved, time_rate = _delta(before, after, "elapsed_ms")
    tokens_saved, token_rate = _delta(before, after, "tokens")
    cost_saved, cost_rate = _delta(before, after, "cost_usd")
    productivity = (
        float(_exact(before["elapsed_ms"]) / _exact(after["elapsed_ms"]) - 1)
        if evidence_digest
        else None
    )
    markers = _pair_markers(
        evidence_digest,
        (time_saved, tokens_saved, cost_saved, productivity),
        tokens_saved is None or cost_saved is None,
    )
    receipt = {
        "schema": PAIR_SCHEMA,
        "marker": "SAVINGS_PAIR_RECEIPTED",
        "markers": markers,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "pair_id": pair_id,
        "baseline": before,
        "factory": after,
        "equivalence": {
            "asserted": bool(evidence_digest),
            "evidence_sha256": evidence_digest,
        },
        "savings": {
            "time_saved_ms": time_saved,
            "time_savings_rate": time_rate,
            "tokens_saved": tokens_saved,
            "token_savings_rate": token_rate,
            "cost_saved_usd": cost_saved,
            "cost_savings_rate": cost_rate,
            "productivity_gain_rate": productivity,
            "productivity_reason": None if productivity is not None else "Equivalent-outcome evidence is required.",
        },
    }
    _atomic_json(destination, receipt)
    receipt["receipt"] = str(destination)
    return receipt


def load_savings_pairs(root: Path) -> list[dict[str, Any]]:
    """Load at most 10000 valid pair receipts."""
    rows: list[dict[str, Any]] = []
    for path in sorted(_savings_dir(root, create=False).glob("*.json"))[:MAX_PAIRS]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == PAIR_SCHEMA:
            rows.append(value)
    return rows


def _metric(rows: list[dict[str, Any]], key: str, saved_key: str) -> dict[str, Any]:
    exact = [row for row in rows if row["baseline"].get(key) is not None and row["factory"].get(key) is not None]
    before = _plain(sum((_exact(row["baseline"][key]) for row in exact), start=_exact(0)))
    after = _plain(sum((_exact(row["factory"][key]) for row in exact), start=_exact(0)))
    saved = _plain(sum((_exact(row["savings"][saved_key]) for row in exact), start=_exact(0)))
    return {
        "exact_pairs": len(exact),
        "coverage_rate": len(exact) / len(rows) if rows else None,
        "baseline_total": before if exact else None,
        "factory_total": after if exact else None,
        "saved_total": saved if exact else None,
        "weighted_savings_rate": _ratio(saved, before) if exact else None,
    }


def public_savings_report(root: Path) -> dict[str, Any]:
    """Aggregate exact pairs without private identifiers, paths, or evidence digests."""
    rows = load_savings_pairs(root)
    equivalent = [row for row in rows if row["equivalence"]["asserted"]]
    before = sum(row["baseline"]["elapsed_ms"] for row in equivalent)
    after = sum(row["factory"]["elapsed_ms"] for row in equivalent)
    productivity = (
        float(_exact(before) / _exact(after) - 1) if equivalent and after > 0 else None
    )
    report = {
        "schema": PUBLIC_SCHEMA,
        "marker": "SAVINGS_REPORT_AGGREGATE_SAFE",
        "markers": ["SAVINGS_REPORT_AGGREGATE_SAFE", "SAVINGS_BACKWARD_COMPATIBLE"],
        "pairs": len(rows),
        "time": _metric(rows, "elapsed_ms", "time_saved_ms"),
        "tokens": _metric(rows, "tokens", "tokens_saved"),
        "cost_usd": _metric(rows, "cost_usd", "cost_saved_usd"),
        "productivity": {
            "exact_pairs": len(equivalent),
            "coverage_rate": len(equivalent) / len(rows) if rows else None,
            "gain_rate": productivity,
            "reason": None if productivity is not None else "Equivalent-outcome evidence is required.",
        },
    }
    if any(
        metric.get("saved_total") is not None and metric["saved_total"] < 0
        for metric in (report["time"], report["tokens"], report["cost_usd"])
    ) or (productivity is not None and productivity < 0):
        report["markers"].append("SAVINGS_NEGATIVE_VISIBLE")
    return report


def export_public_savings_report(root: Path, output: Path) -> Path:
    """Atomically write a publication-safe paired savings report."""
    destination = Path(output).resolve()
    _atomic_json(destination, public_savings_report(root))
    return destination
