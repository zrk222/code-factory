"""Manifest-bound real-defect benchmark evaluation for senior review.

This adapter evaluates results from an external test engine. It never claims to
have generated a defect corpus or executed the replay commands itself.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .runtime_audit_common import canonical_bytes, exact_keys, reject_secret_material, require_digest


SCHEMA = "factory.defect-benchmark.v1"
CATEGORIES = ("stateful_invariant", "tenant_isolation", "failure_recovery", "consumer_compatibility", "migration_integrity", "performance_regression")
CLEAN_FINDING = "NO_FINDING"


class BenchmarkError(ValueError):
    """Stable, fail-closed benchmark contract/result error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _nonempty(value: object, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise BenchmarkError("E_BENCHMARK_FIELD", f"{field} must be a bounded printable string")
    return value.strip()


def _validate_source(source: object) -> str:
    value = _nonempty(source, "case.source", 512)
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        raise BenchmarkError("E_BENCHMARK_SOURCE", "source must be a reviewed local identifier, not a URL")
    return value


def _argv(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise BenchmarkError("E_BENCHMARK_REPLAY", f"{field} must contain 1..32 arguments")
    result = []
    for index, item in enumerate(value):
        result.append(_nonempty(item, f"{field}[{index}]", 256))
    return result


def _validate_case(case: object, index: int, seen: set[str]) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise BenchmarkError("E_BENCHMARK_CONTRACT", f"case {index} must be an object")
    try:
        exact_keys(case, {"id", "category", "source", "source_sha256", "expected_finding", "replay_argv", "buggy_sha256", "fixed_sha256"})
    except Exception as exc:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", f"case {index}: {exc}") from exc
    case_id = _nonempty(case.get("id"), f"case[{index}].id", 160)
    if case_id in seen:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", f"duplicate case id: {case_id}")
    seen.add(case_id)
    category = case.get("category")
    if category not in CATEGORIES:
        raise BenchmarkError("E_BENCHMARK_CATEGORY", f"unsupported category for {case_id}")
    return {"id": case_id, "category": category, "source": _validate_source(case.get("source")), "source_sha256": require_digest(case.get("source_sha256"), f"case[{index}].source_sha256"), "expected_finding": _nonempty(case.get("expected_finding"), f"case[{index}].expected_finding", 512), "replay_argv": _argv(case.get("replay_argv"), f"case[{index}].replay_argv"), "buggy_sha256": require_digest(case.get("buggy_sha256"), f"case[{index}].buggy_sha256"), "fixed_sha256": require_digest(case.get("fixed_sha256"), f"case[{index}].fixed_sha256")}


def validate_benchmark_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Validate a complete immutable benchmark manifest and normalize strings."""
    if not isinstance(value, dict):
        raise BenchmarkError("E_BENCHMARK_CONTRACT", "manifest must be an object")
    reject_secret_material(value, path="benchmark")
    try:
        exact_keys(value, {"schema", "benchmark_id", "version", "cases"})
    except Exception as exc:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", str(exc)) from exc
    if value.get("schema") != SCHEMA:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", f"schema must be {SCHEMA}")
    cases = value.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 500:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", "cases must contain 1..500 entries")
    seen: set[str] = set()
    return {"schema": SCHEMA, "benchmark_id": _nonempty(value.get("benchmark_id"), "benchmark_id", 160), "version": _nonempty(value.get("version"), "version", 40), "cases": [_validate_case(case, index, seen) for index, case in enumerate(cases)]}


def _observation(value: object, case_id: str, side: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError("E_BENCHMARK_RESULT", f"{case_id}.{side} must be an object")
    try:
        exact_keys(value, {"state", "finding"})
    except Exception as exc:
        raise BenchmarkError("E_BENCHMARK_RESULT", f"{case_id}.{side}: {exc}") from exc
    state = value.get("state")
    if state not in {"PASS", "FAIL"}:
        raise BenchmarkError("E_BENCHMARK_RESULT", f"{case_id}.{side}.state must be PASS or FAIL")
    finding = value.get("finding")
    if not isinstance(finding, str) or len(finding) > 512 or any(ord(c) < 32 for c in finding):
        raise BenchmarkError("E_BENCHMARK_RESULT", f"{case_id}.{side}.finding must be a bounded printable string")
    return {"state": state, "finding": finding.strip()}


def _evaluate_case(case: dict[str, Any], pair: object, totals: dict[str, dict[str, int]]) -> dict[str, Any]:
    if not isinstance(pair, dict):
        raise BenchmarkError("E_BENCHMARK_RESULT", f"{case['id']} observation must be an object")
    try:
        exact_keys(pair, {"buggy", "fixed"})
    except Exception as exc:
        raise BenchmarkError("E_BENCHMARK_RESULT", f"{case['id']}: {exc}") from exc
    buggy = _observation(pair["buggy"], case["id"], "buggy")
    fixed = _observation(pair["fixed"], case["id"], "fixed")
    clean = case["expected_finding"] == CLEAN_FINDING
    buggy_correct = buggy["state"] == "PASS" and buggy["finding"] in {"", CLEAN_FINDING} if clean else buggy["state"] == "FAIL" and buggy["finding"] == case["expected_finding"]
    fixed_correct = fixed["state"] == "PASS" and fixed["finding"] in {"", CLEAN_FINDING}
    correct = buggy_correct and fixed_correct
    metric = totals[case["category"]]
    metric.update(cases=metric["cases"] + 1, correct_cases=metric["correct_cases"] + int(correct))
    key = "tn" if clean else "tp"
    metric[key] += int(buggy_correct)
    metric["fp" if clean else "fn"] += int(not buggy_correct)
    return {"id": case["id"], "category": case["category"], "expected_finding": case["expected_finding"], "buggy": buggy, "fixed": fixed, "buggy_correct": buggy_correct, "fixed_correct": fixed_correct, "correct": correct, "replay_argv": case["replay_argv"]}


def _metrics(totals: dict[str, dict[str, int]]) -> dict[str, Any]:
    result = {}
    for category, metric in totals.items():
        recall_den = metric["tp"] + metric["fn"]
        precision_den = metric["tp"] + metric["fp"]
        result[category] = {**metric, "recall": metric["tp"] / recall_den if recall_den else None, "precision": metric["tp"] / precision_den if precision_den else None}
    return result


def evaluate_benchmark(manifest: dict[str, Any], observations: dict[str, Any], *, out: Path | None = None) -> dict[str, Any]:
    """Evaluate externally collected buggy/fixed observations with exact metrics."""
    contract = validate_benchmark_manifest(manifest)
    if not isinstance(observations, dict):
        raise BenchmarkError("E_BENCHMARK_RESULT", "observations must be an object keyed by case id")
    expected_ids = {case["id"] for case in contract["cases"]}
    if set(observations) != expected_ids:
        missing = sorted(expected_ids - set(observations))
        extra = sorted(set(observations) - expected_ids)
        raise BenchmarkError("E_BENCHMARK_RESULT", f"case observations differ; missing={missing}, extra={extra}")
    rows = []
    totals = {category: {"cases": 0, "correct_cases": 0, "tp": 0, "fn": 0, "tn": 0, "fp": 0} for category in CATEGORIES}
    rows = [_evaluate_case(case, observations[case["id"]], totals) for case in contract["cases"]]
    metrics = _metrics(totals)
    core = {"schema": "factory.defect-benchmark-receipt.v1", "marker": "DEFECT_BENCHMARK_BOUND", "benchmark": contract, "cases": rows, "metrics": metrics, "decision": "PASS" if all(row["correct"] for row in rows) else "BLOCKED", "authority": "none", "release_approval": False, "claim_boundary": "Evaluates supplied replay observations; does not execute commands or prove production readiness."}
    receipt = {**core, "receipt_sha256": hashlib.sha256(canonical_bytes(core)).hexdigest()}
    if out is not None:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_bytes(receipt) + b"\n")
    return receipt


def load_benchmark_json(path: Path) -> dict[str, Any]:
    """Load one bounded benchmark JSON object for a review-only CLI input."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError("E_BENCHMARK_JSON", str(exc)) from exc
    if not isinstance(value, dict):
        raise BenchmarkError("E_BENCHMARK_JSON", "JSON must be an object")
    return value
