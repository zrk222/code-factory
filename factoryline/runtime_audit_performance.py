"""Equivalent-workload performance, capacity and leak-regression evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import ceil
from pathlib import Path
from statistics import median
from typing import Any

from .runtime_audit_common import (
    canonical_bytes,
    exact_keys,
    guarded_lane_evaluator,
    lane_result,
    require_int,
    require_number,
    require_str,
)
from .runtime_audit_policy import validate_lane_policy

AUTHORITATIVE = {"human_confirmed", "trusted_source", "observed_production"}
ORIGINS = AUTHORITATIVE | {"agent_proposed"}
LEAK_ENGINES = {
    "leak_sanitizer",
    "valgrind_memcheck",
    "dotnet_counters",
    "jvm_profiler",
    "node_heap",
    "runtime_metrics",
    "python_tracemalloc",
}


def _comparison(actual: float, operator: str, expected: float) -> bool:
    return {
        "lte": actual <= expected,
        "gte": actual >= expected,
        "eq": actual == expected,
    }.get(operator, False)


def _series(value: object, field: str, minimum: int) -> list[float]:
    if not isinstance(value, list) or not minimum <= len(value) <= 10_000:
        raise ValueError(f"{field} must contain {minimum}..10000 samples")
    return [require_number(item, f"{field}[]") for item in value]


@dataclass(frozen=True)
class _PerformanceRuns:
    """Validated equivalent runs and approved threshold declarations."""

    baseline: dict[str, Any]
    candidate: dict[str, Any]
    observations: int
    thresholds: list[dict[str, Any]]


def _performance_identity(
    artifact: dict[str, Any],
    config: dict[str, Any],
    engine: str,
    engine_version: str,
) -> dict[str, Any] | tuple[str, str]:
    """Bind the evidence to the signed engine, workload, and environment."""
    validate_lane_policy("performance_regression", config)
    exact_keys(
        artifact,
        {
            "schema",
            "engine",
            "engine_version",
            "workload_sha256",
            "environment_sha256",
            "baseline",
            "candidate",
            "resource_series",
            "load_generator",
            "leak_check",
        },
    )
    if (
        artifact["schema"] != "factory.runtime.performance.v1"
        or artifact["engine"] != engine
        or artifact["engine_version"] != engine_version
    ):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_IDENTITY_MISMATCH",
            "Performance evidence is not bound to the signed engine.",
        )
    workload = require_str(
        artifact["workload_sha256"], "workload_sha256", minimum=64, maximum=64
    )
    environment = require_str(
        artifact["environment_sha256"], "environment_sha256", minimum=64, maximum=64
    )
    if workload != require_str(
        config.get("workload_sha256"), "config.workload_sha256", minimum=64, maximum=64
    ) or environment != require_str(
        config.get("environment_sha256"),
        "config.environment_sha256",
        minimum=64,
        maximum=64,
    ):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_COMPARISON_NOT_EQUIVALENT",
            "Baseline and candidate are not bound to the approved workload and environment.",
        )
    return workload, environment


def _performance_run_preflight(
    label: str,
    run: dict[str, Any],
    workload: str,
    environment: str,
    config: dict[str, Any],
) -> dict[str, Any] | None:
    """Reject a mismatched, short, or incorrect baseline/candidate run."""
    exact_keys(
        run,
        {
            "observations",
            "metrics",
            "workload_sha256",
            "environment_sha256",
            "soak_seconds",
            "cooldown_seconds",
            "correctness_failures",
        },
    )
    if run["workload_sha256"] != workload or run["environment_sha256"] != environment:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_COMPARISON_NOT_EQUIVALENT",
            f"{label} fingerprint differs from the signed comparison.",
        )
    if (
        require_number(run["soak_seconds"], "soak_seconds") < config["min_soak_seconds"]
        or require_number(run["cooldown_seconds"], "cooldown_seconds")
        < config["min_cooldown_seconds"]
    ):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_WINDOW_SHORT",
            f"{label} did not meet the signed soak and cleanup windows.",
        )
    if require_int(
        run["correctness_failures"], "correctness_failures", minimum=0, maximum=1000000
    ):
        return lane_result(
            "performance_regression",
            "FAIL",
            "PERFORMANCE_CORRECTNESS_FAILURE",
            f"{label} returned incorrect results under load.",
        )
    return None


def _performance_runs(
    artifact: dict[str, Any],
    config: dict[str, Any],
    workload: str,
    environment: str,
) -> dict[str, Any] | _PerformanceRuns:
    """Validate equivalent run windows, observation counts, and threshold scope."""
    baseline, candidate = artifact["baseline"], artifact["candidate"]
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_METRICS_MISSING",
            "Baseline or candidate metrics are missing.",
        )
    for label, run in (("baseline", baseline), ("candidate", candidate)):
        failure = _performance_run_preflight(label, run, workload, environment, config)
        if failure is not None:
            return failure
    observations = require_int(
        candidate.get("observations"),
        "candidate.observations",
        minimum=10,
        maximum=1_000_000,
    )
    require_int(
        baseline.get("observations"),
        "baseline.observations",
        minimum=10,
        maximum=1_000_000,
    )
    if not isinstance(baseline.get("metrics"), dict) or not isinstance(
        candidate.get("metrics"), dict
    ):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_METRICS_MISSING",
            "Numeric metrics are missing.",
        )
    thresholds = config.get("thresholds")
    if not isinstance(thresholds, list) or not 1 <= len(thresholds) <= 128:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_THRESHOLDS_MISSING",
            "No approved threshold was supplied.",
        )
    return _PerformanceRuns(baseline, candidate, observations, thresholds)


@dataclass(frozen=True)
class _ThresholdObservation:
    finding: dict[str, Any]
    passed: bool
    authoritative: bool


@dataclass(frozen=True)
class _ThresholdSummary:
    failures: list[dict[str, Any]]
    advisory: list[dict[str, Any]]
    authoritative_count: int


def _threshold_identity(
    threshold: Any,
    ids: set[str],
    baseline: dict,
    candidate: dict,
) -> dict[str, Any] | tuple[str, str, str]:
    """Validate one approved threshold's id, provenance, and observed metric."""
    if not isinstance(threshold, dict):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_THRESHOLD_INVALID",
            "A threshold is malformed.",
        )
    exact_keys(threshold, {"id", "metric", "mode", "operator", "value", "origin"})
    threshold_id = require_str(threshold["id"], "threshold.id")
    if threshold_id in ids:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_DUPLICATE_THRESHOLD",
            "Threshold IDs must be unique.",
        )
    ids.add(threshold_id)
    metric = require_str(threshold["metric"], "threshold.metric")
    origin = threshold["origin"]
    if origin not in ORIGINS:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_PROVENANCE_UNKNOWN",
            "Threshold provenance is not recognized.",
        )
    if metric not in candidate["metrics"] or metric not in baseline["metrics"]:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_METRIC_MISSING",
            "An approved metric was not observed.",
            details={"metric": metric},
        )
    return threshold_id, metric, origin


def _threshold_observation(
    threshold: dict,
    identity: tuple[str, str, str],
    baseline: dict,
    candidate: dict,
) -> dict[str, Any] | _ThresholdObservation:
    """Compare one candidate metric to its approved absolute or ratio budget."""
    threshold_id, metric, origin = identity
    base_value = require_number(
        baseline["metrics"][metric], f"baseline.metrics.{metric}"
    )
    candidate_value = require_number(
        candidate["metrics"][metric], f"candidate.metrics.{metric}"
    )
    mode = threshold["mode"]
    if mode == "ratio" and base_value == 0:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_ZERO_BASELINE",
            "A relative comparison cannot use a zero baseline; approve an absolute budget.",
        )
    actual = candidate_value if mode == "absolute" else candidate_value / base_value
    expected = require_number(threshold["value"], "threshold.value")
    passed = _comparison(actual, threshold["operator"], expected)
    finding = {
        "id": threshold_id,
        "metric": metric,
        "actual": actual,
        "operator": threshold["operator"],
        "expected": expected,
        "origin": origin,
        "baseline": base_value,
        "candidate": candidate_value,
    }
    return _ThresholdObservation(finding, passed, origin in AUTHORITATIVE)


def _performance_thresholds(
    runs: _PerformanceRuns,
) -> dict[str, Any] | _ThresholdSummary:
    """Keep agent-proposed budgets advisory and report approved violations."""
    failures: list[dict[str, Any]] = []
    advisory: list[dict[str, Any]] = []
    authoritative_count = 0
    ids: set[str] = set()
    for threshold in runs.thresholds:
        identity = _threshold_identity(threshold, ids, runs.baseline, runs.candidate)
        if isinstance(identity, dict):
            return identity
        observation = _threshold_observation(
            threshold, identity, runs.baseline, runs.candidate
        )
        if isinstance(observation, dict):
            return observation
        if observation.authoritative:
            authoritative_count += 1
            if not observation.passed:
                failures.append(observation.finding)
        else:
            advisory.append({**observation.finding, "would_pass": observation.passed})
    if authoritative_count == 0:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "PERFORMANCE_AUTHORITY_MISSING",
            "Agent-proposed thresholds are advisory and cannot release a candidate.",
            details={"advisory": advisory},
        )
    return _ThresholdSummary(failures, advisory, authoritative_count)


@dataclass(frozen=True)
class _ResourceObservation:
    finding: dict[str, Any] | None


@dataclass(frozen=True)
class _ResourceSummary:
    failures: list[dict[str, Any]]
    required_metrics: list[str]


def _resource_series_result(
    metric: str,
    series: Any,
    minimum_samples: int,
    max_growth: float,
) -> dict[str, Any] | _ResourceObservation:
    """Compare retained post-cooldown resources for one required metric."""
    if not isinstance(series, dict) or set(series) != {
        "baseline",
        "candidate",
        "baseline_cooldown",
        "candidate_cooldown",
    }:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "RESOURCE_METRIC_MISSING",
            "A required resource series is absent.",
            details={"metric": metric},
        )
    try:
        base_series = _series(
            series["baseline"], f"resource_series.{metric}.baseline", minimum_samples
        )
        candidate_series = _series(
            series["candidate"], f"resource_series.{metric}.candidate", minimum_samples
        )
        base_cooldown = _series(
            series["baseline_cooldown"],
            f"resource_series.{metric}.baseline_cooldown",
            minimum_samples,
        )
        candidate_cooldown = _series(
            series["candidate_cooldown"],
            f"resource_series.{metric}.candidate_cooldown",
            minimum_samples,
        )
    except ValueError as exc:
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "RESOURCE_SERIES_SHORT",
            str(exc),
        )
    base_start = median(base_series[: max(1, len(base_series) // 3)])
    candidate_start = median(candidate_series[: max(1, len(candidate_series) // 3)])
    base_retained = median(base_cooldown) - base_start
    candidate_retained = median(candidate_cooldown) - candidate_start
    denominator = max(abs(base_start), 1.0)
    retained_ratio = (
        max(0.0, candidate_retained - max(0.0, base_retained)) / denominator
    )
    if retained_ratio > max_growth:
        return _ResourceObservation(
            {
                "metric": metric,
                "retained_growth_ratio": retained_ratio,
                "maximum": max_growth,
            }
        )
    return _ResourceObservation(None)


def _performance_resources(
    artifact: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any] | _ResourceSummary:
    """Require bounded resource series and summarize retention regressions."""
    minimum_samples = require_int(
        config.get("minimum_resource_samples"),
        "config.minimum_resource_samples",
        minimum=3,
        maximum=10_000,
    )
    max_growth = require_number(
        config.get("max_retained_growth_ratio"), "config.max_retained_growth_ratio"
    )
    resources = artifact["resource_series"]
    required_resources = config.get("resource_metrics")
    if (
        not isinstance(resources, dict)
        or not isinstance(required_resources, list)
        or not 1 <= len(required_resources) <= 16
    ):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "RESOURCE_EVIDENCE_MISSING",
            "Resource and memory evidence is required.",
        )
    failures: list[dict[str, Any]] = []
    for metric in required_resources:
        metric = require_str(metric, "config.resource_metrics[]")
        observation = _resource_series_result(
            metric, resources.get(metric), minimum_samples, max_growth
        )
        if isinstance(observation, dict):
            return observation
        if observation.finding is not None:
            failures.append(observation.finding)
    return _ResourceSummary(failures, required_resources)


def _performance_loadgen(
    artifact: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any] | None:
    """Reject a saturated load generator before interpreting candidate metrics."""
    loadgen = artifact["load_generator"]
    if not isinstance(loadgen, dict):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "LOAD_GENERATOR_EVIDENCE_MISSING",
            "Load-generator saturation was not measured.",
        )
    exact_keys(loadgen, {"cpu_peak_pct", "memory_peak_pct", "dropped_iterations"})
    cpu_peak = require_number(loadgen["cpu_peak_pct"], "load_generator.cpu_peak_pct")
    memory_peak = require_number(
        loadgen["memory_peak_pct"], "load_generator.memory_peak_pct"
    )
    dropped = require_int(
        loadgen["dropped_iterations"],
        "load_generator.dropped_iterations",
        minimum=0,
        maximum=1_000_000,
    )
    if (
        cpu_peak
        > require_number(
            config.get("max_loadgen_cpu_pct"), "config.max_loadgen_cpu_pct"
        )
        or memory_peak
        > require_number(
            config.get("max_loadgen_memory_pct"), "config.max_loadgen_memory_pct"
        )
        or dropped
        > require_int(
            config.get("max_dropped_iterations"),
            "config.max_dropped_iterations",
            minimum=0,
            maximum=1_000_000,
        )
    ):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "LOAD_GENERATOR_SATURATED",
            "The load generator cannot support a fair candidate comparison.",
            details={
                "cpu_peak_pct": cpu_peak,
                "memory_peak_pct": memory_peak,
                "dropped_iterations": dropped,
            },
        )
    return None


@dataclass(frozen=True)
class _LeakObservation:
    evidence: dict[str, Any]
    findings: int
    lost_bytes: int
    exit_code: int


def _performance_leak(
    artifact: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any] | _LeakObservation:
    """Bind memory-leak findings to the declared profiling engine."""
    leak = artifact["leak_check"]
    if not isinstance(leak, dict):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "LEAK_EVIDENCE_MISSING",
            "No memory-leak evidence was supplied.",
        )
    exact_keys(leak, {"engine", "findings", "definitely_lost_bytes", "exit_code"})
    if (
        leak.get("engine") not in LEAK_ENGINES
        or leak.get("engine") != config["leak_engine"]
    ):
        return lane_result(
            "performance_regression",
            "INCOMPLETE",
            "LEAK_ENGINE_UNKNOWN",
            "The memory-leak engine is not recognized.",
        )
    leak_findings = require_int(
        leak["findings"], "leak_check.findings", minimum=0, maximum=1_000_000
    )
    lost_bytes = require_int(
        leak["definitely_lost_bytes"],
        "leak_check.definitely_lost_bytes",
        minimum=0,
        maximum=10**15,
    )
    leak_exit = require_int(
        leak["exit_code"], "leak_check.exit_code", minimum=0, maximum=255
    )
    return _LeakObservation(leak, leak_findings, lost_bytes, leak_exit)


def _performance_outcome(
    runs: _PerformanceRuns,
    thresholds: _ThresholdSummary,
    resources: _ResourceSummary,
    leak: _LeakObservation,
) -> dict[str, Any]:
    """Render a bounded pass or actionable regression with observed evidence."""
    if (
        thresholds.failures
        or resources.failures
        or leak.findings
        or leak.lost_bytes
        or leak.exit_code
    ):
        return lane_result(
            "performance_regression",
            "FAIL",
            "PERFORMANCE_OR_RESOURCE_REGRESSION",
            "The candidate exceeded an approved performance limit or retained resources after load.",
            details={
                "threshold_failures": thresholds.failures,
                "resource_failures": resources.failures,
                "leak_check": leak.evidence,
                "advisory": thresholds.advisory,
            },
        )
    return lane_result(
        "performance_regression",
        "PASS",
        "PERFORMANCE_AND_RESOURCES_HELD",
        "Equivalent-workload and post-cleanup resource checks held within signed limits; this does not prove absence of leaks.",
        details={
            "observations": runs.observations,
            "authoritative_thresholds": thresholds.authoritative_count,
            "resource_metrics": resources.required_metrics,
            "leak_engine": leak.evidence["engine"],
            "advisory": thresholds.advisory,
            "leak_claim": "no finding within declared profiler coverage",
        },
    )


@guarded_lane_evaluator("performance_regression")
def evaluate_performance(
    artifact: dict[str, Any],
    config: dict[str, Any],
    *,
    engine: str,
    engine_version: str,
) -> dict[str, Any]:
    """Evaluate equivalent-load thresholds, generator capacity, cooldown retention, and profiler-scoped memory findings."""
    identity = _performance_identity(artifact, config, engine, engine_version)
    if isinstance(identity, dict):
        return identity
    workload, environment = identity
    runs = _performance_runs(artifact, config, workload, environment)
    if isinstance(runs, dict):
        return runs
    threshold_summary = _performance_thresholds(runs)
    if isinstance(threshold_summary, dict):
        return threshold_summary
    resource_summary = _performance_resources(artifact, config)
    if isinstance(resource_summary, dict):
        return resource_summary
    loadgen_failure = _performance_loadgen(artifact, config)
    if loadgen_failure is not None:
        return loadgen_failure
    leak_observation = _performance_leak(artifact, config)
    if isinstance(leak_observation, dict):
        return leak_observation
    return _performance_outcome(
        runs, threshold_summary, resource_summary, leak_observation
    )


_TRACE_IDENTITIES = {
    "dataset_sha256",
    "workload_sha256",
    "environment_sha256",
    "rubric_sha256",
    "prompt_sha256",
    "tool_sha256",
}
_TRACE_METRICS = {
    "success_rate",
    "abstention_rate",
    "cost_usd_mean",
    "latency_ms_p95",
}


def _trace_cohort(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    exact_keys(body, {"schema", "identities", "rows"})
    if body["schema"] != "factory.trace-cohort.v1":
        raise ValueError("cohort schema mismatch")
    exact_keys(body["identities"], _TRACE_IDENTITIES)
    for value in body["identities"].values():
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise ValueError("invalid cohort identity")
    rows = body["rows"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10_000:
        raise ValueError("cohort must contain 1..10000 rows")
    indexed = {}
    for row in rows:
        item = _trace_cohort_row(row)
        if item["case_id"] in indexed:
            raise ValueError("duplicate cohort case")
        indexed[item["case_id"]] = item
    return indexed


def _trace_cohort_row(row: dict[str, Any]) -> dict[str, Any]:
    exact_keys(row, {"case_id", "category", "outcome", "cost_usd", "latency_ms"})
    require_str(row["case_id"], "case_id")
    require_str(row["category"], "category")
    if row["outcome"] not in {"PASS", "FAIL", "ABSTAIN"}:
        raise ValueError("unknown cohort outcome")
    for metric in ("cost_usd", "latency_ms"):
        if row[metric] is None:
            raise ValueError("required cohort measurement is unknown")
        require_number(row[metric], metric, minimum=0)
    return row


def _trace_cohort_metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    count = len(rows)
    latency = sorted(row["latency_ms"] for row in rows)
    return {
        "success_rate": sum(row["outcome"] == "PASS" for row in rows) / count,
        "abstention_rate": sum(row["outcome"] == "ABSTAIN" for row in rows) / count,
        "cost_usd_mean": sum(row["cost_usd"] for row in rows) / count,
        "latency_ms_p95": latency[ceil(0.95 * count) - 1],
    }


def _trace_regression_policy(body: dict[str, Any]) -> list[dict[str, Any]]:
    exact_keys(body, {"schema", "approval", "thresholds", "identities"})
    if body["schema"] != "factory.trace-regression-policy.v1":
        raise ValueError("regression policy schema mismatch")
    exact_keys(body["approval"], {"origin", "reference"})
    if body["approval"]["origin"] not in AUTHORITATIVE:
        raise ValueError("threshold policy lacks approved provenance")
    require_str(body["approval"]["reference"], "approval reference")
    thresholds = body["thresholds"]
    if not isinstance(thresholds, list) or not 1 <= len(thresholds) <= 400:
        raise ValueError("thresholds must contain 1..400 rows")
    keys = [_trace_threshold_key(item) for item in thresholds]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate regression threshold")
    return thresholds


def _trace_threshold_key(item: dict[str, Any]) -> tuple[str, str]:
    exact_keys(item, {"category", "metric", "operator", "limit", "max_regression"})
    require_str(item["category"], "category")
    if item["metric"] not in _TRACE_METRICS or item["operator"] not in {"gte", "lte"}:
        raise ValueError("unsupported regression threshold")
    expected = "gte" if item["metric"] == "success_rate" else "lte"
    if item["operator"] != expected:
        raise ValueError("threshold direction weakens metric")
    require_number(item["limit"], "limit", minimum=0)
    require_number(item["max_regression"], "max_regression", minimum=0)
    if item["metric"].endswith("rate") and item["limit"] > 1:
        raise ValueError("rate limit exceeds one")
    return item["category"], item["metric"]


def _trace_regression_rows(baseline, candidate, thresholds):
    categories = sorted({row["category"] for row in baseline.values()})
    expected = {
        (category, metric) for category in categories for metric in _TRACE_METRICS
    }
    if {_trace_threshold_key(item) for item in thresholds} != expected:
        raise ValueError("policy must cover every category and mandatory metric")
    observations = []
    for item in thresholds:
        category, metric = item["category"], item["metric"]
        before = _trace_cohort_metrics(
            [row for row in baseline.values() if row["category"] == category]
        )[metric]
        after = _trace_cohort_metrics(
            [row for row in candidate.values() if row["category"] == category]
        )[metric]
        regression = before - after if item["operator"] == "gte" else after - before
        passed = _comparison(after, item["operator"], item["limit"]) and (
            regression <= item["max_regression"]
        )
        observations.append(
            {
                "category": category,
                "metric": metric,
                "baseline": before,
                "candidate": after,
                "regression": regression,
                "limit": item["limit"],
                "max_regression": item["max_regression"],
                "state": "PASS" if passed else "FAIL",
                "paired_cases": sum(
                    row["category"] == category for row in baseline.values()
                ),
            }
        )
    return observations


def _bound_trace_regression(bound: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = bound["artifacts"]
    before, after = artifacts["baseline"]["body"], artifacts["candidate_cohort"]["body"]
    baseline, candidate = _trace_cohort(before), _trace_cohort(after)
    if before["identities"] != after["identities"] or set(baseline) != set(candidate):
        raise ValueError("baseline and candidate cohorts are not equivalent")
    if any(baseline[key]["category"] != candidate[key]["category"] for key in baseline):
        raise ValueError("paired categories differ")
    policy = artifacts["regression_policy"]["body"]
    thresholds = _trace_regression_policy(policy)
    if policy["identities"] != before["identities"]:
        raise ValueError("cohort differs from approved policy identities")
    for role in ("dataset", "rubric", "prompt", "tool"):
        if before["identities"][f"{role}_sha256"] != artifacts[role]["sha256"]:
            raise ValueError("cohort identity differs from bound artifact")
    return _trace_regression_rows(baseline, candidate, thresholds)


def evaluate_trace_regression(
    root: Path, binding_request: dict[str, Any]
) -> dict[str, Any]:
    """Compare bound paired observations; this local receipt grants no rollout authority."""
    from .analysis_evidence import AnalysisEvidenceError, validate_evaluation_bindings

    result: dict[str, Any] = {
        "schema": "factory.trace-regression.v1",
        "state": "INCOMPLETE",
        "code": "REGRESSION_GATES",
        "authority": "none",
        "observations": [],
        "claim_boundary": "Local artifact integrity does not authenticate measurements or approvals.",
        "next_actions": [
            "Supply current paired cohorts and approved complete thresholds."
        ],
    }
    try:
        bound = validate_evaluation_bindings(root, binding_request)
        if bound["state"] != "BOUND_LOCAL_EVIDENCE":
            raise ValueError("evaluation bindings are incomplete")
        result["binding_sha256"] = bound["binding_sha256"]
        observations = _bound_trace_regression(bound)
        result["observations"] = observations
        result["state"] = (
            "FAIL" if any(row["state"] == "FAIL" for row in observations) else "PASS"
        )
        result["next_actions"] = (
            ["Repair breached metrics and rerun only the impacted paired cohort."]
            if result["state"] == "FAIL"
            else []
        )
    except (AnalysisEvidenceError, ValueError, TypeError, KeyError):
        pass
    result["receipt_sha256"] = sha256(canonical_bytes(result)).hexdigest()
    return result
