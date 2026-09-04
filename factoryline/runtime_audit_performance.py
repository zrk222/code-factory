"""Equivalent-workload performance, capacity and leak-regression evaluation."""
from __future__ import annotations

from statistics import median
from typing import Any

from .runtime_audit_common import exact_keys, lane_result, require_int, require_number, require_str
from .runtime_audit_policy import validate_lane_policy

AUTHORITATIVE = {"human_confirmed", "trusted_source", "observed_production"}
ORIGINS = AUTHORITATIVE | {"agent_proposed"}
LEAK_ENGINES = {"leak_sanitizer", "valgrind_memcheck", "dotnet_counters", "jvm_profiler", "node_heap", "runtime_metrics", "python_tracemalloc"}


def _comparison(actual: float, operator: str, expected: float) -> bool:
    return {"lte": actual <= expected, "gte": actual >= expected, "eq": actual == expected}.get(operator, False)


def _series(value: object, field: str, minimum: int) -> list[float]:
    if not isinstance(value, list) or not minimum <= len(value) <= 10_000:
        raise ValueError(f"{field} must contain {minimum}..10000 samples")
    return [require_number(item, f"{field}[]") for item in value]


def evaluate_performance(artifact: dict[str, Any], config: dict[str, Any], *, engine: str, engine_version: str) -> dict[str, Any]:
    """Evaluate equivalent-load thresholds, generator capacity, cooldown retention, and profiler-scoped memory findings."""
    validate_lane_policy("performance_regression", config)
    exact_keys(artifact, {"schema", "engine", "engine_version", "workload_sha256", "environment_sha256", "baseline", "candidate", "resource_series", "load_generator", "leak_check"})
    if artifact["schema"] != "factory.runtime.performance.v1" or artifact["engine"] != engine or artifact["engine_version"] != engine_version:
        return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_IDENTITY_MISMATCH", "Performance evidence is not bound to the signed engine.")
    workload = require_str(artifact["workload_sha256"], "workload_sha256", minimum=64, maximum=64)
    environment = require_str(artifact["environment_sha256"], "environment_sha256", minimum=64, maximum=64)
    if workload != require_str(config.get("workload_sha256"), "config.workload_sha256", minimum=64, maximum=64) or environment != require_str(config.get("environment_sha256"), "config.environment_sha256", minimum=64, maximum=64):
        return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_COMPARISON_NOT_EQUIVALENT", "Baseline and candidate are not bound to the approved workload and environment.")
    baseline = artifact["baseline"]
    candidate = artifact["candidate"]
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_METRICS_MISSING", "Baseline or candidate metrics are missing.")
    for label, run in (("baseline", baseline), ("candidate", candidate)):
        exact_keys(run, {"observations", "metrics", "workload_sha256", "environment_sha256", "soak_seconds", "cooldown_seconds", "correctness_failures"})
        if run["workload_sha256"] != workload or run["environment_sha256"] != environment:
            return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_COMPARISON_NOT_EQUIVALENT", f"{label} fingerprint differs from the signed comparison.")
        if require_number(run["soak_seconds"], "soak_seconds") < config["min_soak_seconds"] or require_number(run["cooldown_seconds"], "cooldown_seconds") < config["min_cooldown_seconds"]:
            return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_WINDOW_SHORT", f"{label} did not meet the signed soak and cleanup windows.")
        if require_int(run["correctness_failures"], "correctness_failures", minimum=0, maximum=1000000):
            return lane_result("performance_regression", "FAIL", "PERFORMANCE_CORRECTNESS_FAILURE", f"{label} returned incorrect results under load.")
    observations = require_int(candidate.get("observations"), "candidate.observations", minimum=10, maximum=1_000_000)
    require_int(baseline.get("observations"), "baseline.observations", minimum=10, maximum=1_000_000)
    if not isinstance(baseline.get("metrics"), dict) or not isinstance(candidate.get("metrics"), dict):
        return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_METRICS_MISSING", "Numeric metrics are missing.")
    thresholds = config.get("thresholds")
    if not isinstance(thresholds, list) or not 1 <= len(thresholds) <= 128:
        return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_THRESHOLDS_MISSING", "No approved threshold was supplied.")
    failures: list[dict[str, Any]] = []
    advisory: list[dict[str, Any]] = []
    authoritative_count = 0
    ids: set[str] = set()
    for threshold in thresholds:
        if not isinstance(threshold, dict):
            return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_THRESHOLD_INVALID", "A threshold is malformed.")
        exact_keys(threshold, {"id", "metric", "mode", "operator", "value", "origin"})
        threshold_id = require_str(threshold["id"], "threshold.id")
        if threshold_id in ids:
            return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_DUPLICATE_THRESHOLD", "Threshold IDs must be unique.")
        ids.add(threshold_id)
        metric = require_str(threshold["metric"], "threshold.metric")
        origin = threshold["origin"]
        if origin not in ORIGINS:
            return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_PROVENANCE_UNKNOWN", "Threshold provenance is not recognized.")
        if metric not in candidate["metrics"] or metric not in baseline["metrics"]:
            return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_METRIC_MISSING", "An approved metric was not observed.", details={"metric": metric})
        base_value = require_number(baseline["metrics"][metric], f"baseline.metrics.{metric}")
        candidate_value = require_number(candidate["metrics"][metric], f"candidate.metrics.{metric}")
        mode = threshold["mode"]
        if mode == "ratio" and base_value == 0:
            return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_ZERO_BASELINE", "A relative comparison cannot use a zero baseline; approve an absolute budget.")
        actual = candidate_value if mode == "absolute" else candidate_value / base_value
        expected = require_number(threshold["value"], "threshold.value")
        passed = _comparison(actual, threshold["operator"], expected)
        finding = {"id": threshold_id, "metric": metric, "actual": actual, "operator": threshold["operator"], "expected": expected, "origin": origin, "baseline": base_value, "candidate": candidate_value}
        if origin in AUTHORITATIVE:
            authoritative_count += 1
            if not passed:
                failures.append(finding)
        else:
            advisory.append({**finding, "would_pass": passed})
    if authoritative_count == 0:
        return lane_result("performance_regression", "INCOMPLETE", "PERFORMANCE_AUTHORITY_MISSING", "Agent-proposed thresholds are advisory and cannot release a candidate.", details={"advisory": advisory})

    minimum_samples = require_int(config.get("minimum_resource_samples"), "config.minimum_resource_samples", minimum=3, maximum=10_000)
    max_growth = require_number(config.get("max_retained_growth_ratio"), "config.max_retained_growth_ratio")
    resources = artifact["resource_series"]
    required_resources = config.get("resource_metrics")
    if not isinstance(resources, dict) or not isinstance(required_resources, list) or not 1 <= len(required_resources) <= 16:
        return lane_result("performance_regression", "INCOMPLETE", "RESOURCE_EVIDENCE_MISSING", "Resource and memory evidence is required.")
    resource_failures: list[dict[str, Any]] = []
    for metric in required_resources:
        metric = require_str(metric, "config.resource_metrics[]")
        series = resources.get(metric)
        if not isinstance(series, dict) or set(series) != {"baseline", "candidate", "baseline_cooldown", "candidate_cooldown"}:
            return lane_result("performance_regression", "INCOMPLETE", "RESOURCE_METRIC_MISSING", "A required resource series is absent.", details={"metric": metric})
        try:
            base_series = _series(series["baseline"], f"resource_series.{metric}.baseline", minimum_samples)
            candidate_series = _series(series["candidate"], f"resource_series.{metric}.candidate", minimum_samples)
            base_cooldown = _series(series["baseline_cooldown"], f"resource_series.{metric}.baseline_cooldown", minimum_samples)
            candidate_cooldown = _series(series["candidate_cooldown"], f"resource_series.{metric}.candidate_cooldown", minimum_samples)
        except ValueError as exc:
            return lane_result("performance_regression", "INCOMPLETE", "RESOURCE_SERIES_SHORT", str(exc))
        base_start = median(base_series[: max(1, len(base_series) // 3)])
        candidate_start = median(candidate_series[: max(1, len(candidate_series) // 3)])
        base_retained = median(base_cooldown) - base_start
        candidate_retained = median(candidate_cooldown) - candidate_start
        denominator = max(abs(base_start), 1.0)
        retained_ratio = max(0.0, candidate_retained - max(0.0, base_retained)) / denominator
        if retained_ratio > max_growth:
            resource_failures.append({"metric": metric, "retained_growth_ratio": retained_ratio, "maximum": max_growth})

    loadgen = artifact["load_generator"]
    if not isinstance(loadgen, dict):
        return lane_result("performance_regression", "INCOMPLETE", "LOAD_GENERATOR_EVIDENCE_MISSING", "Load-generator saturation was not measured.")
    exact_keys(loadgen, {"cpu_peak_pct", "memory_peak_pct", "dropped_iterations"})
    cpu_peak = require_number(loadgen["cpu_peak_pct"], "load_generator.cpu_peak_pct")
    memory_peak = require_number(loadgen["memory_peak_pct"], "load_generator.memory_peak_pct")
    dropped = require_int(loadgen["dropped_iterations"], "load_generator.dropped_iterations", minimum=0, maximum=1_000_000)
    if cpu_peak > require_number(config.get("max_loadgen_cpu_pct"), "config.max_loadgen_cpu_pct") or memory_peak > require_number(config.get("max_loadgen_memory_pct"), "config.max_loadgen_memory_pct") or dropped > require_int(config.get("max_dropped_iterations"), "config.max_dropped_iterations", minimum=0, maximum=1_000_000):
        return lane_result("performance_regression", "INCOMPLETE", "LOAD_GENERATOR_SATURATED", "The load generator cannot support a fair candidate comparison.", details={"cpu_peak_pct": cpu_peak, "memory_peak_pct": memory_peak, "dropped_iterations": dropped})

    leak = artifact["leak_check"]
    if not isinstance(leak, dict):
        return lane_result("performance_regression", "INCOMPLETE", "LEAK_EVIDENCE_MISSING", "No memory-leak evidence was supplied.")
    exact_keys(leak, {"engine", "findings", "definitely_lost_bytes", "exit_code"})
    if leak.get("engine") not in LEAK_ENGINES or leak.get("engine") != config["leak_engine"]:
        return lane_result("performance_regression", "INCOMPLETE", "LEAK_ENGINE_UNKNOWN", "The memory-leak engine is not recognized.")
    leak_findings = require_int(leak["findings"], "leak_check.findings", minimum=0, maximum=1_000_000)
    lost_bytes = require_int(leak["definitely_lost_bytes"], "leak_check.definitely_lost_bytes", minimum=0, maximum=10**15)
    leak_exit = require_int(leak["exit_code"], "leak_check.exit_code", minimum=0, maximum=255)
    if failures or resource_failures or leak_findings or lost_bytes or leak_exit:
        return lane_result("performance_regression", "FAIL", "PERFORMANCE_OR_RESOURCE_REGRESSION", "The candidate exceeded an approved performance limit or retained resources after load.", details={"threshold_failures": failures, "resource_failures": resource_failures, "leak_check": leak, "advisory": advisory})
    return lane_result("performance_regression", "PASS", "PERFORMANCE_AND_RESOURCES_HELD", "Equivalent-workload and post-cleanup resource checks held within signed limits; this does not prove absence of leaks.", details={"observations": observations, "authoritative_thresholds": authoritative_count, "resource_metrics": required_resources, "leak_engine": leak["engine"], "advisory": advisory, "leak_claim": "no finding within declared profiler coverage"})
