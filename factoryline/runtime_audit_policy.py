"""Pre-execution validation of signed lane policies, never artifact-provided gates."""
from __future__ import annotations

from typing import Any

from .runtime_audit_common import (RuntimeAuditError, exact_keys, require_bool,
    require_digest, require_int, require_number, require_str, require_unique_strings)

ENGINES = {
    "stateful_invariant": {"hypothesis", "approved_state_machine"},
    "tenant_isolation": {"runtime_http_matrix"},
    "failure_recovery": {"toxiproxy", "approved_fault_runner"},
    "consumer_compatibility": {"pact_verifier", "approved_schema_validator"},
    "migration_integrity": {"database_rehearsal", "flyway"},
    "performance_regression": {"k6", "approved_load_runner"},
}


def records(value: object, field: str, required: set[str], maximum: int = 256) -> list[dict[str, Any]]:
    """Validate bounded policy records with exact fields and unique stable identifiers."""
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise RuntimeAuditError("E_POLICY", f"{field} requires 1..{maximum} records")
    seen: set[str] = set()
    for record in value:
        exact_keys(record, required)
        record_id = require_str(record.get("id"), f"{field}.id")
        if record_id in seen:
            raise RuntimeAuditError("E_DUPLICATE_ID", f"{field}: {record_id}")
        seen.add(record_id)
    return value


def validate_lane_policy(kind: str, config: dict[str, Any]) -> None:
    """Validate one signed lane policy before any audit command receives execution authority."""
    validators = {
        "stateful_invariant": _stateful,
        "tenant_isolation": _tenant,
        "failure_recovery": _recovery,
        "consumer_compatibility": _compatibility,
        "migration_integrity": _migration,
        "performance_regression": _performance,
    }
    if kind not in validators:
        raise RuntimeAuditError("E_LANES", "unknown audit lane")
    validators[kind](config)


def _stateful(config: dict[str, Any]) -> None:
    exact_keys(config, {"invariant_ids", "required_actions", "min_examples", "min_actions"})
    require_unique_strings(config["invariant_ids"], "invariant_ids", minimum=1, maximum=128)
    require_unique_strings(config["required_actions"], "required_actions", minimum=1, maximum=128)
    require_int(config["min_examples"], "min_examples", minimum=2, maximum=1000)
    require_int(config["min_actions"], "min_actions", minimum=2, maximum=200)


def _tenant(config: dict[str, Any]) -> None:
    exact_keys(config, {"forbidden_fields", "denial_statuses", "surfaces"})
    require_unique_strings(config["forbidden_fields"], "forbidden_fields", minimum=1, maximum=128)
    statuses = config["denial_statuses"]
    if not isinstance(statuses, list) or not statuses or any(type(s) is not int or s not in {401, 403, 404} for s in statuses) or len(set(statuses)) != len(statuses):
        raise RuntimeAuditError("E_POLICY", "denial_statuses must be distinct 401, 403 or 404 values")
    categories = {"api", "cache", "session", "export", "storage", "queue", "background_job"}
    # Every surface requires 12 observations (4 relations x 3 phases), so 21
    # surfaces is the largest complete matrix that fits the 256-case artifact cap.
    for item in records(config["surfaces"], "surfaces", {"id", "category", "operation", "resource"}, 21):
        if item["category"] not in categories:
            raise RuntimeAuditError("E_POLICY", "unsupported tenant surface category")
        require_str(item["operation"], "operation", maximum=80)
        require_str(item["resource"], "resource", maximum=512)


def _recovery(config: dict[str, Any]) -> None:
    exact_keys(config, {"fault_modes", "postconditions", "min_concurrency", "max_attempts_per_key"})
    require_unique_strings(config["fault_modes"], "fault_modes", minimum=1, maximum=32)
    require_int(config["min_concurrency"], "min_concurrency", minimum=2, maximum=64)
    require_int(config["max_attempts_per_key"], "max_attempts_per_key", minimum=2, maximum=64)
    for item in records(config["postconditions"], "postconditions", {"id", "metric", "operator", "value"}, 128):
        require_str(item["metric"], "metric")
        if item["operator"] not in {"eq", "lte", "gte"}:
            raise RuntimeAuditError("E_POLICY", "unknown postcondition operator")
        require_number(item["value"], "value")


def _compatibility(config: dict[str, Any]) -> None:
    exact_keys(config, {"provider_version", "provider_branch", "environment", "interactions", "deployment_matrix_required"})
    for key in ("provider_version", "provider_branch", "environment"):
        require_str(config[key], key)
    for item in records(config["interactions"], "interactions", {"id", "consumer_id", "consumer_version", "expected_sha256"}):
        require_str(item["consumer_id"], "consumer_id")
        require_str(item["consumer_version"], "consumer_version")
        require_digest(item["expected_sha256"], "expected_sha256")
    require_bool(config["deployment_matrix_required"], "deployment_matrix_required")


def _migration(config: dict[str, Any]) -> None:
    exact_keys(config, {"before_schema_sha256", "expected_after_schema_sha256", "invariants", "tables", "recovery_strategy", "required_catalog_objects", "max_lock_wait_seconds"})
    require_digest(config["before_schema_sha256"], "before_schema_sha256")
    require_digest(config["expected_after_schema_sha256"], "expected_after_schema_sha256")
    for item in records(config["invariants"], "invariants", {"id", "expected_sha256"}):
        require_digest(item["expected_sha256"], "expected_sha256")
    for item in records(config["tables"], "tables", {"id", "before", "after"}):
        require_int(item["before"], "before", minimum=0, maximum=10**12)
        require_int(item["after"], "after", minimum=0, maximum=10**12)
    if config["recovery_strategy"] not in {"rollback", "forward_fix"}:
        raise RuntimeAuditError("E_POLICY", "unknown recovery strategy")
    require_unique_strings(config["required_catalog_objects"], "required_catalog_objects", minimum=1, maximum=256)
    require_number(config["max_lock_wait_seconds"], "max_lock_wait_seconds")


def _performance(config: dict[str, Any]) -> None:
    exact_keys(config, {"workload_sha256", "environment_sha256", "thresholds", "resource_metrics",
        "minimum_resource_samples", "max_retained_growth_ratio", "max_loadgen_cpu_pct",
        "max_loadgen_memory_pct", "max_dropped_iterations", "min_soak_seconds", "min_cooldown_seconds", "leak_engine"})
    require_digest(config["workload_sha256"], "workload_sha256")
    require_digest(config["environment_sha256"], "environment_sha256")
    for item in records(config["thresholds"], "thresholds", {"id", "metric", "mode", "operator", "value", "origin"}, 128):
        require_str(item["metric"], "metric")
        if item["mode"] not in {"absolute", "ratio"} or item["operator"] not in {"lte", "gte", "eq"} or item["origin"] not in {"human_confirmed", "trusted_source", "observed_production", "agent_proposed"}:
            raise RuntimeAuditError("E_POLICY", "unknown threshold mode/operator/provenance")
        require_number(item["value"], "value")
    require_unique_strings(config["resource_metrics"], "resource_metrics", minimum=1, maximum=16)
    require_int(config["minimum_resource_samples"], "minimum_resource_samples", minimum=3, maximum=10000)
    require_number(config["max_retained_growth_ratio"], "max_retained_growth_ratio")
    for key in ("max_loadgen_cpu_pct", "max_loadgen_memory_pct"):
        if require_number(config[key], key) > 100:
            raise RuntimeAuditError("E_POLICY", "percentage exceeds 100")
    require_int(config["max_dropped_iterations"], "max_dropped_iterations", minimum=0, maximum=1000000)
    for key in ("min_soak_seconds", "min_cooldown_seconds"):
        require_int(config[key], key, minimum=1, maximum=86400)
    if config["leak_engine"] not in {"leak_sanitizer", "valgrind_memcheck", "dotnet_counters", "jvm_profiler", "node_heap", "runtime_metrics", "python_tracemalloc"}:
        raise RuntimeAuditError("E_POLICY", "unknown leak engine")
