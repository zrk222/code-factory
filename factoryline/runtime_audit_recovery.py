"""Fault, concurrency, idempotency, cleanup and recovery evaluation."""
from __future__ import annotations

from typing import Any

from .runtime_audit_common import exact_keys, lane_result, require_int, require_number, require_str, require_unique_strings
from .runtime_audit_policy import validate_lane_policy


def _condition(actual: float, operator: str, expected: float) -> bool:
    return {"eq": actual == expected, "lte": actual <= expected, "gte": actual >= expected}.get(operator, False)


def evaluate_recovery(artifact: dict[str, Any], config: dict[str, Any], *, engine: str, engine_version: str) -> dict[str, Any]:
    """Evaluate signed fault coverage, concurrent retries, durable effects, recovered invariants, and cleanup."""
    validate_lane_policy("failure_recovery", config)
    exact_keys(artifact, {"schema", "engine", "engine_version", "operations", "fault_modes", "phases", "cleanup", "max_concurrency", "fault_observed", "lost_updates"})
    if artifact["schema"] != "factory.runtime.recovery.v1" or artifact["engine"] != engine or artifact["engine_version"] != engine_version:
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_IDENTITY_MISMATCH", "Recovery evidence is not bound to the signed engine.")
    required_faults = set(require_unique_strings(config.get("fault_modes"), "config.fault_modes", minimum=1, maximum=32))
    observed_faults = set(require_unique_strings(artifact["fault_modes"], "fault_modes", minimum=1, maximum=32))
    missing_faults = sorted(required_faults - observed_faults)
    if missing_faults:
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_FAULT_MISSING", "Not every approved dependency fault was injected.", details={"missing": missing_faults})
    operations = artifact["operations"]
    if not isinstance(operations, list) or not 2 <= len(operations) <= 64:
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_OPERATIONS_INCOMPLETE", "Recovery needs 2..64 duplicate or concurrent operations.")
    effects: dict[str, int] = {}
    attempts: dict[str, int] = {}
    operation_ids: set[str] = set()
    if require_int(artifact["max_concurrency"], "max_concurrency", minimum=1, maximum=64) < config["min_concurrency"] or artifact["fault_observed"] is not True:
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_FAULT_NOT_EXERCISED", "Fault impact and simultaneous work were not observed.")
    if artifact["max_concurrency"] > len(operations):
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_OBSERVATION_CONTRADICTION", "Claimed concurrency exceeds recorded operations.", details={"max_concurrency": artifact["max_concurrency"], "observed_operations": len(operations)})
    for operation in operations:
        if not isinstance(operation, dict):
            return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_OPERATION_INVALID", "An operation record is malformed.")
        exact_keys(operation, {"id", "idempotency_key", "effects"})
        operation_id = require_str(operation["id"], "operation.id")
        if operation_id in operation_ids:
            return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_DUPLICATE_OPERATION", "Operation IDs must be unique.")
        operation_ids.add(operation_id)
        key = require_str(operation["idempotency_key"], "operation.idempotency_key")
        effects[key] = effects.get(key, 0) + require_int(operation["effects"], "operation.effects", minimum=0, maximum=1_000_000)
        attempts[key] = attempts.get(key, 0) + 1
    if not any(count >= 2 for count in attempts.values()):
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_DUPLICATE_NOT_EXERCISED", "No idempotency key was replayed.")
    duplicates = {key: count for key, count in effects.items() if count > 1}
    phases = artifact["phases"]
    if not isinstance(phases, dict) or set(phases) != {"pre_fault", "during_fault", "recovered"}:
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_PHASES_INCOMPLETE", "Pre-fault, during-fault and recovered observations are required.")
    if not all(isinstance(value, dict) for value in phases.values()):
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_PHASES_INVALID", "Phase metrics must be objects.")
    recovered = phases["recovered"]
    conditions = config.get("postconditions")
    if not isinstance(conditions, list) or not 1 <= len(conditions) <= 128:
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_POSTCONDITIONS_MISSING", "Approved post-recovery invariants are required.")
    failures: list[dict[str, Any]] = []
    seen: set[str] = set()
    for condition in conditions:
        if not isinstance(condition, dict):
            return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_CONDITION_INVALID", "A postcondition is malformed.")
        exact_keys(condition, {"id", "metric", "operator", "value"})
        condition_id = require_str(condition["id"], "postcondition.id")
        if condition_id in seen:
            return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_DUPLICATE_CONDITION", "Postcondition IDs must be unique.")
        seen.add(condition_id)
        metric = require_str(condition["metric"], "postcondition.metric")
        operator = require_str(condition["operator"], "postcondition.operator", maximum=8)
        if metric not in recovered:
            return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_METRIC_MISSING", "A recovered-state metric is absent.", details={"metric": metric})
        actual = require_number(recovered[metric], f"phases.recovered.{metric}")
        expected = require_number(condition["value"], "postcondition.value")
        if not _condition(actual, operator, expected):
            failures.append({"id": condition_id, "metric": metric, "actual": actual, "operator": operator, "expected": expected})
    cleanup = artifact["cleanup"]
    if not isinstance(cleanup, dict):
        return lane_result("failure_recovery", "INCOMPLETE", "RECOVERY_CLEANUP_MISSING", "Cleanup evidence is absent.")
    exact_keys(cleanup, {"attempted", "succeeded"})
    retry_storm = any(count > config["max_attempts_per_key"] for count in attempts.values())
    lost_updates = require_int(artifact["lost_updates"], "lost_updates", minimum=0, maximum=1000000)
    if duplicates or failures or retry_storm or lost_updates or cleanup.get("attempted") is not True or cleanup.get("succeeded") is not True:
        return lane_result("failure_recovery", "FAIL", "RECOVERY_INVARIANT_VIOLATION", "Retries, faults or cleanup left duplicate effects or an invalid recovered state.", details={"duplicate_effects": duplicates, "postcondition_failures": failures, "cleanup": cleanup, "retry_storm": retry_storm, "lost_updates": lost_updates})
    return lane_result("failure_recovery", "PASS", "RECOVERY_INVARIANTS_HELD", "The declared faults recovered without duplicate effects and cleanup completed.", details={"operations": len(operations), "fault_modes": sorted(observed_faults)})
