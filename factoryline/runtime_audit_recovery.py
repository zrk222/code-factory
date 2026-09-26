"""Fault, concurrency, idempotency, cleanup and recovery evaluation."""

from __future__ import annotations

from typing import Any

from .runtime_audit_common import (
    exact_keys,
    lane_result,
    require_int,
    require_number,
    require_str,
    require_unique_strings,
)
from .runtime_audit_policy import validate_lane_policy

LANE = "failure_recovery"


def _incomplete(finding: str, message: str, details: dict[str, Any] | None = None):
    options = {"details": details} if details is not None else {}
    return lane_result(LANE, "INCOMPLETE", finding, message, **options)


def _identity_matches(artifact: dict[str, Any], engine: str, version: str) -> bool:
    return (
        artifact["schema"] == "factory.runtime.recovery.v1"
        and artifact["engine"] == engine
        and artifact["engine_version"] == version
    )


def _required_faults(config: dict[str, Any], artifact: dict[str, Any]):
    required = set(
        require_unique_strings(
            config.get("fault_modes"), "config.fault_modes", minimum=1, maximum=32
        )
    )
    observed = set(
        require_unique_strings(
            artifact["fault_modes"], "fault_modes", minimum=1, maximum=32
        )
    )
    missing = sorted(required - observed)
    if missing:
        return None, _incomplete(
            "RECOVERY_FAULT_MISSING",
            "Not every approved dependency fault was injected.",
            {"missing": missing},
        )
    return observed, None


def _validate_concurrency(artifact: dict[str, Any], config: dict[str, Any], count: int):
    concurrency = require_int(
        artifact["max_concurrency"], "max_concurrency", minimum=1, maximum=64
    )
    if (
        concurrency < config["min_concurrency"]
        or artifact["fault_observed"] is not True
    ):
        return _incomplete(
            "RECOVERY_FAULT_NOT_EXERCISED",
            "Fault impact and simultaneous work were not observed.",
        )
    if concurrency > count:
        return _incomplete(
            "RECOVERY_OBSERVATION_CONTRADICTION",
            "Claimed concurrency exceeds recorded operations.",
            {"max_concurrency": concurrency, "observed_operations": count},
        )
    return None


def _collect_operations(operations: list[Any]):
    effects: dict[str, int] = {}
    attempts: dict[str, int] = {}
    operation_ids: set[str] = set()
    for operation in operations:
        if not isinstance(operation, dict):
            return (
                None,
                None,
                _incomplete(
                    "RECOVERY_OPERATION_INVALID", "An operation record is malformed."
                ),
            )
        exact_keys(operation, {"id", "idempotency_key", "effects"})
        operation_id = require_str(operation["id"], "operation.id")
        if operation_id in operation_ids:
            return (
                None,
                None,
                _incomplete(
                    "RECOVERY_DUPLICATE_OPERATION", "Operation IDs must be unique."
                ),
            )
        operation_ids.add(operation_id)
        key = require_str(operation["idempotency_key"], "operation.idempotency_key")
        effects[key] = effects.get(key, 0) + require_int(
            operation["effects"], "operation.effects", minimum=0, maximum=1_000_000
        )
        attempts[key] = attempts.get(key, 0) + 1
    return effects, attempts, None


def _phase_metrics(phases: Any):
    required = {"pre_fault", "during_fault", "recovered"}
    if not isinstance(phases, dict) or set(phases) != required:
        return None, _incomplete(
            "RECOVERY_PHASES_INCOMPLETE",
            "Pre-fault, during-fault and recovered observations are required.",
        )
    if not all(isinstance(value, dict) for value in phases.values()):
        return None, _incomplete(
            "RECOVERY_PHASES_INVALID", "Phase metrics must be objects."
        )
    return phases["recovered"], None


def _condition(actual: float, operator: str, expected: float) -> bool:
    return {
        "eq": actual == expected,
        "lte": actual <= expected,
        "gte": actual >= expected,
    }.get(operator, False)


def _check_postcondition(condition: Any, recovered: dict[str, Any], seen: set[str]):
    if not isinstance(condition, dict):
        return None, _incomplete(
            "RECOVERY_CONDITION_INVALID", "A postcondition is malformed."
        )
    exact_keys(condition, {"id", "metric", "operator", "value"})
    condition_id = require_str(condition["id"], "postcondition.id")
    if condition_id in seen:
        return None, _incomplete(
            "RECOVERY_DUPLICATE_CONDITION", "Postcondition IDs must be unique."
        )
    seen.add(condition_id)
    metric = require_str(condition["metric"], "postcondition.metric")
    operator = require_str(condition["operator"], "postcondition.operator", maximum=8)
    if metric not in recovered:
        return None, _incomplete(
            "RECOVERY_METRIC_MISSING",
            "A recovered-state metric is absent.",
            {"metric": metric},
        )
    actual = require_number(recovered[metric], f"phases.recovered.{metric}")
    expected = require_number(condition["value"], "postcondition.value")
    if _condition(actual, operator, expected):
        return None, None
    return {
        "id": condition_id,
        "metric": metric,
        "actual": actual,
        "operator": operator,
        "expected": expected,
    }, None


def _postcondition_failures(conditions: Any, recovered: dict[str, Any]):
    if not isinstance(conditions, list) or not 1 <= len(conditions) <= 128:
        return None, _incomplete(
            "RECOVERY_POSTCONDITIONS_MISSING",
            "Approved post-recovery invariants are required.",
        )
    failures = []
    seen: set[str] = set()
    for condition in conditions:
        failure, issue = _check_postcondition(condition, recovered, seen)
        if issue:
            return None, issue
        if failure:
            failures.append(failure)
    return failures, None


def _cleanup_evidence(cleanup: Any):
    if not isinstance(cleanup, dict):
        return _incomplete("RECOVERY_CLEANUP_MISSING", "Cleanup evidence is absent.")
    exact_keys(cleanup, {"attempted", "succeeded"})
    return None


def _invariant_result(
    effects: dict[str, int],
    failures: list[dict[str, Any]],
    attempts: dict[str, int],
    config: dict[str, Any],
    lost_updates: int,
    cleanup: dict[str, Any],
):
    duplicates = {key: count for key, count in effects.items() if count > 1}
    retry_storm = any(
        count > config["max_attempts_per_key"] for count in attempts.values()
    )
    if not (
        duplicates
        or failures
        or retry_storm
        or lost_updates
        or cleanup.get("attempted") is not True
        or cleanup.get("succeeded") is not True
    ):
        return None
    return lane_result(
        LANE,
        "FAIL",
        "RECOVERY_INVARIANT_VIOLATION",
        "Retries, faults or cleanup left duplicate effects or an invalid recovered state.",
        details={
            "duplicate_effects": duplicates,
            "postcondition_failures": failures,
            "cleanup": cleanup,
            "retry_storm": retry_storm,
            "lost_updates": lost_updates,
        },
    )


def _operation_evidence(artifact: dict[str, Any], config: dict[str, Any]):
    operations = artifact["operations"]
    if not isinstance(operations, list) or not 2 <= len(operations) <= 64:
        return (
            None,
            None,
            None,
            _incomplete(
                "RECOVERY_OPERATIONS_INCOMPLETE",
                "Recovery needs 2..64 duplicate or concurrent operations.",
            ),
        )
    issue = _validate_concurrency(artifact, config, len(operations))
    if issue:
        return None, None, None, issue
    effects, attempts, issue = _collect_operations(operations)
    if issue:
        return None, None, None, issue
    if not any(count >= 2 for count in attempts.values()):
        issue = _incomplete(
            "RECOVERY_DUPLICATE_NOT_EXERCISED", "No idempotency key was replayed."
        )
        return None, None, None, issue
    return operations, effects, attempts, None


def _recovered_state(artifact: dict[str, Any], config: dict[str, Any]):
    recovered, issue = _phase_metrics(artifact["phases"])
    if issue:
        return None, None, issue
    failures, issue = _postcondition_failures(config.get("postconditions"), recovered)
    if issue:
        return None, None, issue
    cleanup = artifact["cleanup"]
    issue = _cleanup_evidence(cleanup)
    if issue:
        return None, None, issue
    return failures, cleanup, None


def evaluate_recovery(
    artifact: dict[str, Any],
    config: dict[str, Any],
    *,
    engine: str,
    engine_version: str,
) -> dict[str, Any]:
    """Evaluate signed fault coverage, retries, durable effects and cleanup."""
    validate_lane_policy(LANE, config)
    exact_keys(
        artifact,
        {
            "schema",
            "engine",
            "engine_version",
            "operations",
            "fault_modes",
            "phases",
            "cleanup",
            "max_concurrency",
            "fault_observed",
            "lost_updates",
        },
    )
    if not _identity_matches(artifact, engine, engine_version):
        return _incomplete(
            "RECOVERY_IDENTITY_MISMATCH",
            "Recovery evidence is not bound to the signed engine.",
        )
    observed_faults, issue = _required_faults(config, artifact)
    if issue:
        return issue
    operations, effects, attempts, issue = _operation_evidence(artifact, config)
    if issue:
        return issue
    failures, cleanup, issue = _recovered_state(artifact, config)
    if issue:
        return issue
    lost_updates = require_int(
        artifact["lost_updates"], "lost_updates", minimum=0, maximum=1000000
    )
    result = _invariant_result(
        effects, failures, attempts, config, lost_updates, cleanup
    )
    if result:
        return result
    return lane_result(
        LANE,
        "PASS",
        "RECOVERY_INVARIANTS_HELD",
        "The declared faults recovered without duplicate effects and cleanup completed.",
        details={"operations": len(operations), "fault_modes": sorted(observed_faults)},
    )
