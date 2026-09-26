"""Isolated migration, reader compatibility and data-integrity evaluation."""

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


def _incomplete(code: str, message: str) -> dict[str, Any]:
    return lane_result("migration_integrity", "INCOMPLETE", code, message)


def _validate_identity(artifact: dict[str, Any], engine: str, version: str):
    if (
        artifact["schema"] != "factory.runtime.migration.v1"
        or artifact["engine"] != engine
        or artifact["engine_version"] != version
    ):
        return _incomplete(
            "MIGRATION_IDENTITY_MISMATCH",
            "Migration evidence is not bound to the signed engine.",
        )
    if artifact["isolated"] is not True:
        return _incomplete(
            "MIGRATION_NOT_ISOLATED",
            "The rehearsal did not attest an isolated database target.",
        )
    return None


def _schema_digests(artifact: dict[str, Any], config: dict[str, Any]):
    expected_after = require_str(
        config.get("expected_after_schema_sha256"),
        "config.expected_after_schema_sha256",
        minimum=64,
        maximum=64,
    )
    before = require_str(
        artifact["before_schema_sha256"], "before_schema_sha256", minimum=64, maximum=64
    )
    after = require_str(
        artifact["after_schema_sha256"], "after_schema_sha256", minimum=64, maximum=64
    )
    if before != config["before_schema_sha256"]:
        return None, _incomplete(
            "MIGRATION_BASELINE_MISMATCH",
            "The rehearsal did not begin from the approved schema.",
        )
    return (before, after, expected_after), None


def _digest_item(item: Any, values: dict[str, str], expected: bool):
    digest_key = "expected_sha256" if expected else "actual_sha256"
    id_key = "config.invariant.id" if expected else "invariant.id"
    duplicate = (
        "Invariant IDs must be unique."
        if expected
        else "Observed invariant IDs must be unique."
    )
    malformed = (
        "A signed invariant is malformed."
        if expected
        else "An invariant result is malformed."
    )
    if not isinstance(item, dict):
        return _incomplete("MIGRATION_INVARIANT_INVALID", malformed)
    exact_keys(item, {"id", digest_key})
    item_id = require_str(item["id"], id_key)
    if item_id in values:
        return _incomplete("MIGRATION_DUPLICATE_INVARIANT", duplicate)
    values[item_id] = require_str(
        item[digest_key], f"invariant.{digest_key}", minimum=64, maximum=64
    )
    return None


def _digest_map(items: Any, *, expected: bool):
    source_name = "signed data invariants" if expected else "Invariant query evidence"
    if not isinstance(items, list) or not 1 <= len(items) <= 256:
        return None, _incomplete(
            "MIGRATION_INVARIANTS_MISSING", f"{source_name} are absent."
        )
    values: dict[str, str] = {}
    for item in items:
        result = _digest_item(item, values, expected)
        if result:
            return None, result
    return values, None


def _record_count_losses(counts: Any, config: dict[str, Any]):
    if not isinstance(counts, list) or not 1 <= len(counts) <= 256:
        return None, _incomplete(
            "MIGRATION_COUNTS_MISSING", "Record-count comparisons are absent."
        )
    losses: list[dict[str, Any]] = []
    tables: set[str] = set()
    expected = {item["id"]: item for item in config["tables"]}
    for item in counts:
        if not isinstance(item, dict):
            return None, _incomplete(
                "MIGRATION_COUNT_INVALID", "A record-count comparison is malformed."
            )
        exact_keys(item, {"table", "before", "after"})
        table = require_str(item["table"], "record_count.table")
        if table in tables:
            return None, _incomplete(
                "MIGRATION_DUPLICATE_COUNT", "Record-count tables must be unique."
            )
        tables.add(table)
        old = require_int(
            item["before"], "record_count.before", minimum=0, maximum=10**12
        )
        new = require_int(
            item["after"], "record_count.after", minimum=0, maximum=10**12
        )
        approved = expected.get(table)
        if approved is None or (old, new) != (approved["before"], approved["after"]):
            losses.append({"table": table, "before": old, "after": new})
    if tables != set(expected):
        return None, _incomplete(
            "MIGRATION_COUNTS_MISSING", "Not all approved tables were checked."
        )
    return losses, None


def _reader_recovery(artifact: dict[str, Any], config: dict[str, Any]):
    readers, recovery = artifact["readers"], artifact["recovery"]
    if not isinstance(readers, dict) or not isinstance(recovery, dict):
        return None, _incomplete(
            "MIGRATION_REHEARSAL_INCOMPLETE", "Reader or recovery evidence is missing."
        )
    exact_keys(readers, {"old", "new"})
    exact_keys(recovery, {"strategy", "exercised", "succeeded"})
    strategy = recovery.get("strategy")
    if strategy != config["recovery_strategy"]:
        return None, _incomplete(
            "MIGRATION_RECOVERY_MISSING",
            "Recovery strategy must be rollback or forward_fix.",
        )
    return (readers, recovery, strategy), None


def _migration_failures(
    artifact,
    config,
    expected,
    actual,
    missing,
    losses,
    readers,
    recovery,
    after,
    expected_after,
):
    violations = require_int(
        artifact["integrity_violations"],
        "integrity_violations",
        minimum=0,
        maximum=1_000_000,
    )
    catalog = require_unique_strings(
        artifact["catalog_objects"], "catalog_objects", minimum=1, maximum=256
    )
    invalid_catalog = require_unique_strings(
        artifact["invalid_catalog_objects"],
        "invalid_catalog_objects",
        minimum=0,
        maximum=256,
    )
    missing_catalog = sorted(set(config["required_catalog_objects"]) - set(catalog))
    lock_wait = require_number(artifact["lock_wait_seconds"], "lock_wait_seconds")
    failures = {
        "after_schema_mismatch": after != expected_after,
        "history_invalid": artifact["history_valid"] is not True,
        "drift_detected": artifact["drift_detected"] is not False,
        "missing_invariants": missing,
        "invariant_failures": sorted(
            key for key, value in expected.items() if actual.get(key) != value
        ),
        "unexpected_invariants": sorted(set(actual) - set(expected)),
        "record_loss": losses,
        "integrity_violations": violations,
        "old_reader": readers.get("old"),
        "new_reader": readers.get("new"),
        "recovery": recovery,
        "missing_catalog_objects": missing_catalog,
        "invalid_catalog_objects": invalid_catalog,
        "lock_wait_seconds": lock_wait,
    }
    return failures


def _migration_failed_integrity(failures):
    if failures["after_schema_mismatch"] or failures["history_invalid"]:
        return True
    if failures["drift_detected"] or failures["missing_invariants"]:
        return True
    if failures["invariant_failures"] or failures["unexpected_invariants"]:
        return True
    if failures["record_loss"] or failures["integrity_violations"]:
        return True
    return False


def _migration_failed_compatibility(failures, config):
    if failures["old_reader"] is not True or failures["new_reader"] is not True:
        return True
    recovery = failures["recovery"]
    if recovery.get("exercised") is not True or recovery.get("succeeded") is not True:
        return True
    if failures["missing_catalog_objects"] or failures["invalid_catalog_objects"]:
        return True
    return bool(
        failures["missing_catalog_objects"]
        or failures["invalid_catalog_objects"]
        or failures["lock_wait_seconds"] > config["max_lock_wait_seconds"]
    )


def _migration_failed(failures, config):
    return _migration_failed_integrity(failures) or _migration_failed_compatibility(
        failures, config
    )


def _migration_result(
    before, after, expected_after, expected, counts, strategy, failures, failed
):
    if failed:
        return lane_result(
            "migration_integrity",
            "FAIL",
            "MIGRATION_INTEGRITY_VIOLATION",
            "The rehearsal found schema drift, data loss, broken readers, or unproven recovery.",
            details={"before_schema_sha256": before, **failures},
        )
    return lane_result(
        "migration_integrity",
        "PASS",
        "MIGRATION_REHEARSAL_HELD",
        "The isolated migration preserved approved data invariants, both readers and recovery.",
        details={
            "before_schema_sha256": before,
            "after_schema_sha256": after,
            "invariants": len(expected),
            "record_counts": len(counts),
            "recovery_strategy": strategy,
        },
    )


def evaluate_migration(
    artifact: dict[str, Any],
    config: dict[str, Any],
    *,
    engine: str,
    engine_version: str,
) -> dict[str, Any]:
    """Evaluate isolated migration integrity, compatibility, catalog, locks, and recovery."""
    validate_lane_policy("migration_integrity", config)
    exact_keys(
        artifact,
        {
            "schema",
            "engine",
            "engine_version",
            "isolated",
            "before_schema_sha256",
            "after_schema_sha256",
            "history_valid",
            "drift_detected",
            "invariants",
            "record_counts",
            "integrity_violations",
            "readers",
            "recovery",
            "catalog_objects",
            "invalid_catalog_objects",
            "lock_wait_seconds",
        },
    )
    result = _validate_identity(artifact, engine, engine_version)
    if result:
        return result
    digests, result = _schema_digests(artifact, config)
    if result:
        return result
    before, after, expected_after = digests
    expected, result = _digest_map(config.get("invariants"), expected=True)
    if result:
        return result
    actual, result = _digest_map(artifact["invariants"], expected=False)
    if result:
        return result
    losses, result = _record_count_losses(artifact["record_counts"], config)
    if result:
        return result
    reader_data, result = _reader_recovery(artifact, config)
    if result:
        return result
    readers, recovery, strategy = reader_data
    missing = sorted(set(expected) - set(actual))
    failures = _migration_failures(
        artifact,
        config,
        expected,
        actual,
        missing,
        losses,
        readers,
        recovery,
        after,
        expected_after,
    )
    return _migration_result(
        before,
        after,
        expected_after,
        expected,
        artifact["record_counts"],
        strategy,
        failures,
        _migration_failed(failures, config),
    )
