"""Isolated migration, reader compatibility and data-integrity evaluation."""
from __future__ import annotations

from typing import Any

from .runtime_audit_common import exact_keys, lane_result, require_int, require_number, require_str, require_unique_strings
from .runtime_audit_policy import validate_lane_policy


def evaluate_migration(artifact: dict[str, Any], config: dict[str, Any], *, engine: str, engine_version: str) -> dict[str, Any]:
    """Evaluate isolated schema migration, data invariants, reader parity, catalog validity, locks, and recovery."""
    validate_lane_policy("migration_integrity", config)
    exact_keys(artifact, {"schema", "engine", "engine_version", "isolated", "before_schema_sha256", "after_schema_sha256", "history_valid", "drift_detected", "invariants", "record_counts", "integrity_violations", "readers", "recovery", "catalog_objects", "invalid_catalog_objects", "lock_wait_seconds"})
    if artifact["schema"] != "factory.runtime.migration.v1" or artifact["engine"] != engine or artifact["engine_version"] != engine_version:
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_IDENTITY_MISMATCH", "Migration evidence is not bound to the signed engine.")
    if artifact["isolated"] is not True:
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_NOT_ISOLATED", "The rehearsal did not attest an isolated database target.")
    expected_after = require_str(config.get("expected_after_schema_sha256"), "config.expected_after_schema_sha256", minimum=64, maximum=64)
    before = require_str(artifact["before_schema_sha256"], "before_schema_sha256", minimum=64, maximum=64)
    after = require_str(artifact["after_schema_sha256"], "after_schema_sha256", minimum=64, maximum=64)
    if before != config["before_schema_sha256"]:
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_BASELINE_MISMATCH", "The rehearsal did not begin from the approved schema.")
    required_invariants = config.get("invariants")
    if not isinstance(required_invariants, list) or not 1 <= len(required_invariants) <= 256:
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_INVARIANTS_MISSING", "Signed data invariants are absent.")
    expected: dict[str, str] = {}
    for item in required_invariants:
        if not isinstance(item, dict):
            return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_INVARIANT_INVALID", "A signed invariant is malformed.")
        exact_keys(item, {"id", "expected_sha256"})
        item_id = require_str(item["id"], "config.invariant.id")
        if item_id in expected:
            return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_DUPLICATE_INVARIANT", "Invariant IDs must be unique.")
        expected[item_id] = require_str(item["expected_sha256"], "config.invariant.expected_sha256", minimum=64, maximum=64)
    observations = artifact["invariants"]
    if not isinstance(observations, list) or not 1 <= len(observations) <= 256:
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_INVARIANTS_MISSING", "Invariant query evidence is absent.")
    actual: dict[str, str] = {}
    for item in observations:
        if not isinstance(item, dict):
            return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_INVARIANT_INVALID", "An invariant result is malformed.")
        exact_keys(item, {"id", "actual_sha256"})
        item_id = require_str(item["id"], "invariant.id")
        if item_id in actual:
            return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_DUPLICATE_INVARIANT", "Observed invariant IDs must be unique.")
        actual[item_id] = require_str(item["actual_sha256"], "invariant.actual_sha256", minimum=64, maximum=64)
    missing = sorted(set(expected) - set(actual))
    counts = artifact["record_counts"]
    if not isinstance(counts, list) or not 1 <= len(counts) <= 256:
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_COUNTS_MISSING", "Record-count comparisons are absent.")
    losses: list[dict[str, Any]] = []
    tables: set[str] = set()
    expected_counts = {item["id"]: item for item in config["tables"]}
    for item in counts:
        if not isinstance(item, dict):
            return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_COUNT_INVALID", "A record-count comparison is malformed.")
        exact_keys(item, {"table", "before", "after"})
        table = require_str(item["table"], "record_count.table")
        if table in tables:
            return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_DUPLICATE_COUNT", "Record-count tables must be unique.")
        tables.add(table)
        old = require_int(item["before"], "record_count.before", minimum=0, maximum=10**12)
        new = require_int(item["after"], "record_count.after", minimum=0, maximum=10**12)
        approved_counts = expected_counts.get(table)
        if approved_counts is None or (old, new) != (approved_counts["before"], approved_counts["after"]):
            losses.append({"table": table, "before": old, "after": new})
    if tables != set(expected_counts):
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_COUNTS_MISSING", "Not all approved tables were checked.")
    readers = artifact["readers"]
    recovery = artifact["recovery"]
    if not isinstance(readers, dict) or not isinstance(recovery, dict):
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_REHEARSAL_INCOMPLETE", "Reader or recovery evidence is missing.")
    exact_keys(readers, {"old", "new"})
    exact_keys(recovery, {"strategy", "exercised", "succeeded"})
    strategy = recovery.get("strategy")
    if strategy != config["recovery_strategy"]:
        return lane_result("migration_integrity", "INCOMPLETE", "MIGRATION_RECOVERY_MISSING", "Recovery strategy must be rollback or forward_fix.")
    invariant_failures = sorted(item_id for item_id, digest in expected.items() if actual.get(item_id) != digest)
    violations = require_int(artifact["integrity_violations"], "integrity_violations", minimum=0, maximum=1_000_000)
    catalog = require_unique_strings(artifact["catalog_objects"], "catalog_objects", minimum=1, maximum=256)
    invalid_catalog = require_unique_strings(artifact["invalid_catalog_objects"], "invalid_catalog_objects", minimum=0, maximum=256)
    missing_catalog = sorted(set(config["required_catalog_objects"]) - set(catalog))
    lock_wait = require_number(artifact["lock_wait_seconds"], "lock_wait_seconds")
    failures = {
        "after_schema_mismatch": after != expected_after,
        "history_invalid": artifact["history_valid"] is not True,
        "drift_detected": artifact["drift_detected"] is not False,
        "missing_invariants": missing,
        "invariant_failures": invariant_failures,
        "record_loss": losses,
        "integrity_violations": violations,
        "old_reader": readers.get("old"),
        "new_reader": readers.get("new"),
        "recovery": recovery,
        "missing_catalog_objects": missing_catalog,
        "invalid_catalog_objects": invalid_catalog,
        "lock_wait_seconds": lock_wait,
    }
    if after != expected_after or artifact["history_valid"] is not True or artifact["drift_detected"] is not False or missing or set(actual) - set(expected) or invariant_failures or losses or violations or readers.get("old") is not True or readers.get("new") is not True or recovery.get("exercised") is not True or recovery.get("succeeded") is not True or missing_catalog or invalid_catalog or lock_wait > config["max_lock_wait_seconds"]:
        return lane_result("migration_integrity", "FAIL", "MIGRATION_INTEGRITY_VIOLATION", "The rehearsal found schema drift, data loss, broken readers, or unproven recovery.", details={"before_schema_sha256": before, **failures})
    return lane_result("migration_integrity", "PASS", "MIGRATION_REHEARSAL_HELD", "The isolated migration preserved approved data invariants, both readers and recovery.", details={"before_schema_sha256": before, "after_schema_sha256": after, "invariants": len(expected), "record_counts": len(counts), "recovery_strategy": strategy})
