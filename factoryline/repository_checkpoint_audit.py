"""Source-bound repository checkpoints and trusted-core decision admission."""

from __future__ import annotations


def _full_repository_checkpoint_identity(
    value, root, scanner, configuration, inventory, context_profile="isolated-v1"
):
    """Reject altered profile, schema, scanner or source-generation bindings."""
    from .deep_audit_io import (
        FULL_REPOSITORY_BATCH_LIMIT,
        FULL_REPOSITORY_CHECKPOINT_SCHEMA,
        FULL_REPOSITORY_CONTEXT_CHECKPOINT_SCHEMA,
        FULL_REPOSITORY_CONTEXT_PROFILE,
        RuntimeAuditError,
        digest,
    )

    workspace = context_profile == FULL_REPOSITORY_CONTEXT_PROFILE
    keys = {
        "schema",
        "root",
        "scanner_identity_sha256",
        "configuration_sha256",
        "inventory_sha256",
        "inventory",
        "batch_primary_limit",
        "primary_results",
        "result_digest",
    }
    if workspace:
        keys.update({"context_profile", "context_generation_sha256"})
    expected_schema = (
        FULL_REPOSITORY_CONTEXT_CHECKPOINT_SCHEMA
        if workspace
        else FULL_REPOSITORY_CHECKPOINT_SCHEMA
    )
    if (
        set(value) != keys
        or value["schema"] != expected_schema
        or (workspace and value["context_profile"] != context_profile)
        or (
            workspace
            and (
                not isinstance(value["context_generation_sha256"], str)
                or len(value["context_generation_sha256"]) != 64
            )
        )
        or value["batch_primary_limit"] != FULL_REPOSITORY_BATCH_LIMIT
    ):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "checkpoint fields or schema differ"
        )
    if value["scanner_identity_sha256"] != scanner:
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "scanner identity changed since checkpoint"
        )
    if (
        value["root"] != root.as_posix()
        or value["configuration_sha256"] != configuration
        or value["inventory_sha256"] != digest(inventory)
        or value["inventory"] != inventory
    ):
        raise RuntimeAuditError(
            "SOURCE_DRIFT", "source inventory or configuration changed since checkpoint"
        )


def _full_repository_checkpoint_rows(value, inventory):
    """Require an ordered, duplicate-free prefix with an intact result digest."""
    from .deep_audit_io import (
        RuntimeAuditError,
        digest,
    )

    results = value["primary_results"]
    if (
        not isinstance(results, list)
        or len(results) > len(inventory)
        or value["result_digest"] != digest(results)
    ):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "checkpoint result digest or list is malformed"
        )
    paths = [row["path"] for row in inventory]
    if (
        paths != sorted(paths)
        or [row.get("path") for row in results if isinstance(row, dict)]
        != paths[: len(results)]
    ):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "checkpoint primary partition differs from inventory"
        )
    if len({row.get("path") for row in results if isinstance(row, dict)}) != len(
        results
    ):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "duplicate checkpoint primary path"
        )
    return results


def _full_repository_result_valid(row):
    """Check the saved result shape before any native revalidation or reuse."""
    return (
        isinstance(row, dict)
        and set(row)
        == {
            "path",
            "input_sha256",
            "input_state",
            "bytes",
            "status",
            "findings",
            "dependencies",
        }
        and row["status"]
        in {"audited", "syntax_error", "unreadable", "too_large", "unsupported"}
        and isinstance(row["findings"], list)
        and isinstance(row["dependencies"], dict)
    )


def _full_repository_discovery_policy(audit) -> dict:
    from .deep_audit_io import (
        RuntimeAuditError,
    )

    constants = audit._security_source_files.__code__.co_consts
    ignored = next((item for item in constants if isinstance(item, frozenset)), None)
    pattern = next((item for item in constants if item == "*.py"), None)
    if ignored is None or pattern is None:
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "native source discovery policy is not inspectable"
        )
    return {
        "engine": "native _security_source_files",
        "include_pattern": pattern,
        "include": "all discovered Python paths, including untracked files",
        "ignored_directory_names": sorted(ignored),
        "symlink_python_paths": "accounted as unreadable; never followed",
    }


def _full_repository_trusted_core_decision(generation, results):
    """Format a decision only after native workspace evidence passes admission."""
    from .deep_audit_io import (
        RuntimeAuditError,
        digest,
        require_digest,
    )

    from . import primitive_observation_binding as primitive

    blocked = primitive._trusted_core_policy_result()
    evidence = generation.get("workspace_evidence")
    if not isinstance(evidence, dict):
        return blocked
    sources = evidence.get("sources")
    oracle = evidence.get("oracle_context")
    coverage = evidence.get("audit_coverage")
    partition = evidence.get("primitive_partition")
    tiers = evidence.get("finding_tiers")
    findings = evidence.get("raw_findings")
    inventory = generation.get("inventory")
    if not all(
        isinstance(value, dict)
        for value in (sources, oracle, coverage, partition, tiers)
    ):
        return blocked
    if not isinstance(findings, list) or not isinstance(inventory, list):
        return blocked
    expected_paths = {row.get("path") for row in inventory if isinstance(row, dict)}
    source_rows = {row.get("path"): row for row in inventory if isinstance(row, dict)}
    if (
        len(source_rows) != len(inventory)
        or generation.get("collection_incomplete") is not False
        or sources.get("capture_complete") is not True
        or sources.get("files_discovered") != len(inventory)
        or sources.get("files_bound") != len(inventory)
        or oracle.get("state") != "captured"
        or coverage.get("complete") is not True
        or coverage.get("files_processed") != len(inventory)
        or partition.get("state") != "VALIDATED"
        or len(results) != len(inventory)
        or any(
            not isinstance(row, dict) or row.get("status") != "audited"
            for row in results
        )
        or not expected_paths
    ):
        return blocked
    try:
        current_tier_policy = primitive.finding_tier_policy_sha256()
        gate = tiers.get("defect_gate")
        ledger = tiers.get("ledger")
        supported, unresolved, expected_completeness = _trusted_core_ledger_counts(
            ledger
        )
        if (
            tiers.get("policy_sha256") != current_tier_policy
            or not isinstance(ledger, list)
            or not isinstance(findings, list)
            or len(ledger) != len(findings)
            or not isinstance(gate, dict)
            or gate.get("state")
            not in {"DEFECTS_PRESENT", "NO_SUPPORTED_DEFECTS_OBSERVED"}
            or gate.get("passed") is not False
            or gate.get("clean") is not False
            or gate.get("completeness_state") != expected_completeness
            or type(gate.get("supported_defect_count")) is not int
            or type(gate.get("needs_context_count")) is not int
            or gate.get("supported_defect_count") < 0
            or gate.get("needs_context_count") < 0
            or gate.get("supported_defect_count") != supported
            or gate.get("needs_context_count") != unresolved
            or not isinstance(tiers.get("tier_counts"), dict)
            or tiers["tier_counts"].get("SUPPORTED_DEFECT")
            != sum(
                isinstance(row, dict) and row.get("tier") == "SUPPORTED_DEFECT"
                for row in ledger or ()
            )
            or tiers["tier_counts"].get("NEEDS_CONTEXT")
            != sum(
                isinstance(row, dict) and row.get("tier") == "NEEDS_CONTEXT"
                for row in ledger or ()
            )
            or tiers.get("ledger_sha256") != digest(ledger)
        ):
            return blocked
        report_body = {
            key: value for key, value in tiers.items() if key != "report_sha256"
        }
        if tiers.get("report_sha256") != digest(report_body):
            return blocked
        if not _trusted_core_ledger_matches(
            findings, ledger, expected_paths, source_rows, primitive
        ):
            return blocked
        require_digest(sources.get("source_manifest_sha256"), "source manifest")
        policy_sha = blocked["policy_sha256"]
        evidence_payload = {
            "policy_id": "trusted-core-v1",
            "policy_sha256": policy_sha,
            "sources_sha256": sources["source_manifest_sha256"],
            "inventory_sha256": generation["inventory_hash"],
            "context_generation_sha256": generation.get("context_generation_sha256"),
            "scanner_identity_sha256": generation["scanner"],
            "configuration_sha256": generation["configuration"],
            "finding_tier_policy_sha256": current_tier_policy,
            "tier_report_sha256": tiers["report_sha256"],
            "tier_ledger_sha256": tiers["ledger_sha256"],
        }
        counts = (gate["supported_defect_count"], gate["needs_context_count"])
        if any(type(value) is not int for value in counts):
            return blocked
        return primitive._trusted_core_policy_result(evidence_payload, counts)
    except (KeyError, TypeError, ValueError, RuntimeAuditError):
        return blocked


def _trusted_core_ledger_matches(
    findings, ledger, expected_paths, source_rows, primitive
):
    for index, (raw, row) in enumerate(zip(findings, ledger, strict=True)):
        identity = row.get("source_identity") if isinstance(row, dict) else None
        if (
            not isinstance(raw, dict)
            or row.get("index") != index
            or row.get("raw_finding") != raw
            or not isinstance(identity, dict)
            or identity.get("path") != raw.get("path")
            or identity.get("path") not in expected_paths
            or identity.get("source_sha256")
            != source_rows[identity["path"]].get("sha256")
            or source_rows[identity["path"]].get("state") != "ready"
            or identity.get("identity_sha256")
            != primitive._tier_sha256(
                {
                    "index": index,
                    "path": identity.get("path"),
                    "source_sha256": identity.get("source_sha256"),
                    "code": raw.get("code"),
                    "line": raw.get("line"),
                    "column": raw.get("column"),
                    "original_severity": raw.get("severity"),
                    "raw_finding": raw,
                }
            )
        ):
            return False

    return True


def _trusted_core_ledger_counts(ledger):
    supported = sum(
        isinstance(row, dict)
        and row.get("tier") == "SUPPORTED_DEFECT"
        and row.get("gate_relevant") is True
        for row in ledger or ()
    )
    unresolved = sum(
        isinstance(row, dict)
        and row.get("tier") == "NEEDS_CONTEXT"
        and row.get("gate_relevant") is True
        for row in ledger or ()
    )
    expected_completeness = (
        "INCOMPLETE" if unresolved else "ASSESSED_WITHIN_DECLARED_SCOPE"
    )
    return supported, unresolved, expected_completeness
