"""Source-binding checks for retained primitive observations."""

import ast
import copy
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from pathlib import PurePosixPath
from contextvars import ContextVar

_ROLE_REBUILD_CONTEXT = ContextVar("factory-role-rebuild-context", default=None)

_FINDING_TIER_POLICY = {
    "schema": "factory.security.finding-tiers.v1",
    "tiers": ["SUPPORTED_DEFECT", "NEEDS_CONTEXT", "PROVEN_PRIMITIVE"],
    "supported_evidence": [
        "source_bound_native_security_precondition",
    ],
    "primitive_evidence": "current_native_source_bound_primitive_partition",
    "unknown_evidence": "NEEDS_CONTEXT",
    "pickle_byte_origin": "source_edge_observation_only; reconstruction_effects_remain_unassessed",
    "known_format_patterns": "factory.context_efficiency._SECRET_BYTES",
    "known_format_policy": "material_observation_only; authority_and_validity_not_established",
    "configuration_load_policy": "static_consumer_observation_only; authority_not_established",
    "claims": "no_precision_or_held_out_measurement",
}

_MISSING_PREMISES = {
    "SECURITY_LITERAL_HTTP_CREDENTIAL": [
        "operational_authority",
        "reachability",
    ],
    "SECURITY_HARDCODED_SECRET": [
        "operative_credential_consumer",
        "security_authority_binding",
        "reachability",
    ],
    "SECURITY_DYNAMIC_EXECUTION": [
        "untrusted_code_input_or_equivalent_effect",
    ],
    "SECURITY_OS_COMMAND": [
        "untrusted_command_input_or_equivalent_effect",
    ],
    "SECURITY_SHELL_COMMAND": [
        "untrusted_command_input_or_equivalent_effect",
    ],
    "SECURITY_UNSAFE_DESERIALIZATION": [
        "external_or_mutable_serialized_data_provenance",
        "dangerous_load_reachability",
    ],
    "SECURITY_WEAK_TLS": ["reachable_remote_endpoint_or_operational_context"],
    "SECURITY_LOG_INJECTION": [
        "untrusted_log_value",
        "log_record_injection_effect",
    ],
    "SECURITY_SQL_INJECTION": [
        "untrusted_query_dataflow",
        "database_execution_effect",
    ],
}

_SECURITY_DEFECT_POLICIES = frozenset(
    {
        "legacy-v1",
        "trusted-core-v1",
        "source-role-v1",
        "source-role-v2",
        "source-role-v3",
    }
)
_PICKLE_SOURCE_ROLE_POLICY = {
    "schema": "factory.security.source-role-policy.v1",
    "policy_id": "source-role-v1",
    "effect": "source-bound test roundtrips and paired local worker protocols become NEEDS_CONTEXT reviews; original severity retained",
    "unassessed": [
        "serializer runtime identity",
        "object reconstruction",
        "dynamic deployment/discovery",
    ],
    "claim_boundary": "Output-policy selection, not a safe reconstruction, legacy detector gain or clean security result.",
}
_SOURCE_ROLE_POLICY_V2 = {
    **_PICKLE_SOURCE_ROLE_POLICY,
    "schema": "factory.security.source-role-policy.v2",
    "policy_id": "source-role-v2",
    "effect": "v1 roles plus captured registered fixture-harness operations become NEEDS_CONTEXT reviews; raw diagnostics and severity retained",
    "unassessed": [
        *_PICKLE_SOURCE_ROLE_POLICY["unassessed"],
        "fixture payloads and filesystem authority",
        "operation and callback effects",
    ],
    "claim_boundary": "Explicit queue selection, not operation safety, detector improvement, held-out precision or a clean security result.",
}
_SOURCE_ROLE_POLICY_V3 = {
    **_SOURCE_ROLE_POLICY_V2,
    "schema": "factory.security.source-role-policy.v3",
    "policy_id": "source-role-v3",
    "effect": "v2 plus captured literal process inputs become NEEDS_CONTEXT reviews; every raw diagnostic and severity retained",
    "unassessed": [
        *_SOURCE_ROLE_POLICY_V2["unassessed"],
        "command effects, shell interpretation, executable/environment, filesystem/cwd, credentials/network and deployment authority",
    ],
}
_TRUSTED_CORE_POLICY = {
    "schema": "factory.security.defect-policy.v1",
    "policy_id": "trusted-core-v1",
    "supported_state": "DEFECTS_PRESENT",
    "review_state": "NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED",
    "unresolved_exit_code": 2,
    "empty_exit_code": 0,
    "incomplete_state": "BLOCKED",
    "claim_boundary": "No clean security result, accuracy gain, or release approval.",
}


def validate_security_defect_policy(value):
    """Validate the closed policy selector before source discovery begins."""
    if type(value) is not str or value not in _SECURITY_DEFECT_POLICIES:
        raise ValueError(
            "defect policy must be legacy-v1, trusted-core-v1, source-role-v1, source-role-v2 or source-role-v3"
        )
    return value


def _trusted_core_policy_result(evidence_payload=None, counts=None):
    """Format a native caller's decision; this helper grants no evidence authority."""
    decision = {
        "schema": _TRUSTED_CORE_POLICY["schema"],
        "policy_id": "trusted-core-v1",
        "policy_sha256": _tier_sha256(_TRUSTED_CORE_POLICY),
        "state": "BLOCKED",
        "exit_code": 2,
        "passed": False,
        "clean": False,
        "release_approved": False,
        "action_summary": "Trusted-core policy admission is incomplete; retain the scan for review.",
        "source_sha256": None,
        "evidence_sha256": None,
        "supported_defect_count": 0,
        "needs_context_count": 0,
        "claim_boundary": _TRUSTED_CORE_POLICY["claim_boundary"],
    }
    if evidence_payload is None or counts is None:
        return decision
    supported, unresolved = counts
    if supported:
        state, exit_code = "DEFECTS_PRESENT", 1
        summary = (
            f"{supported} supported security defect(s) found; "
            f"{unresolved} unresolved item(s) remain for review."
        )
    else:
        state = _TRUSTED_CORE_POLICY["review_state"]
        exit_code = _TRUSTED_CORE_POLICY[
            "unresolved_exit_code" if unresolved else "empty_exit_code"
        ]
        summary = (
            "No supported security defects were regenerated; "
            f"{unresolved} unresolved item(s) remain for review. "
            "This is not a clean security result or release approval."
        )
    decision.update(
        state=state,
        exit_code=exit_code,
        action_summary=summary,
        source_sha256=evidence_payload["sources_sha256"],
        evidence_sha256=_tier_sha256(evidence_payload),
        supported_defect_count=supported,
        needs_context_count=unresolved,
    )
    return decision


def security_defect_policy_decision(
    core, captured_sources, prior_tiers=None, prior_source_state=None
):
    """Regenerate trusted-core admission from the complete captured native scan."""
    policy_id = validate_security_defect_policy(core.get("selected_defect_policy"))
    if policy_id != "trusted-core-v1":
        return None
    decision = _trusted_core_policy_result()
    try:
        if prior_source_state in {"INCOMPLETE", "NO_SOURCES"}:
            return decision
        regenerated, sources_sha256, source_findings = _trusted_core_regenerated_tiers(
            core, captured_sources
        )
        if regenerated is None:
            return decision
        actual = core.get("finding_tier_report")
        expected_rows = _security_tier_rows(regenerated)
        if not _security_tier_reports_match(actual, expected_rows, prior_tiers):
            return decision

        supported = regenerated["defect_gate"]["supported_defect_count"]
        unresolved = regenerated["defect_gate"]["needs_context_count"]
        evidence_payload = {
            "policy_id": policy_id,
            "policy_sha256": decision["policy_sha256"],
            "sources_sha256": sources_sha256,
            "tenant_contract_sha256": _tier_sha256(
                core.get("tenant_read_contract", {})
            ),
            "oracle_context_sha256": _tier_sha256(core.get("oracle_context", {})),
            "database_context_sha256": _tier_sha256(core.get("database_context", {})),
            "native_security_findings_sha256": _tier_sha256(source_findings),
            "tier_report_sha256": regenerated["report_sha256"],
            "tier_ledger_sha256": regenerated["ledger_sha256"],
        }
        return _trusted_core_policy_result(evidence_payload, (supported, unresolved))
    except Exception:
        return decision
    return decision


def _security_tier_reports_match(actual, expected_rows, prior_tiers):
    actual_rows = _security_tier_rows(actual)
    if actual_rows is None or expected_rows is None or actual_rows != expected_rows:
        return False
    if prior_tiers is not None:
        prior_rows = _security_tier_rows(prior_tiers)
        if prior_rows is None or prior_rows != expected_rows:
            return False
    return True


def _trusted_core_regenerated_tiers(core, captured_sources):
    from . import review_audits as audit

    sources = _trusted_core_complete_sources(core, captured_sources, audit)
    if sources is None:
        return None, None, None
    captured, captured_paths, sources_sha256 = sources
    tenant = _trusted_core_tenant_arguments(core, audit)
    if tenant is None:
        return None, None, None
    native_rows = _trusted_core_native_security_rows(captured_paths, tenant, audit)
    if native_rows is None or not _trusted_core_surface_matches(core, native_rows):
        return None, None, None
    regenerated = build_finding_tier_report(
        native_rows,
        core.get("primitive_observations", []),
        core["sources"],
        captured,
        coverage_state=True,
        partition_state="VALIDATED",
    )
    return regenerated, sources_sha256, native_rows


def _trusted_core_complete_sources(core, captured_sources, audit):
    sources = core.get("sources")
    coverage = core.get("audit_coverage")
    if (
        core.get("schema") != audit.SECURITY_SCHEMA
        or core.get("marker") != "SECURITY_AUDIT_COMPLETE"
        or not isinstance(sources, list)
        or not sources
        or not isinstance(coverage, dict)
        or coverage.get("complete") is not True
        or coverage.get("inventory_complete") is not True
        or coverage.get("measurement_state") != "complete"
        or coverage.get("files_discovered") != len(sources)
        or coverage.get("files_attempted") != len(sources)
        or coverage.get("files_audited") != len(sources)
        or core.get("files_scanned") != len(sources)
        or core.get("parse_errors") != 0
        or core.get("unreadable_sources") != 0
        or core.get("oversized_sources") != 0
        or not isinstance(captured_sources, dict)
        or core.get("provider_analysis_profile") is not None
        or not _trusted_core_database_context_valid(core.get("database_context"))
    ):
        return None

    bindings = {}
    for row in sources:
        validated = _trusted_core_source_binding(row)
        if validated is None or validated[0] in bindings:
            return None
        path, digest = validated
        bindings[path] = digest
    if set(captured_sources) != set(bindings) or len(bindings) != len(sources):
        return None
    if len(bindings) > audit.MAX_SECURITY_SOURCE_FILES:
        return None

    total_bytes = 0
    captured = {}
    captured_paths = {}
    for path, digest in bindings.items():
        raw = captured_sources.get(path)
        if not isinstance(raw, bytes) or len(raw) > audit.MAX_BYTES:
            return None
        total_bytes += len(raw)
        if total_bytes > 32 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
            return None
        captured[path] = raw
        captured_paths[Path(path)] = raw
    return captured, captured_paths, _tier_sha256(sources)


def _trusted_core_source_binding(row):
    if not isinstance(row, dict):
        return None
    path, digest = row.get("path"), row.get("sha256")
    if not isinstance(path, str):
        return None
    relative = PurePosixPath(path)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or relative.as_posix() != path
        or relative.suffix != ".py"
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        return None
    return path, digest


def _trusted_core_database_context_valid(value):
    if value in (None, {}):
        return True
    return isinstance(value, dict) and value.get("status") in {
        "COMPLETE",
        "NOT_APPLICABLE",
    }


def _unknown_collection(core):
    oracle = core.get("oracle_context")
    capture = oracle.get("pytest_collection") if isinstance(oracle, dict) else None
    return isinstance(capture, dict) and capture.get("collection_state") == "UNKNOWN"


def _trusted_core_tenant_arguments(core, audit):
    oracle_context = core.get("oracle_context", {})
    if not isinstance(oracle_context, dict):
        return None
    pytest_capture = oracle_context.get("pytest_collection")
    if _unknown_collection(core) or (
        isinstance(pytest_capture, dict)
        and pytest_capture.get("capture_state") != "stable_pre_post"
    ):
        return None

    tenant = core.get("tenant_read_contract", {})
    if not isinstance(tenant, dict):
        return None
    configuration = tenant.get("configuration")
    if "pytest_collection" in oracle_context:
        if (
            not isinstance(configuration, dict)
            or configuration.get("state") != "loaded"
        ):
            return None
    elif configuration is not None and (
        not isinstance(configuration, dict) or configuration.get("state") != "loaded"
    ):
        return None
    calls = tenant.get("calls", [])
    argument_bindings = tenant.get("argument_bindings", {})
    applies = tenant.get("policy_applies", False)
    if (
        not isinstance(calls, list)
        or not isinstance(argument_bindings, dict)
        or type(applies) is not bool
    ):
        return None
    try:
        calls = audit._tenant_contract_calls(tuple(calls))
        if any(
            not isinstance(call, str)
            or not isinstance(rows, list)
            or any(not isinstance(row, str) for row in rows)
            for call, rows in argument_bindings.items()
        ):
            return None
        binding_rows = tuple(
            f"{call}={binding}"
            for call, rows in argument_bindings.items()
            for binding in rows
        )
        argument_bindings = audit._tenant_contract_bindings(binding_rows, calls)
    except Exception:
        return None
    return calls, argument_bindings, applies


def _trusted_core_native_security_rows(captured_paths, tenant, audit):
    calls, argument_bindings, applies = tenant
    native_rows = []
    source_context = (Path("."), captured_paths)
    for path, raw in captured_paths.items():
        tree = ast.parse(raw)
        rows = audit._security_scan_tree(
            Path("."),
            path,
            tree,
            calls,
            argument_bindings,
            {"_security_source_context": source_context},
            tenant_policy_applies=applies,
            security_only=True,
        )
        native_rows.extend(
            row
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("code"), str)
            and row["code"].startswith("SECURITY_")
        )
    native_rows.sort(
        key=lambda row: (
            row.get("path", ""),
            row.get("line", 0),
            row.get("column", 0),
            row.get("code", ""),
        )
    )

    return native_rows


def _trusted_core_surface_matches(core, native_rows):
    surface = [
        row
        for field in ("findings", "primitive_observations")
        for row in core.get(field, [])
        if isinstance(row, dict)
        and isinstance(row.get("code"), str)
        and row["code"].startswith("SECURITY_")
    ]
    surface_ids = sorted(
        (
            row.get("path"),
            row.get("line"),
            row.get("column", 0),
            row.get("code"),
            row.get("severity"),
        )
        for row in surface
    )
    native_ids = sorted(
        (
            row.get("path"),
            row.get("line"),
            row.get("column", 0),
            row.get("code"),
            row.get("severity"),
        )
        for row in native_rows
    )
    return surface_ids == native_ids


def _security_tier_rows(report):
    if not isinstance(report, dict) or not isinstance(report.get("ledger"), list):
        return None
    rows = []
    for row in report["ledger"]:
        raw = row.get("raw_finding") if isinstance(row, dict) else None
        if not isinstance(raw, dict) or not str(raw.get("code", "")).startswith(
            "SECURITY_"
        ):
            continue
        rows.append(
            {
                "raw_finding": raw,
                "tier": row.get("tier"),
                "evidence": row.get("evidence"),
                "evidence_details": row.get("evidence_details"),
                "credential_authority_observation": row.get(
                    "credential_authority_observation"
                ),
                "static_consumer_observation": row.get("static_consumer_observation"),
                "byte_origin_observation": row.get("byte_origin_observation"),
                "missing_premises": row.get("missing_premises"),
            }
        )
    return sorted(rows, key=_tier_sha256)


def finding_tier_policy_sha256():
    """Return the digest bound into the full-workspace context generation."""
    return _tier_sha256(_FINDING_TIER_POLICY)


def build_finding_tier_report(
    raw_findings,
    primitive_observations,
    sources,
    source_bytes,
    *,
    coverage_state,
    partition_state,
):
    """Classify raw findings additively while retaining every original diagnostic."""
    raw_findings = list(raw_findings)
    sources = sources if isinstance(sources, list) else []
    source_bytes = source_bytes if isinstance(source_bytes, dict) else {}
    primitive_observations = (
        primitive_observations if isinstance(primitive_observations, list) else []
    )
    bindings = {
        row.get("path"): row.get("sha256")
        for row in sources
        if isinstance(row, dict)
        and isinstance(row.get("path"), str)
        and isinstance(row.get("sha256"), str)
    }
    regenerated = {}
    signing_cache = {}
    pickle_origin_cache = {}
    primitive_rows = [row for row in primitive_observations if isinstance(row, dict)]
    ledger = [
        _finding_tier_ledger_row(
            index,
            raw,
            bindings,
            source_bytes,
            (regenerated, signing_cache, pickle_origin_cache),
            primitive_rows,
            coverage_state,
            partition_state,
        )
        for index, raw in enumerate(raw_findings)
    ]

    tiers = {
        name: sum(row["tier"] == name for row in ledger)
        for name in (
            "SUPPORTED_DEFECT",
            "NEEDS_CONTEXT",
            "PROVEN_PRIMITIVE",
        )
    }
    total = len(ledger)
    abstentions = tiers["NEEDS_CONTEXT"]
    report = {
        "schema": _FINDING_TIER_POLICY["schema"],
        "policy_sha256": finding_tier_policy_sha256(),
        "raw_diagnostics": _raw_diagnostic_summary(raw_findings, total),
        "tier_counts": tiers,
        "rule_scorecards": _finding_rule_scorecards(ledger),
        "abstention": {
            "count": abstentions,
            "denominator": total,
            "fraction": abstentions / total if total else None,
            "scope": "this_run_raw_diagnostics",
        },
        "retention_metrics": {
            "scope": "within_run_raw_diagnostic_representation_only",
            "raw_diagnostic_retention": {
                "retained": len(ledger),
                "denominator": total,
                "fraction": len(ledger) / total if total else None,
            },
            "known_true_positive_retention": "NOT_MEASURED_NO_LABELLED_HELD_OUT_COHORT",
            "supported_defect_retention": "NOT_MEASURED_NO_LABELLED_HELD_OUT_COHORT",
        },
        "claim_policy": {
            "precision": "NOT_MEASURED",
            "held_out_precision": "NOT_MEASURED",
            "known_true_positive_retention": "NOT_MEASURED",
            "fresh_score_claim": "NOT_AUTHORIZED",
            "interpretation": "Tier counts and abstention are run-local classifications, not accuracy measurements.",
        },
        "validation": {
            "coverage_state": coverage_state,
            "partition_state": partition_state,
        },
        "defect_gate": _finding_tier_defect_gate(
            tiers, ledger, coverage_state, partition_state
        ),
        "ledger": ledger,
    }
    report["ledger_sha256"] = _tier_sha256(ledger)
    report["report_sha256"] = _tier_sha256(report)
    return report


def _finding_native_rows(finding, captured, bound, cache, sources=None, bindings=None):
    facts = finding.get("facts", {})
    if not bound or not (
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        or isinstance(facts, dict)
        and isinstance(facts.get("security_precondition"), dict)
    ):
        return []
    path = finding["path"]
    if path not in cache:
        key = ("independent_source_model",)
        if key not in cache:
            cache[key] = _regenerate_source_model(sources, bindings)
        cache[path] = _regenerate_native_findings(
            path, captured, source_model=cache[key]
        )
    return cache[path]


def _pickle_byte_origin_fields(finding, captured, bound, cache, tier):
    origin = _finding_pickle_byte_origin(finding, captured, bound, cache)
    if origin is None:
        return {}
    fields = {"byte_origin_observation": origin}
    if tier == "NEEDS_CONTEXT":
        fields["missing_premises"] = [
            "serializer_provider_identity",
            "reconstruction_effects_and_input_authority",
            "operational_reachability",
        ]
    return fields


def _finding_pickle_byte_origin(finding, captured, bound, cache):
    """Add independently rebuilt byte provenance without changing finding authority."""
    if not bound or finding.get("code") != "SECURITY_UNSAFE_DESERIALIZATION":
        return None
    path = finding["path"]
    if path not in cache:
        cache[path] = _pickle_byte_origins_for_source(path, captured)
    entry = cache[path].get((finding.get("line"), finding.get("column")))
    facts = finding.get("facts", {})
    if (
        entry is None
        or not isinstance(facts, dict)
        or facts.get("call") != entry["native_call"]
    ):
        return None
    return {
        **entry["origin"],
        "source_path": path,
        "source_sha256": hashlib.sha256(captured).hexdigest(),
    }


def _pickle_byte_origins_for_source(path, captured):
    from . import review_audits as audit
    from .runtime_audit_integrity import (
        _conditional_file_aliases,
        _conditional_module_name,
        _conditional_provider_parents,
        local_pickle_byte_origin,
    )

    try:
        tree = ast.parse(captured)
        aliases = _conditional_file_aliases(
            path, tree, {path: _conditional_module_name(path)}
        )
        if aliases is None:
            return {}
        _conditional_provider_parents(tree)
        result = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = audit._normalized_call_name(node, aliases)
            observation = local_pickle_byte_origin(node, call_name, aliases, audit)
            if observation is not None:
                result[(node.lineno, node.col_offset)] = {
                    "origin": observation,
                    "native_call": call_name,
                }
        return result
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return {}


def _finding_signing_evidence(
    finding, native_rows, bound, captured, bindings, coverage, partition, cache
):
    if not (
        bound
        and finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and isinstance(finding.get("facts"), dict)
        and finding["facts"].get("name") == "SECRET_KEY"
        and (coverage is True or coverage == "COMPLETE")
        and partition == "VALIDATED"
        and _matches_regenerated_finding(finding, native_rows)
    ):
        return None
    from .semantic_credential_sensor import (
        signing_configuration_inventory,
        signing_configuration_evidence,
    )

    if "inventory" not in cache:
        cache["inventory"] = signing_configuration_inventory(captured, bindings)
    return signing_configuration_evidence(finding, cache["inventory"])


def _finding_private_key_authentication_evidence(
    finding, native_rows, bound, captured, bindings, coverage, partition, cache
):
    if not (
        bound
        and finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and finding.get("severity") == "CRITICAL"
        and (coverage is True or coverage == "COMPLETE")
        and partition == "VALIDATED"
        and _matches_regenerated_finding(finding, native_rows)
    ):
        return None
    from .semantic_credential_sensor import (
        private_key_authentication_evidence,
        signing_configuration_inventory,
    )

    if "inventory" not in cache:
        cache["inventory"] = signing_configuration_inventory(captured, bindings)
    return private_key_authentication_evidence(finding, cache["inventory"])


def _finding_flask_session_authority_evidence(
    finding, native_rows, bound, captured, bindings, coverage, partition, cache
):
    if not (
        bound
        and finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and isinstance(finding.get("facts"), dict)
        and isinstance(finding["facts"].get("name"), str)
        and (coverage is True or coverage == "COMPLETE")
        and partition == "VALIDATED"
        and _matches_regenerated_finding(finding, native_rows)
    ):
        return None
    from .semantic_credential_sensor import (
        flask_credential_authority_evidence,
        signing_configuration_inventory,
    )

    if "inventory" not in cache:
        cache["inventory"] = signing_configuration_inventory(captured, bindings)
    return flask_credential_authority_evidence(finding, cache["inventory"])


def _decide_finding_tier(
    finding, bound, native_rows, primitives, credential_evidence=None
):
    if bound and credential_evidence is not None:
        if (
            credential_evidence.get("proof_scope")
            == "source_bound_flask_session_authority"
        ):
            return "SUPPORTED_DEFECT", "source_bound_flask_session_authority", None
        return (
            "SUPPORTED_DEFECT",
            "source_bound_private_key_http_authentication_flow",
            None,
        )
    if bound and _matches_regenerated_precondition_finding(finding, native_rows):
        return "SUPPORTED_DEFECT", "source_bound_native_security_precondition", None
    if bound and _matches_proven_primitive(finding, primitives):
        return (
            "PROVEN_PRIMITIVE",
            "current_native_source_bound_primitive_partition",
            None,
        )
    return "NEEDS_CONTEXT", None, None


def _finding_missing_premises(finding, bound):
    if str(finding.get("code", "")).startswith("QUALITY_"):
        return ["security_relevance_or_effect_scope"]
    if not bound:
        return ["source_byte_binding"]
    return list(
        _MISSING_PREMISES.get(
            str(finding.get("code", "")),
            ["source_provenance", "dangerous_effect", "operational_context"],
        )
    )


def _finding_rule_scorecards(ledger):
    """Run-local yield and abstention; never invent labels or confidence."""
    rows = []
    for code in sorted({str(row["source_identity"]["code"]) for row in ledger}):
        selected = [
            row for row in ledger if str(row["source_identity"]["code"]) == code
        ]
        counts = {
            tier: sum(row["tier"] == tier for row in selected)
            for tier in _FINDING_TIER_POLICY["tiers"]
        }
        rows.append(
            {
                "rule_id": code,
                "lane": "security" if code.startswith("SECURITY_") else "other",
                "raw_count": len(selected),
                "tier_counts": counts,
                "abstention_count": counts["NEEDS_CONTEXT"],
                "measured_actionable_precision": None,
                "decided_labels": 0,
                "confidence_interval": None,
                "label_provenance": "NOT_SUPPLIED",
                "promotion_state": "EXPERIMENTAL_UNMEASURED",
                "raw_severities_preserved": True,
                "claim": "These counts describe this run; rule accuracy is not measured.",
            }
        )
    return rows


def _finding_tier_defect_gate(tiers, ledger, coverage_state, partition_state):
    coverage_complete = coverage_state is True or coverage_state == "COMPLETE"
    partition_valid = partition_state == "VALIDATED"
    unresolved = sum(
        row["tier"] == "NEEDS_CONTEXT" and row.get("gate_relevant") is True
        for row in ledger
    )
    supported = sum(
        row["tier"] == "SUPPORTED_DEFECT" and row.get("gate_relevant") is True
        for row in ledger
    )
    if not coverage_complete or not partition_valid:
        reason = "coverage_or_partition_incomplete"
    elif supported:
        reason = "supported_defect_observed"
    else:
        reason = "no_supported_defect_observed"
    return {
        "state": "BLOCKED"
        if not coverage_complete or not partition_valid
        else "DEFECTS_PRESENT"
        if supported
        else "NO_SUPPORTED_DEFECTS_OBSERVED",
        "blocks_on_supported_defects": bool(supported),
        "completeness_state": "INCOMPLETE"
        if unresolved or not coverage_complete or not partition_valid
        else "ASSESSED_WITHIN_DECLARED_SCOPE",
        "passed": False,
        "clean": False,
        "reason": reason,
        "supported_defect_count": supported,
        "needs_context_count": unresolved,
        "claim": "This tier report does not establish a clean security result.",
    }


def _tier_sha256(value):
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _regenerate_native_findings(path, source_bytes, *, source_model=None):
    """Re-run only the native security producer against the bound source bytes."""
    try:
        relative = PurePosixPath(path)
        if relative.is_absolute() or ".." in relative.parts:
            return []
        from . import review_audits as audit

        root = Path(".") if source_model is None else source_model.root
        source_path = root.joinpath(*relative.parts)
        from .credential_role_constructor_provider import security_snapshot_model

        if source_model is None:
            tree = ast.parse(source_bytes)
            tree._oracle_source_sha256 = hashlib.sha256(source_bytes).hexdigest()
            model = security_snapshot_model(
                root,
                {source_path: tree},
                {source_path: source_bytes},
                {source_path: audit._oracle_tree_fingerprint(tree)},
            )
        else:
            model = source_model
            if model.source_bytes.get(
                source_path
            ) != source_bytes or not model.validate(source_path):
                return []
            tree = model.snapshots[source_path]
        return audit._security_scan_tree(
            root,
            source_path,
            tree,
            oracle_context={
                "_security_source_model": model,
                "_security_source_context": (root, model.source_bytes),
            },
        )
    except Exception:
        return []


def _regenerate_source_model(sources, bindings):
    """Build a verifier-owned graph once from the complete hash-checked Python set."""
    if not isinstance(sources, dict) or not isinstance(bindings, dict):
        return None
    selected = {name: raw for name, raw in sources.items() if str(name).endswith(".py")}
    hashes = {
        name: digest for name, digest in bindings.items() if str(name).endswith(".py")
    }
    captured = _jwt_bound_source_inventory(selected, hashes)
    if (
        captured is None
        or len(captured) > 2000
        or any(len(raw) > 1_000_000 for raw in captured.values())
        or sum(map(len, captured.values())) > 32_000_000
    ):
        return None
    from .credential_role_constructor_provider import security_snapshot_model
    from .review_audits import _oracle_tree_fingerprint

    try:
        trees = {
            path: ast.parse(raw, filename=path.as_posix())
            for path, raw in captured.items()
        }
        for path, tree in trees.items():
            tree._oracle_source_sha256 = hashes[path.as_posix()]
        return security_snapshot_model(
            Path("."),
            trees,
            captured,
            {path: _oracle_tree_fingerprint(tree) for path, tree in trees.items()},
        )
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        return None


def _matches_regenerated_finding(finding, native_rows):
    facts = finding.get("facts", {})
    return any(
        candidate.get("code") == finding.get("code")
        and candidate.get("path") == finding.get("path")
        and candidate.get("line") == finding.get("line")
        and candidate.get("column") == finding.get("column")
        and candidate.get("facts", {}).get("name") == facts.get("name")
        for candidate in native_rows
        if isinstance(candidate, dict) and isinstance(candidate.get("facts"), dict)
    )


def _matches_regenerated_precondition_finding(finding, native_rows):
    facts = finding.get("facts", {})
    premise = facts.get("security_precondition") if isinstance(facts, dict) else None
    if not _valid_security_precondition(premise, finding):
        return False
    for candidate in native_rows:
        if not isinstance(candidate, dict) or not isinstance(
            candidate.get("facts"), dict
        ):
            continue
        if any(
            candidate.get(key) != finding.get(key)
            for key in ("code", "path", "line", "column")
        ):
            continue
        regenerated = candidate["facts"].get("security_precondition")
        if regenerated == premise:
            return True
        if isinstance(regenerated, dict) and "input_value_flow" not in premise:
            # Independent reconstruction may add a witness to a minimal v1
            # claim. Every supplied field still requires exact equality.
            core = {
                key: value
                for key, value in regenerated.items()
                if key != "input_value_flow"
            }
            if core == premise:
                return True
    return False


def _valid_security_precondition(premise, finding):
    return (
        isinstance(premise, dict)
        and premise.get("schema") == "factory.security.precondition.v1"
        and premise.get("status") == "SUPPORTED"
        and premise.get("source_role") in {"untrusted_request", "untrusted_input"}
        and isinstance(premise.get("consumer_role"), str)
        and bool(premise.get("consumer_role"))
        and premise.get("proof_scope") == "local_static_wiring"
        and premise.get("runtime_execution") == "not_performed"
        and premise.get("deployment") == "UNASSESSED"
        and isinstance(premise.get("sink_span"), list)
        and len(premise["sink_span"]) == 4
        and all(type(value) is int and value >= 0 for value in premise["sink_span"])
        and premise["sink_span"][:2] == [finding.get("line"), finding.get("column", 0)]
    )


def _known_format_declaration(finding, source_bytes):
    if finding.get("code") != "SECURITY_HARDCODED_SECRET":
        return False
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, TypeError, ValueError, UnicodeError):
        return False
    facts = finding.get("facts", {})
    name = facts.get("name") if isinstance(facts, dict) else None
    for node in ast.walk(tree):
        if (
            not isinstance(node, (ast.Assign, ast.AnnAssign))
            or node.lineno != finding.get("line")
            or node.col_offset != finding.get("column", 0)
        ):
            continue
        value_node = node.value
        if not isinstance(value_node, ast.Constant) or type(value_node.value) not in {
            str,
            bytes,
        }:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            continue
        value = (
            value_node.value.encode("utf-8")
            if isinstance(value_node.value, str)
            else value_node.value
        )
        from .context_efficiency import _SECRET_BYTES

        return any(pattern.search(value) is not None for pattern in _SECRET_BYTES)
    return False


def _matches_proven_primitive(finding, observations):
    facts = finding.get("facts", {})
    return any(
        row.get("code") == finding.get("code")
        and row.get("path") == finding.get("path")
        and row.get("line") == finding.get("line")
        and row.get("column", 0) == finding.get("column", 0)
        and row.get("severity") == finding.get("severity")
        and isinstance(row.get("facts"), dict)
        and isinstance(facts, dict)
        and all(row["facts"].get(key) == value for key, value in facts.items())
        for row in observations
    )


def fixed_primitive_binding(finding, sources, bindings, integrity, source_bytes=None):
    """Validate a critical hardcoded-secret finding against recognized static test, fixture, endpoint, symbolic, or finite-input evidence and its source hashes."""
    from .provenance import public_symbolic_binding, finite_template_binding
    from .credential_endpoint_admission import endpoint_binding

    facts = finding.get("facts", {})
    disposition = facts.get("disposition")
    if _valid_security_precondition(facts.get("security_precondition"), finding):
        return False
    if disposition == "PROVEN_CLOSED_LITERAL_PICKLE_BYTES":
        return _closed_literal_pickle_binding(finding, sources, bindings, source_bytes)
    if disposition == "PROVEN_LOCAL_CONTROL_LABEL":
        return _local_control_label_binding(finding, sources, bindings, source_bytes)
    if disposition == "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE":
        return _jwt_primitive_binding(
            finding, facts, sources, bindings, integrity, source_bytes
        )
    if facts.get("disposition") == "TEST_OWNED_LOCAL_FIXTURE":
        return django_fixture_binding(finding, sources, bindings)
    if facts.get("disposition") in {
        "TEST_OWNED_APPLICATION_CREDENTIAL",
        "SOURCE_PRESENTATION_METADATA",
    }:
        return application_fixture_binding(finding, sources, bindings, source_bytes)
    if facts.get("disposition") == "ENDPOINT_DECLARATION_ROLE_PROVEN":
        return endpoint_binding(finding, sources, bindings, source_bytes)
    if facts.get("disposition") == "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER":
        return public_symbolic_binding(finding, sources, bindings)
    if facts.get("disposition") == "PROVEN_FINITE_TEMPLATE_INPUT":
        return finite_template_binding(finding, sources, bindings)
    return _fixed_program_binding(
        finding, facts, sources, bindings, integrity, source_bytes
    )


def _local_control_label_binding(finding, sources, bindings, source_bytes):
    """Regenerate this module-local proof without rerunning unrelated detectors."""
    from . import review_audits as audit

    path = finding.get("path")
    if not isinstance(path, str) or not isinstance(source_bytes, dict):
        return False
    relevant = [row for row in sources if row.get("path") == path]
    if len(relevant) != 1 or relevant[0].get("sha256") != bindings.get(path):
        return False
    captured = _jwt_bound_source_inventory(
        {path: source_bytes.get(path)}, {path: bindings.get(path)}
    )
    if captured is None:
        return False
    try:
        tree = ast.parse(captured[Path(path)])
        tree._oracle_source_sha256 = bindings[path]
        audit.integrity.bind_security_call_scopes(tree)
        nodes = list(ast.walk(tree))
        for parent in nodes:
            for child in ast.iter_child_nodes(parent):
                child._security_parent = parent
        aliases = audit._security_aliases(nodes)
        targets = _jwt_declaration_targets(tree, finding.get("facts", {}))
        return (
            len(targets) == 1
            and audit._literal_assignment_diagnostic(path, *targets[0], aliases)
            == finding
        )
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return False


def _closed_literal_pickle_binding(finding, sources, bindings, source_bytes):
    from . import review_audits as audit

    captured = (
        _jwt_bound_source_inventory(source_bytes, bindings)
        if isinstance(source_bytes, dict)
        else None
    )
    if captured is None or len(sources) != len(bindings):
        return False
    path = finding.get("path")
    raw = captured.get(Path(path)) if isinstance(path, str) else None
    if raw is None:
        return False
    try:
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        rows = audit._security_scan_tree(
            Path("."),
            Path(path),
            tree,
            oracle_context={"_security_source_context": (Path("."), captured)},
        )
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return False
    return any(
        row.get("code") == finding.get("code")
        and row.get("line") == finding.get("line")
        and row.get("column") == finding.get("column")
        and row.get("facts") == finding.get("facts")
        for row in rows
    )


def _jwt_primitive_binding(finding, facts, sources, bindings, integrity, source_bytes):
    workspace_sources = sorted((row["path"], row["sha256"]) for row in sources)
    workspace_digest = hashlib.sha256(
        json.dumps(workspace_sources, separators=(",", ":")).encode()
    ).hexdigest()
    provider = next(
        (row for row in sources if row.get("path") == facts.get("provider_path")),
        None,
    )
    span = facts.get("declaration_span")
    owner_spans = ("test_owner_span", "provider_allocation_span")
    if not _jwt_primitive_common(
        finding,
        facts,
        bindings,
        integrity,
        provider,
        span,
        owner_spans,
        workspace_digest,
    ):
        return False
    if not _jwt_operation_recomputes_from_sources(
        finding, facts, source_bytes, workspace_digest, bindings
    ):
        return False
    return _jwt_operation_spans_valid(facts, integrity)


def _jwt_primitive_common(
    finding, facts, bindings, integrity, provider, span, owner_spans, workspace_digest
):
    if not _jwt_primitive_identity(
        finding, facts, bindings, provider, workspace_digest
    ):
        return False
    if not _jwt_primitive_declared_span(finding, span):
        return False
    return all(integrity._valid_source_span(facts.get(key)) for key in owner_spans)


def _jwt_primitive_identity(finding, facts, bindings, provider, workspace_digest):
    return bool(
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and finding.get("severity") == "CRITICAL"
        and facts.get("schema") == "factory.jwt-local-crypto-test-primitive.v1"
        and facts.get("source_path") == finding.get("path")
        and facts.get("source_sha256") == bindings.get(finding.get("path"))
        and facts.get("workspace_sources_sha256") == workspace_digest
        and provider is not None
        and facts.get("provider_sha256") == provider.get("sha256")
        and facts.get("authority_role") == "TEST_OWNED_SYNTHETIC_SIGNING_AUTHORITY"
        and facts.get("transport_role") == "UNASSESSED"
        and facts.get("runtime_assurance") == "INCOMPLETE"
        and facts.get("runtime_executed") is False
    )


def _jwt_primitive_declared_span(finding, span):
    return bool(
        isinstance(span, list)
        and len(span) == 4
        and span[0] == finding.get("line")
        and span[1] == finding.get("column")
        and span[2] >= span[0]
        and span[3] >= span[1]
    )


def _jwt_operation_spans_valid(facts, integrity):
    calls = facts.get("crypto_call_spans")
    inputs = facts.get("input_source_spans")
    return bool(
        facts.get("operation_role") == "test_owned_local_crypto_operation"
        and facts.get("operation_kind") in {"encode", "decode", "roundtrip"}
        and isinstance(calls, list)
        and isinstance(inputs, list)
        and len(calls) > 0
        and len(calls) == len(inputs)
        and all(integrity._valid_source_span(span) for span in calls + inputs)
        and all(
            facts["test_owner_span"][:2] <= span[:2]
            and span[2:] <= facts["test_owner_span"][2:]
            for span in calls
        )
    )


def fixed_program_proof_dispositions():
    """One capture/admission registry for independently rechecked program proofs."""
    return frozenset(
        {
            "PROVEN_FIXED_LITERAL_PROGRAM",
            "PROVEN_SOURCE_BUILT_AST_PROGRAM",
            "PROVEN_FINITE_LITERAL_EVAL_INPUT",
            "PROVEN_CLOSED_DECLARATION_INPUT",
        }
    )


def _fixed_program_binding(
    finding, facts, sources, bindings, integrity, source_bytes=None
):
    if not _fixed_program_binding_base(finding, facts, sources, bindings, integrity):
        return False
    if not isinstance(source_bytes, dict):
        return False
    return _fixed_program_chain_binding(
        finding, facts, sources, source_bytes, integrity
    )


def _fixed_program_binding_base(finding, facts, sources, bindings, integrity):
    workspace_sources = sorted((row["path"], row["sha256"]) for row in sources)
    workspace_digest = hashlib.sha256(
        json.dumps(workspace_sources, separators=(",", ":")).encode()
    ).hexdigest()
    if finding.get("code") != "SECURITY_DYNAMIC_EXECUTION":
        return False
    if not _fixed_program_source_hash_bound(finding, facts, sources, bindings):
        return False
    if not _fixed_program_disposition_bound(finding, facts, integrity):
        return False
    return facts.get("workspace_sources_sha256") == workspace_digest


def _fixed_program_source_hash_bound(finding, facts, sources, bindings):
    source_hash = facts.get("source_sha256")
    if not isinstance(source_hash, str) or not re.fullmatch(
        r"[0-9a-f]{64}", source_hash
    ):
        return False
    path = finding.get("path")
    return (
        facts.get("source_path") == path
        and sum(row["path"] == path for row in sources) == 1
        and source_hash == bindings.get(path)
    )


def _fixed_program_disposition_bound(finding, facts, integrity):
    disposition = facts.get("disposition")
    if disposition == "PROVEN_FIXED_LITERAL_PROGRAM":
        return facts.get("schema") == "factory.fixed-literal-program.v1"
    if disposition == "PROVEN_SOURCE_BUILT_AST_PROGRAM":
        return facts.get("schema") == "factory.source-built-ast-program.v1"
    if disposition == "PROVEN_FINITE_LITERAL_EVAL_INPUT":
        return integrity._finite_eval_binding(finding)
    return integrity._closed_declaration_binding(finding)


def _fixed_program_chain_binding(finding, facts, sources, source_bytes, integrity):
    from .review_integrity import bind_security_call_scopes

    source_path = finding.get("path")
    raw = source_bytes.get(source_path)
    if raw is None:
        raw = source_bytes.get(Path(source_path))
    if (not isinstance(raw, bytes)) or (
        hashlib.sha256(raw).hexdigest() != facts.get("source_sha256")
    ):
        return False
    call_span = facts.get("call_span")
    if not valid_source_span(call_span) or call_span[:2] != [
        finding.get("line"),
        finding.get("column"),
    ]:
        return False
    try:
        tree = ast.parse(raw, filename=source_path)
        bind_security_call_scopes(tree)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return False
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]
        == call_span
    ]
    if len(calls) != 1:
        return False
    from .runtime_audit_integrity import (
        _fixed_eval_builtin_source_clear,
        fixed_eval_workspace_provider_clear,
    )

    if facts.get(
        "disposition"
    ) == "PROVEN_FIXED_LITERAL_PROGRAM" and not fixed_eval_workspace_provider_clear(
        source_bytes, sources
    ):
        return False
    node = calls[0]
    if (
        facts.get("disposition")
        in {
            "PROVEN_FIXED_LITERAL_PROGRAM",
            "PROVEN_SOURCE_BUILT_AST_PROGRAM",
        }
        and not _fixed_eval_builtin_source_clear(tree, node)
    ) or (not fixed_program_builtin_identity(integrity, node, tree, facts.get("call"))):
        return False
    expected = _fixed_program_expected_witness(
        node, facts, raw, source_path, source_bytes, sources, integrity, tree
    )
    if not expected:
        return False
    expected.setdefault("workspace_sources_sha256", facts["workspace_sources_sha256"])
    return facts == {"call": facts.get("call"), **expected}


def _fixed_program_expected_witness(
    node,
    facts,
    raw,
    source_path,
    source_bytes=None,
    sources=None,
    integrity=None,
    tree=None,
):
    disposition = facts.get("disposition")
    if disposition != "PROVEN_FIXED_LITERAL_PROGRAM" and (
        not isinstance(source_bytes, dict)
        or not isinstance(sources, (list, tuple))
        or _jwt_bound_source_inventory(
            source_bytes, {row["path"]: row["sha256"] for row in sources}
        )
        is None
    ):
        return {}
    if disposition in {
        "PROVEN_CLOSED_DECLARATION_INPUT",
        "PROVEN_FINITE_LITERAL_EVAL_INPUT",
    }:
        from .runtime_audit_integrity import (
            closed_declaration_input_witness,
            finite_literal_eval_input_witness,
            source_generated_eval_input_witness,
        )

        call = facts.get("call")
        if disposition == "PROVEN_CLOSED_DECLARATION_INPUT":
            witness = closed_declaration_input_witness(
                node, call, source_bytes=raw, source_path=source_path
            )
        else:
            witness = finite_literal_eval_input_witness(
                node, call, source_bytes=raw, source_path=source_path
            ) or source_generated_eval_input_witness(
                node,
                call,
                source_bytes=raw,
                source_path=source_path,
                builtin_identity_proven=fixed_program_builtin_identity(
                    integrity, node, tree, call
                ),
            )
        if not witness or witness.get("disposition") != disposition:
            return {}
        witness["workspace_sources_sha256"] = facts["workspace_sources_sha256"]
        return witness
    if facts.get("disposition") == "PROVEN_SOURCE_BUILT_AST_PROGRAM":
        from .finite_capture import (
            source_built_ast_program_witness,
            source_built_ast_workspace_provider_clear,
        )

        if not source_built_ast_workspace_provider_clear(
            source_bytes, source_path
        ) or not fixed_program_builtin_identity(integrity, node, tree, "exec"):
            return {}
        witness = source_built_ast_program_witness(
            node, "exec", source_bytes=raw, source_path=source_path
        )
        if not witness:
            return {}
        workspace_sources = sorted(
            (row["path"], row["sha256"]) for row in sources or []
        )
        witness["workspace_sources_sha256"] = hashlib.sha256(
            json.dumps(workspace_sources, separators=(",", ":")).encode()
        ).hexdigest()
        return witness
    from .runtime_audit_integrity import fixed_literal_program_witness

    scope_profile = _fixed_program_verified_scope(node, facts)
    if scope_profile is None:
        return {}
    return fixed_literal_program_witness(
        node,
        facts.get("call"),
        source_bytes=raw,
        builtin_identity_proven=True,
        source_path=source_path,
        scope_profile=scope_profile,
    )


def _fixed_program_verified_scope(node, facts):
    profile = facts.get("profile")
    if not isinstance(profile, dict):
        return None
    scope = getattr(node, "_security_lexical_scope", None)
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        actual = "function"
    elif isinstance(scope, ast.Module):
        actual = "module"
    else:
        return None
    claimed = profile.get("scope")
    if claimed == actual:
        return actual
    if (
        claimed == "native-module-or-function-omitted-namespaces"
        and len(node.args) == 1
        and not node.keywords
    ):
        return claimed
    return None


def closed_shell_binding(finding, sources, bindings, source_bytes):
    """Reject stale, forged, shadowed or unsupported command classifications."""
    from .finite_capture import closed_shell_operation_witness, closed_shell_workspace

    facts = finding.get("facts", {})
    relative = finding.get("path")
    call = facts.get("call", "")
    if not all(isinstance(value, str) for value in (relative, call)):
        return False
    if not isinstance(source_bytes, dict):
        return False
    captured = _jwt_bound_source_inventory(source_bytes, bindings)
    if captured is None:
        return False
    raw = captured.get(Path(relative))
    code = "SECURITY_OS_COMMAND" if call == "os.system" else "SECURITY_SHELL_COMMAND"
    if (finding.get("code"), finding.get("severity")) != (code, "INFO"):
        return False
    proof = closed_shell_operation_witness(raw, relative, facts.get("call_span"), call)
    inventory = closed_shell_workspace(source_bytes, call.split(".")[0])
    if not proof or inventory is None:
        return False
    proof["workspace_sources_sha256"] = inventory
    return bool(
        facts == proof
        and facts["call_span"][:2] == [finding.get("line"), finding.get("column")]
    )


def _jwt_operation_recomputes_from_sources(
    finding, facts, source_bytes, workspace_digest, bindings
):
    """Rebuild the JWT role proof from current captured bytes before admission."""
    if not isinstance(source_bytes, dict) or not source_bytes:
        return False
    relative = facts.get("source_path")
    if not isinstance(relative, str) or relative != finding.get("path"):
        return False
    captured = _jwt_bound_source_inventory(source_bytes, bindings)
    if captured is None:
        return False
    test_path = Path(relative)
    raw = captured.get(test_path)
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != facts.get(
        "source_sha256"
    ):
        return False
    try:
        tree = ast.parse(raw, filename=relative)
    except (SyntaxError, ValueError):
        return False
    targets = _jwt_declaration_targets(tree, facts)
    if len(targets) != 1:
        return False
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._security_parent = parent
    captured_imports = _jwt_captured_api_imports(tree, captured, test_path)
    tree._security_source_context = (Path("."), captured)
    tree._security_oracle_context = {"captured_imports": captured_imports}
    tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
    tree._security_workspace_sources_sha256 = workspace_digest
    from .mock_fixture_provenance import closed_jwt_test_literal

    regenerated = closed_jwt_test_literal(relative, *targets[0])
    if not isinstance(regenerated, dict):
        return False
    return all(facts.get(key) == value for key, value in regenerated.items())


def _jwt_bound_source_inventory(source_bytes, bindings):
    captured = {}
    for name, raw in source_bytes.items():
        if not isinstance(name, str) or not isinstance(raw, bytes):
            return None
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            return None
        captured[path] = raw
    if set(source_bytes) != set(bindings) or any(
        hashlib.sha256(source_bytes[name]).hexdigest() != digest
        for name, digest in bindings.items()
    ):
        return None
    return captured


def _jwt_declaration_targets(tree, facts):
    span = facts.get("declaration_span")
    targets = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset] != span:
            continue
        for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
            if isinstance(target, ast.Name) and target.id == facts.get("name"):
                targets.append((node, target))
    return targets


def _jwt_captured_api_imports(tree, captured, test_path):
    imports = {}
    for statement in tree.body:
        if not isinstance(statement, ast.ImportFrom):
            continue
        bases = [test_path.parent, Path("."), Path("src")]
        if statement.level:
            base = test_path.parent
            for _ in range(statement.level - 1):
                base = base.parent
            bases = [base]
        for alias in statement.names:
            if alias.name == "*":
                continue
            modules = {
                base.joinpath(*(statement.module or "").split(".")) for base in bases
            }
            children = {
                candidate
                for module in modules
                for child in (module / alias.name,)
                for candidate in (child.with_suffix(".py"), child / "__init__.py")
                if candidate in captured
            }
            providers = children or {
                candidate
                for module in modules
                for candidate in (module.with_suffix(".py"), module / "__init__.py")
                if candidate in captured
            }
            if len(providers) == 1:
                imports[alias.asname or alias.name] = (
                    next(iter(providers)).as_posix(),
                    alias.name,
                )
    return imports


def rejected_primitive_proof(finding):
    """Rejected credential proofs preserve the original alert priority/message."""
    facts = finding.get("facts", {})
    if _valid_security_precondition(facts.get("security_precondition"), finding):
        return {
            **finding,
            "facts": {
                **facts,
                "disposition": "UNVERIFIED_CONFLICTING_PRIMITIVE",
                "state": "INCOMPLETE",
                "proof_rejection": "CONTRADICTORY_SECURITY_PREMISES",
            },
        }
    if facts.get("disposition") == "CONDITIONAL_PROVIDER_CONTRACT":
        return {
            **finding,
            "facts": {
                **facts,
                "disposition": "UNVERIFIED_PROVIDER_CONTRACT",
                "state": "INCOMPLETE",
                "proof_rejection": "PROFILE_OR_SOURCE_BINDING_MISMATCH",
            },
        }
    if facts.get("disposition") == "ENDPOINT_DECLARATION_ROLE_PROVEN":
        return {
            **finding,
            "facts": {
                **facts,
                "disposition": "UNVERIFIED_ENDPOINT_DECLARATION",
                "state": "INCOMPLETE",
                "proof_rejection": "NATIVE_SOURCE_BINDING_OR_PUBLICATION_MISMATCH",
            },
        }
    if finding.get("code") == "SECURITY_HARDCODED_SECRET":
        jwt_role_proof = (
            facts.get("disposition") == "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE"
        )
        return {
            **finding,
            "severity": "CRITICAL" if jwt_role_proof else finding.get("severity"),
            "message": (
                "The JWT test-role proof is not bound to the current source; credential risk remains active."
                if jwt_role_proof
                else finding.get("message")
            ),
            "facts": {
                **facts,
                "disposition": "UNVERIFIED_CREDENTIAL_ROLE",
                "state": "INCOMPLETE",
                "proof_rejection": "SOURCE_BINDING_MISMATCH",
            },
        }
    return {
        **finding,
        "severity": "HIGH",
        "message": "The fixed-program proof is not bound to the current source; execution risk remains unverified.",
        "facts": {
            **facts,
            "disposition": "UNVERIFIED_FIXED_PROGRAM",
            "state": "INCOMPLETE",
            "proof_rejection": "SOURCE_BINDING_MISMATCH",
        },
    }


def _conditional_provider_row(finding, profile, captured, audit):
    from .runtime_audit_integrity import conditional_provider_pickle_witness

    facts, path = finding.get("facts", {}), finding.get("path")
    if (
        finding.get("code") != "SECURITY_UNSAFE_DESERIALIZATION"
        or not isinstance(facts, dict)
        or facts.get("disposition")
        or _valid_security_precondition(facts.get("security_precondition"), finding)
    ):
        return None
    raw = captured.get(path)
    if not isinstance(raw, bytes):
        return None
    native = _regenerate_native_findings(path, raw)
    if finding not in native:
        return None
    try:
        calls = [
            node
            for node in ast.walk(ast.parse(raw))
            if isinstance(node, ast.Call)
            and (node.lineno, node.col_offset)
            == (finding.get("line"), finding.get("column", 0))
        ]
        if len(calls) != 1:
            return None
        node = calls[0]
        witness = conditional_provider_pickle_witness(
            profile,
            captured,
            path,
            [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset],
            audit,
        )
    except (SyntaxError, TypeError, ValueError, RecursionError):
        return None
    if not witness:
        return None
    return {
        **finding,
        "facts": {
            **facts,
            "disposition": "CONDITIONAL_PROVIDER_CONTRACT",
            "analysis_profile": profile["analysis_profile"],
            "profile_sha256": profile["profile_sha256"],
            "model_sha256": profile["model_sha256"],
            "contract_sha256": profile["contract_sha256"],
            "provider_witness": witness,
        },
    }


def apply_conditional_provider_profile(report, profile, captured):
    """Produce conditional candidates, then seal through independent source admission."""
    from . import review_audits as audit
    from .finite_capture import provider_analysis_profile

    current = provider_analysis_profile(
        profile["analysis_profile"], tuple(profile["contracts"])
    )
    if current != profile or not current["conditional"]:
        raise ValueError("conditional profile identity differs")
    core = dict(report)
    core["provider_analysis_profile"] = current
    core["provider_analysis_cache"] = "CONDITIONAL_DECISIONS_NOT_REUSED"
    core["_primitive_source_bytes"] = dict(captured)
    core["source_manifest_sha256"] = _tier_sha256(
        {
            "sources": core.get("sources", []),
            "oracle_context": core.get("oracle_context", {}),
            "database_context": core.get("database_context", {}),
            "provider_analysis_profile": current,
        }
    )
    core["findings"] = [
        _conditional_provider_row(finding, current, captured, audit) or finding
        for finding in core.get("findings", [])
    ]
    return audit._seal_security_scan(core)


def apply_pickle_source_role_policy(core, captured, *, source_model=None):
    """Rebuild context reviews from the native raw ledger on every seal."""
    policy_id = core.get("selected_defect_policy")
    if policy_id not in {"source-role-v1", "source-role-v2", "source-role-v3"}:
        return
    original = [*core.get("findings", []), *core.get("context_reviews", [])]
    core["context_reviews"] = []
    sources = _pickle_role_sources(core, captured)
    roles = (
        None
        if sources is None
        else _pickle_role_inventory(sources, source_model=source_model)
    )
    if roles is not None:
        roles["policy_id"] = policy_id
    active, reviews = _pickle_role_partition(original, roles)
    core["findings"], core["context_reviews"] = active, reviews
    core["finding_counts"] = dict(
        sorted(Counter(row["code"] for row in active).items())
    )
    core["context_review_count"] = len(reviews)
    ledger = core.get("finding_tier_report", {}).get("ledger", [])
    reviewed_ids = {_pickle_role_identity(row) for row in reviews}
    for row in ledger:
        row.pop("source_role_review", None)
        finding = row.get("raw_finding", {})
        if _pickle_role_identity(finding) in reviewed_ids:
            row["source_role_review"] = _pickle_source_role_witness(finding, roles)
    tier_report = core.get("finding_tier_report", {})
    tier_report.pop("report_sha256", None)
    if isinstance(tier_report.get("ledger"), list):
        tier_report["ledger_sha256"] = _tier_sha256(tier_report["ledger"])
        tier_report["report_sha256"] = _tier_sha256(tier_report)
    core["defect_policy_decision"] = _pickle_source_role_decision(
        roles, active, reviews, ledger, policy_id
    )
    if _unknown_collection(core):
        core["state"] = "INCOMPLETE"
        core["action_summary"] = (
            "Pytest collection is UNKNOWN; fixture and oracle authority remain unassessed."
        )
    elif roles is not None:
        core["state"] = "FINDINGS" if active else "REVIEW_REQUIRED"
        core["action_summary"] = (
            f"{len(active)} active diagnostics; {len(reviews)} unresolved source-context reviews. No clean security result established."
        )


def _pickle_role_partition(original, roles):
    """Partition source-context reviews while retaining every original diagnostic."""
    active, reviews = [], []
    for finding in original:
        witness = None if roles is None else _pickle_source_role_witness(finding, roles)
        if witness is None:
            active.append(finding)
        else:
            reviews.append(finding)
    return active, reviews


def _pickle_role_identity(finding):
    return (
        finding.get("path"),
        finding.get("code"),
        finding.get("line"),
        finding.get("column", 0),
    )


def _pickle_role_sources(core, captured):
    if (
        _unknown_collection(core)
        or core.get("audit_coverage", {}).get("complete") is not True
        or not isinstance(captured, dict)
    ):
        return None
    rows = core.get("sources")
    if not isinstance(rows, list) or not rows or len(rows) > 2000:
        return None
    selected = {}
    for row in rows:
        path = row.get("path")
        raw = captured.get(path)
        if not isinstance(path, str) or path in selected or not isinstance(raw, bytes):
            return None
        if hashlib.sha256(raw).hexdigest() != row.get("sha256") or len(raw) > 1_000_000:
            return None
        selected[path] = raw
    return selected if sum(map(len, selected.values())) <= 32_000_000 else None


def _pickle_role_inventory(sources, *, source_model=None):
    try:
        trees = (
            _pickle_role_model_trees(sources, source_model)
            if source_model is not None
            else {path: ast.parse(raw) for path, raw in sources.items()}
        )
    except (SyntaxError, ValueError, RecursionError):
        return None
    if trees is None:
        return None
    if source_model is None:
        from .credential_role_constructor_provider import security_snapshot_model
        from .review_audits import _oracle_tree_fingerprint

        snapshots = {Path(path): tree for path, tree in trees.items()}
        for path, tree in snapshots.items():
            tree._oracle_source_sha256 = hashlib.sha256(
                sources[path.as_posix()]
            ).hexdigest()
        source_model = security_snapshot_model(
            Path("."),
            snapshots,
            {Path(path): raw for path, raw in sources.items()},
            {path: _oracle_tree_fingerprint(tree) for path, tree in snapshots.items()},
        )
    return {
        "sources": sources,
        "trees": trees,
        "source_model": source_model,
        "sources_sha256": _tier_sha256(
            {
                path: hashlib.sha256(raw).hexdigest()
                for path, raw in sorted(sources.items())
            }
        ),
        "origins": {},
        "native": {},
        "unsafe_callbacks": _pickle_role_serializer_risk(trees)
        or _pickle_role_callback_risk(None, trees.values()),
    }


def _pickle_role_model_trees(sources, model):
    """Reuse only an exact scan-local producer capture, never serialized evidence."""
    from .credential_role_constructor_provider import SourceSnapshotIndex
    from .review_audits import _oracle_tree_fingerprint

    if type(model) is not SourceSnapshotIndex or not model.bounded:
        return None
    captured = {model.relative(path): raw for path, raw in model.source_bytes.items()}
    if captured != sources or set(model.snapshots) != set(model.source_bytes):
        return None
    fingerprints = getattr(model, "producer_fingerprints", {})
    trees = {}
    for path, tree in model.snapshots.items():
        if _oracle_tree_fingerprint(tree) != fingerprints.get(
            path
        ) or not model.validate(path):
            return None
        trees[model.relative(path)] = tree
    return trees


def _pickle_test_path(path):
    value = PurePosixPath(path)
    return (
        bool({"test", "tests"}.intersection(value.parts[:-1]))
        or value.name.startswith("test_")
        or value.name.endswith("_test.py")
    )


def _pickle_source_role_witness(finding, inventory):
    from .finite_capture import (
        captured_file_program_role,
        captured_literal_caller_program_role,
        captured_registered_fixture_helper_role,
    )

    return (
        (
            _authored_shell_source_role_witness(finding, inventory)
            if inventory.get("policy_id") == "source-role-v3"
            else None
        )
        or (
            captured_registered_fixture_helper_role(finding, inventory)
            if inventory.get("policy_id") == "source-role-v3"
            and not _valid_security_precondition(
                finding.get("facts", {}).get("security_precondition"), finding
            )
            else None
        )
        or _pickle_test_role_witness(finding, inventory)
        or _pickle_worker_role_witness(finding, inventory)
        or (
            _registered_fixture_role_witness(finding, inventory)
            or (
                (
                    captured_file_program_role(finding, inventory)
                    or captured_literal_caller_program_role(finding, inventory)
                )
                if finding.get("code") == "SECURITY_DYNAMIC_EXECUTION"
                and _pickle_role_native_match(finding, inventory)
                and not _valid_security_precondition(
                    finding.get("facts", {}).get("security_precondition"), finding
                )
                else None
            )
            if inventory.get("policy_id") in {"source-role-v2", "source-role-v3"}
            else None
        )
    )


def _authored_shell_source_role_witness(finding, inventory):
    """Classify literal input origin; never establish operation or shell safety."""
    from .finite_capture import (
        _closed_shell_provider,
        closed_shell_workspace,
        shell_execution_calls,
    )

    if finding.get("code") not in {
        "SECURITY_OS_COMMAND",
        "SECURITY_SHELL_COMMAND",
    } or not _pickle_role_native_match(finding, inventory):
        return None
    if _valid_security_precondition(
        finding.get("facts", {}).get("security_precondition"), finding
    ):
        return None
    path = finding.get("path")
    tree = inventory["trees"].get(path)
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and (n.lineno, n.col_offset) == (finding.get("line"), finding.get("column", 0))
    ]
    if len(calls) != 1:
        return None
    call = calls[0]
    providers = [
        name
        for name in shell_execution_calls()
        if _closed_shell_provider(tree, call, name, shell_execution_calls())
    ]
    if len(providers) != 1 or len(call.args) != 1:
        return None
    provider = providers[0]
    argument = _authored_shell_literal_input(call, provider, inventory=inventory)
    if argument is None:
        return None
    if closed_shell_workspace(inventory["sources"], provider.split(".")[0]) is None:
        return None
    return {
        "schema": "factory.security.authored-command-context.v1",
        "role": "CAPTURED_LITERAL_PROCESS_COMMAND_INPUT",
        "tier": "NEEDS_CONTEXT",
        "source_path": path,
        "source_sha256": hashlib.sha256(inventory["sources"][path]).hexdigest(),
        "sources_sha256": inventory["sources_sha256"],
        "call_span": _pickle_span(call),
        "provider": provider,
        "command_expression_sha256": _tier_sha256(ast.dump(argument)),
        "policy_sha256": _tier_sha256(_SOURCE_ROLE_POLICY_V3),
        "original_severity": finding.get("severity"),
        **{
            key: "UNASSESSED"
            for key in (
                "command_effects",
                "shell_runtime_interpretation",
                "environment_and_executable_identity",
                "filesystem_and_cwd_authority",
                "credential_or_network_effects",
                "deployment_authorization",
            )
        },
        "safe_execution": False,
    }


def _authored_shell_literal_input(call, provider, *, inventory=None):
    """Keep command origin literal without interpreting command effects."""
    argument = call.args[0]
    original = argument
    if inventory is not None and not isinstance(
        argument, (ast.Constant, ast.List, ast.Tuple)
    ):
        argument = _authored_shell_bound_input(call, inventory)
        if argument is None:
            return None
    pieces = (
        argument.elts if isinstance(argument, (ast.List, ast.Tuple)) else [argument]
    )
    if (
        not pieces
        or len(pieces) > 64
        or not all(
            isinstance(n, ast.Constant) and type(n.value) is str and n.value
            for n in pieces
        )
    ):
        return None
    values = [n.value for n in pieces]
    if (
        sum(map(len, values)) > 4096
        or any(
            not 32 <= ord(char) <= 126 or char in "|&;<>`$%'\"\\"
            for value in values
            for char in value
        )
    ) or (
        any(
            token.strip("'\"")
            .lower()
            .startswith(("-c", "/c", "--command", "-encodedcommand"))
            for value in values
            for token in value.split()
        )
    ):
        return None
    keys = [kw.arg for kw in call.keywords]
    if None in keys or len(keys) != len(set(keys)):
        return None
    if provider == "os.system":
        if keys or not isinstance(argument, ast.Constant):
            return None
    elif not any(
        kw.arg == "shell"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in call.keywords
    ):
        return None
    if any(
        kw.arg
        not in {
            "shell",
            "cwd",
            "text",
            "encoding",
            "errors",
            "capture_output",
            "check",
            "timeout",
        }
        or (kw.arg != "cwd" and not isinstance(kw.value, ast.Constant))
        for kw in call.keywords
    ):
        return None
    return original


def _authored_shell_bound_input(call, inventory):
    """Consume native value facts; accept only unchanged captured literal content."""
    from .credential_role_identity_effects import _Value
    from .finite_capture import security_structural_value

    environment = getattr(call, "_security_structural_values", None)
    if not isinstance(environment, dict):
        return None
    value = security_structural_value(call.args[0], environment)
    constants = _authored_shell_literal_index(inventory)
    allowed = {
        "CONSTANT",
        "CONTAINER",
        "ALIAS_USE",
        "BOUND_EXPRESSION",
        "CONTAINER_SELECT",
        "FIELD_SELECT",
        "HELPER_RETURN",
    }

    def literal(item):
        if (
            not isinstance(item, _Value)
            or item.roots
            or item.class_roots
            or item.unknown
            or item.content_unknown
            or any(step[0] not in allowed for step in item.trace)
        ):
            return None
        if item.scalar_kind in {"list", "tuple"} and 0 < len(item.items) <= 64:
            if any(
                isinstance(n, ast.Call)
                for kw in call.keywords
                for n in ast.walk(kw.value)
            ):
                return None
            children = [literal(child) for _, child in item.items]
            return ast.List(elts=children, ctx=ast.Load()) if all(children) else None
        if item.scalar_kind != "text":
            return None
        selected = [
            constants.get((tuple(step[1]), step[2]), ())
            for step in item.trace
            if step[0] == "CONSTANT"
        ]
        nodes = [node for group in selected for node in group]
        if (
            not selected
            or any(not group for group in selected)
            or len({node.value for node in nodes}) != 1
        ):
            return None
        return ast.Constant(value=nodes[0].value)

    return literal(value)


def _authored_shell_literal_index(inventory):
    constants = inventory.get("literal_nodes")
    if constants is not None:
        return constants
    constants = {}
    for tree in inventory["trees"].values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and type(node.value) is str:
                key = (
                    tuple(_pickle_span(node)),
                    hashlib.sha256(
                        ast.dump(node, include_attributes=False).encode()
                    ).hexdigest(),
                )
                constants.setdefault(key, []).append(node)
    inventory["literal_nodes"] = constants
    return constants


def _pickle_worker_role_witness(finding, inventory):
    path = finding.get("path")
    if (
        finding.get("code") != "SECURITY_UNSAFE_DESERIALIZATION"
        or path not in inventory["trees"]
        or inventory["unsafe_callbacks"]
        or _pickle_test_path(path)
        or _valid_security_precondition(
            finding.get("facts", {}).get("security_precondition"), finding
        )
    ):
        return None
    if not _pickle_role_native_match(finding, inventory):
        return None
    tree = inventory["trees"][path]
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (node.lineno, node.col_offset)
        == (finding.get("line"), finding.get("column", 0))
    ]
    if len(calls) != 1:
        return None
    evidence = _pickle_pipe_protocol(tree, calls[0]) or _pickle_queue_protocol(
        tree, calls[0]
    )
    if not evidence:
        return None
    return {
        "schema": "factory.security.pickle-worker-context.v1",
        "role": "CAPTURED_LOCAL_WORKER_PROTOCOL",
        "tier": "NEEDS_CONTEXT",
        "source_path": path,
        "source_sha256": hashlib.sha256(inventory["sources"][path]).hexdigest(),
        "sources_sha256": inventory["sources_sha256"],
        "protocol": evidence,
        "reconstruction_effects": "UNASSESSED",
        "external_writer_authority": "UNASSESSED",
        "runtime_provider_identity": "UNASSESSED",
        "safe_reconstruction": False,
        "original_severity": finding.get("severity"),
        "policy_sha256": _tier_sha256(_PICKLE_SOURCE_ROLE_POLICY),
    }


def _pickle_span(node):
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


def _pickle_pipe_protocol(tree, sink):
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    spawns = _pickle_worker_spawns(tree)
    if not spawns:
        return None
    if ast.unparse(sink.func) == "pickle.load" and len(sink.args) == 1:
        if _pickle_worker_stdin_scope(sink, parents, tree):
            return {
                "kind": "SAME_MODULE_SUBPROCESS_STDIN",
                "sink_span": _pickle_span(sink),
                "spawn_spans": [_pickle_span(node) for node in spawns],
            }
    if (
        ast.unparse(sink.func) != "pickle.loads"
        or len(sink.args) != 1
        or not isinstance(sink.args[0], ast.Name)
    ):
        return None
    scope = parents.get(sink)
    while scope in parents and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        scope = parents[scope]
    return _pickle_worker_pipe_receiver(tree, scope, sink, spawns)


def _pickle_worker_spawns(tree):
    commands = {
        node.targets[0].id: node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    }
    spawns = []
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Name)
            or not node.args
        ):
            continue
        command = (
            commands.get(node.args[0].id)
            if isinstance(node.args[0], ast.Name)
            else node.args[0]
        )
        if not isinstance(command, (ast.List, ast.Tuple)):
            continue
        argv = [ast.unparse(value) for value in command.elts]
        pipes = {kw.arg: ast.unparse(kw.value) for kw in node.keywords}
        if (
            argv
            in [
                ["sys.executable", "'-u'", "'-m'", "__name__"],
                ["sys.executable", "'-m'", "__name__"],
            ]
            and pipes.get("stdin") == pipes.get("stdout") == "subprocess.PIPE"
        ):
            spawns.append(node)
    return spawns


def _pickle_worker_stdin_scope(sink, parents, tree):
    scope = parents.get(sink)
    while scope in parents and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        scope = parents[scope]
    if (
        not isinstance(scope, ast.FunctionDef)
        or parents.get(scope) is not tree
        or scope.args.args
    ):
        return False
    if ast.unparse(sink.args[0]) != "stdin.buffer":
        return False
    bindings = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "stdin" for t in node.targets)
        and node.lineno < sink.lineno
    ]
    bound = len(bindings) == 1 and ast.unparse(bindings[0].value) == "sys.stdin"
    launched = any(
        isinstance(node, ast.If)
        and ast.unparse(node.test) == "__name__ == '__main__'"
        and any(
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Call)
            and ast.unparse(item.value.func) == scope.name
            for item in node.body
        )
        for node in tree.body
    )
    dumps = any(
        isinstance(node, ast.Call) and ast.unparse(node.func) == "pickle.dumps"
        for node in ast.walk(scope)
    )
    return bound and launched and dumps


def _pickle_worker_pipe_receiver(tree, scope, sink, spawns):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    receives = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == sink.args[0].id
        and isinstance(node.value, ast.Await)
        and isinstance(node.value.value, ast.Call)
        and ast.unparse(node.value.value.func) == "buffered.receive_exactly"
        and node.lineno < sink.lineno
    ]
    enclosing = _pickle_role_enclosing(
        tree, sink, (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    buffers = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and any(isinstance(t, ast.Name) and t.id == "buffered" for t in node.targets)
        and _pickle_role_enclosing(tree, node, (ast.FunctionDef, ast.AsyncFunctionDef))[
            :1
        ]
        in [enclosing[i : i + 1] for i in range(len(enclosing))]
        and any(
            isinstance(value, ast.Attribute) and ast.unparse(value) == "process.stdout"
            for value in ast.walk(node.value)
        )
    ]
    dumps = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "pickle.dumps"
    ]
    all_buffers = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "buffered" for t in node.targets)
    ]
    writes = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Name)
        and node.id == sink.args[0].id
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if (
        len(receives) != 1
        or len(writes) != 1
        or not buffers
        or len(all_buffers) != len(buffers)
        or not dumps
    ):
        return None
    if any(
        arg.arg == "buffered"
        for frame in enclosing
        for arg in [*frame.args.args, *frame.args.posonlyargs, *frame.args.kwonlyargs]
    ):
        return None
    if not any(
        _pickle_role_enclosing(tree, node, (ast.FunctionDef, ast.AsyncFunctionDef))[:1]
        == enclosing[-1:]
        for node in spawns
    ):
        return None
    return {
        "kind": "SAME_MODULE_SUBPROCESS_STDOUT",
        "sink_span": _pickle_span(sink),
        "receive_span": _pickle_span(receives[0]),
        "buffer_spans": [_pickle_span(n) for n in buffers],
        "spawn_spans": [_pickle_span(n) for n in spawns],
        "serialization_spans": [_pickle_span(n) for n in dumps],
    }


def _pickle_role_enclosing(tree, node, kinds):
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    result = []
    while node in parents:
        node = parents[node]
        if isinstance(node, kinds):
            result.append(node)
    return result


def _pickle_queue_protocol(tree, sink):
    if (
        ast.unparse(sink.func) != "pickle.loads"
        or len(sink.args) != 1
        or ast.unparse(sink.args[0]) != "res"
    ):
        return None
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    names = {ast.unparse(node.func) for node in calls}
    if (
        not {
            "_interpqueues.create",
            "_interpqueues.get",
            "_interpqueues.put",
            "_interpreters.exec",
            "pickle.dumps",
        }
        <= names
    ):
        return None
    creates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(ast.unparse(t) == "self._queue_id" for t in node.targets)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "_interpqueues.create"
    ]
    receives = [
        node
        for node in calls
        if ast.unparse(node.func) == "_interpqueues.get"
        and node.args
        and ast.unparse(node.args[0]) == "self._queue_id"
    ]
    peers = _pickle_queue_serializing_peers(tree, calls)
    if (
        len(creates) != 1
        or len(receives) != 1
        or not peers
        or _pickle_role_enclosing(tree, creates[0], (ast.ClassDef,))[:1]
        != _pickle_role_enclosing(tree, sink, (ast.ClassDef,))[:1]
        or not _pickle_role_enclosing(tree, sink, (ast.ClassDef,))
        or not _pickle_queue_sink_bound(tree, sink, receives[0])
    ):
        return None
    if not _pickle_queue_identities_bound(tree, sink, creates[0]):
        return None
    return {
        "kind": "SOURCE_CREATED_INTERPRETER_QUEUE",
        "sink_span": _pickle_span(sink),
        "queue_creation_span": _pickle_span(creates[0]),
        "receive_span": _pickle_span(receives[0]),
        "embedded_peer_sha256": peers,
    }


def _pickle_queue_identities_bound(tree, sink, creation):
    owner = _pickle_role_enclosing(tree, sink, (ast.ClassDef,))[0]
    queue_writes = [
        node
        for node in ast.walk(owner)
        if isinstance(node, ast.Attribute)
        and ast.unparse(node) == "self._queue_id"
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if len(queue_writes) != 1:
        return False
    frames = _pickle_role_enclosing(tree, sink, (ast.FunctionDef, ast.AsyncFunctionDef))
    calls = [node for node in ast.walk(frames[0]) if isinstance(node, ast.Call)]
    if not any(
        ast.unparse(node.func) == "_interpreters.exec"
        and node.args
        and ast.unparse(node.args[0]) == "self._interpreter_id"
        for node in calls
    ):
        return False
    return any(
        ast.unparse(node.func) == "_interpqueues.put"
        and node.args
        and ast.unparse(node.args[0]) == "self._queue_id"
        for node in calls
    )


def _pickle_queue_sink_bound(tree, sink, receive):
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    scope = sink
    while scope in parents and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        scope = parents[scope]
    if not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ) or receive not in set(ast.walk(scope)):
        return False
    writes = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Assign)
        and node.lineno < sink.lineno
        and any(
            isinstance(value, ast.Name) and value.id == "res"
            for target in node.targets
            for value in ast.walk(target)
        )
    ]
    expected = ["_interpqueues.get(self._queue_id)", "res[:2]"]
    if [
        ast.unparse(node.value) for node in sorted(writes, key=lambda node: node.lineno)
    ] != expected:
        return False
    return any(
        isinstance(node, ast.Call)
        and ast.unparse(node.func) == "_interpreters.set___main___attrs"
        and len(node.args) == 2
        and ast.unparse(node.args[1]) == "{'queue_id': self._queue_id}"
        for node in ast.walk(tree)
    )


def _pickle_queue_serializing_peers(tree, calls):
    peers = []
    for node in calls:
        if (
            ast.unparse(node.func) != "compile"
            or not node.args
            or not isinstance(node.args[0], ast.Constant)
        ):
            continue
        source = node.args[0].value
        if not isinstance(source, str):
            continue
        bindings = [
            item.targets[0].id
            for item in ast.walk(tree)
            if isinstance(item, ast.Assign)
            and item.value is node
            and len(item.targets) == 1
            and isinstance(item.targets[0], ast.Name)
        ]
        if len(bindings) != 1 or not any(
            ast.unparse(item.func) == "_interpreters.exec"
            and len(item.args) == 2
            and ast.unparse(item.args[1]) == bindings[0]
            for item in calls
        ):
            continue
        try:
            peer = ast.parse(source)
        except SyntaxError:
            continue
        names = {
            ast.unparse(item.func)
            for item in ast.walk(peer)
            if isinstance(item, ast.Call)
        }
        queue_calls = [
            item
            for item in ast.walk(peer)
            if isinstance(item, ast.Call)
            and ast.unparse(item.func) in {"_interpqueues.put", "_interpqueues.get"}
        ]
        ids_bound = queue_calls and all(
            item.args and ast.unparse(item.args[0]) == "queue_id"
            for item in queue_calls
        )
        if {
            "dumps",
            "_interpqueues.put",
            "_interpqueues.get",
            "loads",
        } <= names and ids_bound:
            peers.append(hashlib.sha256(source.encode()).hexdigest())
    return peers


def _pickle_test_role_witness(finding, inventory):
    path = finding.get("path")
    if (
        finding.get("code") != "SECURITY_UNSAFE_DESERIALIZATION"
        or not isinstance(path, str)
        or not _pickle_test_path(path)
        or path not in inventory["trees"]
    ):
        return None
    if (
        _valid_security_precondition(
            finding.get("facts", {}).get("security_precondition"), finding
        )
        or inventory["unsafe_callbacks"]
    ):
        return None
    source = inventory["sources"][path]
    if not _pickle_role_native_match(finding, inventory):
        return None
    origin = _finding_pickle_byte_origin(finding, source, True, inventory["origins"])
    if origin is None or _pickle_operational_importer(path, inventory["trees"]):
        return None
    tree = inventory["trees"][path]
    scope = _pickle_role_test_scope(tree, finding, inventory)
    if scope is None:
        return None
    return {
        "schema": "factory.security.pickle-test-context.v1",
        "role": "CAPTURED_TEST_ROUNDTRIP",
        "tier": "NEEDS_CONTEXT",
        "source_path": path,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "sources_sha256": inventory["sources_sha256"],
        "test_span": [
            scope.lineno,
            scope.col_offset,
            scope.end_lineno,
            scope.end_col_offset,
        ],
        "test_ast_sha256": _tier_sha256(ast.dump(scope, include_attributes=False)),
        "byte_origin": origin,
        "static_operational_importer": "NOT_OBSERVED",
        "reconstruction_effects": "UNASSESSED",
        "dynamic_deployment": "UNASSESSED",
        "original_severity": finding.get("severity"),
        "safe_reconstruction": False,
        "policy_sha256": _tier_sha256(_PICKLE_SOURCE_ROLE_POLICY),
    }


def _pickle_role_native_match(finding, inventory):
    from .review_audits import _security_only_scan_context

    path = finding["path"]
    if path not in inventory["native"]:
        with _security_only_scan_context(True):
            inventory["native"][path] = _regenerate_native_findings(
                path, inventory["sources"][path], source_model=inventory["source_model"]
            )
    return finding in inventory["native"][path]


def _pickle_role_test_scope(tree, finding, inventory=None):
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (node.lineno, node.col_offset)
        == (finding.get("line"), finding.get("column", 0))
    ]
    if len(calls) != 1:
        return None
    scope = calls[0]
    while scope in parents and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        scope = parents[scope]
    if not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ) or not scope.name.startswith("test"):
        return None
    owner = parents.get(scope)
    if owner is not tree and not (
        isinstance(owner, ast.ClassDef) and parents.get(owner) is tree
    ):
        return None
    if _pickle_role_disabled(tree) or _pickle_role_disabled(scope):
        return None
    if isinstance(owner, ast.ClassDef) and (
        _pickle_role_disabled(owner)
        or any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "__init__"
            for node in owner.body
        )
    ):
        return None
    imports = [
        node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    framework = any(
        (isinstance(node, ast.ImportFrom) and node.module in {"pytest", "unittest"})
        or isinstance(node, ast.Import)
        and any(alias.name in {"pytest", "unittest"} for alias in node.names)
        for node in imports
    )
    asserted = any(isinstance(node, ast.Assert) for node in ast.walk(scope))
    registered_owner = (
        isinstance(owner, ast.ClassDef)
        and inventory is not None
        and id(owner) in _pickle_role_unittest_owners(inventory)
    )
    collected_owner = (
        owner is tree
        or isinstance(owner, ast.ClassDef)
        and (
            owner.name.startswith("Test")
            or _pickle_collected_descendant(owner.name, tree, scope.name)
            or registered_owner
        )
    )
    return (
        scope
        if collected_owner and (framework or asserted or registered_owner)
        else None
    )


def _pickle_role_unittest_owners(inventory):
    if "unittest_owners" not in inventory:
        inventory["unittest_owners"] = _pickle_role_unittest_graph(inventory["trees"])
    return inventory["unittest_owners"]


def _pickle_role_unittest_graph(trees):
    from . import review_audits as audit
    from .runtime_audit_integrity import (
        _conditional_file_aliases,
        _conditional_module_name,
    )

    if any(
        PurePosixPath(path).stem == "unittest" or "/unittest/" in "/" + path
        for path in trees
    ):
        return set()
    modules = {path: _conditional_module_name(path) for path in trees}
    writes = _pickle_role_class_writes(trees, modules)
    classes = {}
    for path, tree in trees.items():
        aliases = _conditional_file_aliases(path, tree, modules)
        if aliases is None:
            continue
        local = {
            node.name: f"{modules[path]}.{node.name}"
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        }
        for node in tree.body:
            if (
                isinstance(node, ast.ClassDef)
                and not _pickle_role_disabled(node)
                and not _pickle_role_bases_rebound(tree, node, aliases)
            ):
                bases = [
                    audit._resolved_ast_name(base, {**local, **aliases})
                    for base in node.bases
                ]
                if not any(
                    _pickle_role_class_path_written(name, writes)
                    for name in [local[node.name], *bases]
                ):
                    classes[local[node.name]] = (node, bases)
    selected = {"unittest.TestCase"}
    # Framework contracts are conditional on unshadowed dependency identities.
    if not any(
        PurePosixPath(path).stem == "django"
        or "django" in PurePosixPath(path).parts[:-1]
        for path in trees
    ):
        selected.update(
            f"{module}.{base}"
            for module in ("django.test", "django.test.testcases")
            for base in ("SimpleTestCase", "TransactionTestCase", "TestCase")
            if not any(
                _pickle_role_class_path_written(f"{alias}.{base}", writes)
                for alias in ("django.test", "django.test.testcases")
            )
        )
    for _ in range(len(classes) + 1):
        before = set(selected)
        selected.update(
            name
            for name, (_, bases) in classes.items()
            if any(base in selected for base in bases)
        )
        if before == selected:
            break
    return {id(node) for name, (node, _) in classes.items() if name in selected}


def _pickle_role_class_path_written(name, writes):
    return any(
        name == value
        or name.startswith(value + ".")
        or value
        in {name + ".__bases__", name + ".__class__", name + ".__init_subclass__"}
        for value in writes
    )


def _pickle_role_class_writes(trees, modules):
    from . import review_audits as audit
    from .runtime_audit_integrity import _conditional_file_aliases

    imports = {
        path: _conditional_file_aliases(path, tree, modules)
        for path, tree in trees.items()
    }
    exports = {modules[path]: aliases for path, aliases in imports.items()}

    writes = set()
    for path, tree in trees.items():
        writes.update(
            _pickle_role_tree_writes(path, tree, modules, imports, exports, audit)
        )
    return writes


def _pickle_role_canonical_name(name, exports):
    seen = set()
    for _ in range(12):
        if name in seen:
            return name
        seen.add(name)
        parts = name.split(".")
        for length in range(len(parts) - 1, 0, -1):
            selected = (exports.get(".".join(parts[:length])) or {}).get(parts[length])
            if selected:
                name = ".".join([selected, *parts[length + 1 :]])
                break
        else:
            return name
    return name


def _pickle_role_tree_writes(path, tree, modules, imports, exports, audit):
    uncertain = imports[path] is None
    aliases = dict(imports[path] or {})
    aliases.update(
        {
            node.name: f"{modules[path]}.{node.name}"
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        }
    )
    writes = set()
    for node in ast.walk(tree):
        if _pickle_role_write_target(node, aliases, uncertain):
            original = audit._resolved_ast_name(node, aliases)
            writes.update((original, _pickle_role_canonical_name(original, exports)))
        writes.update(
            _pickle_role_reflective_writes(node, aliases, uncertain, exports, audit)
        )
    return writes


def _pickle_role_write_target(node, aliases, uncertain):
    if not (
        isinstance(node, (ast.Name, ast.Attribute))
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ):
        return False
    root = node
    while isinstance(root, ast.Attribute):
        root = root.value
    return isinstance(root, ast.Name) and (uncertain or root.id in aliases)


def _pickle_role_reflective_writes(node, aliases, uncertain, exports, audit):
    if not isinstance(node, ast.Call) or audit._resolved_ast_name(
        node.func, aliases
    ).removeprefix("builtins.") not in {"setattr", "delattr"}:
        return set()
    if (
        len(node.args) < 2
        or not isinstance(node.args[1], ast.Constant)
        or not isinstance(node.args[1].value, str)
    ):
        return set()
    receiver = node.args[0]
    while isinstance(receiver, ast.Attribute):
        receiver = receiver.value
    if not isinstance(receiver, ast.Name) or not (uncertain or receiver.id in aliases):
        return set()
    original = (
        audit._resolved_ast_name(node.args[0], aliases) + "." + node.args[1].value
    )
    return {original, _pickle_role_canonical_name(original, exports)}


def _pickle_role_import_rebound(tree, aliases):
    return any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id in aliases
        for node in ast.walk(tree)
    )


def _pickle_role_bases_rebound(tree, node, aliases):
    roots = {
        value.id
        for base in node.bases
        for value in ast.walk(base)
        if isinstance(value, ast.Name)
    }
    return _pickle_role_import_rebound(
        tree, {name: target for name, target in aliases.items() if name in roots}
    )


def _pickle_role_disabled(node):
    return any(
        isinstance(item, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__test__"
            for target in item.targets
        )
        and isinstance(item.value, ast.Constant)
        and item.value.value is False
        for item in node.body
    )


def _pickle_collected_descendant(name, tree, method):
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    selected = {name}
    for _ in range(16):
        before = set(selected)
        selected.update(
            node.name
            for node in classes
            if not _pickle_role_disabled(node)
            and not any(
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name in {method, "__init__"}
                for item in node.body
            )
            and any(
                isinstance(base, ast.Name) and base.id in selected
                for base in node.bases
            )
        )
        if selected == before:
            return any(value.startswith("Test") for value in selected)
    return False


def _pickle_operational_importer(path, trees):
    parts = PurePosixPath(path).with_suffix("").parts
    candidates = {".".join(parts[index:]) for index in range(len(parts))}
    for importer, tree in trees.items():
        if _pickle_test_path(importer):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(
                alias.name in candidates for alias in node.names
            ):
                return True
            if isinstance(node, ast.ImportFrom) and _pickle_role_imports_target(
                node, importer, candidates
            ):
                return True
    return False


def _pickle_role_imports_target(node, importer, candidates):
    package = list(PurePosixPath(importer).with_suffix("").parts[:-1])
    if node.level:
        package = package[: max(0, len(package) - node.level + 1)]
    else:
        package = []
    prefix = ".".join([*package, *([node.module] if node.module else [])])
    return prefix in candidates or any(
        ".".join(filter(None, [prefix, alias.name])) in candidates
        for alias in node.names
    )


def _pickle_role_serializer_risk(trees):
    from . import review_audits as audit

    for path, tree in trees.items():
        value = PurePosixPath(path)
        if value.stem in {"pickle", "_pickle"} or (
            value.name == "__init__.py" and value.parent.name in {"pickle", "_pickle"}
        ):
            return True
        aliases = _pickle_role_serializer_aliases(tree, audit)
        if _pickle_role_serializer_rebound(tree, aliases):
            return True
        for node in ast.walk(tree):
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if any(
                    audit._resolved_ast_name(child, aliases).split(".")[0]
                    in {"pickle", "_pickle"}
                    for child in ast.walk(node)
                    if isinstance(child, (ast.Name, ast.Attribute))
                ):
                    return True
            if isinstance(node, ast.Call) and _pickle_role_serializer_mutation(
                node, aliases, audit
            ):
                return True
    return False


def _pickle_role_serializer_rebound(tree, aliases):
    stores = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    args = {node.arg for node in ast.walk(tree) if isinstance(node, ast.arg)}
    direct = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name in {"pickle", "_pickle"}
    }
    return bool(direct.intersection(stores | args))


def _pickle_role_serializer_aliases(tree, audit):
    aliases = audit._security_aliases(list(ast.walk(tree)))
    assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    for _ in range(len(assignments) + 1):
        before = dict(aliases)
        for node in assignments:
            name = audit._resolved_ast_name(node.value, aliases)
            if name in {"pickle", "_pickle", "pickle.__dict__", "_pickle.__dict__"}:
                aliases.update(
                    {
                        target.id: name
                        for target in node.targets
                        if isinstance(target, ast.Name)
                    }
                )
        if aliases == before:
            break
    return aliases


def _pickle_role_serializer_mutation(node, aliases, audit):
    name = audit._resolved_ast_name(node.func, aliases)
    if name.removeprefix("builtins.") in {"setattr", "delattr", "vars"}:
        return bool(
            node.args
            and audit._resolved_ast_name(node.args[0], aliases) in {"pickle", "_pickle"}
        )
    return name.startswith(("pickle.__dict__.", "_pickle.__dict__.")) or name in {
        "pickle.__setattr__",
        "pickle.__delattr__",
        "_pickle.__setattr__",
        "_pickle.__delattr__",
    }


def _pickle_role_callback_risk(tree, trees=None):
    from . import review_audits as audit

    hooks = {
        "__reduce__",
        "__reduce_ex__",
        "__getstate__",
        "__setstate__",
        "__new__",
        "__getnewargs__",
        "__getnewargs_ex__",
    }
    dangerous = {"eval", "exec", "open", "compile", "__import__"}
    roots = (
        "subprocess.",
        "os.system",
        "os.popen",
        "requests.",
        "socket.",
        "urllib.request.",
    )
    functions = [
        (node, owner)
        for owner in (trees if trees is not None else [tree])
        for node in ast.walk(owner)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    pending = [
        (node, owner)
        for node, owner in functions
        if (tree is None or owner is tree) and node.name in hooks
    ]
    seen = set()
    owner_aliases = {}
    while pending:
        function, owner = pending.pop()
        if id(function) in seen:
            continue
        seen.add(id(function))
        if id(owner) not in owner_aliases:
            owner_aliases[id(owner)] = audit._security_aliases(list(ast.walk(owner)))
        aliases = owner_aliases[id(owner)]
        names = [
            audit._resolved_ast_name(node, aliases)
            for node in ast.walk(function)
            if isinstance(node, (ast.Name, ast.Attribute))
        ]
        if any(
            name in dangerous
            or name.removeprefix("builtins.") in dangerous
            or name.startswith(roots)
            for name in names
        ):
            return True
        referenced = {name.rsplit(".", 1)[-1] for name in names}
        pending.extend(
            (node, owner) for node, owner in functions if node.name in referenced
        )
    return False


def _conditional_provider_binding(finding, core, bindings, audit):
    from . import review_audits as native_audit
    from .finite_capture import provider_analysis_profile
    from .runtime_audit_common import RuntimeAuditError

    profile = core.get("provider_analysis_profile")
    captured = core.get("_primitive_source_bytes")
    if (
        not isinstance(profile, dict)
        or profile.get("analysis_profile")
        not in {"trusted-dependencies-v1", "trusted-dependencies-v2"}
        or not isinstance(captured, dict)
        or core.get("audit_coverage", {}).get("complete") is not True
    ):
        return False
    if (
        len(bindings) != len(core.get("sources", []))
        or _jwt_bound_source_inventory(
            {path: captured.get(path) for path in bindings}, bindings
        )
        is None
    ):
        return False
    try:
        current = provider_analysis_profile(
            profile["analysis_profile"], tuple(profile["contracts"])
        )
        if current != profile:
            return False
        selected = _conditional_binding_contract(current, finding)
        if selected is None:
            return False
        required = {finding.get("path"), *selected["artifacts"]}
        if not required <= set(bindings):
            return False
        native = _regenerate_native_findings(
            finding.get("path"), captured.get(finding.get("path"))
        )
        return any(
            _conditional_provider_row(row, current, captured, native_audit) == finding
            for row in native
            if (row.get("code"), row.get("line"), row.get("column"))
            == (finding.get("code"), finding.get("line"), finding.get("column"))
        )
    except (KeyError, TypeError, ValueError, RecursionError, RuntimeAuditError):
        return False


def _conditional_binding_contract(profile, finding):
    if profile["analysis_profile"] == "trusted-dependencies-v1":
        return profile["contracts"][0]
    from .finite_capture import provider_contract_view

    witness = finding.get("facts", {}).get("provider_witness", {})
    digest = witness.get("selected_contract_sha256")
    if not isinstance(digest, str):
        return None
    view = provider_contract_view(profile, digest)
    if not isinstance(view, dict) or view["selected_model_sha256"] != witness.get(
        "selected_model_sha256"
    ):
        return None
    return view["contract"]


def partition_proven_primitive_observations(core, audit):
    """Keep proved fixed programs visible without describing them as defects."""
    token = _ROLE_REBUILD_CONTEXT.set({})
    try:
        return _partition_proven_primitive_observations(core, audit)
    finally:
        _ROLE_REBUILD_CONTEXT.reset(token)


def _partition_proven_primitive_observations(core, audit):
    """Use one independent source rebuild per byte inventory within this seal."""
    from .audit_action_refs import _security_scan_action_summary, _security_scan_state

    bindings = {row["path"]: row["sha256"] for row in core.get("sources", [])}
    captured = _primitive_source_capture(core)
    prior = core.get("primitive_observations", [])
    previous_tiers = core.get("finding_tier_report", {})
    if (
        isinstance(previous_tiers, dict)
        and previous_tiers.get("schema") == _FINDING_TIER_POLICY["schema"]
        and isinstance(previous_tiers.get("ledger"), list)
    ):
        raw_findings = [
            copy.deepcopy(row["raw_finding"])
            for row in previous_tiers["ledger"]
            if isinstance(row, dict) and isinstance(row.get("raw_finding"), dict)
        ]
    else:
        raw_findings = copy.deepcopy([*core.get("findings", []), *prior])
    retained, proved = [], []
    touched = bool(prior)
    for finding in [*core["findings"], *prior]:
        facts = finding.get("facts", {})
        if facts.get("disposition") not in fixed_program_proof_dispositions() | {
            "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER",
            "PROVEN_FINITE_TEMPLATE_INPUT",
            "ENDPOINT_DECLARATION_ROLE_PROVEN",
            "TEST_OWNED_LOCAL_FIXTURE",
            "TEST_OWNED_APPLICATION_CREDENTIAL",
            "SOURCE_PRESENTATION_METADATA",
            "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
            "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX",
            "PROVEN_CLOSED_LITERAL_PICKLE_BYTES",
            "PROVEN_LOCAL_CONTROL_LABEL",
            "CONDITIONAL_PROVIDER_CONTRACT",
        }:
            retained.append(finding)
            continue
        touched = True
        endpoint_complete = (
            facts.get("disposition")
            not in {
                "ENDPOINT_DECLARATION_ROLE_PROVEN",
                "TEST_OWNED_LOCAL_FIXTURE",
                "TEST_OWNED_APPLICATION_CREDENTIAL",
                "SOURCE_PRESENTATION_METADATA",
                "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
                "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX",
            }
            or core.get("audit_coverage", {}).get("complete") is True
        )
        if endpoint_complete and _current_primitive_binding(
            finding, core, bindings, audit, captured
        ):
            proved.append(finding)
        else:
            retained.append(rejected_primitive_proof(finding))
    if touched:
        core["primitive_observations"] = proved
        core["primitive_observation_count"] = len(core["primitive_observations"])
        core["findings"] = retained
        core["finding_counts"] = dict(
            sorted(
                (code, sum(f["code"] == code for f in retained))
                for code in {f["code"] for f in retained}
            )
        )
        core["state"] = _security_scan_state(
            core.get("sources", []),
            retained,
            core.get("database_context"),
            core.get("audit_coverage"),
        )
        core["action_summary"] = _security_scan_action_summary(core["state"])
    coverage = core.get("audit_coverage", {})
    core["finding_tier_report"] = build_finding_tier_report(
        raw_findings,
        core.get("primitive_observations", []),
        core.get("sources", []),
        captured,
        coverage_state=(coverage.get("complete") is True),
        partition_state="VALIDATED"
        if coverage.get("complete") is True
        else "INCOMPLETE",
    )
    if _unknown_collection(core):
        core["state"] = "INCOMPLETE"
        core["action_summary"] = (
            "Pytest collection is UNKNOWN; fixture and oracle authority remain unassessed."
        )


def _primitive_source_capture(core):
    """Read the report's private source snapshot without exposing it in its mapping."""
    if "_primitive_source_bytes" in core:
        captured = core["_primitive_source_bytes"]
    else:
        captured = getattr(core, "_captured_sources", ())
        if type(captured) is tuple and all(
            type(row) is tuple and len(row) == 2 for row in captured
        ):
            captured = dict(captured)
    return captured if isinstance(captured, dict) else {}


def _current_primitive_binding(finding, core, bindings, audit, captured=None):
    if _unknown_collection(core) and finding.get("facts", {}).get("disposition") in {
        "TEST_OWNED_LOCAL_FIXTURE",
        "TEST_OWNED_APPLICATION_CREDENTIAL",
        "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
    }:
        return False
    if _valid_security_precondition(
        finding.get("facts", {}).get("security_precondition"), finding
    ):
        return False
    captured = _primitive_source_capture(core) if captured is None else captured
    if finding.get("facts", {}).get("disposition") == "CONDITIONAL_PROVIDER_CONTRACT":
        if "_primitive_source_bytes" not in core and captured:
            core = {**core, "_primitive_source_bytes": captured}
        return _conditional_provider_binding(finding, core, bindings, audit)
    sources = core.get("sources", [])
    if (
        finding.get("facts", {}).get("disposition")
        == "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX"
    ):
        return closed_shell_binding(finding, sources, bindings, captured)
    if finding.get("facts", {}).get("disposition") in {
        "TEST_OWNED_LOCAL_FIXTURE",
        "TEST_OWNED_APPLICATION_CREDENTIAL",
        "SOURCE_PRESENTATION_METADATA",
    }:
        configs = core.get("oracle_context", {}).get("configuration_sources", [])
        sources = [*sources, *configs]
        bindings = {row["path"]: row["sha256"] for row in sources}
    return audit._fixed_primitive_binding(finding, sources, bindings, captured)


def annotate_application_fixture(finding, node):
    """Attach hashed application-fixture evidence only to eligible findings, leaving preclassified findings and unsupported literals unchanged."""
    from . import review_integrity as integrity

    if finding.get("facts", {}).get("disposition"):
        return finding
    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_oracle_context", {})
    facts = finding.get("facts", {})
    key = f"{node.lineno}:{node.col_offset}:{facts.get('name')}"
    evidence = context.get("application_fixture_evidence", {}).get(key)
    if not isinstance(evidence, dict) or evidence.get("eligible") is not True:
        return finding
    presentation = evidence.get("classification") == "PRESENTATION_METADATA_ROLE"
    proof = {
        **facts,
        "schema": "factory.presentation-metadata-role.v1"
        if presentation
        else "factory.application-test-credential.v1",
        "disposition": "SOURCE_PRESENTATION_METADATA"
        if presentation
        else "TEST_OWNED_APPLICATION_CREDENTIAL",
        "fixture_evidence": evidence,
        "declaration_span": [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ],
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "isolation_assurance": "UNASSESSED",
        "target_execution": "not_performed",
    }
    if presentation:
        proof["downstream_consumer_security"] = "UNASSESSED"
    proof["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {**finding, "facts": proof}


def application_fixture_binding(finding, sources, bindings, source_bytes=None):
    """Validate application-fixture evidence, source/configuration hashes, spans, and proof fields without claiming runtime isolation."""
    facts = finding.get("facts", {})
    evidence = facts.get("fixture_evidence", {})
    if not isinstance(evidence, dict):
        return False
    configs = evidence.get("configuration_sha256", {})
    if not isinstance(configs, dict) or not set(configs) <= {
        "requirements.txt",
        "pyproject.toml",
        "tox.ini",
    }:
        return False
    digest = _application_fixture_inventory(sources, bindings, configs)
    if digest is None:
        return False
    unsigned = {
        key: value for key, value in facts.items() if key != "proof_facts_sha256"
    }
    if not _application_fixture_claim(finding, facts, evidence, bindings, digest):
        return False
    if not _application_fixture_use_proof(evidence, bindings, facts, source_bytes):
        return False
    return (
        facts.get("proof_facts_sha256")
        == hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _application_fixture_inventory(sources, bindings, configs):
    if len(sources) != len({row["path"] for row in sources}):
        return None
    manifest = {
        row["path"]: row["sha256"] for row in sources if row["path"].endswith(".py")
    }
    if any(bindings.get(name) != digest for name, digest in configs.items()):
        return None
    manifest.update(configs)
    return hashlib.sha256(
        "\n".join(
            sorted(f"{name}\0{value}" for name, value in manifest.items())
        ).encode()
    ).hexdigest()


def _application_fixture_claim(finding, facts, evidence, bindings, digest):
    return bool(
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and finding.get("severity") == "CRITICAL"
        and _application_role_binding(facts, evidence)
        and evidence.get("eligible") is True
        and evidence.get("inventory_sha256") == digest
        and evidence.get("source") == finding.get("path")
        and evidence.get("source_sha256") == bindings.get(finding.get("path"))
        and valid_source_span(facts.get("declaration_span"))
        and facts["declaration_span"][:2]
        == [finding.get("line"), finding.get("column")]
        and _application_assurance_binding(facts, evidence)
    )


def _application_fixture_use_proof(evidence, bindings, facts, source_bytes):
    if evidence.get("classification") == "PRESENTATION_METADATA_ROLE":
        if evidence.get("profile") == "STATIC_API_DATA_ROLE":
            return _presentation_data_role_recomputes(
                evidence, bindings, facts, source_bytes
            )
        return _presentation_witness_bindings(evidence, bindings, facts)
    if evidence.get("profile") == "DJANGO_CLASS_LOCAL_ACCOUNT_ENROLLMENT":
        return _application_class_role_recomputes(
            evidence, bindings, facts.get("name"), source_bytes
        )
    if evidence.get("profile") == "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP":
        return _application_credential_role_recomputes(
            evidence, bindings, facts.get("name"), source_bytes
        )
    if evidence.get("profile") in {
        "SOURCE_BOUND_FACTORY_TEST_AUTHORITY",
        "SOURCE_BOUND_DIGEST_TEST_AUTHORITY",
        "LOCAL_SOURCE_SIGNING_AUTHORITY",
    }:
        return _application_fixture_role_recomputes(
            evidence,
            bindings,
            facts.get("name"),
            source_bytes,
            "factory.test-authority-consumer-closure.v1",
            evidence["profile"],
        )
    return _application_witness_bindings(
        evidence, bindings
    ) and _application_use_closure_binding(
        evidence, bindings, facts.get("name"), source_bytes
    )


def _application_class_source_inputs(source_bytes, bindings, configs):
    """Validate current full-source and selected configuration bytes before rebuilding class facts."""
    from .import_context import application_configuration_names

    configuration_names = application_configuration_names()
    if (
        not isinstance(source_bytes, dict)
        or not isinstance(bindings, dict)
        or not isinstance(configs, dict)
        or set(source_bytes) != set(bindings)
        or len(source_bytes) > 2000 + len(configuration_names)
    ):
        return None
    for name, raw in source_bytes.items():
        if not isinstance(name, str) or not isinstance(raw, bytes):
            return None
        path = Path(name)
        if (
            not name
            or len(name) > 4096
            or "\\" in name
            or ":" in name
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != name
        ):
            return None
    python_names = {name for name in bindings if name.endswith(".py")}
    if (
        not python_names
        or len(python_names) > 2000
        or set(bindings) - python_names != set(configs)
        or not set(configs) <= configuration_names
        or sum(map(len, source_bytes.values())) > 32 * 1024 * 1024
        or any(len(source_bytes[name]) > 1_000_000 for name in python_names)
    ):
        return None
    return _jwt_bound_source_inventory(source_bytes, bindings)


def _presentation_data_role_recomputes(evidence, bindings, facts, source_bytes):
    """Rebuild all consumers; hashed witness spans alone cannot prove a data role."""
    configs = evidence.get("configuration_sha256", {})
    captured = _application_class_source_inputs(source_bytes, bindings, configs)
    if captured is None:
        return False
    from . import review_audits as audit
    from .credential_role_constructor_provider import PresentationRoleIndex
    from .mock_fixture_provenance import application_test_index
    from .context_efficiency import provider_context_cache_helpers

    try:
        index = _application_role_rebuild_index(
            captured, bindings, source_bytes, configs, application_test_index
        )
        if index is None:
            return False
        modules, source = index["modules"], index["source"]
        helpers = (
            *provider_context_cache_helpers(audit.contracts),
            audit._oracle_imports,
        )
        key = (
            "presentation-data-role",
            tuple(
                (
                    helper,
                    id(getattr(helper, "__code__", None)),
                    id(getattr(helper, "__defaults__", None)),
                )
                for helper in helpers
            ),
        )
        cache = index.setdefault("profiles", {})
        if key not in cache:
            eligible = {path.resolve(): path for path in modules}
            imports = {
                path: audit._oracle_imports(source.root, path, tree, eligible)
                for path, tree in modules.items()
            }
            cache[key] = PresentationRoleIndex(source, imports, audit)
        path = Path(evidence.get("source", ""))
        if path not in modules:
            return False
        targets = _jwt_declaration_targets(
            modules[path],
            {
                "name": facts.get("name"),
                "declaration_span": facts.get("declaration_span"),
            },
        )
        if len(targets) != 1:
            return False
        regenerated = cache[key].evidence(path, targets[0][0])
        return regenerated.get("eligible") is True and evidence == {
            **regenerated,
            "source": path.as_posix(),
            "source_sha256": bindings[path.as_posix()],
            "declaration_span": facts.get("declaration_span"),
            "inventory_sha256": evidence.get("inventory_sha256"),
            "configuration_sha256": configs,
            "isolation_assurance": "UNASSESSED",
        }
    except (
        SyntaxError,
        UnicodeError,
        ValueError,
        TypeError,
        AttributeError,
        KeyError,
        RecursionError,
        MemoryError,
    ):
        return False


def _application_class_role_recomputes(evidence, bindings, secret_name, source_bytes):
    """Rebuild class-role evidence from current byte-bound Python and config inputs."""
    return _application_fixture_role_recomputes(
        evidence,
        bindings,
        secret_name,
        source_bytes,
        "factory.application-consumer-use-closure.v2",
        "DJANGO_CLASS_LOCAL_ACCOUNT_ENROLLMENT",
    )


def _application_credential_role_recomputes(
    evidence, bindings, secret_name, source_bytes
):
    """Recompute plaintext role and provider bindings from the captured full source set."""
    return _application_fixture_role_recomputes(
        evidence,
        bindings,
        secret_name,
        source_bytes,
        "factory.credential-role-consumer-closure.v1",
        "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP",
    )


def _application_fixture_role_recomputes(
    evidence, bindings, secret_name, source_bytes, closure_schema, profile
):
    """Rebuild fixture role evidence from current byte-bound Python and config inputs."""
    closure = evidence.get("consumer_use_closure", {})
    if not isinstance(closure, dict) or closure.get("schema") != closure_schema:
        return False
    configs = evidence.get("configuration_sha256")
    captured = _application_class_source_inputs(source_bytes, bindings, configs)
    if captured is None:
        return False
    from .mock_fixture_provenance import (
        application_test_index,
        application_test_secret_evidence,
    )

    try:
        index = _application_role_rebuild_index(
            captured, bindings, source_bytes, configs, application_test_index
        )
        if index is None:
            return False
        modules = index["modules"]
        path = Path(evidence.get("source", ""))
        if path not in modules:
            return False
        targets = _jwt_declaration_targets(
            modules[path],
            {"name": secret_name, "declaration_span": evidence.get("declaration_span")},
        )
        if len(targets) != 1:
            return False
        literal = targets[0][0].value
        if not isinstance(literal, ast.Constant) or type(literal.value) is not str:
            return False
        regenerated = application_test_secret_evidence(
            index, path, literal.lineno, literal.value
        )
        return bool(
            regenerated.get("eligible") is True
            and regenerated.get("profile") == profile
            and evidence
            == {
                **regenerated,
                "inventory_sha256": evidence.get("inventory_sha256"),
                "configuration_sha256": configs,
            }
        )
    except (
        SyntaxError,
        UnicodeError,
        ValueError,
        TypeError,
        AttributeError,
        KeyError,
        RecursionError,
        MemoryError,
    ):
        return False


def _application_role_rebuild_index(captured, bindings, source_bytes, configs, build):
    """Reuse parsing only after the caller has verified every current byte hash."""
    from .credential_role_identity_effects import module_fixture_helper_epoch

    helpers = (build, ast.parse, *module_fixture_helper_epoch())
    key = (
        tuple(sorted(bindings.items())),
        tuple(sorted(configs.items())),
        tuple(
            (id(h), id(getattr(h, "__code__", h)), id(getattr(h, "__defaults__", None)))
            for h in helpers
        ),
    )
    memo = _ROLE_REBUILD_CONTEXT.get()
    if memo is not None and key in memo:
        return memo[key]
    modules, python_bytes, inventory = {}, {}, {}
    for path, raw in captured.items():
        if path.suffix != ".py":
            continue
        tree = ast.parse(raw, filename=path.as_posix())
        tree._oracle_source_sha256 = bindings[path.as_posix()]
        modules[path], python_bytes[path], inventory[path] = (
            tree,
            raw,
            tree._oracle_source_sha256,
        )
    result = build(
        Path("."),
        modules,
        python_bytes,
        inventory,
        {name: source_bytes[name] for name in configs},
    )
    if memo is not None:
        memo[key] = result
    return result


def _application_use_closure_binding(
    evidence, bindings, secret_name, source_bytes=None
):
    closure = evidence.get("consumer_use_closure")
    if not isinstance(closure, dict):
        return False
    assignments, uses = closure.get("assignments"), closure.get("uses")
    operations = closure.get("operations")
    if (
        closure.get("schema") != "factory.application-consumer-use-closure.v1"
        or closure.get("complete") is not True
        or closure.get("source") != evidence.get("source")
        or closure.get("source_sha256") != bindings.get(closure.get("source"))
        or not isinstance(assignments, list)
        or len(assignments) > 8
        or not isinstance(uses, list)
        or not 1 <= len(uses) <= 512
        or not isinstance(operations, list)
        or len(operations) > 16
    ):
        return False
    captured = (
        source_bytes.get(closure.get("source"))
        if isinstance(source_bytes, dict)
        else None
    )
    if not isinstance(captured, bytes) or hashlib.sha256(
        captured
    ).hexdigest() != closure.get("source_sha256"):
        return False
    try:
        source_tree = ast.parse(captured.decode("utf-8"))
    except (SyntaxError, UnicodeError):
        return False
    if not _application_closure_ast_rows(
        source_tree,
        closure.get("source"),
        assignments,
        uses,
        operations,
        source_bytes,
    ):
        return False
    witnesses = evidence.get("witness_spans")
    if not isinstance(witnesses, dict) or not _application_closure_rows_bound(
        closure, assignments, uses, operations, witnesses, bindings, secret_name
    ):
        return False
    return _application_closure_use_containment(
        assignments, uses, operations, witnesses
    )


def _application_closure_rows_bound(
    closure, assignments, uses, operations, witnesses, bindings, secret_name
):
    rows = [*assignments, *uses]
    assignment_names = [row.get("name") for row in assignments if isinstance(row, dict)]
    use_names = {row.get("name") for row in uses if isinstance(row, dict)}
    allowed_roles = {"derived_value", "verification", *witnesses}
    if (
        not isinstance(secret_name, str)
        or not secret_name.isidentifier()
        or not all(
            _application_closure_local_row(row, closure, bindings) for row in rows
        )
        or not all(
            row["role"] == "credential_lineage_assignment" for row in assignments
        )
        or not all(row["role"] in allowed_roles for row in uses)
        or not all(
            _application_closure_operation_row(row, closure, bindings)
            for row in operations
        )
    ):
        return False
    return (
        secret_name in use_names
        and len(set(assignment_names)) == len(assignment_names)
        and set(assignment_names) <= use_names
        and use_names <= {secret_name, *assignment_names}
        and len({tuple(row["span"]) for row in rows}) == len(rows)
        and (
            "verification" not in {row["role"] for row in uses}
            or any(row["role"] == "verification" for row in operations)
        )
        and len([row for row in operations if row["role"] == "verification"])
        == len(
            [row for row in operations if row["role"] == "verification_implementation"]
        )
    )


def _application_closure_local_row(row, closure, bindings):
    return bool(
        isinstance(row, dict)
        and row.get("path") == closure.get("source")
        and row.get("sha256") == closure.get("source_sha256")
        and valid_source_span(row.get("span"))
        and isinstance(row.get("name"), str)
        and row["name"].isidentifier()
        and bindings.get(row["path"]) == row["sha256"]
    )


def _application_closure_operation_row(row, closure, bindings):
    if (
        not isinstance(row, dict)
        or not isinstance(row.get("path"), str)
        or not isinstance(row.get("sha256"), str)
        or not valid_source_span(row.get("span"))
        or row.get("name") != ""
        or row.get("role")
        not in {"request", "verification", "verification_implementation"}
        or bindings.get(row["path"]) != row["sha256"]
    ):
        return False
    return row["role"] == "verification_implementation" or (
        row["path"] == closure.get("source")
        and row["sha256"] == closure.get("source_sha256")
    )


def _application_closure_use_containment(assignments, uses, operations, witnesses):
    for row in uses:
        if row["role"] == "derived_value":
            containers = assignments
        else:
            containers = (
                [{"span": witnesses[row["role"]]}] if row["role"] in witnesses else []
            ) + [op for op in operations if op["role"] == row["role"]]
        if not any(
            _source_span_contains(parent["span"], row["span"]) for parent in containers
        ):
            return False
    return True


def _application_closure_ast_rows(
    source_tree, source_path, assignments, uses, operations, source_bytes
):
    by_span = _application_closure_span_index(source_tree)
    return (
        _application_closure_assignment_ast_rows(by_span, assignments)
        and _application_closure_use_ast_rows(by_span, uses)
        and _application_closure_operation_ast_rows(
            source_tree, by_span, source_path, operations, source_bytes
        )
    )


def _application_closure_span_index(tree):
    return {
        (
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ): node
        for node in ast.walk(tree)
        if hasattr(node, "lineno") and hasattr(node, "end_lineno")
    }


def _application_closure_assignment_ast_rows(by_span, assignments):
    for row in assignments:
        statement = by_span.get(tuple(row["span"]))
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
            if isinstance(statement, ast.AnnAssign)
            else []
        )
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return False
        if targets[0].id != row["name"]:
            return False
    return True


def _application_closure_use_ast_rows(by_span, uses):
    for row in uses:
        node = by_span.get(tuple(row["span"]))
        if (
            not isinstance(node, ast.Name)
            or not isinstance(node.ctx, ast.Load)
            or node.id != row["name"]
        ):
            return False
    return True


def _application_closure_operation_ast_rows(
    source_tree, by_span, source_path, operations, source_bytes
):
    for row in operations:
        tree = source_tree
        if row["path"] != source_path:
            raw = source_bytes.get(row["path"])
            if not isinstance(raw, bytes):
                return False
            try:
                tree = ast.parse(raw.decode("utf-8"))
            except (SyntaxError, UnicodeError):
                return False
            by_span = _application_closure_span_index(tree)
        operation = by_span.get(tuple(row["span"]))
        if row["role"] in {"request", "verification"}:
            if not isinstance(operation, ast.Call):
                return False
        elif row["role"] == "verification_implementation":
            if not isinstance(operation, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False
        else:
            return False
    return True


def _source_span_contains(parent, child):
    return (
        valid_source_span(parent)
        and valid_source_span(child)
        and parent[0] <= child[0] <= child[2] <= parent[2]
        and (parent[0] != child[0] or parent[1] <= child[1])
        and (parent[2] != child[2] or child[3] <= parent[3])
    )


def _application_role_binding(facts, evidence):
    roles = {
        "APPLICATION_TEST_CREDENTIAL_ROLE": (
            "TEST_OWNED_APPLICATION_CREDENTIAL",
            "factory.application-test-credential.v1",
        ),
        "PRESENTATION_METADATA_ROLE": (
            "SOURCE_PRESENTATION_METADATA",
            "factory.presentation-metadata-role.v1",
        ),
    }
    selected = roles.get(evidence.get("classification"))
    return (
        selected is not None
        and (facts.get("disposition"), facts.get("schema")) == selected
    )


def _presentation_witness_bindings(evidence, bindings, facts):
    profiles = {
        "JSON_SCHEMA_ANNOTATION": ({"SCHEMA_TITLE"}, "class_literal"),
        "MASKING_SENTINEL": (
            {"MASK_OUTPUT", "PRESERVE_PREVIOUS_VALUE"},
            "module_literal",
        ),
    }
    selected = profiles.get(evidence.get("profile"))
    uses, declaration = evidence.get("uses"), evidence.get("declaration")
    if (
        selected is None
        or not isinstance(uses, list)
        or not 1 <= len(uses) <= 2000
        or not isinstance(declaration, dict)
    ):
        return False
    if any(
        container.get("downstream_consumer_security") != "UNASSESSED"
        for container in (facts, evidence)
    ):
        return False
    span = [
        declaration.get(key) for key in ("line", "column", "end_line", "end_column")
    ]
    if (
        span != facts.get("declaration_span")
        or declaration.get("source_role") != selected[1]
        or declaration.get("path") != evidence.get("source")
        or declaration.get("source_sha256") != evidence.get("source_sha256")
        or declaration.get("member") != facts.get("name")
    ):
        return False
    if not all(_presentation_witness_row(row, bindings) for row in uses):
        return False
    return {row["role"] for row in uses} == selected[0] and len(uses) == len(
        {(row["path"], tuple(row["span"]), row["role"]) for row in uses}
    )


def _presentation_witness_row(row, bindings):
    return (
        isinstance(row, dict)
        and isinstance(row.get("path"), str)
        and isinstance(row.get("sha256"), str)
        and re.fullmatch("[0-9a-f]{64}", row["sha256"]) is not None
        and bindings.get(row["path"]) == row["sha256"]
        and valid_source_span(row.get("span"))
        and isinstance(row.get("role"), str)
    )


def _application_assurance_binding(facts, evidence):
    expected = {
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "isolation_assurance": "UNASSESSED",
        "target_execution": "not_performed",
    }
    return all(
        container.get(key) == value
        for container in (facts, evidence)
        for key, value in expected.items()
    ) and evidence.get("declaration_span") == facts.get("declaration_span")


def _application_witness_bindings(evidence, bindings):
    profiles = {
        "DRF_TEST_USER_ENROLLMENT": {"creation", "header", "request"},
        "PYTEST_FLASK_TEST_STORE_ENROLLMENT": {"creation", "enrollment", "request"},
        "UNITTEST_FACTORY_USER_ENROLLMENT": {"creation", "enrollment", "request"},
        "UNITTEST_FACTORY_INVITATION_ENROLLMENT": {
            "creation",
            "enrollment",
            "request",
            "token",
        },
    }
    witnesses = evidence.get("witness_sources")
    spans = evidence.get("witness_spans")
    required = profiles.get(evidence.get("profile"))
    if (
        not isinstance(witnesses, dict)
        or not isinstance(spans, dict)
        or required is None
    ):
        return False
    if set(witnesses) != required or set(spans) != required:
        return False
    return all(
        isinstance(row, dict)
        and bindings.get(row.get("path")) == row.get("sha256")
        and isinstance(row.get("sha256"), str)
        and valid_source_span(row.get("span"))
        and spans[key] == row["span"]
        for key, row in witnesses.items()
    )


def annotate_django_fixture(finding, node):
    """Retain the original severity and primitive; attach captured owner evidence."""
    from . import review_integrity as integrity

    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_oracle_context", {})
    facts = finding.get("facts", {})
    key = f"{node.lineno}:{node.col_offset}:{facts.get('name')}"
    item = context.get("django_fixture_evidence", {}).get(key)
    if not isinstance(item, dict) or item.get("eligible") is not True:
        return finding
    if item.get("source_sha256") != getattr(module, "_oracle_source_sha256", None):
        return finding
    proof = {
        **facts,
        "schema": "factory.test-owned-credential.v1",
        "disposition": "TEST_OWNED_LOCAL_FIXTURE",
        "fixture_evidence": item,
        "declaration_span": [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ],
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }
    proof["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {**finding, "facts": proof}


def django_fixture_binding(finding, sources, bindings):
    """Validate the full analyzed inventory and config identity before partition."""
    facts = finding.get("facts", {})
    evidence = facts.get("fixture_evidence", {})
    if not isinstance(evidence, dict):
        return False
    configs = evidence.get("runner_config_sha256", {})
    if not isinstance(configs, dict) or set(configs) != {"pyproject.toml", "tox.ini"}:
        return False
    digest = _django_fixture_inventory(sources, bindings, configs)
    if digest is None:
        return False
    unsigned = {
        name: value for name, value in facts.items() if name != "proof_facts_sha256"
    }
    return _django_fixture_claim(finding, facts, evidence, bindings, digest, unsigned)


def _django_fixture_inventory(sources, bindings, configs):
    paths = [row["path"] for row in sources]
    if len(paths) != len(set(paths)):
        return None
    inventory = {
        row["path"]: row["sha256"] for row in sources if row["path"].endswith(".py")
    }
    if any(bindings.get(name) != digest for name, digest in configs.items()):
        return None
    inventory.update(configs)
    return hashlib.sha256(
        "\n".join(
            sorted(f"{name}\0{value}" for name, value in inventory.items())
        ).encode()
    ).hexdigest()


def _django_fixture_claim(finding, facts, evidence, bindings, digest, unsigned):
    if not _django_fixture_identity(finding, facts, evidence, bindings):
        return False
    if not _django_fixture_hashes(facts, evidence, digest):
        return False
    if not _django_fixture_span(finding, facts):
        return False
    return facts.get("proof_facts_sha256") == _proof_facts_digest(unsigned)


def _django_fixture_identity(finding, facts, evidence, bindings):
    return (
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and facts.get("disposition") == "TEST_OWNED_LOCAL_FIXTURE"
        and facts.get("schema") == "factory.test-owned-credential.v1"
        and evidence.get("classification") == "TEST_OWNED_LOCAL_FIXTURE"
        and evidence.get("eligible") is True
        and evidence.get("source") == finding.get("path")
        and finding.get("path") in bindings
        and isinstance(evidence.get("source_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", evidence["source_sha256"]) is not None
        and evidence.get("source_sha256") == bindings.get(finding.get("path"))
    )


def _django_fixture_hashes(facts, evidence, digest):
    return evidence.get("inventory_sha256") == digest


def _django_fixture_span(finding, facts):
    return valid_source_span(facts.get("declaration_span")) and facts[
        "declaration_span"
    ][:2] == [finding.get("line"), finding.get("column")]


def _proof_facts_digest(unsigned):
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def closed_declaration_binding(finding, audit):
    """Validate a closed declaration witness, grammar profile, program digest, and contained source spans; execution remains unperformed."""
    facts = finding.get("facts", {})
    span = facts.get("call_span")
    return _closed_declaration_claim(
        finding, facts, span, audit
    ) and _closed_declaration_literal(facts, span, audit)


def _closed_declaration_claim(finding, facts, span, audit):
    return _closed_declaration_profile(facts) and _closed_declaration_identity(
        finding, facts, span, audit
    )


def _closed_declaration_profile(facts):
    return (
        facts.get("disposition") == "PROVEN_CLOSED_DECLARATION_INPUT"
        and facts.get("schema") == "factory.closed-declaration-input.v1"
        and facts.get("grammar_profile") == "python3.12-type-alias-subset-v1"
        and facts.get("hypothesis") == "ARGUMENT_CODE_INJECTION"
        and facts.get("input_effect") == "CLOSED_INERT_DECLARATION"
        and facts.get("runtime_assurance") == "INCOMPLETE"
        and facts.get("target_execution") == "not_performed"
        and isinstance(facts.get("program_sha256"), str)
    )


def _closed_declaration_identity(finding, facts, span, audit):
    return (
        re.fullmatch(r"[0-9a-f]{64}", facts["program_sha256"]) is not None
        and audit._valid_source_span(span)
        and span[:2] == [finding.get("line"), finding.get("column")]
    )


def _closed_declaration_literal(facts, span, audit):
    return audit._valid_source_span(facts.get("literal_span")) and tuple(
        span[:2]
    ) <= tuple(facts["literal_span"][:2]) <= tuple(facts["literal_span"][2:]) <= tuple(
        span[2:]
    )


def valid_source_span(span):
    """Check that a source span contains four ordered integer coordinates with a positive starting line."""
    return (
        isinstance(span, list)
        and len(span) == 4
        and all(type(n) is int for n in span)
        and span[0] > 0
        and min(span[1], span[3]) >= 0
        and tuple(span[:2]) <= tuple(span[2:])
    )


def finite_eval_binding(finding, audit):
    """Delegate finite-eval proof validation to the shared runtime checker with this module's span validator."""
    from .runtime_audit_integrity import finite_eval_binding as bind

    return bind(finding, audit._valid_source_span)


def fixed_program_builtin_identity(audit, node, module, call_name):
    """Confirm exec or eval resolves to an unshadowed builtin without module-level indirection through sensitive builtin names."""
    audit = getattr(audit, "integrity", audit)
    if not _fixed_builtin_call_identity(audit, node, call_name):
        return False
    return _fixed_builtin_source_unshadowed(audit, node, module)


def _fixed_builtin_call_identity(audit, node, call_name):
    if not isinstance(node.func, audit.ast.Name) or node.func.id not in {
        "exec",
        "eval",
    }:
        return False
    return call_name == node.func.id and not audit._builtin_repr_names_shadowed(
        node, {node.func.id}
    )


def _fixed_builtin_source_unshadowed(audit, node, module):
    direct_call_names = {
        call.func
        for call in audit.ast.walk(module)
        if isinstance(call, audit.ast.Call)
        and getattr(call.func, "id", None) in {"exec", "eval"}
        and getattr(call, "_security_lexical_scope", None)
        is getattr(node, "_security_lexical_scope", None)
    }
    return _fixed_builtin_nodes_unshadowed(audit, module, node.func, direct_call_names)


def _fixed_builtin_nodes_unshadowed(audit, module, selected_func, direct_call_names):
    for item in audit.ast.walk(module):
        if item is selected_func or item in direct_call_names:
            continue
        if _fixed_builtin_node_is_shadow(audit, item):
            return False
    return True


def _fixed_builtin_node_is_shadow(audit, item):
    if isinstance(item, audit.ast.Name) and item.id in {
        "__builtins__",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "__import__",
        "exec",
        "eval",
    }:
        return True
    if isinstance(item, audit.ast.Attribute) and item.attr in {
        "__dict__",
        "__globals__",
        "__builtins__",
        "__getattribute__",
        "__setattr__",
        "import_module",
    }:
        return True
    if (
        isinstance(item, audit.ast.Attribute)
        and item.attr in {"exec", "eval"}
        and isinstance(item.ctx, (audit.ast.Store, audit.ast.Del))
    ):
        return True
    if isinstance(item, audit.ast.ImportFrom) and (
        item.module == "builtins" or any(a.name == "*" for a in item.names)
    ):
        return True
    if isinstance(item, audit.ast.Import) and any(
        a.name == "builtins" for a in item.names
    ):
        return True
    return False


def fixed_program_witness(audit, relative, node, call_name):
    """Bind literal-program proof to the captured source and lexical identity."""
    from .provenance import finite_template_witness
    from .runtime_audit_integrity import (
        closed_declaration_input_witness,
        finite_literal_eval_input_witness,
        fixed_literal_program_witness,
        source_generated_eval_input_witness,
    )

    scope = getattr(node, "_security_lexical_scope", None)
    if not isinstance(
        scope, (audit.ast.Module, audit.ast.FunctionDef, audit.ast.AsyncFunctionDef)
    ):
        return {}
    module = audit._security_module_scope(scope)
    workspace_profile = getattr(module, "_fixed_program_workspace", {})
    context = getattr(module, "_security_source_context", None)
    witness = _fixed_program_native_witness(
        audit,
        relative,
        node,
        call_name,
        module,
        workspace_profile,
        context,
        closed_declaration_input_witness,
        finite_literal_eval_input_witness,
        source_generated_eval_input_witness,
        finite_template_witness,
        fixed_literal_program_witness,
    )
    if witness:
        return witness
    return _fixed_program_legacy_witness(
        audit,
        relative,
        node,
        call_name,
        module,
        workspace_profile,
        context,
        fixed_literal_program_witness,
    )


def _fixed_program_native_witness(
    audit,
    relative,
    node,
    call_name,
    module,
    workspace_profile,
    context,
    closed_declaration_input_witness,
    finite_literal_eval_input_witness,
    source_generated_eval_input_witness,
    finite_template_witness,
    fixed_literal_program_witness,
):
    if (
        isinstance(context, tuple)
        and len(context) == 2
        and isinstance(workspace_profile, dict)
    ):
        root, sources = context
        raw = sources.get(root / relative) if isinstance(sources, dict) else None
        if isinstance(raw, bytes) and audit.hashlib.sha256(raw).hexdigest() == getattr(
            module, "_oracle_source_sha256", None
        ):
            if witness := (
                closed_declaration_input_witness(
                    node, call_name, source_bytes=raw, source_path=relative
                )
                or finite_literal_eval_input_witness(
                    node, call_name, source_bytes=raw, source_path=relative
                )
                or source_generated_eval_input_witness(
                    node,
                    call_name,
                    source_bytes=raw,
                    source_path=relative,
                    builtin_identity_proven=audit._fixed_program_builtin_identity(
                        node, module, call_name
                    ),
                )
                or finite_template_witness(
                    relative, node, call_name, root, sources, workspace_profile
                )
            ):
                witness["workspace_sources_sha256"] = workspace_profile.get(
                    "sources_sha256"
                )
                return witness
            if (
                workspace_profile.get("complete") is True
                and workspace_profile.get("eval_provider_mutation_risk") is False
                and audit._fixed_program_builtin_identity(node, module, call_name)
            ):
                witness = fixed_literal_program_witness(
                    node,
                    call_name,
                    source_bytes=raw,
                    builtin_identity_proven=True,
                    source_path=relative,
                    scope_profile="native-module-or-function-omitted-namespaces",
                )
                if witness:
                    witness["workspace_sources_sha256"] = workspace_profile.get(
                        "sources_sha256"
                    )
                    return witness
            if witness := _source_built_ast_native_witness(
                audit,
                relative,
                node,
                call_name,
                module,
                workspace_profile,
                context,
                raw,
            ):
                witness["workspace_sources_sha256"] = workspace_profile.get(
                    "sources_sha256"
                )
                return witness
    return {}


def _source_built_ast_native_witness(
    audit, relative, node, call_name, module, workspace_profile, context, raw
):
    if (
        call_name != "exec"
        or not isinstance(workspace_profile, dict)
        or workspace_profile.get("complete") is not True
        or not audit._fixed_program_builtin_identity(node, module, call_name)
        or not isinstance(context, tuple)
        or len(context) != 2
        or not isinstance(context[1], dict)
    ):
        return {}
    from .finite_capture import (
        source_built_ast_program_witness,
        source_built_ast_workspace_provider_clear,
    )

    root, sources = context
    if not source_built_ast_workspace_provider_clear(sources, relative, root):
        return {}
    return source_built_ast_program_witness(
        node, call_name, source_bytes=raw, source_path=relative
    )


def _fixed_program_legacy_witness(
    audit,
    relative,
    node,
    call_name,
    module,
    workspace_profile,
    context,
    fixed_literal_program_witness,
):
    if (
        not isinstance(workspace_profile, dict)
        or workspace_profile.get("complete") is not True
        or workspace_profile.get("namespace_mutation_risk") is not False
        or not isinstance(workspace_profile.get("sources_sha256"), str)
    ):
        return {}
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return {}
    if not audit._fixed_program_builtin_identity(node, module, call_name):
        return {}
    root, sources = context
    raw = sources.get(root / relative) if isinstance(sources, dict) else None
    if not isinstance(raw, bytes) or audit.hashlib.sha256(raw).hexdigest() != getattr(
        module, "_oracle_source_sha256", None
    ):
        return {}
    witness = fixed_literal_program_witness(
        node,
        call_name,
        source_bytes=raw,
        builtin_identity_proven=True,
        source_path=relative,
        scope_profile="native-module-or-function-omitted-namespaces",
    )
    if witness:
        witness["workspace_sources_sha256"] = workspace_profile["sources_sha256"]
    return witness


def bind_fixed_program_workspace(
    audit, root, contexts, snapshots, files, source_bytes=None, imports=None
):
    """Bind the workspace builtin profile and source digest into each context, adding credential consumers only for complete snapshots."""
    import json

    from .runtime_audit_integrity import workspace_builtin_profile

    profile = workspace_builtin_profile(snapshots, files)
    profile.pop("source_hashes", None)
    sources = sorted(
        (
            path.relative_to(root).as_posix(),
            getattr(tree, "_oracle_source_sha256", None),
        )
        for path, tree in snapshots.items()
    )
    profile["sources_sha256"] = audit.hashlib.sha256(
        json.dumps(sources, separators=(",", ":")).encode()
    ).hexdigest()
    if (
        source_bytes is not None
        and imports is not None
        and set(snapshots) == set(files)
    ):
        inventory = {
            path: getattr(tree, "_oracle_source_sha256", None)
            for path, tree in snapshots.items()
        }
        audit.bind_credential_consumers(
            root, snapshots, imports, contexts, source_bytes, inventory=inventory
        )
    for context in contexts.values():
        context["fixed_program_workspace"] = {
            **profile,
            "credential_consumers": context.get("credential_consumers", {}),
            "finite_template_inputs": context.get("finite_template_inputs", {}),
        }


def fixed_program_workspace_helpers(audit):
    """Return the source and validator helpers used to construct fixed-program workspace evidence."""
    from . import runtime_audit_integrity as runtime
    from .finite_capture import (
        _source_built_ast_annotations_static,
        _source_built_ast_builder,
        _source_built_ast_constants,
        _source_built_ast_effects_closed,
        _source_built_ast_module_alias,
        _source_built_ast_owned_values,
        _source_built_ast_provider_expr,
        _source_built_ast_scope,
        _source_built_ast_sensitive_attribute,
        _source_built_ast_sink,
        source_built_ast_program_witness,
        source_built_ast_workspace_provider_clear,
        shell_execution_calls,
        _closed_shell_operation,
        _closed_shell_call_role,
        _closed_shell_provider_mutated,
        _closed_shell_provider,
        _closed_shell_namespace,
        _shell_source_provider_clear,
        _shell_import_aliases,
        _shell_dynamic_provider_access,
        _shell_namespace_queries_closed,
        closed_shell_workspace,
        closed_shell_operation_witness,
        closed_shell_finding,
    )

    return (
        audit.bind_fixed_program_workspace,
        fixed_program_proof_dispositions,
        _fixed_program_binding,
        _fixed_program_binding_base,
        _fixed_program_source_hash_bound,
        _fixed_program_disposition_bound,
        _fixed_program_chain_binding,
        _fixed_program_expected_witness,
        fixed_program_builtin_identity,
        fixed_program_witness,
        _fixed_program_native_witness,
        _fixed_program_legacy_witness,
        _source_built_ast_native_witness,
        _source_built_ast_annotations_static,
        _source_built_ast_builder,
        _source_built_ast_constants,
        _source_built_ast_effects_closed,
        _source_built_ast_module_alias,
        _source_built_ast_owned_values,
        _source_built_ast_provider_expr,
        _source_built_ast_scope,
        _source_built_ast_sensitive_attribute,
        _source_built_ast_sink,
        source_built_ast_program_witness,
        source_built_ast_workspace_provider_clear,
        shell_execution_calls,
        _closed_shell_operation,
        _closed_shell_call_role,
        _closed_shell_provider_mutated,
        _closed_shell_provider,
        _closed_shell_namespace,
        _shell_source_provider_clear,
        _shell_import_aliases,
        _shell_dynamic_provider_access,
        _shell_namespace_queries_closed,
        closed_shell_workspace,
        closed_shell_operation_witness,
        closed_shell_finding,
        runtime.workspace_builtin_profile,
        runtime._fixed_literal_program_kinds,
        runtime._fixed_literal_value,
        runtime._closed_declaration_program,
        runtime._closed_declaration_namespace,
        runtime._closed_declaration_binding,
        runtime.closed_declaration_input_witness,
        *runtime.fixed_eval_workspace_helpers(),
        runtime._fixed_program_span,
        runtime._finite_eval_comprehension,
        runtime._finite_eval_domain,
        runtime._finite_eval_module_prefix,
        runtime.finite_literal_eval_input_witness,
        runtime.finite_template_input_helpers,
        *runtime.finite_template_input_helpers(),
        audit._finite_eval_binding,
        audit._closed_declaration_binding,
        audit._valid_source_span,
        *runtime.workspace_builtin_helpers(),
        *audit.credential_consumer_helpers(),
    )


def primitive_binding_helpers():
    """Return primitive-binding validators for endpoint, fixture, declaration, finite-eval, workspace, and symbolic-identifier evidence."""
    from .credential_role_identity_effects import security_value_helper_epoch
    from .audit_action_refs import (
        _captured_application_source_bytes,
        _application_configuration_hashes,
    )
    from .credential_endpoint_admission import endpoint_evidence_helpers
    from .credential_endpoint_admission import endpoint_admission_helpers
    from .credential_endpoint_admission import catalog_callable_helpers
    from .finite_capture import (
        captured_literal_caller_program_role,
        captured_file_program_role,
        captured_registered_fixture_helper_role,
        _source_built_ast_annotations_static,
        _source_built_ast_builder,
        _source_built_ast_constants,
        _source_built_ast_effects_closed,
        _source_built_ast_module_alias,
        _source_built_ast_owned_values,
        _source_built_ast_provider_expr,
        _source_built_ast_scope,
        _source_built_ast_sensitive_attribute,
        _source_built_ast_sink,
        source_built_ast_program_witness,
        source_built_ast_workspace_provider_clear,
    )

    return (
        _primitive_source_capture,
        _unknown_collection,
        captured_literal_caller_program_role,
        captured_file_program_role,
        captured_registered_fixture_helper_role,
        fixed_program_proof_dispositions,
        _security_tier_reports_match,
        _raw_diagnostic_summary,
        _finding_source_binding,
        _finding_tier_ledger_row,
        _finding_flask_session_authority_evidence,
        _decide_finding_tier,
        _pickle_role_partition,
        _pickle_source_role_decision,
        _pickle_source_role_witness,
        _pickle_role_inventory,
        _pickle_role_model_trees,
        _regenerate_source_model,
        *security_value_helper_epoch(),
        _pickle_role_test_scope,
        _pickle_role_unittest_owners,
        _pickle_role_unittest_graph,
        _pickle_role_class_writes,
        _pickle_role_callback_risk,
        _authored_shell_source_role_witness,
        _authored_shell_literal_input,
        _authored_shell_bound_input,
        *_registered_fixture_helpers(),
        fixed_primitive_binding,
        _local_control_label_binding,
        _jwt_primitive_binding,
        _jwt_primitive_common,
        _jwt_primitive_identity,
        _jwt_primitive_declared_span,
        _jwt_operation_spans_valid,
        _fixed_program_binding,
        closed_shell_binding,
        _jwt_operation_recomputes_from_sources,
        _jwt_bound_source_inventory,
        _jwt_declaration_targets,
        _jwt_captured_api_imports,
        rejected_primitive_proof,
        partition_proven_primitive_observations,
        _partition_proven_primitive_observations,
        _pickle_byte_origin_fields,
        _finding_pickle_byte_origin,
        _pickle_byte_origins_for_source,
        _application_role_rebuild_index,
        _current_primitive_binding,
        annotate_django_fixture,
        django_fixture_binding,
        _django_fixture_inventory,
        _django_fixture_claim,
        _django_fixture_identity,
        _django_fixture_hashes,
        _django_fixture_span,
        _proof_facts_digest,
        annotate_application_fixture,
        application_fixture_binding,
        _application_fixture_inventory,
        _application_fixture_claim,
        _application_fixture_use_proof,
        _application_class_source_inputs,
        _application_fixture_role_recomputes,
        _application_class_role_recomputes,
        _application_credential_role_recomputes,
        _captured_application_source_bytes,
        _application_configuration_hashes,
        _application_role_binding,
        _application_witness_bindings,
        _application_use_closure_binding,
        _application_closure_ast_rows,
        _application_closure_span_index,
        _application_closure_assignment_ast_rows,
        _application_closure_use_ast_rows,
        _application_closure_operation_ast_rows,
        _application_closure_rows_bound,
        _application_closure_local_row,
        _application_closure_operation_row,
        _application_closure_use_containment,
        _source_span_contains,
        _presentation_witness_bindings,
        _presentation_witness_row,
        _presentation_data_role_recomputes,
        _application_assurance_binding,
        closed_declaration_binding,
        _closed_declaration_claim,
        _closed_declaration_profile,
        _closed_declaration_identity,
        _closed_declaration_literal,
        _django_fixture_inventory,
        _django_fixture_claim,
        _proof_facts_digest,
        _fixed_builtin_call_identity,
        valid_source_span,
        finite_eval_binding,
        fixed_program_builtin_identity,
        _fixed_builtin_call_identity,
        _fixed_builtin_source_unshadowed,
        _fixed_builtin_nodes_unshadowed,
        _fixed_builtin_node_is_shadow,
        fixed_program_witness,
        _fixed_program_native_witness,
        _fixed_program_legacy_witness,
        _source_built_ast_native_witness,
        _source_built_ast_annotations_static,
        _source_built_ast_builder,
        _source_built_ast_constants,
        _source_built_ast_effects_closed,
        _source_built_ast_module_alias,
        _source_built_ast_owned_values,
        _source_built_ast_provider_expr,
        _source_built_ast_scope,
        _source_built_ast_sensitive_attribute,
        _source_built_ast_sink,
        _fixed_program_expected_witness,
        source_built_ast_program_witness,
        source_built_ast_workspace_provider_clear,
        bind_fixed_program_workspace,
        fixed_program_workspace_helpers,
        credential_context_cache_schema,
        *endpoint_evidence_helpers(),
        *endpoint_admission_helpers(),
        *catalog_callable_helpers(),
    )


def credential_context_cache_schema():
    """Return the versioned oracle-context cache key derived from the current publication catalog digest."""
    from .credential_endpoint_admission import catalog_content_digest

    return "factory.security-oracle-context-cache.v8:" + catalog_content_digest()


def _raw_diagnostic_summary(raw_findings, total):
    """Count original diagnostics without altering their severity or code."""
    return {
        "count": total,
        "by_severity": dict(
            sorted(
                (
                    severity,
                    sum(
                        row.get("severity") == severity
                        for row in raw_findings
                        if isinstance(row, dict)
                    ),
                )
                for severity in {
                    row.get("severity")
                    for row in raw_findings
                    if isinstance(row, dict) and isinstance(row.get("severity"), str)
                }
            )
        ),
        "by_code": dict(
            sorted(
                (
                    code,
                    sum(
                        row.get("code") == code
                        for row in raw_findings
                        if isinstance(row, dict)
                    ),
                )
                for code in {
                    row.get("code")
                    for row in raw_findings
                    if isinstance(row, dict) and isinstance(row.get("code"), str)
                }
            )
        ),
    }


def _finding_source_binding(finding, bindings, source_bytes):
    """Bind one diagnostic to the captured bytes and declared source hash."""
    path = finding.get("path")
    source_hash = bindings.get(path) if isinstance(path, str) else None
    captured = source_bytes.get(path) if isinstance(path, str) else None
    bound_source = (
        isinstance(captured, bytes)
        and isinstance(source_hash, str)
        and hashlib.sha256(captured).hexdigest() == source_hash
    )
    return path, source_hash, captured, bound_source


def _finding_tier_ledger_row(
    index,
    raw,
    bindings,
    source_bytes,
    caches,
    primitive_rows,
    coverage_state,
    partition_state,
):
    """Regenerate one source-bound tier without discarding its raw diagnostic."""
    regenerated, signing_cache, pickle_origin_cache = caches
    if not isinstance(raw, dict):
        raw = {"diagnostic_value": copy.deepcopy(raw)}
    finding = copy.deepcopy(raw)
    path, source_hash, captured, bound_source = _finding_source_binding(
        finding, bindings, source_bytes
    )
    native_rows = _finding_native_rows(
        finding, captured, bound_source, regenerated, source_bytes, bindings
    )
    signing_evidence = _finding_signing_evidence(
        finding,
        native_rows,
        bound_source,
        source_bytes,
        bindings,
        coverage_state,
        partition_state,
        signing_cache,
    )
    credential_evidence = _finding_private_key_authentication_evidence(
        finding,
        native_rows,
        bound_source,
        source_bytes,
        bindings,
        coverage_state,
        partition_state,
        signing_cache,
    )
    if credential_evidence is None:
        credential_evidence = _finding_flask_session_authority_evidence(
            finding,
            native_rows,
            bound_source,
            source_bytes,
            bindings,
            coverage_state,
            partition_state,
            signing_cache,
        )
    tier, evidence, evidence_details = _decide_finding_tier(
        finding,
        bound_source,
        native_rows,
        primitive_rows,
        credential_evidence,
    )
    identity = _tier_sha256(
        {
            "index": index,
            "path": path,
            "source_sha256": source_hash,
            "code": finding.get("code"),
            "line": finding.get("line"),
            "column": finding.get("column"),
            "original_severity": finding.get("severity"),
            "raw_finding": finding,
        }
    )
    row = {
        "index": index,
        "tier": tier,
        "gate_relevant": str(finding.get("code", "")).startswith("SECURITY_"),
        "evidence": evidence,
        "original_severity": finding.get("severity"),
        "source_identity": {
            "path": path,
            "source_sha256": source_hash,
            "line": finding.get("line"),
            "column": finding.get("column"),
            "code": finding.get("code"),
            "identity_sha256": identity,
        },
        "raw_finding": finding,
    }
    if (
        bound_source
        and _matches_regenerated_finding(finding, native_rows)
        and _known_format_declaration(finding, captured)
    ):
        row["material_observation"] = {
            "kind": "KNOWN_CREDENTIAL_FORMAT",
            "source_bound": True,
            "credential_validity": "NOT_ESTABLISHED",
            "security_authority": "UNASSESSED",
        }
    if tier == "NEEDS_CONTEXT":
        row["missing_premises"] = _finding_missing_premises(finding, bound_source)
    row.update(
        _pickle_byte_origin_fields(
            finding, captured, bound_source, pickle_origin_cache, tier
        )
    )
    if signing_evidence is not None:
        row["static_consumer_observation"] = signing_evidence
    if credential_evidence is not None:
        row["credential_authority_observation"] = credential_evidence
    if evidence_details is not None:
        row["evidence_details"] = evidence_details
    return row


def _pickle_source_role_decision(
    roles, active, reviews, ledger, policy_id="source-role-v1"
):
    """Describe unresolved context review without claiming safe reconstruction."""
    policy = {
        "source-role-v2": _SOURCE_ROLE_POLICY_V2,
        "source-role-v3": _SOURCE_ROLE_POLICY_V3,
    }.get(policy_id, _PICKLE_SOURCE_ROLE_POLICY)
    return {
        **policy,
        "policy_sha256": _tier_sha256(policy),
        "state": "BLOCKED"
        if roles is None
        else "ALERTS_AND_CONTEXT_REVIEW"
        if active
        else "CONTEXT_REVIEW_REQUIRED",
        "exit_code": 2 if roles is None else 1 if active else 0,
        "active_alert_count": len(active),
        "context_review_count": len(reviews),
        "source_sha256": None if roles is None else roles["sources_sha256"],
        "evidence_sha256": _tier_sha256(
            {
                "sources": None if roles is None else roles["sources_sha256"],
                "reviews": [row.get("source_role_review") for row in ledger],
            }
        ),
        "clean": False,
        "passed": False,
        "release_approved": False,
    }


def _registered_fixture_helpers():
    return (
        _registered_fixture_role_witness,
        _registered_fixture_entry,
        _registered_fixture_registration,
        _registered_fixture_recipe,
        _registered_fixture_recipe_ast,
        _registered_fixture_flow,
        _registered_fixture_expr,
        _registered_fixture_step,
        _registered_fixture_namespace,
        _registered_fixture_prefix,
        _registered_fixture_module_clear,
        _registered_fixture_assign,
        _registered_fixture_profile,
    )


def _registered_fixture_recipe_ast(tree, marker, directory):
    """Canonicalize one finite runner recipe; preserve all executable statements.

    Only module-owned function names and the registration marker/directory may
    vary. Imported providers, local bindings, control flow, calls and literals
    otherwise remain exact. This is an observed protocol, never a safety proof.
    """
    tree = copy.deepcopy(tree)
    names = {
        node.name: f"_stage_{index}"
        for index, node in enumerate(tree.body)
        if isinstance(node, ast.FunctionDef)
    }
    for node in ast.walk(tree):
        if "type_params" in node._fields and not node.type_params:
            node._fields = tuple(
                field for field in node._fields if field != "type_params"
            )
        if isinstance(node, ast.FunctionDef):
            node.name = names.get(node.name, node.name)
        elif isinstance(node, ast.Name):
            node.id = names.get(node.id, node.id)
        elif isinstance(node, ast.Attribute) and node.attr == marker:
            node.attr = "_registered_input_suffixes"
        elif isinstance(node, ast.Constant) and node.value == marker:
            node.value = "_registered_input_suffixes"
        elif isinstance(node, ast.Constant) and node.value == directory:
            node.value = "_fixture_directory"
    return ast.dump(tree, include_attributes=False)


def _registered_fixture_recipe(tree, marker):
    """Match the complete reviewed fixture-discovery/invocation recipe.

    The finite semantic profile includes argument filtering, error reporting
    and every module statement, so adding a write/hook anywhere invalidates it.
    Its digest is of canonical executable AST, not a repository or file hash.
    """
    anchors = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "DATA"
    ]
    if len(anchors) != 1:
        return None
    anchor = anchors[0]
    expr = anchor.value
    if not (
        isinstance(expr, ast.Call)
        and ast.unparse(expr.func) == "str"
        and len(expr.args) == 1
        and not expr.keywords
        and isinstance(expr.args[0], ast.BinOp)
        and isinstance(expr.args[0].op, ast.Div)
        and ast.unparse(expr.args[0].left) == "pathlib.Path(__file__).parent"
        and isinstance(expr.args[0].right, ast.Constant)
        and type(expr.args[0].right.value) is str
        and re.fullmatch(r"[A-Za-z0-9_-]+", expr.args[0].right.value)
    ):
        return None
    canonical = _registered_fixture_recipe_ast(tree, marker, expr.args[0].right.value)
    recipe = hashlib.sha256(canonical.encode()).hexdigest()
    # registered-fixture-runner-v1: discovery -> suffix-bound DATA filenames ->
    # executor(function,*filenames), with captured result/error reporting.
    if recipe != _registered_fixture_profile():
        return None
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    return {
        "profile": "registered-fixture-runner-v1",
        "ast_sha256": recipe,
        "data_anchor_span": _pickle_span(anchor),
        "stage_spans": [_pickle_span(node) for node in functions],
    }


def _registered_fixture_registration(tree, function):
    registrations = [
        item
        for node in tree.body
        if (item := _registered_fixture_registration_row(node, function))
    ]
    if (
        len(registrations) != 1
        or function.decorator_list
        or _pickle_role_disabled(function)
    ):
        return None
    registration, target, suffixes = registrations[0]
    if registration.lineno <= function.end_lineno:
        return None
    if not _registered_fixture_namespace_closed(tree, function, target):
        return None
    parameters = _registered_fixture_signature(function, suffixes)
    if parameters is None:
        return None
    return registration, target.attr, parameters


def _registered_fixture_registration_row(node, function):
    if (
        not isinstance(node, ast.Assign)
        or len(node.targets) != 1
        or not isinstance(node.value, ast.List)
    ):
        return None
    target = node.targets[0]
    if not (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == function.name
    ):
        return None
    suffixes = [
        item.value for item in node.value.elts if isinstance(item, ast.Constant)
    ]
    if (
        len(suffixes) != len(node.value.elts)
        or not suffixes
        or not all(
            type(item) is str and re.fullmatch(r"\.[A-Za-z0-9_-]+", item)
            for item in suffixes
        )
    ):
        return None
    return node, target, suffixes


def _registered_fixture_namespace_closed(tree, function, target):
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == function.name
        ):
            return False
        if isinstance(node, ast.Subscript) and ast.unparse(node.value) in {
            "globals()",
            "locals()",
        }:
            if (
                not isinstance(node.ctx, ast.Load)
                or not isinstance(node.slice, ast.Constant)
                or node.slice.value == function.name
            ):
                return False
        if isinstance(node, ast.Call) and ast.unparse(node.func) in {
            "globals().update",
            "locals().update",
        }:
            return False
    allowed = {id(target.value)}
    if any(
        isinstance(node, ast.Name)
        and node.id == function.name
        and id(node) not in allowed
        for node in ast.walk(tree)
    ):
        return False
    definitions = sum(
        isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == function.name
        for node in ast.walk(tree)
    )
    return definitions == 1


def _registered_fixture_signature(function, suffixes):
    parameters = function.args.posonlyargs + function.args.args
    if (
        function.args.vararg
        or function.args.kwarg
        or function.args.kwonlyargs
        or len(parameters) != len(suffixes) + 1
        or parameters[-1].arg != "verbose"
        or len(function.args.defaults) != 1
        or not isinstance(function.args.defaults[0], ast.Constant)
        or function.args.defaults[0].value is not False
    ):
        return None
    return [item.arg for item in parameters[:-1]]


def _registered_fixture_entry(tree, path, marker, inventory):
    entries = [
        entry
        for node in tree.body
        if (entry := _registered_fixture_entry_candidate(node, path, marker, inventory))
    ]
    return entries[0] if len(entries) == 1 else None


def _registered_fixture_entry_candidate(node, path, marker, inventory):
    call = _registered_fixture_main_call(node)
    if call is None:
        return None
    alias = node.body[0].names[0]
    harness_path = str(PurePosixPath(path).parent / (alias.name + ".py"))
    harness = inventory["trees"].get(harness_path)
    if harness is None or not _registered_fixture_harness_unique(
        alias.name, harness_path, inventory
    ):
        return None
    recipe = _registered_fixture_recipe(harness, marker)
    functions = [
        item.name for item in harness.body if isinstance(item, ast.FunctionDef)
    ]
    if not recipe or not functions or call.func.attr != functions[-1]:
        return None
    return {
        "path": harness_path,
        "sha256": hashlib.sha256(inventory["sources"][harness_path]).hexdigest(),
        "entry_span": _pickle_span(call),
        "recipe": recipe,
    }


def _registered_fixture_main_call(node):
    if (
        not isinstance(node, ast.If)
        or ast.unparse(node.test) != "__name__ == '__main__'"
        or node.orelse
    ):
        return None
    if len(node.body) != 2 or not isinstance(node.body[0], ast.Import):
        return None
    imported = node.body[0]
    if len(imported.names) != 1 or "." in imported.names[0].name:
        return None
    expr = node.body[1]
    if not isinstance(expr, ast.Expr) or not isinstance(expr.value, ast.Call):
        return None
    call = expr.value
    alias = imported.names[0]
    if (
        not isinstance(call.func, ast.Attribute)
        or not isinstance(call.func.value, ast.Name)
        or call.func.value.id != (alias.asname or alias.name)
        or call.keywords
        or len(call.args) != 1
        or ast.unparse(call.args[0]) != "globals()"
    ):
        return None
    return call


def _registered_fixture_harness_unique(module_name, harness_path, inventory):
    harness = inventory["trees"][harness_path]
    providers = {
        alias.name.split(".")[0]
        for item in harness.body
        if isinstance(item, ast.Import)
        for alias in item.names
    }
    if any(
        PurePosixPath(name).stem in providers
        or PurePosixPath(name).name == "__init__.py"
        and PurePosixPath(name).parent.name in providers
        for name in inventory["trees"]
    ):
        return False
    module_paths = [
        name
        for name in inventory["trees"]
        if PurePosixPath(name).stem == module_name
        or name.endswith("/" + module_name + "/__init__.py")
    ]
    return module_paths == [harness_path]


def _registered_fixture_expr(node, bindings):
    """Trace source-visible fixture dependencies; opaque calls do not prove effects."""
    if not _registered_fixture_expr_is_supported(node):
        return None
    if isinstance(node, ast.Constant):
        return frozenset()
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.Attribute):
        return _registered_fixture_expr(node.value, bindings)
    if isinstance(node, ast.Subscript):
        return _registered_fixture_subscript_expr(node, bindings)
    if isinstance(node, ast.Call):
        result = _registered_fixture_call_expr(node, bindings)
        if result is None:
            return None
        values = result
    else:
        values = list(ast.iter_child_nodes(node))
        values = [item for item in values if isinstance(item, ast.expr)]
    parts = [_registered_fixture_expr(value, bindings) for value in values]
    if (
        any(part is None for part in parts)
        or isinstance(node, ast.Call)
        and any("provider" in part for part in parts)
    ):
        return None
    result = frozenset().union(*parts)
    if (
        isinstance(node, ast.Call)
        and not result
        and not _registered_fixture_pure_call(node)
    ):
        return None
    return result


def _registered_fixture_expr_is_supported(node):
    return isinstance(node, ast.expr) and not ast.unparse(node).startswith(
        ("os.environ", "sys.argv", "request.", "requests.", "socket.")
    )


def _registered_fixture_subscript_expr(node, bindings):
    origin = _registered_fixture_expr(node.value, bindings)
    if not origin or not origin.intersection({"fixture", "sink"}):
        return None
    return _registered_fixture_join_values([node.value, node.slice], bindings)


def _registered_fixture_join_values(values, bindings):
    parts = [_registered_fixture_expr(value, bindings) for value in values]
    if any(part is None for part in parts):
        return None
    return frozenset().union(*parts)


def _registered_fixture_call_expr(node, bindings):
    name = ast.unparse(node.func)
    aliases = bindings.get(None, {})
    root = name.split(".")[0]
    name = aliases.get(root, root) + name[len(root) :]
    if name.startswith(("request.", "requests.", "socket.", "os.environ", "sys.argv")):
        return None
    if (
        isinstance(node.func, ast.Name)
        and node.func.id not in bindings
        and node.func.id
        not in {
            "list",
            "str",
            "bytes",
            "len",
            "eval",
            "exec",
            "globals",
            "locals",
            "open",
        }
    ):
        return None
    values = node.args + [
        keyword.value
        for keyword in node.keywords
        if _registered_fixture_expr(keyword.value, bindings) != frozenset({"provider"})
    ]
    if isinstance(node.func, ast.Attribute) and _registered_fixture_expr(
        node.func.value, bindings
    ) != frozenset({"provider"}):
        values = [node.func.value, *values]
    return values


def _registered_fixture_pure_call(node):
    return ast.unparse(node.func) in {
        "globals",
        "locals",
        "list",
        "str",
        "bytes",
        "globals().copy",
        "locals().copy",
    }


def _registered_fixture_assign(node, bindings, sink):
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        value = _registered_fixture_expr(node.value, bindings)
        if value is not None and sink in ast.walk(node.value):
            value |= {"sink"}
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                bindings[target.id] = value
            else:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name) and name.id in bindings:
                        bindings[name.id] = None


def _registered_fixture_step(node, bindings, paths, sink):
    if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
        bindings[node.target.id] = frozenset()
    if isinstance(node, ast.With):
        _registered_fixture_with_items(node, bindings, paths)
    _registered_fixture_assign(node, bindings, sink)
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        _registered_fixture_mutation(node.value, bindings)
    if (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and node.value is sink
    ):
        # exec's explicit namespace receives the output of this test operation.
        if (
            ast.unparse(sink.func) == "exec"
            and len(sink.args) > 1
            and isinstance(sink.args[1], ast.Name)
        ):
            bindings[sink.args[1].id] = frozenset({"sink"})


def _registered_fixture_with_items(node, bindings, paths):
    for item in node.items:
        if isinstance(item.optional_vars, ast.Name):
            bindings[item.optional_vars.id] = None
        call = item.context_expr
        if _registered_fixture_open_call(call, item.optional_vars, bindings, paths):
            bindings[item.optional_vars.id] = frozenset({"fixture"})


def _registered_fixture_open_call(call, optional, bindings, paths):
    if not (
        isinstance(call, ast.Call)
        and ast.unparse(call.func) == "open"
        and call.args
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id in paths
        and len(call.args) <= 2
        and not call.keywords
        and isinstance(optional, ast.Name)
    ):
        return False
    name = call.args[0].id
    valid_mode = (
        len(call.args) == 1
        or isinstance(call.args[1], ast.Constant)
        and call.args[1].value in {"r", "rb"}
    )
    return bindings.get(name) == frozenset({"path:" + name}) and valid_mode


def _registered_fixture_mutation(call, bindings):
    if not isinstance(call.func, ast.Attribute) or not isinstance(
        call.func.value, ast.Name
    ):
        return
    name = call.func.value.id
    origin = bindings.get(name)
    if origin is None or "provider" in origin:
        return
    effect = _registered_fixture_expr(call, bindings)
    if effect is None:
        bindings[name] = None
    elif call.func.attr in {"append", "extend"}:
        bindings[name] |= effect


def _registered_fixture_namespace(tree):
    bindings = {None: {}}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            bindings[node.name] = frozenset({"provider"})
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                bindings[local] = frozenset({"provider"})
                bindings[None][local] = (
                    node.module + "." + alias.name
                    if isinstance(node, ast.ImportFrom) and node.module
                    else alias.name
                )
    return bindings


def _registered_fixture_prefix(function, sink, bindings):
    if any(
        isinstance(node, ast.If)
        and node.lineno < sink.lineno
        and any(
            isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            for item in ast.walk(node)
        )
        for node in ast.walk(function)
    ):
        return False
    if any(
        isinstance(
            node, (ast.AugAssign, ast.NamedExpr, ast.Delete, ast.Global, ast.Nonlocal)
        )
        for node in ast.walk(function)
    ):
        return False
    if any(
        isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        )
        and node is not function
        for node in ast.walk(function)
    ):
        return False
    for node in ast.walk(function):
        if isinstance(node, (ast.For, ast.AsyncFor)) and node.lineno < sink.lineno:
            if not isinstance(node.target, ast.Name) or not isinstance(
                node.iter, (ast.List, ast.Tuple)
            ):
                return False
            if not all(isinstance(item, ast.Constant) for item in node.iter.elts):
                return False
        if (
            isinstance(node, ast.Try)
            and node.lineno < sink.lineno
            and any(
                isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                for handler in node.handlers
                for item in ast.walk(handler)
            )
        ):
            return False
    return True


def _registered_fixture_flow(function, sink, parameters, tree):
    bindings = _registered_fixture_namespace(tree)
    bindings.update({name: frozenset({"path:" + name}) for name in parameters})
    observations, transformations, reads, saw_sink = [], [], [], False
    if not _registered_fixture_prefix(function, sink, bindings):
        return None
    nodes = sorted(
        (
            node
            for node in ast.walk(function)
            if isinstance(
                node,
                (
                    ast.Assign,
                    ast.AnnAssign,
                    ast.With,
                    ast.For,
                    ast.Expr,
                    ast.Assert,
                    ast.Try,
                ),
            )
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for node in nodes:
        if not saw_sink and node.lineno >= sink.lineno:
            origin = (
                _registered_fixture_expr(sink.args[0], bindings) if sink.args else None
            )
            if origin is None or "fixture" not in origin:
                return None
            saw_sink = True
        _registered_fixture_step(node, bindings, parameters, sink)
        node_reads, node_transformations, node_observations = (
            _registered_fixture_node_evidence(node, bindings, sink, saw_sink)
        )
        reads.extend(node_reads)
        transformations.extend(node_transformations)
        observations.extend(node_observations)
    return (
        {
            "oracle_spans": observations,
            "read_spans": reads,
            "registered_filename_parameters": parameters,
            "transformations": transformations,
            "sink_input_ast_sha256": _tier_sha256(
                ast.dump(sink.args[0], include_attributes=False)
            ),
            "effects": "UNASSESSED",
        }
        if observations
        else None
    )


def _registered_fixture_node_evidence(node, bindings, sink, saw_sink):
    reads = _registered_fixture_read_spans(node, bindings)
    transformations = _registered_fixture_transformations(node, bindings)
    observations = _registered_fixture_observations(node, bindings, sink, saw_sink)
    return reads, transformations, observations


def _registered_fixture_read_spans(node, bindings):
    if not isinstance(node, ast.With):
        return []
    return [
        _pickle_span(item.context_expr)
        for item in node.items
        if isinstance(item.optional_vars, ast.Name)
        and bindings.get(item.optional_vars.id) == frozenset({"fixture"})
    ]


def _registered_fixture_transformations(node, bindings):
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return []
    value = _registered_fixture_expr(node.value, bindings)
    if not value or not value.intersection({"fixture", "sink"}):
        return []
    return [
        {
            "span": _pickle_span(node),
            "ast_sha256": _tier_sha256(ast.dump(node, include_attributes=False)),
        }
    ]


def _registered_fixture_observations(node, bindings, sink, saw_sink):
    if not saw_sink:
        return []
    if isinstance(node, ast.Assert):
        value = _registered_fixture_expr(node.test, bindings)
        return [_pickle_span(node)] if value is not None and "sink" in value else []
    if isinstance(node, ast.Try) and node.orelse and node.handlers:
        return (
            [_pickle_span(node)]
            if _registered_fixture_try_is_observation(node, bindings)
            else []
        )
    return []


def _registered_fixture_try_is_observation(node, bindings):
    calls = [
        item
        for statement in node.body
        for item in ast.walk(statement)
        if isinstance(item, ast.Call)
    ]
    linked = any(
        "sink" in (_registered_fixture_expr(call, bindings) or ()) for call in calls
    )
    raises = any(
        isinstance(item, ast.Raise)
        and item.exc is not None
        and ast.unparse(item.exc).startswith("AssertionError(")
        for statement in node.orelse
        for item in ast.walk(statement)
    )
    return linked and raises


def _registered_fixture_module_clear(tree, entry_span=None):
    protected = {
        "open",
        "globals",
        "locals",
        "list",
        "str",
        "bytes",
        "len",
        "eval",
        "exec",
        "__name__",
        "__builtins__",
    }
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in protected
            and not isinstance(node.ctx, ast.Load)
        ):
            return False
        if isinstance(node, ast.arg) and node.arg in protected:
            return False
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in protected:
            return False
        if (
            isinstance(node, ast.alias)
            and (node.asname or node.name.split(".")[0]) in protected
        ):
            return False
        if isinstance(node, ast.Call) and ast.unparse(node.func) in {
            "globals",
            "locals",
            "vars",
        }:
            parent = parents.get(node)
            copied = isinstance(parent, ast.Attribute) and parent.attr == "copy"
            passed = (
                isinstance(parent, ast.Call)
                and parent.args == [node]
                and _pickle_span(parent) == entry_span
            )
            if not copied and not passed:
                return False
    return not _pickle_role_disabled(tree)


def _registered_fixture_role_witness(finding, inventory):
    if (
        finding.get("code")
        not in {"SECURITY_UNSAFE_YAML", "SECURITY_DYNAMIC_EXECUTION"}
        or _valid_security_precondition(
            finding.get("facts", {}).get("security_precondition"), finding
        )
        or finding.get("path") not in inventory["trees"]
    ):
        return None
    path = finding["path"]
    if _pickle_operational_importer(
        path, inventory["trees"]
    ) or not _pickle_role_native_match(finding, inventory):
        return None
    tree = inventory["trees"][path]
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (node.lineno, node.col_offset)
        == (finding.get("line"), finding.get("column", 0))
    ]
    if len(calls) != 1:
        return None
    sink = calls[0]
    owners = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and sink in ast.walk(node)
    ]
    if len(owners) != 1:
        return None
    function = owners[0]
    registration = _registered_fixture_registration(tree, function)
    if registration is None:
        return None
    statement, marker, parameters = registration
    entry = _registered_fixture_entry(tree, path, marker, inventory)
    flow = _registered_fixture_flow(function, sink, parameters, tree)
    if (
        entry is None
        or flow is None
        or not _registered_fixture_module_clear(tree, entry["entry_span"])
    ):
        return None
    return {
        "schema": "factory.security.registered-fixture-context.v1",
        "role": "REGISTERED_FIXTURE_HARNESS_OPERATION",
        "tier": "NEEDS_CONTEXT",
        "source_path": path,
        "source_sha256": hashlib.sha256(inventory["sources"][path]).hexdigest(),
        "sources_sha256": inventory["sources_sha256"],
        "sink_span": _pickle_span(sink),
        "function_span": _pickle_span(function),
        "registration_span": _pickle_span(statement),
        "harness": entry,
        "input_flow": flow,
        "safe_operation": False,
        "fixture_payloads": "UNASSESSED",
        "filesystem_authority": "UNASSESSED",
        "dynamic_deployment": "UNASSESSED",
        "original_severity": finding.get("severity"),
        "policy_sha256": _tier_sha256(_SOURCE_ROLE_POLICY_V2),
    }


# The canonical executable-AST profile is reconstructed and independently reviewed
# from the captured runner; comments, whitespace and owning function names differ
# freely, while additional/mutated executable statements fail closed.
def _registered_fixture_profile():
    return "cd7f402b425a5dd00386aa4763891c617a0acfde1f0797fb779c879edd0f5713"
