"""Source-binding checks for retained primitive observations."""

import ast
import copy
import hashlib
import json
import re
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
    primitive_rows = [row for row in primitive_observations if isinstance(row, dict)]
    ledger = []
    for index, raw in enumerate(raw_findings):
        if not isinstance(raw, dict):
            raw = {"diagnostic_value": copy.deepcopy(raw)}
        finding = copy.deepcopy(raw)
        path = finding.get("path")
        source_hash = bindings.get(path) if isinstance(path, str) else None
        captured = source_bytes.get(path) if isinstance(path, str) else None
        bound_source = (
            isinstance(captured, bytes)
            and isinstance(source_hash, str)
            and hashlib.sha256(captured).hexdigest() == source_hash
        )
        native_rows = _finding_native_rows(finding, captured, bound_source, regenerated)
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
        if signing_evidence is not None:
            row["static_consumer_observation"] = signing_evidence
        if credential_evidence is not None:
            row["credential_authority_observation"] = credential_evidence
        if evidence_details is not None:
            row["evidence_details"] = evidence_details
        ledger.append(row)

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
        "raw_diagnostics": {
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
                        if isinstance(row, dict)
                        and isinstance(row.get("severity"), str)
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
        },
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


def _finding_native_rows(finding, captured, bound, cache):
    facts = finding.get("facts", {})
    if not bound or not (
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        or isinstance(facts, dict)
        and isinstance(facts.get("security_precondition"), dict)
    ):
        return []
    path = finding["path"]
    if path not in cache:
        cache[path] = _regenerate_native_findings(path, captured)
    return cache[path]


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


def _decide_finding_tier(
    finding, bound, native_rows, primitives, credential_evidence=None
):
    if bound and credential_evidence is not None:
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


def _regenerate_native_findings(path, source_bytes):
    """Re-run only the native security producer against the bound source bytes."""
    try:
        relative = PurePosixPath(path)
        if relative.is_absolute() or ".." in relative.parts:
            return []
        from . import review_audits as audit

        root = Path(".")
        source_path = root.joinpath(*relative.parts)
        tree = ast.parse(source_bytes)
        return audit._security_scan_tree(root, source_path, tree)
    except Exception:
        return []


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
    return any(
        candidate.get("code") == finding.get("code")
        and candidate.get("path") == finding.get("path")
        and candidate.get("line") == finding.get("line")
        and candidate.get("column") == finding.get("column")
        and candidate.get("facts", {}).get("security_precondition") == premise
        for candidate in native_rows
        if isinstance(candidate, dict) and isinstance(candidate.get("facts"), dict)
    )


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
    captured = _jwt_bound_source_inventory({path: source_bytes.get(path)}, {path: bindings.get(path)})
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
        return len(targets) == 1 and audit._literal_assignment_diagnostic(path, *targets[0], aliases) == finding
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return False


def _closed_literal_pickle_binding(finding, sources, bindings, source_bytes):
    from . import review_audits as audit

    captured = _jwt_bound_source_inventory(source_bytes, bindings) if isinstance(source_bytes, dict) else None
    if captured is None or len(sources) != len(bindings):
        return False
    path = finding.get("path")
    raw = captured.get(Path(path)) if isinstance(path, str) else None
    if raw is None:
        return False
    try:
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        rows = audit._security_scan_tree(Path("."), Path(path), tree, oracle_context={
            "_security_source_context": (Path("."), captured)
        })
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return False
    return any(row.get("code") == finding.get("code") and row.get("line") == finding.get("line")
               and row.get("column") == finding.get("column") and row.get("facts") == finding.get("facts")
               for row in rows)


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


def _fixed_program_binding(
    finding, facts, sources, bindings, integrity, source_bytes=None
):
    if not _fixed_program_binding_base(finding, facts, sources, bindings, integrity):
        return False
    if facts.get("disposition") != "PROVEN_FIXED_LITERAL_PROGRAM":
        return True
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
    if disposition == "PROVEN_FINITE_LITERAL_EVAL_INPUT":
        return integrity._finite_eval_binding(finding)
    return integrity._closed_declaration_binding(finding)


def _fixed_program_chain_binding(finding, facts, sources, source_bytes, integrity):
    source_path = finding.get("path")
    raw = source_bytes.get(source_path)
    if raw is None:
        raw = source_bytes.get(Path(source_path))
    if not isinstance(raw, bytes):
        return False
    if hashlib.sha256(raw).hexdigest() != facts.get("source_sha256"):
        return False
    call_span = facts.get("call_span")
    if not valid_source_span(call_span) or call_span[:2] != [
        finding.get("line"),
        finding.get("column"),
    ]:
        return False
    try:
        tree = ast.parse(raw, filename=source_path)
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

    if not fixed_eval_workspace_provider_clear(source_bytes, sources):
        return False
    node = calls[0]
    if not _fixed_eval_builtin_source_clear(tree, node):
        return False
    expected = _fixed_program_expected_witness(node, facts, raw, source_path)
    if not expected:
        return False
    fields = (
        "schema",
        "disposition",
        "source_path",
        "source_sha256",
        "call_span",
        "literal_span",
        "program_sha256",
        "statement_kinds",
        "def_use_witness",
        "profile",
    )
    return all(facts.get(key) == expected.get(key) for key in fields)


def _fixed_program_expected_witness(node, facts, raw, source_path):
    from .runtime_audit_integrity import fixed_literal_program_witness

    profile = facts.get("profile")
    scope = profile.get("scope") if isinstance(profile, dict) else None
    return fixed_literal_program_witness(
        node,
        facts.get("call"),
        source_bytes=raw,
        builtin_identity_proven=True,
        source_path=source_path,
        scope_profile=scope,
    )


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
        if facts.get("disposition") not in {
            "PROVEN_FIXED_LITERAL_PROGRAM",
            "PROVEN_CLOSED_DECLARATION_INPUT",
            "PROVEN_FINITE_LITERAL_EVAL_INPUT",
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
            finding, core, bindings, audit
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
        core.get("_primitive_source_bytes", {}),
        coverage_state=(coverage.get("complete") is True),
        partition_state="VALIDATED"
        if coverage.get("complete") is True
        else "INCOMPLETE",
    )


def _current_primitive_binding(finding, core, bindings, audit):
    sources = core.get("sources", [])
    if (
        finding.get("facts", {}).get("disposition")
        == "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX"
    ):
        return closed_shell_binding(
            finding, sources, bindings, core.get("_primitive_source_bytes")
        )
    if finding.get("facts", {}).get("disposition") in {
        "TEST_OWNED_LOCAL_FIXTURE",
        "TEST_OWNED_APPLICATION_CREDENTIAL",
        "SOURCE_PRESENTATION_METADATA",
    }:
        configs = core.get("oracle_context", {}).get("configuration_sources", [])
        sources = [*sources, *configs]
        bindings = {row["path"]: row["sha256"] for row in sources}
    return audit._fixed_primitive_binding(
        finding, sources, bindings, core.get("_primitive_source_bytes")
    )


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
    if (
        not isinstance(source_bytes, dict)
        or not isinstance(bindings, dict)
        or not isinstance(configs, dict)
        or set(source_bytes) != set(bindings)
        or len(source_bytes) > 2003
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
        or not set(configs) <= {"pyproject.toml", "requirements.txt", "tox.ini"}
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
    return {}


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
    from .audit_action_refs import (
        _captured_application_source_bytes,
        _application_configuration_hashes,
    )
    from .credential_endpoint_admission import endpoint_evidence_helpers
    from .credential_endpoint_admission import endpoint_admission_helpers
    from .credential_endpoint_admission import catalog_callable_helpers

    return (
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
