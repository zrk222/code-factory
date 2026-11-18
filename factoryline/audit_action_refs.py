"""Resolve agent work references without promoting report text to instructions."""

from __future__ import annotations

import ast
import re
import json
from collections import Counter, OrderedDict
from contextvars import ContextVar
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace
from typing import Any
from pathlib import Path

from .runtime_audit_common import canonical_bytes

from .audit_taxonomy import _canonical


_ACTION_CONTRACT_EXPORTS = frozenset(
    """_expected_reference
    derive_agent_action_references
    _bound_report
    _validate_report_shape
    _validate_report_contract
    _validate_report_digest
    _taxonomy_value
    _denominator
    resolve_agent_action_reference
    ACTION_EXECUTION_CONTRACT
    _CODE_RULES
    _NUMBER_FIELDS
    _DENOMINATOR_STATES""".split()
)


def __getattr__(name: str):
    """Resolve legacy action exports without loading worker contracts on import."""
    if name in _ACTION_CONTRACT_EXPORTS:
        from . import deep_audit_contract

        return getattr(deep_audit_contract, name)
    raise AttributeError(name)


def audit_remediation_packet(
    candidate_sha256: str,
    finding: dict[str, Any],
    source_bound_security_precondition: dict[str, Any] | None = None,
) -> dict:
    """Create a deterministic host-agent handoff; evidence remains untrusted data."""
    from .deep_audit_contract import audit_remediation_packet as packet

    return packet(candidate_sha256, finding, source_bound_security_precondition)


def _security_scan_candidate_payload(
    sources: Any,
    tenant_read_contract: Any,
    oracle_context: Any,
    database_context: Any = None,
    *,
    include_database_context: bool = True,
) -> dict[str, Any]:
    """Return the shared candidate binding payload for a security scan."""
    payload = {
        "sources": sources,
        "tenant_read_contract": tenant_read_contract,
        "oracle_context": oracle_context,
    }
    if include_database_context:
        payload["database_context"] = (
            {} if database_context is None else database_context
        )
    return payload


def _security_scan_report_candidate_payload(report: dict[str, Any]) -> dict[str, Any]:
    """Build the shared candidate payload from a sealed scan report."""
    payload = _security_scan_candidate_payload(
        report.get("sources", []),
        report.get("tenant_read_contract", {}),
        report.get("oracle_context", {}),
        report.get("database_context", {}),
        include_database_context="database_context" in report,
    )
    if "selected_defect_policy" in report:
        decision = report.get("defect_policy_decision")
        payload["selected_defect_policy"] = report["selected_defect_policy"]
        payload["defect_policy_sha256"] = (
            decision.get("policy_sha256") if isinstance(decision, dict) else None
        )
        payload["defect_policy_evidence_sha256"] = (
            decision.get("evidence_sha256") if isinstance(decision, dict) else None
        )
        from .primitive_observation_binding import finding_tier_policy_sha256

        payload["finding_tier_policy_sha256"] = finding_tier_policy_sha256()
    return payload


def _security_scan_state(
    files: list[Path],
    findings: list[dict[str, Any]],
    database_context: dict | None = None,
    coverage: dict | None = None,
) -> str:
    if any(item["severity"] in {"CRITICAL", "HIGH"} for item in findings):
        return "BLOCKED"
    if any(item.get("code") == "QUALITY_UNKNOWN_TEST_ORACLE" for item in findings):
        return "INCOMPLETE"
    if database_context and database_context.get("status") not in {
        "COMPLETE",
        "NOT_APPLICABLE",
    }:
        return "INCOMPLETE"
    if (
        coverage is not None
        and coverage.get("complete") is False
        and coverage.get("measurement_state") != "no_eligible_sources"
    ):
        return "INCOMPLETE"
    if not files:
        return "NO_SOURCES"
    return "FINDINGS" if findings else "CLEAN"


def _security_scan_action_summary(state: str) -> str:
    if state == "INCOMPLETE":
        return (
            "Some sources or database details could not be verified. "
            "Review the reported coverage gaps and rerun after resolving them."
        )
    if state == "NO_SOURCES":
        return (
            "No eligible Python sources were found; no security conclusions were drawn."
        )
    if state == "CLEAN":
        return "No high-risk static security or quality patterns found."
    return "Resolve each listed finding and rerun this deterministic scan before release review."


def _application_configuration_hashes(class_profiles):
    from .captured_security_audit import _application_configuration_hashes as capture

    return capture(class_profiles)


def _captured_application_source_bytes(
    workspace, findings, bindings, source_bytes, *, capture_all_sources=False
):
    from .captured_security_audit import _captured_application_source_bytes as capture

    captured = capture(
        workspace,
        findings,
        bindings,
        source_bytes,
        capture_all_sources=capture_all_sources,
    )
    if any(
        row.get("facts", {}).get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
        for row in findings
    ):
        captured.source_role_capture["fixture_workspace"] = workspace
    return captured


class _ConfigurationProofCapture(dict):
    """Own one provisional proof collector without changing the captured bytes map."""

    def __init__(self, *args, provisional_exclusions=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.provisional_exclusions = provisional_exclusions

    def bind_provisional_exclusions(self, captured, workspace):
        """Bind provisional source points to their captured workspace for replay."""
        if self.provisional_exclusions:
            captured.source_role_capture["fixture_workspace"] = workspace
            captured.source_role_capture["provisional_exclusions"] = tuple(
                sorted(self.provisional_exclusions)
            )


class _CapturedSecuritySources(dict):
    """Keep auxiliary source-role bytes outside the scanner's Python inventory."""

    def __init__(
        self,
        *args,
        source_role_sources=None,
        source_role_bindings=(),
        source_role_workspace=None,
        source_role_capture=None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.source_role_capture = deepcopy(
            source_role_capture
            or {
                "sources": dict(source_role_sources or {}),
                "bindings": list(source_role_bindings),
                "workspace": source_role_workspace,
            }
        )

    @property
    def source_role_sources(self):
        """Return auxiliary bytes without adding them to the source inventory."""
        return self.source_role_capture.get("sources", {})

    @source_role_sources.setter
    def source_role_sources(self, value):
        """Replace the auxiliary source map used for local verification."""
        self.source_role_capture["sources"] = dict(value or {})

    def update(self, other=(), /, **kwargs):
        """Preserve private capture metadata when merging scan source maps."""
        if isinstance(other, _CapturedSecuritySources):
            self.source_role_capture = deepcopy(other.source_role_capture)
        super().update(other, **kwargs)

    def __deepcopy__(self, memo):
        result = type(self)(
            deepcopy(dict(self), memo),
            source_role_capture=deepcopy(self.source_role_capture, memo),
        )
        memo[id(self)] = result
        return result


class _SourceBoundSecurityReport(dict):
    """Keep captured bytes outside the serializable report for local revalidation."""

    __slots__ = ("_captured_sources", "_source_role_capture")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._captured_sources = ()
        self._source_role_capture = {}

    def copy(self):
        """Copy public fields while retaining the immutable source capture."""
        result = _SourceBoundSecurityReport(self)
        result._captured_sources = self._captured_sources
        result._source_role_capture = deepcopy(self._source_role_capture)
        return result


def _prepare_security_scan_sources(core, prior_tier_report):
    """Normalize review rows and temporarily expose captured bytes to integrity."""
    core["findings"] = [*core.get("findings", []), *core.pop("context_reviews", [])]
    core.pop("context_review_count", None)
    for row in (prior_tier_report or {}).get("ledger", []):
        row.pop("source_role_review", None)
    captured = core.pop("_primitive_source_bytes", None)
    if captured is None and type(core) is _SourceBoundSecurityReport:
        captured = _CapturedSecuritySources(
            dict(core._captured_sources),
            source_role_capture=core._source_role_capture,
        )
    if captured is not None:
        core["_primitive_source_bytes"] = captured
    return captured


def _preserve_security_scan_incomplete_state(audit, core, prior_state, prior_summary):
    """Prevent resealing from promoting a previously incomplete scan to clean."""
    if prior_state == "INCOMPLETE" and core.get("state") == "CLEAN":
        core["state"] = "INCOMPLETE"
        core["action_summary"] = prior_summary or audit._security_scan_action_summary(
            "INCOMPLETE"
        )


def _apply_security_scan_policy(
    audit,
    core,
    captured,
    prior_tier_report,
    prior_state,
    producer_source_model=None,
    _verifier_native_rows=None,
):
    """Recompute only the explicitly selected defect policy after integrity runs."""
    if "selected_defect_policy" in core:
        from . import primitive_observation_binding as primitive

        policy = primitive.validate_security_defect_policy(
            core["selected_defect_policy"]
        )
        core.pop("defect_policy_decision", None)
        if policy == "trusted-core-v1":
            core["defect_policy_decision"] = primitive.security_defect_policy_decision(
                core,
                captured,
                prior_tiers=prior_tier_report,
                prior_source_state=prior_state,
                _verifier_native_rows=_verifier_native_rows,
            )
        elif policy in {"source-role-v1", "source-role-v2", "source-role-v3"}:
            primitive.apply_pickle_source_role_policy(
                core,
                captured,
                source_model=producer_source_model,
                configuration_bytes={
                    row["path"]: captured[row["path"]]
                    for row in core.get("oracle_context", {}).get(
                        "configuration_sources", []
                    )
                    if isinstance(captured, dict)
                    and isinstance(captured.get(row.get("path")), bytes)
                    and sha256(captured[row["path"]]).hexdigest() == row.get("sha256")
                },
                prior_tiers=prior_tier_report,
                prior_source_state=prior_state,
                _verifier_native_rows=_verifier_native_rows,
            )
    else:
        core.pop("defect_policy_decision", None)


def _security_scan_seal_findings(findings, selected, supported, failed):
    if failed:
        return findings
    return [
        item
        for item in findings
        if not selected
        or not item.get("code", "").startswith("SECURITY_")
        or _canonical(item) in supported
    ]


def _security_scan_seal_actions(audit, candidate, findings, witnesses, failed):
    if failed:
        return [], None
    actions = []
    seen = set()
    packet_ids = set()
    for item in findings:
        identity = _canonical(item)
        if identity in seen:
            continue
        seen.add(identity)
        snapshot = json.loads(identity)
        witness_ref = witnesses.get(identity)
        try:
            expected = audit_remediation_packet(
                candidate, deepcopy(snapshot), deepcopy(witness_ref)
            )
            packet = audit.audit_remediation_packet(
                candidate,
                deepcopy(snapshot),
                **(
                    {"source_bound_security_precondition": deepcopy(witness_ref)}
                    if witness_ref is not None
                    else {}
                ),
            )
            matches = isinstance(packet, dict) and _canonical(packet) == _canonical(
                expected
            )
        except Exception:
            matches = False
            packet = None
        if not matches or packet["id"] in packet_ids:
            return [], "MALFORMED_OR_DUPLICATE_PACKET"
        packet_ids.add(packet["id"])
        actions.append(packet)
    if len(actions) != len(seen) or len(packet_ids) != len(actions):
        return [], "MISSING_OR_DUPLICATE_PACKET"
    return actions, None


def _finish_security_scan_seal(audit, core, captured, baseline, input_physical):
    """Bind candidate actions and report digest after all source policy checks."""
    candidate = sha256(
        json.dumps(
            audit._security_scan_report_candidate_payload(core),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    core["candidate_sha256"] = candidate
    conservation_failed = core.get("finding_conservation", {}).get("state") == "FAILED"
    findings = core["findings"]
    effect_witnesses = {}
    selected = core.get("selected_defect_policy") not in {None, "legacy-v1"}
    blocked = core.get("defect_policy_decision", {}).get("state") == "BLOCKED"
    supported_rows = {}
    for row in core.get("finding_tier_report", {}).get("ledger", []):
        raw_finding = row.get("raw_finding")
        if row.get("tier") != "SUPPORTED_DEFECT" or not isinstance(raw_finding, dict):
            continue
        key = _canonical(raw_finding)
        supported_rows[key] = row if key not in supported_rows else None
    ambiguous_supported = (
        selected and not blocked and any(row is None for row in supported_rows.values())
    )
    if ambiguous_supported and not conservation_failed:
        core["finding_conservation"].update(
            state="FAILED",
            failure_code="SECURITY_ACTION_HANDOFF_INVALID",
            handoff_state="FAILED",
            handoff_failure="AMBIGUOUS_SUPPORTED_LEDGER_ROW",
        )
        _security_scan_block_conservation_failure(
            core,
            baseline,
            input_physical,
            failure_code="SECURITY_ACTION_HANDOFF_INVALID",
        )
        conservation_failed = True
    supported = {
        key
        for key, row in supported_rows.items()
        if selected and not blocked and row is not None
    }
    source_hashes = {
        item.get("path"): item.get("sha256")
        for item in core.get("sources", [])
        if isinstance(item, dict)
    }
    for key, row in supported_rows.items():
        if not selected or blocked or row is None:
            continue
        witness_ref = row.get("source_bound_security_precondition")
        identity = row.get("source_identity")
        if not isinstance(witness_ref, dict) or not isinstance(identity, dict):
            continue
        source_path = witness_ref.get("source_path")
        source_sha256 = witness_ref.get("source_sha256")
        if (
            identity.get("path") == source_path
            and identity.get("source_sha256") == source_sha256
            and identity.get("identity_sha256")
            == witness_ref.get("finding_identity_sha256")
            and source_hashes.get(source_path) == source_sha256
            and isinstance(captured.get(source_path), bytes)
            and sha256(captured[source_path]).hexdigest() == source_sha256
        ):
            effect_witnesses[key] = witness_ref
    findings = _security_scan_seal_findings(
        findings, selected, supported, conservation_failed
    )
    actions, handoff_failure = _security_scan_seal_actions(
        audit, candidate, findings, effect_witnesses, conservation_failed
    )
    if handoff_failure is not None:
        core["finding_conservation"].update(
            state="FAILED",
            failure_code="SECURITY_ACTION_HANDOFF_INVALID",
            handoff_state="FAILED",
            handoff_failure=handoff_failure,
        )
        _security_scan_block_conservation_failure(
            core,
            baseline,
            input_physical,
            failure_code="SECURITY_ACTION_HANDOFF_INVALID",
        )
        actions = []
    core["agent_actions"] = actions
    core.pop("audit_sha256", None)
    core["audit_sha256"] = sha256(
        json.dumps(
            core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    if captured:
        result = _SourceBoundSecurityReport(core)
        result._captured_sources = tuple(captured.items())
        result._source_role_capture = deepcopy(
            getattr(captured, "source_role_capture", {})
        )
        return result
    return core


def _security_fixture_verifier_bindings(audit, core, root, verified):
    """Validate current collection and configuration; producer proof rows are not inputs."""
    from .import_context import (
        application_configuration_names,
        application_profile_configuration,
    )
    from .pytest_collection_audit import pytest_collection_authoritative

    if root is None and _has_application_fixture_claim(core):
        return _security_fixture_snapshot_bindings(audit, core, verified)
    if not isinstance(root, Path) or not root.is_absolute():
        return None
    expected = core.get("oracle_context", {}).get("static_pytest_collection")
    try:
        files = audit._security_source_files(root)
        observed = {path.relative_to(root).as_posix() for path in files}
        if observed != {name for name in verified if name.endswith(".py")}:
            return None
        audit._verify_security_bindings(root, core["sources"])
        _, current = audit._pytest_collection_config(root, files, allow_unknown=True)
        if current != expected or not pytest_collection_authoritative(current):
            return None
        _, identities, valid = application_profile_configuration(
            root, audit._security_source_bytes, audit.MAX_BYTES
        )
    except (OSError, ValueError, audit.ReviewAuditError, audit.RuntimeAuditError):
        return None
    names = application_configuration_names(verified) & verified.keys()
    reads = {
        name: item["sha256"]
        for name, item in identities.items()
        if item.get("state") == "read"
    }
    if not valid or reads.keys() != names:
        return None
    expected_digests = tuple(sorted(reads.items()))
    if any(
        sha256(verified[name]).hexdigest() != digest
        for name, digest in expected_digests
    ):
        return None
    return expected_digests


def _security_fixture_snapshot_bindings(audit, core, verified):
    """Replay detached, hash-checked bytes through the canonical static verifier."""
    from tempfile import TemporaryDirectory

    try:
        with TemporaryDirectory(prefix="factory-fixture-replay-") as directory:
            root = Path(directory).resolve()
            for name, raw in verified.items():
                destination = root / name
                if not destination.resolve().is_relative_to(root):
                    return None
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
            return _security_fixture_verifier_bindings(audit, core, root, verified)
    except (OSError, ValueError):
        return None


def _has_application_fixture_claim(core):
    return any(
        row.get("facts", {}).get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
        for field in (
            "findings",
            "primitive_observations",
            "refuted_security_observations",
        )
        for row in core.get(field, ())
    )


def rebuild_application_fixture_context(audit, model, verified, fixture_bindings):
    """Rebuild per-source scan proof from verifier-owned syntax and bytes."""
    contexts = {path: {} for path in model.snapshots}
    if fixture_bindings is not None:
        from .context_efficiency import bind_application_fixture_context

        configs = {name: verified[name] for name, _ in fixture_bindings}
        bind_application_fixture_context(
            model.root,
            model.snapshots,
            contexts,
            [{"path": name, "sha256": digest} for name, digest in fixture_bindings],
            lambda _root, name: configs[name],
            audit.MAX_BYTES,
            source_bytes=model.source_bytes,
            source_inventory=model.inventory,
        )
    audit.integrity.bind_fixed_program_workspace(
        model.root, contexts, model.snapshots, list(model.snapshots)
    )
    return contexts


def _security_scan_verification_state(audit, core, captured, primitive):
    """Snapshot the complete source, tenant and implementation identity for resealing."""
    from . import finite_capture

    if core.get("selected_defect_policy") not in {
        "trusted-core-v1",
        "source-role-v1",
        "source-role-v2",
        "source-role-v3",
    } or core.get("state") not in {
        "CLEAN",
        "FINDINGS",
        "REVIEW_REQUIRED",
        "BLOCKED",
        "INCOMPLETE",
    }:
        return None
    sources = primitive._trusted_core_complete_sources(core, captured, audit)
    tenant = primitive._trusted_core_tenant_arguments(core, audit)
    if sources is None or tenant != ((), {}, False):
        return None
    fields = (
        "tenant_read_contract",
        "oracle_context",
        "database_context",
        "provider_analysis_profile",
        "selected_defect_policy",
        "audit_coverage",
    )
    functions = (
        "_regenerate_native_findings",
        "_trusted_core_native_security_rows",
        "build_finding_tier_report",
        "_trusted_core_regenerated_tiers",
        "_trusted_core_complete_sources",
        "_trusted_core_tenant_arguments",
        "_trusted_core_surface_matches",
        "_native_surface_identity",
        "security_defect_policy_decision",
    )
    return (
        sources,
        tenant,
        audit._oracle_context_cache_key(
            Path("."),
            core["sources"],
            {k: core.get(k) for k in fields},
            captured=True,
        ),
        tuple(
            (fn, getattr(fn, "__code__", None))
            for fn in (
                audit._security_scan_tree,
                _security_fixture_verifier_bindings,
                _security_fixture_snapshot_bindings,
                _has_application_fixture_claim,
                rebuild_application_fixture_context,
                _negative_semantic_points,
                primitive.closed_shell_binding,
                *(
                    value
                    for name, value in vars(finite_capture).items()
                    if "shell" in name and callable(value)
                ),
                *(getattr(primitive, k) for k in functions),
            )
        ),
        _security_fixture_verifier_bindings(
            audit,
            core,
            getattr(captured, "source_role_capture", {}).get("fixture_workspace"),
            sources[0],
        ),
    )


def _security_scan_transaction_copy(core):
    """Copy mutable checkpoint state while retaining private source capture."""
    captured = (
        getattr(core, "_captured_sources", None)
        if type(core) is _SourceBoundSecurityReport
        else None
    )
    working = deepcopy(core)
    if type(working) is _SourceBoundSecurityReport and captured is not None:
        working._captured_sources = captured
        working._source_role_capture = deepcopy(core._source_role_capture)
    return working


def _security_scan_diagnostic_rows(core, verified_runtime_rows=()):
    return [
        row
        for values in (
            core.get("findings", []),
            core.get("context_reviews", []),
            core.get("primitive_observations", []),
            verified_runtime_rows,
        )
        if isinstance(values, (list, tuple))
        for row in values
        if isinstance(row, dict)
    ]


def _security_scan_verified_runtime_rows(core, rows, ledger):
    """Accept only current source-bound QUALITY rows with unique raw ledger owners."""
    if type(core) is not _SourceBoundSecurityReport or not getattr(
        core, "_captured_sources", None
    ):
        return []
    try:
        available = Counter(
            _canonical(row["raw_finding"])
            for row in ledger
            if isinstance(row, dict) and isinstance(row.get("raw_finding"), dict)
        )
        trusted = []
        for row in rows:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("code"), str)
                or not row["code"].startswith("QUALITY_")
            ):
                return []
            identity = _canonical(row)
            if available[identity] != 1:
                return []
            available[identity] -= 1
            trusted.append(deepcopy(row))
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return []
    return trusted


def _security_scan_sync_runtime_coverage_ledger(core, before, after):
    """Carry only a new validated coverage field into one exact raw ledger row."""
    annotated = deepcopy(after)
    facts = annotated.get("facts")
    coverage = facts.get("runtime_case_coverage") if isinstance(facts, dict) else None
    if not isinstance(coverage, dict) or type(coverage.get("eligible")) is not bool:
        return
    annotated["facts"].pop("runtime_case_coverage")
    if annotated != before:
        return
    ledger = core.get("finding_tier_report", {}).get("ledger", [])
    if not isinstance(ledger, list):
        return
    try:
        identity = _canonical(before)
        matches = [
            row
            for row in ledger
            if isinstance(row, dict)
            and isinstance(row.get("raw_finding"), dict)
            and _canonical(row["raw_finding"]) == identity
        ]
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return
    if len(matches) == 1:
        matches[0]["raw_finding"] = deepcopy(after)


def _security_scan_identity_counts(
    rows, *, owners=None, allow_rejected=False, primitive=None
):
    try:
        if owners is not None:
            return Counter(owners.get(_canonical(row)) for row in rows)
        counts = Counter(_canonical(row) for row in rows)
        ambiguous = False
        if allow_rejected:
            row_owners = {_canonical(row): _canonical(row) for row in rows}
            rejected_dispositions = primitive.fixed_program_proof_dispositions() | {
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
            }
            for row in rows:
                identity = _canonical(row)
                facts = row.get("facts", {})
                if (
                    not isinstance(facts, dict)
                    or facts.get("disposition") not in rejected_dispositions
                ):
                    continue
                rejected_identity = _canonical(primitive.rejected_primitive_proof(row))
                if rejected_identity == identity:
                    continue
                owner = row_owners.get(rejected_identity)
                if owner is not None and owner != identity:
                    ambiguous = True
                row_owners[rejected_identity] = identity
            return row_owners, ambiguous
        return counts
    except (TypeError, ValueError):
        return (None, True) if allow_rejected else None


def _security_scan_conservation(
    core,
    baseline,
    input_physical,
    native_expected_rows,
    primitive,
    native_surface_mismatch=False,
    native_verification_invalidated=False,
    verified_runtime_rows=(),
    negative_expected_rows=(),
):
    ledger = core.get("finding_tier_report", {}).get("ledger", [])
    ledger_valid = isinstance(ledger, list) and all(
        isinstance(row, dict) and isinstance(row.get("raw_finding"), dict)
        for row in ledger
    )
    ledger_rows = (
        [
            row["raw_finding"]
            for row in ledger
            if isinstance(row, dict) and isinstance(row.get("raw_finding"), dict)
        ]
        if isinstance(ledger, list)
        else []
    )
    physical_rows = _security_scan_diagnostic_rows(core, verified_runtime_rows)
    baseline_counts = _security_scan_identity_counts(baseline)
    physical_owners, ambiguous_physical = _security_scan_identity_counts(
        baseline, allow_rejected=True, primitive=primitive
    )
    input_physical_counts = _security_scan_identity_counts(
        input_physical, owners=physical_owners
    )
    physical_counts = _security_scan_identity_counts(
        physical_rows, owners=physical_owners
    )
    ledger_counts = _security_scan_identity_counts(ledger_rows)
    counts_valid = all(
        counts is not None
        for counts in (
            baseline_counts,
            physical_owners,
            input_physical_counts,
            physical_counts,
            ledger_counts,
        )
    )
    physical_matches = (
        counts_valid
        and not ambiguous_physical
        and input_physical_counts == baseline_counts
        and physical_counts == baseline_counts
    )
    ledger_matches = counts_valid and ledger_valid and ledger_counts == baseline_counts
    native_matches = (
        native_expected_rows is None
        and not native_surface_mismatch
        and not native_verification_invalidated
    )
    negative_rows = core.get("refuted_security_observations", [])
    negative_matches = _canonical(negative_rows) == _canonical(
        list(negative_expected_rows)
    ) and core.get("refuted_security_observation_count", 0) == len(negative_rows)
    if native_expected_rows is not None and not (
        native_surface_mismatch or native_verification_invalidated
    ):
        try:
            native_matches = primitive._trusted_core_surface_matches(
                core, native_expected_rows
            ) and primitive._trusted_core_surface_matches(
                {"findings": ledger_rows}, native_expected_rows
            )
        except Exception:
            native_matches = False
        if not native_matches and physical_matches and not native_surface_mismatch:
            native_matches = primitive._trusted_core_surface_matches(
                {"findings": baseline}, native_expected_rows
            )
    return {
        "state": (
            "PASS"
            if physical_matches
            and ledger_matches
            and native_matches
            and negative_matches
            and not native_surface_mismatch
            and not native_verification_invalidated
            else "FAILED"
        ),
        "scope": "diagnostic_identity_multiplicity",
        "native_rows": (
            "MISMATCH"
            if native_surface_mismatch
            else "INVALIDATED"
            if native_verification_invalidated
            else "VERIFIED"
            if native_expected_rows is not None
            else "UNAVAILABLE"
        ),
        "native_surface_mismatch": native_surface_mismatch,
        "native_verification_state_changed": native_verification_invalidated,
        "native_matches": native_matches,
        "physical_matches_expected": physical_matches,
        "ledger_matches_expected": ledger_matches,
        "refuted_observations_match_expected": negative_matches,
        "refuted_observation_rows": len(negative_rows),
        "original_observation_rows": len(physical_rows) + len(negative_rows),
        "expected_raw_rows": len(baseline),
        "input_physical_raw_rows": len(input_physical),
        "physical_raw_rows": len(physical_rows),
        "ledger_raw_rows": len(ledger_rows),
        "expected_security_rows": (
            len(native_expected_rows) if native_expected_rows is not None else None
        ),
    }


def _security_scan_block_conservation_failure(
    core,
    baseline,
    input_physical,
    failure_code="SECURITY_FINDING_CONSERVATION_FAILED",
):
    """Keep forensic rows and suppress every action after a surface mismatch."""
    conservation = core["finding_conservation"]
    conservation["failure_code"] = failure_code
    conservation["baseline_raw_diagnostics"] = baseline
    conservation["input_physical_raw_diagnostics"] = input_physical
    core["state"] = "BLOCKED"
    message = (
        f"Provisional exclusion rolled back ({failure_code}); raw diagnostics were "
        "retained and no repair actions were emitted."
        if conservation.get("provisional_exclusion_rollback")
        else "Security finding conservation failed after policy; raw diagnostics were "
        "retained and no repair actions were emitted."
    )
    core["action_summary"] = f"{core.get('action_summary', '')} {message}".strip()
    decision = core.get("defect_policy_decision")
    if isinstance(decision, dict):
        conservation["prior_policy_state"] = decision.get("state")
        decision.update(
            state="BLOCKED",
            exit_code=2,
            passed=False,
            clean=False,
            release_approved=False,
            failure_code=conservation["failure_code"],
            action_summary=message,
        )


def _unreconciled_native_diagnostics(core, captured, baseline, native_rows):
    """Expose missing verifier findings without treating them as policy inputs."""
    from .primitive_observation_binding import _RULE_SPAN_KEYS, _native_surface_identity

    if not isinstance(captured, dict):
        return []
    source_hashes = {
        row["path"]: row["sha256"]
        for row in core.get("sources", [])
        if isinstance(row, dict)
        and isinstance(row.get("path"), str)
        and isinstance(row.get("sha256"), str)
    }
    present = Counter()
    for row in baseline:
        try:
            present[_native_surface_identity(row)] += 1
        except TypeError:
            continue
    missing, checked = [], {}
    for row in native_rows:
        try:
            identity = _native_surface_identity(row)
            if present[identity]:
                present[identity] -= 1
                continue
        except (AttributeError, TypeError):
            continue
        path = row.get("path")
        if not isinstance(path, str) or path not in source_hashes:
            continue
        if path not in checked:
            raw = captured.get(path)
            checked[path] = (
                isinstance(raw, bytes)
                and sha256(raw).hexdigest() == source_hashes[path]
            )
        if not checked[path]:
            continue
        diagnostic = {
            key: row.get(key, 0 if key == "column" else None)
            for key in (*_RULE_SPAN_KEYS, "severity")
        }
        missing.append({**diagnostic, "source_sha256": source_hashes[path]})
    return missing


_VERIFIER_BINDING_MEMO = ContextVar("factory_verifier_binding_memo", default=None)


def _verifier_binding_helpers():
    from . import import_context, semantic_credential_sensor as sensor
    from .credential_role_constructor_provider import (
        SourceSnapshotIndex,
        _ast_matches_source,
    )

    return (
        import_context.epoch_binding_occurrences,
        import_context.binding_walker_epoch,
        sensor.signing_configuration_inventory,
        sensor._signing_inventory_snapshots,
        SourceSnapshotIndex._matches_snapshot,
        _ast_matches_source,
        _verifier_owned_nodes,
        _verifier_binding_query,
        ast.walk,
        ast.iter_child_nodes,
        ast.parse,
        ast.dump,
        sha256,
    )


def _verifier_owned_nodes(snapshots):
    nodes = []
    for tree in snapshots.values():
        for node in ast.walk(tree):
            nodes.append(node)
            if len(nodes) > 65536:
                return None
    return tuple(nodes)


class _VerifierBindingMemo:
    """Cache default binding queries over one independently parsed signing graph."""

    def __init__(self):
        self.entries = OrderedDict()
        self.inputs = None
        self.changed = False
        self.active = True

    def enroll(self, inventory, captured, bindings):
        from .credential_role_constructor_provider import (
            SourceSnapshotIndex,
            _helper_snapshot,
        )
        from .import_context import binding_walker_epoch

        index = inventory.get("index") if isinstance(inventory, dict) else None
        if (
            not self.active
            or type(index) is not SourceSnapshotIndex
            or not index.bounded
        ):
            return
        if self.inputs is not None:
            self.changed = True
            return
        self.node_order = _verifier_owned_nodes(index.snapshots)
        self.helpers = _helper_snapshot(_verifier_binding_helpers)
        if not self.node_order or self.helpers is None:
            return
        self.owned = frozenset(self.node_order)
        self.walker = binding_walker_epoch()
        self.inputs = (
            index,
            dict(index.snapshots),
            dict(index.source_bytes),
            dict(index.inventory),
            captured,
            dict(captured),
            bindings,
            dict(bindings),
        )

    def query(self, statements, name):
        from .credential_role_constructor_provider import _binding_occurrence_events
        from .import_context import binding_walker_epoch

        if (
            not self.active
            or self.inputs is None
            or self.changed
            or type(statements) not in (list, tuple)
        ):
            return statements, None
        if not 0 < len(statements) <= 256:
            return statements, None
        roots = tuple(statements)
        if any(
            not isinstance(node, ast.AST) or node not in self.owned for node in roots
        ):
            return statements, None
        if self.walker != binding_walker_epoch():
            self.changed = True
            return statements, None
        key = roots, name
        if key not in self.entries:
            rows = tuple(_binding_occurrence_events(roots, name))
            if self.walker != binding_walker_epoch():
                self.changed = True
                return statements, None
            if len(rows) > 256:
                return roots, rows
            if len(self.entries) == 4096:
                self.entries.popitem(last=False)
            self.entries[key] = rows
        self.entries.move_to_end(key)
        return roots, self.entries[key]

    def current(self):
        from .credential_role_constructor_provider import (
            SourceSnapshotIndex,
            _helper_snapshot,
            _same_helper_epoch,
        )
        from .import_context import binding_walker_epoch

        if self.inputs is None:
            return not self.changed
        index, trees, raw, digests, captured, before, bindings, keys = self.inputs
        if (
            self.changed
            or captured != before
            or bindings != keys
            or self.walker != binding_walker_epoch()
            or not _same_helper_epoch(
                _helper_snapshot(_verifier_binding_helpers), self.helpers
            )
        ):
            return False
        return (
            index.snapshots == trees
            and index.source_bytes == raw
            and index.inventory == digests
            and all(
                SourceSnapshotIndex._matches_snapshot(
                    index, p, tree, raw[p], sha256(raw[p]).hexdigest()
                )
                for p, tree in trees.items()
            )
            and _verifier_owned_nodes(trees) == self.node_order
        )

    def retire(self):
        """Disable inherited contexts and release snapshot references after staging."""
        self.active = False
        self.entries.clear()
        self.inputs = None
        self.node_order = self.owned = ()


def _verifier_signing_inventory(sensor, captured, bindings):
    inventory = sensor.signing_configuration_inventory(captured, bindings)
    memo = _VERIFIER_BINDING_MEMO.get()
    if memo is not None:
        try:
            memo.enroll(inventory, captured, bindings)
        except Exception:
            memo.changed = True
    return inventory


def _verifier_binding_query(statements, name, per_pass_facts):
    memo = _VERIFIER_BINDING_MEMO.get()
    if memo is None or per_pass_facts is not None or type(name) is not str:
        return statements, None
    try:
        return memo.query(statements, name)
    except Exception:
        # The raw walker still owns ordinary errors on the uncached path.
        memo.changed = True
        return statements, None


def _verifier_ledger_current(memo):
    try:
        return memo is None or memo.current()
    except Exception:
        return False


def _bounded_verifier_tier_report(build, *args, **kwargs):
    """Publish a staged ledger only after checking its independent binding epoch."""
    memo = (
        _VerifierBindingMemo()
        if kwargs.get("_verifier_native_rows") is not None
        else None
    )
    token = _VERIFIER_BINDING_MEMO.set(memo)
    try:
        report = build(*args, **kwargs)
        current = _verifier_ledger_current(memo)
    finally:
        if memo is not None:
            memo.retire()
        _VERIFIER_BINDING_MEMO.reset(token)
    if current:
        return report

    token = _VERIFIER_BINDING_MEMO.set(None)
    try:
        return build(*args, **kwargs)
    finally:
        _VERIFIER_BINDING_MEMO.reset(token)


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


def _partition_with_fixture_authority(audit, core, captured, rows, *, stale=False):
    if captured is not None:
        core["_primitive_source_bytes"] = captured
    if stale:
        core["_stale_fixture_authority"] = True
    try:
        audit.integrity.partition_proven_primitive_observations(core, rows)
    finally:
        core.pop("_primitive_source_bytes", None)
        core.pop("_stale_fixture_authority", None)


def _restore_refuted_observations(core):
    """Check the negative surface and recover every row for native replay."""
    capture = getattr(core, "_source_role_capture", {})
    originals = capture.get("sealed_exclusion_rows", ())
    negative = capture.get("sealed_negative_rows", ())
    observed = core.pop("refuted_security_observations", [])
    count = core.pop("refuted_security_observation_count", 0)
    valid = type(observed) is list and all(type(row) is dict for row in observed)
    if not valid:
        capture["negative_observation_invalid"] = True
        observed = []
    if negative or observed:
        if (_canonical(list(negative)), len(negative)) != (_canonical(observed), count):
            capture["negative_observation_invalid"] = True
        # Untrusted additions remain visible to the independent native comparison.
        originals = (*originals, *(row for row in observed if row not in negative))
    return originals


def _restore_provisional_rows(core):
    """Recover original diagnostics before the next independent verification."""
    originals = _restore_refuted_observations(core)
    if not originals:
        return

    def missing_from(rows):
        present = Counter()
        for row in rows:
            try:
                present[_canonical(row)] += 1
            except (TypeError, ValueError):
                continue
        for row in originals:
            key = _canonical(row)
            if present[key]:
                present[key] -= 1
            else:
                yield deepcopy(row)

    core["findings"] = [
        *core.get("findings", []),
        *missing_from(_security_scan_diagnostic_rows(core)),
    ]
    report = core.get("finding_tier_report", {})
    ledger = report.get("ledger")
    if isinstance(ledger, list):
        raw_rows = (
            entry.get("raw_finding") for entry in ledger if isinstance(entry, dict)
        )
        core["finding_tier_report"] = {
            **report,
            "ledger": [
                *ledger,
                *({"raw_finding": row} for row in missing_from(raw_rows)),
            ],
        }


def _without_provisional_rows(rows, keys, primitive):
    return [row for row in rows if primitive._native_surface_identity(row) not in keys]


def _declaration_bindings(nodes, names):
    from .import_context import _binding_name

    return {
        node
        for node in nodes
        if _binding_name(node) in names
        or isinstance(node, ast.alias)
        and (node.asname or node.name.split(".")[0]) in names
        or isinstance(node, (ast.Global, ast.Nonlocal))
        and names.intersection(node.names)
    }


def _declaration_record_field(node, owner):
    match node:
        case ast.Subscript(
            value=ast.Name(id=name),
            slice=ast.Constant(value=str() as key),
            ctx=ast.Load(),
        ) if name == owner:
            return key
    return None


def _declaration_record_domain(tree, gate, loop, nodes):
    if not isinstance(loop.iter, ast.Name):
        return None
    name, allowed, records = loop.iter.id, {loop.iter}, []
    deferred = any(
        isinstance(stmt, ast.ImportFrom)
        and stmt.module == "__future__"
        and any(alias.name == "annotations" for alias in stmt.names)
        for stmt in tree.body
    )
    for statement in tree.body[: tree.body.index(gate)]:
        match statement:
            case (
                ast.Assign(targets=[ast.Name() as target], value=ast.List() as value)
                | ast.AnnAssign(
                    target=ast.Name() as target,
                    value=ast.List() as value,
                )
            ) if target.id == name and not records:
                if isinstance(statement, ast.AnnAssign) and not (
                    deferred or isinstance(statement.annotation, ast.Name)
                ):
                    return None
            case ast.AugAssign(
                target=ast.Name() as target, op=ast.Add(), value=ast.List() as value
            ) if target.id == name and records:
                pass
            case _:
                continue
        if len(records) + len(value.elts) > 64 or not all(
            isinstance(item, ast.Dict) for item in value.elts
        ):
            return None
        allowed.add(target)
        records.extend(value.elts)
    uses = {node for node in nodes if isinstance(node, ast.Name) and node.id == name}
    return (
        records
        if records
        and uses == allowed
        and _declaration_bindings(nodes, {name}) < allowed
        else None
    )


def _plain_function_declaration(source, name):
    from .finite_capture import _fixed_eval_attribute_hazard, _fixed_eval_name_hazard

    if not (type(source) is str and type(name) is str and len(source) <= 16384):
        return False
    tree = ast.parse(source)
    if len(tree.body) != 1 or not isinstance(function := tree.body[0], ast.FunctionDef):
        return False
    args = function.args
    if (
        function.name != name
        or name.startswith("_")
        or function.decorator_list
        or function.returns
        or getattr(function, "type_params", ())
        or any([*args.defaults, *args.kw_defaults])
        or any(node.annotation for node in ast.walk(args) if isinstance(node, ast.arg))
    ):
        return False
    reflection = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
        "__builtins__",
    }
    return not any(
        _fixed_eval_name_hazard(node, None, reflection)
        or _fixed_eval_attribute_hazard(node)
        for node in ast.walk(function)
    ) and _declaration_provider_clear(tree)


def _declaration_provider_clear(tree):
    from .finite_capture import _fixed_eval_builtin_provider_risk

    return not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__main__"
        or isinstance(node, ast.alias)
        and node.name in {"__main__", "*"}
        for node in ast.walk(tree)
    ) and not _fixed_eval_builtin_provider_risk(tree)


def _owned_declaration_seed(seed, preceding, nodes):
    if not isinstance(seed, ast.Dict) or any(
        not isinstance(key, ast.Constant)
        or type(key.value) is not str
        or not key.value.isidentifier()
        or key.value.startswith("_")
        for key in seed.keys
    ):
        return False
    if len({key.value for key in seed.keys}) != len(seed.keys) or any(
        not isinstance(value, (ast.Name, ast.Constant)) for value in seed.values
    ):
        return False
    names = {node.id for node in seed.values if isinstance(node, ast.Name)}
    owned = {
        alias
        for stmt in preceding
        if isinstance(stmt, ast.Import)
        for alias in stmt.names
        if (alias.asname or alias.name.split(".")[0]) in names
    }
    return len(owned) == len(names) and _declaration_bindings(nodes, names) == owned


def _declaration_loop_use(loop, statement, call):
    """Prove the record and namespace are used only at the selected read boundary."""
    owner, namespace = loop.target.id, call.args[1]
    nodes = list(ast.walk(loop))
    parents = {
        child: parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    if _declaration_bindings(nodes, {owner}) != {loop.target} or any(
        _declaration_record_field(parents.get(node), owner) is None
        for node in nodes
        if isinstance(node, ast.Name) and node.id == owner and node is not loop.target
    ):
        return None
    i = loop.body.index(statement)
    if not 1 <= i < len(loop.body) - 1:
        return None
    match loop.body[i - 1]:
        case (
            ast.Assign(targets=[ast.Name() as target], value=seed)
            | ast.AnnAssign(
                target=ast.Name() as target, annotation=ast.Name(), value=seed
            )
        ) if target.id == namespace.id:
            pass
        case _:
            return None
    match loop.body[i + 1]:
        case ast.Assign(
            value=ast.Subscript(value=ast.Name() as access, slice=ast.Name(id=selector))
        ) if access.id == namespace.id:
            pass
        case _:
            return None
    uses = {
        node for node in nodes if isinstance(node, ast.Name) and node.id == namespace.id
    }
    if uses != {target, namespace, access} or _declaration_bindings(
        nodes, {namespace.id}
    ) != {target}:
        return None
    for stmt in loop.body[: i - 1]:
        match stmt:
            case ast.Assign(targets=[ast.Name(id=name) as bound], value=value) if (
                name == selector
            ):
                if _declaration_bindings(nodes, {selector}) == {bound}:
                    return seed, _declaration_record_field(value, owner)
    return None


def _declaration_entry(tree, node):
    for gate in tree.body:
        match gate:
            case ast.If(
                test=ast.Compare(
                    left=ast.Name(id="__name__"),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value="__main__")],
                ),
                orelse=[],
            ):
                for loop in gate.body:
                    if isinstance(loop, ast.For) and isinstance(loop.target, ast.Name):
                        for i, stmt in enumerate(loop.body):
                            if isinstance(stmt, ast.Expr) and stmt.value is node:
                                return gate, loop, i, stmt
    return None


def _captured_declaration_domain_clear(tree, call, entry):
    gate, loop, _, statement = entry
    nodes = list(ast.walk(tree))
    if _declaration_bindings(nodes, {"exec", "__name__"}):
        return False
    program = _declaration_record_field(call.args[0], loop.target.id)
    boundary = _declaration_loop_use(loop, statement, call)
    if program is None or boundary is None or boundary[1] in {None, program}:
        return False
    seed, selector = boundary
    if not _owned_declaration_seed(seed, tree.body[: tree.body.index(gate)], nodes):
        return False
    domain = _declaration_record_domain(tree, gate, loop, nodes)
    if not domain:
        return False
    for row in domain:
        record = ast.literal_eval(row)
        if len(record) != len(row.keys) or not _plain_function_declaration(
            record.get(program), record.get(selector)
        ):
            return False
    return True


def _captured_declaration_authority(index, path, node):
    from .runtime_audit_integrity import _exact_source_call

    exact = _exact_source_call(index.source_bytes[path], node)
    if exact is None:
        return None
    tree, call = exact
    entry = _declaration_entry(tree, call)
    if entry is None or not _captured_declaration_domain_clear(tree, call, entry):
        return None
    gate, loop, pos, statement = entry
    # Mask only the already verified declaration when checking provider effects.
    # This tree belongs to the verifier; the scanner's source AST is untouched.
    loop.body[pos] = ast.copy_location(ast.Pass(), statement)
    if not _declaration_provider_clear(tree):
        return None
    sources = {}
    for peer, snapshot in index.snapshots.items():
        relative = index.relative(peer)
        if relative is None or relative in sources or not index.validate(peer):
            return None
        if peer != path and not _declaration_provider_clear(snapshot):
            return None
        sources[relative] = index.inventory[peer]
    return sha256(
        canonical_bytes(
            ["closed-entry-declaration-v1", sources, gate.lineno, loop.lineno]
        )
    ).hexdigest()


def with_captured_declaration_proof(relative, node, row):
    """Bind observed program roles to source and stage their proof for replay."""
    match row, node:
        case {"code": "SECURITY_DYNAMIC_EXECUTION", "severity": "HIGH"}, ast.Call(
            func=ast.Name(id="eval"), args=[ast.Attribute(), ast.Name()], keywords=[]
        ):
            from .xonsh_program_audit import stage_xonsh_program_refutation

            stage_xonsh_program_refutation(relative, node, row)
            return row
        case {"code": "SECURITY_DYNAMIC_EXECUTION", "severity": "HIGH"}, ast.Call(
            func=ast.Name(id="exec"), args=[ast.Subscript(), ast.Name()], keywords=[]
        ):
            pass
        case _:
            return _with_captured_operand_proof(relative, node, row)
    from .captured_security_audit import _native_span
    from .pytest_collection_audit import _captured_pytest_inputs
    from .semantic_credential_sensor import _security_helper_source_context

    module, index, path = _security_helper_source_context(node, None)
    stage = getattr(_captured_pytest_inputs(module)[1], "provisional_exclusions", None)
    if type(stage) is not set or path is None or len(index.snapshots) > 128:
        return row
    try:
        if index.relative(path) != relative or not index.validate(path):
            return row
        span = _native_span(node)
        authority = _captured_declaration_authority(index, path, node) if span else None
        if authority:
            stage.add((row["code"], relative, *span, row["severity"], authority))
    except (ValueError, SyntaxError, TypeError, RecursionError, MemoryError):
        pass
    return row


def _captured_operand_prover(code, node):
    """Select the proof for this exact diagnostic and syntactic operand shape."""
    match code, node:
        case "SECURITY_DYNAMIC_EXECUTION", ast.Call(
            func=ast.Name(id="eval"), args=[ast.Call()], keywords=[]
        ):
            from .captured_operand_audit import captured_local_representation_proof

            return captured_local_representation_proof
        case "SECURITY_OS_COMMAND", ast.Call(args=[_], keywords=[]):
            from .captured_operand_audit import captured_command_operand_proof

            return captured_command_operand_proof
        case "SECURITY_UNSAFE_DESERIALIZATION", ast.Call(
            args=[ast.Call()], keywords=[]
        ):
            from .pickle_model_audit import captured_local_serialization_proof

            return captured_local_serialization_proof
        case "SECURITY_HARDCODED_SECRET", (
            ast.Assign(value=ast.Constant(value=str()))
            | ast.AnnAssign(value=ast.Constant(value=str()))
        ):
            return _captured_credential_operand_proof
        case _:
            return None


def _captured_credential_operand_proof(index, path, node):
    from .fixture_scope_value_audit import (
        captured_hash_fixture_proof,
        captured_password_validation_proof,
    )
    from .provenance import (
        captured_oauth_placeholder_proof,
        captured_oauth_service_locator_proof,
    )
    from .pytest_collection_audit import captured_http_fixture_token_proof

    if len(index.snapshots) > 128:
        return captured_hash_fixture_proof(index, path, node)
    if isinstance(index.parents[path].get(id(node)), ast.Module):
        return captured_oauth_placeholder_proof(
            index, path, node
        ) or captured_oauth_service_locator_proof(index, path, node)
    return (
        captured_password_validation_proof(index, path, node)
        or captured_hash_fixture_proof(index, path, node)
        or captured_http_fixture_token_proof(index, path, node)
    )


def _with_captured_operand_proof(relative, node, row):
    """Bind a captured operand refutation to the original primitive and source inventory."""
    prove = _captured_operand_prover(row["code"], node)
    if prove is None or row["facts"].get("security_precondition") is not None:
        return row

    from .captured_security_audit import _native_span
    from .fixture_scope_value_audit import HASH_FIXTURE_MAX_SNAPSHOTS
    from .pytest_collection_audit import _captured_pytest_inputs
    from .semantic_credential_sensor import _security_helper_source_context

    module, index, path = _security_helper_source_context(node, None)
    span = _native_span(node)
    if path is None or span is None or index.relative(path) != relative:
        return row
    point = (row["code"], relative, *span, row["severity"])
    max_snapshots = (
        HASH_FIXTURE_MAX_SNAPSHOTS
        if row["code"] == "SECURITY_HARDCODED_SECRET"
        else 128
    )
    evidence = _bound_operand_refutation(
        index, path, node, point, prove, max_snapshots=max_snapshots
    )
    if evidence is None:
        if row["code"] == "SECURITY_OS_COMMAND":
            _attach_installer_prerequisite(index, path, node, point, row)
        elif row["code"] == "SECURITY_HARDCODED_SECRET":
            _attach_validation_marker_context(index, path, node, point, row)
        return row
    row["facts"]["captured_operand_role"] = evidence
    stage = getattr(_captured_pytest_inputs(module)[1], "provisional_exclusions", None)
    if type(stage) is set:
        stage.add((*point, evidence["source_authority_sha256"]))
    return row


def _attach_installer_prerequisite(index, path, node, point, row):
    """Record a conditional manifest guard while preserving the shell finding."""
    from .captured_operand_audit import captured_installer_prerequisite
    from .pytest_collection_audit import captured_pytest_documents

    evidence = _bound_operand_refutation(
        index, path, node, point, captured_installer_prerequisite
    )
    if evidence is None:
        return
    manifest = evidence["manifest"]
    documents = captured_pytest_documents(index.snapshots[path]) or {}
    raw = documents.get(manifest["path"])
    if not isinstance(raw, bytes) or sha256(raw).hexdigest() != manifest["sha256"]:
        return
    row["facts"]["captured_installer_prerequisite"] = evidence
    row["message"] = (
        "The script raises before this shell call when the working directory selects "
        "the captured root manifest. The actual invocation directory remains unresolved."
    )


def _attach_validation_marker_context(index, path, node, point, row):
    """Record the local test use while keeping the unresolved credential review."""
    from .pytest_collection_audit import captured_validation_marker_context

    evidence = _bound_operand_refutation(
        index, path, node, point, captured_validation_marker_context
    )
    if evidence is None:
        return
    row["facts"]["captured_validation_marker_context"] = evidence
    row["message"] = (
        "The captured in-process test uses this literal as a validation marker. "
        "The declared classifier engine reads a shared registry. "
        "Actual consumer selection remains unresolved."
    )


def _bound_operand_refutation(index, path, node, point, prove, *, max_snapshots=128):
    from .credential_role_constructor_provider import SourceSnapshotIndex

    if (
        not index.bounded
        or len(index.snapshots) > max_snapshots
        or not index.validate(path)
    ):
        return None
    try:
        proof = prove(index, path, node)
        if proof is None:
            return None
        # A successful proof must survive a fresh byte-to-AST check and freshly
        # built parent maps before even its first-pass evidence is attached.
        source = SourceSnapshotIndex(
            index.root,
            dict(index.snapshots),
            dict(index.source_bytes),
            dict(index.inventory),
        )
        if not all(source.validate(peer) for peer in source.snapshots):
            return None
        if prove(source, path, node) != proof:
            return None
        manifest = sorted(
            (source.relative(peer), source.inventory[peer]) for peer in source.snapshots
        )
        authority = sha256(
            canonical_bytes(["captured-operand-refutation-v1", point, manifest, proof])
        ).hexdigest()
    except (SyntaxError, TypeError, ValueError, RecursionError, MemoryError):
        return None
    return {**proof, "source_authority_sha256": authority}


def _provisional_witnesses(points):
    witnesses = {}
    for point in points:
        if len(point) not in (7, 8):
            raise ValueError("invalid source role point")
        identity = tuple((type(value), value) for value in point[:7])
        authority = point[7] if len(point) == 8 else None
        if identity in witnesses or (
            len(point) == 8
            and not (
                type(authority) is str and re.fullmatch(r"[0-9a-f]{64}", authority)
            )
        ):
            raise ValueError("ambiguous or invalid source role point")
        witnesses[identity] = authority
    return witnesses


def _negative_semantic_points(rows, core, captured, primitive):
    """Recompute a specific refuted hypothesis, never general runtime safety."""
    if core.get("audit_coverage", {}).get("complete") is not True:
        return set()
    sources = core.get("sources", [])
    bindings = {row["path"]: row["sha256"] for row in sources}
    fixture_sources = [
        *sources,
        *core.get("oracle_context", {}).get("configuration_sources", []),
    ]
    fixture_bindings = {row["path"]: row["sha256"] for row in fixture_sources}
    collection_known = not primitive._unknown_collection(core)
    points = set()
    for row in rows:
        facts = row.get("facts", {})
        shell = (
            facts.get("disposition") == "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX"
            and facts.get("operation_role")
            in {
                "empty_command_input",
                "terminal_display_reset",
                "fixed_privileged_stop_syntax",
            }
            and facts.get("hypothesis") == "SOURCE_COMMAND_INJECTION"
            and primitive.closed_shell_binding(row, sources, bindings, captured)
        )
        fixture = (
            collection_known
            and facts.get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
            and isinstance(evidence := facts.get("fixture_evidence"), dict)
            and (
                evidence.get("source_hypothesis")
                == "SOURCE_TEST_CLIENT_CREDENTIAL_UNUSED"
                or evidence.get("fixture_contract") == "DRF_CLASS_ACCOUNT_LIFECYCLE"
            )
            and primitive.application_fixture_binding(
                row, fixture_sources, fixture_bindings, captured
            )
        )
        if shell or fixture:
            points.add(
                tuple(row.get(key) for key in (*primitive._RULE_SPAN_KEYS, "severity"))
            )
    return points


def _stage_provisional_exclusions(
    audit,
    core,
    claims,
    proof,
    baseline,
    input_physical,
    native_rows,
    primitive,
):
    """Stage only rows whose source proof and original bytes agree in replay."""
    if native_rows is None:
        return None, (), set()
    claimed, verified = _provisional_witnesses(claims), _provisional_witnesses(proof)
    if not claimed.items() <= verified.items():
        return None, (), set()
    keys = set(claimed)
    identity = primitive._native_surface_identity
    originals = [row for row in input_physical if identity(row) in keys]
    if Counter(map(identity, originals)) != Counter(keys):
        return None, (), set()
    raw = _security_scan_identity_counts(originals)
    if raw is None or any(
        _security_scan_identity_counts(row for row in rows if identity(row) in keys)
        != raw
        for rows in (baseline, native_rows)
    ):
        return None, (), set()
    candidate = core.copy()
    candidate["refuted_security_observations"] = deepcopy(originals)
    candidate["refuted_security_observation_count"] = len(
        candidate["refuted_security_observations"]
    )
    candidate["findings"] = _without_provisional_rows(core["findings"], keys, primitive)
    if "primitive_observations" in core:
        candidate["primitive_observations"] = _without_provisional_rows(
            core["primitive_observations"], keys, primitive
        )
    report = core.get("finding_tier_report")
    if isinstance(report, dict) and isinstance(report.get("ledger"), list):
        candidate["finding_tier_report"] = {
            **report,
            "ledger": [
                row
                for row in report["ledger"]
                if identity(row["raw_finding"]) not in keys
            ],
        }
    findings = candidate["findings"]
    candidate["finding_counts"] = dict(
        sorted(Counter(row["code"] for row in findings).items())
    )
    candidate["state"] = audit._security_scan_state(
        core["sources"], findings, core.get("database_context"), core["audit_coverage"]
    )
    candidate["action_summary"] = audit._security_scan_action_summary(
        candidate["state"]
    )
    return candidate, originals, keys


def _security_scan_replay_native_rows(
    audit, core, captured, primitive, state_builder, proof
):
    """Replay the verified source snapshot and compare its full diagnostic surface."""
    verified = expected = None
    try:
        verified = state_builder(audit, core, captured, primitive)
        if verified is None:
            return verified, None, expected, False
        sources, tenant, _, _, fixture = verified
        rows = primitive._trusted_core_native_security_rows(
            sources[0],
            tenant,
            audit,
            *((fixture,) if fixture is not None else ()),
            **(
                {"provisional_exclusions": proof}
                if proof is not None and fixture is not None
                else {}
            ),
        )
        if rows is None:
            return verified, None, expected, False
        if proof is not None:
            proof.update(_negative_semantic_points(rows, core, captured, primitive))
        expected = deepcopy(rows)
        if not primitive._trusted_core_surface_matches(core, rows):
            return verified, None, expected, True
        return verified, rows, expected, False
    except Exception:
        return verified, None, expected, False


def _security_scan_verification_unchanged(
    audit, core, captured, primitive, verified, state_builder, state_code
):
    """Compare source and verifier authority again before committing staged rows."""
    try:
        return (
            state_builder(audit, core, captured, primitive),
            _security_scan_verification_state,
            state_builder.__code__,
        ) == (verified, state_builder, state_code)
    except Exception:
        return False


def _security_scan_partition_native_rows(
    audit, core, captured, primitive, baseline, input_physical, *, allow_exclusions=True
):
    """Partition from fresh native rows and retain invalidation evidence."""
    state_builder = _security_scan_verification_state
    state_code = state_builder.__code__
    capture = getattr(captured, "source_role_capture", {})
    claims = set()
    if (
        allow_exclusions
        and core.get("selected_defect_policy") == "source-role-v3"
        and not capture.get("negative_observation_invalid")
    ):
        claims.update(capture.get("provisional_exclusions", ()))
        claims.update(
            _negative_semantic_points(input_physical, core, captured, primitive)
        )
    proof = set() if claims else None
    verified, native_rows, native_expected_rows, native_surface_mismatch = (
        _security_scan_replay_native_rows(
            audit, core, captured, primitive, state_builder, proof
        )
    )
    native_verification_invalidated = False
    staged, originals, keys = None, (), set()
    if claims and not native_surface_mismatch:
        try:
            staged, originals, keys = _stage_provisional_exclusions(
                audit,
                core,
                claims,
                proof,
                baseline,
                input_physical,
                native_rows,
                primitive,
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
        if staged is None:
            native_verification_invalidated = True
            native_rows = None
    fixture_claim = bool(core.get("selected_defect_policy")) and (
        _has_application_fixture_claim(core)
    )
    partitioned = core if staged is None else staged
    partition_rows = (
        native_rows
        if staged is None
        else _without_provisional_rows(native_rows, keys, primitive)
    )
    stale_fixture = fixture_claim and (native_rows is None or verified[4] is None)
    _partition_with_fixture_authority(
        audit,
        partitioned,
        captured,
        partition_rows,
        stale=stale_fixture,
    )
    if (
        native_expected_rows is not None
        and not native_verification_invalidated
        and not _security_scan_verification_unchanged(
            audit, partitioned, captured, primitive, verified, state_builder, state_code
        )
    ):
        native_verification_invalidated = True
        native_rows = None
    capture.pop("sealed_exclusion_rows", None)
    capture.pop("sealed_negative_rows", None)
    if native_verification_invalidated:
        if staged is not None or (fixture_claim and not stale_fixture):
            _partition_with_fixture_authority(
                audit, core, captured, None, stale=fixture_claim
            )
        keys = set()
    elif staged is not None:
        core.clear()
        core.update(staged)
        capture["sealed_exclusion_rows"] = tuple(deepcopy(originals))
        capture["sealed_negative_rows"] = tuple(
            deepcopy(core.get("refuted_security_observations", []))
        )
        native_rows = partition_rows
        native_expected_rows = _without_provisional_rows(
            native_expected_rows, keys, primitive
        )
    return (
        native_rows,
        native_expected_rows,
        native_surface_mismatch,
        native_verification_invalidated,
        keys,
    )


def _security_scan_seal_baseline(core, runtime_rows):
    """Snapshot both raw surfaces before partitioning can change either."""
    input_ledger = core.get("finding_tier_report", {}).get("ledger", [])
    verified_runtime_rows = _security_scan_verified_runtime_rows(
        core, runtime_rows, input_ledger
    )
    input_physical = deepcopy(
        _security_scan_diagnostic_rows(core, verified_runtime_rows)
    )
    baseline = deepcopy(
        [row["raw_finding"] for row in input_ledger]
        if isinstance(input_ledger, list)
        and (bool(input_ledger) or not input_physical)
        and all(
            isinstance(row, dict) and isinstance(row.get("raw_finding"), dict)
            for row in input_ledger
        )
        else input_physical
    )
    return baseline, input_physical, verified_runtime_rows


def _record_security_scan_conservation(
    core,
    captured,
    conservation,
    baseline,
    input_physical,
    native_expected_rows,
    provisional_failure,
):
    """Record the conservation check and keep forensic rows on failed seals."""
    if provisional_failure is not None:
        conservation.update(
            state="FAILED", provisional_exclusion_rollback=provisional_failure
        )
    core["finding_conservation"] = conservation
    if conservation["state"] != "FAILED":
        return
    if (
        conservation["native_surface_mismatch"]
        and not conservation["native_verification_state_changed"]
    ):
        missing = _unreconciled_native_diagnostics(
            core, captured, input_physical, native_expected_rows
        )
        if missing:
            conservation["unreconciled_native_diagnostics"] = missing
    _security_scan_block_conservation_failure(
        core,
        baseline,
        input_physical,
        provisional_failure
        or conservation.get("failure_code")
        or "SECURITY_FINDING_CONSERVATION_FAILED",
    )


def seal_security_scan(
    audit,
    core: dict[str, Any],
    *,
    producer_source_model=None,
    _verified_runtime_rows=None,
    _provisional_failure=None,
) -> dict[str, Any]:
    """Revalidate local captures on every seal; never serialize their source bytes."""
    caller_core = core
    core = _security_scan_transaction_copy(caller_core)
    prior_tier_report = core.get("finding_tier_report")
    _restore_provisional_rows(core)
    baseline, input_physical, verified_runtime_rows = _security_scan_seal_baseline(
        core, _verified_runtime_rows
    )
    prior_state, prior_summary = core.get("state"), core.get("action_summary")
    captured = _prepare_security_scan_sources(core, prior_tier_report)
    from . import primitive_observation_binding as primitive

    (
        native_rows,
        native_expected_rows,
        native_surface_mismatch,
        native_verification_invalidated,
        exclusions,
    ) = _security_scan_partition_native_rows(
        audit,
        core,
        captured,
        primitive,
        baseline,
        input_physical,
        allow_exclusions=_provisional_failure is None,
    )
    if exclusions:
        baseline = _without_provisional_rows(baseline, exclusions, primitive)
        input_physical = _without_provisional_rows(
            input_physical, exclusions, primitive
        )
    from .captured_security_audit import _revalidate_scan_role_support

    _revalidate_scan_role_support(audit, core, captured, primitive, native_rows)
    _preserve_security_scan_incomplete_state(audit, core, prior_state, prior_summary)
    _apply_security_scan_policy(
        audit,
        core,
        captured,
        prior_tier_report,
        prior_state,
        producer_source_model,
        native_rows,
    )
    _apply_security_scan_configuration(audit, core, captured)
    conservation = _security_scan_conservation(
        core,
        baseline,
        input_physical,
        native_expected_rows,
        primitive,
        native_surface_mismatch,
        native_verification_invalidated,
        verified_runtime_rows,
        getattr(captured, "source_role_capture", {}).get("sealed_negative_rows", ()),
    )
    _record_security_scan_conservation(
        core,
        captured,
        conservation,
        baseline,
        input_physical,
        native_expected_rows,
        _provisional_failure,
    )
    result = _finish_security_scan_seal(audit, core, captured, baseline, input_physical)
    if exclusions and any(
        value.get("state") == "BLOCKED"
        for value in (result, result.get("defect_policy_decision", {}))
    ):
        # The caller still holds the untouched raw rows and the prior tier evidence.
        failure_code = (
            conservation.get("failure_code")
            or core.get("defect_policy_decision", {}).get("failure_code")
            or "SECURITY_PROVISIONAL_EXCLUSION_POLICY_BLOCKED"
        )
        return seal_security_scan(
            audit,
            caller_core,
            producer_source_model=producer_source_model,
            _verified_runtime_rows=_verified_runtime_rows,
            _provisional_failure=failure_code,
        )
    caller_core.clear()
    caller_core.update(result)
    if type(caller_core) is _SourceBoundSecurityReport:
        caller_core._captured_sources = getattr(
            result, "_captured_sources", getattr(caller_core, "_captured_sources", None)
        )
        caller_core._source_role_capture = deepcopy(
            getattr(result, "_source_role_capture", {})
        )
    return result


def _apply_security_scan_configuration(audit, core, captured):
    """Finalize descriptive tenant metadata after partition and policy decisions."""
    configuration = core.get("tenant_read_contract", {}).get("configuration")
    if not isinstance(configuration, dict) or configuration.get("state") != "missing":
        return
    if core.get("state") == "CLEAN":
        core["state"] = "INCOMPLETE"
        _apply_security_scan_policy(
            audit, core, captured, core.get("finding_tier_report"), "INCOMPLETE"
        )
    if core.get("selected_defect_policy") in {
        "source-role-v1",
        "source-role-v2",
        "source-role-v3",
    } and (
        core.get("defect_policy_decision", {}).get("source_sha256") is not None
        or core.get("state") == "INCOMPLETE"
    ):
        return
    message = (
        " Tenant isolation remains unassessed for custom reads; add "
        "`.factory/tenant-read-contract.json` with every tenant-scoped "
        "read and its binding, or explicitly declare an empty read set."
    )
    if message.strip() not in core.get("action_summary", ""):
        core["action_summary"] = core.get("action_summary", "") + message


def security_scan_report(
    audit,
    files: list[Path],
    findings: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    counts: dict[str, int],
    outcomes: dict[str, int],
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
    oracle_edges: list[dict[str, Any]],
    oracle_configuration: list[dict[str, Any]],
    database_context: dict | None = None,
    tenant_policy_applies: bool = False,
    primitive_source_bytes: dict[str, bytes] | None = None,
    *,
    source_limit: int | None = None,
    collection_identity: dict | None = None,
    security_only: bool = False,
    defect_policy: str = "legacy-v1",
    tenant_read_configuration: dict | None = None,
    producer_source_model=None,
    collection_observation: dict | None = None,
    defer_collection_binding: bool = False,
) -> dict[str, Any]:
    """Assemble and seal the bounded Python security scan report with coverage, source bindings, findings, and its non-runtime, non-approval limits."""
    audit_coverage = audit._security_scan_coverage(
        files,
        outcomes,
        _validate_source_file_limit(
            audit.MAX_SECURITY_SOURCE_FILES if source_limit is None else source_limit
        ),
    )
    state = audit._security_scan_state(
        files, findings, database_context, audit_coverage
    )
    core: dict[str, Any] = {
        "schema": audit.SECURITY_SCHEMA,
        "marker": "SECURITY_AUDIT_COMPLETE",
        "state": state,
        "files_scanned": len(bindings),
        "parse_errors": outcomes["syntax_error"],
        "unreadable_sources": outcomes["unreadable"],
        "oversized_sources": outcomes["too_large"],
        "audit_coverage": audit_coverage,
        "tenant_read_contract": audit._tenant_read_contract(
            tenant_read_calls, tenant_read_bindings, tenant_policy_applies
        ),
        "oracle_context": audit.contracts.import_context_metadata(
            files, oracle_edges, oracle_configuration
        ),
        "sources": bindings,
        "_primitive_source_bytes": primitive_source_bytes or {},
        "database_context": database_context or {},
        "findings": findings,
        "finding_counts": dict(sorted(counts.items())),
        "governance": "human_controlled",
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
        },
        "claim_boundary": "Bounded Python AST pattern scan only. Declared tenant argument bindings verify syntactic pass-through, not tenant identity, authorization, or access isolation; this is not a penetration test, runtime exploit proof, dependency advisory, or release approval.",
    }
    _apply_security_scan_report_metadata(
        core,
        security_only,
        defect_policy,
        tenant_read_configuration,
        collection_identity,
    )
    core["source_manifest_sha256"] = audit.sha256(
        json.dumps(
            {
                "sources": bindings,
                "oracle_context": core["oracle_context"],
                "database_context": core["database_context"],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    core["action_summary"] = audit._security_scan_action_summary(state)
    if collection_observation is not None and not defer_collection_binding:
        from .mission_control_status import (
            _bind_security_scan_collection_observation,
        )

        core = _bind_security_scan_collection_observation(
            core,
            collection_observation.get("before"),
            collection_observation.get("after"),
            scan_identity=collection_identity,
            strict_transaction=True,
        )
    return audit._seal_security_scan(
        core,
        **(
            {"producer_source_model": producer_source_model}
            if producer_source_model is not None
            else {}
        ),
    )


def _apply_security_scan_report_metadata(
    core, security_only, defect_policy, tenant_read_configuration, collection_identity
):
    if security_only is True:
        core["oracle_context"]["test_oracle_assessment"] = "NOT_ASSESSED_SECURITY_ONLY"
    if defect_policy != "legacy-v1":
        core["selected_defect_policy"] = defect_policy
    if tenant_read_configuration is not None:
        core["tenant_read_contract"]["configuration"] = deepcopy(
            tenant_read_configuration
        )
    if collection_identity is not None:
        from .pytest_collection_audit import pytest_collection_authoritative

        core["oracle_context"]["static_pytest_collection"] = deepcopy(
            collection_identity
        )
        if not pytest_collection_authoritative(collection_identity):
            core["oracle_context"]["pytest_collection"] = deepcopy(collection_identity)
            core["state"] = "INCOMPLETE"


def _security_scan_context(audit, security_only, evidence, configuration=None):
    """Keep effective security-only mode and its oracle boundary together."""
    if type(security_only) is not bool:
        raise audit.ReviewAuditError("security_only must be a boolean.")
    enabled = security_only or audit._SECURITY_ONLY_SCAN.get() is True
    if enabled and any(value is not None for value in evidence):
        raise audit.ReviewAuditError(
            "security_only cannot credit runtime test-oracle evidence."
        )
    if configuration is not None:
        if not isinstance(configuration, dict) or configuration.get("state") not in (
            "missing",
            "loaded",
        ):
            raise audit.ReviewAuditError("Tenant configuration metadata is malformed.")
        try:
            canonical_bytes(configuration)
        except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
            raise audit.ReviewAuditError(
                "Tenant configuration metadata must contain valid JSON values."
            ) from None
    return audit._security_only_scan_context(enabled)


def _prepare_security_scan_transaction(
    audit,
    root,
    evidence,
    tenant_read_calls,
    tenant_read_bindings,
    tenant_read_scopes,
    tenant_policy_applies,
    cache_enabled,
    analysis_profile,
    provider_contracts,
    defect_policy,
    max_files,
    tenant_read_configuration,
    bind_collection_receipt,
):
    from .finite_capture import provider_analysis_profile
    from .primitive_observation_binding import validate_security_defect_policy

    selected_policy = validate_security_defect_policy(defect_policy)
    if type(bind_collection_receipt) is not bool:
        raise audit.ReviewAuditError("bind_collection_receipt must be a boolean.")
    source_limit = audit._validate_source_file_limit(max_files)
    profile = provider_analysis_profile(analysis_profile, provider_contracts)
    workspace = Path(root).resolve()
    effective_security_only = audit._SECURITY_ONLY_SCAN.get() is True
    receipt_before = None
    if bind_collection_receipt:
        from .mission_control_status import _capture_security_scan_collection

        receipt_before = _capture_security_scan_collection(
            workspace, effective_security_only
        )
    if not isinstance(tenant_policy_applies, bool):
        raise audit.ReviewAuditError("tenant_policy_applies must be a boolean.")
    tenant_read_calls = audit._tenant_contract_calls(tenant_read_calls)
    tenant_read_bindings = audit._tenant_contract_bindings(
        tenant_read_bindings, tenant_read_calls
    )
    tenant_read_scopes = audit._validate_tenant_scopes(workspace, tenant_read_scopes)
    cache_enabled = audit._validate_cache_enabled(cache_enabled)
    files = audit._security_source_files(workspace)
    if tenant_policy_applies:
        tenant_read_scopes[""] = {
            "calls": (),
            "bindings": {},
            "_policy_applies": True,
        }
    transaction = SimpleNamespace(
        selected_policy=selected_policy,
        source_limit=source_limit,
        profile=profile,
        workspace=workspace,
        receipt_before=receipt_before,
        effective_security_only=effective_security_only,
        tenant_read_calls=tenant_read_calls,
        tenant_read_bindings=tenant_read_bindings,
        tenant_read_scopes=tenant_read_scopes,
        cache_enabled=cache_enabled,
        files=files,
        blocked=None,
    )
    if len(files) > source_limit:
        blocked = audit._security_source_limit_report(
            workspace,
            files,
            tenant_read_calls,
            tenant_read_bindings,
            tenant_policy_applies,
            evidence,
            profile,
            selected_policy,
            source_limit,
            tenant_read_configuration,
        )
        if bind_collection_receipt:
            from .mission_control_status import (
                _bind_security_scan_collection_observation,
                _capture_security_scan_collection,
            )

            after = _capture_security_scan_collection(
                workspace, effective_security_only
            )
            blocked = _bind_security_scan_collection_observation(
                blocked, receipt_before, after
            )
            blocked = audit._seal_security_scan(blocked)
            blocked = _finish_security_scan_collection_receipt(
                audit,
                workspace,
                blocked,
                receipt_before,
                after,
                None,
                effective_security_only,
                strict_transaction=False,
            )
        transaction.blocked = blocked
    return transaction


def _collect_security_scan_inputs(audit, transaction, runtime_requested):
    """Collect the source inventory and any provisional evidence before sealing."""
    database_context = {}
    captured = _CapturedSecuritySources()
    conditional = transaction.profile["conditional"]
    configuration = _ConfigurationProofCapture(
        provisional_exclusions=(
            set()
            if transaction.selected_policy == "source-role-v3"
            and not conditional
            and not runtime_requested
            else None
        )
    )
    producer_source_model = {"configuration_bytes": configuration}
    collection_identity = {}
    scanned = audit._scan_security_sources(
        transaction.workspace,
        transaction.files,
        transaction.tenant_read_calls,
        transaction.tenant_read_bindings,
        transaction.tenant_read_scopes,
        cache_enabled=transaction.cache_enabled and not conditional,
        database_context=database_context,
        primitive_source_bytes_out=captured,
        capture_all_sources=conditional or transaction.selected_policy != "legacy-v1",
        producer_source_model_out=producer_source_model,
        collection_identity_out=collection_identity,
    )
    configuration.bind_provisional_exclusions(captured, transaction.workspace)
    return (
        scanned,
        database_context,
        captured,
        producer_source_model.get("source"),
        collection_identity,
    )


def security_scan(
    audit,
    root: Path,
    *,
    tenant_read_calls: tuple[str, ...] = (),
    tenant_read_bindings: tuple[str, ...] = (),
    tenant_read_scopes: dict | None = None,
    tenant_policy_applies: bool = False,
    cache_enabled: bool = True,
    oracle_evidence: str | None = None,
    oracle_trust_root: str | None = None,
    oracle_trust_sha256: str | None = None,
    oracle_environment_sha256: str | None = None,
    analysis_profile: str = "source-closed-v1",
    provider_contracts: tuple[dict, ...] = (),
    defect_policy: str = "legacy-v1",
    max_files: int | None = None,
    security_only: bool = False,
    tenant_read_configuration: dict | None = None,
    bind_collection_receipt: bool = False,
) -> dict[str, Any]:
    """Run a bounded AST scan with content-bound process-local context reuse."""
    evidence = (
        oracle_evidence,
        oracle_trust_root,
        oracle_trust_sha256,
        oracle_environment_sha256,
    )
    runtime_requested = any(value is not None for value in evidence)
    with _security_scan_context(
        audit, security_only, evidence, tenant_read_configuration
    ):
        transaction = _prepare_security_scan_transaction(
            audit,
            root,
            evidence,
            tenant_read_calls,
            tenant_read_bindings,
            tenant_read_scopes,
            tenant_policy_applies,
            cache_enabled,
            analysis_profile,
            provider_contracts,
            defect_policy,
            max_files,
            tenant_read_configuration,
            bind_collection_receipt,
        )
        if transaction.blocked is not None:
            return transaction.blocked
        selected_policy = transaction.selected_policy
        source_limit = transaction.source_limit
        profile = transaction.profile
        workspace = transaction.workspace
        receipt_before = transaction.receipt_before
        effective_security_only = transaction.effective_security_only
        tenant_read_calls = transaction.tenant_read_calls
        tenant_read_bindings = transaction.tenant_read_bindings
        files = transaction.files
        (
            (bindings, findings, counts, outcomes, oracle_edges, oracle_configuration),
            database_context,
            primitive_source_bytes,
            producer_source_model,
            collection_identity,
        ) = _collect_security_scan_inputs(audit, transaction, runtime_requested)
        receipt_observation = None
        if bind_collection_receipt:
            from .mission_control_status import _capture_security_scan_collection

            receipt_after = _capture_security_scan_collection(
                workspace, effective_security_only
            )
            receipt_observation = {"before": receipt_before, "after": receipt_after}
        result = audit._security_scan_report(
            files,
            findings,
            bindings,
            counts,
            outcomes,
            tenant_read_calls,
            tenant_read_bindings,
            oracle_edges,
            oracle_configuration,
            database_context,
            tenant_policy_applies,
            primitive_source_bytes,
            source_limit=source_limit,
            collection_identity=collection_identity,
            security_only=audit._SECURITY_ONLY_SCAN.get() is True,
            defect_policy=selected_policy
            if not profile["conditional"]
            else "legacy-v1",
            tenant_read_configuration=(
                None
                if profile["conditional"] or runtime_requested
                else tenant_read_configuration
            ),
            producer_source_model=producer_source_model,
            collection_observation=receipt_observation,
            defer_collection_binding=runtime_requested,
        )
        result = _finish_native_security_scan(
            audit,
            workspace,
            result,
            evidence,
            profile,
            selected_policy,
            primitive_source_bytes,
            producer_source_model,
            tenant_read_configuration,
        )
        return _finish_security_scan_collection_receipt(
            audit,
            workspace,
            result,
            receipt_before,
            receipt_observation.get("after") if receipt_observation else None,
            collection_identity,
            effective_security_only,
            producer_source_model,
            enabled=bind_collection_receipt,
        )


def _finish_security_scan_collection_receipt(
    audit,
    workspace,
    report,
    before,
    after,
    scan_identity,
    security_only,
    producer_source_model=None,
    strict_transaction=True,
    enabled=True,
):
    if not enabled:
        return report
    from .mission_control_status import (
        _bind_security_scan_collection_observation,
        _capture_security_scan_collection,
    )

    final = _capture_security_scan_collection(workspace, security_only)
    current = report.get("oracle_context", {}).get("pytest_collection", {})
    if (
        isinstance(final, dict)
        and final == after
        and isinstance(current, dict)
        and isinstance(current.get("capture_observations"), dict)
    ):
        proof_root = getattr(report, "_source_role_capture", {}).get(
            "fixture_workspace"
        )
        if not proof_root or not report.get("selected_defect_policy"):
            return report
        # Pytest identity does not cover the launch and dependency configuration
        # used by application fixture proofs.
        if (
            proof_root == workspace
            and _security_fixture_verifier_bindings(
                audit, report, proof_root, dict(report._captured_sources)
            )
            is not None
        ):
            return report
        report = report.copy()
        # Keep live authority revocation distinct from a detached JSON receipt.
        report._source_role_capture["fixture_workspace"] = False
        return audit._seal_security_scan(
            report, producer_source_model=producer_source_model
        )
    prepared = _bind_security_scan_collection_observation(
        report,
        before,
        after,
        scan_identity=scan_identity,
        final=final,
        final_checked=True,
        strict_transaction=strict_transaction,
    )
    return audit._seal_security_scan(
        prepared, producer_source_model=producer_source_model
    )


def _finish_native_security_scan(
    audit,
    workspace,
    result,
    evidence,
    profile,
    selected_policy,
    primitive_source_bytes,
    producer_source_model,
    tenant_read_configuration,
):
    """Retain resealing only after conditional or runtime inputs actually change."""
    runtime_requested = any(value is not None for value in evidence)
    if profile["conditional"]:
        from .primitive_observation_binding import apply_conditional_provider_profile

        result = apply_conditional_provider_profile(
            result, profile, primitive_source_bytes
        )
        if selected_policy != "legacy-v1":
            result["selected_defect_policy"] = selected_policy
            result = audit._seal_security_scan(
                result, producer_source_model=producer_source_model
            )
    if tenant_read_configuration is not None and (
        profile["conditional"] or runtime_requested
    ):
        result["tenant_read_contract"]["configuration"] = deepcopy(
            tenant_read_configuration
        )
        if not runtime_requested:
            result = audit._seal_security_scan(result)
    if runtime_requested:
        result = audit._reconcile_runtime_oracles(workspace, result, evidence)
    return result


def _validate_source_file_limit(value: int | None) -> int:
    from .review_audits import MAX_SECURITY_SOURCE_FILES, ReviewAuditError

    if value is None:
        return MAX_SECURITY_SOURCE_FILES
    if type(value) is not int or not 1 <= value <= MAX_SECURITY_SOURCE_FILES:
        raise ReviewAuditError(
            f"max_files must be an integer from 1 to {MAX_SECURITY_SOURCE_FILES}."
        )
    return value


def _security_scan_coverage(
    files: list[Path], outcomes: dict[str, int], limit: int
) -> dict[str, Any]:
    audited = outcomes["audited"]
    attempted = len(files)
    complete = bool(files) and attempted == audited
    if not files:
        measurement_state = "no_eligible_sources"
    elif complete:
        measurement_state = "complete"
    else:
        measurement_state = "incomplete"
    return {
        "language": "Python",
        "files_discovered": len(files),
        "files_attempted": attempted,
        "files_audited": audited,
        "audit_rate": round(audited / len(files), 4) if files else None,
        "rate_defined": bool(files),
        "inventory_complete": True,
        "measurement_state": measurement_state,
        "complete": complete,
        "limit": limit,
    }


def blocked_security_scan_report(
    audit,
    workspace: Path,
    files: list[Path],
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
    tenant_policy_applies: bool = False,
    source_limit: int | None = None,
) -> dict[str, Any]:
    """Return a fail-closed receipt when the bounded inventory is exceeded."""
    relative_paths = [path.relative_to(workspace).as_posix() for path in files]
    source_limit = _validate_source_file_limit(
        audit.MAX_SECURITY_SOURCE_FILES if source_limit is None else source_limit
    )
    advice = (
        f"rerun factory scan --max-files {audit.MAX_SECURITY_SOURCE_FILES}."
        if source_limit < audit.MAX_SECURITY_SOURCE_FILES
        else "partition the workspace to stay within the captured-source bound."
    )
    finding = audit._security_finding(
        "SECURITY_AUDIT_INCOMPLETE",
        ".",
        audit.ast.Module(body=[], type_ignores=[]),
        (
            f"Eligible Python source inventory contains {len(files)} files, above "
            f"the {source_limit}-file scan limit. No files were scanned; {advice}"
        ),
        "HIGH",
        files_discovered=len(files),
        files_scanned=0,
    )
    core = {
        "schema": audit.SECURITY_SCHEMA,
        "marker": "SECURITY_AUDIT_COMPLETE",
        "state": "BLOCKED",
        "files_scanned": 0,
        "parse_errors": 0,
        "unreadable_sources": 0,
        "oversized_sources": 0,
        "audit_coverage": {
            "language": "Python",
            "files_discovered": len(files),
            "files_attempted": 0,
            "files_audited": 0,
            "audit_rate": 0.0,
            "rate_defined": True,
            "measurement_state": "blocked",
            "inventory_complete": True,
            "complete": False,
            "limit": source_limit,
            "inventory_sha256": audit.sha256(
                "\n".join(relative_paths).encode("utf-8")
            ).hexdigest(),
        },
        "tenant_read_contract": audit._tenant_read_contract(
            tenant_read_calls, tenant_read_bindings, tenant_policy_applies
        ),
        "sources": [],
        "oracle_context": {
            "mode": "not_assessed_source_limit",
            "configuration_sources": [],
        },
        "findings": [finding],
        "finding_counts": {finding["code"]: 1},
        "governance": "human_controlled",
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
        },
        "claim_boundary": (
            "No security analysis completed because the eligible Python source "
            "inventory exceeded the configured scan limit. Other languages, "
            "runtime behavior, dependency advisories, and release approval are "
            "outside this scanner's scope."
        ),
        "action_summary": finding["message"],
    }
    return audit._seal_security_scan(core)
