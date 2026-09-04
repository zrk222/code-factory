"""Runtime authorization matrix and tenant-isolation evaluation."""
from __future__ import annotations

from typing import Any

from .runtime_audit_common import exact_keys, lane_result, require_int, require_str, require_unique_strings
from .runtime_audit_policy import validate_lane_policy

DENIED_RELATIONS = {"cross_tenant", "anonymous", "revoked_session"}


def evaluate_tenant(artifact: dict[str, Any], config: dict[str, Any], *, engine: str, engine_version: str) -> dict[str, Any]:
    """Evaluate owner and denied tenant relations across cold, warm, and post-revocation runtime surfaces."""
    validate_lane_policy("tenant_isolation", config)
    exact_keys(artifact, {"schema", "engine", "engine_version", "cases"})
    if artifact["schema"] != "factory.runtime.tenant.v1" or artifact["engine"] != engine or artifact["engine_version"] != engine_version:
        return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_IDENTITY_MISMATCH", "Authorization evidence is not bound to the signed engine.")
    forbidden = set(require_unique_strings(config.get("forbidden_fields"), "config.forbidden_fields", minimum=1, maximum=128))
    denial_statuses_raw = config.get("denial_statuses")
    if not isinstance(denial_statuses_raw, list) or not 1 <= len(denial_statuses_raw) <= 8:
        return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_CONFIG_INVALID", "Approved denial statuses are missing.")
    denial_statuses = {require_int(item, "config.denial_statuses[]", minimum=100, maximum=599) for item in denial_statuses_raw}
    cases = artifact["cases"]
    if not isinstance(cases, list) or not 2 <= len(cases) <= 256:
        return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_MATRIX_INCOMPLETE", "Runtime request matrix must contain 2..256 cases.")
    keyed: dict[tuple[str, str], set[str]] = {}
    findings: list[dict[str, Any]] = []
    ids: set[str] = set()
    pairs: set[tuple[str, str, str]] = set()
    for case in cases:
        if not isinstance(case, dict):
            return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_CASE_INVALID", "A request observation is malformed.")
        exact_keys(case, {"id", "surface_id", "phase", "relation", "status", "tenant_data_sha256", "fields", "mutation_effect"})
        case_id = require_str(case["id"], "case.id")
        if case_id in ids:
            return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_DUPLICATE_CASE", "Duplicate request IDs make the matrix ambiguous.")
        ids.add(case_id)
        surface_id = require_str(case["surface_id"], "case.surface_id", maximum=128)
        phase = require_str(case["phase"], "case.phase", maximum=32)
        if phase not in {"cold", "warm", "post_revocation"}:
            return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_PHASE_UNKNOWN", "Cold, warm, and post-revocation observations are required.")
        relation = require_str(case["relation"], "case.relation", maximum=32)
        if relation not in DENIED_RELATIONS | {"owner"}:
            return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_RELATION_UNKNOWN", "The authorization relation is not recognized.")
        status = require_int(case["status"], "case.status", minimum=100, maximum=599)
        fields = case["fields"]
        if not isinstance(fields, list) or len(fields) > 256 or not all(isinstance(item, str) for item in fields):
            return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_FIELDS_INVALID", "Returned field names are malformed.")
        keyed.setdefault((surface_id, phase), set()).add(relation)
        pair = (surface_id, phase, relation)
        if pair in pairs:
            return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_DUPLICATE_CASE", "Repeated surface/relation observations are ambiguous.")
        pairs.add(pair)
        if relation == "owner":
            if not 200 <= status < 300:
                findings.append({"id": case_id, "code": "OWNER_REQUEST_DENIED"})
        else:
            leaked = sorted(forbidden & set(fields))
            digest = case["tenant_data_sha256"]
            if status not in denial_statuses or digest not in (None, "") or leaked or case["mutation_effect"] is not False:
                findings.append({"id": case_id, "code": "TENANT_BOUNDARY_BYPASS", "relation": relation, "status": status, "leaked_fields": leaked, "tenant_data_present": digest not in (None, ""), "mutation_effect": case["mutation_effect"]})
    expected_paths = {(item["id"], phase) for item in config["surfaces"] for phase in ("cold", "warm", "post_revocation")}
    complete = set(keyed) == expected_paths and all(relations == DENIED_RELATIONS | {"owner"} for relations in keyed.values())
    if not complete:
        return lane_result("tenant_isolation", "INCOMPLETE", "TENANT_MATRIX_INCOMPLETE", "Every signed surface must exercise owner, cross-tenant, anonymous and revoked-session access.", details={"missing_surfaces": sorted(expected_paths - set(keyed)), "observed_findings": findings})
    if findings:
        return lane_result("tenant_isolation", "FAIL", "TENANT_ISOLATION_VIOLATION", "A real request exposed or changed tenant-scoped data outside approved authorization.", details={"findings": findings})
    return lane_result("tenant_isolation", "PASS", "TENANT_MATRIX_HELD", "Cold, warm, and post-revocation boundaries held across every signed runtime surface.", details={"cases": len(cases), "surface_phases": len(keyed)})
