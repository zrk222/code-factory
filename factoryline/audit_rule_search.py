"""Context-bounded search over Code Factory's six-lane rejection inventory.

The index is derived from the repository's deterministic rejection markers at
read time.  It is deliberately advisory: searching rules never executes an
audit, changes a gate, or grants authority.  A signed runtime-audit plan and
the existing human-controlled CLI remain the only execution path.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


class AuditRuleSearchError(ValueError):
    """Stable validation error for the read-only rule search surface."""

    def __init__(self, message: str, marker: str = "MCP_AUDIT_RULE_SEARCH_INVALID"):
        super().__init__(message)
        self.marker = marker


_LANE_SPECS: tuple[tuple[str, str, str], ...] = (
    ("stateful_workflows", "Stateful workflows and business invariants", "Do workflow sequences preserve business invariants after retries and reversals?"),
    ("authorization_tenant_isolation", "Authorization and tenant isolation", "Can one tenant reach another tenant's data through every request and background surface?"),
    ("failure_recovery", "Failure, concurrency, retries and recovery", "Do timeouts, duplicate events, concurrent writes, and worker crashes recover safely?"),
    ("api_consumer_compatibility", "API and consumer compatibility", "Will existing consumers continue to work with this contract and deployment?"),
    ("migration_data_integrity", "Database migration and data integrity", "Can old and new versions migrate and recover without loss or constraint drift?"),
    ("performance_resources", "Performance, memory and resource regression", "Does the candidate stay within approved latency, resource, and leak budgets?"),
)
_LANE_MODULES = {
    "stateful_workflows": "runtime_audit_stateful.py",
    "authorization_tenant_isolation": "runtime_audit_tenant.py",
    "failure_recovery": "runtime_audit_recovery.py",
    "api_consumer_compatibility": "runtime_audit_compatibility.py",
    "migration_data_integrity": "runtime_audit_migration.py",
    "performance_resources": "runtime_audit_performance.py",
}
_CROSSCUTTING_MODULES = (
    "runtime_audit_contract.py",
    "runtime_audit_common.py",
    "runtime_audit_policy.py",
    "runtime_audit_runner.py",
    "runtime_audit_integrity.py",
    "runtime_audit.py",
)
_REJECTION_PREFIXES = ("E_", "RUNTIME_", "CROSS_", "HOLLOW_", "INCOMPLETE_")
_NON_REJECTION_MARKERS = {
    "PASS", "FAIL", "INCOMPLETE", "STATEFUL_INVARIANTS_HELD",
    "TENANT_MATRIX_HELD", "RECOVERY_INVARIANTS_HELD",
    "CONSUMER_CONTRACTS_HELD", "MIGRATION_REHEARSAL_HELD",
    "PERFORMANCE_AND_RESOURCES_HELD", "BLOCKED", "NOT_RUN",
    "READY_FOR_HUMAN_REVIEW", "SUPERVISED_ONLY",
}
_EVIDENCE_TYPES = {
    "stateful_workflows": ["state-machine traces", "property examples", "known-bad invariant result"],
    "authorization_tenant_isolation": ["runtime request matrix", "tenant/resource identities", "denial evidence"],
    "failure_recovery": ["fault schedule", "concurrency trace", "recovery postconditions"],
    "api_consumer_compatibility": ["consumer contract", "schema digest", "deployment matrix"],
    "migration_data_integrity": ["before/after schema digests", "sanitized fixture counts", "rollback or forward-fix evidence"],
    "performance_resources": ["approved workload baseline", "latency/resource samples", "leak or retention evidence"],
    "cross_cutting": ["signed plan", "candidate digest", "source and evidence hashes", "human release decision"],
}
_ROOT = Path(__file__).resolve().parent


def _markers(module: str, *, lane_specific: bool = False) -> list[str]:
    try:
        tree = ast.parse((_ROOT / module).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return []
    values = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and len(node.value) >= 4
        and node.value.replace("_", "").isalnum()
        and node.value.upper() == node.value
    }
    return sorted(value for value in values if value not in _NON_REJECTION_MARKERS and (lane_specific or value.startswith(_REJECTION_PREFIXES)))


def _rule(rule_id: str, code: str, lane: str, label: str, module: str) -> dict[str, Any]:
    name = code.replace("_", " ").title()
    return {
        "ruleId": rule_id,
        "name": name,
        "lane": lane,
        "laneLabel": label,
        "description": f"Deterministic Code Factory rejection condition {code} in the {label} lane.",
        "practicalQuestion": next(question for key, _, question in _LANE_SPECS if key == lane) if lane != "cross_cutting" else "Is the signed contract, evidence, and execution boundary still intact?",
        "rejectionCondition": code,
        "requiredEvidenceTypes": list(_EVIDENCE_TYPES[lane]),
        "sourceModule": module,
    }


def _inventory() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for lane, label, _ in _LANE_SPECS:
        for code in _markers(_LANE_MODULES[lane], lane_specific=True):
            rules.append(_rule(f"CF-RULE-{code}", code, lane, label, _LANE_MODULES[lane]))
    seen_cross_cutting: set[str] = set()
    for module in _CROSSCUTTING_MODULES:
        for code in _markers(module):
            if code in seen_cross_cutting:
                continue
            seen_cross_cutting.add(code)
            rules.append(_rule(f"CF-RULE-{code}", code, "cross_cutting", "Cross-cutting contract, policy, provenance, evidence and execution integrity", module))
    return sorted(rules, key=lambda item: (item["lane"], item["rejectionCondition"], item["sourceModule"]))


def _validate(arguments: object) -> tuple[str, str | None, bool, int]:
    if not isinstance(arguments, dict):
        raise AuditRuleSearchError("factory.search_audit_rules requires an object")
    allowed = {"query", "lane", "includeCrossCutting", "limit"}
    unknown = sorted(set(arguments) - allowed)
    if unknown:
        raise AuditRuleSearchError("unsupported search fields: " + ", ".join(unknown))
    query = arguments.get("query")
    if not isinstance(query, str) or not query.strip() or len(query) > 200:
        raise AuditRuleSearchError("query must be a non-empty string of at most 200 characters")
    lane = arguments.get("lane")
    if lane is not None and lane not in {key for key, _, _ in _LANE_SPECS}:
        raise AuditRuleSearchError("lane must name one of the six mandatory audit lanes")
    include_cross_cutting = arguments.get("includeCrossCutting", True)
    if type(include_cross_cutting) is not bool:
        raise AuditRuleSearchError("includeCrossCutting must be boolean")
    limit = arguments.get("limit", 5)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
        raise AuditRuleSearchError("limit must be an integer from 1 to 20")
    return query.strip().lower(), lane, include_cross_cutting, limit


def search_audit_rules(arguments: object) -> dict[str, object]:
    """Return a bounded, deterministic search result over the six-lane index."""
    query, lane, include_cross_cutting, limit = _validate(arguments)
    inventory = _inventory()
    searchable = []
    for rule in inventory:
        if lane is not None and rule["lane"] not in {lane, "cross_cutting"}:
            continue
        if not include_cross_cutting and rule["lane"] == "cross_cutting":
            continue
        haystack = " ".join(
            str(rule[field]).lower()
            for field in ("name", "description", "practicalQuestion", "rejectionCondition", "lane", "laneLabel")
        )
        if query in haystack:
            searchable.append(rule)
    results = searchable[:limit]
    index_sha256 = sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "marker": "MCP_AUDIT_RULE_SEARCH_READ_ONLY",
        "schema": "factory.audit-rule-search.v1",
        "query": query,
        "lane": lane,
        "includeCrossCutting": include_cross_cutting,
        "totalMatched": len(searchable),
        "returned": len(results),
        "ruleIndexSha256": index_sha256,
        "rules": results,
        "nextRecommendedStep": (
            "Use the matching rule IDs to select a signed runtime-audit lane plan; execution remains human-controlled through the CLI."
            if results
            else "No matching rules found. Try broader terms or include cross-cutting rules."
        ),
        "action_summary": "Search the bounded six-lane rejection inventory without executing an audit or changing a gate.",
        "authority": "none",
        "claim_boundary": "Rule discovery is advisory context only; it does not execute, approve, weaken, or release an audit lane.",
    }
