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
import math
import re
from typing import Any, Callable, Mapping


class AuditRuleSearchError(ValueError):
    """Stable validation error for the read-only rule search surface."""

    def __init__(self, message: str, marker: str = "MCP_AUDIT_RULE_SEARCH_INVALID"):
        super().__init__(message)
        self.marker = marker


_MAX_JEV_QUERY = 200
_MAX_JEV_CANDIDATES = 20
_NO_RELEASE_DECISION = {"authority": "none", "releaseDecision": False}


def _candidate_ids(search_payload: Mapping[str, Any]) -> list[str]:
    from .jev_classifier import JevClassificationError

    rules = search_payload.get("rules")
    if not isinstance(rules, list) or len(rules) > _MAX_JEV_CANDIDATES:
        raise JevClassificationError("search payload must contain at most 20 rules")
    ids = []
    for rule in rules:
        if not isinstance(rule, Mapping) or not isinstance(rule.get("ruleId"), str):
            raise JevClassificationError("search payload contains an invalid rule")
        ids.append(rule["ruleId"])
    return ids


def build_jev_input(search_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Build the secret-free advisory request for ranked audit retrieval."""
    from .jev_classifier import JevClassificationError, JEV_LABELS, _digest

    query = search_payload.get("query")
    ranking = search_payload.get("ranking")
    if not isinstance(query, str) or not query or len(query) > _MAX_JEV_QUERY:
        raise JevClassificationError("search query is missing or too long")
    if ranking not in {"bm25", "bm25f"}:
        raise JevClassificationError("Jev handoff requires BM25 or BM25F retrieval")
    candidate_ids = _candidate_ids(search_payload)
    context = {
        "query": query,
        "ranking": ranking,
        "ruleIndexSha256": search_payload.get("ruleIndexSha256"),
        "candidateRuleIds": candidate_ids,
    }
    return {
        "schema": "factory.jev-classification-input.v1",
        "query": query,
        "ranking": ranking,
        "candidateRuleIds": candidate_ids,
        "contextSha256": _digest(context),
        "allowedLabels": sorted(JEV_LABELS),
        "authority": "none",
        "claimBoundary": "Advisory routing only; deterministic CF gates remain authoritative.",
    }


def _probability(value: object, label: str) -> float:
    from .jev_classifier import JevClassificationError

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JevClassificationError(f"{label} must be numeric")
    if not 0.0 <= float(value) <= 1.0:
        raise JevClassificationError(f"{label} must be between 0 and 1")
    return round(float(value), 6)


def _rule_scores(raw: object, allowed: set[str]) -> dict[str, float]:
    from .jev_classifier import JevClassificationError

    if not isinstance(raw, Mapping):
        raise JevClassificationError("ruleScores must be an object")
    normalized = {}
    for rule_id, score in raw.items():
        if rule_id not in allowed:
            raise JevClassificationError(
                "Jev scored a rule outside the retrieved candidates"
            )
        normalized[rule_id] = _probability(score, "Jev rule score")
    return normalized


def normalize_jev_result(
    raw: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    model_id: str = "jev",
    model_version: str = "unspecified",
) -> dict[str, Any]:
    """Validate a typed Jev response and bind it to the exact request context."""
    from .jev_classifier import JevClassificationError, JEV_LABELS

    if not isinstance(raw, Mapping):
        raise JevClassificationError("Jev response must be an object")
    label = raw.get("label")
    probability = raw.get("probability")
    context_sha = raw.get("contextSha256")
    selected = raw.get("selectedRuleIds", [])
    rule_scores = raw.get("ruleScores", {})
    if label not in JEV_LABELS:
        raise JevClassificationError("Jev returned an unsupported label")
    probability = _probability(probability, "Jev probability")
    if context_sha != request.get("contextSha256"):
        raise JevClassificationError("Jev context hash does not match retrieval")
    if not isinstance(selected, list) or not all(
        isinstance(item, str) for item in selected
    ):
        raise JevClassificationError("selectedRuleIds must be a list of strings")
    allowed = set(request.get("candidateRuleIds", []))
    if not set(selected) <= allowed:
        raise JevClassificationError(
            "Jev selected a rule outside the retrieved candidates"
        )
    return {
        "schema": "factory.jev-classification-result.v1",
        "label": label,
        "probability": probability,
        "selectedRuleIds": selected,
        "ruleScores": _rule_scores(rule_scores, allowed),
        "modelId": model_id,
        "modelVersion": model_version,
        "requestId": str(raw.get("requestId", "unassigned")),
        "contextSha256": request["contextSha256"],
        "status": "ADVISORY",
        **_NO_RELEASE_DECISION,
        "claimBoundary": "Typed classification is advisory and does not prove semantics or authorize execution.",
    }


def _retrieval_fallback(request, model_id, model_version, request_id, reason, boundary):
    return {
        "schema": "factory.jev-classification-result.v1",
        "label": "HUMAN_REVIEW",
        "probability": 0.0,
        "selectedRuleIds": request["candidateRuleIds"],
        "ruleScores": {},
        "modelId": model_id,
        "modelVersion": model_version,
        "requestId": request_id,
        "contextSha256": request["contextSha256"],
        "status": "FALLBACK",
        "fallbackReason": reason,
        **_NO_RELEASE_DECISION,
        "claimBoundary": boundary,
    }


def classify_retrieval(
    search_payload: Mapping[str, Any],
    *,
    transport: Callable[[dict[str, Any]], Mapping[str, Any]] | None = None,
    model_id: str = "jev",
    model_version: str = "unspecified",
) -> dict[str, Any]:
    """Classify BM25/BM25F candidates, failing closed when Jev is unavailable."""
    from .jev_classifier import (
        _TRANSPORT_ERRORS,
        build_jev_input,
        normalize_jev_result,
    )

    request = build_jev_input(search_payload)
    if transport is None:
        return _retrieval_fallback(
            request,
            model_id,
            model_version,
            "unavailable",
            "JEV_UNAVAILABLE",
            "Jev is optional; human review is required when the classifier is unavailable.",
        )
    try:
        raw = transport(request)
        return normalize_jev_result(
            raw,
            request=request,
            model_id=model_id,
            model_version=model_version,
        )
    except _TRANSPORT_ERRORS as exc:
        return _retrieval_fallback(
            request,
            model_id,
            model_version,
            "fallback",
            type(exc).__name__,
            "Invalid or unavailable Jev output fails closed to human review.",
        )


_LANE_SPECS: tuple[tuple[str, str, str], ...] = (
    (
        "stateful_workflows",
        "Stateful workflows and business invariants",
        "Do workflow sequences preserve business invariants after retries and reversals?",
    ),
    (
        "authorization_tenant_isolation",
        "Authorization and tenant isolation",
        "Can one tenant reach another tenant's data through every request and background surface?",
    ),
    (
        "failure_recovery",
        "Failure, concurrency, retries and recovery",
        "Do timeouts, duplicate events, concurrent writes, and worker crashes recover safely?",
    ),
    (
        "api_consumer_compatibility",
        "API and consumer compatibility",
        "Will existing consumers continue to work with this contract and deployment?",
    ),
    (
        "migration_data_integrity",
        "Database migration and data integrity",
        "Can old and new versions migrate and recover without loss or constraint drift?",
    ),
    (
        "performance_resources",
        "Performance, memory and resource regression",
        "Does the candidate stay within approved latency, resource, and leak budgets?",
    ),
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
    "import_context.py",
    "runtime_audit.py",
    "runtime_audit_process.py",
)
_REJECTION_PREFIXES = ("E_", "RUNTIME_", "CROSS_", "HOLLOW_", "INCOMPLETE_")
_NON_REJECTION_MARKERS = {
    "ABSTAIN",
    "BOUND_LOCAL_EVIDENCE",
    "REGRESSION_GATES",
    "PASS",
    "FAIL",
    "INCOMPLETE",
    "STATEFUL_INVARIANTS_HELD",
    "TENANT_MATRIX_HELD",
    "RECOVERY_INVARIANTS_HELD",
    "CONSUMER_CONTRACTS_HELD",
    "MIGRATION_REHEARSAL_HELD",
    "PERFORMANCE_AND_RESOURCES_HELD",
    "BLOCKED",
    "NOT_RUN",
    "READY_FOR_HUMAN_REVIEW",
    "SUPERVISED_ONLY",
}
_EVIDENCE_TYPES = {
    "stateful_workflows": [
        "state-machine traces",
        "property examples",
        "known-bad invariant result",
    ],
    "authorization_tenant_isolation": [
        "runtime request matrix",
        "tenant/resource identities",
        "denial evidence",
    ],
    "failure_recovery": [
        "fault schedule",
        "concurrency trace",
        "recovery postconditions",
    ],
    "api_consumer_compatibility": [
        "consumer contract",
        "schema digest",
        "deployment matrix",
    ],
    "migration_data_integrity": [
        "before/after schema digests",
        "sanitized fixture counts",
        "rollback or forward-fix evidence",
    ],
    "performance_resources": [
        "approved workload baseline",
        "latency/resource samples",
        "leak or retention evidence",
    ],
    "cross_cutting": [
        "signed plan",
        "candidate digest",
        "source and evidence hashes",
        "human release decision",
    ],
}
_ROOT = Path(__file__).resolve().parent
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_SEARCH_FIELDS = (
    "name",
    "description",
    "practicalQuestion",
    "rejectionCondition",
    "lane",
    "laneLabel",
    "requiredEvidenceTypes",
    "sourceModule",
)
_BM25F_FIELDS = {
    # Higher weights keep rule identifiers and the human-facing name precise.
    "name": (2.8, 0.55),
    "rejectionCondition": (3.2, 0.45),
    "practicalQuestion": (2.0, 0.70),
    "laneLabel": (1.5, 0.70),
    "description": (1.0, 0.80),
    "requiredEvidenceTypes": (0.9, 0.75),
    "lane": (0.8, 0.60),
    "sourceModule": (0.6, 0.65),
}


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
    return sorted(
        value
        for value in values
        if value not in _NON_REJECTION_MARKERS
        and (lane_specific or value.startswith(_REJECTION_PREFIXES))
    )


def _rule(
    rule_id: str, code: str, lane: str, label: str, module: str
) -> dict[str, Any]:
    name = code.replace("_", " ").title()
    return {
        "ruleId": rule_id,
        "name": name,
        "lane": lane,
        "laneLabel": label,
        "description": f"Deterministic Code Factory rejection condition {code} in the {label} lane.",
        "practicalQuestion": next(
            question for key, _, question in _LANE_SPECS if key == lane
        )
        if lane != "cross_cutting"
        else "Is the signed contract, evidence, and execution boundary still intact?",
        "rejectionCondition": code,
        "requiredEvidenceTypes": list(_EVIDENCE_TYPES[lane]),
        "sourceModule": module,
    }


def _inventory() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for lane, label, _ in _LANE_SPECS:
        for code in _markers(_LANE_MODULES[lane], lane_specific=True):
            rules.append(
                _rule(f"CF-RULE-{code}", code, lane, label, _LANE_MODULES[lane])
            )
    seen_cross_cutting: set[str] = set()
    for module in _CROSSCUTTING_MODULES:
        for code in _markers(module):
            if code in seen_cross_cutting:
                continue
            seen_cross_cutting.add(code)
            rules.append(
                _rule(
                    f"CF-RULE-{code}",
                    code,
                    "cross_cutting",
                    "Cross-cutting contract, policy, provenance, evidence and execution integrity",
                    module,
                )
            )
    return sorted(
        rules,
        key=lambda item: (
            item["lane"],
            item["rejectionCondition"],
            item["sourceModule"],
        ),
    )


def _search_arguments(arguments: object) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise AuditRuleSearchError("factory.search_audit_rules requires an object")
    allowed = {"query", "lane", "includeCrossCutting", "limit", "ranking"}
    unknown = sorted(set(arguments) - allowed)
    if unknown:
        raise AuditRuleSearchError("unsupported search fields: " + ", ".join(unknown))
    return arguments


def _validate_query(arguments: dict[str, Any]) -> str:
    query = arguments.get("query")
    if not isinstance(query, str) or not query.strip() or len(query) > 200:
        raise AuditRuleSearchError(
            "query must be a non-empty string of at most 200 characters"
        )
    return query


def _validate_lane(arguments: dict[str, Any]) -> str | None:
    lane = arguments.get("lane")
    if lane is not None and lane not in {key for key, _, _ in _LANE_SPECS}:
        raise AuditRuleSearchError(
            "lane must name one of the six mandatory audit lanes"
        )
    return lane


def _validate_cross_cutting(arguments: dict[str, Any]) -> bool:
    include_cross_cutting = arguments.get("includeCrossCutting", True)
    if type(include_cross_cutting) is not bool:
        raise AuditRuleSearchError("includeCrossCutting must be boolean")
    return include_cross_cutting


def _validate_limit(arguments: dict[str, Any]) -> int:
    limit = arguments.get("limit", 5)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
        raise AuditRuleSearchError("limit must be an integer from 1 to 20")
    return limit


def _validate_ranking(arguments: dict[str, Any]) -> str:
    ranking = arguments.get("ranking", "bm25f")
    if ranking not in {"lexical", "bm25", "bm25f"}:
        raise AuditRuleSearchError("ranking must be lexical, bm25, or bm25f")
    return ranking


def _validate(arguments: object) -> tuple[str, str | None, bool, int, str]:
    values = _search_arguments(arguments)
    query = _validate_query(values)
    lane = _validate_lane(values)
    include_cross_cutting = _validate_cross_cutting(values)
    limit = _validate_limit(values)
    ranking = _validate_ranking(values)
    return query.strip().lower(), lane, include_cross_cutting, limit, ranking


def _tokens(value: object) -> list[str]:
    """Tokenize search text without locale, stemming, or model dependencies."""
    if isinstance(value, list):
        value = " ".join(str(item) for item in value)
    return _TOKEN_RE.findall(str(value).lower())


def _field_values(rule: dict[str, Any]) -> dict[str, str]:
    return {field: str(rule.get(field, "")) for field in _SEARCH_FIELDS}


def _bm25_scores(
    rules: list[dict[str, Any]], query: str, *, fielded: bool
) -> dict[str, float]:
    """Return explainable BM25/BM25F scores for the bounded in-memory index.

    This intentionally stays local and deterministic.  It is a retrieval aid,
    not a semantic verifier and never changes the rule inventory or authority.
    """
    query_terms = sorted(set(_tokens(query)))
    if not query_terms:
        return {str(rule["ruleId"]): 0.0 for rule in rules}
    documents = [_field_values(rule) for rule in rules]
    n_docs = len(documents)
    field_tokens = [
        {field: _tokens(value) for field, value in document.items()}
        for document in documents
    ]
    avg_len = {
        field: (sum(len(item[field]) for item in field_tokens) / n_docs)
        if n_docs
        else 0.0
        for field in _SEARCH_FIELDS
    }
    if not fielded:
        return _bm25_scores_flat(rules, query_terms, field_tokens)
    return _bm25f_scores(rules, query_terms, field_tokens, avg_len)


def _bm25_scores_flat(
    rules: list[dict[str, Any]],
    query_terms: list[str],
    field_tokens: list[dict[str, list[str]]],
) -> dict[str, float]:
    flattened = [
        [token for values in item.values() for token in values] for item in field_tokens
    ]
    n_docs = len(flattened)
    avg = sum(len(tokens) for tokens in flattened) / n_docs if n_docs else 0.0
    doc_frequency = {
        term: sum(term in set(tokens) for tokens in flattened) for term in query_terms
    }
    scores: dict[str, float] = {}
    for rule, tokens in zip(rules, flattened):
        counts = {term: tokens.count(term) for term in query_terms}
        length = len(tokens)
        score = 0.0
        for term in query_terms:
            df = doc_frequency[term]
            if not counts[term] or not df:
                continue
            idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
            norm = 1.2 * (1.0 - 0.75 + 0.75 * length / avg) if avg else 1.2
            score += idf * (counts[term] * 2.2) / (counts[term] + norm)
        scores[str(rule["ruleId"])] = round(score, 8)
    return scores


def _bm25f_scores(
    rules: list[dict[str, Any]],
    query_terms: list[str],
    field_tokens: list[dict[str, list[str]]],
    avg_len: dict[str, float],
) -> dict[str, float]:
    n_docs = len(field_tokens)

    doc_frequency = {
        term: sum(
            any(term in set(tokens) for tokens in fields.values())
            for fields in field_tokens
        )
        for term in query_terms
    }
    scores = {}
    for rule, fields in zip(rules, field_tokens):
        score = 0.0
        for term in query_terms:
            df = doc_frequency[term]
            if not df:
                continue
            idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
            weighted_tf = 0.0
            for field, (boost, b_value) in _BM25F_FIELDS.items():
                tokens = fields[field]
                count = tokens.count(term)
                if not count:
                    continue
                average = avg_len[field]
                normalization = (
                    1.0 - b_value + b_value * len(tokens) / average if average else 1.0
                )
                weighted_tf += boost * count / normalization
            if weighted_tf:
                score += idf * (2.2 * weighted_tf) / (2.2 + weighted_tf)
        scores[str(rule["ruleId"])] = round(score, 8)
    return scores


def _filter_rules(
    inventory: list[dict[str, Any]],
    query: str,
    lane: str | None,
    include_cross_cutting: bool,
    ranking: str,
) -> list[dict[str, Any]]:
    candidates = []
    for rule in inventory:
        if lane is not None and rule["lane"] not in {lane, "cross_cutting"}:
            continue
        if not include_cross_cutting and rule["lane"] == "cross_cutting":
            continue
        if ranking != "lexical":
            candidates.append(rule)
            continue
        haystack = " ".join(
            str(rule[field]).lower()
            for field in (
                "name",
                "description",
                "practicalQuestion",
                "rejectionCondition",
                "lane",
                "laneLabel",
            )
        )
        if query in haystack:
            candidates.append(rule)
    return candidates


def _rank_rules(
    candidates: list[dict[str, Any]], query: str, ranking: str
) -> tuple[list[dict[str, Any]], dict[str, float]]:
    scores = _bm25_scores(candidates, query, fielded=ranking == "bm25f")
    if ranking == "lexical":
        return candidates, scores
    ranked = [rule for rule in candidates if scores.get(str(rule["ruleId"]), 0.0) > 0.0]
    ranked.sort(key=lambda rule: (-scores[str(rule["ruleId"])], str(rule["ruleId"])))
    return ranked, scores


def _render_rules(
    rules: list[dict[str, Any]], scores: dict[str, float], ranking: str, limit: int
) -> list[dict[str, Any]]:
    rendered = []
    for rule in rules[:limit]:
        item = dict(rule)
        if ranking != "lexical":
            item["retrievalScore"] = scores[str(rule["ruleId"])]
        rendered.append(item)
    return rendered


def search_audit_rules(arguments: object) -> dict[str, object]:
    """Return bounded deterministic lexical/BM25/BM25F results over the index."""
    query, lane, include_cross_cutting, limit, ranking = _validate(arguments)
    inventory = _inventory()
    searchable = _filter_rules(inventory, query, lane, include_cross_cutting, ranking)
    searchable, scores = _rank_rules(searchable, query, ranking)
    result_rules = _render_rules(searchable, scores, ranking, limit)
    index_sha256 = sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    payload = {
        "marker": "MCP_AUDIT_RULE_SEARCH_READ_ONLY",
        "schema": "factory.audit-rule-search.v1",
        "query": query,
        "lane": lane,
        "includeCrossCutting": include_cross_cutting,
        "ranking": ranking,
        "totalMatched": len(searchable),
        "returned": len(result_rules),
        "ruleIndexSha256": index_sha256,
        "rules": result_rules,
        "nextRecommendedStep": (
            "Use the matching rule IDs to select a signed runtime-audit lane plan; execution remains human-controlled through the CLI."
            if result_rules
            else "No matching rules found. Try broader terms or include cross-cutting rules."
        ),
        "action_summary": "Search the bounded six-lane rejection inventory with deterministic lexical or BM25 retrieval without executing an audit or changing a gate.",
        "authority": "none",
        "claim_boundary": "Rule discovery is advisory context only; BM25/BM25F ranks text matches but does not prove semantics, execute, approve, weaken, or release an audit lane.",
    }
    if ranking in {"bm25", "bm25f"}:
        # The handoff is a hash-bound, secret-free request.  It does not call
        # a provider; callers explicitly inject an optional Jev transport.
        from .jev_classifier import build_jev_input

        payload["jevHandoff"] = build_jev_input(payload)
    return payload
