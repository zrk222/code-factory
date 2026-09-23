"""Optional Jev-compatible classification for retrieved CF rules.

Jev is deliberately an advisory classifier here.  BM25/BM25F finds the
candidate rules locally; an injected transport may classify that bounded set.
No provider call is made by default, and a missing/invalid provider always
falls back to human review.  The result can never approve, merge, publish,
weaken a gate, or grant credentials.
"""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Callable, Mapping


class JevClassificationError(ValueError):
    """Stable validation error for the optional Jev adapter."""


JEV_LABELS = {
    "NO_MATCH",
    "TARGETED_REPAIR",
    "RUN_LANE",
    "HUMAN_REVIEW",
    "STOP",
}
_MAX_QUERY = 200
_MAX_CANDIDATES = 20


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _candidate_ids(search_payload: Mapping[str, Any]) -> list[str]:
    rules = search_payload.get("rules")
    if not isinstance(rules, list) or len(rules) > _MAX_CANDIDATES:
        raise JevClassificationError("search payload must contain at most 20 rules")
    ids: list[str] = []
    for rule in rules:
        if not isinstance(rule, Mapping) or not isinstance(rule.get("ruleId"), str):
            raise JevClassificationError("search payload contains an invalid rule")
        ids.append(rule["ruleId"])
    return ids


def build_jev_input(search_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Build a secret-free, hash-bound classifier request from a search result."""
    query = search_payload.get("query")
    ranking = search_payload.get("ranking")
    if not isinstance(query, str) or not query or len(query) > _MAX_QUERY:
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
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JevClassificationError(f"{label} must be numeric")
    if not 0.0 <= float(value) <= 1.0:
        raise JevClassificationError(f"{label} must be between 0 and 1")
    return round(float(value), 6)


def _rule_scores(raw: object, allowed: set[str]) -> dict[str, float]:
    if not isinstance(raw, Mapping):
        raise JevClassificationError("ruleScores must be an object")
    normalized: dict[str, float] = {}
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
    normalized_scores = _rule_scores(rule_scores, allowed)
    return {
        "schema": "factory.jev-classification-result.v1",
        "label": label,
        "probability": probability,
        "selectedRuleIds": selected,
        "ruleScores": normalized_scores,
        "modelId": model_id,
        "modelVersion": model_version,
        "requestId": str(raw.get("requestId", "unassigned")),
        "contextSha256": request["contextSha256"],
        "status": "ADVISORY",
        "authority": "none",
        "releaseDecision": False,
        "claimBoundary": "Typed classification is advisory and does not prove semantics or authorize execution.",
    }


def classify_retrieval(
    search_payload: Mapping[str, Any],
    *,
    transport: Callable[[dict[str, Any]], Mapping[str, Any]] | None = None,
    model_id: str = "jev",
    model_version: str = "unspecified",
) -> dict[str, Any]:
    """Classify BM25/BM25F candidates, failing closed when Jev is unavailable."""
    request = build_jev_input(search_payload)
    if transport is None:
        return {
            "schema": "factory.jev-classification-result.v1",
            "label": "HUMAN_REVIEW",
            "probability": 0.0,
            "selectedRuleIds": request["candidateRuleIds"],
            "ruleScores": {},
            "modelId": model_id,
            "modelVersion": model_version,
            "requestId": "unavailable",
            "contextSha256": request["contextSha256"],
            "status": "FALLBACK",
            "fallbackReason": "JEV_UNAVAILABLE",
            "authority": "none",
            "releaseDecision": False,
            "claimBoundary": "Jev is optional; human review is required when the classifier is unavailable.",
        }
    try:
        raw = transport(request)
        return normalize_jev_result(
            raw,
            request=request,
            model_id=model_id,
            model_version=model_version,
        )
    except (
        JevClassificationError,
        OSError,
        TimeoutError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        return {
            "schema": "factory.jev-classification-result.v1",
            "label": "HUMAN_REVIEW",
            "probability": 0.0,
            "selectedRuleIds": request["candidateRuleIds"],
            "ruleScores": {},
            "modelId": model_id,
            "modelVersion": model_version,
            "requestId": "fallback",
            "contextSha256": request["contextSha256"],
            "status": "FALLBACK",
            "fallbackReason": type(exc).__name__,
            "authority": "none",
            "releaseDecision": False,
            "claimBoundary": "Invalid or unavailable Jev output fails closed to human review.",
        }


def fuse_advisory_scores(
    search_payload: Mapping[str, Any],
    classification: Mapping[str, Any],
    *,
    local_weight: float = 0.7,
    jev_weight: float = 0.3,
) -> dict[str, Any]:
    """Fuse local BM25/BM25F scores with optional Jev per-rule scores.

    Local relevance stays dominant, weights must sum to one, and missing Jev
    scores leave local ordering unchanged. The result is advisory only.
    """
    _validate_weights(local_weight, jev_weight)
    rules = search_payload.get("rules")
    if not isinstance(rules, list):
        raise JevClassificationError("search payload rules are required")
    raw_jev_scores = classification.get("ruleScores", {})
    if not isinstance(raw_jev_scores, Mapping):
        raise JevClassificationError("classification ruleScores must be an object")
    ranked = [
        _fused_rule_score(rule, raw_jev_scores, local_weight, jev_weight)
        for rule in rules
    ]
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return {
        "schema": "factory.jev-bm25-score-fusion.v1",
        "ranking": "bm25f+jev-advisory",
        "localWeight": float(local_weight),
        "jevWeight": float(jev_weight),
        "orderedRuleIds": [rule_id for _, rule_id in ranked],
        "scores": {rule_id: score for score, rule_id in ranked},
        "authority": "none",
        "releaseDecision": False,
        "claimBoundary": "Score fusion only changes advisory ordering; CF deterministic gates remain authoritative.",
    }


def _validate_weights(local_weight: object, jev_weight: object) -> None:
    if (
        isinstance(local_weight, bool)
        or isinstance(jev_weight, bool)
        or not isinstance(local_weight, (int, float))
        or not isinstance(jev_weight, (int, float))
        or local_weight < 0
        or jev_weight < 0
        or abs(float(local_weight) + float(jev_weight) - 1.0) > 1e-9
    ):
        raise JevClassificationError("score weights must be non-negative and sum to 1")


def _fused_rule_score(
    rule: object,
    jev_scores: Mapping[str, Any],
    local_weight: float,
    jev_weight: float,
) -> tuple[float, str]:
    if not isinstance(rule, Mapping) or not isinstance(rule.get("ruleId"), str):
        raise JevClassificationError("search payload contains an invalid rule")
    local = rule.get("retrievalScore", 0.0)
    if isinstance(local, bool) or not isinstance(local, (int, float)):
        raise JevClassificationError("local retrievalScore must be numeric")
    local_score = max(0.0, min(1.0, float(local) / 10.0))
    jev_score = jev_scores.get(rule["ruleId"])
    if jev_score is None:
        fused = local_score
    else:
        fused = float(local_weight) * local_score + float(jev_weight) * _probability(
            jev_score, "Jev rule score"
        )
    return round(fused, 8), str(rule["ruleId"])
