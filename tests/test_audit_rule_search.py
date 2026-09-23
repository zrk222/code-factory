from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.audit_rule_search import AuditRuleSearchError, search_audit_rules
from factoryline.jev_classifier import (
    JevClassificationError,
    build_jev_input,
    classify_retrieval,
    fuse_advisory_scores,
    normalize_jev_result,
)
from factoryline.mcp import dispatch


def _content(response: dict[str, object]) -> dict[str, object]:
    result = response["result"]
    assert isinstance(result, dict)
    content = result["content"]
    assert isinstance(content, list)
    return json.loads(content[0]["text"])


def test_search_is_bounded_lane_filtered_and_hash_addressed():
    payload = search_audit_rules(
        {
            "query": "tenant isolation",
            "lane": "authorization_tenant_isolation",
            "includeCrossCutting": False,
            "limit": 3,
        }
    )

    assert payload["marker"] == "MCP_AUDIT_RULE_SEARCH_READ_ONLY"
    assert payload["schema"] == "factory.audit-rule-search.v1"
    assert payload["lane"] == "authorization_tenant_isolation"
    assert payload["includeCrossCutting"] is False
    assert 0 <= payload["returned"] <= 3
    assert payload["totalMatched"] >= payload["returned"]
    assert len(payload["ruleIndexSha256"]) == 64
    assert all(
        rule["lane"] == "authorization_tenant_isolation" for rule in payload["rules"]
    )
    assert all(rule["requiredEvidenceTypes"] for rule in payload["rules"])
    assert payload["authority"] == "none"
    assert payload["ranking"] == "bm25f"
    assert all("retrievalScore" in rule for rule in payload["rules"])


def test_bm25_and_bm25f_are_deterministic_and_explainable():
    bm25 = search_audit_rules({"query": "tenant cache isolation", "ranking": "bm25"})
    bm25f = search_audit_rules({"query": "tenant cache isolation", "ranking": "bm25f"})

    assert bm25["ranking"] == "bm25"
    assert bm25f["ranking"] == "bm25f"
    assert (
        bm25["rules"]
        == search_audit_rules({"query": "tenant cache isolation", "ranking": "bm25"})[
            "rules"
        ]
    )
    assert (
        bm25f["rules"]
        == search_audit_rules({"query": "tenant cache isolation", "ranking": "bm25f"})[
            "rules"
        ]
    )
    assert all(rule["retrievalScore"] > 0 for rule in bm25f["rules"])
    assert bm25f["jevHandoff"]["schema"] == "factory.jev-classification-input.v1"
    assert bm25f["jevHandoff"]["authority"] == "none"


def test_jev_fallback_and_typed_transport_are_fail_closed():
    payload = search_audit_rules({"query": "tenant isolation", "ranking": "bm25f"})
    fallback = classify_retrieval(payload)
    assert fallback["label"] == "HUMAN_REVIEW"
    assert fallback["status"] == "FALLBACK"
    assert fallback["releaseDecision"] is False

    request = build_jev_input(payload)
    normalized = normalize_jev_result(
        {
            "label": "RUN_LANE",
            "probability": 0.8,
            "selectedRuleIds": request["candidateRuleIds"][:1],
            "ruleScores": {request["candidateRuleIds"][0]: 0.8},
            "contextSha256": request["contextSha256"],
        },
        request=request,
    )
    assert normalized["status"] == "ADVISORY"

    def transport(value: dict[str, object]) -> dict[str, object]:
        return {
            "label": "TARGETED_REPAIR",
            "probability": 0.91,
            "selectedRuleIds": value["candidateRuleIds"][:1],
            "ruleScores": {value["candidateRuleIds"][0]: 0.91},
            "contextSha256": value["contextSha256"],
            "requestId": "jev-test-1",
        }

    result = classify_retrieval(payload, transport=transport, model_version="test")
    assert result["status"] == "ADVISORY"
    assert result["label"] == "TARGETED_REPAIR"
    assert result["modelVersion"] == "test"
    assert result["contextSha256"] == request["contextSha256"]

    fused = fuse_advisory_scores(payload, result)
    assert fused["ranking"] == "bm25f+jev-advisory"
    assert fused["authority"] == "none"
    assert fused["releaseDecision"] is False
    assert fused["orderedRuleIds"]

    def bad_transport(value: dict[str, object]) -> dict[str, object]:
        return {
            "label": "RUN_LANE",
            "probability": 0.99,
            "selectedRuleIds": ["CF-RULE-NOT-RETRIEVED"],
            "contextSha256": value["contextSha256"],
        }

    bad = classify_retrieval(payload, transport=bad_transport)
    assert bad["status"] == "FALLBACK"
    assert bad["fallbackReason"] == "JevClassificationError"


def test_jev_handoff_rejects_non_ranked_search():
    lexical = search_audit_rules({"query": "tenant", "ranking": "lexical"})
    with pytest.raises(JevClassificationError):
        build_jev_input(lexical)


def test_lexical_mode_preserves_legacy_substring_search():
    payload = search_audit_rules({"query": "e_", "ranking": "lexical", "limit": 2})
    assert payload["ranking"] == "lexical"
    assert all("retrievalScore" not in rule for rule in payload["rules"])


def test_search_inventory_matches_the_six_lane_source_count():
    payload = search_audit_rules({"query": "code factory", "limit": 20})

    assert payload["totalMatched"] == 143
    assert payload["returned"] == 20


def test_search_can_surface_cross_cutting_rules_and_keeps_context_small():
    payload = search_audit_rules({"query": "e_", "limit": 2})

    assert payload["returned"] <= 2
    assert all(
        "rejectionCondition" in rule and "practicalQuestion" in rule
        for rule in payload["rules"]
    )
    if payload["rules"]:
        assert "signed runtime-audit lane plan" in payload["nextRecommendedStep"]


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"query": "tenant", "limit": 0},
        {"query": "tenant", "lane": "not-a-lane"},
        {"query": "tenant", "includeCrossCutting": "yes"},
        {"query": "tenant", "ranking": "neural"},
        {"query": "tenant", "unexpected": True},
    ],
)
def test_search_rejects_ambiguous_or_unsafe_inputs(arguments: dict[str, object]):
    with pytest.raises(AuditRuleSearchError):
        search_audit_rules(arguments)


def test_search_is_exposed_as_read_only_mcp_tool(tmp_path: Path):
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "factory.search_audit_rules",
                "arguments": {"query": "migration", "lane": "migration_data_integrity"},
            },
        },
        tmp_path,
    )
    payload = _content(response)

    assert payload["marker"] == "MCP_AUDIT_RULE_SEARCH_READ_ONLY"
    assert payload["lane"] == "migration_data_integrity"


def test_search_mcp_errors_have_stable_marker(tmp_path: Path):
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "factory.search_audit_rules",
                "arguments": {"query": "tenant", "limit": 99},
            },
        },
        tmp_path,
    )

    assert response["error"]["data"]["marker"] == "MCP_AUDIT_RULE_SEARCH_INVALID"
