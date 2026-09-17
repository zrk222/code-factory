from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.audit_rule_search import AuditRuleSearchError, search_audit_rules
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


def test_search_inventory_matches_the_six_lane_source_count():
    payload = search_audit_rules({"query": "code factory", "limit": 20})

    assert payload["totalMatched"] == 140
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
