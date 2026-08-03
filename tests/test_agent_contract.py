from __future__ import annotations

from pathlib import Path
import hashlib

import pytest

from factoryline.agent_contract import (
    AgentContractError,
    validate_agent_contract,
    validate_verifier_attestation,
)


def _contract():
    digest = "a" * 64
    return {
        "schema": "factory.agent-contract.v2",
        "id": "planner-v2",
        "role": "planner",
        "context": {"recipe_id": "recipe.plan", "digest": digest, "max_tokens": 12000, "sources": ["spec", "policy"]},
        "model": {"id": "model-balanced", "tier": "balanced", "max_latency_ms": 5000, "max_cost_usd": 0.5, "capabilities": ["json"], "privacy_class": "restricted"},
        "prompt": {"id": "planner", "version": "2", "digest": digest},
        "tools": {"allow": ["read_repo"], "deny": ["network"]},
        "harness": {"context_wall": "isolated", "subagents": [], "permissions": ["read"]},
        "handoff": {"input_schema": "factory.plan.input.v1", "output_schema": "factory.plan.output.v1"},
    }


def test_contract_is_canonical_and_hash_bound(tmp_path: Path):
    result = validate_agent_contract(_contract())
    assert result["markers"] == ["AGENT_CONTRACT_BOUND"]
    assert len(result["contract_digest"]) == 64
    path = tmp_path / "agent.json"
    import json
    path.write_text(json.dumps(result), encoding="utf-8")
    assert validate_agent_contract(path)["contract_digest"] == result["contract_digest"]


@pytest.mark.parametrize("field", ["model", "context", "prompt", "tools", "harness", "handoff"])
def test_contract_rejects_missing_core5_seam(field: str):
    value = _contract()
    value.pop(field)
    with pytest.raises(AgentContractError, match="AGENT_CONTRACT_INVALID"):
        validate_agent_contract(value)


def test_contract_rejects_rails_and_secrets():
    value = _contract()
    value["model"]["max_latency_ms"] = 5001
    with pytest.raises(AgentContractError, match="AGENT_CONTRACT_RAILS_ENFORCED"):
        validate_agent_contract(value)
    value = _contract()
    value["model"]["api_key"] = "secret"
    with pytest.raises(AgentContractError, match="AGENT_CONTRACT_SECRET_FIELD"):
        validate_agent_contract(value)


def test_verifier_attestation_requires_distinct_fresh_isolated_adapter():
    value = {
        "schema": "factory.verifier-attestation.v1",
        "mission_digest": "b" * 64,
        "contract_digest": "c" * 64,
        "creator_id": "creator-1",
        "verifier_id": "verifier-1",
        "verifier_context": ["mission.json", "candidate_diff", "evidence_manifest"],
        "fresh_session": True,
        "context_wall": "isolated",
        "evidence_digest": "d" * 64,
        "adapter_id": "adapter-local",
    }
    result = validate_verifier_attestation(value, mission_digest="b" * 64, contract_digest="c" * 64)
    assert result["markers"] == ["VERIFIER_ADAPTER_ATTESTED"]
    value["verifier_id"] = value["creator_id"]
    with pytest.raises(AgentContractError, match="VERIFIER_IDENTITY_DISTINCT"):
        validate_verifier_attestation(value)
