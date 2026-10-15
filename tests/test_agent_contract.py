from __future__ import annotations

from pathlib import Path
import json
from hashlib import sha256

import pytest

from factoryline.agent_contract import (
    AgentContractError,
    validate_agent_contract,
    validate_verifier_attestation,
)


def test_trace_evaluation_native_mcp_and_current_dashboard_projection(tmp_path):
    from test_analysis_evidence import _span_fixture
    from factoryline.mcp import dispatch
    from factoryline.analysis_evidence import trace_evaluation_status
    from factoryline.runtime_audit_common import canonical_bytes

    request, _ = _span_fixture(tmp_path)
    raw = canonical_bytes(request)
    (tmp_path / "request.json").write_bytes(raw)
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "factory.evaluate_trace",
                "arguments": {
                    "request_path": "request.json",
                    "request_sha256": sha256(raw).hexdigest(),
                    "kind": "spans",
                },
            },
        },
        tmp_path,
    )
    result = json.loads(response["result"]["content"][0]["text"])
    assert result["state"] == "PASS"
    assert result["authority"] == "none"
    receipt = canonical_bytes(result)
    (tmp_path / "evaluation.json").write_bytes(receipt)
    directory = tmp_path / ".factory" / "trace-evaluation"
    directory.mkdir(parents=True)
    manifest = {
        "schema": "factory.trace-evaluation-manifest.v1",
        "kind": "spans",
        "request": {"path": "request.json", "sha256": sha256(raw).hexdigest()},
        "receipt": {"path": "evaluation.json", "sha256": sha256(receipt).hexdigest()},
    }
    (directory / "latest.json").write_bytes(canonical_bytes(manifest))
    projection = trace_evaluation_status(tmp_path)
    assert projection["state"] == "PASS"
    assert projection["metrics"]["span_count"] == 1
    assert projection["metrics"]["actual_cost_usd"] is None
    (tmp_path / "src" / "sample.py").write_text("VALUE = 2\n")
    stale = trace_evaluation_status(tmp_path)
    assert stale["state"] == "INCOMPLETE"
    assert stale["metrics"] == {}


def test_trace_evaluation_ui_and_junie_preserve_unknowns_and_boundaries(tmp_path):
    from factoryline.studio import _studio_html
    from factoryline.analysis_evidence import trace_evaluation_status

    assert trace_evaluation_status(tmp_path)["state"] == "MISSING"
    html = _studio_html("local-test-token")
    assert "Trace evaluation: evidence and gaps" in html
    assert "renderTraceEvaluation(payload.trace_evaluation)" in html
    assert "renderTraceEvaluation({state:'UNAVAILABLE',metrics:{}" in html
    manifest = json.loads(
        (Path(__file__).parents[1] / "factoryline/data/junie_pack.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["trace_evaluation"]["native_tool"] == "factory.evaluate_trace"
    assert (
        "cannot clear deterministic failures" in manifest["trace_evaluation"]["limits"]
    )


def _contract():
    digest = "a" * 64
    return {
        "schema": "factory.agent-contract.v2",
        "id": "planner-v2",
        "role": "planner",
        "context": {
            "recipe_id": "recipe.plan",
            "digest": digest,
            "max_tokens": 12000,
            "sources": ["spec", "policy"],
        },
        "model": {
            "id": "model-balanced",
            "tier": "balanced",
            "max_latency_ms": 5000,
            "max_cost_usd": 0.5,
            "capabilities": ["json"],
            "privacy_class": "restricted",
        },
        "prompt": {"id": "planner", "version": "2", "digest": digest},
        "tools": {"allow": ["read_repo"], "deny": ["network"]},
        "harness": {
            "context_wall": "isolated",
            "subagents": [],
            "permissions": ["read"],
        },
        "handoff": {
            "input_schema": "factory.plan.input.v1",
            "output_schema": "factory.plan.output.v1",
        },
    }


def test_contract_is_canonical_and_hash_bound(tmp_path: Path):
    result = validate_agent_contract(_contract())
    assert result["markers"] == ["AGENT_CONTRACT_BOUND"]
    assert len(result["contract_digest"]) == 64
    path = tmp_path / "agent.json"
    import json

    path.write_text(json.dumps(result), encoding="utf-8")
    assert validate_agent_contract(path)["contract_digest"] == result["contract_digest"]


@pytest.mark.parametrize(
    "field", ["model", "context", "prompt", "tools", "harness", "handoff"]
)
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
    result = validate_verifier_attestation(
        value, mission_digest="b" * 64, contract_digest="c" * 64
    )
    assert result["markers"] == ["VERIFIER_ADAPTER_ATTESTED"]
    value["verifier_id"] = value["creator_id"]
    with pytest.raises(AgentContractError, match="VERIFIER_IDENTITY_DISTINCT"):
        validate_verifier_attestation(value)


def test_studio_journey_ui_and_junie_exact_action_boundaries():
    from factoryline.studio import _studio_html

    html = _studio_html("local-test-token")
    assert "Check current stages" in html
    assert "Review build command" in html
    assert "Review verification command" in html
    assert "Run separately approved repair" in html
    assert "plan_sha256:plan.plan_sha256" in html
    assert "command_index:Number(command.value)" in html
    assert "frame.setAttribute('sandbox','allow-scripts')" in html
    assert "frame.setAttribute('referrerpolicy','no-referrer')" in html
    assert "if(frame){frame.remove();frame=null;}" in html
    assert "Agent connection details (your coding agent supplies these)" in html
    manifest = json.loads(
        (Path(__file__).parents[1] / "factoryline/data/junie_pack.json").read_text(
            encoding="utf-8"
        )
    )
    actions = manifest["beginner_acceptance_workflow"]["studio_actions"]
    assert actions["endpoint"] == "/api/journey"
    assert actions["actions"] == ["status", "plan", "execute", "preview", "repair"]
    assert "A passing command is not an application verdict" in actions["limits"]


def test_studio_journey_wrapper_rejects_missing_locator_and_preserves_backend_result(
    tmp_path, monkeypatch
):
    from factoryline.studio import journey_from_studio, StudioRequestError
    from factoryline import app_builder

    with pytest.raises(StudioRequestError, match="JOURNEY_REQUEST_INVALID"):
        journey_from_studio(tmp_path, {"action": "execute"})
    calls = []

    def backend(root, payload):
        calls.append(payload)
        return {"stage": "verification", "ok": False, "cleanup_confirmed": True}

    monkeypatch.setattr(app_builder, "studio_journey", backend)
    request = {"action": "status", "binding_path": "bound.json", "owner": "owner"}
    assert journey_from_studio(tmp_path, request)["ok"] is False
    assert calls == [request]
