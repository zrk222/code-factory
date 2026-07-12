from __future__ import annotations

import sys

import pytest

from factoryline.assurance import (
    AssuranceError,
    GateNode,
    RiskDAG,
    build_cyclonedx_sbom,
    build_evidence_graph,
    build_vex,
    private_challenge_manifest,
    run_constrained,
    verify_policy_mutations,
)


def _records():
    return [
        {"evidence_id": "root", "tenant_id": "acme", "stage": "strict", "verdict": "VERIFIED", "parent_ids": []},
        {"evidence_id": "child", "tenant_id": "acme", "stage": "compile", "verdict": "VERIFIED", "parent_ids": ["root"]},
    ]


def test_evidence_graph_is_deterministic_and_rejects_cycles():
    first = build_evidence_graph(_records(), tenant_id="acme")
    second = build_evidence_graph(list(reversed(_records())), tenant_id="acme")
    assert first["graph_sha256"] == second["graph_sha256"]
    assert first["roots"] == ["root"] and first["heads"] == ["child"]
    cyclic = [
        {"evidence_id": "a", "tenant_id": "acme", "parent_ids": ["b"]},
        {"evidence_id": "b", "tenant_id": "acme", "parent_ids": ["a"]},
    ]
    with pytest.raises(AssuranceError) as error:
        build_evidence_graph(cyclic, tenant_id="acme")
    assert error.value.code == "E_GRAPH_CYCLE"


def test_risk_dag_selects_impacted_gates_and_dependencies():
    dag = RiskDAG([
        GateNode("contract", 5, paths=("factoryline/",)),
        GateNode("tests", 3, depends_on=("contract",), paths=("tests/",)),
        GateNode("docs", 1, paths=("docs/",)),
    ])
    plan = dag.plan(["tests/test_api.py"], minimum_risk=3)
    assert plan["selected"] == ["contract", "tests"]
    with pytest.raises(AssuranceError) as error:
        RiskDAG([GateNode("a", 1, depends_on=("b",)), GateNode("b", 1, depends_on=("a",))])
    assert error.value.code == "E_DAG_CYCLE"


def test_runner_contains_cwd_and_reports_process_boundary(tmp_path):
    result = run_constrained([sys.executable, "-c", "print('ok')"], root=tmp_path)
    assert result["ok"] is True
    assert result["isolation"] == "process-boundary"
    with pytest.raises(AssuranceError) as error:
        run_constrained([sys.executable, "-c", "print('no')"], root=tmp_path, cwd="..")
    assert error.value.code == "E_RUNNER_CWD"


def test_sbom_and_vex_are_sorted_and_hashed():
    sbom = build_cyclonedx_sbom([
        {"name": "z", "version": "1"},
        {"name": "a", "version": "2"},
    ])
    assert [item["name"] for item in sbom["components"]] == ["a", "z"]
    assert sbom["bom_sha256"]
    vex = build_vex([{"vulnerability": "CVE-1", "component": "a", "status": "not_affected"}])
    assert vex["entries"][0]["status"] == "not_affected"


def test_policy_mutation_challenge_detects_hollow_policy_and_private_manifest_hides_payload():
    policy = {"rules": [{"id": "tests", "required": True}, {"id": "review", "required": True}]}
    result = verify_policy_mutations(policy, lambda value: len(value["rules"]) == 2 and all(rule.get("required") for rule in value["rules"]))
    assert result["status"] == "VERIFIED"
    hollow = verify_policy_mutations(policy, lambda value: True)
    assert hollow["status"] == "HOLLOW_POLICY"
    manifest = private_challenge_manifest("private", [{"input": "secret"}], tenant_id="acme")
    assert "secret" not in str(manifest)
    assert manifest["challenge_count"] == 1
