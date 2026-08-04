from __future__ import annotations

import json
from pathlib import Path

from factoryline.cli import main
from factoryline.graph_ops import GRAPH_OPS_SCHEMA, graph_ops_html, graph_ops_impact, graph_ops_snapshot
from factoryline.product_missions import close_mission
from factoryline.proof_reuse import record_proof


def _completed_mission(tmp_path: Path):
    from test_product_missions import _pipeline, _validation_for

    graph, slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = tmp_path / "validation.json"
    validation.write_text(json.dumps(_validation_for(mission, "builder", "verifier", evidence)), encoding="utf-8")
    completion = close_mission(Path(mission["path"]), validation, tmp_path)
    return graph, slices, mission, completion


def test_graph_ops_links_local_product_mission_and_valid_completion_exactly(tmp_path: Path):
    graph, slices, mission, _completion = _completed_mission(tmp_path)

    first = graph_ops_snapshot(tmp_path)
    second = graph_ops_snapshot(tmp_path)

    assert first["schema"] == GRAPH_OPS_SCHEMA
    assert first["graph_sha256"] == second["graph_sha256"]
    assert first["authority"] == {
        "execution": False, "approval": False, "publication": False, "deployment": False,
        "signing": False, "messaging": False, "credential": False, "connector": False,
    }
    assert "GRAPH_OPS_UNIFIED_READ_ONLY" in first["markers"]
    assert "GRAPH_OPS_SLICE_LINKS_EXACT" in first["markers"]
    assert "GRAPH_OPS_MISSION_EVIDENCE_LINKED" in first["markers"]
    kinds = {node["kind"] for node in first["nodes"]}
    assert {"product", "requirement", "slice", "mission", "completion"} <= kinds

    edges = {(edge["source"], edge["target"], edge["relation"]) for edge in first["edges"]}
    project = graph["project"]
    selected_requirements = mission["slice"]["requirement_ids"]
    completion_id = f"completion:{mission['id']}"
    for requirement_id in selected_requirements:
        assert (completion_id, f"requirement:{project}:{requirement_id}", "verifies") in edges
    for item in slices["slices"]:
        current = f"slice:{project}:{item['id']}"
        for dependency in item["depends_on"]:
            assert (f"slice:{project}:{dependency}", current, "depends_on") in edges


def test_graph_ops_marks_stale_proof_and_prioritizes_rerun_without_execution(tmp_path: Path):
    input_file = tmp_path / "input.txt"
    output_file = tmp_path / "output.txt"
    input_file.write_text("before", encoding="utf-8")
    output_file.write_text("green", encoding="utf-8")
    receipt = record_proof(tmp_path, {
        "name": "unit", "command": ["python", "-m", "pytest"], "read_only": True,
        "inputs": ["input.txt"], "outputs": ["output.txt"],
    }, elapsed_ms=50)
    plan_dir = tmp_path / ".factory" / "proof-plans"
    plan_dir.mkdir(parents=True)
    (plan_dir / "unit.json").write_text(json.dumps({
        "schema": "factory.proof-plan.v1",
        "items": [{"gate": "unit", "proof_key": receipt["proof_key"], "disposition": "RUN", "reason": "changed input"}],
    }), encoding="utf-8")
    input_file.write_text("after", encoding="utf-8")

    snapshot = graph_ops_snapshot(tmp_path)

    proof = next(node for node in snapshot["nodes"] if node["id"] == f"proof:{receipt['proof_key']}")
    assert proof["status"] == "stale"
    assert snapshot["facts"]["stale_proof_count"] == 1
    assert snapshot["recommendation"]["action"] == "rerun_invalid_proof"
    assert "GRAPH_OPS_PROOF_HASH_STATUS" in snapshot["markers"]


def test_graph_ops_impact_maps_only_explicit_changed_input_edges_to_stale_reruns(tmp_path: Path, capsys):
    input_file = tmp_path / "input.txt"
    output_file = tmp_path / "output.txt"
    unrelated = tmp_path / "unrelated.txt"
    input_file.write_text("before", encoding="utf-8")
    output_file.write_text("green", encoding="utf-8")
    unrelated.write_text("unchanged", encoding="utf-8")
    receipt = record_proof(tmp_path, {
        "name": "unit", "command": ["python", "-m", "pytest"], "read_only": True,
        "inputs": ["input.txt"], "outputs": ["output.txt"],
    }, elapsed_ms=50)
    plan_dir = tmp_path / ".factory" / "proof-plans"
    plan_dir.mkdir(parents=True)
    (plan_dir / "unit.json").write_text(json.dumps({
        "schema": "factory.proof-plan.v1",
        "items": [{"gate": "unit", "proof_key": receipt["proof_key"], "disposition": "RUN", "reason": "changed input"}],
    }), encoding="utf-8")
    input_file.write_text("after", encoding="utf-8")

    impact = graph_ops_impact(tmp_path, ["input.txt", "unrelated.txt"])

    assert impact["marker"] == "GRAPH_OPS_IMPACT_EXACT"
    assert [item["proof_id"] for item in impact["matched_proofs"]] == [f"proof:{receipt['proof_key']}"]
    assert [item["proof_id"] for item in impact["rerun_proofs"]] == [f"proof:{receipt['proof_key']}"]
    assert impact["verified_current_proofs"] == []
    assert impact["matched_proofs"][0]["gates"] == ["unit"]
    assert impact["unmatched_changed_paths"] == ["unrelated.txt"]
    assert all(value is False for value in impact["authority"].values())

    code = main(["graph", "impact", "--root", str(tmp_path), "--changed", "input.txt", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["impact_sha256"] == graph_ops_impact(tmp_path, ["input.txt"])["impact_sha256"]


def test_graph_ops_reports_compact_error_for_malformed_json(tmp_path: Path):
    proof_dir = tmp_path / ".factory" / "proofs"
    proof_dir.mkdir(parents=True)
    (proof_dir / "broken.json").write_text("{", encoding="utf-8")

    snapshot = graph_ops_snapshot(tmp_path)

    assert snapshot["complete"] is False
    assert snapshot["source_errors"] == [{"source": ".factory/proofs/broken.json", "code": "SOURCE_UNREADABLE"}]


def test_graph_ops_exposes_declared_gate_state_without_running_commands(tmp_path: Path):
    plan_dir = tmp_path / ".factory" / "proof-plans"
    plan_dir.mkdir(parents=True)
    (plan_dir / "blocked.json").write_text(json.dumps({
        "schema": "factory.proof-plan.v1",
        "items": [{"gate": "integration", "proof_key": "a" * 64, "disposition": "BLOCK", "reason": "not read-only"}],
    }), encoding="utf-8")

    snapshot = graph_ops_snapshot(tmp_path)

    gate = next(node for node in snapshot["nodes"] if node["kind"] == "gate")
    assert gate["status"] == "BLOCK"
    assert snapshot["recommendation"]["action"] == "resolve_blocked_gate"
    assert "GRAPH_OPS_DECLARED_GATE_STATE" in snapshot["markers"]


def test_graph_ops_returns_partial_graph_for_oversized_artifact(tmp_path: Path):
    proof_dir = tmp_path / ".factory" / "proofs"
    proof_dir.mkdir(parents=True)
    (proof_dir / "too-large.json").write_bytes(b"x" * 1_048_577)

    snapshot = graph_ops_snapshot(tmp_path)

    assert snapshot["complete"] is False
    assert "GRAPH_OPS_PARTIAL_RESULT" in snapshot["markers"]
    assert snapshot["source_errors"][0]["code"] == "SOURCE_TOO_LARGE"


def test_graph_ops_cli_is_read_only_and_machine_readable(tmp_path: Path, capsys):
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    code = main(["graph", "ops", "--root", str(tmp_path), "--json"])

    payload = json.loads(capsys.readouterr().out)
    after = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert code == 0
    assert payload["cli_marker"] == "GRAPH_OPS_CLI_READ_ONLY"
    assert payload["recommendation"]["action"] == "initialize_graph"
    assert before == after


def test_graph_ops_visual_template_is_accessible_and_uses_text_nodes_only():
    page = graph_ops_html("session-token")

    assert "GRAPH_OPS_VISUAL_ACCESSIBLE" in page
    assert "GRAPH_OPS_TEXT_NODE_RENDERING" in page
    assert 'const endpoint="/api/graph-ops"' in page
    assert '"X-Factory-Studio-Token":sessionToken' in page
    assert "textContent" in page
    assert "innerHTML" not in page
    assert "@media (max-width:768px)" in page
    assert "Read-only inspection." in page
