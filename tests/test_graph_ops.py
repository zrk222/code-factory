from __future__ import annotations

import json
from pathlib import Path

from factoryline.cli import main
from factoryline.graph_ops import GRAPH_OPS_SCHEMA, graph_ops_html, graph_ops_impact, graph_ops_snapshot
from factoryline.product_missions import close_mission
from factoryline.proof_reuse import record_proof
from factoryline.run_admission import prepare_admission


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
    assert "Proof observatory" in page
    assert "Evidence health" in page
    assert "health-donut" in page
    assert "renderObservatory" in page
    assert 'const endpoint="/api/graph-ops"' in page
    assert '"X-Factory-Studio-Token":sessionToken' in page
    assert 'id="graph-refresh"' in page
    assert 'id="graph-stop"' in page
    assert "setInterval(()=>{if(graphAutoRefresh)load();},1000)" in page
    assert "Memory Spine · proof-aware briefing" in page
    assert "Turn the diff into the next safe proof." in page
    assert 'id="memory-refresh"' in page
    assert 'id="team-refresh"' in page
    assert 'id="memory-auto-refresh"' in page
    assert 'id="memory-actions"' in page
    assert 'id="team-seats"' in page
    assert 'fetch("/api/developer-memory"' in page
    assert "renderDeveloperMemory(payload)" in page
    assert "Observed project contributors" in page
    assert "not a verified identity-provider or billing-seat roster" in page
    assert "setInterval(()=>{if(memoryAutoRefresh)loadDeveloperMemory();},5000)" in page
    assert "textContent" in page
    assert "innerHTML" not in page
    assert "@media (max-width:768px)" in page
    assert "Read-only inspection." in page
    assert "Verified semantic time travel" in page
    assert 'id="forensics-panel"' in page
    assert 'id="prepare-recovery"' in page
    assert 'id="validate-recovery"' in page
    assert 'id="execute-recovery"' in page
    assert "Execute approved recovery" in page
    assert "disabled aria-describedby=\"execution-lock\"" in page
    assert "recovery.execute===false" in page
    assert "ProofSearch · Counterfactual Arena" in page
    assert 'id="candidate-arena"' in page
    assert 'id="copy-proofsearch"' in page
    assert 'id="export-proofsearch"' in page
    assert 'id="validate-proofsearch"' in page
    assert 'id="apply-proofsearch"' in page
    assert "Apply verified repair" in page
    assert 'facts.apply===false' in page
    assert "Not measured" in page
    assert "Evidence Frontier · proof-guided loop" in page
    assert 'id="frontier-cards"' in page
    assert 'id="copy-frontier"' in page
    assert 'id="export-frontier"' in page
    assert 'id="validate-frontier"' in page
    assert 'id="run-frontier"' in page
    assert "Run next experiment" in page
    assert "execution_allowed===false" in page
    assert '"reality_check"' in page
    assert 'id="authorization-title"' in page
    assert 'id="authorize-selected"' in page
    assert 'id="run-authorized-reality"' in page
    assert '"/api/graph-ops-authorize"' in page
    assert '"/api/graph-ops-run"' in page
    assert "AUTHORIZE ${id}" in page
    assert "Portfolio Flight Plan" in page
    assert "Safe parallel waves" in page
    assert 'id="portfolio-run-wave"' in page
    assert 'id="portfolio-authorize-harness"' in page
    assert "GRAPH_OPS_PORTFOLIO_ADMISSION_READ_ONLY" in page
    assert "renderPortfolio(payload)" in page
    assert "Graph Ops cannot execute a wave" in page


def test_graph_ops_projects_sealed_admission_without_changing_its_base_graph(tmp_path: Path):
    from test_run_admission import _passport, _request

    before = graph_ops_snapshot(tmp_path)
    packet = prepare_admission(tmp_path, _passport(tmp_path), _request(tmp_path))
    after = graph_ops_snapshot(tmp_path)

    assert after["base_graph_sha256"] == before["base_graph_sha256"]
    assert after["graph_sha256"] != before["graph_sha256"]
    assert "GRAPH_OPS_PORTFOLIO_ADMISSION_READ_ONLY" in after["markers"]
    assert after["portfolio"]["authority"]["execution"] is False
    assert after["admissions"] == {"count": 1, "sealed_count": 1, "invalid_count": 0}
    node = next(item for item in after["nodes"] if item["kind"] == "admission")
    assert node["facts"]["packet_sha256"] == packet["packet_sha256"]


def test_graph_ops_exposes_verified_proofsearch_winner_and_candidate_controls(tmp_path: Path):
    from test_proofsearch import _candidate, _plan, _request
    from factoryline.proofsearch import evaluate_proofsearch

    plan = _plan(tmp_path)
    request = _request(tmp_path, plan, [
        _candidate(tmp_path, "winner", risk=2, lines=8),
        _candidate(tmp_path, "larger", risk=9, lines=40),
    ])
    evaluation = tmp_path / ".factory" / "proofsearch" / "demo.evaluation.json"
    evaluate_proofsearch(tmp_path, request, evaluation)

    snapshot = graph_ops_snapshot(tmp_path)

    assert snapshot["facts"]["proofsearch_evaluation_count"] == 1
    assert snapshot["facts"]["proofsearch_candidate_count"] == 2
    assert snapshot["facts"]["proofsearch_winner_count"] == 1
    assert snapshot["recommendation"]["action"] == "review_verified_repair"
    assert "GRAPH_OPS_PROOFSEARCH_ARENA" in snapshot["markers"]
    assert "GRAPH_OPS_VERIFIED_REPAIR_LOCKED" in snapshot["markers"]
    winner = next(node for node in snapshot["nodes"] if node["kind"] == "repair_candidate" and node["status"] == "winner")
    assert winner["label"] == "winner"
    decision = next(node for node in snapshot["nodes"] if node["kind"] == "proofsearch")
    assert decision["facts"]["apply"] is False
    assert all(value is False for value in decision["facts"]["authority"].values())


def test_graph_ops_projects_a_verified_evidence_frontier_without_execution(tmp_path: Path):
    from test_evidence_frontier import _evaluation, _experiment, _request
    from factoryline.evidence_frontier import plan_evidence_frontier

    evaluation = _evaluation(tmp_path)
    request = _request(tmp_path, evaluation, [
        _experiment("targeted", {"repair-a": "pass", "repair-b": "fail", "repair-c": "fail"}, root=tmp_path),
    ])
    frontier = tmp_path / ".factory" / "proofsearch" / "comparison.frontier.json"
    plan_evidence_frontier(tmp_path, request, frontier)

    snapshot = graph_ops_snapshot(tmp_path)

    assert snapshot["facts"]["evidence_frontier_count"] == 1
    assert snapshot["facts"]["evidence_frontier_ready_count"] == 1
    assert snapshot["recommendation"]["action"] == "review_evidence_frontier"
    assert "GRAPH_OPS_EVIDENCE_FRONTIER_READ_ONLY" in snapshot["markers"]
    decision = next(node for node in snapshot["nodes"] if node["kind"] == "evidence_frontier")
    assert decision["facts"]["next_experiment"] == "targeted"
    assert all(value is False for value in decision["facts"]["authority"].values())
    experiment = next(node for node in snapshot["nodes"] if node["kind"] == "evidence_experiment")
    assert experiment["status"] == "next"
    assert experiment["facts"]["execution_allowed"] is False


def test_graph_ops_projects_a_supervised_reality_check_without_rerunning_it(tmp_path: Path):
    from test_reality_check import _write
    from factoryline.reality_check import run_reality_check

    receipt = run_reality_check(tmp_path, _write(tmp_path))
    directory = tmp_path / ".factory" / "reality"; directory.mkdir(parents=True)
    (directory / "approval.reality.json").write_text(json.dumps(receipt), encoding="utf-8")

    snapshot = graph_ops_snapshot(tmp_path)

    assert snapshot["facts"]["reality_check_count"] == 1
    assert snapshot["facts"]["reality_check_verified_count"] == 1
    assert "GRAPH_OPS_REALITY_CHECK_SUPERVISED" in snapshot["markers"]
    node = next(node for node in snapshot["nodes"] if node["kind"] == "reality_check")
    assert node["status"] == "verified"
    assert node["facts"]["promise"] == "A manager can approve a request."


def test_graph_ops_projects_counterexamples_guardrails_and_temporal_resilience_read_only(tmp_path: Path):
    from test_counterexample import _source as counterexample_source
    from test_guardrails import _manifest as guardrail_manifest, _principal as guardrail_principal, _store as guardrail_store
    from test_resilience import _steps as resilience_steps, _write_lineage
    from factoryline.counterexample import compile_counterexample_plan, write_counterexample_plan
    from factoryline.guardrails import evaluate_guardrails
    from factoryline.resilience import compile_temporal_resilience_plan, write_temporal_resilience_plan

    source = tmp_path / "specs" / "checkout.counterexamples.json"
    source.parent.mkdir()
    source.write_text(json.dumps(counterexample_source()), encoding="utf-8")
    counterexample_out = tmp_path / ".factory" / "counterexamples" / "checkout.json"
    write_counterexample_plan(compile_counterexample_plan(tmp_path, source), counterexample_out)

    db = tmp_path / "continuity.sqlite3"
    guardrail_store(db)
    manifest = guardrail_manifest(tmp_path / "guardrails.json")
    evaluation = evaluate_guardrails(manifest, db, guardrail_principal("reader", ("reader",)), changed_paths=["src/checkout/submit.py"])
    guardrail_out = tmp_path / ".factory" / "guardrails" / "checkout.json"
    guardrail_out.parent.mkdir(parents=True)
    guardrail_out.write_text(json.dumps(evaluation), encoding="utf-8")

    lineage = _write_lineage(tmp_path / ".factory" / "graph-runs" / "checkout.lineage.json", resilience_steps())
    resilience_out = tmp_path / ".factory" / "resilience" / "checkout.json"
    write_temporal_resilience_plan(compile_temporal_resilience_plan(tmp_path, lineage), resilience_out)
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    snapshot = graph_ops_snapshot(tmp_path)
    after = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    assert before == after
    assert {"counterexample_plan", "guardrail_evaluation", "temporal_resilience"} <= {node["kind"] for node in snapshot["nodes"]}
    assert snapshot["facts"]["counterexample_verified_count"] == 1
    assert snapshot["facts"]["guardrail_active_count"] == 1
    assert snapshot["facts"]["guardrail_withheld_count"] == 1
    assert snapshot["facts"]["temporal_resilience_verified_count"] == 1
    assert {
        "GRAPH_OPS_COUNTEREXAMPLE_PROOFS_READ_ONLY",
        "GRAPH_OPS_GUARDRAIL_EVALUATIONS_REDACTED",
        "GRAPH_OPS_TEMPORAL_RESILIENCE_READ_ONLY",
    } <= set(snapshot["markers"])
