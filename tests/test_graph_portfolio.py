from __future__ import annotations

import json

from factoryline.cli import main
from factoryline.graph_portfolio import GRAPH_PORTFOLIO_SCHEMA, graph_portfolio_plan


def _snapshot(*, cycle: bool = False, complete: bool = True):
    edges = [
        {"source": "slice:a", "target": "slice:b", "relation": "depends_on"},
        {"source": "slice:a", "target": "slice:c", "relation": "depends_on"},
    ]
    if cycle:
        edges.append({"source": "slice:c", "target": "slice:a", "relation": "depends_on"})
    return {
        "complete": complete,
        "graph_sha256": "a" * 64,
        "nodes": [
            {"id": "slice:a", "kind": "slice", "status": "unknown"},
            {"id": "slice:b", "kind": "slice", "status": "current"},
            {"id": "slice:c", "kind": "slice", "status": "stale"},
        ],
        "edges": edges,
    }


def test_portfolio_returns_stable_structural_plan_and_shared_candidate():
    first = graph_portfolio_plan(_snapshot())
    second = graph_portfolio_plan(_snapshot())

    assert first["schema"] == GRAPH_PORTFOLIO_SCHEMA
    assert first["portfolio_sha256"] == second["portfolio_sha256"]
    assert first["verdict"] == "READY"
    assert first["critical_path"] == ["slice:a", "slice:b"]
    assert [item["node_id"] for item in first["shared_candidates"]] == ["slice:a"]
    assert [item["node_id"] for item in first["workset"]] == ["slice:a", "slice:b", "slice:c"]
    assert first["workset"][1]["disposition"] == "REUSE_CANDIDATE"
    assert first["quantitative"]["critical_path_ms"] is None
    assert first["quantitative"]["time_saved_ms"] is None
    assert first["parallel_waves"] == [
        {"index": 1, "node_ids": ["slice:a"], "authority": "proposal_only"},
        {"index": 2, "node_ids": ["slice:b", "slice:c"], "authority": "proposal_only"},
    ]
    assert all(value is False for value in first["authority"].values())


def test_portfolio_uses_only_complete_valid_duration_sets_and_never_claims_savings():
    plan = graph_portfolio_plan(_snapshot(), {"slice:a": 10, "slice:b": 20, "slice:c": 7})
    invalid = graph_portfolio_plan(_snapshot(), {"slice:a": 10})

    assert plan["quantitative"]["durations_measured"] is True
    assert plan["quantitative"]["critical_path_ms"] == 30
    assert plan["quantitative"]["time_saved_ms"] is None
    assert invalid["quantitative"]["durations_measured"] is False


def test_portfolio_blocks_cycle_and_incomplete_snapshot_without_workset():
    cycle = graph_portfolio_plan(_snapshot(cycle=True))
    incomplete = graph_portfolio_plan(_snapshot(complete=False))

    assert cycle["markers"] == ["GRAPH_PORTFOLIO_CYCLE_BLOCKED"]
    assert cycle["cycles"] == [["slice:a", "slice:c"]]
    assert cycle["workset"] == []
    assert incomplete["markers"] == ["GRAPH_PORTFOLIO_GRAPH_INCOMPLETE"]
    assert incomplete["workset"] == []


def test_portfolio_propagates_root_blocker_without_scheduling_descendants():
    snapshot = _snapshot()
    snapshot["nodes"][0]["status"] = "blocked"

    plan = graph_portfolio_plan(snapshot)

    assert [item["disposition"] for item in plan["workset"]] == ["BLOCK", "BLOCK", "BLOCK"]
    assert plan["workset"][1]["blocked_by"] == ["slice:a"]
    assert plan["parallel_waves"] == []


def test_graph_portfolio_cli_is_machine_readable_and_never_executes(tmp_path, capsys):
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    code = main(["graph", "portfolio", "--root", str(tmp_path), "--json"])

    payload = json.loads(capsys.readouterr().out)
    after = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert code == 0
    assert payload["cli_marker"] == "GRAPH_PORTFOLIO_CLI_READ_ONLY"
    assert all(value is False for value in payload["authority"].values())
    assert before == after
