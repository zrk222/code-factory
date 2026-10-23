from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest
from factoryline.graph_authorization import (
    GraphAuthorizationError,
    create_graph_authorization,
    run_authorized_reality_check,
    validate_graph_authorization,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.reality_check import run_reality_check, write_reality_check_artifacts
from factoryline.cli import main
from factoryline.graph_portfolio import GRAPH_PORTFOLIO_SCHEMA, graph_portfolio_plan


def _prepared_reality(root: Path) -> str:
    from test_first_lap import _write

    receipt = run_reality_check(root, _write(root))
    write_reality_check_artifacts(receipt, root / ".factory" / "reality")
    return next(
        node["id"]
        for node in graph_ops_snapshot(root)["nodes"]
        if node["kind"] == "reality_check"
    )


def _payload(node_id: str, *, authorization_id: str = "run-approval") -> dict[str, str]:
    return {
        "action": "reality_check_execution",
        "id": authorization_id,
        "node_id": node_id,
        "approved_by": "release-owner",
        "rationale": "The declared intent needs one fresh local proof.",
        "expires_at": "2026-08-15T13:00:00Z",
        "confirmation": f"AUTHORIZE {authorization_id}",
    }


def test_graph_authorization_binds_a_verified_reality_check_and_consumes_once(
    tmp_path: Path,
):
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = create_graph_authorization(tmp_path, _payload(node_id), now=now)

    authorization = result["authorization"]
    assert result["marker"] == "GRAPH_OPS_HUMAN_AUTHORIZATION_RECORDED"
    assert authorization["binding"]["node_id"] == node_id
    assert authorization["authority"]["execution"] is True
    assert authorization["authority"]["repair"] is False
    assert validate_graph_authorization(authorization)["state"] == "approved"
    projected = graph_ops_snapshot(tmp_path)
    assert "GRAPH_OPS_HUMAN_AUTHORIZATIONS_PROJECTED" in projected["markers"]
    assert projected["facts"]["graph_authorization_approved_count"] == 1
    assert (
        next(node for node in projected["nodes"] if node["kind"] == "authorization")[
            "status"
        ]
        == "approved"
    )

    executed = run_authorized_reality_check(
        tmp_path, Path(result["path"]), now=now + timedelta(minutes=1)
    )
    assert executed["marker"] == "GRAPH_OPS_AUTHORIZED_REALITY_CHECK_EXECUTED"
    assert executed["receipt"]["marker"] == "REALITY_CHECK_VERIFIED"
    assert Path(executed["outputs"]["receipt"]).name.endswith(".reality.json")

    consumed = validate_graph_authorization(
        json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    )
    assert consumed["state"] == "consumed"
    with pytest.raises(GraphAuthorizationError, match="unused Reality Check"):
        run_authorized_reality_check(
            tmp_path, Path(result["path"]), now=now + timedelta(minutes=2)
        )


def test_graph_authorization_requires_confirmation_and_rejects_changed_bound_receipt(
    tmp_path: Path,
):
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    denied = _payload(node_id, authorization_id="denied")
    denied["confirmation"] = "yes"
    with pytest.raises(GraphAuthorizationError, match="confirmation"):
        create_graph_authorization(tmp_path, denied, now=now)

    result = create_graph_authorization(
        tmp_path, _payload(node_id, authorization_id="stale"), now=now
    )
    source = Path(result["authorization"]["binding"]["source"])
    receipt_path = tmp_path / source
    receipt_path.write_text("{}", encoding="utf-8")
    with pytest.raises(GraphAuthorizationError, match="changed after approval"):
        run_authorized_reality_check(
            tmp_path, Path(result["path"]), now=now + timedelta(minutes=1)
        )


def test_graph_authorization_rejects_a_concurrent_execution_lock(tmp_path: Path):
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = create_graph_authorization(
        tmp_path, _payload(node_id, authorization_id="locked"), now=now
    )
    lock = Path(result["path"]).with_suffix(".json.lock")
    lock.write_text("in progress\n", encoding="utf-8")

    with pytest.raises(GraphAuthorizationError, match="already executing"):
        run_authorized_reality_check(
            tmp_path, Path(result["path"]), now=now + timedelta(minutes=1)
        )


def _snapshot(*, cycle: bool = False, complete: bool = True):
    edges = [
        {"source": "slice:a", "target": "slice:b", "relation": "depends_on"},
        {"source": "slice:a", "target": "slice:c", "relation": "depends_on"},
    ]
    if cycle:
        edges.append(
            {"source": "slice:c", "target": "slice:a", "relation": "depends_on"}
        )
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
    assert [item["node_id"] for item in first["workset"]] == [
        "slice:a",
        "slice:b",
        "slice:c",
    ]
    assert first["workset"][1]["disposition"] == "REUSE_CANDIDATE"
    assert first["quantitative"]["critical_path_ms"] is None
    assert first["quantitative"]["time_saved_ms"] is None
    assert first["parallel_waves"] == [
        {"index": 1, "node_ids": ["slice:a"], "authority": "proposal_only"},
        {"index": 2, "node_ids": ["slice:b", "slice:c"], "authority": "proposal_only"},
    ]
    assert all(value is False for value in first["authority"].values())


def test_portfolio_uses_only_complete_valid_duration_sets_and_never_claims_savings():
    plan = graph_portfolio_plan(
        _snapshot(), {"slice:a": 10, "slice:b": 20, "slice:c": 7}
    )
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

    assert [item["disposition"] for item in plan["workset"]] == [
        "BLOCK",
        "BLOCK",
        "BLOCK",
    ]
    assert plan["workset"][1]["blocked_by"] == ["slice:a"]
    assert plan["parallel_waves"] == []


def test_graph_portfolio_cli_is_machine_readable_and_never_executes(tmp_path, capsys):
    before = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    code = main(["graph", "portfolio", "--root", str(tmp_path), "--json"])

    payload = json.loads(capsys.readouterr().out)
    after = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert code == 0
    assert payload["cli_marker"] == "GRAPH_PORTFOLIO_CLI_READ_ONLY"
    assert all(value is False for value in payload["authority"].values())
    assert before == after
