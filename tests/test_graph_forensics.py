from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.graph_forensics import GraphForensicsError, graph_forensics, mission_history_steps, seal_graph_lineage, seal_mission_graph_lineage, verify_graph_lineage
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.mission_graph import apply_mission_event, init_mission_graph
from factoryline.product_missions import compile_product_prd, create_mission, decide_mission, plan_value_slices


H0 = hashlib.sha256(b"zero").hexdigest()
H1 = hashlib.sha256(b"one").hexdigest()
H2 = hashlib.sha256(b"two").hexdigest()
H3 = hashlib.sha256(b"three").hexdigest()


def _write_lineage(path: Path, run_id: str, steps: list[dict], graph_id: str = "checkout") -> Path:
    core = {"schema": "factory.graph-lineage.v1", "run_id": run_id, "graph_id": graph_id, "steps": steps}
    core["lineage_sha256"] = hashlib.sha256(
        json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(core), encoding="utf-8")
    return path


def _step(sequence: int, node: str, *, superstep: int | None = None, reads=None, writes=None, effects=None, route="next") -> dict:
    return {
        "sequence": sequence,
        "superstep": sequence if superstep is None else superstep,
        "node_id": node,
        "checkpoint_id": f"cp-{sequence}",
        "reads": reads or [],
        "writes": writes or [],
        "evidence": [{"path": f"evidence/{node}.json", "sha256": H3}],
        "side_effects": effects or [],
        "decision": {"route": route, "reason": f"route selected by {node}"},
    }


def _read(key: str, version: int, sha: str) -> dict:
    return {"key": key, "version": version, "sha256": sha}


def _write(key: str, before: int, after: int, before_sha: str, after_sha: str, *, mode="replace", reducer=None) -> dict:
    return {"key": key, "previous_version": before, "version": after, "before_sha256": before_sha, "after_sha256": after_sha, "mode": mode, "reducer": reducer}


def _baseline() -> list[dict]:
    return [
        _step(1, "plan", writes=[_write("plan", 0, 1, H0, H1)]),
        _step(2, "build", reads=[_read("plan", 1, H1)], writes=[_write("candidate", 0, 1, H0, H1)]),
        _step(3, "verify", reads=[_read("candidate", 1, H1)], writes=[_write("verdict", 0, 1, H0, H1)]),
    ]


def test_lineage_verification_is_hash_sealed_and_tamper_evident(tmp_path: Path):
    path = _write_lineage(tmp_path / "run.json", "good", _baseline())
    verified = verify_graph_lineage(path)
    assert verified["valid"] is True
    assert verified["markers"] == ["GRAPH_LINEAGE_VERIFIED", "GRAPH_LINEAGE_BOUNDS_ENFORCED"]

    payload = json.loads(path.read_text())
    payload["steps"][1]["decision"]["route"] = "skip"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = verify_graph_lineage(path)
    assert result["valid"] is False
    assert "lineage_sha256 does not match" in result["errors"][-1]


def test_lineage_seal_is_atomic_and_rejects_invalid_steps(tmp_path: Path):
    steps = tmp_path / "steps.json"
    steps.write_text(json.dumps(_baseline()), encoding="utf-8")
    out = tmp_path / "runs" / "sealed.lineage.json"

    result = seal_graph_lineage("sealed", "checkout", steps, out)

    assert result["marker"] == "GRAPH_LINEAGE_SEALED"
    assert verify_graph_lineage(out)["valid"] is True
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"sequence": 1}]), encoding="utf-8")
    rejected = tmp_path / "rejected.lineage.json"
    with pytest.raises(GraphForensicsError):
        seal_graph_lineage("bad", "checkout", bad, rejected)
    assert rejected.exists() is False


def test_forensics_finds_first_divergence_and_smallest_causal_recovery(tmp_path: Path):
    good = _write_lineage(tmp_path / "good.json", "good", _baseline())
    bad_steps = _baseline()
    bad_steps[1] = _step(2, "build", reads=[_read("plan", 1, H1)], writes=[_write("candidate", 0, 1, H0, H2)], route="risky")
    bad_steps[2] = _step(3, "verify", reads=[_read("candidate", 1, H2)], writes=[_write("verdict", 0, 1, H0, H2)])
    bad = _write_lineage(tmp_path / "bad.json", "bad", bad_steps)

    result = graph_forensics(good, bad)

    assert result["divergence"]["candidate_node"] == "build"
    assert result["divergence"]["causal_nodes"] == ["build", "verify"]
    assert result["recovery_plan"]["checkpoint_id"] == "cp-1"
    assert result["recovery_plan"]["execute"] is False
    assert result["authority"]["checkpoint_mutation"] is False
    assert result["forensics_sha256"]


def test_identical_semantics_require_no_recovery(tmp_path: Path):
    left = _write_lineage(tmp_path / "left.json", "left", _baseline())
    right = _write_lineage(tmp_path / "right.json", "right", _baseline())

    result = graph_forensics(left, right)

    assert result["divergence"] is None
    assert result["recovery_plan"]["action"] == "no_recovery_required"
    assert "semantically identical" in result["mermaid"]


def test_concurrency_guard_detects_parallel_conflict_stale_read_and_duplicate_effect(tmp_path: Path):
    good = _write_lineage(tmp_path / "good.json", "good", _baseline())
    effect = {"effect_id": "ticket-42", "idempotency_key": "key-a", "status": "completed"}
    candidate_steps = [
        _step(1, "seed", writes=[_write("shared", 0, 1, H0, H1)], effects=[effect]),
        _step(2, "worker-a", superstep=2, reads=[_read("shared", 0, H0)], writes=[_write("shared", 1, 2, H1, H2)], effects=[effect]),
        _step(3, "worker-b", superstep=2, reads=[_read("shared", 1, H1)], writes=[_write("shared", 1, 3, H1, H3)]),
    ]
    candidate = _write_lineage(tmp_path / "candidate.json", "candidate", candidate_steps)

    result = graph_forensics(good, candidate)
    codes = {item["code"] for item in result["anomalies"]}

    assert {"STALE_READ", "PARALLEL_WRITE_CONFLICT", "DUPLICATE_SIDE_EFFECT"} <= codes


def test_common_parallel_reducer_is_not_reported_as_conflict(tmp_path: Path):
    steps = [
        _step(1, "a", superstep=1, writes=[_write("items", 0, 1, H0, H1, mode="reduce", reducer="append")]),
        _step(2, "b", superstep=1, writes=[_write("items", 0, 2, H0, H2, mode="reduce", reducer="append")]),
    ]
    left = _write_lineage(tmp_path / "left.json", "left", steps)
    right = _write_lineage(tmp_path / "right.json", "right", steps)

    assert "PARALLEL_WRITE_CONFLICT" not in {item["code"] for item in graph_forensics(left, right)["anomalies"]}


def test_graph_mismatch_fails_closed(tmp_path: Path):
    left = _write_lineage(tmp_path / "left.json", "left", _baseline(), "one")
    right = _write_lineage(tmp_path / "right.json", "right", _baseline(), "two")
    with pytest.raises(GraphForensicsError, match="same graph_id"):
        graph_forensics(left, right)


def test_cli_and_graph_ops_surface_verified_forensics_without_writes(tmp_path: Path, capsys):
    run_root = tmp_path / ".factory" / "graph-runs"
    good = _write_lineage(run_root / "01-good.lineage.json", "good", _baseline())
    bad_steps = _baseline()
    bad_steps[1] = _step(2, "build", reads=[_read("plan", 1, H1)], writes=[_write("candidate", 0, 1, H0, H2)])
    bad = _write_lineage(run_root / "02-bad.lineage.json", "bad", bad_steps)
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    assert main(["graph", "lineage-verify", str(good), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["graph", "forensics", "--baseline", str(good), "--candidate", str(bad), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["divergence"]["candidate_node"] == "build"
    snapshot = graph_ops_snapshot(tmp_path)
    after = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    assert "GRAPH_OPS_SEMANTIC_LINEAGE" in snapshot["markers"]
    assert "GRAPH_OPS_COUNTERFACTUAL_RECOVERY_PREVIEW" in snapshot["markers"]
    assert {"lineage", "forensics"} <= {node["kind"] for node in snapshot["nodes"]}
    forensic = next(node for node in snapshot["nodes"] if node["kind"] == "forensics")
    assert forensic["source"] == ".factory/graph-runs/02-bad.lineage.json"
    assert forensic["facts"]["baseline"]["run_id"] == "good"
    assert forensic["facts"]["candidate"]["run_id"] == "bad"
    assert forensic["facts"]["authority"]["execution"] is False
    assert snapshot["recommendation"]["action"] == "review_counterfactual_fork"
    assert before == after


def test_lineage_seal_cli_writes_only_explicit_output(tmp_path: Path, capsys):
    steps = tmp_path / "steps.json"
    steps.write_text(json.dumps(_baseline()), encoding="utf-8")
    out = tmp_path / ".factory" / "graph-runs" / "cli.lineage.json"

    code = main(["graph", "lineage-seal", "--run-id", "cli", "--graph-id", "checkout", "--steps", str(steps), "--out", str(out), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["path"] == str(out)
    assert verify_graph_lineage(out)["valid"] is True


def test_lineage_bounds_accept_2000_steps_and_reject_2001_or_401_state_items(tmp_path: Path):
    steps = [_step(index, f"node-{index}") for index in range(1, 2001)]
    maximum = _write_lineage(tmp_path / "maximum.json", "maximum", steps)
    over_steps = _write_lineage(tmp_path / "over-steps.json", "over-steps", [*steps, _step(2001, "node-2001")])
    crowded = _baseline()
    crowded[0]["reads"] = [_read(f"key-{index}", 0, H0) for index in range(401)]
    over_state = _write_lineage(tmp_path / "over-state.json", "over-state", crowded)

    assert verify_graph_lineage(maximum)["valid"] is True
    assert verify_graph_lineage(over_steps)["marker"] == "GRAPH_LINEAGE_INVALID"
    crowded_result = verify_graph_lineage(over_state)
    assert crowded_result["valid"] is False
    assert "GRAPH_LINEAGE_BOUNDS_ENFORCED" in crowded_result["markers"]
    assert any("at most 400 objects" in error for error in crowded_result["errors"])


def test_lineage_verify_cli_fails_closed_for_missing_or_oversized_source(tmp_path: Path, capsys):
    missing = tmp_path / "missing.json"
    assert main(["graph", "lineage-verify", str(missing), "--json"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "GRAPH_LINEAGE_UNREADABLE"
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (2_097_152 + 1))
    assert main(["graph", "lineage-verify", str(oversized), "--json"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "GRAPH_LINEAGE_UNREADABLE"


def test_native_mission_history_is_automatically_translated_to_control_state_lineage():
    history = {
        "schema": "factory.mission.graph.history.v1",
        "mission_id": "M-001",
        "events": [{
            "version": 1, "source_state": "planned", "target_state": "creator_running",
            "event": "approve", "event_sha256": H2, "previous_sha256": "",
            "receipt": {"path": "approval.json", "sha256": H1},
        }],
    }

    steps = mission_history_steps(history)

    assert steps[0]["node_id"] == "mission-event:approve"
    assert steps[0]["reads"][0]["key"] == "mission_state"
    assert steps[0]["writes"][0]["version"] == 1
    assert steps[0]["decision"]["route"] == "creator_running"
    assert steps[0]["side_effects"] == []


def test_native_mission_ledger_is_verified_and_sealed_end_to_end(tmp_path: Path):
    prd = tmp_path / "PRD.md"
    prd.write_text("""# Forensic fixture
## Actors
- Maintainer: owns the proof.
## Outcomes
- Preserve verified behavior.
## Requirements
- REQ-PROOF: The system must preserve verified behavior.
## Acceptance
Scenario: Preserve proof
  Given one approved mission
  When its event ledger is exported
  Then its lineage is hash sealed
""", encoding="utf-8")
    product = compile_product_prd(prd, tmp_path)
    slices = plan_value_slices(Path(product["path"]), tmp_path)
    mission = create_mission(Path(slices["path"]), slices["slices"][0]["id"], tmp_path, "owner")
    mission_path = Path(mission["path"])
    init_mission_graph(mission_path, tmp_path)
    approval = decide_mission(mission_path, tmp_path, owner="owner", decision="approved_execution", rationale="Approved for bounded proof.")
    apply_mission_event(mission_path, tmp_path, "approve", "owner", "owner", "approve-forensics", Path(approval["path"]))

    out = tmp_path / ".factory" / "graph-runs" / "mission.lineage.json"
    result = seal_mission_graph_lineage(mission_path, tmp_path, "mission-run", out)

    assert result["marker"] == "GRAPH_LINEAGE_MISSION_LEDGER_EXPORTED"
    assert result["mission_id"] == mission["id"]
    assert verify_graph_lineage(out)["valid"] is True
