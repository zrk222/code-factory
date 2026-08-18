from __future__ import annotations

import hashlib
import json
from pathlib import Path

from factoryline.cli import main
from factoryline.resilience import compile_temporal_resilience_plan, verify_temporal_resilience_plan, write_temporal_resilience_plan


H0 = hashlib.sha256(b"zero").hexdigest()
H1 = hashlib.sha256(b"one").hexdigest()
H2 = hashlib.sha256(b"two").hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _write_lineage(path: Path, steps: list[dict]) -> Path:
    core = {"schema": "factory.graph-lineage.v1", "run_id": "checkout-run", "graph_id": "checkout", "steps": steps}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({**core, "lineage_sha256": _digest(core)}), encoding="utf-8")
    return path


def _step(sequence: int, node: str, *, superstep: int, reads=None, writes=None, effects=None) -> dict:
    return {"sequence": sequence, "superstep": superstep, "node_id": node, "checkpoint_id": f"cp-{sequence}", "reads": reads or [], "writes": writes or [], "evidence": [{"path": f"evidence/{node}.json", "sha256": H2}], "side_effects": effects or [], "decision": {"route": "next", "reason": "fixture"}}


def _read(key: str, version: int, value: str) -> dict:
    return {"key": key, "version": version, "sha256": value}


def _write(key: str, before: int, after: int, before_sha: str, after_sha: str) -> dict:
    return {"key": key, "previous_version": before, "version": after, "before_sha256": before_sha, "after_sha256": after_sha, "mode": "replace", "reducer": None}


def _steps() -> list[dict]:
    effect = {"effect_id": "payment-1", "idempotency_key": "payment-key", "status": "completed"}
    return [
        _step(1, "seed", superstep=1, writes=[_write("shared", 0, 1, H0, H1)], effects=[effect]),
        _step(2, "worker-a", superstep=2, reads=[_read("shared", 0, H0)], writes=[_write("shared", 1, 2, H1, H2)], effects=[effect]),
        _step(3, "worker-b", superstep=2, reads=[_read("shared", 1, H1)], writes=[_write("shared", 1, 3, H1, H0)]),
    ]


def _reseal(plan: dict) -> dict:
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    return {**core, "plan_sha256": _digest(core)}


def test_temporal_resilience_compiler_covers_declared_concurrency_and_is_locked(tmp_path: Path):
    lineage = _write_lineage(tmp_path / ".factory" / "graph-runs" / "checkout.json", _steps())
    plan = compile_temporal_resilience_plan(tmp_path, lineage)
    out = tmp_path / ".factory" / "resilience" / "checkout.plan.json"
    write_temporal_resilience_plan(plan, out)

    result = verify_temporal_resilience_plan(tmp_path, out)
    assert result["ok"] is True
    assert {"stale_read", "parallel_write", "duplicate_effect", "retry_replay", "checkpoint_replay"} <= set(plan["facts"]["kinds"])
    assert all(schedule["execution"] == "locked" for schedule in plan["schedules"])
    assert all(value is False for value in plan["authority"].values())


def test_temporal_resilience_verifier_rejects_missing_schedule_tamper_and_stale_lineage(tmp_path: Path):
    lineage = _write_lineage(tmp_path / "checkout.json", _steps())
    out = tmp_path / "resilience.json"
    write_temporal_resilience_plan(compile_temporal_resilience_plan(tmp_path, lineage), out)

    incomplete = json.loads(out.read_text(encoding="utf-8"))
    incomplete["schedules"] = incomplete["schedules"][:-1]
    out.write_text(json.dumps(_reseal(incomplete)), encoding="utf-8")
    assert verify_temporal_resilience_plan(tmp_path, out)["marker"] == "TEMPORAL_RESILIENCE_PLAN_INCOMPLETE"

    tampered = json.loads(out.read_text(encoding="utf-8"))
    tampered["plan_sha256"] = "0" * 64
    out.write_text(json.dumps(tampered), encoding="utf-8")
    assert verify_temporal_resilience_plan(tmp_path, out)["marker"] == "TEMPORAL_RESILIENCE_PLAN_TAMPERED"

    write_temporal_resilience_plan(compile_temporal_resilience_plan(tmp_path, lineage), out)
    changed = _steps()
    changed[0]["decision"]["reason"] = "changed lineage meaning"
    _write_lineage(lineage, changed)
    assert verify_temporal_resilience_plan(tmp_path, out)["marker"] == "TEMPORAL_RESILIENCE_SOURCE_STALE"


def test_resilience_cli_writes_only_explicit_output_and_verifies(tmp_path: Path, capsys):
    lineage = _write_lineage(tmp_path / "checkout.json", _steps())
    out = tmp_path / ".factory" / "resilience" / "checkout.plan.json"
    assert main(["resilience", "plan", str(lineage.relative_to(tmp_path)), "--root", str(tmp_path), "--out", str(out), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "TEMPORAL_RESILIENCE_PLAN_COMPILED"
    assert main(["resilience", "verify", str(out.relative_to(tmp_path)), "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "TEMPORAL_RESILIENCE_PLAN_VERIFIED"
