"""Plan temporal failure schedules from a sealed graph lineage without running them."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from .graph_forensics import verify_graph_lineage


RESILIENCE_PLAN_SCHEMA = "factory.temporal-resilience-plan.v1"
MAX_SCHEDULES = 64


class ResilienceError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise ResilienceError("RESILIENCE_PATH_INVALID", "lineage path must stay inside the workspace") from exc


def _lineage(root: Path, path: Path) -> tuple[dict[str, Any], str]:
    candidate = Path(path).resolve()
    relative = _relative(root, candidate)
    verification = verify_graph_lineage(candidate)
    if not verification.get("valid"):
        raise ResilienceError("RESILIENCE_LINEAGE_INVALID", "lineage must pass hash and bounds verification")
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResilienceError("RESILIENCE_LINEAGE_UNREADABLE", f"lineage cannot be read: {exc}") from exc
    return payload, relative


def _schedule(schedule_id: str, kind: str, *, node_id: str, sequence: int, state_key: str | None = None, effect_id: str | None = None) -> dict[str, Any]:
    return {"id": schedule_id, "kind": kind, "node_id": node_id, "sequence": sequence, "state_key": state_key, "effect_id": effect_id, "execution": "locked", "expected_marker": {"stale_read": "STALE_READ", "parallel_write": "PARALLEL_WRITE_CONFLICT", "duplicate_effect": "DUPLICATE_SIDE_EFFECT", "retry_replay": "UNSAFE_RETRY", "checkpoint_replay": "UNSAFE_CHECKPOINT_REPLAY"}[kind]}


def _schedules(lineage: dict[str, Any]) -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    writes: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for step in lineage["steps"]:
        sequence, node_id = int(step["sequence"]), str(step["node_id"])
        for item in step.get("reads", []):
            plans.append(_schedule(f"stale-{sequence}-{item['key']}", "stale_read", node_id=node_id, sequence=sequence, state_key=item["key"]))
        for effect in step.get("side_effects", []):
            effect_id = str(effect["effect_id"])
            plans.append(_schedule(f"duplicate-{sequence}-{effect_id}", "duplicate_effect", node_id=node_id, sequence=sequence, effect_id=effect_id))
            plans.append(_schedule(f"retry-{sequence}-{effect_id}", "retry_replay", node_id=node_id, sequence=sequence, effect_id=effect_id))
        for item in step.get("writes", []):
            writes.setdefault((int(step["superstep"]), str(item["key"])), []).append({"node_id": node_id, "sequence": sequence, "item": item})
            plans.append(_schedule(f"checkpoint-{sequence}-{item['key']}", "checkpoint_replay", node_id=node_id, sequence=sequence, state_key=item["key"]))
    for (_, key), members in writes.items():
        if len(members) > 1:
            for member in members:
                plans.append(_schedule(f"parallel-{member['sequence']}-{key}", "parallel_write", node_id=member["node_id"], sequence=member["sequence"], state_key=key))
    ordered = sorted({item["id"]: item for item in plans}.values(), key=lambda item: item["id"])
    return ordered[:MAX_SCHEDULES]


def compile_temporal_resilience_plan(root: Path, lineage_path: Path) -> dict[str, Any]:
    """Derive bounded replay-risk schedules from sealed lineage without executing a graph."""
    workspace = Path(root).resolve()
    lineage, relative = _lineage(workspace, lineage_path)
    schedules = _schedules(lineage)
    core = {"schema": RESILIENCE_PLAN_SCHEMA, "marker": "TEMPORAL_RESILIENCE_PLAN_COMPILED", "source": {"path": relative, "lineage_sha256": lineage["lineage_sha256"], "graph_id": lineage["graph_id"], "run_id": lineage["run_id"]}, "schedules": schedules, "facts": {"schedule_count": len(schedules), "kinds": sorted({item["kind"] for item in schedules})}, "authority": {"execution": False, "checkpoint_mutation": False, "source_write": False, "repair": False, "approval": False}, "scope_limits": ["Schedules are fault hypotheses derived from declared lineage only.", "The planner cannot invoke a graph, replay a checkpoint, or establish production resilience."]}
    return {**core, "plan_sha256": _sha(core)}


def _read_resilience_plan(root: Path, plan_path: Path) -> dict[str, Any]:
    candidate = Path(plan_path).resolve()
    _relative(root, candidate)
    try:
        plan = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResilienceError("RESILIENCE_PLAN_UNREADABLE", f"plan cannot be read: {exc}") from exc
    if not isinstance(plan, dict) or plan.get("schema") != RESILIENCE_PLAN_SCHEMA:
        raise ResilienceError("RESILIENCE_PLAN_INVALID", f"plan must use {RESILIENCE_PLAN_SCHEMA}")
    return plan


def _resilience_plan_hash(plan: dict[str, Any]) -> str | None:
    supplied = plan.get("plan_sha256")
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    return supplied if isinstance(supplied, str) and supplied == _sha(core) else None


def _resilience_source(plan: dict[str, Any]) -> dict[str, Any]:
    source = plan.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("path"), str):
        raise ResilienceError("RESILIENCE_PLAN_INVALID", "plan source is invalid")
    return source


def _resilience_comparison(plan: dict[str, Any], expected: dict[str, Any], supplied: str) -> dict[str, Any]:
    if expected["source"] != plan["source"]:
        return {"schema": RESILIENCE_PLAN_SCHEMA, "marker": "TEMPORAL_RESILIENCE_SOURCE_STALE", "ok": False}
    if expected["schedules"] != plan.get("schedules"):
        count = len(plan.get("schedules", [])) if isinstance(plan.get("schedules"), list) else None
        return {"schema": RESILIENCE_PLAN_SCHEMA, "marker": "TEMPORAL_RESILIENCE_PLAN_INCOMPLETE", "ok": False, "expected_schedule_count": len(expected["schedules"]), "actual_schedule_count": count}
    return {"schema": RESILIENCE_PLAN_SCHEMA, "marker": "TEMPORAL_RESILIENCE_PLAN_VERIFIED", "ok": True, "schedule_count": len(expected["schedules"]), "plan_sha256": supplied}


def verify_temporal_resilience_plan(root: Path, plan_path: Path) -> dict[str, Any]:
    """Verify plan integrity, lineage freshness, and complete deterministic schedule coverage."""
    workspace = Path(root).resolve()
    plan = _read_resilience_plan(workspace, plan_path)
    supplied = _resilience_plan_hash(plan)
    if supplied is None:
        return {"schema": RESILIENCE_PLAN_SCHEMA, "marker": "TEMPORAL_RESILIENCE_PLAN_TAMPERED", "ok": False}
    source = _resilience_source(plan)
    expected = compile_temporal_resilience_plan(workspace, workspace / source["path"])
    return _resilience_comparison(plan, expected, supplied)


def write_temporal_resilience_plan(plan: dict[str, Any], out_path: Path) -> Path:
    """Atomically write a resilience plan to its explicit workspace output path."""
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(_canonical(plan))
    temporary.replace(target)
    return target
