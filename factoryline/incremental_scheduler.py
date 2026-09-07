"""Dependency-aware planning for proof reuse.

The scheduler only plans. It never runs a gate and never turns a reused proof
into publication or deployment authority.
"""
from __future__ import annotations

from collections import defaultdict, deque
import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any

from .proof_reuse import plan_proofs
from .runtime_audit_common import canonical_bytes, exact_keys, reject_secret_material, require_str, require_unique_strings


SCHEMA = "factory.incremental-plan.v1"
ASSURANCE_LEVELS = ("supervised_local", "isolated_worker", "hardened_vm")


class SchedulerError(ValueError):
    """Stable, fail-closed schedule manifest error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _paths(value: object, field: str, *, minimum: int = 1, maximum: int = 500) -> list[str]:
    try:
        paths = require_unique_strings(value, field, minimum=minimum, maximum=maximum)
    except Exception as exc:
        raise SchedulerError(getattr(exc, "code", "E_SCHEDULE_PATHS"), str(exc)) from exc
    normalized = []
    for raw in paths:
        path = raw.replace("\\", "/").strip()
        if not path or path.startswith("/") or path == "." or "/../" in f"/{path}/" or path.startswith("../") or path.endswith("/.."):
            raise SchedulerError("E_SCHEDULE_PATHS", f"{field} contains an unsafe path: {raw}")
        normalized.append(path.lstrip("./"))
    return sorted(set(normalized))


def _validate_gate(gate: object, index: int, ids: set[str]) -> dict[str, Any]:
    if not isinstance(gate, dict):
        raise SchedulerError("E_SCHEDULE_CONTRACT", f"gate {index} must be an object")
    try:
        exact_keys(gate, {"id", "depends_on", "side_effects", "proof"})
    except Exception as exc:
        raise SchedulerError("E_SCHEDULE_CONTRACT", f"gate {index}: {exc}") from exc
    gate_id = require_str(gate.get("id"), f"gates[{index}].id", maximum=160)
    if gate_id in ids:
        raise SchedulerError("E_SCHEDULE_CONTRACT", f"duplicate gate id: {gate_id}")
    deps = gate.get("depends_on")
    if not isinstance(deps, list) or any(not isinstance(dep, str) or not dep.strip() for dep in deps) or len(deps) > 500 or len(set(deps)) != len(deps):
        raise SchedulerError("E_SCHEDULE_DEPENDENCY", f"{gate_id}.depends_on must be a unique list")
    if gate_id in deps:
        raise SchedulerError("E_SCHEDULE_CYCLE", f"gate {gate_id} depends on itself")
    side_effects = gate.get("side_effects")
    if type(side_effects) is not bool:
        raise SchedulerError("E_SCHEDULE_SIDE_EFFECTS", f"{gate_id}.side_effects must be boolean")
    proof = gate.get("proof")
    if proof is not None and not isinstance(proof, dict):
        raise SchedulerError("E_SCHEDULE_PROOF", f"{gate_id}.proof must be an object or null")
    ids.add(gate_id)
    return {"id": gate_id, "depends_on": sorted(deps), "side_effects": side_effects, "proof": proof}


def _validate_closure(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise SchedulerError("E_SCHEDULE_CONTRACT", "dependency_closure must be an object")
    normalized = {}
    for key, paths in value.items():
        if not isinstance(key, str) or not key.strip():
            raise SchedulerError("E_SCHEDULE_CONTRACT", "dependency closure ids must be non-empty")
        normalized[key] = _paths(paths, f"dependency_closure.{key}")
    return normalized


def validate_schedule_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Validate a bounded DAG and normalize all path and gate identifiers."""
    if not isinstance(value, dict):
        raise SchedulerError("E_SCHEDULE_CONTRACT", "manifest must be an object")
    reject_secret_material(value, path="schedule")
    try:
        exact_keys(value, {"schema", "plan_id", "assurance_level", "changed_paths", "dependency_closure", "gates"})
    except Exception as exc:
        raise SchedulerError("E_SCHEDULE_CONTRACT", str(exc)) from exc
    if value.get("schema") != SCHEMA:
        raise SchedulerError("E_SCHEDULE_CONTRACT", f"schema must be {SCHEMA}")
    assurance = value.get("assurance_level")
    if assurance not in ASSURANCE_LEVELS:
        raise SchedulerError("E_SCHEDULE_ASSURANCE", "unsupported assurance level")
    gates = value.get("gates")
    if not isinstance(gates, list) or not 1 <= len(gates) <= 500:
        raise SchedulerError("E_SCHEDULE_CONTRACT", "gates must contain 1..500 entries")
    ids: set[str] = set()
    normalized_gates = [_validate_gate(gate, index, ids) for index, gate in enumerate(gates)]
    unknown = sorted({dep for gate in normalized_gates for dep in gate["depends_on"] if dep not in ids})
    if unknown:
        raise SchedulerError("E_SCHEDULE_DEPENDENCY", f"unknown dependencies: {unknown}")
    return {"schema": SCHEMA, "plan_id": require_str(value.get("plan_id"), "plan_id", maximum=160), "assurance_level": assurance, "changed_paths": _paths(value.get("changed_paths"), "changed_paths"), "dependency_closure": _validate_closure(value.get("dependency_closure")), "gates": normalized_gates}


def _topological(gates: list[dict[str, Any]]) -> list[str]:
    indegree = {gate["id"]: len(gate["depends_on"]) for gate in gates}
    dependents: dict[str, list[str]] = defaultdict(list)
    for gate in gates:
        for dep in gate["depends_on"]:
            dependents[dep].append(gate["id"])
    ready = deque(sorted(item for item, degree in indegree.items() if degree == 0))
    order = []
    while ready:
        current = ready.popleft()
        order.append(current)
        for child in sorted(dependents[current]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if len(order) != len(gates):
        raise SchedulerError("E_SCHEDULE_CYCLE", "dependency graph contains a cycle")
    return order


def _route_gate(root: Path, manifest: dict[str, Any], gate: dict[str, Any]) -> dict[str, Any]:
    gate_id = gate["id"]
    closure = manifest["dependency_closure"].get(gate_id)
    if not closure:
        return {"id": gate_id, "depends_on": gate["depends_on"], "dependency_paths": [], "disposition": "RUN", "reason": "PROOF_RELEVANCE_FAIL_CLOSED", "proof": None}
    if gate["side_effects"]:
        return {"id": gate_id, "depends_on": gate["depends_on"], "dependency_paths": closure, "disposition": "BLOCK", "reason": "PROOF_SIDE_EFFECT_REUSE_REFUSED", "proof": None}
    changed = manifest["changed_paths"]
    def intersects(left: str, right: str) -> bool:
        a = tuple(part for part in left.replace("\\", "/").strip("/").split("/") if part and part != ".")
        b = tuple(part for part in right.replace("\\", "/").strip("/").split("/") if part and part != ".")
        return bool(a and b) and (a == b or (len(a) < len(b) and b[:len(a)] == a) or (len(b) < len(a) and a[:len(b)] == b))
    if any(intersects(changed_path, dependency_path) for changed_path in changed for dependency_path in closure):
        return {"id": gate_id, "depends_on": gate["depends_on"], "dependency_paths": closure, "disposition": "RUN", "reason": "DEPENDENCY_CLOSURE_CHANGED", "proof": None}
    proof = gate.get("proof")
    if not proof:
        return {"id": gate_id, "depends_on": gate["depends_on"], "dependency_paths": closure, "disposition": "RUN", "reason": "PROOF_EXECUTION_REQUIRED", "proof": None}
    if proof.get("assurance_level") not in (None, manifest["assurance_level"]):
        return {"id": gate_id, "depends_on": gate["depends_on"], "dependency_paths": closure, "disposition": "RUN", "reason": "PROOF_ASSURANCE_MISMATCH", "proof": None}
    try:
        with tempfile.TemporaryDirectory(prefix="factory-schedule-", dir=str(root)) as temporary:
            planned = plan_proofs(root, {"schema": "factory.proof-request.v1", "gates": [proof]}, changed_paths=manifest["changed_paths"], out=Path(temporary) / "proof-plan.json")
        item = planned["items"][0]
    except Exception as exc:
        return {"id": gate_id, "depends_on": gate["depends_on"], "dependency_paths": closure, "disposition": "RUN", "reason": getattr(exc, "code", "PROOF_EXECUTION_REQUIRED"), "proof": None}
    return {"id": gate_id, "depends_on": gate["depends_on"], "dependency_paths": closure, "disposition": item["disposition"], "reason": item["reason"], "proof": {"proof_key": item.get("proof_key"), "receipt_sha256": item.get("receipt_sha256")}}


def plan_incremental(root: Path, manifest: dict[str, Any], *, out: Path | None = None) -> dict[str, Any]:
    """Produce a topological RUN/REUSE/SKIP/BLOCK plan without executing gates."""
    contract = validate_schedule_manifest(manifest)
    root = Path(root).resolve()
    order = _topological(contract["gates"])
    by_id = {gate["id"]: gate for gate in contract["gates"]}
    items = {}
    for gate_id in order:
        item = _route_gate(root, contract, by_id[gate_id])
        dependency_items = [items[dep] for dep in by_id[gate_id]["depends_on"]]
        if any(dep["disposition"] == "BLOCK" for dep in dependency_items):
            item.update(disposition="BLOCK", reason="SCHEDULER_DEPENDENCY_BLOCKED", proof=None)
        elif any(dep["disposition"] == "RUN" for dep in dependency_items) and item["disposition"] == "REUSE":
            item.update(disposition="RUN", reason="SCHEDULER_DEPENDENCY_RUN", proof=None)
        items[gate_id] = item
    rows = [items[gate_id] for gate_id in order]
    counts = {name: sum(row["disposition"] == name for row in rows) for name in ("RUN", "REUSE", "SKIP", "BLOCK")}
    core = {"schema": SCHEMA, "marker": "INCREMENTAL_PLAN_COMPACT", "plan_id": contract["plan_id"], "assurance_level": contract["assurance_level"], "changed_paths_sha256": hashlib.sha256(canonical_bytes(contract["changed_paths"])).hexdigest(), "order": order, "items": rows, "counts": counts, "obligations": order, "findings": {row["id"]: {"disposition": row["disposition"], "reason": row["reason"]} for row in rows}, "authority": "none", "release_approval": False, "claim_boundary": "Plans dependency-aware proof routing; never executes gates or grants publication authority."}
    result = {**core, "plan_sha256": hashlib.sha256(canonical_bytes(core)).hexdigest()}
    if out is not None:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_bytes(result) + b"\n")
    return result


def compare_shadow(incremental: dict[str, Any], full: dict[str, Any], *, out: Path | None = None) -> dict[str, Any]:
    """Compare an incremental plan with a full baseline before any skip is reviewed."""
    if not isinstance(incremental, dict) or not isinstance(full, dict):
        raise SchedulerError("E_SHADOW_INPUT", "both plans must be objects")
    if incremental.get("assurance_level") != full.get("assurance_level"):
        raise SchedulerError("E_SHADOW_ASSURANCE", "incremental and full assurance levels differ")
    inc_obligations = incremental.get("obligations")
    full_obligations = full.get("obligations")
    inc_findings = incremental.get("findings")
    full_findings = full.get("findings")
    if not isinstance(inc_obligations, list) or not isinstance(full_obligations, list) or not isinstance(inc_findings, dict) or not isinstance(full_findings, dict):
        raise SchedulerError("E_SHADOW_INPUT", "plans must include obligations and findings")
    differences = {"obligations_missing": sorted(set(full_obligations) - set(inc_obligations)), "obligations_extra": sorted(set(inc_obligations) - set(full_obligations)), "findings_changed": sorted(key for key in set(inc_findings) | set(full_findings) if inc_findings.get(key) != full_findings.get(key))}
    equivalent = not any(differences.values())
    core = {"schema": "factory.incremental-shadow.v1", "marker": "INCREMENTAL_SHADOW_COMPARE", "shadow_equivalent": equivalent, "differences": differences, "authority": "none", "release_approval": False, "claim_boundary": "Compares supplied plans; does not execute either plan or establish production equivalence."}
    result = {**core, "receipt_sha256": hashlib.sha256(canonical_bytes(core)).hexdigest()}
    if out is not None:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_bytes(result) + b"\n")
    return result


def load_schedule_json(path: Path) -> dict[str, Any]:
    """Load one bounded incremental schedule JSON object without execution."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchedulerError("E_SCHEDULE_JSON", str(exc)) from exc
    if not isinstance(value, dict):
        raise SchedulerError("E_SCHEDULE_JSON", "JSON must be an object")
    return value
