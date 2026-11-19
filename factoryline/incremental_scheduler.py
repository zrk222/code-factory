"""Dependency-aware proof planning and supervised pre-PR execution.

Proof reuse and execution receipts do not carry publication or deployment authority.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import hashlib
import json
from pathlib import Path, PureWindowsPath
from threading import Lock
from time import monotonic_ns
from typing import Any

from .proof_reuse import evaluate_proofs
from .runtime_audit_common import (
    canonical_bytes,
    exact_keys,
    reject_secret_material,
    require_str,
    require_unique_strings,
)


SCHEMA = "factory.incremental-plan.v1"
ASSURANCE_LEVELS = ("supervised_local", "isolated_worker", "hardened_vm")


class SchedulerError(ValueError):
    """Stable, fail-closed schedule manifest error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _paths(
    value: object, field: str, *, minimum: int = 1, maximum: int = 500
) -> list[str]:
    try:
        paths = require_unique_strings(value, field, minimum=minimum, maximum=maximum)
    except Exception as exc:
        raise SchedulerError(
            getattr(exc, "code", "E_SCHEDULE_PATHS"), str(exc)
        ) from exc
    normalized = []
    for raw in paths:
        path = raw.replace("\\", "/").strip()
        windows_path = PureWindowsPath(path)
        parts = path.split("/")
        if (
            not path
            or "\x00" in path
            or windows_path.drive
            or windows_path.root
            or all(part in {"", "."} for part in parts)
            or any(part == ".." for part in parts)
        ):
            raise SchedulerError(
                "E_SCHEDULE_PATHS", f"{field} contains an unsafe path: {raw}"
            )
        normalized.append("/".join(part for part in parts if part not in {"", "."}))
    return sorted(set(normalized))


def paths_intersect(left: str, right: str) -> bool:
    """Conservatively match equal/ancestor paths across Windows and POSIX.

    Comparison is case-insensitive to avoid stale proof reuse when a manifest
    moves between case-sensitive and case-insensitive filesystems. This may
    rerun extra gates for case-distinct POSIX names, never skip them.
    """
    a = tuple(
        part.casefold()
        for part in left.replace("\\", "/").strip("/").split("/")
        if part and part != "."
    )
    b = tuple(
        part.casefold()
        for part in right.replace("\\", "/").strip("/").split("/")
        if part and part != "."
    )
    return bool(a and b) and (
        a == b
        or (len(a) < len(b) and b[: len(a)] == a)
        or (len(b) < len(a) and a[: len(b)] == b)
    )


def _validate_gate(gate: object, index: int, ids: set[str]) -> dict[str, Any]:
    value = _gate_object(gate, index)
    gate_id = _unique_gate_id(value, index, ids)
    dependencies = _gate_dependencies(value, gate_id)
    side_effects = _gate_side_effects(value, gate_id)
    proof = _gate_proof(value, gate_id)
    ids.add(gate_id)
    return {
        "id": gate_id,
        "depends_on": dependencies,
        "side_effects": side_effects,
        "proof": proof,
    }


def _gate_object(gate: object, index: int) -> dict[str, Any]:
    if not isinstance(gate, dict):
        raise SchedulerError("E_SCHEDULE_CONTRACT", f"gate {index} must be an object")
    try:
        exact_keys(gate, {"id", "depends_on", "side_effects", "proof"})
    except Exception as exc:
        raise SchedulerError("E_SCHEDULE_CONTRACT", f"gate {index}: {exc}") from exc
    return gate


def _unique_gate_id(gate: dict[str, Any], index: int, ids: set[str]) -> str:
    gate_id = require_str(gate.get("id"), f"gates[{index}].id", maximum=160)
    if gate_id in ids:
        raise SchedulerError("E_SCHEDULE_CONTRACT", f"duplicate gate id: {gate_id}")
    return gate_id


def _gate_dependencies(gate: dict[str, Any], gate_id: str) -> list[str]:
    deps = gate.get("depends_on")
    if (
        not isinstance(deps, list)
        or any(not isinstance(dep, str) or not dep.strip() for dep in deps)
        or len(deps) > 500
        or len(set(deps)) != len(deps)
    ):
        raise SchedulerError(
            "E_SCHEDULE_DEPENDENCY", f"{gate_id}.depends_on must be a unique list"
        )
    if gate_id in deps:
        raise SchedulerError("E_SCHEDULE_CYCLE", f"gate {gate_id} depends on itself")
    return sorted(deps)


def _gate_side_effects(gate: dict[str, Any], gate_id: str) -> bool:
    side_effects = gate.get("side_effects")
    if type(side_effects) is not bool:
        raise SchedulerError(
            "E_SCHEDULE_SIDE_EFFECTS", f"{gate_id}.side_effects must be boolean"
        )
    return side_effects


def _gate_proof(gate: dict[str, Any], gate_id: str) -> dict[str, Any] | None:
    proof = gate.get("proof")
    if proof is not None and not isinstance(proof, dict):
        raise SchedulerError(
            "E_SCHEDULE_PROOF", f"{gate_id}.proof must be an object or null"
        )
    return proof


def _validate_closure(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise SchedulerError(
            "E_SCHEDULE_CONTRACT", "dependency_closure must be an object"
        )
    normalized = {}
    for key, paths in value.items():
        if not isinstance(key, str) or not key.strip():
            raise SchedulerError(
                "E_SCHEDULE_CONTRACT", "dependency closure ids must be non-empty"
            )
        normalized[key] = _paths(paths, f"dependency_closure.{key}")
    return normalized


def validate_schedule_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Validate a bounded DAG and normalize all path and gate identifiers."""
    if not isinstance(value, dict):
        raise SchedulerError("E_SCHEDULE_CONTRACT", "manifest must be an object")
    reject_secret_material(value, path="schedule")
    try:
        exact_keys(
            value,
            {
                "schema",
                "plan_id",
                "assurance_level",
                "changed_paths",
                "dependency_closure",
                "gates",
            },
        )
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
    normalized_gates = [
        _validate_gate(gate, index, ids) for index, gate in enumerate(gates)
    ]
    unknown = sorted(
        {
            dep
            for gate in normalized_gates
            for dep in gate["depends_on"]
            if dep not in ids
        }
    )
    if unknown:
        raise SchedulerError(
            "E_SCHEDULE_DEPENDENCY", f"unknown dependencies: {unknown}"
        )
    return {
        "schema": SCHEMA,
        "plan_id": require_str(value.get("plan_id"), "plan_id", maximum=160),
        "assurance_level": assurance,
        "changed_paths": _paths(value.get("changed_paths"), "changed_paths"),
        "dependency_closure": _validate_closure(value.get("dependency_closure")),
        "gates": normalized_gates,
    }


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


def _route_gate(
    root: Path,
    manifest: dict[str, Any],
    gate: dict[str, Any],
    *,
    evaluated_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gate_id = gate["id"]
    closure = manifest["dependency_closure"].get(gate_id)
    if not closure:
        return {
            "id": gate_id,
            "depends_on": gate["depends_on"],
            "dependency_paths": [],
            "disposition": "RUN",
            "reason": "PROOF_RELEVANCE_FAIL_CLOSED",
            "proof": None,
        }
    if gate["side_effects"]:
        return {
            "id": gate_id,
            "depends_on": gate["depends_on"],
            "dependency_paths": closure,
            "disposition": "BLOCK",
            "reason": "PROOF_SIDE_EFFECT_REUSE_REFUSED",
            "proof": None,
        }
    changed = manifest["changed_paths"]

    if any(
        paths_intersect(changed_path, dependency_path)
        for changed_path in changed
        for dependency_path in closure
    ):
        return {
            "id": gate_id,
            "depends_on": gate["depends_on"],
            "dependency_paths": closure,
            "disposition": "RUN",
            "reason": "DEPENDENCY_CLOSURE_CHANGED",
            "proof": None,
        }
    proof = gate.get("proof")
    if not proof:
        return {
            "id": gate_id,
            "depends_on": gate["depends_on"],
            "dependency_paths": closure,
            "disposition": "RUN",
            "reason": "PROOF_EXECUTION_REQUIRED",
            "proof": None,
        }
    if proof.get("assurance_level") not in (None, manifest["assurance_level"]):
        return {
            "id": gate_id,
            "depends_on": gate["depends_on"],
            "dependency_paths": closure,
            "disposition": "RUN",
            "reason": "PROOF_ASSURANCE_MISMATCH",
            "proof": None,
        }
    if evaluated_proof is None:
        try:
            planned = evaluate_proofs(
                root,
                {"schema": "factory.proof-request.v1", "gates": [proof]},
                changed_paths=manifest["changed_paths"],
            )
            evaluated_proof = planned["items"][0]
        except Exception as exc:
            return {
                "id": gate_id,
                "depends_on": gate["depends_on"],
                "dependency_paths": closure,
                "disposition": "RUN",
                "reason": getattr(exc, "code", "PROOF_EXECUTION_REQUIRED"),
                "proof": None,
            }
    return {
        "id": gate_id,
        "depends_on": gate["depends_on"],
        "dependency_paths": closure,
        "disposition": evaluated_proof["disposition"],
        "reason": evaluated_proof["reason"],
        "proof": {
            "proof_key": evaluated_proof.get("proof_key"),
            "receipt_sha256": evaluated_proof.get("receipt_sha256"),
        },
    }


def _proof_is_batch_eligible(manifest: dict[str, Any], gate: dict[str, Any]) -> bool:
    gate_id = gate["id"]
    closure = manifest["dependency_closure"].get(gate_id)
    if not closure or gate["side_effects"]:
        return False
    if any(
        paths_intersect(changed_path, dependency_path)
        for changed_path in manifest["changed_paths"]
        for dependency_path in closure
    ):
        return False
    proof = gate.get("proof")
    return bool(
        proof and proof.get("assurance_level") in (None, manifest["assurance_level"])
    )


def plan_incremental(
    root: Path, manifest: dict[str, Any], *, out: Path | None = None
) -> dict[str, Any]:
    """Produce a topological RUN/REUSE/SKIP/BLOCK plan without executing gates."""
    contract = validate_schedule_manifest(manifest)
    root = Path(root).resolve()
    order = _topological(contract["gates"])
    by_id = {gate["id"]: gate for gate in contract["gates"]}
    eligible_ids = [
        gate_id
        for gate_id in order
        if _proof_is_batch_eligible(contract, by_id[gate_id])
    ]
    proof_results: dict[str, dict[str, Any]] = {}
    if eligible_ids:
        batch = evaluate_proofs(
            root,
            {
                "schema": "factory.proof-request.v1",
                "gates": [by_id[gate_id]["proof"] for gate_id in eligible_ids],
            },
            changed_paths=contract["changed_paths"],
        )
        proof_results = dict(zip(eligible_ids, batch["items"], strict=True))
    items = {}
    for gate_id in order:
        item = _route_gate(
            root,
            contract,
            by_id[gate_id],
            evaluated_proof=proof_results.get(gate_id),
        )
        dependency_items = [items[dep] for dep in by_id[gate_id]["depends_on"]]
        if any(dep["disposition"] == "BLOCK" for dep in dependency_items):
            item.update(
                disposition="BLOCK", reason="SCHEDULER_DEPENDENCY_BLOCKED", proof=None
            )
        elif (
            any(dep["disposition"] == "RUN" for dep in dependency_items)
            and item["disposition"] == "REUSE"
        ):
            item.update(
                disposition="RUN", reason="SCHEDULER_DEPENDENCY_RUN", proof=None
            )
        items[gate_id] = item
    rows = [items[gate_id] for gate_id in order]
    counts = {
        name: sum(row["disposition"] == name for row in rows)
        for name in ("RUN", "REUSE", "SKIP", "BLOCK")
    }
    core = {
        "schema": SCHEMA,
        "marker": "INCREMENTAL_PLAN_COMPACT",
        "plan_id": contract["plan_id"],
        "assurance_level": contract["assurance_level"],
        "changed_paths_sha256": hashlib.sha256(
            canonical_bytes(contract["changed_paths"])
        ).hexdigest(),
        "order": order,
        "items": rows,
        "counts": counts,
        "obligations": order,
        "findings": {
            row["id"]: {"disposition": row["disposition"], "reason": row["reason"]}
            for row in rows
        },
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Plans dependency-aware proof routing; never executes gates or grants publication authority.",
    }
    result = {**core, "plan_sha256": hashlib.sha256(canonical_bytes(core)).hexdigest()}
    if out is not None:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_bytes(result) + b"\n")
    return result


def compare_shadow(
    incremental: dict[str, Any], full: dict[str, Any], *, out: Path | None = None
) -> dict[str, Any]:
    """Compare an incremental plan with a full baseline before any skip is reviewed."""
    if not isinstance(incremental, dict) or not isinstance(full, dict):
        raise SchedulerError("E_SHADOW_INPUT", "both plans must be objects")
    if incremental.get("assurance_level") != full.get("assurance_level"):
        raise SchedulerError(
            "E_SHADOW_ASSURANCE", "incremental and full assurance levels differ"
        )
    inc_obligations = incremental.get("obligations")
    full_obligations = full.get("obligations")
    inc_findings = incremental.get("findings")
    full_findings = full.get("findings")
    if (
        not isinstance(inc_obligations, list)
        or not isinstance(full_obligations, list)
        or not isinstance(inc_findings, dict)
        or not isinstance(full_findings, dict)
    ):
        raise SchedulerError(
            "E_SHADOW_INPUT", "plans must include obligations and findings"
        )
    differences = {
        "obligations_missing": sorted(set(full_obligations) - set(inc_obligations)),
        "obligations_extra": sorted(set(inc_obligations) - set(full_obligations)),
        "findings_changed": sorted(
            key
            for key in set(inc_findings) | set(full_findings)
            if inc_findings.get(key) != full_findings.get(key)
        ),
    }
    equivalent = not any(differences.values())
    core = {
        "schema": "factory.incremental-shadow.v1",
        "marker": "INCREMENTAL_SHADOW_COMPARE",
        "shadow_equivalent": equivalent,
        "differences": differences,
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Compares supplied plans; does not execute either plan or establish production equivalence.",
    }
    result = {
        **core,
        "receipt_sha256": hashlib.sha256(canonical_bytes(core)).hexdigest(),
    }
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


def _pre_pr_inputs(root: Path, manifest: dict) -> tuple[dict, dict, str]:
    from .change_review import ChangeReviewError, _resolve_changed_paths
    from .migration import git_lines
    from .live_feedback import validate_live_manifest
    from .runtime_audit_common import exact_keys, require_str

    exact_keys(
        manifest,
        {"schema", "feature", "base", "head_sha", "schedule", "live", "oracle"},
    )
    if manifest["schema"] != "factory.pre-pr.v1":
        raise ChangeReviewError("PRE_PR_SCHEMA", "unsupported pre-PR manifest")
    require_str(manifest["feature"], "feature", maximum=128)
    base = require_str(manifest["base"], "base", maximum=160)
    head = "".join(git_lines(root, "rev-parse", "HEAD"))
    if manifest["head_sha"] != head:
        raise ChangeReviewError("PRE_PR_HEAD", "candidate HEAD does not match")
    schedule = validate_schedule_manifest(manifest["schedule"])
    live = validate_live_manifest(root, manifest["live"])
    _, changed = _resolve_changed_paths(root, base, None)
    if schedule["changed_paths"] != changed or live["changed_paths"] != changed:
        raise ChangeReviewError(
            "PRE_PR_SCOPE", "both plans must cover the current Git diff"
        )
    gate_ids = {row["id"] for row in schedule["gates"]}
    if gate_ids != {row["id"] for row in live["checks"]}:
        raise ChangeReviewError("PRE_PR_OBLIGATIONS", "check IDs must match every gate")
    return schedule, live, head


def _pre_pr_oracle(root: Path, oracle: dict, contract_sha: str) -> dict:
    from .oracle_firewall import verify_oracle_contract, verify_oracle_challenge_result
    from .runtime_audit_common import exact_keys
    from .senior_assurance import _inside, _file_digest, load_assurance_json

    exact_keys(oracle, {"contract", "challenge", "result"})
    paths = {key: _inside(root, value, key)[0] for key, value in oracle.items()}
    hashes = {key: _file_digest(path, key) for key, path in paths.items()}
    contract = verify_oracle_contract(root, paths["contract"])
    challenge = verify_oracle_challenge_result(
        root, paths["challenge"], paths["result"]
    )
    plan = load_assurance_json(paths["challenge"])
    binding = contract.get("contract", {}).get("contract_sha256")
    matched = (
        binding == contract_sha
        and plan.get("contract", {}).get("contract_sha256") == binding
    )
    return {
        "ok": contract["ok"] and challenge["ok"] and matched,
        "contract": contract,
        "challenge": challenge,
        "input_hashes": hashes,
        "contract_matched": matched,
    }


def _resource_bound(value: object, maximum: int, label: str) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise SchedulerError("E_PRE_PR_BUDGET", f"{label} must be 1..{maximum}")
    return value


def _pre_pr_resource_claim(
    claim: object, gate_id: str, side_effects: bool, cpu: int, memory: int
) -> dict:
    if not isinstance(claim, dict) or set(claim) != {
        "nonmutating",
        "cpu_slots",
        "memory_mib",
    }:
        raise SchedulerError(
            "E_PRE_PR_BUDGET", f"{gate_id} has an invalid resource claim"
        )
    nonmutating = claim["nonmutating"]
    if type(nonmutating) is not bool or (nonmutating and side_effects):
        raise SchedulerError(
            "E_PRE_PR_BUDGET", f"{gate_id} has an unsafe mutation claim"
        )
    return {
        "nonmutating": nonmutating,
        "cpu_slots": _resource_bound(claim["cpu_slots"], cpu, f"{gate_id}.cpu_slots"),
        "memory_mib": _resource_bound(
            claim["memory_mib"], memory, f"{gate_id}.memory_mib"
        ),
    }


def _pre_pr_execution_budget(value: object, schedule: dict) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "cpu_slots",
        "memory_mib",
        "gates",
    }:
        raise SchedulerError("E_PRE_PR_BUDGET", "expected CPU, memory and gate claims")
    cpu = _resource_bound(value["cpu_slots"], 8, "cpu_slots")
    memory = _resource_bound(value["memory_mib"], 2**31 - 1, "memory_mib")
    effects = {gate["id"]: gate["side_effects"] for gate in schedule["gates"]}
    claims = value["gates"]
    if not isinstance(claims, dict) or set(claims).difference(effects):
        raise SchedulerError(
            "E_PRE_PR_BUDGET", "gate claims must name known obligations"
        )
    return {
        "cpu_slots": cpu,
        "memory_mib": memory,
        "gates": {
            key: _pre_pr_resource_claim(claim, key, effects[key], cpu, memory)
            for key, claim in claims.items()
        },
    }


def _pre_pr_dependencies_pass(item: dict, rows: dict[str, dict]) -> bool:
    return all(
        dep in rows and rows[dep]["state"] == "PASS" for dep in item["depends_on"]
    )


def _pre_pr_dependencies_current(
    root: Path, item: dict, rows: dict, schedule: dict
) -> bool:
    pending = list(item["depends_on"])
    seen = set()
    while pending:
        dep = pending.pop()
        if dep in seen:
            continue
        seen.add(dep)
        routing = rows[dep]["routing"]
        if routing["disposition"] == "REUSE" and not _pre_pr_reuse_current(
            root, routing, schedule
        ):
            return False
        pending.extend(routing["depends_on"])
    return True


def _pre_pr_dispatch_check(
    before_dispatch: Callable[[str], bool] | None,
) -> Callable[[str], str | None]:
    lock = Lock()

    def check(gate_id: str) -> str | None:
        if before_dispatch is None:
            return None
        with lock:
            try:
                return None if before_dispatch(gate_id) is True else "DISPATCH_REVOKED"
            except Exception:
                return "DISPATCH_CHECK_FAILED"

    return check


def _pre_pr_gate_row(
    item: dict,
    *,
    root: Path,
    checks: dict,
    live: dict,
    execute: bool,
    source: str,
    schedule: dict,
    rows: dict[str, dict],
    recheck_dependencies: bool,
    dispatch_check: Callable[[str], str | None],
) -> dict:
    from .senior_assurance import _source_digest

    row = {"id": item["id"], "routing": item, "state": "BLOCKED"}
    if not _pre_pr_dependencies_pass(item, rows):
        return {**row, "reason": "DEPENDENCY_FAILED"}
    if _source_digest(root)[0] != source:
        return {**row, "reason": "SOURCE_CHANGED"}
    if recheck_dependencies and not _pre_pr_dependencies_current(
        root, item, rows, schedule
    ):
        return {**row, "reason": "DEPENDENCY_PROOF_CHANGED"}
    if item["disposition"] == "REUSE" and not _pre_pr_reuse_current(
        root, item, schedule
    ):
        item = {**item, "disposition": "BLOCK", "reason": "REUSE_CHANGED"}
    if execute and item["disposition"] == "RUN":
        denial = dispatch_check(item["id"])
        if denial is not None:
            return {**row, "reason": denial}
    row.update(_pre_pr_gate(root, item, checks[item["id"]], live, execute, source))
    return row


def _pre_pr_wave(items: list[dict], rows: dict[str, dict], budget: dict) -> list[dict]:
    """Take a contiguous ready wave, leaving all undeclared work serial."""
    wave = []
    cpu = memory = 0
    for item in items:
        claim = budget["gates"].get(item["id"])
        if not claim or not claim["nonmutating"] or item["disposition"] != "RUN":
            break
        if not _pre_pr_dependencies_pass(item, rows):
            break
        cpu += claim["cpu_slots"]
        memory += claim["memory_mib"]
        if cpu > budget["cpu_slots"] or memory > budget["memory_mib"]:
            break
        wave.append(item)
    return wave or items[:1]


def _pre_pr_wave_evidence(
    wave: list[dict], completed: list[dict], budget: dict, elapsed_ns: int
) -> dict | None:
    attempted = [row["id"] for row in completed if _pre_pr_attempted(row)]
    if not attempted:
        return None
    claims = [budget["gates"].get(item["id"], {}) for item in wave]
    return {
        "mode": "parallel" if len(wave) > 1 else "serial",
        "admitted_gates": [item["id"] for item in wave],
        "attempted_gates": attempted,
        "reserved_cpu_slots": sum(item.get("cpu_slots", 0) for item in claims),
        "reserved_memory_mib": sum(item.get("memory_mib", 0) for item in claims),
        "wall_ns": elapsed_ns,
    }


def _pre_pr_attempted(row: dict) -> bool:
    return row.get("live_receipt", {}).get("mode") == "execute"


def _pre_pr_gate_rows(
    root: Path,
    plan: dict,
    live: dict,
    execute: bool,
    source: str,
    schedule: dict,
    *,
    budget: dict | None = None,
    before_dispatch: Callable[[str], bool] | None = None,
) -> tuple[list[dict], list[dict]]:
    checks = {row["id"]: row for row in live["checks"]}
    rows: dict[str, dict] = {}
    waves: list[dict] = []
    items = plan["items"]
    run = partial(
        _pre_pr_gate_row,
        root=root,
        checks=checks,
        live=live,
        execute=execute,
        source=source,
        schedule=schedule,
        rows=rows,
        recheck_dependencies=budget is not None,
        dispatch_check=_pre_pr_dispatch_check(before_dispatch),
    )
    position = 0
    while position < len(items):
        started = monotonic_ns()
        remaining = items[position:]
        wave = (
            _pre_pr_wave(remaining, rows, budget)
            if execute and budget
            else remaining[:1]
        )
        if len(wave) == 1:
            completed = [run(wave[0])]
        else:
            with ThreadPoolExecutor(max_workers=len(wave)) as executor:
                completed = list(executor.map(run, wave))
        rows.update((row["id"], row) for row in completed)
        if budget is not None:
            evidence = _pre_pr_wave_evidence(
                wave, completed, budget, monotonic_ns() - started
            )
            if evidence:
                waves.append(evidence)
        position += len(wave)
    return list(rows.values()), waves


def _pre_pr_execution_evidence(
    rows: list[dict],
    waves: list[dict],
    budget: dict | None,
    execute: bool,
    wall_ns: int,
    stable: bool,
) -> dict:
    mode = "resource_admitted" if budget is not None else "serial"
    return {
        "mode": mode if execute else "plan",
        "budget": budget,
        "wall_ns": wall_ns,
        "waves": waves,
        "runs_attempted": sum(_pre_pr_attempted(row) for row in rows),
        "completed_checks": sum(row["state"] == "PASS" for row in rows),
        "verified_reuse": sum(
            stable and row["reason"] == "VERIFIED_REUSE" for row in rows
        ),
        "peak_reserved_cpu_slots": max(
            (row["reserved_cpu_slots"] for row in waves), default=0
        ),
        "peak_reserved_memory_mib": max(
            (row["reserved_memory_mib"] for row in waves), default=0
        ),
        "claim_boundary": "Gate wall time and per-invocation host reservations for declared checks only; no measured process resources or kernel isolation.",
    }


def _pre_pr_gate(
    root: Path, item: dict, check: dict, live: dict, execute: bool, source: str
) -> dict:
    from .live_feedback import run_live_feedback
    from .change_review import _sha

    if item["disposition"] == "REUSE":
        return {"state": "PASS", "reason": "VERIFIED_REUSE", "proof": item["proof"]}
    if item["disposition"] != "RUN":
        return {"state": "BLOCKED", "reason": item["reason"]}
    # A dependency can require execution even when this check's own paths did not
    # change. Force only this scheduled obligation through the existing runner.
    observed = _pre_pr_executable_observation(check)
    executable = _sha(observed) if observed else None
    pinned = (
        {**check, "argv": [observed["path"], *check["argv"][1:]]} if observed else check
    )
    forced = {**live, "checks": [pinned], "changed_paths": check["paths"]}
    receipt = run_live_feedback(root, forced, execute=execute)
    state = receipt["checks"][0]["state"]
    if receipt["source_sha256"] != source or executable != _pre_pr_executable_identity(
        check
    ):
        state = "BLOCKED"
    return {"state": state, "reason": "SCHEDULED_EXECUTION", "live_receipt": receipt}


def run_pre_pr(
    root: Path,
    manifest: dict,
    *,
    execute: bool = False,
    execution_budget: dict | None = None,
    before_dispatch: Callable[[str], bool] | None = None,
) -> dict:
    """Reconcile local evidence; only a trusted caller may opt into proof waves.

    The budget is host-supplied, never part of the candidate manifest. Resource
    claims reserve CPU slots and memory MiB; they are not process limits.
    The optional trusted pre-dispatch guard is serialized but may run on worker
    threads. Only an explicit true result authorizes the corresponding RUN.
    """
    from .github_proof_review import render_github_proof_review
    from .change_review import _sha, review_change
    from .senior_assurance import _source_digest
    from .verification import verify_feature

    root = Path(root).resolve()
    schedule, live, head = _pre_pr_inputs(root, manifest)
    schedule = _pre_pr_observed_schedule(schedule, live)
    budget = _pre_pr_execution_budget(execution_budget, schedule)
    _pre_pr_validate_dispatch_hook(before_dispatch)
    source = _source_digest(root)[0]
    oracle = _pre_pr_oracle(root, manifest["oracle"], live["contract_sha256"])
    plan = plan_incremental(root, schedule)
    _pre_pr_reconsider_exact_reuse(root, plan, schedule)
    _pre_pr_bind_reuse(plan, schedule, live)
    proof_snapshots = _pre_pr_proof_snapshots(root, plan, schedule, live)
    started = monotonic_ns()
    rows, waves = _pre_pr_gate_rows(
        root,
        plan,
        live,
        execute and oracle["ok"],
        source,
        schedule,
        budget=budget,
        before_dispatch=before_dispatch,
    )
    wall_ns = monotonic_ns() - started
    verification = verify_feature(root, manifest["feature"], strict_release=True)
    review = review_change(
        root, base=manifest["base"], changed=schedule["changed_paths"]
    )
    final_oracle = _pre_pr_oracle(root, manifest["oracle"], live["contract_sha256"])
    _, _, final_head = _pre_pr_inputs(root, manifest)
    reuse_stable = all(
        _pre_pr_reuse_current(root, row["routing"], schedule)
        for row in rows
        if row["routing"]["disposition"] == "REUSE"
    )
    final_verification = verify_feature(root, manifest["feature"], strict_release=True)
    stable = (
        source == _source_digest(root)[0]
        and head == final_head
        and oracle == final_oracle
        and reuse_stable
        and verification["release_contract"] == final_verification["release_contract"]
    )
    execution = _pre_pr_execution_evidence(
        rows, waves, budget, execute, wall_ns, stable
    )
    conditions = {
        "stable": stable,
        "oracle_verified": oracle["ok"],
        "feature_verified": verification["shippable"],
        "final_feature_verified": final_verification["shippable"],
        "same_contract": verification["release_contract"].get("oracle_contract_sha256")
        == live["contract_sha256"],
        "obligations_satisfied": all(row["state"] == "PASS" for row in rows),
    }
    if execute and all(conditions.values()):
        _pre_pr_record_proofs(root, rows, schedule, live, proof_snapshots)
    core = {
        "schema": "factory.pre-pr-receipt.v1",
        "state": "PASS" if all(conditions.values()) else "BLOCKED",
        "conditions": conditions,
        "manifest_sha256": _sha(manifest),
        "head_sha": head,
        "source_sha256": source,
        "source_stable": stable,
        "mode": "execute" if execute else "plan",
        "plan": plan,
        "checks": rows,
        "execution": execution,
        "oracle": oracle,
        "feature_verification": verification,
        "final_feature_verification": final_verification,
        "review": review,
        "github_payload": render_github_proof_review(review, head),
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Local declared-obligation reconciliation only; oracle declared independence is not authenticated execution, and no merge or release is authorized.",
    }
    return {**core, "receipt_sha256": _sha(core)}


def _pre_pr_validate_dispatch_hook(before_dispatch: object) -> None:
    """Require a callable hook before any scheduled gate can be admitted."""
    if before_dispatch is not None and not callable(before_dispatch):
        raise SchedulerError(
            "E_PRE_PR_DISPATCH", "the trusted dispatch check must be callable"
        )


def _pre_pr_observed_schedule(schedule: dict, live: dict) -> dict:
    """Bind host observations without mutating caller declarations."""
    checks = {row["id"]: row for row in live["checks"]}
    schedule = {**schedule, "gates": [dict(row) for row in schedule["gates"]]}
    for gate in schedule["gates"]:
        if gate["proof"]:
            proof = gate["proof"]
            gate["proof"] = {
                **proof,
                "toolchain": {
                    **proof.get("toolchain", {}),
                    "pre_pr_executable_sha256": _pre_pr_executable_identity(
                        checks[gate["id"]]
                    )
                    or "unverifiable",
                },
            }
    return schedule


def _pre_pr_reconsider_exact_reuse(root: Path, plan: dict, schedule: dict) -> None:
    """An unchanged Git diff may still have an exact current proof."""
    gates = {row["id"]: row for row in schedule["gates"]}
    for item in plan["items"]:
        proof = gates[item["id"]]["proof"]
        if item["reason"] != "DEPENDENCY_CLOSURE_CHANGED" or not proof:
            continue
        if proof.get("assurance_level") not in (None, schedule["assurance_level"]):
            continue
        checked = evaluate_proofs(
            root,
            {"schema": "factory.proof-request.v1", "gates": [proof]},
            changed_paths=schedule["changed_paths"],
        )["items"][0]
        if checked["disposition"] == "REUSE":
            item.update(
                disposition="REUSE",
                reason=checked["reason"],
                proof={key: checked[key] for key in ("proof_key", "receipt_sha256")},
            )


def _pre_pr_proof_snapshots(root: Path, plan: dict, schedule: dict, live: dict) -> dict:
    """Capture exact declared facts before execution, including existing outputs."""
    from .proof_reuse import ProofReuseError, proof_facts

    snapshots = {}
    gates = {row["id"]: row for row in schedule["gates"]}
    checks = {row["id"]: row for row in live["checks"]}
    for item in plan["items"]:
        proof = gates[item["id"]]["proof"]
        if (
            item["disposition"] != "RUN"
            or not proof
            or proof.get("read_only") is not True
        ):
            continue
        if not _pre_pr_proof_matches(item, proof, checks[item["id"]], schedule, live):
            continue
        try:
            snapshots[item["id"]] = (
                proof_facts(root, proof),
                proof_facts(root, {**proof, "inputs": proof.get("outputs")}),
                _pre_pr_executable_identity(checks[item["id"]]),
            )
            if snapshots[item["id"]][-1] is None or snapshots[item["id"]][
                -1
            ] != proof.get("toolchain", {}).get("pre_pr_executable_sha256"):
                del snapshots[item["id"]]
        except ProofReuseError:
            # Incomplete declarations cannot manufacture a reusable observation.
            continue
    return snapshots


def _pre_pr_record_proofs(
    root: Path, rows: list[dict], schedule: dict, live: dict, snapshots: dict
) -> None:
    from .proof_reuse import ProofReuseError, record_proof

    current = _pre_pr_proof_snapshots(
        root, {"items": [row["routing"] for row in rows]}, schedule, live
    )
    gates = {row["id"]: row for row in schedule["gates"]}
    for row in rows:
        identifier = row["id"]
        receipt = row.get("live_receipt", {})
        if (
            identifier not in snapshots
            or current.get(identifier) != snapshots[identifier]
            or row["state"] != "PASS"
            or receipt.get("mode") != "execute"
        ):
            continue
        observation = receipt["checks"][0]
        duration = observation.get("duration_ms")
        if observation.get("state") != "PASS" or not isinstance(duration, (int, float)):
            continue
        try:
            record_proof(
                root, gates[identifier]["proof"], elapsed_ms=max(1, int(duration))
            )
        except ProofReuseError:
            # Never overwrite an existing (including corrupt) receipt implicitly.
            continue


def _pre_pr_proof_matches(
    item: dict, proof: dict, check: dict, schedule: dict, live: dict
) -> bool:
    from .change_review import _sha

    return (
        bool(item["dependency_paths"])
        and proof.get("assurance_level") in (None, schedule["assurance_level"])
        and proof.get("command") == check["argv"]
        and proof.get("environment") == check["env"]
        and check["expected_exit"] == 0
        and set(item["dependency_paths"]).issubset(proof.get("inputs", []))
        and proof.get("toolchain", {}).get("pre_pr_check_sha256")
        == _sha(
            {
                "check": check,
                "contract_sha256": live["contract_sha256"],
                "assurance_level": schedule["assurance_level"],
            }
        )
    )


def _pre_pr_bind_reuse(plan: dict, schedule: dict, live: dict) -> None:
    from .change_review import _sha

    checks = {row["id"]: row for row in live["checks"]}
    gates = {row["id"]: row for row in schedule["gates"]}
    for item in plan["items"]:
        if item["disposition"] != "REUSE":
            continue
        check = checks[item["id"]]
        proof = gates[item["id"]]["proof"]
        matches = _pre_pr_proof_matches(item, proof, check, schedule, live)
        if not matches:
            item.update(disposition="RUN", reason="CHECK_PROOF_MISMATCH", proof=None)
    by_id = {row["id"]: row for row in plan["items"]}
    for item in plan["items"]:
        if item["disposition"] == "REUSE" and any(
            by_id[dep]["disposition"] == "RUN" for dep in item["depends_on"]
        ):
            item.update(disposition="RUN", reason="DEPENDENCY_RECHECK", proof=None)
    # Rebuild the plan hash after this conservative execution refinement.
    plan["counts"] = {
        name: sum(row["disposition"] == name for row in plan["items"])
        for name in ("RUN", "REUSE", "SKIP", "BLOCK")
    }
    plan["findings"] = {
        row["id"]: {"disposition": row["disposition"], "reason": row["reason"]}
        for row in plan["items"]
    }
    plan["plan_sha256"] = _sha(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )


def _pre_pr_reuse_current(root: Path, item: dict, schedule: dict) -> bool:
    from .proof_reuse import evaluate_proofs

    gate = next(row for row in schedule["gates"] if row["id"] == item["id"])
    proof = gate["proof"]
    observed = _pre_pr_executable_identity(
        {"argv": proof["command"], "env": proof.get("environment", {})}
    )
    if (
        not observed
        or proof.get("toolchain", {}).get("pre_pr_executable_sha256") != observed
    ):
        return False
    checked = evaluate_proofs(
        root,
        {
            "schema": "factory.proof-request.v1",
            "gates": [gate["proof"]],
        },
        changed_paths=schedule["changed_paths"],
    )["items"][0]
    return checked["disposition"] == "REUSE" and all(
        checked.get(key) == item["proof"].get(key)
        for key in ("proof_key", "receipt_sha256")
    )


def _pre_pr_executable_identity(check: dict) -> str | None:
    from .change_review import _sha

    observed = _pre_pr_executable_observation(check)
    return _sha(observed) if observed else None


def _pre_pr_executable_observation(check: dict) -> dict | None:
    """Observe runner resolution and stable native executable bytes, without execution."""
    import shutil
    from .proof_reuse import ProofReuseError, _stable_file_read
    from .senior_assurance import _process_environment

    argv = check["argv"]
    # Launchers/shells introduce another executable not established by argv[0].
    if Path(argv[0]).stem.lower() in {
        "py",
        "env",
        "cmd",
        "powershell",
        "pwsh",
        "sh",
        "bash",
        "rtk",
        "uv",
    } or any(arg in {"&&", "||", ";", "|"} for arg in argv):
        return None
    try:
        resolved = shutil.which(argv[0], path=_process_environment(check)["PATH"])
        if not resolved or not Path(resolved).is_absolute():
            return None
        path = Path(resolved).resolve(strict=True)
        identity, digest = _stable_file_read(path, label="pre-PR executable")
        # Script/shebang launch chains are not a single bound native executable.
        with path.open("rb") as handle:
            magic = handle.read(4)
        if not (
            magic.startswith(b"MZ")
            or magic
            in {
                b"\x7fELF",
                b"\xcf\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xca\xfe\xba\xbe",
            }
        ):
            return None
        if (identity, digest, path) != (
            *_stable_file_read(path, label="pre-PR executable"),
            Path(resolved).resolve(strict=True),
        ):
            return None
        return {"path": str(path), "identity": identity, "sha256": digest}
    except (OSError, ValueError, ProofReuseError):
        return None
