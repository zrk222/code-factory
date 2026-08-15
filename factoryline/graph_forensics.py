"""Deterministic semantic forensics for graph execution lineage.

The module verifies supplied, hash-sealed state lineage receipts and compares
two runs.  It never invokes a graph, mutates a checkpoint, or repeats a side
effect.  Recovery output is a review plan, not execution authority.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any
import hashlib
import json
import re
import tempfile


LINEAGE_SCHEMA = "factory.graph-lineage.v1"
FORENSICS_SCHEMA = "factory.graph-forensics.v1"
MAX_LINEAGE_BYTES = 2_097_152
MAX_STEPS = 2_000
MAX_STATE_ITEMS = 400
_SHA = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITY = {
    "execution": False, "checkpoint_mutation": False, "approval": False,
    "publication": False, "deployment": False, "signing": False,
    "messaging": False, "credential": False, "connector": False,
}


class GraphForensicsError(ValueError):
    """A closed, user-correctable lineage contract failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bounded(value: object, field: str, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", f"{field} must be non-empty and at most {maximum} characters")
    return value.strip()


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", f"{field} must be a lowercase SHA-256 digest")
    return value


def _items(raw: object, field: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > MAX_STATE_ITEMS or any(not isinstance(item, dict) for item in raw):
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", f"{field} must be a list of at most {MAX_STATE_ITEMS} objects")
    return list(raw)


def _load(path: Path) -> dict[str, Any]:
    candidate = Path(path)
    try:
        if not candidate.is_file() or candidate.stat().st_size > MAX_LINEAGE_BYTES:
            raise GraphForensicsError("GRAPH_LINEAGE_UNREADABLE", "lineage file is missing or too large")
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except GraphForensicsError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GraphForensicsError("GRAPH_LINEAGE_UNREADABLE", "lineage file is not readable canonical JSON") from exc
    if not isinstance(value, dict):
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", "lineage root must be one object")
    return value


def _nonnegative(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", f"{field} must be a non-negative integer")
    return value


def _normalize_read(item: dict[str, Any], field: str) -> dict[str, Any]:
    return {"key": _bounded(item.get("key"), f"{field}.key"), "version": _nonnegative(item.get("version"), "read version"), "sha256": _hash(item.get("sha256"), "read.sha256")}


def _normalize_write(item: dict[str, Any], field: str) -> dict[str, Any]:
    previous = _nonnegative(item.get("previous_version"), "write previous_version")
    version = _nonnegative(item.get("version"), "write version")
    if version <= previous:
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", "write version must advance previous_version")
    mode = item.get("mode", "replace")
    if mode not in {"replace", "reduce", "delete"}:
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", "write mode must be replace, reduce, or delete")
    reducer = item.get("reducer")
    return {
        "key": _bounded(item.get("key"), f"{field}.key"), "previous_version": previous, "version": version,
        "before_sha256": _hash(item.get("before_sha256"), "write.before_sha256"),
        "after_sha256": _hash(item.get("after_sha256"), "write.after_sha256"), "mode": mode,
        "reducer": _bounded(reducer, "write.reducer") if reducer is not None else None,
    }


def _normalize_evidence(item: dict[str, Any], _field: str) -> dict[str, str]:
    return {"path": _bounded(item.get("path"), "evidence.path", 320), "sha256": _hash(item.get("sha256"), "evidence.sha256")}


def _normalize_effect(item: dict[str, Any], _field: str) -> dict[str, str]:
    return {"effect_id": _bounded(item.get("effect_id"), "side_effect.effect_id"), "idempotency_key": _bounded(item.get("idempotency_key"), "side_effect.idempotency_key", 240), "status": _bounded(item.get("status"), "side_effect.status", 40)}


def _normalize_collection(raw: object, field: str, normalizer: Any, errors: list[str]) -> list[dict[str, Any]]:
    try:
        items = _items(raw, field)
    except GraphForensicsError as exc:
        errors.append(str(exc))
        return []
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        try:
            normalized.append(normalizer(item, f"{field}[{index}]"))
        except GraphForensicsError as exc:
            errors.append(str(exc))
    return normalized


def _normalize_step(raw: object, offset: int, seen: set[int], errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        errors.append(f"steps[{offset}] must be an object")
        return None
    try:
        sequence = _nonnegative(raw.get("sequence"), f"steps[{offset}].sequence")
        superstep = _nonnegative(raw.get("superstep"), f"steps[{offset}].superstep")
        if sequence < 1 or sequence in seen:
            raise GraphForensicsError("GRAPH_LINEAGE_INVALID", f"steps[{offset}].sequence must be a unique positive integer")
        node_id = _bounded(raw.get("node_id"), f"steps[{offset}].node_id")
        checkpoint_id = _bounded(raw.get("checkpoint_id"), f"steps[{offset}].checkpoint_id", 240)
    except GraphForensicsError as exc:
        errors.append(str(exc))
        return None
    seen.add(sequence)
    reads = _normalize_collection(raw.get("reads", []), f"steps[{offset}].reads", _normalize_read, errors)
    writes = _normalize_collection(raw.get("writes", []), f"steps[{offset}].writes", _normalize_write, errors)
    evidence = _normalize_collection(raw.get("evidence", []), f"steps[{offset}].evidence", _normalize_evidence, errors)
    effects = _normalize_collection(raw.get("side_effects", []), f"steps[{offset}].side_effects", _normalize_effect, errors)
    decision = raw.get("decision")
    try:
        if not isinstance(decision, dict):
            raise GraphForensicsError("GRAPH_LINEAGE_INVALID", f"steps[{offset}].decision must be an object")
        normalized_decision = {"route": _bounded(decision.get("route"), "decision.route"), "reason": _bounded(decision.get("reason"), "decision.reason", 500)}
    except GraphForensicsError as exc:
        errors.append(str(exc))
        normalized_decision = {"route": "invalid", "reason": "invalid"}
    return {
        "sequence": sequence, "superstep": superstep, "node_id": node_id, "checkpoint_id": checkpoint_id,
        "reads": sorted(reads, key=lambda item: item["key"]), "writes": sorted(writes, key=lambda item: item["key"]),
        "evidence": sorted(evidence, key=lambda item: item["path"]),
        "side_effects": sorted(effects, key=lambda item: (item["effect_id"], item["idempotency_key"])), "decision": normalized_decision,
    }


def _lineage_steps(value: dict[str, Any], errors: list[str]) -> list[object]:
    steps = value.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        errors.append(f"steps must contain 1..{MAX_STEPS} objects")
        return []
    return steps


def _validate_identity(value: dict[str, Any], errors: list[str]) -> None:
    for field in ("run_id", "graph_id"):
        try:
            _bounded(value.get(field), field)
        except GraphForensicsError as exc:
            errors.append(str(exc))


def verify_graph_lineage(path: Path) -> dict[str, Any]:
    """Verify schema, state-version contracts, ordering, and content hash."""
    value = _load(path)
    errors: list[str] = []
    if value.get("schema") != LINEAGE_SCHEMA:
        errors.append(f"schema must be {LINEAGE_SCHEMA}")
    _validate_identity(value, errors)
    steps = _lineage_steps(value, errors)
    seen_sequences: set[int] = set()
    normalized_steps = [step for offset, raw in enumerate(steps) if (step := _normalize_step(raw, offset, seen_sequences, errors)) is not None]
    normalized_steps.sort(key=lambda item: item["sequence"])
    if normalized_steps and [item["sequence"] for item in normalized_steps] != list(range(1, len(normalized_steps) + 1)):
        errors.append("step sequences must be contiguous from 1")
    core = {
        "schema": LINEAGE_SCHEMA,
        "run_id": value.get("run_id"),
        "graph_id": value.get("graph_id"),
        "steps": normalized_steps,
    }
    calculated = _digest(core)
    if value.get("lineage_sha256") != calculated:
        errors.append("lineage_sha256 does not match canonical lineage content")
    marker = "GRAPH_LINEAGE_VERIFIED" if not errors else "GRAPH_LINEAGE_INVALID"
    return {
        "schema": "factory.graph-lineage-verification.v1", "valid": not errors,
        "errors": errors, "run_id": value.get("run_id"), "graph_id": value.get("graph_id"),
        "lineage_sha256": calculated, "steps": normalized_steps,
        "marker": marker,
        "markers": [marker, "GRAPH_LINEAGE_BOUNDS_ENFORCED"],
    }


def _steps_for_seal(steps: list[object]) -> list[dict[str, Any]]:
    if not steps or len(steps) > MAX_STEPS:
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", f"steps must contain 1..{MAX_STEPS} objects")
    errors: list[str] = []
    seen: set[int] = set()
    normalized = [step for offset, raw in enumerate(steps) if (step := _normalize_step(raw, offset, seen, errors)) is not None]
    normalized.sort(key=lambda item: item["sequence"])
    if [item["sequence"] for item in normalized] != list(range(1, len(normalized) + 1)):
        errors.append("step sequences must be contiguous from 1")
    if errors:
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", "; ".join(errors))
    return normalized


def seal_graph_lineage(run_id: str, graph_id: str, steps_path: Path, out: Path) -> dict[str, Any]:
    """Validate supplied step objects and atomically write a sealed lineage receipt."""
    try:
        source = json.loads(Path(steps_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GraphForensicsError("GRAPH_LINEAGE_STEPS_UNREADABLE", "steps input must be readable JSON") from exc
    steps = source.get("steps") if isinstance(source, dict) else source
    if not isinstance(steps, list):
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", "steps input must be a list or an object containing steps")
    core = {"schema": LINEAGE_SCHEMA, "run_id": _bounded(run_id, "run_id"), "graph_id": _bounded(graph_id, "graph_id"), "steps": _steps_for_seal(steps)}
    payload = {**core, "lineage_sha256": _digest(core)}
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp", delete=False) as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            temporary = Path(handle.name)
        verification = verify_graph_lineage(temporary)
        if not verification["valid"]:
            raise GraphForensicsError("GRAPH_LINEAGE_INVALID", "; ".join(verification["errors"]))
        temporary.replace(destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return {**verification, "path": str(destination), "marker": "GRAPH_LINEAGE_SEALED"}


def mission_history_steps(history: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a verified native mission event chain into semantic control-state lineage."""
    if history.get("schema") != "factory.mission.graph.history.v1" or not isinstance(history.get("events"), list):
        raise GraphForensicsError("GRAPH_LINEAGE_HISTORY_INVALID", "mission history schema or events are invalid")
    steps: list[dict[str, Any]] = []
    for offset, event in enumerate(history["events"], 1):
        if not isinstance(event, dict) or event.get("version") != offset:
            raise GraphForensicsError("GRAPH_LINEAGE_HISTORY_INVALID", "mission events must be contiguous objects")
        source = _bounded(event.get("source_state"), "event.source_state")
        target = _bounded(event.get("target_state"), "event.target_state")
        event_name = _bounded(event.get("event"), "event.event")
        receipt = event.get("receipt")
        if not isinstance(receipt, dict):
            raise GraphForensicsError("GRAPH_LINEAGE_HISTORY_INVALID", "mission event receipt is missing")
        receipt_path = _bounded(receipt.get("path"), "event.receipt.path", 320)
        receipt_sha = _hash(receipt.get("sha256"), "event.receipt.sha256")
        event_sha = _hash(event.get("event_sha256"), "event.event_sha256")
        previous_tip = event.get("previous_sha256")
        if not previous_tip or previous_tip == "GENESIS":
            previous_tip = _digest("GENESIS")
        previous_tip = _hash(previous_tip, "event.previous_sha256")
        steps.append({
            "sequence": offset,
            "superstep": offset,
            "node_id": f"mission-event:{event_name}",
            "checkpoint_id": event_sha,
            "reads": [
                {"key": "mission_state", "version": offset - 1, "sha256": _digest(source)},
                {"key": "event_tip", "version": offset - 1, "sha256": previous_tip},
            ],
            "writes": [
                {"key": "mission_state", "previous_version": offset - 1, "version": offset, "before_sha256": _digest(source), "after_sha256": _digest(target), "mode": "replace", "reducer": None},
                {"key": "event_tip", "previous_version": offset - 1, "version": offset, "before_sha256": previous_tip, "after_sha256": event_sha, "mode": "replace", "reducer": None},
            ],
            "evidence": [{"path": receipt_path, "sha256": receipt_sha}],
            "side_effects": [],
            "decision": {"route": target, "reason": f"guarded mission event {event_name}"},
        })
    if not steps:
        raise GraphForensicsError("GRAPH_LINEAGE_HISTORY_INVALID", "mission history contains no events")
    return steps


def seal_mission_graph_lineage(mission_path: Path, root: Path, run_id: str, out: Path) -> dict[str, Any]:
    """Export the verified Code Factory mission ledger as a sealed lineage receipt."""
    from .mission_graph import mission_graph_history

    history = mission_graph_history(mission_path, root)
    steps = mission_history_steps(history)
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    step_file: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, prefix=".mission-steps.", suffix=".json", delete=False) as handle:
            json.dump(steps, handle, ensure_ascii=False, sort_keys=True)
            step_file = Path(handle.name)
        result = seal_graph_lineage(run_id, str(history["mission_id"]), step_file, destination)
    finally:
        if step_file is not None and step_file.exists():
            step_file.unlink()
    return {**result, "marker": "GRAPH_LINEAGE_MISSION_LEDGER_EXPORTED", "mission_id": history["mission_id"], "chain_head": history["chain_head"]}


def _step_fingerprint(step: dict[str, Any]) -> str:
    return _digest({key: step[key] for key in ("node_id", "reads", "writes", "evidence", "side_effects", "decision")})


def _anomalies(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    latest: dict[str, int] = {}
    effects: dict[str, tuple[str, int]] = {}
    by_superstep: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for step in steps:
        by_superstep[step["superstep"]].append(step)
    for superstep in sorted(by_superstep):
        group = by_superstep[superstep]
        writers: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
        for step in group:
            for read in step["reads"]:
                expected = latest.get(read["key"], read["version"])
                if read["version"] < expected:
                    findings.append({"code": "STALE_READ", "severity": "critical", "sequence": step["sequence"], "node_id": step["node_id"], "state_key": read["key"], "observed_version": read["version"], "latest_version": expected})
            for write in step["writes"]:
                writers[write["key"]].append((step, write))
                expected = latest.get(write["key"], write["previous_version"])
                if write["previous_version"] < expected:
                    findings.append({"code": "STALE_WRITE", "severity": "critical", "sequence": step["sequence"], "node_id": step["node_id"], "state_key": write["key"], "observed_version": write["previous_version"], "latest_version": expected})
            for effect in step["side_effects"]:
                previous = effects.get(effect["effect_id"])
                if previous and effect["status"] == "completed":
                    findings.append({"code": "DUPLICATE_SIDE_EFFECT", "severity": "critical", "sequence": step["sequence"], "node_id": step["node_id"], "effect_id": effect["effect_id"], "first_sequence": previous[1], "idempotency_key_changed": previous[0] != effect["idempotency_key"]})
                effects.setdefault(effect["effect_id"], (effect["idempotency_key"], step["sequence"]))
        for key, entries in sorted(writers.items()):
            if len(entries) > 1:
                reducers = {write.get("reducer") for _, write in entries}
                modes = {write["mode"] for _, write in entries}
                if modes != {"reduce"} or len(reducers) != 1 or None in reducers:
                    findings.append({"code": "PARALLEL_WRITE_CONFLICT", "severity": "critical", "superstep": superstep, "state_key": key, "writers": sorted(step["node_id"] for step, _ in entries), "reducers": sorted(str(item) for item in reducers)})
            latest[key] = max(write["version"] for _, write in entries)
    return sorted(findings, key=lambda item: (item.get("sequence", 0), item["code"], item.get("state_key", "")))


def _causal_cone(steps: list[dict[str, Any]], start: int, changed_keys: set[str]) -> tuple[list[int], list[str]]:
    impacted_sequences: list[int] = []
    impacted_nodes: list[str] = []
    keys = set(changed_keys)
    for step in steps[start:]:
        reads = {item["key"] for item in step["reads"]}
        writes = {item["key"] for item in step["writes"]}
        if reads & keys or writes & keys:
            impacted_sequences.append(step["sequence"])
            impacted_nodes.append(step["node_id"])
            keys.update(writes)
    return impacted_sequences, list(dict.fromkeys(impacted_nodes))


def _divergence_index(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> int | None:
    for index in range(max(len(left), len(right))):
        if index >= len(left) or index >= len(right) or _step_fingerprint(left[index]) != _step_fingerprint(right[index]):
            return index
    return None


def _recovery_analysis(left: list[dict[str, Any]], right: list[dict[str, Any]], index: int | None) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if index is None:
        return None, {"action": "no_recovery_required", "reason": "verified semantic steps are identical", "checkpoint_id": None, "rerun_nodes": [], "invalidated_evidence": [], "requires_human_approval": True, "execute": False}
    baseline_step = left[index] if index < len(left) else None
    candidate_step = right[index] if index < len(right) else None
    changed_keys = {item["key"] for step in (baseline_step, candidate_step) if step for item in [*step["reads"], *step["writes"]]}
    sequences, nodes = _causal_cone(right, index, changed_keys)
    evidence = sorted({item["path"] for step in right if step["sequence"] in sequences for item in step["evidence"]})
    prior = right[index - 1] if index > 0 and index - 1 < len(right) else None
    divergence = {
        "index": index, "sequence": candidate_step["sequence"] if candidate_step else None,
        "baseline_node": baseline_step["node_id"] if baseline_step else None,
        "candidate_node": candidate_step["node_id"] if candidate_step else None,
        "changed_state_keys": sorted(changed_keys), "causal_sequences": sequences, "causal_nodes": nodes,
    }
    recovery = {
        "action": "review_counterfactual_fork", "reason": "fork before the first semantic divergence and rerun only its causal cone",
        "checkpoint_id": prior["checkpoint_id"] if prior else None, "rerun_nodes": nodes, "invalidated_evidence": evidence,
        "requires_human_approval": True, "execute": False,
    }
    return divergence, recovery


def graph_forensics(baseline_path: Path, candidate_path: Path) -> dict[str, Any]:
    """Compare verified lineage receipts and preview the smallest recovery branch."""
    baseline = verify_graph_lineage(baseline_path)
    candidate = verify_graph_lineage(candidate_path)
    invalid = [name for name, result in (("baseline", baseline), ("candidate", candidate)) if not result["valid"]]
    if invalid:
        raise GraphForensicsError("GRAPH_LINEAGE_INVALID", f"invalid lineage: {', '.join(invalid)}")
    if baseline["graph_id"] != candidate["graph_id"]:
        raise GraphForensicsError("GRAPH_LINEAGE_GRAPH_MISMATCH", "baseline and candidate must describe the same graph_id")
    left, right = baseline["steps"], candidate["steps"]
    divergence_index = _divergence_index(left, right)
    anomalies = _anomalies(right)
    divergence, recovery = _recovery_analysis(left, right, divergence_index)
    markers = ["GRAPH_FORENSICS_READ_ONLY", "GRAPH_FORENSICS_CAUSAL_CONE", "GRAPH_FORENSICS_CONCURRENCY_GUARD", "GRAPH_FORENSICS_AUTHORITY_RETAINED"]
    if divergence is not None:
        markers.append("GRAPH_FORENSICS_FIRST_DIVERGENCE")
    core = {
        "schema": FORENSICS_SCHEMA, "marker": "GRAPH_FORENSICS_VERIFIED_SEMANTIC_TIME_TRAVEL",
        "markers": markers,
        "graph_id": baseline["graph_id"],
        "baseline": {"run_id": baseline["run_id"], "lineage_sha256": baseline["lineage_sha256"], "steps": len(left)},
        "candidate": {"run_id": candidate["run_id"], "lineage_sha256": candidate["lineage_sha256"], "steps": len(right)},
        "divergence": divergence, "anomalies": anomalies, "recovery_plan": recovery,
        "authority": _AUTHORITY,
        "scope_limits": ["supplied lineage only", "no checkpoint mutation", "no graph execution", "no side-effect replay", "no savings claim"],
    }
    return {**core, "forensics_sha256": _digest(core), "mermaid": _forensics_mermaid(divergence, recovery)}


def _label(value: object) -> str:
    return str(value or "none").replace('"', "'")[:100]


def _forensics_mermaid(divergence: dict[str, Any] | None, recovery: dict[str, Any]) -> str:
    if divergence is None:
        return 'flowchart LR\n    A["Baseline"] -->|semantically identical| B["Candidate"]\n'
    lines = [
        "flowchart LR", '    A["Verified baseline"] --> D["First divergence"]',
        f'    D -->|candidate| C["{_label(divergence.get("candidate_node"))}"]',
    ]
    for index, node in enumerate(recovery["rerun_nodes"][:12], 1):
        lines.append(f'    C --> R{index}["{_label(node)}"]')
    lines.append('    D --> H["Human-reviewed recovery fork"]')
    return "\n".join(lines) + "\n"
