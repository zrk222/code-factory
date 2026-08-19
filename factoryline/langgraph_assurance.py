"""Offline assurance receipts for recorded LangGraph resume paths.

The bridge intentionally does not import LangGraph or invoke an application.
Teams record hash-only transitions in their own test harness, then compare a
reference receipt with a separately captured resume receipt.  The result is a
bounded proof artifact, not a claim about production resilience.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from hashlib import sha256
import json
from pathlib import Path
import re
import tempfile
from typing import Any

from .graph_forensics import GraphForensicsError, graph_forensics, seal_graph_lineage, verify_graph_lineage


LANGGRAPH_ASSURANCE_SCHEMA = "factory.langgraph-assurance.v1"
LANGGRAPH_INCIDENT_SCHEMA = "factory.langgraph-incident-capsule.v1"
TRANSITION_MARKER = "LANGGRAPH_TRANSITION_HASH_ONLY"
PARITY_MARKER = "LANGGRAPH_RESUME_PARITY_VERIFIED"
DIVERGENCE_MARKER = "LANGGRAPH_REPLAY_DIVERGENCE"
CAPSULE_MARKER = "LANGGRAPH_INCIDENT_CAPSULE"
INPUT_MARKER = "LANGGRAPH_INPUT_REJECTED"
MCP_MARKER = "LANGGRAPH_MCP_READ_ONLY"
_TEXT = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
_MAX_STATE_ITEMS = 400
_MISSING = {"factory_state": "missing"}
AUTHORITY = {
    "graph_invocation": False,
    "checkpoint_mutation": False,
    "side_effect_replay": False,
    "approval": False,
    "deployment": False,
    "publication": False,
    "credential": False,
    "connector": False,
}


class LangGraphAssuranceError(ValueError):
    """A closed LangGraph assurance input or workspace-boundary failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LangGraphAssuranceError(INPUT_MARKER, "state values must be canonical JSON") from exc


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _TEXT.fullmatch(value):
        raise LangGraphAssuranceError(INPUT_MARKER, f"{label} must use 1-160 safe identifier characters")
    return value


def _state(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or len(value) > _MAX_STATE_ITEMS:
        raise LangGraphAssuranceError(INPUT_MARKER, f"{label} must be an object with at most {_MAX_STATE_ITEMS} keys")
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        normalized[_identifier(key, f"{label} key")] = item
    _canonical(normalized)
    return normalized


def _opaque(value: object, label: str) -> str:
    """Return a digest label so recorder outputs never retain source values."""
    return f"sha256:{_sha({label: value})}"


def _inside(root: Path, value: Path | str, label: str, *, must_exist: bool) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        raise LangGraphAssuranceError(INPUT_MARKER, f"{label} must be workspace-relative")
    try:
        resolved = (root / candidate).resolve()
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise LangGraphAssuranceError(INPUT_MARKER, f"{label} escapes the workspace") from exc
    if must_exist and not resolved.is_file():
        raise LangGraphAssuranceError(INPUT_MARKER, f"{label} must name an existing file")
    return resolved


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            temporary = Path(handle.name)
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


class LangGraphTransitionRecorder:
    """Record hash-only state transitions supplied by a team-owned harness."""

    def __init__(self, graph_id: str, run_id: str):
        self.graph_id = _identifier(graph_id, "graph_id")
        self.run_id = _identifier(run_id, "run_id")
        self._steps: list[dict[str, Any]] = []
        self._versions: dict[str, tuple[int, str]] = {}
        self._superstep: int | None = None
        self._superstep_snapshot: dict[str, tuple[int, str]] = {}

    def _start_superstep(self, superstep: int) -> None:
        if not isinstance(superstep, int) or isinstance(superstep, bool) or superstep < 0:
            raise LangGraphAssuranceError(INPUT_MARKER, "superstep must be a non-negative integer")
        if self._superstep is not None and superstep < self._superstep:
            raise LangGraphAssuranceError(INPUT_MARKER, "superstep must not decrease")
        if superstep != self._superstep:
            self._superstep = superstep
            self._superstep_snapshot = dict(self._versions)

    def _state_reads_and_writes(self, before: dict[str, Any], after: dict[str, Any]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        reads: list[dict[str, object]] = []
        writes: list[dict[str, object]] = []
        for key in sorted(set(before) | set(after)):
            prior_version, prior_hash = self._superstep_snapshot.get(key, (0, _sha(_MISSING)))
            before_hash = _sha(before.get(key, _MISSING))
            if key in self._superstep_snapshot and before_hash != prior_hash:
                raise LangGraphAssuranceError(INPUT_MARKER, f"before_state does not match recorded version for {key}")
            reads.append({"key": key, "version": prior_version, "sha256": before_hash})
            after_hash = _sha(after.get(key, _MISSING))
            if before_hash != after_hash:
                writes.append({
                    "key": key,
                    "previous_version": prior_version,
                    "version": prior_version + 1,
                    "before_sha256": before_hash,
                    "after_sha256": after_hash,
                    "mode": "delete" if key not in after else "replace",
                    "reducer": None,
                })
                self._versions[key] = (prior_version + 1, after_hash)
        return reads, writes

    @staticmethod
    def _effects(side_effects: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []
        for index, effect in enumerate(side_effects):
            if not isinstance(effect, Mapping) or set(effect) != {"effect_id", "idempotency_key", "status"}:
                raise LangGraphAssuranceError(INPUT_MARKER, f"side_effects[{index}] must contain effect_id, idempotency_key, and status")
            normalized.append({
                "effect_id": _opaque(effect["effect_id"], "effect_id"),
                "idempotency_key": _opaque(effect["idempotency_key"], "idempotency_key"),
                "status": _identifier(effect["status"], f"side_effects[{index}].status"),
            })
        return sorted(normalized, key=lambda item: (item["effect_id"], item["idempotency_key"]))

    @staticmethod
    def _decision(decision: Mapping[str, object]) -> dict[str, str]:
        if not isinstance(decision, Mapping) or set(decision) != {"route", "reason"}:
            raise LangGraphAssuranceError(INPUT_MARKER, "decision must contain exactly route and reason")
        return {
            "route": _opaque(decision["route"], "route"),
            "reason": _opaque(decision["reason"], "reason"),
        }

    def record_transition(
        self,
        node_id: str,
        *,
        superstep: int,
        checkpoint_id: str,
        before_state: Mapping[str, object],
        after_state: Mapping[str, object],
        decision: Mapping[str, object],
        side_effects: Iterable[Mapping[str, object]] = (),
    ) -> dict[str, object]:
        """Record one local, hash-only transition without invoking a graph."""
        self._start_superstep(superstep)
        before = _state(before_state, "before_state")
        after = _state(after_state, "after_state")
        node = _identifier(node_id, "node_id")
        checkpoint = _identifier(checkpoint_id, "checkpoint_id")
        reads, writes = self._state_reads_and_writes(before, after)
        step = {
            "sequence": len(self._steps) + 1,
            "superstep": superstep,
            "node_id": node,
            "checkpoint_id": checkpoint,
            "reads": reads,
            "writes": writes,
            "evidence": [],
            "side_effects": self._effects(side_effects),
            "decision": self._decision(decision),
        }
        self._steps.append(step)
        return {"marker": TRANSITION_MARKER, "sequence": step["sequence"], "node_id": node, "state_keys": sorted(set(before) | set(after))}

    def seal(self, root: Path, out: Path | str) -> dict[str, object]:
        """Seal the recorded steps below one explicit workspace root."""
        workspace = Path(root).resolve()
        if not workspace.is_dir():
            raise LangGraphAssuranceError(INPUT_MARKER, "workspace root must be an existing directory")
        destination = _inside(workspace, out, "out", must_exist=False)
        if not self._steps:
            raise LangGraphAssuranceError(INPUT_MARKER, "at least one transition is required before sealing")
        temporary: Path | None = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=destination.parent, prefix=".langgraph-steps.", suffix=".json", delete=False
            ) as handle:
                json.dump({"steps": self._steps}, handle, ensure_ascii=False, sort_keys=True)
                temporary = Path(handle.name)
            sealed = seal_graph_lineage(self.run_id, self.graph_id, temporary, destination)
        except GraphForensicsError as exc:
            raise LangGraphAssuranceError(INPUT_MARKER, str(exc)) from exc
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
        return {"marker": TRANSITION_MARKER, "lineage": sealed}


def _anomaly_cone(steps: list[dict[str, Any]], anomaly: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    sequence = anomaly.get("sequence")
    node = anomaly.get("node_id")
    if not isinstance(sequence, int):
        writers = anomaly.get("writers")
        node = writers[0] if isinstance(writers, list) and writers else "parallel-writers"
        sequence = next((step["sequence"] for step in steps if step["node_id"] == node), 1)
    start = next((index for index, step in enumerate(steps) if step["sequence"] == sequence), 0)
    keys = {str(anomaly["state_key"])} if isinstance(anomaly.get("state_key"), str) else set()
    sequences: list[int] = []
    nodes: list[str] = []
    for step in steps[start:]:
        reads = {item["key"] for item in step["reads"]}
        writes = {item["key"] for item in step["writes"]}
        if not keys or reads & keys or writes & keys:
            sequences.append(step["sequence"])
            nodes.append(step["node_id"])
            keys.update(writes)
    divergence = {
        "index": start,
        "sequence": sequence,
        "baseline_node": None,
        "candidate_node": node,
        "changed_state_keys": sorted(keys),
        "causal_sequences": sequences,
        "causal_nodes": list(dict.fromkeys(nodes)),
        "anomaly": anomaly["code"],
    }
    recovery = {
        "action": "review_counterfactual_fork",
        "reason": "review the first deterministic anomaly and rerun only its causal cone",
        "checkpoint_id": steps[start - 1]["checkpoint_id"] if start else None,
        "rerun_nodes": list(dict.fromkeys(nodes)),
        "invalidated_evidence": [],
        "requires_human_approval": True,
        "execute": False,
    }
    return divergence, recovery


def _mermaid(divergence: dict[str, Any] | None, recovery: dict[str, Any]) -> str:
    if divergence is None:
        return 'flowchart LR\n    R["Reference"] -->|resume parity verified| S["Resumed"]\n'
    node = str(divergence.get("candidate_node") or "anomaly").replace('"', "'")[:100]
    lines = [
        "flowchart LR",
        '    R["Reference lineage"] --> D["First divergence"]',
        f'    D --> N["{node}"]',
        '    D --> H["Human review required"]',
    ]
    for index, item in enumerate(recovery.get("rerun_nodes", [])[:12], 1):
        label = str(item).replace('"', "'")[:100]
        lines.append(f'    N --> C{index}["{label}"]')
    return "\n".join(lines) + "\n"


def _incident_capsule(
    graph_id: str,
    reference: dict[str, Any],
    resumed: dict[str, Any],
    divergence: dict[str, Any] | None,
    anomalies: list[dict[str, Any]],
    recovery: dict[str, Any],
) -> dict[str, Any]:
    core = {
        "schema": LANGGRAPH_INCIDENT_SCHEMA,
        "marker": CAPSULE_MARKER,
        "graph_id": graph_id,
        "reference_lineage_sha256": reference["lineage_sha256"],
        "resumed_lineage_sha256": resumed["lineage_sha256"],
        "first_divergence": divergence,
        "anomalies": anomalies,
        "recovery_plan": recovery,
        "authority": AUTHORITY,
        "scope_limits": [
            "hashes, node identifiers, and state-key identifiers only",
            "no raw state values, prompts, or secrets",
            "no graph invocation, checkpoint mutation, or side-effect replay",
            "no time, token, cost, quality, or productivity estimate",
        ],
    }
    return {**core, "mermaid": _mermaid(divergence, recovery), "capsule_sha256": _sha(core)}


def _verified_comparison(reference_file: Path, resumed_file: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        reference = verify_graph_lineage(reference_file)
        resumed = verify_graph_lineage(resumed_file)
        if not reference["valid"] or not resumed["valid"]:
            raise GraphForensicsError("GRAPH_LINEAGE_INVALID", "reference and resumed lineages must both verify")
        if reference["graph_id"] != resumed["graph_id"]:
            raise GraphForensicsError("GRAPH_LINEAGE_GRAPH_MISMATCH", "reference and resumed graph_id values differ")
        return reference, resumed, graph_forensics(reference_file, resumed_file), graph_forensics(reference_file, reference_file)
    except GraphForensicsError as exc:
        raise LangGraphAssuranceError(INPUT_MARKER, str(exc)) from exc


def _assurance_payload(reference: dict[str, Any], resumed: dict[str, Any], comparison: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    anomalies = sorted(
        [*baseline["anomalies"], *comparison["anomalies"]],
        key=lambda item: (item.get("sequence", 0), item["code"], item.get("state_key", "")),
    )
    divergence = comparison["divergence"]
    recovery = comparison["recovery_plan"]
    verified = divergence is None and not anomalies
    if not verified and divergence is None:
        divergence, recovery = _anomaly_cone(resumed["steps"], anomalies[0])
    marker = PARITY_MARKER if verified else DIVERGENCE_MARKER
    core = {
        "schema": LANGGRAPH_ASSURANCE_SCHEMA,
        "marker": marker,
        "markers": [TRANSITION_MARKER, marker] + ([] if verified else [CAPSULE_MARKER]),
        "verdict": "VERIFIED" if verified else "REVIEW_REQUIRED",
        "graph_id": reference["graph_id"],
        "reference": {"run_id": reference["run_id"], "lineage_sha256": reference["lineage_sha256"]},
        "resumed": {"run_id": resumed["run_id"], "lineage_sha256": resumed["lineage_sha256"]},
        "first_divergence": divergence,
        "anomalies": anomalies,
        "recovery_plan": recovery,
        "mermaid": _mermaid(divergence, recovery),
        "authority": AUTHORITY,
        "scope_limits": [
            "supplied sealed lineages only",
            "does not invoke LangGraph or a graph application",
            "does not establish production resilience or correctness beyond supplied transitions",
            "does not estimate time, tokens, cost, quality, or productivity",
        ],
    }
    payload = {**core, "assurance_sha256": _sha(core)}
    if not verified:
        payload["incident_capsule"] = _incident_capsule(
            payload["graph_id"], reference, resumed, divergence, anomalies, recovery
        )
    return payload


def verify_langgraph_resume_parity(
    root: Path,
    reference_path: Path | str,
    resumed_path: Path | str,
    out: Path | str | None = None,
) -> dict[str, Any]:
    """Compare two sealed run receipts without executing either graph."""
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise LangGraphAssuranceError(INPUT_MARKER, "workspace root must be an existing directory")
    reference_file = _inside(workspace, reference_path, "reference", must_exist=True)
    resumed_file = _inside(workspace, resumed_path, "resumed", must_exist=True)
    destination = _inside(workspace, out, "out", must_exist=False) if out is not None else None
    reference, resumed, comparison, baseline = _verified_comparison(reference_file, resumed_file)
    payload = _assurance_payload(reference, resumed, comparison, baseline)
    if destination is not None:
        _atomic_json(destination, payload)
        payload = {**payload, "path": str(destination.relative_to(workspace).as_posix())}
    return payload
