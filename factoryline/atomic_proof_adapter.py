"""Evidence-only Atomic workflow mechanics for Code Factory.

The adapter borrows four useful runtime mechanics from Atomic without becoming
another agent runtime: a declared stage DAG, capability-scoped handoffs,
checkpoint continuity, and immutable artifact/source preconditions.  Atomic
or another team-owned exporter writes the compact envelope; this module only
validates and persists local, hash-only evidence.  It never imports or invokes
Atomic, executes a command, resumes a checkpoint, or grants authority.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .agent_license import AgentLicenseError, normalize_agent_identity
from .oracle_firewall import OracleFirewallError, admission_oracle_decision, verify_oracle_contract
from .protocol_enums import AgentCapability, AgentRunStatus, AutonomyLevel, IsolationBoundary, WorkflowNodeKind


ENVELOPE_SCHEMA = "factory.atomic-run-envelope.v1"
RECEIPT_SCHEMA = "factory.atomic-proof-adapter.v1"
PROJECTION_SCHEMA = "factory.atomic-proof-adapter-projection.v1"
INPUT_MARKER = "ATOMIC_INPUT_REJECTED"
BOUND_MARKER = "ATOMIC_RUN_BOUND"
MCP_MARKER = "ATOMIC_MCP_READ_ONLY"
MAX_BYTES = 1_048_576
MAX_ITEMS = 128
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STAGE_KINDS = WorkflowNodeKind.values()
_STAGE_STATUS = AgentRunStatus.values()
_AUTONOMY = AutonomyLevel.values()
_ISOLATION = IsolationBoundary.values()
_CAPABILITIES = AgentCapability.values()
AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class AtomicProofAdapterError(ValueError):
    """A stable local envelope, binding, or continuity failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", "input must be canonical JSON") from exc


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", f"{field} must use 1-96 safe identifier characters")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"{field} must be a lowercase SHA-256 digest")
    return value


def _inside(root: Path, value: object, field: str, *, exists: bool) -> Path:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", f"{field} must be a non-empty workspace-relative path")
    supplied = Path(value.replace("\\", "/"))
    if supplied.is_absolute() or ".." in supplied.parts:
        raise AtomicProofAdapterError("ATOMIC_INPUT_REJECTED", f"{field} must remain beneath the workspace")
    target = (root / supplied).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise AtomicProofAdapterError("ATOMIC_INPUT_REJECTED", f"{field} must remain beneath the workspace") from exc
    if exists and not target.is_file():
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"{field} must name an existing workspace file")
    return target


def _path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", f"{field} must be a non-empty workspace-relative path")
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise AtomicProofAdapterError("ATOMIC_INPUT_REJECTED", f"{field} must be workspace-relative without parent traversal")
    return path.as_posix().rstrip("/") or "."


def _exact_keys(value: object, allowed: set[str], field: str, *, required: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", f"{field} must be an object")
    missing = (required or allowed) - set(value)
    unknown = set(value) - allowed
    if missing or unknown:
        raise AtomicProofAdapterError("E_ATOMIC_PRIVATE_FIELD" if unknown else "E_ATOMIC_ENVELOPE_SCHEMA", f"{field} has unsupported or missing fields")
    return value


def _paths(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", f"{field} must contain 1-64 paths")
    result = sorted({_path(item, field) for item in value})
    if len(result) != len(value):
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", f"{field} must be unique")
    return result


def _scope_allows(scope: list[str], path: str) -> bool:
    return any(item == "." or path == item or path.startswith(item.rstrip("/") + "/") for item in scope)


def _source_preconditions(root: Path, value: object, field: str, scope: list[str]) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"{field} must contain 1-64 source preconditions")
    result: list[dict[str, str]] = []
    for index, item in enumerate(value):
        entry = _exact_keys(item, {"path", "sha256"}, f"{field}[{index}]")
        path = _path(entry["path"], f"{field}[{index}].path")
        if not _scope_allows(scope, path):
            raise AtomicProofAdapterError("E_ATOMIC_SCOPE_ESCAPE", f"{field}[{index}].path is outside the sealed Oracle scope")
        declared_sha = _hash(entry["sha256"], f"{field}[{index}].sha256")
        source = _inside(root, path, f"{field}[{index}].path", exists=True)
        if hashlib.sha256(source.read_bytes()).hexdigest() != declared_sha:
            raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"{field}[{index}] no longer matches the workspace source bytes")
        result.append({"path": path, "sha256": declared_sha})
    if len({item["path"] for item in result}) != len(result):
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"{field} paths must be unique")
    return sorted(result, key=lambda item: item["path"])


def _topology(value: object) -> tuple[dict[str, Any], set[tuple[str, str]]]:
    workflow = _exact_keys(value, {"id", "definition_sha256", "topology_sha256", "nodes", "edges"}, "workflow")
    nodes = workflow["nodes"]
    edges = workflow["edges"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_ITEMS:
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "workflow.nodes must contain 1-128 typed stages")
    if not isinstance(edges, list) or len(edges) > MAX_ITEMS * 2:
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "workflow.edges must contain 0-256 declared edges")
    normalized_nodes: list[dict[str, str]] = []
    for index, item in enumerate(nodes):
        entry = _exact_keys(item, {"id", "kind"}, f"workflow.nodes[{index}]")
        kind = entry.get("kind")
        if kind not in _STAGE_KINDS:
            raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"workflow.nodes[{index}].kind is unsupported")
        normalized_nodes.append({"id": _identifier(entry["id"], f"workflow.nodes[{index}].id"), "kind": kind})
    node_ids = {item["id"] for item in normalized_nodes}
    if len(node_ids) != len(normalized_nodes):
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "workflow node identifiers must be unique")
    normalized_edges: list[dict[str, str]] = []
    for index, item in enumerate(edges):
        entry = _exact_keys(item, {"from", "to"}, f"workflow.edges[{index}]")
        source = _identifier(entry["from"], f"workflow.edges[{index}].from")
        target = _identifier(entry["to"], f"workflow.edges[{index}].to")
        if source not in node_ids or target not in node_ids or source == target:
            raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "workflow edge must join distinct declared stages")
        normalized_edges.append({"from": source, "to": target})
    edge_pairs = {(item["from"], item["to"]) for item in normalized_edges}
    if len(edge_pairs) != len(normalized_edges):
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "workflow edges must be unique")
    incoming = {node: 0 for node in node_ids}
    outgoing: dict[str, list[str]] = {node: [] for node in node_ids}
    for source, target in edge_pairs:
        incoming[target] += 1
        outgoing[source].append(target)
    ready = sorted(node for node, count in incoming.items() if count == 0)
    visited = 0
    while ready:
        source = ready.pop(0)
        visited += 1
        for target in sorted(outgoing[source]):
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    if visited != len(node_ids):
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "workflow topology must be a declared DAG")
    normalized = {
        "id": _identifier(workflow["id"], "workflow.id"),
        "definition_sha256": _hash(workflow["definition_sha256"], "workflow.definition_sha256"),
        "topology_sha256": _hash(workflow["topology_sha256"], "workflow.topology_sha256"),
        "nodes": sorted(normalized_nodes, key=lambda item: item["id"]),
        "edges": sorted(normalized_edges, key=lambda item: (item["from"], item["to"])),
    }
    declared_digest = _sha({"nodes": normalized["nodes"], "edges": normalized["edges"]})
    if normalized["topology_sha256"] != declared_digest:
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "workflow.topology_sha256 must bind the declared DAG")
    return normalized, edge_pairs


def _stages(root: Path, value: object, workflow: dict[str, Any], contract_scope: list[str]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ITEMS:
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "stages must contain 1-128 typed stages")
    node_kinds = {item["id"]: item["kind"] for item in workflow["nodes"]}
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        entry = _exact_keys(item, {"id", "kind", "status", "scope_paths", "capabilities", "input_sha256", "output_sha256", "artifact_sha256", "tool_manifest_sha256", "checkpoint", "source_preconditions"}, f"stages[{index}]")
        stage_id = _identifier(entry["id"], f"stages[{index}].id")
        kind = entry.get("kind")
        if stage_id not in node_kinds or node_kinds[stage_id] != kind:
            raise AtomicProofAdapterError("E_ATOMIC_STAGE_IDENTITY_UNPROVEN", f"stages[{index}] must exactly match one workflow node")
        status = entry.get("status")
        if status not in _STAGE_STATUS:
            raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"stages[{index}].status is unsupported")
        scope = _paths(entry["scope_paths"], f"stages[{index}].scope_paths")
        if any(not _scope_allows(contract_scope, path) for path in scope):
            raise AtomicProofAdapterError("E_ATOMIC_SCOPE_ESCAPE", f"stages[{index}].scope_paths is outside the sealed Oracle scope")
        capabilities = entry.get("capabilities")
        if not isinstance(capabilities, list) or not 1 <= len(capabilities) <= len(_CAPABILITIES) or any(item not in _CAPABILITIES for item in capabilities):
            raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"stages[{index}].capabilities is unsupported")
        if len(set(capabilities)) != len(capabilities):
            raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", f"stages[{index}].capabilities must be unique")
        checkpoint = _exact_keys(entry["checkpoint"], {"id", "sha256"}, f"stages[{index}].checkpoint")
        stage = {
            "id": stage_id,
            "kind": kind,
            "status": status,
            "scope_paths": scope,
            "capabilities": sorted(capabilities),
            "input_sha256": _hash(entry["input_sha256"], f"stages[{index}].input_sha256"),
            "output_sha256": _hash(entry["output_sha256"], f"stages[{index}].output_sha256"),
            "artifact_sha256": _hash(entry["artifact_sha256"], f"stages[{index}].artifact_sha256"),
            "tool_manifest_sha256": _hash(entry["tool_manifest_sha256"], f"stages[{index}].tool_manifest_sha256"),
            "checkpoint": {"id": _identifier(checkpoint["id"], f"stages[{index}].checkpoint.id"), "sha256": _hash(checkpoint["sha256"], f"stages[{index}].checkpoint.sha256")},
            "source_preconditions": _source_preconditions(root, entry["source_preconditions"], f"stages[{index}].source_preconditions", contract_scope),
        }
        normalized.append(stage)
    stage_ids = {item["id"] for item in normalized}
    if stage_ids != set(node_kinds) or len(stage_ids) != len(normalized):
        raise AtomicProofAdapterError("E_ATOMIC_STAGE_IDENTITY_UNPROVEN", "stages must contain every declared workflow node exactly once")
    checkpoints = [item["checkpoint"]["id"] for item in normalized]
    if len(set(checkpoints)) != len(checkpoints):
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "checkpoint identities must be unique within one run")
    normalized.sort(key=lambda item: item["id"])
    return normalized, {item["id"]: item for item in normalized}


def _handoffs(value: object, stages: dict[str, dict[str, Any]], edge_pairs: set[tuple[str, str]], contract_sha256: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "handoffs must contain 0-128 declared handoffs")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        entry = _exact_keys(item, {"id", "from_stage", "to_stage", "capability", "scope_paths", "contract_sha256", "source_preconditions_sha256", "artifact_sha256", "tool_manifest_sha256"}, f"handoffs[{index}]")
        source = _identifier(entry["from_stage"], f"handoffs[{index}].from_stage")
        target = _identifier(entry["to_stage"], f"handoffs[{index}].to_stage")
        if source not in stages or target not in stages or (source, target) not in edge_pairs:
            raise AtomicProofAdapterError("E_ATOMIC_STAGE_IDENTITY_UNPROVEN", f"handoffs[{index}] must join one declared workflow edge")
        capability = entry.get("capability")
        if capability not in stages[source]["capabilities"] or capability not in stages[target]["capabilities"]:
            raise AtomicProofAdapterError("E_ATOMIC_STAGE_IDENTITY_UNPROVEN", f"handoffs[{index}].capability is not declared by both stages")
        scope = _paths(entry["scope_paths"], f"handoffs[{index}].scope_paths")
        if any(
            not _scope_allows(stages[source]["scope_paths"], candidate)
            or not _scope_allows(stages[target]["scope_paths"], candidate)
            for candidate in scope
        ):
            raise AtomicProofAdapterError("E_ATOMIC_SCOPE_ESCAPE", f"handoffs[{index}].scope_paths exceeds the declared stage scopes")
        if _hash(entry["contract_sha256"], f"handoffs[{index}].contract_sha256") != contract_sha256:
            raise AtomicProofAdapterError("E_ATOMIC_UNBOUND_INTENT", f"handoffs[{index}] must bind the sealed Oracle Contract")
        expected_preconditions = _sha(stages[source]["source_preconditions"])
        if _hash(entry["source_preconditions_sha256"], f"handoffs[{index}].source_preconditions_sha256") != expected_preconditions:
            raise AtomicProofAdapterError("E_ATOMIC_HANDOFF_DRIFT", f"handoffs[{index}] source preconditions drift from the sender stage")
        if _hash(entry["artifact_sha256"], f"handoffs[{index}].artifact_sha256") != stages[source]["artifact_sha256"]:
            raise AtomicProofAdapterError("E_ATOMIC_HANDOFF_DRIFT", f"handoffs[{index}] artifact hash drifts from the sender stage")
        if _hash(entry["tool_manifest_sha256"], f"handoffs[{index}].tool_manifest_sha256") != stages[source]["tool_manifest_sha256"]:
            raise AtomicProofAdapterError("E_ATOMIC_HANDOFF_DRIFT", f"handoffs[{index}] tool manifest drifts from the sender stage")
        normalized.append({"id": _identifier(entry["id"], f"handoffs[{index}].id"), "from_stage": source, "to_stage": target, "capability": capability, "scope_paths": scope, "contract_sha256": contract_sha256, "source_preconditions_sha256": expected_preconditions, "artifact_sha256": stages[source]["artifact_sha256"], "tool_manifest_sha256": stages[source]["tool_manifest_sha256"]})
    if len({item["id"] for item in normalized}) != len(normalized):
        raise AtomicProofAdapterError("E_ATOMIC_STAGE_IDENTITY_UNPROVEN", "handoff identifiers must be unique")
    return sorted(normalized, key=lambda item: item["id"])


def _receipt_valid(value: object) -> bool:
    if not isinstance(value, dict) or value.get("schema") != RECEIPT_SCHEMA:
        return False
    digest = value.get("receipt_sha256")
    return isinstance(digest, str) and _SHA256.fullmatch(digest) is not None and _sha({key: item for key, item in value.items() if key != "receipt_sha256"}) == digest


def _read_receipt(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    target = _inside(root, path.as_posix(), "receipt", exists=True)
    if target.stat().st_size > MAX_BYTES:
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "receipt exceeds 1 MiB")
    try:
        value = json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "receipt must be valid UTF-8 JSON") from exc
    if not _receipt_valid(value):
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "receipt hash is invalid")
    return value, target


def _resume(value: object, root: Path, run_id: str, workflow: dict[str, Any], contract_sha256: str, stages: dict[str, dict[str, Any]]) -> dict[str, str] | None:
    if value is None:
        return None
    resume = _exact_keys(value, {"prior_receipt", "prior_run_id", "checkpoint_id", "checkpoint_sha256"}, "resume")
    receipt, _ = _read_receipt(root, Path(_path(resume["prior_receipt"], "resume.prior_receipt")))
    if receipt.get("run", {}).get("id") != _identifier(resume["prior_run_id"], "resume.prior_run_id"):
        raise AtomicProofAdapterError("E_ATOMIC_RESUME_DIVERGENCE", "resume prior_run_id does not match the bound receipt")
    if receipt["run"]["id"] == run_id:
        raise AtomicProofAdapterError("E_ATOMIC_RESUME_DIVERGENCE", "resume must use a new run identifier")
    if receipt.get("oracle", {}).get("contract_sha256") != contract_sha256:
        raise AtomicProofAdapterError("E_ATOMIC_RESUME_DIVERGENCE", "resume Oracle Contract digest diverges")
    prior_workflow = receipt.get("workflow", {})
    if not isinstance(prior_workflow, dict) or any(prior_workflow.get(field) != workflow.get(field) for field in ("id", "definition_sha256", "topology_sha256")):
        raise AtomicProofAdapterError("E_ATOMIC_RESUME_DIVERGENCE", "resume workflow binding diverges")
    checkpoint_id = _identifier(resume["checkpoint_id"], "resume.checkpoint_id")
    checkpoint_sha = _hash(resume["checkpoint_sha256"], "resume.checkpoint_sha256")
    prior_stage = next((item for item in receipt.get("stages", []) if isinstance(item, dict) and item.get("checkpoint", {}).get("id") == checkpoint_id), None)
    current_stage = next((item for item in stages.values() if item["checkpoint"]["id"] == checkpoint_id), None)
    if not isinstance(prior_stage, dict) or current_stage is None:
        raise AtomicProofAdapterError("E_ATOMIC_RESUME_DIVERGENCE", "resume checkpoint is unavailable in the bound runs")
    if prior_stage.get("checkpoint", {}).get("sha256") != checkpoint_sha or current_stage["checkpoint"]["sha256"] != checkpoint_sha:
        raise AtomicProofAdapterError("E_ATOMIC_RESUME_DIVERGENCE", "resume checkpoint hash diverges")
    if prior_stage.get("tool_manifest_sha256") != current_stage["tool_manifest_sha256"] or prior_stage.get("source_preconditions") != current_stage["source_preconditions"]:
        raise AtomicProofAdapterError("E_ATOMIC_RESUME_DIVERGENCE", "resume tool or source-precondition binding diverges")
    return {"prior_receipt": _path(resume["prior_receipt"], "resume.prior_receipt"), "prior_run_id": receipt["run"]["id"], "checkpoint_id": checkpoint_id, "checkpoint_sha256": checkpoint_sha, "recovery_action": "human_reviewed_fork"}


def _handoff_history(root: Path, workflow_id: str, handoffs: list[dict[str, Any]]) -> None:
    expected = {item["id"]: item for item in handoffs}
    if not expected:
        return
    directory = root / ".factory" / "atomic"
    for path in sorted(directory.glob("*.json"))[:200]:
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not _receipt_valid(value) or value.get("workflow", {}).get("id") != workflow_id:
            continue
        for historical in value.get("handoffs", []):
            if not isinstance(historical, dict) or historical.get("id") not in expected:
                continue
            current = expected[historical["id"]]
            fields = ("from_stage", "to_stage", "capability", "scope_paths", "contract_sha256", "source_preconditions_sha256", "artifact_sha256", "tool_manifest_sha256")
            if any(historical.get(field) != current.get(field) for field in fields):
                raise AtomicProofAdapterError("E_ATOMIC_HANDOFF_DRIFT", f"handoff {historical['id']} diverges from a prior bound workflow receipt")


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def import_atomic_run(root: Path, envelope_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Validate one Atomic mechanics envelope and write an immutable local receipt."""
    workspace = Path(root).resolve()
    source = _inside(workspace, Path(envelope_path).as_posix(), "envelope", exists=True)
    if source.stat().st_size > MAX_BYTES:
        raise AtomicProofAdapterError("E_ATOMIC_PRIVATE_FIELD", "envelope exceeds 1 MiB")
    try:
        envelope = json.loads(source.read_text(encoding="utf-8-sig"))
        _canonical(envelope)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", "envelope must be valid canonical UTF-8 JSON") from exc
    allowed = {"schema", "envelope_id", "run_id", "status", "agent", "autonomy", "isolation", "oracle", "workflow", "stages", "handoffs", "resume"}
    entry = _exact_keys(envelope, allowed, "envelope", required=allowed - {"resume"})
    if entry.get("schema") != ENVELOPE_SCHEMA:
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", f"envelope.schema must equal {ENVELOPE_SCHEMA}")
    run_id = _identifier(entry["run_id"], "run_id")
    envelope_id = _identifier(entry["envelope_id"], "envelope_id")
    if entry.get("status") not in _STAGE_STATUS:
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", "status is unsupported")
    autonomy = entry.get("autonomy")
    isolation = entry.get("isolation")
    if autonomy not in _AUTONOMY or isolation not in _ISOLATION:
        raise AtomicProofAdapterError("E_ATOMIC_ENVELOPE_SCHEMA", "autonomy or isolation is unsupported")
    if autonomy == "autonomous" and isolation == "unverified":
        raise AtomicProofAdapterError("E_ATOMIC_ISOLATION_UNPROVEN", "autonomous Atomic evidence requires a declared isolated host boundary")
    try:
        agent = normalize_agent_identity(entry["agent"], "agent")
    except AgentLicenseError as exc:
        raise AtomicProofAdapterError("E_ATOMIC_STAGE_IDENTITY_UNPROVEN", str(exc)) from exc
    oracle = _exact_keys(entry["oracle"], {"contract_path", "contract_sha256"}, "oracle")
    contract_path = _path(oracle["contract_path"], "oracle.contract_path")
    contract_sha256 = _hash(oracle["contract_sha256"], "oracle.contract_sha256")
    checked_contract = verify_oracle_contract(workspace, Path(contract_path))
    if not checked_contract.get("ok") or checked_contract.get("contract", {}).get("contract_sha256") != contract_sha256:
        raise AtomicProofAdapterError("E_ATOMIC_UNBOUND_INTENT", "Atomic envelope must bind one current sealed Oracle Contract")
    workflow, edge_pairs = _topology(entry["workflow"])
    contract_scope = list(checked_contract["contract"]["scope_paths"])
    stages, stage_index = _stages(workspace, entry["stages"], workflow, contract_scope)
    handoffs = _handoffs(entry["handoffs"], stage_index, edge_pairs, contract_sha256)
    all_paths = sorted({path for stage in stages for path in [*stage["scope_paths"], *(item["path"] for item in stage["source_preconditions"])]})
    try:
        admission = admission_oracle_decision(workspace, Path(contract_path), autonomy, all_paths)
    except OracleFirewallError as exc:
        code = "E_ATOMIC_SCOPE_ESCAPE" if exc.code == "ORACLE_SCOPE_ESCAPE" else "E_ATOMIC_UNBOUND_INTENT"
        raise AtomicProofAdapterError(code, str(exc)) from exc
    resume = _resume(entry.get("resume"), workspace, run_id, workflow, contract_sha256, stage_index)
    _handoff_history(workspace, workflow["id"], handoffs)
    core = {
        "schema": RECEIPT_SCHEMA,
        "marker": BOUND_MARKER,
        "imported_at": _now(),
        "envelope": {"path": source.relative_to(workspace).as_posix(), "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "id": envelope_id},
        "run": {"id": run_id, "status": entry["status"]},
        "agent": agent,
        "autonomy": autonomy,
        "isolation": {"declared_mode": isolation, "verified": False, "claim_boundary": "A declared host boundary is not proof of a sandbox, container, worktree, VM, or remote policy."},
        "oracle": {"path": checked_contract["path"], "contract_sha256": contract_sha256, "admission": admission},
        "workflow": workflow,
        "stages": stages,
        "handoffs": handoffs,
        "resume": resume,
        "authority": dict(AUTHORITY),
        "claim_boundary": "Local validation of a team-supplied Atomic export. It does not import or invoke Atomic, authenticate the declared agent, prove runtime execution, verify a host sandbox, mutate a checkpoint, approve a change, or authorize release work.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    destination = Path(out) if out is not None else Path(".factory") / "atomic" / f"{run_id}-{receipt['receipt_sha256'][:12]}.json"
    target = _inside(workspace, destination.as_posix(), "out", exists=False)
    if target.exists():
        raise AtomicProofAdapterError("E_ATOMIC_EVIDENCE_UNVERIFIED", "output receipt already exists; choose a new immutable path")
    _atomic_json(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}


def verify_atomic_receipt(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify a local Atomic adapter receipt and its current Oracle binding."""
    workspace = Path(root).resolve()
    try:
        receipt, path = _read_receipt(workspace, Path(receipt_path))
        oracle = receipt.get("oracle")
        if not isinstance(oracle, dict) or not isinstance(oracle.get("path"), str):
            return {"ok": False, "marker": "ATOMIC_RECEIPT_INVALID", "reason": "oracle_missing", "authority": dict(AUTHORITY)}
        contract = verify_oracle_contract(workspace, Path(oracle["path"]))
        if not contract.get("ok") or contract.get("contract", {}).get("contract_sha256") != oracle.get("contract_sha256"):
            return {"ok": False, "marker": "ATOMIC_RECEIPT_INVALID", "reason": "oracle_binding_stale", "authority": dict(AUTHORITY)}
        return {"ok": True, "marker": "ATOMIC_RECEIPT_VALID", "receipt": receipt, "path": path.relative_to(workspace).as_posix(), "authority": dict(AUTHORITY)}
    except AtomicProofAdapterError as exc:
        return {"ok": False, "marker": "ATOMIC_RECEIPT_INVALID", "reason": exc.code, "authority": dict(AUTHORITY)}


def atomic_envelope_template() -> dict[str, Any]:
    """Return a secret-free Atomic handoff shape without creating a run or config."""
    digest = "replace-with-lowercase-sha256"
    return {
        "schema": "factory.atomic-envelope-template.v1",
        "envelope_schema": ENVELOPE_SCHEMA,
        "envelope": {
            "schema": ENVELOPE_SCHEMA,
            "envelope_id": "replace-with-safe-envelope-id",
            "run_id": "replace-with-safe-run-id",
            "status": "completed",
            "agent": {
                "schema": "factory.agent-identity.v1",
                "subject": "replace-with-declared-agent-id",
                "provider": "atomic-exporter",
                "model": "replace-with-declared-model-id",
            },
            "autonomy": "supervised",
            "isolation": "declared_worktree",
            "oracle": {"contract_path": ".factory/oracles/contracts/current.json", "contract_sha256": digest},
            "workflow": {
                "id": "replace-with-workflow-id",
                "definition_sha256": digest,
                "topology_sha256": digest,
                "nodes": [
                    {"id": "plan", "kind": "planner"},
                    {"id": "build", "kind": "worker"},
                    {"id": "verify", "kind": "validator"},
                ],
                "edges": [{"from": "plan", "to": "build"}, {"from": "build", "to": "verify"}],
            },
            "stages": [
                {
                    "id": "plan",
                    "kind": "planner",
                    "status": "completed",
                    "scope_paths": ["replace-with-approved-scope"],
                    "capabilities": ["read_workspace", "handoff"],
                    "input_sha256": digest,
                    "output_sha256": digest,
                    "artifact_sha256": digest,
                    "tool_manifest_sha256": digest,
                    "checkpoint": {"id": "replace-with-checkpoint-id", "sha256": digest},
                    "source_preconditions": [{"path": "replace-with-existing-source-path", "sha256": digest}],
                }
            ],
            "handoffs": [],
        },
        "authority": dict(AUTHORITY),
        "claim_boundary": "Template only. Replace placeholders with reviewed local identifiers and digests. Never add prompts, source bodies, URLs, credentials, provider tokens, tool output bodies, or execution instructions.",
    }


def atomic_proof_projection(root: Path) -> dict[str, Any]:
    """Return bounded, read-only Atomic bridge facts for Graph Ops and MCP."""
    workspace = Path(root).resolve()
    receipts: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "atomic").glob("*.json"))[:200]:
        checked = verify_atomic_receipt(workspace, path.relative_to(workspace))
        if not checked.get("ok"):
            invalid.append(path.relative_to(workspace).as_posix())
            continue
        value = checked["receipt"]
        receipts.append({
            "path": checked["path"],
            "run_id": value["run"]["id"],
            "status": value["run"]["status"],
            "workflow_id": value["workflow"]["id"],
            "contract_sha256": value["oracle"]["contract_sha256"],
            "stage_count": len(value["stages"]),
            "handoff_count": len(value["handoffs"]),
            "resumed": value.get("resume") is not None,
            "receipt_sha256": value["receipt_sha256"],
        })
    receipts.sort(key=lambda item: item["path"])
    return {
        "schema": PROJECTION_SCHEMA,
        "marker": MCP_MARKER,
        "receipt_count": len(receipts),
        "bound_count": len(receipts),
        "resumed_count": sum(int(item["resumed"]) for item in receipts),
        "invalid_count": len(invalid),
        "latest": receipts[-1] if receipts else None,
        "receipts": receipts[-20:],
        "invalid": invalid[:100],
        "authority": dict(AUTHORITY),
        "claim_boundary": "Read-only local Atomic adapter facts. The projection does not start a stage, send an intercom message, resume a checkpoint, inspect an Atomic runtime, or grant execution or release authority.",
    }
