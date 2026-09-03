"""Portable, evidence-only proof bridge for coding-agent handoffs.

The bridge accepts a compact, hash-only export from a supported client.  It is
not an agent runtime: it never contacts Eve, Junie, Grok Build, Vercel, an IDE,
or a model provider.  A receipt means only that supplied local facts are bound
to the current sealed Oracle Contract and have passed the structural checks
below.  It never proves a provider identity, an external execution, a sandbox,
or a release decision.
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
from .semantic_authority import SemanticAuthorityError, verify_semantic_binding
from .protocol_enums import (
    AgentCapability,
    AgentProvider,
    AgentRunStatus,
    AutonomyLevel,
    EvidenceKind,
    IsolationBoundary,
    WorkflowNodeKind,
)


ENVELOPE_SCHEMA = "factory.agent-proof-envelope.v1"
RECEIPT_SCHEMA = "factory.agent-proof-bridge.v1"
PROJECTION_SCHEMA = "factory.agent-proof-bridge-projection.v1"
BOUND_MARKER = "AGENT_PROOF_BOUND"
MCP_MARKER = "AGENT_PROOF_MCP_READ_ONLY"
MAX_BYTES = 1_048_576
MAX_EVIDENCE_BYTES = 10 * 1_048_576
MAX_ITEMS = 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
_PROVIDERS = AgentProvider.values()
_STATUS = AgentRunStatus.values()
_AUTONOMY = AutonomyLevel.values()
_ISOLATION = IsolationBoundary.values()
_NODE_KINDS = WorkflowNodeKind.values()
_CAPABILITIES = AgentCapability.values()
_EVIDENCE_KINDS = EvidenceKind.values()
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


class AgentProofBridgeError(ValueError):
    """Stable refusal for malformed, unbound, or non-portable evidence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", "input must be canonical JSON") from exc


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", f"{field} must use 1-96 safe identifier characters")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", f"{field} must be a lowercase SHA-256 digest")
    return value


def _path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", f"{field} must be a non-empty workspace-relative path")
    candidate = Path(value.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_PRIVATE_FIELD", f"{field} must remain workspace-relative")
    return candidate.as_posix().rstrip("/") or "."


def _inside(root: Path, value: object, field: str, *, exists: bool) -> Path:
    relative = _path(value, field)
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_PRIVATE_FIELD", f"{field} must remain beneath the workspace") from exc
    if exists and not target.is_file():
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", f"{field} must name an existing workspace file")
    return target


def _exact(value: object, allowed: set[str], field: str, *, required: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", f"{field} must be an object")
    missing = (required or allowed) - set(value)
    unknown = set(value) - allowed
    if missing or unknown:
        code = "E_AGENT_BRIDGE_PRIVATE_FIELD" if unknown else "E_AGENT_BRIDGE_SCHEMA"
        raise AgentProofBridgeError(code, f"{field} has unsupported or missing fields")
    return value


def _paths(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ITEMS:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", f"{field} must contain 1-{MAX_ITEMS} paths")
    paths = sorted(_path(item, field) for item in value)
    if len(set(paths)) != len(paths):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", f"{field} must be unique")
    return paths


def _scope_allows(scope: list[str], candidate: str) -> bool:
    return any(item == "." or candidate == item or candidate.startswith(item.rstrip("/") + "/") for item in scope)


def _source_preconditions(root: Path, value: object, scope: list[str]) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ITEMS:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "source_preconditions must contain 1-64 entries")
    result: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        entry = _exact(raw, {"path", "sha256"}, f"source_preconditions[{index}]")
        path = _path(entry["path"], f"source_preconditions[{index}].path")
        if not _scope_allows(scope, path):
            raise AgentProofBridgeError("E_AGENT_BRIDGE_SCOPE_ESCAPE", "source precondition is outside the sealed Oracle scope")
        digest = _digest(entry["sha256"], f"source_preconditions[{index}].sha256")
        source = _inside(root, path, f"source_preconditions[{index}].path", exists=True)
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "source precondition does not match current workspace bytes")
        result.append({"path": path, "sha256": digest})
    if len({item["path"] for item in result}) != len(result):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "source precondition paths must be unique")
    return sorted(result, key=lambda item: item["path"])


def _workflow(value: object) -> dict[str, Any]:
    entry = _exact(value, {"id", "definition_sha256", "topology_sha256", "nodes", "edges"}, "workflow")
    if not isinstance(entry["nodes"], list) or not 1 <= len(entry["nodes"]) <= MAX_ITEMS:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "workflow.nodes must contain 1-64 stages")
    if not isinstance(entry["edges"], list) or len(entry["edges"]) > MAX_ITEMS * 2:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "workflow.edges must contain 0-128 links")
    nodes = []
    for index, raw in enumerate(entry["nodes"]):
        node = _exact(raw, {"id", "kind"}, f"workflow.nodes[{index}]")
        if node["kind"] not in _NODE_KINDS:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "workflow node kind is unsupported")
        nodes.append({"id": _identifier(node["id"], f"workflow.nodes[{index}].id"), "kind": node["kind"]})
    if len({node["id"] for node in nodes}) != len(nodes):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "workflow node identities must be unique")
    ids = {node["id"] for node in nodes}
    edges = []
    for index, raw in enumerate(entry["edges"]):
        edge = _exact(raw, {"from", "to"}, f"workflow.edges[{index}]")
        source, target = _identifier(edge["from"], f"workflow.edges[{index}].from"), _identifier(edge["to"], f"workflow.edges[{index}].to")
        if source not in ids or target not in ids or source == target:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "workflow edges must join distinct declared stages")
        edges.append({"from": source, "to": target})
    pairs = {(edge["from"], edge["to"]) for edge in edges}
    if len(pairs) != len(edges):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "workflow edges must be unique")
    incoming = {identifier: 0 for identifier in ids}
    children: dict[str, list[str]] = {identifier: [] for identifier in ids}
    for source, target in pairs:
        incoming[target] += 1
        children[source].append(target)
    ready, visited = sorted(identifier for identifier, count in incoming.items() if count == 0), 0
    while ready:
        source = ready.pop(0)
        visited += 1
        for target in sorted(children[source]):
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    if visited != len(ids):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "workflow topology must be acyclic")
    nodes.sort(key=lambda node: node["id"])
    edges.sort(key=lambda edge: (edge["from"], edge["to"]))
    topology = _sha({"nodes": nodes, "edges": edges})
    if _digest(entry["topology_sha256"], "workflow.topology_sha256") != topology:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "workflow topology digest does not bind the declared DAG")
    return {"id": _identifier(entry["id"], "workflow.id"), "definition_sha256": _digest(entry["definition_sha256"], "workflow.definition_sha256"), "topology_sha256": topology, "nodes": nodes, "edges": edges}


def _evidence(root: Path, value: object, visual: bool) -> list[dict[str, str]]:
    """Bind compact before/after artifacts instead of accepting bare hashes."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ITEMS:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "evidence_pairs must contain 1-64 proof pairs")
    result = []
    for index, raw in enumerate(value):
        entry = _exact(raw, {"id", "kind", "before_path", "after_path", "before_sha256", "after_sha256", "claim_sha256"}, f"evidence_pairs[{index}]")
        if entry["kind"] not in _EVIDENCE_KINDS:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "evidence kind is unsupported")
        before, after = _digest(entry["before_sha256"], f"evidence_pairs[{index}].before_sha256"), _digest(entry["after_sha256"], f"evidence_pairs[{index}].after_sha256")
        if before == after:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "before and after evidence must not share one digest")
        before_path = _path(entry["before_path"], f"evidence_pairs[{index}].before_path")
        after_path = _path(entry["after_path"], f"evidence_pairs[{index}].after_path")
        if before_path == after_path:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "before and after evidence must use distinct artifacts")
        before_artifact = _inside(root, before_path, f"evidence_pairs[{index}].before_path", exists=True)
        after_artifact = _inside(root, after_path, f"evidence_pairs[{index}].after_path", exists=True)
        if before_artifact.stat().st_size > MAX_EVIDENCE_BYTES or after_artifact.stat().st_size > MAX_EVIDENCE_BYTES:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "evidence artifact exceeds 10 MiB")
        if hashlib.sha256(before_artifact.read_bytes()).hexdigest() != before or hashlib.sha256(after_artifact.read_bytes()).hexdigest() != after:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "evidence artifact bytes do not match their declared digest")
        result.append({"id": _identifier(entry["id"], f"evidence_pairs[{index}].id"), "kind": entry["kind"], "before_path": before_path, "after_path": after_path, "before_sha256": before, "after_sha256": after, "claim_sha256": _digest(entry["claim_sha256"], f"evidence_pairs[{index}].claim_sha256")})
    if len({item["id"] for item in result}) != len(result):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "evidence pair identities must be unique")
    if visual and not any(item["kind"] == "visual" for item in result):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "a declared visual surface requires a before/after visual evidence pair")
    return sorted(result, key=lambda item: item["id"])


def _provider_receipt(provider: str, value: object) -> dict[str, Any]:
    common = {"session_id", "runtime_sha256", "tool_manifest_sha256"}
    profiles = {
        "eve": common | {"workflow_id", "checkpoint_id", "checkpoint_sha256", "deployment_commit_sha"},
        "junie": common | {"mission_sha256", "action_policy_sha256", "change_list_sha256"},
        "grok_build": common | {"stream_sha256", "mode", "permission_policy_sha256"},
        "coderabbit": common | {"review_output_sha256", "review_mode", "base_commit_sha", "head_commit_sha", "finding_count"},
        "devin": common | {"task_sha256", "result_sha256", "base_commit_sha", "head_commit_sha", "permission_profile_sha256"},
        "generic": common,
    }
    entry = _exact(value, profiles[provider], "provider_receipt")
    result: dict[str, Any] = {
        "session_id": _identifier(entry["session_id"], "provider_receipt.session_id"),
        "runtime_sha256": _digest(entry["runtime_sha256"], "provider_receipt.runtime_sha256"),
        "tool_manifest_sha256": _digest(entry["tool_manifest_sha256"], "provider_receipt.tool_manifest_sha256"),
    }
    if provider == "eve":
        if not isinstance(entry["deployment_commit_sha"], str) or not _GIT_SHA.fullmatch(entry["deployment_commit_sha"]):
            raise AgentProofBridgeError("E_AGENT_BRIDGE_PROVIDER_PROFILE", "Eve deployment_commit_sha must be a lowercase Git SHA")
        result.update({"workflow_id": _identifier(entry["workflow_id"], "provider_receipt.workflow_id"), "checkpoint_id": _identifier(entry["checkpoint_id"], "provider_receipt.checkpoint_id"), "checkpoint_sha256": _digest(entry["checkpoint_sha256"], "provider_receipt.checkpoint_sha256"), "deployment_commit_sha": entry["deployment_commit_sha"]})
    elif provider == "junie":
        result.update({"mission_sha256": _digest(entry["mission_sha256"], "provider_receipt.mission_sha256"), "action_policy_sha256": _digest(entry["action_policy_sha256"], "provider_receipt.action_policy_sha256"), "change_list_sha256": _digest(entry["change_list_sha256"], "provider_receipt.change_list_sha256")})
    elif provider == "grok_build":
        if entry["mode"] not in {"headless", "interactive"}:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_PROVIDER_PROFILE", "Grok Build mode must be headless or interactive")
        result.update({"stream_sha256": _digest(entry["stream_sha256"], "provider_receipt.stream_sha256"), "mode": entry["mode"], "permission_policy_sha256": _digest(entry["permission_policy_sha256"], "provider_receipt.permission_policy_sha256")})
    elif provider == "coderabbit":
        if entry["review_mode"] != "agent":
            raise AgentProofBridgeError("E_AGENT_BRIDGE_PROVIDER_PROFILE", "CodeRabbit review_mode must be agent for structured review evidence")
        if not isinstance(entry["finding_count"], int) or not 0 <= entry["finding_count"] <= 10_000:
            raise AgentProofBridgeError("E_AGENT_BRIDGE_PROVIDER_PROFILE", "CodeRabbit finding_count must be an integer between 0 and 10000")
        for field in ("base_commit_sha", "head_commit_sha"):
            if not isinstance(entry[field], str) or not _GIT_SHA.fullmatch(entry[field]):
                raise AgentProofBridgeError("E_AGENT_BRIDGE_PROVIDER_PROFILE", f"CodeRabbit {field} must be a lowercase Git SHA")
        result.update({"review_output_sha256": _digest(entry["review_output_sha256"], "provider_receipt.review_output_sha256"), "review_mode": "agent", "base_commit_sha": entry["base_commit_sha"], "head_commit_sha": entry["head_commit_sha"], "finding_count": entry["finding_count"]})
    elif provider == "devin":
        for field in ("base_commit_sha", "head_commit_sha"):
            if not isinstance(entry[field], str) or not _GIT_SHA.fullmatch(entry[field]):
                raise AgentProofBridgeError("E_AGENT_BRIDGE_PROVIDER_PROFILE", f"Devin {field} must be a lowercase Git SHA")
        result.update({"task_sha256": _digest(entry["task_sha256"], "provider_receipt.task_sha256"), "result_sha256": _digest(entry["result_sha256"], "provider_receipt.result_sha256"), "base_commit_sha": entry["base_commit_sha"], "head_commit_sha": entry["head_commit_sha"], "permission_profile_sha256": _digest(entry["permission_profile_sha256"], "provider_receipt.permission_profile_sha256")})
    return result


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_receipt(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    target = _inside(root, path.as_posix(), "receipt", exists=True)
    if target.stat().st_size > MAX_BYTES:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "receipt exceeds 1 MiB")
    try:
        value = json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", "receipt must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != RECEIPT_SCHEMA:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", "receipt schema is unsupported")
    digest = value.get("receipt_sha256")
    core = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if not isinstance(digest, str) or digest != _sha(core):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "receipt digest does not match its canonical body")
    return value, target


def _resume(root: Path, value: object, run_id: str, workflow: dict[str, Any], provider: str, profile: dict[str, Any], contract_sha256: str) -> dict[str, str] | None:
    if value is None:
        return None
    entry = _exact(value, {"prior_receipt", "prior_run_id", "checkpoint_id", "checkpoint_sha256", "provider_receipt_sha256"}, "resume")
    prior, _ = _read_receipt(root, Path(_path(entry["prior_receipt"], "resume.prior_receipt")))
    if prior.get("run", {}).get("id") != _identifier(entry["prior_run_id"], "resume.prior_run_id") or prior.get("run", {}).get("id") == run_id:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_RESUME_DIVERGENCE", "resume must name a distinct matching prior run")
    if prior.get("provider") != provider or prior.get("workflow", {}).get("topology_sha256") != workflow["topology_sha256"] or prior.get("oracle", {}).get("contract_sha256") != contract_sha256:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_RESUME_DIVERGENCE", "provider, workflow, or Oracle binding diverges on resume")
    checkpoint = _identifier(entry["checkpoint_id"], "resume.checkpoint_id")
    checkpoint_sha = _digest(entry["checkpoint_sha256"], "resume.checkpoint_sha256")
    prior_profile = prior.get("provider_receipt", {})
    if provider == "eve" and (checkpoint != profile.get("checkpoint_id") or checkpoint_sha != profile.get("checkpoint_sha256")):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_RESUME_DIVERGENCE", "Eve checkpoint differs from the declared current checkpoint")
    if provider == "eve" and (checkpoint != prior_profile.get("checkpoint_id") or checkpoint_sha != prior_profile.get("checkpoint_sha256")):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_RESUME_DIVERGENCE", "Eve checkpoint differs from the prior receipt")
    prior_digest = _digest(entry["provider_receipt_sha256"], "resume.provider_receipt_sha256")
    if prior_digest != _sha(prior_profile):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_RESUME_DIVERGENCE", "prior provider profile digest differs")
    return {"prior_receipt": _path(entry["prior_receipt"], "resume.prior_receipt"), "prior_run_id": prior["run"]["id"], "checkpoint_id": checkpoint, "checkpoint_sha256": checkpoint_sha, "recovery_action": "human_reviewed_fork"}


def import_agent_proof(root: Path, envelope_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Bind one provider-neutral coding-agent export to a sealed Oracle Contract."""
    workspace = Path(root).resolve()
    source = _inside(workspace, envelope_path.as_posix(), "envelope", exists=True)
    if source.stat().st_size > MAX_BYTES:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_PRIVATE_FIELD", "envelope exceeds 1 MiB")
    try:
        envelope = json.loads(source.read_text(encoding="utf-8-sig"))
        _canonical(envelope)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", "envelope must be canonical UTF-8 JSON") from exc
    allowed = {"schema", "envelope_id", "provider", "run_id", "status", "agent", "autonomy", "isolation", "scope_paths", "surface", "oracle", "workflow", "source_preconditions", "evidence_pairs", "provider_receipt", "resume", "semantic_authority"}
    entry = _exact(envelope, allowed, "envelope", required=allowed - {"resume", "semantic_authority"})
    if entry.get("schema") != ENVELOPE_SCHEMA or entry.get("provider") not in _PROVIDERS or entry.get("status") not in _STATUS:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", "envelope schema, provider, or status is unsupported")
    provider, run_id = entry["provider"], _identifier(entry["run_id"], "run_id")
    if entry.get("autonomy") not in _AUTONOMY or entry.get("isolation") not in _ISOLATION:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", "autonomy or isolation is unsupported")
    if entry["autonomy"] == "autonomous" and entry["isolation"] == "unverified":
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "autonomous evidence requires a declared isolated boundary")
    if entry.get("surface") not in {"visual", "nonvisual"}:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCHEMA", "surface must be visual or nonvisual")
    try:
        agent = normalize_agent_identity(entry["agent"], "agent")
    except AgentLicenseError as exc:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_PROVIDER_PROFILE", str(exc)) from exc
    oracle = _exact(entry["oracle"], {"contract_path", "contract_sha256"}, "oracle")
    contract_path = _path(oracle["contract_path"], "oracle.contract_path")
    contract_sha = _digest(oracle["contract_sha256"], "oracle.contract_sha256")
    checked_contract = verify_oracle_contract(workspace, Path(contract_path))
    if not checked_contract.get("ok") or checked_contract.get("contract", {}).get("contract_sha256") != contract_sha:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_UNBOUND_INTENT", "agent proof must bind one current sealed Oracle Contract")
    scope = _paths(entry["scope_paths"], "scope_paths")
    contract_scope = list(checked_contract["contract"]["scope_paths"])
    if any(not _scope_allows(contract_scope, path) for path in scope):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SCOPE_ESCAPE", "declared agent scope is outside the sealed Oracle scope")
    try:
        semantic = ({"bound": False, "claim_boundary": "No semantic authority binding was supplied; this provider envelope remains Oracle-bound evidence only."} if entry.get("semantic_authority") is None else {"bound": True, **verify_semantic_binding(workspace, entry["semantic_authority"], agent, scope)})
    except SemanticAuthorityError as exc:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_SEMANTIC_AUTHORITY", str(exc)) from exc
    preconditions = _source_preconditions(workspace, entry["source_preconditions"], contract_scope)
    workflow = _workflow(entry["workflow"])
    evidence = _evidence(workspace, entry["evidence_pairs"], entry["surface"] == "visual")
    profile = _provider_receipt(provider, entry["provider_receipt"])
    try:
        admission = admission_oracle_decision(workspace, Path(contract_path), entry["autonomy"], sorted({*scope, *(item["path"] for item in preconditions)}))
    except OracleFirewallError as exc:
        code = "E_AGENT_BRIDGE_SCOPE_ESCAPE" if exc.code == "ORACLE_SCOPE_ESCAPE" else "E_AGENT_BRIDGE_UNBOUND_INTENT"
        raise AgentProofBridgeError(code, str(exc)) from exc
    resume = _resume(workspace, entry.get("resume"), run_id, workflow, provider, profile, contract_sha)
    core = {
        "schema": RECEIPT_SCHEMA,
        "marker": BOUND_MARKER,
        "imported_at": _now(),
        "envelope": {"id": _identifier(entry["envelope_id"], "envelope_id"), "path": source.relative_to(workspace).as_posix(), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()},
        "provider": provider,
        "run": {"id": run_id, "status": entry["status"]},
        "agent": agent,
        "autonomy": entry["autonomy"],
        "isolation": {"declared_mode": entry["isolation"], "verified": False, "claim_boundary": "A declared host boundary is not sandbox, identity, or provider-runtime proof."},
        "oracle": {"path": checked_contract["path"], "contract_sha256": contract_sha, "admission": admission},
        "semantic_authority": semantic,
        "scope_paths": scope,
        "surface": entry["surface"],
        "workflow": workflow,
        "source_preconditions": preconditions,
        "evidence_pairs": evidence,
        "provider_receipt": profile,
        "resume": resume,
        "authority": dict(AUTHORITY),
        "claim_boundary": "Local validation of a team-supplied provider export. It does not contact Eve, Junie, Grok Build, Vercel, an IDE, or a model; authenticate the agent; prove a sandbox or external run; view prompts, source bodies, URLs, credentials, or tool output; execute, approve, repair, deploy, publish, sign, or release work.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    destination = Path(out) if out is not None else Path(".factory") / "agent-bridges" / f"{provider}-{run_id}-{receipt['receipt_sha256'][:12]}.json"
    target = _inside(workspace, destination.as_posix(), "out", exists=False)
    if target.exists():
        raise AgentProofBridgeError("E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED", "output receipt already exists; use a new immutable path")
    _write(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}


def verify_agent_proof(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify a receipt digest and its current Oracle binding without a provider call."""
    workspace = Path(root).resolve()
    try:
        receipt, target = _read_receipt(workspace, receipt_path)
        oracle = receipt.get("oracle", {})
        if not isinstance(oracle, dict) or not isinstance(oracle.get("path"), str):
            return {"ok": False, "marker": "AGENT_PROOF_RECEIPT_INVALID", "reason": "oracle_missing", "authority": dict(AUTHORITY)}
        current = verify_oracle_contract(workspace, Path(oracle["path"]))
        if not current.get("ok") or current.get("contract", {}).get("contract_sha256") != oracle.get("contract_sha256"):
            return {"ok": False, "marker": "AGENT_PROOF_RECEIPT_INVALID", "reason": "oracle_binding_stale", "authority": dict(AUTHORITY)}
        semantic = receipt.get("semantic_authority")
        if isinstance(semantic, dict) and semantic.get("bound") is True:
            binding = {key: semantic.get(key) for key in ("lease_path", "lease_sha256", "action_id", "action", "context_urn")}
            try:
                verify_semantic_binding(workspace, binding, receipt.get("agent"), receipt.get("scope_paths"))
            except SemanticAuthorityError:
                return {"ok": False, "marker": "AGENT_PROOF_RECEIPT_INVALID", "reason": "semantic_authority_stale", "authority": dict(AUTHORITY)}
        return {"ok": True, "marker": "AGENT_PROOF_RECEIPT_VALID", "receipt": receipt, "path": target.relative_to(workspace).as_posix(), "authority": dict(AUTHORITY)}
    except AgentProofBridgeError as exc:
        return {"ok": False, "marker": "AGENT_PROOF_RECEIPT_INVALID", "reason": exc.code, "authority": dict(AUTHORITY)}


def agent_proof_projection(root: Path) -> dict[str, Any]:
    """Return bounded read-only provider-neutral facts for Graph Ops and MCP."""
    workspace = Path(root).resolve()
    receipts, invalid = [], []
    for path in sorted((workspace / ".factory" / "agent-bridges").glob("*.json"))[:200]:
        checked = verify_agent_proof(workspace, path.relative_to(workspace))
        if not checked.get("ok"):
            invalid.append(path.relative_to(workspace).as_posix())
            continue
        receipt = checked["receipt"]
        receipts.append({
            "path": checked["path"], "provider": receipt["provider"], "run_id": receipt["run"]["id"], "status": receipt["run"]["status"],
            "contract_sha256": receipt["oracle"]["contract_sha256"], "workflow_id": receipt["workflow"]["id"],
            "stage_count": len(receipt["workflow"]["nodes"]), "evidence_pair_count": len(receipt["evidence_pairs"]),
            "visual": receipt["surface"] == "visual", "resumed": receipt.get("resume") is not None,
            "semantic_authority_bound": bool(receipt.get("semantic_authority", {}).get("bound")) if isinstance(receipt.get("semantic_authority"), dict) else False,
            "receipt_sha256": receipt["receipt_sha256"],
        })
    receipts.sort(key=lambda item: item["path"])
    provider_counts = {provider: sum(item["provider"] == provider for item in receipts) for provider in sorted(_PROVIDERS)}
    return {
        "schema": PROJECTION_SCHEMA, "marker": MCP_MARKER, "receipt_count": len(receipts), "bound_count": len(receipts),
        "resumed_count": sum(int(item["resumed"]) for item in receipts), "visual_evidence_count": sum(int(item["visual"]) for item in receipts), "semantic_authority_bound_count": sum(int(item["semantic_authority_bound"]) for item in receipts),
        "invalid_count": len(invalid), "providers": provider_counts, "latest": receipts[-1] if receipts else None,
        "receipts": receipts[-20:], "invalid": invalid[:100], "authority": dict(AUTHORITY),
        "claim_boundary": "Read-only local provider-bridge facts. No agent, provider, sandbox, checkpoint, deployment, approval, repair, credential, connector, or release action ran.",
    }


def agent_handoff_brief(root: Path, contract_path: Path) -> dict[str, Any]:
    """Render the current sealed intent as a compact, zero-authority handoff brief.

    The brief is deliberately derived from an already sealed contract. It is a
    local read model for a worker and its supervisor, not a new instruction
    source, permission grant, prompt capture, or provider integration.
    """
    workspace = Path(root).resolve()
    target = _inside(workspace, contract_path.as_posix(), "contract", exists=True)
    checked = verify_oracle_contract(workspace, target.relative_to(workspace))
    if not checked.get("ok"):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_UNBOUND_INTENT", "handoff brief requires one current sealed Oracle Contract")
    contract = checked.get("contract")
    if not isinstance(contract, dict) or not isinstance(contract.get("contract_sha256"), str):
        raise AgentProofBridgeError("E_AGENT_BRIDGE_UNBOUND_INTENT", "sealed Oracle Contract is incomplete")

    def rules(group: str) -> list[dict[str, Any]]:
        result = []
        rule_groups = contract.get("rules", {})
        for raw in rule_groups.get(group, []) if isinstance(rule_groups, dict) else []:
            if not isinstance(raw, dict):
                continue
            result.append({"id": raw.get("id"), "statement": raw.get("statement"), "origin": raw.get("origin"), "effect": raw.get("effect"), "critical": raw.get("critical")})
        return result

    return {
        "schema": "factory.agent-handoff-brief.v1",
        "marker": "AGENT_HANDOFF_BRIEF_READ_ONLY",
        "contract": {"id": contract.get("id"), "path": checked.get("path"), "contract_sha256": contract["contract_sha256"], "scope_paths": list(contract.get("scope_paths", []))},
        "intended_outcomes": rules("requirements"),
        "forbidden_outcomes": rules("forbidden_behaviors"),
        "negative_cases": rules("negative_cases"),
        "invariants": rules("invariants"),
        "approved_gates": rules("gates"),
        "worker_protocol": [
            "Do not alter the contract, its source bindings, scope, thresholds, exceptions, or negative cases.",
            "Keep changes inside the declared scope and retain source preconditions.",
            "Return only a hash-only evidence envelope with real before/after artifacts for independent review.",
        ],
        "human_review_protocol": [
            "Review any oracle weakening, scope change, exception, or source drift before resuming work.",
            "Treat this brief as a local representation of the contract, not proof of provider identity or runtime execution.",
        ],
        "authority": dict(AUTHORITY),
        "claim_boundary": "Local read-only rendering of a sealed Oracle Contract. It does not start an agent, send a prompt, modify intent, approve work, execute code, or contact a provider.",
    }


def provider_template(provider: str) -> dict[str, Any]:
    """Return a secret-free input template; it does not create a provider config."""
    if provider not in _PROVIDERS:
        raise AgentProofBridgeError("E_AGENT_BRIDGE_PROVIDER_PROFILE", "provider must be eve, junie, grok_build, coderabbit, devin, or generic")
    common = {"session_id": "replace-with-safe-run-id", "runtime_sha256": "replace-with-sha256", "tool_manifest_sha256": "replace-with-sha256"}
    if provider == "eve":
        common.update({"workflow_id": "replace-with-workflow-id", "checkpoint_id": "replace-with-checkpoint-id", "checkpoint_sha256": "replace-with-sha256", "deployment_commit_sha": "replace-with-lowercase-git-sha"})
    elif provider == "junie":
        common.update({"mission_sha256": "replace-with-sha256", "action_policy_sha256": "replace-with-sha256", "change_list_sha256": "replace-with-sha256"})
    elif provider == "grok_build":
        common.update({"stream_sha256": "replace-with-sha256", "mode": "headless", "permission_policy_sha256": "replace-with-sha256"})
    elif provider == "coderabbit":
        common.update({"review_output_sha256": "replace-with-sha256-of-local-jsonl", "review_mode": "agent", "base_commit_sha": "replace-with-lowercase-git-sha", "head_commit_sha": "replace-with-lowercase-git-sha", "finding_count": 0})
    elif provider == "devin":
        common.update({"task_sha256": "replace-with-sha256", "result_sha256": "replace-with-sha256", "base_commit_sha": "replace-with-lowercase-git-sha", "head_commit_sha": "replace-with-lowercase-git-sha", "permission_profile_sha256": "replace-with-sha256"})
    return {"schema": ENVELOPE_SCHEMA, "provider": provider, "provider_receipt": common, "authority": dict(AUTHORITY), "claim_boundary": "Template only. Replace every placeholder with a reviewed local digest; never put prompts, source bodies, URLs, credentials, or provider tokens in an envelope."}
