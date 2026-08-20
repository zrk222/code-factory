"""Local stdio-only MCP adapter over deterministic Graph Ops facts."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Any, TextIO

from . import __version__
from .developer_memory import developer_memory_brief
from .graph_ops import graph_ops_impact, graph_ops_snapshot
from .langgraph_assurance import MCP_MARKER, LangGraphAssuranceError, verify_langgraph_resume_parity
from .proof_delta import proof_delta_status
from .proof_reuse import verify_proof_receipt
from .prd_grill import verify_prd_grill
from .intake_grill import intake_status
from .gauntlet import gauntlet_status
from .agent_license import AgentLicenseError, derive_license, license_projection, normalize_agent_identity
from .combine import combine_projection
from .workspace_advisor import inspect_workspace


MCP_PROTOCOL_VERSION = "2025-03-26"
MCP_STATUS_SCHEMA = "factory.mcp.status.v1"
MCP_SERVER_NAME = "code-factory"
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}
_READ_ONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
_MAX_RECEIPT_BYTES = 262_144
_MAX_RECEIPTS = 250
_RECEIPT_ROOTS = (
    Path("receipts"),
    Path(".factory/proofs"),
    Path(".factory/runs"),
    Path(".factory/change-reviews"),
    Path(".factory/repair-sandboxes"),
    Path(".factory/prd-grills"),
    Path(".factory/cdte"),
    Path(".factory/verifier-sessions"),
    Path(".factory/proof-plans"),
    Path(".factory/proof-deltas"),
    Path(".factory/intake-grills"),
    Path(".factory/intake-confirmations"),
    Path(".factory/gauntlets"),
    Path(".factory/agent-licenses"),
    Path(".factory/combines"),
)


class McpError(ValueError):
    """A stable error raised for an invalid local MCP request."""

    def __init__(self, message: str, marker: str = "MCP_INVALID_PARAMS_REJECTED"):
        super().__init__(message)
        self.marker = marker


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _workspace_root(root: Path | str) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise McpError("workspace root must be an existing directory")
    return workspace


def _tool_definitions() -> list[dict[str, object]]:
    no_args = {"type": "object", "properties": {}, "additionalProperties": False}
    return [
        {
            "name": "factory.status",
            "description": "Return the local Code Factory MCP boundary, version, workspace root, and tool inventory. Read only.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.graph_ops",
            "description": "Return deterministic local Graph Ops facts. summary is a compact next-action view; neither format executes work.",
            "inputSchema": {
                "type": "object",
                "properties": {"format": {"type": "string", "enum": ["json", "summary"], "default": "json"}},
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.graph_impact",
            "description": "Map explicit root-relative changed paths to bound proof impact without executing work.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "changed_paths": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 50,
                        "items": {"type": "string", "minLength": 1, "maxLength": 512},
                    },
                },
                "required": ["changed_paths"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.developer_memory",
            "description": "Return a read-only next-proof brief with redacted continuity facts and observed local Git contributor attribution. It never runs a proof, writes memory, or treats Git authors as verified seats.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "changed_paths": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 50,
                        "items": {"type": "string", "minLength": 1, "maxLength": 512},
                    },
                    "base": {"type": "string", "minLength": 1, "maxLength": 120},
                },
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.langgraph_assurance",
            "description": "Compare two existing workspace-relative LangGraph transition receipts. It never invokes a graph, mutates checkpoints, replays effects, or writes a receipt.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reference": {"type": "string", "minLength": 1, "maxLength": 512},
                    "resumed": {"type": "string", "minLength": 1, "maxLength": 512},
                },
                "required": ["reference", "resumed"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.next_action",
            "description": "Read the one fact-derived Graph Ops recommendation without executing it.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.list_receipts",
            "description": "List up to 50 newest local receipt-like JSON artifacts. Entries are unassessed until a named verification path runs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
                    "feature": {"type": "string", "minLength": 1, "maxLength": 80},
                },
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.get_receipt",
            "description": "Return one local receipt by root-relative path or exact feature identifier. The payload stays unassessed unless a verifier was explicitly run.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 1, "maxLength": 512},
                    "feature": {"type": "string", "minLength": 1, "maxLength": 80},
                },
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.verifier_status",
            "description": "Read a local Verifier Plane session. It never starts a worker or verifier and reports unknown evidence and budget use as unobserved.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": {"type": "string", "minLength": 1, "maxLength": 512},
                    "mission": {"type": "string", "minLength": 1, "maxLength": 64},
                },
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.proof_reuse",
            "description": "Read the reuse disposition for an exact local proof receipt. It never runs a gate; missing a complete gate request fails closed as BLOCK.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "gate": {"type": "string", "minLength": 1, "maxLength": 120},
                    "changed_paths": {
                        "type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 512}, "maxItems": 50,
                    },
                },
                "required": ["gate"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.proof_delta_status",
            "description": "Read the newest local Proof-Delta retry-admission receipt. It never starts an agent, applies a repair, or admits a retry.",
            "inputSchema": {
                "type": "object",
                "properties": {"mission": {"type": "string", "minLength": 1, "maxLength": 64}},
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.cdte_status",
            "description": "Read the latest existing deterministic CDTE scan for an optional feature. It never synthesizes constraints or writes a scan receipt.",
            "inputSchema": {
                "type": "object",
                "properties": {"feature": {"type": "string", "minLength": 1, "maxLength": 80}},
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.prd_grill_status",
            "description": "Read the newest PRD Grill receipt bound to a root-relative PRD path. It never rewrites a PRD or authorizes implementation.",
            "inputSchema": {
                "type": "object",
                "properties": {"prd_path": {"type": "string", "minLength": 1, "maxLength": 512}},
                "required": ["prd_path"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.intake_status",
            "description": "Read source-bound framework, intent, acceptance, and external-effects intake status. It never selects a framework, creates a mission, or authorizes implementation.",
            "inputSchema": {
                "type": "object",
                "properties": {"prd_path": {"type": "string", "description": "Optional root-relative PRD path to scope the status."}},
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.gauntlet_status",
            "description": "Read local Survival Card facts, including whether only redacted verified continuity metadata was bound, for an optional Gauntlet source id. It never compiles a proposal, admits or runs a batch, signs a card, or promotes a result.",
            "inputSchema": {
                "type": "object",
                "properties": {"source_id": {"type": "string", "minLength": 1, "maxLength": 96}},
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.agent_license_status",
            "description": "Read the local, expiry-bound Earned Autonomy tier for all governed declared agents or one supplied declared identity. It never authenticates identity, records evidence, issues a license, raises autonomy, or starts an agent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent": {
                        "type": "object",
                        "properties": {
                            "schema": {"type": "string", "const": "factory.agent-identity.v1"},
                            "subject": {"type": "string"},
                            "provider": {"type": "string"},
                            "model": {"type": "string"},
                        },
                        "required": ["schema", "subject", "provider", "model"],
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.combine_status",
            "description": "Read locally verified Combine scoreboards that compare completed governed run evidence. It never launches agents, estimates quality, or creates a vendor ranking.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.workspace_advisor",
            "description": "Measure bounded local workspace shape and a path-only Remote/WSL preflight. It does not query the IDE, connect remotely, change caches, indexes, inspections, or settings, and is not a performance diagnosis.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
    ]


def mcp_status(root: Path | str) -> dict[str, object]:
    """Return the explicit boundary for the local MCP adapter."""
    workspace = _workspace_root(root)
    return {
        "schema": MCP_STATUS_SCHEMA,
        "marker": "FACTORY_MCP_LOCAL_READ_ONLY",
        "markers": ["FACTORY_MCP_LOCAL_READ_ONLY", "MCP_STDLIB_ONLY"],
        "transport": "stdio",
        "workspace_root": str(workspace),
        "server": {"name": MCP_SERVER_NAME, "version": __version__, "protocol_version": MCP_PROTOCOL_VERSION},
        "authority": dict(_AUTHORITY),
        "tools": [tool["name"] for tool in _tool_definitions()],
        "resources": ["factory://status", "factory://graph"],
    }


def _relative_path(root: Path, value: object, label: str, *, must_exist: bool = False) -> tuple[str, Path]:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > 512:
        raise McpError(f"{label} must be a non-empty root-relative path")
    supplied = Path(value)
    if supplied.is_absolute() or ".." in supplied.parts:
        raise McpError(f"{label} must be root-relative without parent traversal")
    candidate = (root / supplied).resolve()
    try:
        relative = candidate.relative_to(root).as_posix()
    except ValueError as exc:
        raise McpError(f"{label} must remain beneath the workspace root") from exc
    if must_exist and not candidate.is_file():
        raise McpError(f"{label} must name an existing regular file")
    return relative, candidate


def _receipt_path(root: Path, value: object, *, must_exist: bool = False) -> tuple[str, Path]:
    relative, candidate = _relative_path(root, value, "receipt path", must_exist=must_exist)
    if candidate.suffix.lower() != ".json" or not any(candidate.is_relative_to(root / item) for item in _RECEIPT_ROOTS):
        raise McpError("receipt path must be a JSON file beneath a local receipt directory")
    return relative, candidate


def _receipt_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for relative in _RECEIPT_ROOTS:
        directory = root / relative
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.json"):
            if path.is_file():
                candidate = path.resolve()
                if candidate.is_relative_to(root):
                    files.append(candidate)
    return sorted(files, key=lambda path: (-path.stat().st_mtime_ns, path.as_posix()))[:_MAX_RECEIPTS]


def _load_small_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > _MAX_RECEIPT_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _receipt_metadata(root: Path, path: Path) -> dict[str, object]:
    relative = path.relative_to(root).as_posix()
    stat = path.stat()
    payload = _load_small_json(path)
    timestamp = None
    schema = None
    if payload is not None:
        schema = payload.get("schema") if isinstance(payload.get("schema"), str) else None
        for field in ("recorded_at", "created_at", "generated_at"):
            if isinstance(payload.get(field), str):
                timestamp = payload[field]
                break
    return {
        "path": relative,
        "schema": schema,
        "timestamp": timestamp,
        "timestamp_source": "receipt" if timestamp else "filesystem_mtime",
        "filesystem_mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "size_bytes": stat.st_size,
        "assessment": "unassessed",
        "verification": "not_run",
    }


def _feature(value: object, label: str = "feature") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value):
        raise McpError(f"{label} must use 1-80 letters, digits, dots, underscores, or hyphens")
    return value


def _feature_matches(payload: dict[str, Any], feature: str) -> bool:
    return any(payload.get(field) == feature for field in ("feature", "project", "mission_id", "run_id"))


def _find_feature_receipt(root: Path, feature: str, *, schema: str | None = None) -> tuple[Path, dict[str, Any]] | None:
    for path in _receipt_files(root):
        payload = _load_small_json(path)
        if payload is None or (schema is not None and payload.get("schema") != schema):
            continue
        if _feature_matches(payload, feature):
            return path, payload
    return None


def _receipt_listing(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"limit", "feature"}:
        raise McpError("factory.list_receipts accepts only limit and optional feature")
    limit = arguments.get("limit", 10)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise McpError("limit must be an integer from 1 to 50")
    feature = _feature(arguments["feature"]) if "feature" in arguments else None
    entries = []
    for path in _receipt_files(root):
        payload = _load_small_json(path)
        if feature is not None and (payload is None or not _feature_matches(payload, feature)):
            continue
        entries.append(_receipt_metadata(root, path))
        if len(entries) == limit:
            break
    return {
        "marker": "MCP_RECEIPTS_UNASSESSED",
        "feature": feature,
        "entries": entries,
        "scope": "Only bounded local JSON files under documented receipt directories are listed.",
    }


def _get_receipt(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"path", "feature"}:
        raise McpError("factory.get_receipt accepts only path or feature")
    has_path, has_feature = "path" in arguments, "feature" in arguments
    if has_path == has_feature:
        raise McpError("factory.get_receipt requires exactly one of path or feature")
    if has_path:
        _, path = _receipt_path(root, arguments["path"], must_exist=True)
        payload = _load_small_json(path)
    else:
        match = _find_feature_receipt(root, _feature(arguments["feature"]))
        path, payload = match if match is not None else (None, None)
    if path is None or payload is None:
        return {"marker": "MCP_RECEIPT_NOT_FOUND", "found": False, "assessment": "unassessed"}
    return {
        "marker": "MCP_RECEIPT_UNASSESSED",
        "found": True,
        "metadata": _receipt_metadata(root, path),
        "receipt": payload,
        "scope": "The receipt is returned as local data; this tool does not verify, sign, approve, or promote it.",
    }


def _error(request_id: object, code: int, message: str, marker: str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message, "data": {"marker": marker}},
    }


def _result(request_id: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _content(payload: object) -> dict[str, object]:
    return {"content": [{"type": "text", "text": _canonical(payload)}]}


def _changed_paths(arguments: object) -> list[str]:
    if not isinstance(arguments, dict) or set(arguments) != {"changed_paths"}:
        raise McpError("factory.graph_impact requires only changed_paths")
    value = arguments["changed_paths"]
    if not isinstance(value, list) or not 1 <= len(value) <= 50:
        raise McpError("changed_paths must contain 1 to 50 paths")
    paths: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not 1 <= len(entry) <= 512:
            raise McpError("each changed path must contain 1 to 512 characters")
        candidate = Path(entry)
        if candidate.is_absolute() or ".." in candidate.parts or entry.strip() != entry:
            raise McpError("each changed path must be root-relative without parent traversal")
        paths.append(candidate.as_posix())
    return paths


def _graph_summary(graph: dict[str, Any]) -> dict[str, object]:
    counts: dict[str, int] = {}
    for node in graph.get("nodes", []):
        if isinstance(node, dict) and isinstance(node.get("kind"), str):
            counts[node["kind"]] = counts.get(node["kind"], 0) + 1
    return {
        "graph_sha256": graph["graph_sha256"],
        "recommendation": graph["recommendation"],
        "authority": graph["authority"],
        "node_counts": dict(sorted(counts.items())),
        "errors": graph.get("errors", []),
    }


def _graph_ops(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"format"}:
        raise McpError("factory.graph_ops accepts only optional format")
    output_format = arguments.get("format", "json")
    if output_format not in {"json", "summary"}:
        raise McpError("format must be json or summary")
    graph = graph_ops_snapshot(root)
    payload: dict[str, object] = {"marker": "MCP_GRAPH_OPS_PARITY"}
    payload["graph" if output_format == "json" else "summary"] = graph if output_format == "json" else _graph_summary(graph)
    return payload


def _developer_memory(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"changed_paths", "base"}:
        raise McpError("factory.developer_memory accepts only optional changed_paths and base")
    changed = _changed_paths({"changed_paths": arguments["changed_paths"]}) if "changed_paths" in arguments else None
    base = arguments.get("base", "main")
    if not isinstance(base, str) or not base.strip() or len(base) > 120:
        raise McpError("base must be a non-empty string of at most 120 characters")
    return {
        "marker": "MCP_DEVELOPER_MEMORY_READ_ONLY",
        "brief": developer_memory_brief(root, base=base, changed=changed),
        "scope": "Read-only local evidence projection; no proof, memory record, approval, or identity-directory action ran.",
    }


def _langgraph_assurance(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) != {"reference", "resumed"}:
        raise McpError("factory.langgraph_assurance requires only reference and resumed")
    reference, _ = _relative_path(root, arguments["reference"], "reference", must_exist=True)
    resumed, _ = _relative_path(root, arguments["resumed"], "resumed", must_exist=True)
    try:
        assurance = verify_langgraph_resume_parity(root, reference, resumed)
    except LangGraphAssuranceError as exc:
        raise McpError(exc.message, "MCP_LANGGRAPH_ASSURANCE_REJECTED") from exc
    return {
        "marker": MCP_MARKER,
        "assurance": assurance,
        "scope": "Read-only local comparison of supplied receipts; no graph, checkpoint, effect, approval, deployment, publication, credential, or connector action ran.",
    }


def _verifier_session_path(root: Path, arguments: object) -> tuple[Path, dict[str, Any]] | None:
    if not isinstance(arguments, dict) or set(arguments) - {"session", "mission"}:
        raise McpError("factory.verifier_status accepts only session or mission")
    has_session, has_mission = "session" in arguments, "mission" in arguments
    if has_session == has_mission:
        raise McpError("factory.verifier_status requires exactly one of session or mission")
    if has_session:
        _, path = _receipt_path(root, arguments["session"], must_exist=True)
        payload = _load_small_json(path)
        return (path, payload) if payload is not None else None
    return _find_feature_receipt(root, _feature(arguments["mission"], "mission"), schema="factory.verifier-session.v1")


def _verifier_status(root: Path, arguments: object) -> dict[str, object]:
    found = _verifier_session_path(root, arguments)
    if found is None:
        return {"marker": "MCP_VERIFIER_SESSION_NOT_FOUND", "found": False, "assessment": "unassessed"}
    path, session = found
    if session.get("schema") != "factory.verifier-session.v1" or not isinstance(session.get("budgets"), dict):
        return {"marker": "MCP_VERIFIER_SESSION_INVALID", "found": True, "assessment": "unassessed", "path": path.relative_to(root).as_posix()}
    budgets = session["budgets"]
    return {
        "marker": "MCP_VERIFIER_SESSION_UNASSESSED",
        "found": True,
        "session": {"path": path.relative_to(root).as_posix(), "mission_id": session.get("mission_id"), "session_sha256": session.get("session_sha256")},
        "worker": {"identity": "unobserved", "result": "not_supplied"},
        "verifier": {"identity": "unobserved", "result": "not_supplied", "independence": "unassessed"},
        "budget": {"limits": budgets, "remaining": "unobserved"},
        "independent_evidence": "not_supplied",
        "assessment": "unassessed",
        "scope": "Session bytes are local facts. This tool does not start workers, infer budget use, or claim independent verification.",
    }


def _proof_reuse(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"gate", "changed_paths"} or "gate" not in arguments:
        raise McpError("factory.proof_reuse requires gate and accepts optional changed_paths")
    gate = _feature(arguments["gate"], "gate")
    changed = _changed_paths({"changed_paths": arguments["changed_paths"]}) if "changed_paths" in arguments else []
    matches: list[dict[str, object]] = []
    for path in _receipt_files(root):
        payload = _load_small_json(path)
        if payload is None or payload.get("schema") != "factory.proof-receipt.v1" or payload.get("gate") != gate:
            continue
        verification = verify_proof_receipt(root, path)
        matches.append({"path": path.relative_to(root).as_posix(), "verification": verification})
    return {
        "marker": "MCP_PROOF_REUSE_REQUEST_INCOMPLETE",
        "gate": gate,
        "changed_paths": changed,
        "disposition": "BLOCK",
        "reason": "A complete proof request (command, inputs, outputs, toolchain, and environment) is required before RUN, REUSE, or SKIP can be determined.",
        "matching_receipts": matches,
        "next_action": "Run factory proofs plan with an explicit proof-request manifest; this MCP tool will not run it.",
    }


def _proof_delta_status(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"mission"}:
        raise McpError("factory.proof_delta_status accepts only optional mission")
    mission = _feature(arguments["mission"], "mission") if "mission" in arguments else None
    return {
        "marker": "MCP_PROOF_DELTA_READ_ONLY",
        "status": proof_delta_status(root, mission),
        "scope": "Read-only local evidence projection; no retry, worker, repair, approval, merge, publication, deployment, credential, or connector action ran.",
    }


def _cdte_status(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"feature"}:
        raise McpError("factory.cdte_status accepts only optional feature")
    feature = _feature(arguments["feature"]) if "feature" in arguments else None
    records = []
    directory = root / ".factory" / "cdte"
    for item in _receipt_files(root):
        if not item.is_relative_to(directory):
            continue
        payload = _load_small_json(item)
        if payload is not None and payload.get("schema") == "factory.cdte-scan.v1" and (feature is None or payload.get("run_id") == feature):
            records.append({"metadata": _receipt_metadata(root, item), "fail_closed": payload.get("fail_closed"), "requires_hitl_escalation": payload.get("requires_hitl_escalation"), "conflicts": len(payload.get("conflicts", [])) if isinstance(payload.get("conflicts"), list) else None})
            break
    if records:
        return {"marker": "MCP_CDTE_SCAN_OBSERVED", "feature": feature, "scan": records[0], "assessment": "unassessed"}
    return {"marker": "MCP_CDTE_SCAN_REQUIRED", "feature": feature, "assessment": "unassessed", "next_action": "Run factory cdte scan explicitly to create a deterministic, receipted gate result."}


def _prd_grill_status(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) != {"prd_path"}:
        raise McpError("factory.prd_grill_status requires only prd_path")
    relative, source = _relative_path(root, arguments["prd_path"], "prd_path", must_exist=True)
    if source.stat().st_size > _MAX_RECEIPT_BYTES:
        raise McpError("prd_path must be at most 262144 bytes")
    source_sha = sha256(source.read_bytes()).hexdigest()
    matches = []
    directory = root / ".factory" / "prd-grills"
    if directory.is_dir():
        for path in _receipt_files(root):
            if not path.is_relative_to(directory):
                continue
            payload = _load_small_json(path)
            source_record = payload.get("source") if isinstance(payload, dict) else None
            if payload is not None and payload.get("schema") == "factory.prd_grill.v1" and isinstance(source_record, dict) and source_record.get("sha256") == source_sha:
                matches.append(path)
    if not matches:
        return {"marker": "MCP_PRD_GRILL_REQUIRED", "prd_path": relative, "assessment": "unassessed", "next_action": "Run factory prd grill explicitly to create a source-bound clarification receipt."}
    path = matches[0]
    verification = verify_prd_grill(path)
    return {"marker": "MCP_PRD_GRILL_STATUS", "prd_path": relative, "metadata": _receipt_metadata(root, path), "verification": verification, "current_source_sha256": source_sha}


def _workspace_advisor(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.workspace_advisor accepts no arguments")
    report = inspect_workspace(root)
    return {
        "marker": "MCP_WORKSPACE_ADVISOR_READ_ONLY",
        "report": report,
        "scope": "In-memory local filesystem inspection only; no artifacts are written by MCP.",
    }


def _intake_status(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"prd_path"}:
        raise McpError("factory.intake_status accepts only optional prd_path")
    prd: Path | None = None
    if "prd_path" in arguments:
        relative, source = _relative_path(root, arguments["prd_path"], "prd_path", must_exist=True)
        if source.stat().st_size > _MAX_RECEIPT_BYTES:
            raise McpError("prd_path must be at most 262144 bytes")
        prd = Path(relative)
    return {
        "marker": "MCP_INTAKE_READ_ONLY",
        "status": intake_status(root, prd),
        "scope": "Read-only local intake projection; it does not infer intent, select a framework, create a mission, execute work, or authorize release actions.",
    }


def _gauntlet_status(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"source_id"}:
        raise McpError("factory.gauntlet_status accepts only optional source_id")
    source_id = _feature(arguments["source_id"], "source_id") if "source_id" in arguments else None
    return {
        "marker": "MCP_GAUNTLET_READ_ONLY",
        "status": gauntlet_status(root, source_id),
        "scope": "Read-only local Survival Card projection; no proposal, admission, E2E run, repair, approval, signing, publication, deployment, credential, or connector action ran.",
    }


def _agent_license_status(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"agent"}:
        raise McpError("factory.agent_license_status accepts only optional agent")
    try:
        if "agent" in arguments:
            identity = normalize_agent_identity(arguments["agent"])
            status: object = {"licenses": [derive_license(root, identity)]}
        else:
            status = license_projection(root)
    except AgentLicenseError as exc:
        raise McpError(str(exc), exc.code) from exc
    return {
        "marker": "MCP_AGENT_LICENSE_READ_ONLY",
        "status": status,
        "scope": "Read-only local evidence projection. Subjects are declared identities; this tool does not authenticate, record, issue, promote, execute, approve, repair, merge, publish, deploy, sign, or grant credentials.",
    }


def _combine_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.combine_status accepts no arguments")
    return {
        "marker": "MCP_COMBINE_READ_ONLY",
        "status": combine_projection(root),
        "scope": "Read-only local comparison of verified governed events; no agent command, score estimation, repair, approval, publication, deployment, or credential action ran.",
    }


def _tool_call(root: Path, params: object) -> dict[str, object]:
    if not isinstance(params, dict) or set(params) - {"name", "arguments"}:
        raise McpError("tools/call requires name and optional arguments")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str):
        raise McpError("tools/call name must be a string")
    if name == "factory.status":
        if arguments != {}:
            raise McpError("factory.status accepts no arguments")
        return _content(mcp_status(root))
    if name == "factory.graph_ops":
        return _content(_graph_ops(root, arguments))
    if name == "factory.graph_impact":
        return _content({
            "marker": "MCP_GRAPH_IMPACT_PARITY",
            "impact": graph_ops_impact(root, _changed_paths(arguments)),
        })
    if name == "factory.developer_memory":
        return _content(_developer_memory(root, arguments))
    if name == "factory.langgraph_assurance":
        return _content(_langgraph_assurance(root, arguments))
    if name == "factory.next_action":
        if arguments != {}:
            raise McpError("factory.next_action accepts no arguments")
        graph = graph_ops_snapshot(root)
        return _content({
            "marker": "MCP_GRAPH_OPS_PARITY",
            "graph_sha256": graph["graph_sha256"],
            "recommendation": graph["recommendation"],
            "authority": graph["authority"],
        })
    if name == "factory.list_receipts":
        return _content(_receipt_listing(root, arguments))
    if name == "factory.get_receipt":
        return _content(_get_receipt(root, arguments))
    if name == "factory.verifier_status":
        return _content(_verifier_status(root, arguments))
    if name == "factory.proof_reuse":
        return _content(_proof_reuse(root, arguments))
    if name == "factory.proof_delta_status":
        return _content(_proof_delta_status(root, arguments))
    if name == "factory.cdte_status":
        return _content(_cdte_status(root, arguments))
    if name == "factory.prd_grill_status":
        return _content(_prd_grill_status(root, arguments))
    if name == "factory.intake_status":
        return _content(_intake_status(root, arguments))
    if name == "factory.gauntlet_status":
        return _content(_gauntlet_status(root, arguments))
    if name == "factory.agent_license_status":
        return _content(_agent_license_status(root, arguments))
    if name == "factory.combine_status":
        return _content(_combine_status(root, arguments))
    if name == "factory.workspace_advisor":
        return _content(_workspace_advisor(root, arguments))
    raise McpError("unknown MCP tool")


def _resource_read(root: Path, params: object) -> dict[str, object]:
    if not isinstance(params, dict) or set(params) != {"uri"} or not isinstance(params.get("uri"), str):
        raise McpError("resources/read requires only a URI")
    uri = params["uri"]
    if uri == "factory://status":
        payload = mcp_status(root)
    elif uri == "factory://graph":
        payload = graph_ops_snapshot(root)
    else:
        raise McpError("unknown MCP resource")
    return {
        "marker": "MCP_RESOURCES_PARITY",
        "contents": [{"uri": uri, "mimeType": "application/json", "text": _canonical(payload)}],
    }


def _require_no_params(params: object, method: str) -> None:
    if params != {}:
        raise McpError(f"{method} accepts no params")


def _initialize(_root: Path, params: object) -> dict[str, object]:
    if not isinstance(params, dict):
        raise McpError("initialize params must be an object")
    return {
        "marker": "MCP_INITIALIZED",
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "serverInfo": {"name": MCP_SERVER_NAME, "version": __version__},
        "capabilities": {"tools": {}, "resources": {}},
    }


def _tools_list(_root: Path, params: object) -> dict[str, object]:
    _require_no_params(params, "tools/list")
    return {"marker": "FACTORY_MCP_TOOL_INVENTORY", "tools": _tool_definitions()}


def _tools_call(root: Path, params: object) -> dict[str, object]:
    return _tool_call(root, params)


def _resources_list(_root: Path, params: object) -> dict[str, object]:
    _require_no_params(params, "resources/list")
    return {
        "marker": "MCP_RESOURCES_PARITY",
        "resources": [
            {"uri": "factory://status", "name": "Factory MCP status", "mimeType": "application/json"},
            {"uri": "factory://graph", "name": "Factory Graph Ops", "mimeType": "application/json"},
        ],
    }


def _resources_read(root: Path, params: object) -> dict[str, object]:
    return _resource_read(root, params)


def _method_result(root: Path, method: str, params: object) -> dict[str, object]:
    handlers = {
        "initialize": _initialize,
        "tools/list": _tools_list,
        "tools/call": _tools_call,
        "resources/list": _resources_list,
        "resources/read": _resources_read,
    }
    handler = handlers.get(method)
    if handler is None:
        raise LookupError(method)
    return handler(root, params)


def _request_context(request: object) -> tuple[object, bool, str, object] | None:
    if not isinstance(request, dict):
        return None
    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        return None
    return request.get("id"), "id" not in request, request["method"], request.get("params", {})


def _error_or_notification(is_notification: bool, request_id: object, code: int,
                           message: str, marker: str) -> dict[str, object] | None:
    if is_notification:
        return None
    return _error(request_id, code, message, marker)


def _result_or_notification(is_notification: bool, request_id: object,
                            result: dict[str, object]) -> dict[str, object] | None:
    if is_notification:
        return None
    return _result(request_id, result)


def dispatch(request: object, root: Path | str) -> dict[str, object] | None:
    """Dispatch one MCP JSON-RPC object without mutating the workspace."""
    context = _request_context(request)
    if context is None:
        request_id = request.get("id") if isinstance(request, dict) else None
        return _error(request_id, -32602, "invalid JSON-RPC request", "MCP_INVALID_PARAMS_REJECTED")
    request_id, is_notification, method, params = context
    if method == "notifications/initialized":
        return None
    try:
        response = _method_result(_workspace_root(root), method, params)
    except LookupError:
        return _error_or_notification(is_notification, request_id, -32601, "method not found", "MCP_UNKNOWN_METHOD_REJECTED")
    except McpError as exc:
        return _error_or_notification(is_notification, request_id, -32602, str(exc), exc.marker)
    return _result_or_notification(is_notification, request_id, response)


def serve_stdio(root: Path | str, *, input_stream: TextIO | None = None, output_stream: TextIO | None = None) -> int:
    """Serve newline-delimited JSON-RPC requests over stdio and return 0 at EOF."""
    _workspace_root(root)
    input_stream = input_stream or sys.stdin
    output_stream = output_stream or sys.stdout
    for raw in input_stream:
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            response = _error(None, -32602, "invalid JSON-RPC request", "MCP_INVALID_PARAMS_REJECTED")
        else:
            response = dispatch(request, root)
        if response is not None:
            output_stream.write(_canonical(response) + "\n")
            output_stream.flush()
    return 0
