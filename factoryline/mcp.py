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
from .intent_ledger import IntentLedgerError, inspect_intent_ledger
from .judgment import JudgmentError, judgment_status, safety_case
from .graph_ops import graph_ops_impact, graph_ops_snapshot
from .journey_proof import journey_proof_status
from .langgraph_assurance import MCP_MARKER, LangGraphAssuranceError, verify_langgraph_resume_parity
from .proof_delta import proof_delta_status
from .proof_reuse import verify_proof_receipt
from .prd_grill import verify_prd_grill
from .intake_grill import intake_status
from .gauntlet import gauntlet_status
from .agent_license import AgentLicenseError, derive_license, license_projection, normalize_agent_identity
from .combine import combine_projection
from .workspace_advisor import inspect_workspace
from .revenueforge import RevenueForgeError, revenueforge_projection
from .revenue_evidence import query_evidence_memory
from .appforge_design import appforge_design_projection
from .appforge_oracle import appforge_oracle_projection
from .oracle_firewall import oracle_firewall_projection
from .semantic_authority import semantic_authority_projection
from .enterprise_enforcement import enterprise_enforcement_projection
from .atomic_proof_adapter import atomic_proof_projection
from .agent_proof_bridge import AgentProofBridgeError, agent_handoff_brief, agent_proof_projection
from .proof_worklog import proof_worklog_projection
from .operations_control import operations_control_projection
from .lifecycle_ledger import lifecycle_projection
from .repair_loop import repair_loop_projection
from .mission_control_status import mission_control_status
from .codex_metadata import MetadataAuditError, audit_metadata
from .saas_proof import saas_proof_projection
from .jetbrains_handshake import JetBrainsHandshakeError, build_agent_proof_mission, evaluate_jetbrains_handshake, jetbrains_handshake_projection


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
    Path(".factory/intent-ledgers"),
    Path(".factory/journey-proof"),
    Path(".factory/oracles"),
    Path(".factory/semantic-authority"),
    Path(".factory/enterprise-enforcement"),
    Path(".factory/appforge"),
    Path(".factory/operations-control"),
    Path(".factory/lifecycle"),
    Path(".factory/repair-loops"),
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
            "name": "factory.journey_status",
            "description": "Return only hash-verified local Journey Reality, failure capsule, workflow, healing, and agent-audit receipts. It never executes an agent or provider.",
            "inputSchema": no_args,
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
            "name": "factory.intent_ledger",
            "description": "Read a named local Change List's human-confirmed behavioral contract, scope escape, stale-proof, coverage state, and one fact-derived next action. It never captures or amends intent, starts an agent, runs a proof, or changes source.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "change_list": {"type": "string", "minLength": 1, "maxLength": 160},
                    "changed_paths": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 200,
                        "items": {"type": "string", "minLength": 1, "maxLength": 512},
                    },
                    "base": {"type": "string", "minLength": 1, "maxLength": 120},
                },
                "required": ["change_list"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.judgment_status",
            "description": "Return the tracked human-proposed and human-promoted engineering-decision Capsules. Read only; it never promotes, waives, or infers a decision.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.judgment_safety_case",
            "description": "Map explicit changed paths to active Judgment Capsules, supplied hash-bound proof receipts, and an optional human-declared hash-bound change profile. It returns deterministic routing and never executes a proof or change.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "changed_paths": {"type": "array", "minItems": 1, "maxItems": 50, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                    "proof_receipts": {"type": "array", "maxItems": 50, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                    "change_profile": {"type": "string", "minLength": 1, "maxLength": 512},
                },
                "required": ["changed_paths"],
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
        {
            "name": "factory.revenue_status",
            "description": "Return hash-verified local RevenueForge build and evidence status. It never contacts Apple, changes pricing, replies to testers, or publishes.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.revenue_memory",
            "description": "Return unexpired, exact-app Evidence Memory guidance for one journey and quarantine contradictions. Prior evidence never proves the current build.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "app_id": {"type": "string", "minLength": 1, "maxLength": 160},
                    "journey": {"type": "string", "minLength": 1, "maxLength": 80},
                    "at": {"type": "string", "format": "date-time", "maxLength": 40},
                },
                "required": ["app_id", "journey"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.appforge_status",
            "description": "Return hash-verified local AppForge design-contract status. It never creates, approves, renders, or releases a design.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.oracle_firewall_status",
            "description": "Read sealed original-intent handoffs, provenance contracts, independent challenge plans, and blocked weakening facts. It never alters an oracle, code, agent, or release.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.semantic_authority_status",
            "description": "Read hash-sealed agent handoffs, expiring scoped leases, and local admission receipts. It never sends a message, calls a tool, grants authority, or executes work.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.enterprise_enforcement_status",
            "description": "Read signed local workload-policy admission receipts and any exact decision-bound runner packet. It does not authenticate a cloud workload, execute argv, or enforce a network boundary.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.atomic_status",
            "description": "Read imported Atomic workflow DAG, capability handoff, checkpoint, and source-precondition facts bound to a sealed Oracle Contract. It never invokes Atomic, resumes a checkpoint, or grants authority.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.operations_control_status",
            "description": "Read local verified-isolation, repro-budget, change-envelope, proof-tier, architecture-zone, and coordination receipt facts. It never creates a worktree, dispatches a task, or approves work.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.lifecycle_status",
            "description": "Read local hash-linked harness lifecycle summaries. It does not broadcast, contact an agent, resume a run, or grant authority.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.repair_loop_status",
            "description": "Read exact failure, human-authored consequence, candidate, and independent re-check packet facts. It never executes a repair or approves work.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.mission_control_status",
            "description": "Read one bounded human/agent control-plane status built from local intent, operations, session, and repair evidence. It never grants authority.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.agent_bridge_status",
            "description": "Read imported Eve, Junie, Grok Build, CodeRabbit, Devin, or generic hash-only handoff receipts bound to a sealed Oracle Contract. It never starts an agent, contacts a provider, resumes a checkpoint, or grants authority.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.agent_handoff_brief",
            "description": "Render one current sealed Oracle Contract for an agent and supervising human. It never starts an agent or changes intent.",
            "inputSchema": {
                "type": "object",
                "properties": {"contract": {"type": "string", "minLength": 1, "maxLength": 512}},
                "required": ["contract"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.proof_worklog_status",
            "description": "Read local, review-required proof worklog drafts. It never posts to a tracker, chat, repository, or service.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.codex_metadata_audit",
            "description": "Audit selected local Codex/workflow metadata for unbound terminal claims, stale execution status, missing intent, or self-attested gates. It never reads provider state or mutates a receipt.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {"type": "array", "minItems": 1, "maxItems": 8, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                },
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.appforge_oracle_status",
            "description": "Read candidate-bound AppForge policy and user-intent authority receipts. It never contacts Apple, changes a candidate, or claims review readiness.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.saas_status",
            "description": "Return hash-verified local, provider-neutral OAuth/OIDC-to-entitlement proof status. It never contacts an identity, billing, or deployment provider.",
            "inputSchema": no_args,
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.agent_proof_mission",
            "description": "Render a sealed Junie-compatible proof mission from an existing repair scope. It never starts or configures an agent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "minLength": 1, "maxLength": 512},
                    "changed_paths": {"type": "array", "minItems": 1, "maxItems": 200, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                },
                "required": ["scope"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.jetbrains_handshake",
            "description": "Cross-check returned paths, Qodana or SonarQube SARIF, intent, and optional non-hollow E2E evidence without running any provider or test.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "minLength": 1, "maxLength": 512},
                    "changed_paths": {"type": "array", "minItems": 1, "maxItems": 200, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                    "analysis_sarif": {"type": "string", "minLength": 1, "maxLength": 512},
                    "analysis_provider": {"type": "string", "enum": ["auto", "qodana", "sonarqube"], "default": "auto"},
                    "qodana_sarif": {"type": "string", "minLength": 1, "maxLength": 512, "description": "Compatibility alias for analysis_sarif with provider qodana."},
                    "e2e_receipt": {"type": "string", "minLength": 1, "maxLength": 512},
                    "max_new_errors": {"type": "integer", "minimum": 0, "default": 0},
                    "max_new_warnings": {"type": "integer", "minimum": 0, "default": 0},
                },
                "required": ["scope", "changed_paths"],
                "additionalProperties": False,
            },
            "annotations": _READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "factory.jetbrains_handshake_status",
            "description": "Read the latest hash-valid local agent-analyzer-FactoryLine handshake receipt. It never reruns or approves it.",
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


def _intent_ledger(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"change_list", "changed_paths", "base"} or "change_list" not in arguments:
        raise McpError("factory.intent_ledger requires change_list and accepts only optional changed_paths and base")
    change_list = arguments["change_list"]
    if not isinstance(change_list, str) or not change_list.strip() or len(change_list) > 160:
        raise McpError("change_list must be a non-empty string of at most 160 characters")
    changed = _changed_paths({"changed_paths": arguments["changed_paths"]}) if "changed_paths" in arguments else None
    base = arguments.get("base", "main")
    if not isinstance(base, str) or not base.strip() or len(base) > 120:
        raise McpError("base must be a non-empty string of at most 120 characters")
    try:
        ledger = inspect_intent_ledger(root, change_list=change_list, changed=changed, base=base)
    except IntentLedgerError as exc:
        raise McpError(str(exc), exc.code) from exc
    return {
        "marker": "MCP_INTENT_LEDGER_READ_ONLY",
        "ledger": ledger,
        "scope": "Read-only local Intent Ledger projection; no record capture, source write, Change List edit, proof, agent, memory recall, approval, repair, merge, publication, deployment, signing, messaging, credential, or connector action ran.",
    }


def _judgment_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.judgment_status accepts no arguments")
    return {
        "marker": "MCP_JUDGMENT_STATUS_READ_ONLY",
        "status": judgment_status(root),
        "scope": "Read-only local human-decision projection; no model, policy inference, promotion, source write, proof execution, approval, repair, merge, publication, deployment, signing, messaging, credential, or connector action ran.",
    }


def _judgment_safety_case(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"changed_paths", "proof_receipts", "change_profile"} or "changed_paths" not in arguments:
        raise McpError("factory.judgment_safety_case requires changed_paths and accepts only optional proof_receipts and change_profile")
    changed = _changed_paths({"changed_paths": arguments["changed_paths"]})
    proof_values = arguments.get("proof_receipts", [])
    receipt_paths = _changed_paths({"changed_paths": proof_values}) if proof_values else []
    profile_value = arguments.get("change_profile")
    if profile_value is not None and (not isinstance(profile_value, str) or not profile_value.strip()):
        raise McpError("change_profile must be a non-empty workspace-relative path")
    try:
        value = safety_case(
            root,
            changed=changed,
            proof_receipts=[Path(item) for item in receipt_paths],
            change_profile=Path(profile_value) if isinstance(profile_value, str) else None,
        )
    except JudgmentError as exc:
        raise McpError(str(exc), exc.code) from exc
    return {
        "marker": "MCP_JUDGMENT_SAFETY_CASE_READ_ONLY",
        "safety_case": value,
        "scope": "Read-only deterministic route over explicit paths, supplied receipt hashes, and an optional human-declared change profile. It does not infer source semantics. No model, test execution, policy promotion, source write, approval, repair, merge, publication, deployment, signing, messaging, credential, or connector action ran.",
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


def _revenue_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.revenue_status accepts no arguments")
    return {
        "marker": "MCP_REVENUEFORGE_READ_ONLY",
        "action_summary": "Read current local RevenueForge receipts and surface mismatches or unknowns; no provider action ran.",
        "status": revenueforge_projection(root),
        "scope": "Read-only local projection; no Apple request, credential access, pricing, offer, reply, publication, deployment, or approval action ran.",
    }


def _revenue_memory(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"app_id", "journey", "at"} or not {"app_id", "journey"} <= set(arguments):
        raise McpError("factory.revenue_memory requires app_id and journey and accepts optional at")
    app_id = arguments["app_id"]
    journey = arguments["journey"]
    at = arguments.get("at")
    if not isinstance(app_id, str) or not app_id.strip() or len(app_id) > 160:
        raise McpError("app_id must be a non-empty string of at most 160 characters")
    if not isinstance(journey, str) or not journey.strip() or len(journey) > 80:
        raise McpError("journey must be a non-empty string of at most 80 characters")
    if at is not None and (not isinstance(at, str) or not at.strip() or len(at) > 40):
        raise McpError("at must be an ISO-8601 string of at most 40 characters")
    try:
        status = query_evidence_memory(root, app_id, journey, at)
    except RevenueForgeError as exc:
        raise McpError(str(exc), exc.code) from exc
    return {
        "marker": "MCP_REVENUEFORGE_MEMORY_READ_ONLY",
        "action_summary": "Retrieve exact-app, unexpired prior lessons and quarantine contradictions; require fresh evidence for the current build.",
        "status": status,
        "scope": "Read-only exact-scope guidance; no memory promotion, cross-tenant reuse, proof execution, provider action, or approval ran.",
    }


def _appforge_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.appforge_status accepts no arguments")
    return {
        "marker": "MCP_APPFORGE_READ_ONLY",
        "action_summary": "Read hash-verified local AppForge design, strict quality-audit, and submission-dossier receipts while preserving human design and release authority.",
        "status": appforge_design_projection(root),
        "scope": "Read-only local design projection; no design creation, intent override, render, App Store write, publication, deployment, or approval ran.",
    }


def _oracle_firewall_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.oracle_firewall_status accepts no arguments")
    return {
        "marker": "MCP_ORACLE_FIREWALL_READ_ONLY",
        "action_summary": "Read local source-to-decision facts, preserve blocked oracle weakening, and expose no mutation or approval surface.",
        "status": oracle_firewall_projection(root),
        "scope": "Read-only local proof-of-the-oracle projection; no contract sealing, candidate mutation, challenge execution, agent action, approval, or provider action ran.",
    }


def _semantic_authority_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.semantic_authority_status accepts no arguments")
    return {
        "marker": "MCP_SEMANTIC_AUTHORITY_READ_ONLY",
        "action_summary": "Read sealed context-bound handoffs, expiring least-privilege leases, and local decision receipts without treating a message as permission.",
        "status": semantic_authority_projection(root),
        "scope": "Read-only local proof projection. It does not validate open-ended semantics, authenticate a real-world identity, run a sandbox, invoke a tool, execute code, approve work, or contact a provider.",
    }


def _enterprise_enforcement_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.enterprise_enforcement_status accepts no arguments")
    return {
        "marker": "MCP_ENTERPRISE_ENFORCEMENT_READ_ONLY",
        "action_summary": "Read local signed workload/policy admission decisions and decision-bound runner packets without treating either as execution or a production deployment control.",
        "status": enterprise_enforcement_projection(root),
        "scope": "Read-only local PEP-reference projection. It does not perform OIDC federation, identify a live workload, invoke a tool, enforce an Envoy/eBPF/container boundary, approve work, or contact a provider.",
    }


def _atomic_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.atomic_status accepts no arguments")
    return {
        "marker": "ATOMIC_MCP_READ_ONLY",
        "action_summary": "Read local Atomic mechanics receipts only; retain the Oracle Contract, declared scope, and zero authority boundary.",
        "status": atomic_proof_projection(root),
        "scope": "Read-only imported evidence. No Atomic runtime, intercom message, checkpoint resume, code mutation, approval, provider call, or release action ran.",
    }


def _operations_control_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.operations_control_status accepts no arguments")
    return {
        "marker": "OPS_CONTROL_MCP_READ_ONLY",
        "action_summary": "Read local operational-precondition receipts without creating a worktree, running a reproduction, dispatching an agent, or changing a release decision.",
        "status": operations_control_projection(root),
        "scope": "Read-only local operations facts. No execution, provider call, approval, repair, merge, publication, deployment, credential, or connector action ran.",
    }


def _lifecycle_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.lifecycle_status accepts no arguments")
    return {
        "marker": "LIFECYCLE_MCP_READ_ONLY",
        "action_summary": "Read hash-linked local harness lifecycle facts while preserving the sealed intent and zero-authority boundary.",
        "status": lifecycle_projection(root),
        "scope": "Read-only local lifecycle facts. No task dispatch, broadcast, agent resume, execution, approval, provider, credential, connector, or release action ran.",
    }


def _repair_loop_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.repair_loop_status accepts no arguments")
    return {
        "marker": "REPAIR_LOOP_MCP_READ_ONLY",
        "action_summary": "Read exact issue-to-consequence-to-independent-recheck packets without attempting the candidate or changing any decision.",
        "status": repair_loop_projection(root),
        "scope": "Read-only local repair-loop facts. No repair, agent, provider, approval, merge, publication, deployment, credential, or connector action ran.",
    }


def _mission_control_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.mission_control_status accepts no arguments")
    return {
        "marker": "MISSION_CONTROL_MCP_READ_ONLY",
        "action_summary": "Read the shared human and agent control-plane state without granting an agent, human, or provider any action authority.",
        "status": mission_control_status(root),
        "scope": "Read-only local control-plane facts. No agent execution, repair, approval, merge, publication, deployment, credential, or connector action ran.",
    }


def _agent_bridge_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.agent_bridge_status accepts no arguments")
    return {
        "marker": "AGENT_PROOF_MCP_READ_ONLY",
        "action_summary": "Read locally bound provider-neutral agent proof facts while retaining the sealed Oracle Contract and zero-authority boundary.",
        "status": agent_proof_projection(root),
        "scope": "Read-only imported evidence. No Eve, Junie, Grok Build, Vercel, IDE, model, checkpoint, code, approval, provider, credential, or release action ran.",
    }


def _agent_handoff_brief(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) != {"contract"} or not isinstance(arguments.get("contract"), str) or not arguments["contract"].strip() or len(arguments["contract"]) > 512:
        raise McpError("factory.agent_handoff_brief requires one workspace-relative contract path")
    try:
        brief = agent_handoff_brief(root, Path(arguments["contract"]))
    except AgentProofBridgeError as exc:
        raise McpError(str(exc), exc.code) from exc
    return {"marker": "AGENT_HANDOFF_BRIEF_MCP_READ_ONLY", "action_summary": "Read the sealed original-intent contract shared by worker and reviewer without sending it to a provider or changing it.", "brief": brief}


def _proof_worklog_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.proof_worklog_status accepts no arguments")
    return {
        "marker": "PROOF_WORKLOG_MCP_READ_ONLY",
        "action_summary": "Read local review-required worklog drafts from sealed contracts and receipt summaries without posting or messaging anyone.",
        "status": proof_worklog_projection(root),
        "scope": "Read-only local draft evidence. No ticket, pull request, chat message, release note, provider, credential, approval, or deployment action ran.",
    }


def _codex_metadata_audit(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"paths"}:
        raise McpError("factory.codex_metadata_audit accepts optional paths only")
    supplied = arguments.get("paths")
    if supplied is not None and (not isinstance(supplied, list) or not 1 <= len(supplied) <= 8 or not all(isinstance(item, str) and item.strip() and len(item) <= 512 for item in supplied)):
        raise McpError("paths must contain 1-8 non-empty workspace-relative paths")
    try:
        audit = audit_metadata(root, [Path(item) for item in supplied] if supplied is not None else None)
    except MetadataAuditError as exc:
        raise McpError(exc.message, exc.code) from exc
    return {
        "marker": "MCP_CODEX_METADATA_AUDIT_READ_ONLY",
        "action_summary": "Hash selected local run metadata and surface unbound terminal claims, stale or orphaned run state, missing intent bindings, and self-attested gates without importing prompts, tool output, credentials, or provider state.",
        "audit": audit,
        "scope": "Read-only local metadata integrity only; no prompt body, credential, provider state, execution, approval, or release authority is exposed or granted.",
    }


def _appforge_oracle_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.appforge_oracle_status accepts no arguments")
    return {
        "marker": "MCP_APPFORGE_ORACLE_READ_ONLY",
        "action_summary": "Read candidate-bound AppForge authority receipts and surface missing policy or human-source controls without asserting App Review readiness.",
        "status": appforge_oracle_projection(root),
        "scope": "Read-only local authority metadata; no Apple request, credential access, TestFlight action, App Review submission, or approval claim ran.",
    }


def _saas_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.saas_status accepts no arguments")
    return {
        "marker": "MCP_SAAS_PROOF_READ_ONLY",
        "action_summary": "Read hash-valid local identity-to-entitlement proof status; no provider request or mutation ran.",
        "status": saas_proof_projection(root),
        "scope": "Read-only local receipt metadata; not OAuth provider certification, payment settlement, production proof, legal advice, or deploy authority.",
    }


def _agent_proof_mission(root: Path, arguments: object) -> dict[str, object]:
    if not isinstance(arguments, dict) or set(arguments) - {"scope", "changed_paths"} or "scope" not in arguments:
        raise McpError("factory.agent_proof_mission requires scope and accepts optional changed_paths")
    try:
        mission = build_agent_proof_mission(root, Path(arguments["scope"]), arguments.get("changed_paths"))
    except (JetBrainsHandshakeError, TypeError) as exc:
        raise McpError(str(exc), getattr(exc, "code", "MCP_INVALID_PARAMS_REJECTED")) from exc
    return {"marker": "MCP_AGENT_PROOF_MISSION_READ_ONLY", "mission": mission, "scope": "No agent, Qodana, test, source write, approval, credential, or network action ran."}


def _jetbrains_handshake(root: Path, arguments: object) -> dict[str, object]:
    required = {"scope", "changed_paths"}
    allowed = required | {"analysis_sarif", "analysis_provider", "qodana_sarif", "e2e_receipt", "max_new_errors", "max_new_warnings"}
    if not isinstance(arguments, dict) or set(arguments) - allowed or not required <= set(arguments):
        raise McpError("factory.jetbrains_handshake requires scope and changed_paths plus one analysis SARIF path")
    analysis_sarif = arguments.get("analysis_sarif")
    qodana_sarif = arguments.get("qodana_sarif")
    if bool(analysis_sarif) == bool(qodana_sarif):
        raise McpError("factory.jetbrains_handshake requires exactly one of analysis_sarif or qodana_sarif")
    provider = "qodana" if qodana_sarif else arguments.get("analysis_provider", "auto")
    try:
        result = evaluate_jetbrains_handshake(
            root, Path(arguments["scope"]), arguments["changed_paths"], Path(qodana_sarif or analysis_sarif),
            Path(arguments["e2e_receipt"]) if arguments.get("e2e_receipt") else None,
            analysis_provider=provider,
            max_new_errors=arguments.get("max_new_errors", 0), max_new_warnings=arguments.get("max_new_warnings", 0),
        )
    except (JetBrainsHandshakeError, TypeError) as exc:
        raise McpError(str(exc), getattr(exc, "code", "MCP_INVALID_PARAMS_REJECTED")) from exc
    return {"marker": "MCP_JETBRAINS_HANDSHAKE_READ_ONLY", "handshake": result, "scope": "No agent, analyzer, test, receipt write, approval, credential, or network action ran."}


def _jetbrains_handshake_status(root: Path, arguments: object) -> dict[str, object]:
    if arguments != {}:
        raise McpError("factory.jetbrains_handshake_status accepts no arguments")
    return {"marker": "MCP_JETBRAINS_HANDSHAKE_STATUS_READ_ONLY", "status": jetbrains_handshake_projection(root), "scope": "Latest local receipt metadata only; no evidence was rerun or approved."}


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
    if name == "factory.journey_status":
        if arguments != {}:
            raise McpError("factory.journey_status accepts no arguments")
        return _content(journey_proof_status(root))
    if name == "factory.graph_impact":
        return _content({
            "marker": "MCP_GRAPH_IMPACT_PARITY",
            "impact": graph_ops_impact(root, _changed_paths(arguments)),
        })
    if name == "factory.developer_memory":
        return _content(_developer_memory(root, arguments))
    if name == "factory.intent_ledger":
        return _content(_intent_ledger(root, arguments))
    if name == "factory.judgment_status":
        return _content(_judgment_status(root, arguments))
    if name == "factory.judgment_safety_case":
        return _content(_judgment_safety_case(root, arguments))
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
    if name == "factory.revenue_status":
        return _content(_revenue_status(root, arguments))
    if name == "factory.revenue_memory":
        return _content(_revenue_memory(root, arguments))
    if name == "factory.appforge_status":
        return _content(_appforge_status(root, arguments))
    if name == "factory.oracle_firewall_status":
        return _content(_oracle_firewall_status(root, arguments))
    if name == "factory.semantic_authority_status":
        return _content(_semantic_authority_status(root, arguments))
    if name == "factory.enterprise_enforcement_status":
        return _content(_enterprise_enforcement_status(root, arguments))
    if name == "factory.atomic_status":
        return _content(_atomic_status(root, arguments))
    if name == "factory.operations_control_status":
        return _content(_operations_control_status(root, arguments))
    if name == "factory.lifecycle_status":
        return _content(_lifecycle_status(root, arguments))
    if name == "factory.repair_loop_status":
        return _content(_repair_loop_status(root, arguments))
    if name == "factory.mission_control_status":
        return _content(_mission_control_status(root, arguments))
    if name == "factory.agent_bridge_status":
        return _content(_agent_bridge_status(root, arguments))
    if name == "factory.agent_handoff_brief":
        return _content(_agent_handoff_brief(root, arguments))
    if name == "factory.proof_worklog_status":
        return _content(_proof_worklog_status(root, arguments))
    if name == "factory.codex_metadata_audit":
        return _content(_codex_metadata_audit(root, arguments))
    if name == "factory.appforge_oracle_status":
        return _content(_appforge_oracle_status(root, arguments))
    if name == "factory.saas_status":
        return _content(_saas_status(root, arguments))
    if name == "factory.agent_proof_mission":
        return _content(_agent_proof_mission(root, arguments))
    if name == "factory.jetbrains_handshake":
        return _content(_jetbrains_handshake(root, arguments))
    if name == "factory.jetbrains_handshake_status":
        return _content(_jetbrains_handshake_status(root, arguments))
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
