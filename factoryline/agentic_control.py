"""Deterministic agent-access control plane for Code Factory.

This module turns the agentic-access patterns into small, verifiable contracts:
swim-lane events, model-tier routing, typed handoffs, lazy cookbook recipes,
reusable workflow manifests, and read-only branch/merge boundaries.  It never
starts a model, edits a checkout, creates a branch, or approves a merge.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable


SCHEMA = "factory.agentic-control.v1"
HANDOFF_SCHEMA = "factory.agent-handoff.v1"
SWIMLANE_SCHEMA = "factory.swimlane-event.v1"
WORKFLOW_SCHEMA = "factory.reusable-workflow.v1"
SANDBOX_SCHEMA = "factory.sandbox-boundary.v1"
ROUTE_TRACE_SCHEMA = "factory.route-trace.v1"
EXTENDED_RECEIPT_SCHEMA = "factory.receipt.v2"
EXTENDED_ASSURANCE_SCHEMA = "factory.extended-assurance.v1"
DRIFT_SCHEMA = "factory.agentic-control-drift.v1"
CAPABILITY_SCHEMA = "factory.capability-registry.v1"
TASK_CARD_SCHEMA = "factory.task-card.v1"
ORCHESTRATOR_PLAN_SCHEMA = "factory.orchestrator-plan.v1"
MODEL_ROUTE_SCHEMA = "factory.model-route.v1"
TASK_BOARD_SCHEMA = "factory.task-board.v1"
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_PHASES = ("scout", "plan", "build", "verify", "handoff", "review")
_TASK_STATES = ("queued", "leased", "running", "checkpointed", "verifying", "review_required", "completed", "blocked", "expired", "cancelled")
MODEL_TIERS = frozenset({"lightweight", "workhorse", "frontier"})
BASELINE_LANES = (
    "stateful_workflows",
    "authorization_tenant_isolation",
    "failure_recovery",
    "api_consumer_compatibility",
    "migration_data_integrity",
    "performance_resources",
)
EXTENDED_LANES = (
    "supply_chain_provenance",
    "semantic_robustness",
)
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "credential": False,
    "connector": False,
    "model_call": False,
}


class AgenticControlError(ValueError):
    """Fail-closed validation error for the agent-access boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(
        value if isinstance(value, bytes) else _canonical(value)
    ).hexdigest()


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise AgenticControlError("E_AGENTIC_ID", f"{label} must be a safe identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise AgenticControlError(
            "E_AGENTIC_DIGEST", f"{label} must be a SHA-256 digest"
        )
    return value


def _bounded_text(value: object, label: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise AgenticControlError(
            "E_AGENTIC_SCHEMA", f"{label} must be a bounded printable string"
        )
    return value.strip()


def _relative_paths(values: Iterable[str], label: str = "allowed_paths") -> list[str]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise AgenticControlError("E_AGENTIC_PATH", f"{label} contains an invalid path")
        path = Path(value.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise AgenticControlError("E_AGENTIC_PATH", f"{label} must be workspace-relative")
        normalized.append(path.as_posix())
    return sorted(set(normalized))


def create_capability_registry(
    registry_id: str,
    version: str,
    capabilities: Iterable[dict[str, Any]],
    *,
    owner: str = "human-release-authority",
) -> dict[str, Any]:
    """Create a hash-bound role/capability registry without granting authority."""
    registry_id = _id(registry_id, "registry_id")
    version = _bounded_text(version, "version", 32)
    owner = _id(owner, "owner")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in capabilities:
        if not isinstance(raw, dict):
            raise AgenticControlError("E_CAPABILITY_SCHEMA", "capability must be an object")
        required = {
            "id", "role", "risk_class", "allowed_tools", "forbidden_tools",
            "allowed_paths", "model_tier", "stop_condition", "approval_required",
            "required_evidence",
        }
        if set(raw) != required:
            raise AgenticControlError("E_CAPABILITY_SCHEMA", "capability fields are not exact")
        capability_id = _id(raw["id"], "capability.id")
        if capability_id in seen:
            raise AgenticControlError("E_CAPABILITY_SCHEMA", "capability ids must be unique")
        seen.add(capability_id)
        role = _id(raw["role"], "capability.role")
        if raw["risk_class"] not in {"low", "medium", "high", "critical"}:
            raise AgenticControlError("E_CAPABILITY_SCHEMA", "risk_class is invalid")
        if raw["model_tier"] not in {"lightweight", "workhorse", "frontier"}:
            raise AgenticControlError("E_CAPABILITY_SCHEMA", "model_tier is invalid")
        if not isinstance(raw["approval_required"], bool):
            raise AgenticControlError("E_CAPABILITY_SCHEMA", "approval_required must be boolean")
        tools = {}
        for key in ("allowed_tools", "forbidden_tools", "required_evidence"):
            value = raw[key]
            if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
                raise AgenticControlError("E_CAPABILITY_SCHEMA", f"{key} must be a list of strings")
            tools[key] = sorted(set(item.strip() for item in value))
        overlap = set(tools["allowed_tools"]) & set(tools["forbidden_tools"])
        if overlap:
            raise AgenticControlError("E_CAPABILITY_SCHEMA", "allowed and forbidden tools overlap")
        rows.append({
            "id": capability_id,
            "role": role,
            "risk_class": raw["risk_class"],
            "allowed_tools": tools["allowed_tools"],
            "forbidden_tools": tools["forbidden_tools"],
            "allowed_paths": _relative_paths(raw["allowed_paths"]),
            "model_tier": raw["model_tier"],
            "stop_condition": _bounded_text(raw["stop_condition"], "stop_condition"),
            "approval_required": raw["approval_required"],
            "required_evidence": tools["required_evidence"],
        })
    if not rows:
        raise AgenticControlError("E_CAPABILITY_SCHEMA", "at least one capability is required")
    core = {
        "schema": CAPABILITY_SCHEMA,
        "registry_id": registry_id,
        "version": version,
        "owner": owner,
        "capabilities": sorted(rows, key=lambda item: item["id"]),
        "authority": dict(_AUTHORITY),
    }
    digest = _sha(core)
    return {**core, "registry_sha256": digest, "marker": "CAPABILITY_REGISTRY_HASH_BOUND"}


def verify_capability_registry(registry: dict[str, Any]) -> dict[str, Any]:
    """Verify registry bytes and reject any authority escalation or ambiguity."""
    if not isinstance(registry, dict) or registry.get("schema") != CAPABILITY_SCHEMA:
        raise AgenticControlError("E_CAPABILITY_SCHEMA", f"registry must use {CAPABILITY_SCHEMA}")
    required = {"schema", "registry_id", "version", "owner", "capabilities", "authority"}
    if set(registry) != required | {"registry_sha256", "marker"}:
        raise AgenticControlError("E_CAPABILITY_SCHEMA", "registry fields are not exact")
    core = {key: registry[key] for key in required}
    if registry.get("registry_sha256") != _sha(core):
        raise AgenticControlError("E_CAPABILITY_TAMPERED", "registry digest does not match contents")
    if registry.get("marker") != "CAPABILITY_REGISTRY_HASH_BOUND":
        raise AgenticControlError("E_CAPABILITY_SCHEMA", "registry marker is invalid")
    if not isinstance(core["authority"], dict) or any(value is not False for value in core["authority"].values()):
        raise AgenticControlError("E_CAPABILITY_AUTHORITY", "registry cannot grant authority")
    # Re-run the canonical constructor to validate every nested field.
    rebuilt = create_capability_registry(
        core["registry_id"], core["version"], core["capabilities"], owner=core["owner"]
    )
    if rebuilt["registry_sha256"] != registry["registry_sha256"]:
        raise AgenticControlError("E_CAPABILITY_TAMPERED", "registry normalization changed its digest")
    return dict(registry)


def create_task_card(
    task_id: str,
    workflow_id: str,
    capability_id: str,
    registry_sha256: str,
    intent_digest: str,
    *,
    allowed_paths: Iterable[str] = (),
    dependencies: Iterable[str] = (),
    stop_condition: str,
    next_action: str,
    created_at: str,
) -> dict[str, Any]:
    """Create a durable, lease-ready task card; it never dispatches work."""
    task_id, workflow_id, capability_id = (
        _id(task_id, "task_id"), _id(workflow_id, "workflow_id"), _id(capability_id, "capability_id")
    )
    _digest(registry_sha256, "registry_sha256")
    _digest(intent_digest, "intent_digest")
    deps = sorted(set(_id(value, "dependency") for value in dependencies))
    if task_id in deps:
        raise AgenticControlError("E_TASK_CARD", "task cannot depend on itself")
    core = {
        "schema": TASK_CARD_SCHEMA,
        "task_id": task_id,
        "workflow_id": workflow_id,
        "capability_id": capability_id,
        "registry_sha256": registry_sha256,
        "intent_digest": intent_digest,
        "allowed_paths": _relative_paths(allowed_paths),
        "dependencies": deps,
        "state": "queued",
        "attempt": 0,
        "lease": None,
        "checkpoint": None,
        "stop_condition": _bounded_text(stop_condition, "stop_condition"),
        "next_action": _bounded_text(next_action, "next_action"),
        "created_at": _bounded_text(created_at, "created_at", 80),
        "authority": dict(_AUTHORITY),
    }
    digest = _sha(core)
    return {**core, "task_sha256": digest, "marker": "TASK_CARD_HASH_BOUND"}


def transition_task_card(
    card: dict[str, Any],
    state: str,
    *,
    lease_id: str | None = None,
    lease_expires_at: str | None = None,
    checkpoint_digest: str | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Apply one deterministic task transition and return a new hash-bound card."""
    verify_task_card(card)
    if state not in _TASK_STATES:
        raise AgenticControlError("E_TASK_STATE", "unsupported task state")
    current = card["state"]
    allowed = {
        "queued": {"leased", "cancelled"},
        "leased": {"running", "expired", "cancelled"},
        "running": {"checkpointed", "verifying", "blocked", "expired", "cancelled"},
        "checkpointed": {"running", "verifying", "blocked", "expired"},
        "verifying": {"review_required", "completed", "blocked"},
        "review_required": {"completed", "blocked"},
        "blocked": {"leased", "cancelled"},
        "expired": {"leased", "cancelled"},
        "completed": set(),
        "cancelled": set(),
    }
    if state not in allowed[current]:
        raise AgenticControlError("E_TASK_TRANSITION", f"cannot move {current} to {state}")
    updated = dict(card)
    updated["state"] = state
    if state == "leased":
        if not lease_id or not lease_expires_at:
            raise AgenticControlError("E_TASK_LEASE", "lease id and expiry are required")
        updated["lease"] = {"lease_id": _id(lease_id, "lease_id"), "expires_at": _bounded_text(lease_expires_at, "lease_expires_at", 80)}
        updated["attempt"] = int(card["attempt"]) + 1
    elif state in {"expired", "cancelled", "completed"}:
        updated["lease"] = None
    if checkpoint_digest is not None:
        _digest(checkpoint_digest, "checkpoint_digest")
        updated["checkpoint"] = checkpoint_digest
    if evidence_digest is not None:
        _digest(evidence_digest, "evidence_digest")
        updated["evidence_digest"] = evidence_digest
    core = {key: value for key, value in updated.items() if key not in {"task_sha256", "marker", "evidence_digest"}}
    if "evidence_digest" in updated:
        core["evidence_digest"] = updated["evidence_digest"]
    digest = _sha(core)
    return {**core, "task_sha256": digest, "marker": "TASK_CARD_HASH_BOUND"}


def verify_task_card(card: dict[str, Any]) -> dict[str, Any]:
    """Verify a task card's digest, state, and authority boundary."""
    if not isinstance(card, dict) or card.get("schema") != TASK_CARD_SCHEMA:
        raise AgenticControlError("E_TASK_SCHEMA", f"task card must use {TASK_CARD_SCHEMA}")
    if card.get("marker") != "TASK_CARD_HASH_BOUND" or not isinstance(card.get("task_sha256"), str):
        raise AgenticControlError("E_TASK_SCHEMA", "task card marker or digest is missing")
    required = {
        "schema", "task_id", "workflow_id", "capability_id", "registry_sha256",
        "intent_digest", "allowed_paths", "dependencies", "state", "attempt",
        "lease", "checkpoint", "stop_condition", "next_action", "created_at",
        "authority", "task_sha256", "marker",
    }
    optional = {"evidence_digest"}
    if set(card) - required - optional or required - set(card):
        raise AgenticControlError("E_TASK_SCHEMA", "task card fields are not exact")
    core = {key: value for key, value in card.items() if key not in {"task_sha256", "marker"}}
    if card["task_sha256"] != _sha(core):
        raise AgenticControlError("E_TASK_TAMPERED", "task card digest does not match contents")
    if card.get("state") not in _TASK_STATES or not isinstance(card.get("authority"), dict):
        raise AgenticControlError("E_TASK_SCHEMA", "task card state or authority is invalid")
    if not isinstance(card.get("attempt"), int) or isinstance(card.get("attempt"), bool) or card["attempt"] < 0:
        raise AgenticControlError("E_TASK_SCHEMA", "task card attempt is invalid")
    if not isinstance(card.get("lease"), (dict, type(None))):
        raise AgenticControlError("E_TASK_SCHEMA", "task card lease is invalid")
    if isinstance(card.get("lease"), dict):
        if set(card["lease"]) != {"lease_id", "expires_at"}:
            raise AgenticControlError("E_TASK_SCHEMA", "task card lease fields are not exact")
        _id(card["lease"]["lease_id"], "lease_id")
        _bounded_text(card["lease"]["expires_at"], "lease_expires_at", 80)
    if card.get("checkpoint") is not None:
        _digest(card["checkpoint"], "checkpoint_digest")
    if card.get("evidence_digest") is not None:
        _digest(card["evidence_digest"], "evidence_digest")
    _digest(card["registry_sha256"], "registry_sha256")
    _digest(card["intent_digest"], "intent_digest")
    if any(value is not False for value in card["authority"].values()):
        raise AgenticControlError("E_TASK_AUTHORITY", "task card cannot grant authority")
    return dict(card)


def project_task_board(cards: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Project verified task cards into deterministic Kanban swim lanes.

    This is intentionally a projection, not a dispatcher.  It validates the
    dependency graph, rejects missing edges and cycles, then reports what is
    ready, waiting, running, in review, or blocked.  No lease, model, branch,
    merge, or release action is performed.
    """
    verified = [verify_task_card(card) for card in cards]
    by_id: dict[str, dict[str, Any]] = {}
    for card in verified:
        task_id = _id(card["task_id"], "task_id")
        if task_id in by_id:
            raise AgenticControlError("E_TASK_BOARD_DUPLICATE", "task ids must be unique")
        if not isinstance(card.get("dependencies"), list):
            raise AgenticControlError("E_TASK_BOARD_DEPENDENCY", "dependencies must be a list")
        for dependency in card["dependencies"]:
            _id(dependency, "dependency")
        by_id[task_id] = card

    for card in verified:
        missing = sorted(set(card["dependencies"]) - set(by_id))
        if missing:
            raise AgenticControlError(
                "E_TASK_BOARD_DEPENDENCY",
                f"unknown dependencies for {card['task_id']}: {', '.join(missing)}",
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise AgenticControlError("E_TASK_BOARD_CYCLE", "task dependency graph contains a cycle")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dependency in by_id[task_id]["dependencies"]:
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in sorted(by_id):
        visit(task_id)

    completed = {task_id for task_id, card in by_id.items() if card["state"] == "completed"}
    rows: list[dict[str, Any]] = []
    lane_ids: dict[str, list[str]] = {
        "triage": [], "ready": [], "running": [], "review": [],
        "blocked": [], "done": [],
    }
    for task_id in sorted(by_id):
        card = by_id[task_id]
        unmet = sorted(set(card["dependencies"]) - completed)
        state = card["state"]
        if state == "completed":
            lane = "done"
        elif state in {"leased", "running", "checkpointed"}:
            lane = "running"
        elif state in {"verifying", "review_required"}:
            lane = "review"
        elif state in {"blocked", "expired", "cancelled"}:
            lane = "blocked"
        elif unmet:
            lane = "triage"
        else:
            lane = "ready"
        lane_ids[lane].append(task_id)
        rows.append({
            "task_id": task_id,
            "workflow_id": card["workflow_id"],
            "state": state,
            "lane": lane,
            "dependencies": sorted(card["dependencies"]),
            "unmet_dependencies": unmet,
            "attempt": card["attempt"],
            "task_sha256": card["task_sha256"],
            "next_action": card["next_action"],
            "stop_condition": card["stop_condition"],
        })

    edges = [
        {"from": task_id, "to": dependency}
        for task_id in sorted(by_id)
        for dependency in sorted(by_id[task_id]["dependencies"])
    ]
    next_actions = [
        {
            "task_id": task_id,
            "action": "REVIEW_READY_CARD",
            "reason": "All dependencies are completed; a human or approved orchestrator may decide the next step.",
        }
        for task_id in lane_ids["ready"]
    ] + [
        {
            "task_id": task_id,
            "action": "RESOLVE_DEPENDENCIES",
            "reason": "Task is waiting on incomplete dependency cards.",
        }
        for task_id in lane_ids["triage"]
    ]
    core = {
        "schema": TASK_BOARD_SCHEMA,
        "task_count": len(rows),
        "cards": rows,
        "lanes": {lane: ids for lane, ids in lane_ids.items()},
        "dependency_edges": edges,
        "next_actions": next_actions,
        "dispatcher": {"poll_interval_seconds": 60, "started": False},
        "authority": dict(_AUTHORITY),
        "claim_boundary": "Read-only task metadata; no dispatch, lease, model, branch, merge, approval, publication, or deployment action ran.",
    }
    return {
        **core,
        "board_sha256": _sha(core),
        "marker": "TASK_BOARD_PROJECTED_READ_ONLY",
    }


def verify_task_board(board: dict[str, Any]) -> dict[str, Any]:
    """Verify a projected task board and its authority boundary."""
    if not isinstance(board, dict) or board.get("schema") != TASK_BOARD_SCHEMA:
        raise AgenticControlError("E_TASK_BOARD_SCHEMA", f"board must use {TASK_BOARD_SCHEMA}")
    required = {
        "schema", "task_count", "cards", "lanes", "dependency_edges", "next_actions",
        "dispatcher", "authority", "claim_boundary",
    }
    if set(board) != required | {"board_sha256", "marker"}:
        raise AgenticControlError("E_TASK_BOARD_SCHEMA", "board fields are not exact")
    core = {key: board[key] for key in required}
    if board.get("board_sha256") != _sha(core):
        raise AgenticControlError("E_TASK_BOARD_TAMPERED", "board digest does not match contents")
    if board.get("marker") != "TASK_BOARD_PROJECTED_READ_ONLY":
        raise AgenticControlError("E_TASK_BOARD_SCHEMA", "board marker is invalid")
    if not isinstance(board["authority"], dict) or any(value is not False for value in board["authority"].values()):
        raise AgenticControlError("E_TASK_BOARD_AUTHORITY", "task board cannot grant authority")
    if board["dispatcher"] != {"poll_interval_seconds": 60, "started": False}:
        raise AgenticControlError("E_TASK_BOARD_SCHEMA", "dispatcher metadata is invalid")
    return dict(board)


def create_orchestrator_plan(
    request: dict[str, Any], *, created_at: str | None = None
) -> dict[str, Any]:
    """Compile a typed request-routing plan without dispatching an agent or tool."""
    if not isinstance(request, dict):
        raise AgenticControlError("E_ORCHESTRATOR_INPUT", "request must be an object")
    required = {
        "goal",
        "intent_digest",
        "capability_registry_sha256",
        "workflow_ids",
        "recipe_names",
        "task_ids",
        "model_tier",
        "stop_condition",
        "approval_required",
    }
    if set(request) != required:
        raise AgenticControlError(
            "E_ORCHESTRATOR_SCHEMA", "request fields must exactly match the routing contract"
        )
    goal = _bounded_text(request["goal"], "goal", maximum=1024)
    intent_digest = _digest(request["intent_digest"], "intent_digest")
    registry_digest = _digest(
        request["capability_registry_sha256"], "capability_registry_sha256"
    )
    model_tier = _id(request["model_tier"], "model_tier")
    if model_tier not in MODEL_TIERS:
        raise AgenticControlError(
            "E_ORCHESTRATOR_MODEL_TIER",
            "model_tier must be lightweight, workhorse, or frontier",
        )
    stop_condition = _bounded_text(request["stop_condition"], "stop_condition")
    if request["approval_required"] is not True:
        raise AgenticControlError(
            "E_ORCHESTRATOR_APPROVAL", "orchestrator plans require human approval"
        )
    def _ids(value: object, label: str) -> list[str]:
        if not isinstance(value, list):
            raise AgenticControlError("E_ORCHESTRATOR_SCHEMA", f"{label} must be a list")
        return sorted({_id(item, f"{label} item") for item in value})

    workflow_ids = _ids(request["workflow_ids"], "workflow_ids")
    recipe_names = _ids(request["recipe_names"], "recipe_names")
    task_ids = _ids(request["task_ids"], "task_ids")
    if not workflow_ids or not task_ids:
        raise AgenticControlError(
            "E_ORCHESTRATOR_SCHEMA", "at least one workflow and task are required"
        )
    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    core = {
        "schema": ORCHESTRATOR_PLAN_SCHEMA,
        "goal": goal,
        "intent_digest": intent_digest,
        "capability_registry_sha256": registry_digest,
        "workflow_ids": workflow_ids,
        "recipe_names": recipe_names,
        "task_ids": task_ids,
        "model_tier": model_tier,
        "stop_condition": stop_condition,
        "approval_required": True,
        "created_at": timestamp,
        "status": "PLANNED",
        "authority": dict(_AUTHORITY),
    }
    digest = _sha(core)
    return {
        **core,
        "plan_id": "orchestrator-plan:" + digest[:32],
        "plan_sha256": digest,
        "next_action": "human_review_required",
    }


def verify_orchestrator_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Verify a routing plan and reject authority or intent mutations."""
    if not isinstance(plan, dict) or plan.get("schema") != ORCHESTRATOR_PLAN_SCHEMA:
        raise AgenticControlError("E_ORCHESTRATOR_SCHEMA", "unsupported orchestrator plan")
    core_keys = {
        "schema",
        "goal",
        "intent_digest",
        "capability_registry_sha256",
        "workflow_ids",
        "recipe_names",
        "task_ids",
        "model_tier",
        "stop_condition",
        "approval_required",
        "created_at",
        "status",
        "authority",
    }
    if set(plan) != core_keys | {"plan_id", "plan_sha256", "next_action"}:
        raise AgenticControlError("E_ORCHESTRATOR_SCHEMA", "plan fields are not exact")
    if plan.get("plan_sha256") != _sha({key: plan[key] for key in core_keys}):
        raise AgenticControlError("E_ORCHESTRATOR_TAMPERED", "plan digest does not match contents")
    if plan.get("plan_id") != "orchestrator-plan:" + str(plan["plan_sha256"])[:32]:
        raise AgenticControlError("E_ORCHESTRATOR_TAMPERED", "plan id does not match digest")
    if plan.get("approval_required") is not True or plan.get("status") != "PLANNED":
        raise AgenticControlError("E_ORCHESTRATOR_APPROVAL", "plan must remain pending human approval")
    if any(value is not False for value in plan.get("authority", {}).values()):
        raise AgenticControlError("E_ORCHESTRATOR_AUTHORITY", "plan cannot grant authority")
    return dict(plan)


def _route_fields(
    route: dict[str, Any], *, require_schema: bool = True
) -> dict[str, Any]:
    """Validate and normalize the deterministic model-route fields."""
    if require_schema and route.get("schema") != MODEL_ROUTE_SCHEMA:
        raise AgenticControlError(
            "E_ROUTE_TRACE", "model route schema marker is missing"
        )
    tier = route.get("tier")
    task_class = route.get("task_class")
    risk = route.get("risk")
    rationale = route.get("rationale")
    if tier not in {"lightweight", "workhorse", "frontier"}:
        raise AgenticControlError("E_ROUTE_TRACE", "model route tier is invalid")
    if task_class not in {"routine", "standard", "critical"}:
        raise AgenticControlError("E_ROUTE_TRACE", "model route task class is invalid")
    if risk not in {"low", "medium", "high", "critical"}:
        raise AgenticControlError("E_ROUTE_TRACE", "model route risk is invalid")
    if not isinstance(rationale, str) or not rationale.strip():
        raise AgenticControlError("E_ROUTE_TRACE", "model route rationale is required")
    return {
        "tier": tier,
        "task_class": task_class,
        "risk": risk,
        "rationale": rationale,
    }


def route_model(
    task_class: str,
    *,
    risk: str = "medium",
    latency_budget_ms: int | None = None,
    token_budget: int | None = None,
) -> dict[str, Any]:
    """Choose a model tier using explicit inputs only; no model is contacted."""
    if task_class not in {"routine", "standard", "critical"}:
        raise AgenticControlError(
            "E_MODEL_ROUTE", "task_class must be routine, standard, or critical"
        )
    if risk not in {"low", "medium", "high", "critical"}:
        raise AgenticControlError(
            "E_MODEL_ROUTE", "risk must be low, medium, high, or critical"
        )
    for value, label in (
        (latency_budget_ms, "latency_budget_ms"),
        (token_budget, "token_budget"),
    ):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise AgenticControlError(
                "E_MODEL_ROUTE", f"{label} must be a non-negative integer or null"
            )
    if risk in {"high", "critical"} or task_class == "critical":
        tier, reason = (
            "frontier",
            "high-risk or critical work requires the deepest review capacity",
        )
    elif task_class == "routine" and (
        latency_budget_ms is not None and latency_budget_ms <= 1500
    ):
        tier, reason = (
            "lightweight",
            "bounded routine work prioritizes latency and cost",
        )
    elif token_budget is not None and token_budget < 4000 and task_class == "routine":
        tier, reason = "lightweight", "bounded token budget fits a lightweight route"
    else:
        tier, reason = "workhorse", "standard work uses the balanced default tier"
    core = {
        "schema": MODEL_ROUTE_SCHEMA,
        "tier": tier,
        "task_class": task_class,
        "risk": risk,
        "budgets": {
            "latency_budget_ms": latency_budget_ms,
            "token_budget": token_budget,
        },
        "rationale": reason,
        "authority": {"model_call": False, "execution": False},
        "marker": "MODEL_ROUTE_DETERMINISTIC",
    }
    return {**core, "route_sha256": _sha(core)}


def verify_model_route(route: dict[str, Any]) -> dict[str, Any]:
    """Verify a standalone deterministic model-route receipt.

    The receipt describes routing intent only. It cannot select a provider,
    invoke a model, spend credits, or grant execution authority.
    """
    if not isinstance(route, dict) or route.get("schema") != MODEL_ROUTE_SCHEMA:
        raise AgenticControlError("E_MODEL_ROUTE_TRACE", "unsupported model route")
    required = {
        "schema",
        "tier",
        "task_class",
        "risk",
        "budgets",
        "rationale",
        "authority",
        "marker",
    }
    if set(route) != required | {"route_sha256"}:
        raise AgenticControlError(
            "E_MODEL_ROUTE_TRACE", "model route fields are not exact"
        )
    core = {key: route[key] for key in required}
    _route_fields(core)
    budgets = core["budgets"]
    if not isinstance(budgets, dict) or set(budgets) != {
        "latency_budget_ms",
        "token_budget",
    }:
        raise AgenticControlError("E_MODEL_ROUTE_TRACE", "model route budgets are invalid")
    for value, label in (
        (budgets["latency_budget_ms"], "latency_budget_ms"),
        (budgets["token_budget"], "token_budget"),
    ):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise AgenticControlError(
                "E_MODEL_ROUTE_TRACE", f"{label} must be a non-negative integer or null"
            )
    if core["marker"] != "MODEL_ROUTE_DETERMINISTIC":
        raise AgenticControlError("E_MODEL_ROUTE_TRACE", "model route marker is invalid")
    if core["authority"] != {"model_call": False, "execution": False}:
        raise AgenticControlError(
            "E_MODEL_ROUTE_AUTHORITY", "model route cannot grant authority"
        )
    if route["route_sha256"] != _sha(core):
        raise AgenticControlError(
            "E_MODEL_ROUTE_TAMPERED", "model route digest does not match contents"
        )
    return dict(route)


def create_typed_handoff(
    workflow_id: str,
    stage: str,
    source_agent: str,
    target_agent: str,
    intent_digest: str,
    payload_digest: str,
    *,
    allowed_paths: Iterable[str] = (),
    next_action: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Create a secret-free, hash-bound handoff envelope."""
    workflow_id, source_agent, target_agent = (
        _id(workflow_id, "workflow_id"),
        _id(source_agent, "source_agent"),
        _id(target_agent, "target_agent"),
    )
    if not isinstance(stage, str) or stage not in _PHASES:
        raise AgenticControlError(
            "E_HANDOFF_STAGE", f"stage must be one of {', '.join(_PHASES)}"
        )
    _digest(intent_digest, "intent_digest")
    _digest(payload_digest, "payload_digest")
    if (
        not isinstance(next_action, str)
        or not next_action.strip()
        or len(next_action) > 512
    ):
        raise AgenticControlError(
            "E_HANDOFF_ACTION", "next_action must be a bounded non-empty string"
        )
    paths = []
    for path in allowed_paths:
        if (
            not isinstance(path, str)
            or not path.strip()
            or Path(path).is_absolute()
            or ".." in Path(path).parts
        ):
            raise AgenticControlError(
                "E_HANDOFF_PATH", "allowed_paths must be workspace-relative"
            )
        paths.append(Path(path.replace("\\", "/")).as_posix())
    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise AgenticControlError(
            "E_HANDOFF_TIME", "created_at must be a non-empty timestamp"
        )
    core = {
        "schema": HANDOFF_SCHEMA,
        "workflow_id": workflow_id,
        "stage": stage,
        "source_agent": source_agent,
        "target_agent": target_agent,
        "intent_digest": intent_digest,
        "payload_digest": payload_digest,
        "allowed_paths": sorted(set(paths)),
        "next_action": next_action.strip(),
        "created_at": timestamp,
        "authority": dict(_AUTHORITY),
    }
    return {
        **core,
        "handoff_id": "handoff:" + _sha(core)[:32],
        "handoff_sha256": _sha(core),
    }


def verify_typed_handoff(envelope: dict[str, Any]) -> dict[str, Any]:
    """Verify the exact handoff digest and reject unsupported mutations."""
    if not isinstance(envelope, dict) or envelope.get("schema") != HANDOFF_SCHEMA:
        raise AgenticControlError(
            "E_HANDOFF_SCHEMA", f"handoff must use {HANDOFF_SCHEMA}"
        )
    required = {
        "schema",
        "workflow_id",
        "stage",
        "source_agent",
        "target_agent",
        "intent_digest",
        "payload_digest",
        "allowed_paths",
        "next_action",
        "created_at",
        "authority",
    }
    if set(envelope) != required | {"handoff_id", "handoff_sha256"}:
        raise AgenticControlError("E_HANDOFF_SCHEMA", "handoff fields are not exact")
    core = {key: envelope[key] for key in required}
    expected = _sha(core)
    if (
        envelope.get("handoff_sha256") != expected
        or envelope.get("handoff_id") != "handoff:" + expected[:32]
    ):
        raise AgenticControlError(
            "E_HANDOFF_TAMPERED", "handoff digest does not match its contents"
        )
    if any(value is not False for value in envelope["authority"].values()):
        raise AgenticControlError(
            "E_HANDOFF_AUTHORITY", "handoff cannot grant authority"
        )
    return dict(envelope)


def create_route_trace(
    route: dict[str, Any],
    workflow: dict[str, Any],
    handoff: dict[str, Any],
    swimlane_events: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Bind routing, workflow, handoff, and lane lineage into one trace."""
    if not isinstance(route, dict):
        raise AgenticControlError(
            "E_ROUTE_TRACE", "a deterministic model route is required"
        )
    route_fields = (
        _route_fields(verify_model_route(route))
        if "route_sha256" in route
        else _route_fields(route)
    )
    verified_workflow = verify_reusable_workflow(workflow)
    verified_handoff = verify_typed_handoff(handoff)
    events = verify_swimlane(swimlane_events)
    if verified_workflow["workflow_id"] != verified_handoff["workflow_id"]:
        raise AgenticControlError(
            "E_ROUTE_TRACE", "workflow and handoff identifiers differ"
        )
    if events["workflow_id"] != verified_handoff["workflow_id"]:
        raise AgenticControlError(
            "E_ROUTE_TRACE", "swim-lane workflow identifier differs"
        )
    core = {
        "schema": ROUTE_TRACE_SCHEMA,
        "route": route_fields,
        "workflow_sha256": verified_workflow["workflow_sha256"],
        "handoff_sha256": verified_handoff["handoff_sha256"],
        "swimlane_head_digest": events["head_digest"],
        "event_count": events["events"],
        "authority": dict(_AUTHORITY),
    }
    digest = _sha(core)
    return {
        **core,
        "trace_id": "route:" + digest[:32],
        "trace_sha256": digest,
        "marker": "ROUTE_TRACE_HASH_BOUND",
        "claim_boundary": "Route lineage only; no model call, source mutation, execution, approval, merge, or release action ran.",
    }


def verify_route_trace(trace: dict[str, Any]) -> dict[str, Any]:
    """Verify route-trace hashes and ensure every linked authority is false."""
    if not isinstance(trace, dict) or trace.get("schema") != ROUTE_TRACE_SCHEMA:
        raise AgenticControlError(
            "E_ROUTE_TRACE", f"trace must use {ROUTE_TRACE_SCHEMA}"
        )
    keys = (
        "schema",
        "route",
        "workflow_sha256",
        "handoff_sha256",
        "swimlane_head_digest",
        "event_count",
        "authority",
    )
    core = {key: trace.get(key) for key in keys}
    _route_fields(
        core["route"] if isinstance(core["route"], dict) else {},
        require_schema=False,
    )
    for key in ("workflow_sha256", "handoff_sha256", "swimlane_head_digest"):
        _digest(core[key], key)
    if (
        isinstance(core["event_count"], bool)
        or not isinstance(core["event_count"], int)
        or core["event_count"] < 1
    ):
        raise AgenticControlError(
            "E_ROUTE_TRACE", "event_count must be a positive integer"
        )
    if not isinstance(core["authority"], dict):
        raise AgenticControlError(
            "E_ROUTE_TRACE_AUTHORITY", "route authority must be an object"
        )
    expected = _sha(core)
    if (
        trace.get("trace_sha256") != expected
        or trace.get("trace_id") != "route:" + expected[:32]
    ):
        raise AgenticControlError(
            "E_ROUTE_TRACE_TAMPERED", "route trace digest does not match contents"
        )
    if any(value is not False for value in trace.get("authority", {}).values()):
        raise AgenticControlError(
            "E_ROUTE_TRACE_AUTHORITY", "route trace cannot grant authority"
        )
    return dict(trace)


def new_swimlane_event(
    workflow_id: str,
    lane: str,
    stage: str,
    status: str,
    *,
    sequence: int,
    artifact_digest: str | None = None,
    previous_event_digest: str | None = None,
    elapsed_ms: int | None = None,
) -> dict[str, Any]:
    """Create one append-only, observable swim-lane event."""
    _id(workflow_id, "workflow_id")
    if not isinstance(lane, str) or not lane.strip() or len(lane) > 96:
        raise AgenticControlError(
            "E_SWIMLANE_SCHEMA", "lane must be a bounded non-empty string"
        )
    if stage not in _PHASES or not isinstance(status, str) or not status.strip():
        raise AgenticControlError("E_SWIMLANE_SCHEMA", "stage or status is invalid")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise AgenticControlError(
            "E_SWIMLANE_SEQUENCE", "sequence must be a non-negative integer"
        )
    if artifact_digest is not None:
        _digest(artifact_digest, "artifact_digest")
    if previous_event_digest is not None:
        _digest(previous_event_digest, "previous_event_digest")
    if elapsed_ms is not None and (
        isinstance(elapsed_ms, bool)
        or not isinstance(elapsed_ms, int)
        or elapsed_ms < 0
    ):
        raise AgenticControlError(
            "E_SWIMLANE_SCHEMA", "elapsed_ms must be non-negative"
        )
    core = {
        "schema": SWIMLANE_SCHEMA,
        "workflow_id": workflow_id,
        "lane": lane.strip(),
        "stage": stage,
        "status": status.strip(),
        "sequence": sequence,
        "artifact_digest": artifact_digest,
        "previous_event_digest": previous_event_digest,
        "elapsed_ms": elapsed_ms,
    }
    digest = _sha(core)
    return {**core, "event_id": "swim:" + digest[:32], "event_digest": digest}


def verify_swimlane(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Check contiguous ordering and hash-linked lineage for an event stream."""
    rows = list(events)
    if not rows:
        raise AgenticControlError(
            "E_SWIMLANE_EMPTY", "at least one swim-lane event is required"
        )
    previous = None
    for index, event in enumerate(rows):
        if not isinstance(event, dict) or event.get("schema") != SWIMLANE_SCHEMA:
            raise AgenticControlError("E_SWIMLANE_SCHEMA", "event schema is invalid")
        if (
            event.get("sequence") != index
            or event.get("previous_event_digest") != previous
        ):
            raise AgenticControlError(
                "E_SWIMLANE_SEQUENCE", "swim-lane sequence or predecessor is invalid"
            )
        core = {
            key: event.get(key)
            for key in (
                "schema",
                "workflow_id",
                "lane",
                "stage",
                "status",
                "sequence",
                "artifact_digest",
                "previous_event_digest",
                "elapsed_ms",
            )
        }
        digest = _sha(core)
        if (
            event.get("event_digest") != digest
            or event.get("event_id") != "swim:" + digest[:32]
        ):
            raise AgenticControlError(
                "E_SWIMLANE_TAMPERED", "event digest does not match its contents"
            )
        previous = digest
    return {
        "schema": "factory.swimlane-ledger.v1",
        "workflow_id": rows[0]["workflow_id"],
        "events": len(rows),
        "head_digest": previous,
        "state": rows[-1]["status"],
        "marker": "SWIMLANE_CHAIN_VERIFIED",
    }


@dataclass(frozen=True)
class CookbookRecipe:
    name: str
    summary: str
    required_inputs: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    next_action: str


_COOKBOOK = {
    "first-proof": CookbookRecipe(
        "first-proof",
        "Run the smallest local proof path.",
        ("root",),
        ("factory first-proof",),
        "Inspect the receipt and choose the next gate.",
    ),
    "pr-review": CookbookRecipe(
        "pr-review",
        "Bind a pull-request diff to deterministic proof evidence.",
        ("root", "changed_paths"),
        ("factory github proof-review",),
        "Review proof debt before merge.",
    ),
    "mobile-evidence": CookbookRecipe(
        "mobile-evidence",
        "Normalize mobile build and storefront evidence.",
        ("root", "evidence_manifest"),
        ("factory revenue appforge-mobile-evidence",),
        "Resolve missing evidence before submission.",
    ),
}


def list_cookbook_recipes() -> list[str]:
    """Return names only; recipe bodies remain lazy until requested."""
    return sorted(_COOKBOOK)


def load_cookbook_recipe(name: str) -> dict[str, Any]:
    """Load exactly one bounded recipe and no standing prompt context."""
    recipe = _COOKBOOK.get(name)
    if recipe is None:
        raise AgenticControlError(
            "E_COOKBOOK_UNKNOWN", f"unknown cookbook recipe: {name}"
        )
    return {
        "schema": "factory.cookbook-recipe.v1",
        "name": recipe.name,
        "summary": recipe.summary,
        "required_inputs": list(recipe.required_inputs),
        "allowed_tools": list(recipe.allowed_tools),
        "next_action": recipe.next_action,
        "authority": dict(_AUTHORITY),
        "marker": "COOKBOOK_CONTEXT_LAZY",
    }


def compile_reusable_workflow(
    workflow_id: str, phases: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    """Compile a reusable phase recipe with strict order and unique stages."""
    _id(workflow_id, "workflow_id")
    rows = list(phases)
    if not rows or len(rows) > len(_PHASES):
        raise AgenticControlError(
            "E_WORKFLOW_PHASES", "workflow must contain 1-6 phases"
        )
    normalized = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"stage", "recipe"}:
            raise AgenticControlError(
                "E_WORKFLOW_SCHEMA", "each phase must contain exactly stage and recipe"
            )
        stage = row["stage"]
        if stage not in _PHASES or stage in seen:
            raise AgenticControlError(
                "E_WORKFLOW_PHASES", "phases must be unique known stages"
            )
        recipe = load_cookbook_recipe(row["recipe"])
        seen.add(stage)
        normalized.append({"stage": stage, "recipe": recipe["name"]})
    order = [_PHASES.index(row["stage"]) for row in normalized]
    if order != sorted(order):
        raise AgenticControlError(
            "E_WORKFLOW_ORDER", "phases must follow scout-to-review order"
        )
    core = {
        "schema": WORKFLOW_SCHEMA,
        "workflow_id": workflow_id,
        "phases": normalized,
        "authority": dict(_AUTHORITY),
    }
    digest = _sha(core)
    return {
        **core,
        "workflow_sha256": digest,
        "workflow_id": workflow_id,
        "marker": "REUSABLE_WORKFLOW_HASH_BOUND",
        "next_action": "Execute only after the caller supplies each phase's required evidence.",
    }


def verify_reusable_workflow(manifest: dict[str, Any]) -> dict[str, Any]:
    """Verify workflow phase order, recipe references, authority, and digest."""
    if not isinstance(manifest, dict) or manifest.get("schema") != WORKFLOW_SCHEMA:
        raise AgenticControlError(
            "E_WORKFLOW_SCHEMA", f"workflow must use {WORKFLOW_SCHEMA}"
        )
    core = {
        "schema": manifest["schema"],
        "workflow_id": manifest["workflow_id"],
        "phases": manifest["phases"],
        "authority": manifest["authority"],
    }
    if manifest.get("workflow_sha256") != _sha(core):
        raise AgenticControlError(
            "E_WORKFLOW_TAMPERED", "workflow digest does not match contents"
        )
    return dict(manifest)


def create_sandbox_boundary(
    root: Path,
    *,
    repo_path: str = ".",
    expected_branch: str | None = None,
    expected_head_sha: str | None = None,
) -> dict[str, Any]:
    """Inspect a checkout and issue a non-mutating branch/merge boundary."""
    workspace = Path(root).resolve()
    relative = Path(repo_path.replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        raise AgenticControlError("E_SANDBOX_PATH", "repo_path escapes the workspace")
    checkout = (workspace / relative).resolve()
    try:
        checkout.relative_to(workspace)
    except ValueError as exc:
        raise AgenticControlError(
            "E_SANDBOX_PATH", "repo_path escapes the workspace"
        ) from exc
    if not checkout.is_dir():
        raise AgenticControlError("E_SANDBOX_REPO", "repo_path is not a directory")

    def git(*args: str) -> str:
        run = subprocess.run(
            ["git", "-C", str(checkout), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if run.returncode:
            raise AgenticControlError(
                "E_SANDBOX_GIT", run.stderr.strip() or "git inspection failed"
            )
        return run.stdout.strip()

    branch = git("branch", "--show-current")
    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain")
    if expected_branch is not None and branch != expected_branch:
        raise AgenticControlError(
            "E_SANDBOX_BRANCH",
            f"expected branch {expected_branch!r}, observed {branch!r}",
        )
    if expected_head_sha is not None and (
        not _GIT_SHA.fullmatch(expected_head_sha) or head != expected_head_sha
    ):
        raise AgenticControlError(
            "E_SANDBOX_HEAD", "checkout head does not match the pinned base"
        )
    core = {
        "schema": SANDBOX_SCHEMA,
        "repo_path": relative.as_posix() or ".",
        "branch": branch,
        "head_sha": head,
        "dirty": bool(status),
        "expected_branch": expected_branch,
        "expected_head_sha": expected_head_sha,
        "merge": "human_confirmation_required",
        "authority": dict(_AUTHORITY),
    }
    digest = _sha(core)
    return {
        **core,
        "boundary_sha256": digest,
        "marker": "SANDBOX_BOUNDARY_INSPECTED",
        "next_action": "A human maintainer must review and apply any candidate in a separately provisioned branch; Code Factory did not mutate Git.",
    }


def verify_sandbox_boundary(boundary: dict[str, Any]) -> dict[str, Any]:
    """Verify the inspected checkout binding and preserve human merge authority."""
    if not isinstance(boundary, dict) or boundary.get("schema") != SANDBOX_SCHEMA:
        raise AgenticControlError(
            "E_SANDBOX_SCHEMA", f"boundary must use {SANDBOX_SCHEMA}"
        )
    core_keys = (
        "schema",
        "repo_path",
        "branch",
        "head_sha",
        "dirty",
        "expected_branch",
        "expected_head_sha",
        "merge",
        "authority",
    )
    core = {key: boundary.get(key) for key in core_keys}
    if boundary.get("boundary_sha256") != _sha(core):
        raise AgenticControlError(
            "E_SANDBOX_TAMPERED", "boundary digest does not match contents"
        )
    if boundary.get("merge") != "human_confirmation_required" or any(
        value is not False for value in boundary["authority"].values()
    ):
        raise AgenticControlError(
            "E_SANDBOX_AUTHORITY", "sandbox boundary cannot grant merge authority"
        )
    return dict(boundary)


def agentic_control_projection(root: Path) -> dict[str, Any]:
    """Return the Mission Control projection without reading prompts or executing work."""
    root = Path(root).resolve()
    return {
        "schema": SCHEMA,
        "root_bound": True,
        "features": {
            "observable_swim_lanes": {
                "status": "available",
                "event_schema": SWIMLANE_SCHEMA,
            },
            "tiered_model_routing": {
                "status": "available",
                "tiers": ["lightweight", "workhorse", "frontier"],
            },
            "typed_agent_handoffs": {"status": "available", "schema": HANDOFF_SCHEMA},
            "route_tracing": {"status": "available", "schema": ROUTE_TRACE_SCHEMA},
            "lazy_cookbook_context": {
                "status": "available",
                "recipes": list_cookbook_recipes(),
            },
            "reusable_workflows": {"status": "available", "schema": WORKFLOW_SCHEMA},
            "sandboxed_branch_merge_boundaries": {
                "status": "available",
                "schema": SANDBOX_SCHEMA,
            },
            "capability_registry": {
                "status": "available",
                "schema": CAPABILITY_SCHEMA,
                "authority": "registry_only; no execution grant",
            },
            "durable_task_cards": {
                "status": "available",
                "schema": TASK_CARD_SCHEMA,
                "states": list(_TASK_STATES),
                "authority": "lease_and_checkpoint_metadata_only",
            },
            "deterministic_task_board": {
                "status": "available",
                "schema": TASK_BOARD_SCHEMA,
                "lanes": ["triage", "ready", "running", "review", "blocked", "done"],
                "dispatcher": "projection_only; 60-second cadence metadata",
                "authority": "read_only; no dispatch or lease grant",
            },
            "orchestrator_request_routing": {
                "status": "available",
                "schema": ORCHESTRATOR_PLAN_SCHEMA,
                "authority": "plan_only; human approval required",
            },
        },
        "extended_assurance": {
            "status": "opt_in",
            "lanes": list(EXTENDED_LANES),
            "receipt_schema": EXTENDED_RECEIPT_SCHEMA,
            "blocking_policy": "only explicitly required lanes can block release",
        },
        "authority": dict(_AUTHORITY),
        "claim_boundary": "Control-plane metadata only; no model, source, branch, merge, approval, credential, or network action ran.",
        "marker": "AGENTIC_CONTROL_PROJECTION_READY",
    }


def _projection_core(projection: dict[str, Any]) -> dict[str, Any]:
    """Return the stable projection fields used for reproducible drift hashes."""
    core = dict(projection)
    core.pop("marker", None)
    return core


def _validate_projection(projection: object, label: str) -> dict[str, Any]:
    """Validate a control projection before comparing its nested policy state."""
    if not isinstance(projection, dict) or projection.get("schema") != SCHEMA:
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_SCHEMA", f"{label} must use {SCHEMA}"
        )
    features = projection.get("features")
    extended = projection.get("extended_assurance")
    authority = projection.get("authority")
    if not isinstance(features, dict) or not features:
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_SCHEMA", f"{label}.features must be a non-empty object"
        )
    if not isinstance(extended, dict) or not isinstance(authority, dict):
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_SCHEMA",
            f"{label} must include extended assurance and authority",
        )
    if any(value is not False for value in authority.values()):
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_AUTHORITY", f"{label} contains an authority escalation"
        )
    if projection.get("root_bound") is not True:
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_SCHEMA", f"{label}.root_bound must remain true"
        )
    return projection


def _deep_diffs(before: object, after: object, path: str = "") -> list[dict[str, Any]]:
    """Produce bounded, deterministic leaf diffs for nested JSON-compatible values."""
    if isinstance(before, dict) and isinstance(after, dict):
        diffs: list[dict[str, Any]] = []
        for key in sorted(set(before) | set(after)):
            child = f"{path}.{key}" if path else str(key)
            if key not in before:
                diffs.append(
                    {
                        "path": child,
                        "kind": "added",
                        "before": None,
                        "after": after[key],
                    }
                )
            elif key not in after:
                diffs.append(
                    {
                        "path": child,
                        "kind": "removed",
                        "before": before[key],
                        "after": None,
                    }
                )
            else:
                diffs.extend(_deep_diffs(before[key], after[key], child))
        return diffs
    if before != after:
        return [
            {"path": path or "$", "kind": "changed", "before": before, "after": after}
        ]
    return []


def _drift_finding(diff: dict[str, Any]) -> dict[str, Any]:
    """Classify one projection diff using release-sensitive control-plane rules."""
    path = str(diff["path"])
    kind = str(diff["kind"])
    code = "AGENTIC_CONTROL_DRIFT"
    severity = "REVIEW_REQUIRED"
    if path.startswith("authority."):
        code, severity = "AGENTIC_AUTHORITY_ESCALATION", "BLOCKED"
    elif path == "schema" or path.endswith(".schema"):
        code, severity = "AGENTIC_SCHEMA_CHANGED", "BLOCKED"
    elif path.startswith("features.") and kind == "removed":
        code, severity = "AGENTIC_FEATURE_REMOVED", "BLOCKED"
    elif path == "extended_assurance.blocking_policy" and diff["after"] != (
        "only explicitly required lanes can block release"
    ):
        code, severity = "AGENTIC_BLOCKING_POLICY_WEAKENED", "BLOCKED"
    elif path == "extended_assurance.status" and diff["after"] == "disabled":
        code, severity = "AGENTIC_ASSURANCE_DISABLED", "BLOCKED"
    elif path == "extended_assurance.lanes" and kind == "changed":
        before = (
            set(diff["before"] or []) if isinstance(diff["before"], list) else set()
        )
        after = set(diff["after"] or []) if isinstance(diff["after"], list) else set()
        if before - after:
            code, severity = "AGENTIC_ASSURANCE_LANE_REMOVED", "BLOCKED"
        else:
            code, severity = "AGENTIC_ASSURANCE_LANES_CHANGED", "REVIEW_REQUIRED"
    return {**diff, "code": code, "severity": severity}


def compare_agentic_control_drift(
    baseline: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Compare two control projections and emit a tamper-evident drift receipt."""
    baseline = _validate_projection(baseline, "baseline")
    current = _validate_projection(current, "current")
    baseline_core = _projection_core(baseline)
    current_core = _projection_core(current)
    diffs = _deep_diffs(baseline_core, current_core)
    findings = [_drift_finding(item) for item in diffs[:128]]
    blocked = [item for item in findings if item["severity"] == "BLOCKED"]
    verdict = "BLOCKED" if blocked else ("REVIEW_REQUIRED" if findings else "CLEAR")
    core = {
        "schema": DRIFT_SCHEMA,
        "baseline_sha256": _sha(baseline_core),
        "current_sha256": _sha(current_core),
        "findings": findings,
        "verdict": verdict,
        "authority": dict(_AUTHORITY),
    }
    return {
        **core,
        "drift_sha256": _sha(core),
        "marker": f"AGENTIC_CONTROL_DRIFT_{verdict}",
        "summary": {
            "changed": len(findings),
            "blocked": len(blocked),
            "review_required": sum(
                item["severity"] == "REVIEW_REQUIRED" for item in findings
            ),
        },
        "claim_boundary": "Deterministic comparison of supplied control-plane projections only; it does not prove runtime behavior, identity, deployment, publication, or release approval.",
    }


def verify_agentic_control_drift(receipt: dict[str, Any]) -> dict[str, Any]:
    """Verify a control-plane drift receipt hash, verdict, and authority boundary."""
    if not isinstance(receipt, dict) or receipt.get("schema") != DRIFT_SCHEMA:
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_SCHEMA", f"receipt must use {DRIFT_SCHEMA}"
        )
    core_keys = (
        "schema",
        "baseline_sha256",
        "current_sha256",
        "findings",
        "verdict",
        "authority",
    )
    core = {key: receipt.get(key) for key in core_keys}
    for key in ("baseline_sha256", "current_sha256"):
        _digest(core[key], key)
    if not isinstance(core["findings"], list) or core["verdict"] not in {
        "CLEAR",
        "REVIEW_REQUIRED",
        "BLOCKED",
    }:
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_SCHEMA", "receipt findings or verdict are invalid"
        )
    if not isinstance(core["authority"], dict) or any(
        value is not False for value in core["authority"].values()
    ):
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_AUTHORITY", "drift receipt cannot grant authority"
        )
    if receipt.get("drift_sha256") != _sha(core):
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_TAMPERED", "drift receipt digest does not match contents"
        )
    expected = (
        "BLOCKED"
        if any(item.get("severity") == "BLOCKED" for item in core["findings"])
        else ("REVIEW_REQUIRED" if core["findings"] else "CLEAR")
    )
    if (
        core["verdict"] != expected
        or receipt.get("marker") != f"AGENTIC_CONTROL_DRIFT_{expected}"
    ):
        raise AgenticControlError(
            "E_AGENTIC_DRIFT_TAMPERED", "drift verdict does not match findings"
        )
    return {
        "schema": DRIFT_SCHEMA,
        "verdict": expected,
        "drift_sha256": receipt["drift_sha256"],
        "marker": "AGENTIC_CONTROL_DRIFT_VERIFIED",
        "claim_boundary": receipt.get("claim_boundary"),
    }


def _required_digest(value: object, label: str) -> str:
    """Accept a plain SHA-256 value or a sha256:<value> notation."""
    if isinstance(value, str) and value.startswith("sha256:"):
        value = value[7:]
    return _digest(value, label)


def _supply_chain_lane(evidence: object) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {"status": "BLOCKED", "reason": "provenance evidence is required"}
    required = ("source_sha256", "builder_id", "artifact_sha256", "dependencies_sha256")
    if any(key not in evidence for key in required):
        return {
            "status": "BLOCKED",
            "reason": "source, builder, artifact, and dependency bindings are required",
        }
    try:
        source = _required_digest(evidence["source_sha256"], "source_sha256")
        artifact = _required_digest(evidence["artifact_sha256"], "artifact_sha256")
        dependencies = _required_digest(
            evidence["dependencies_sha256"], "dependencies_sha256"
        )
    except AgenticControlError as exc:
        return {"status": "BLOCKED", "reason": exc.message}
    builder = evidence["builder_id"]
    if not isinstance(builder, str) or not builder.strip() or len(builder) > 256:
        return {
            "status": "BLOCKED",
            "reason": "builder_id must be a bounded non-empty identifier",
        }
    challenge = evidence.get("challenge")
    if (
        not isinstance(challenge, dict)
        or challenge.get("provenance_mutation_rejected") is not True
    ):
        return {
            "status": "BLOCKED",
            "reason": "provenance mutation challenge must be rejected",
        }
    return {
        "status": "PASSED",
        "bindings": {
            "source_sha256": source,
            "artifact_sha256": artifact,
            "dependencies_sha256": dependencies,
            "builder_id": builder.strip(),
        },
        "challenge": {"provenance_mutation_rejected": True},
    }


def _semantic_lane(evidence: object) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {
            "status": "BLOCKED",
            "reason": "semantic robustness evidence is required",
        }
    cases = evidence.get("cases")
    if not isinstance(cases, list) or not cases:
        return {
            "status": "BLOCKED",
            "reason": "at least one differential/property case is required",
        }
    normalized = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {
            "case_id",
            "expected",
            "observed",
            "matched",
        }:
            return {
                "status": "BLOCKED",
                "reason": f"case {index} must contain case_id, expected, observed, and matched",
            }
        if (
            not isinstance(case["case_id"], str)
            or not case["case_id"].strip()
            or not isinstance(case["matched"], bool)
        ):
            return {
                "status": "BLOCKED",
                "reason": f"case {index} has invalid identity or match flag",
            }
        normalized.append(
            {
                "case_id": case["case_id"].strip(),
                "expected": str(case["expected"]),
                "observed": str(case["observed"]),
                "matched": case["matched"],
            }
        )
    challenge = evidence.get("challenge")
    if not isinstance(challenge, dict):
        return {
            "status": "BLOCKED",
            "reason": "semantic mutation challenge is required",
        }
    attempted, caught = (
        challenge.get("mutations_attempted"),
        challenge.get("mutations_caught"),
    )
    if (
        any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in (attempted, caught)
        )
        or caught != attempted
    ):
        return {"status": "BLOCKED", "reason": "every semantic mutation must be caught"}
    if not all(case["matched"] for case in normalized):
        return {
            "status": "BLOCKED",
            "reason": "differential/property observations diverge from their declared expectations",
        }
    return {
        "status": "PASSED",
        "cases": normalized,
        "challenge": {"mutations_attempted": attempted, "mutations_caught": caught},
    }


def build_extended_assurance_receipt(
    feature: str,
    *,
    extended_assurance: bool,
    evidence: dict[str, Any] | None = None,
    required_lanes: Iterable[str] = (),
    tenant_id: str = "local",
    run_id: str = "extended-assurance",
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Run optional lanes 7–8 from supplied evidence and emit Receipt v2 payload.

    The function never invokes fuzzers, scanners, builders, or providers. It
    validates externally produced evidence and creates a payload ready for the
    existing enterprise Receipt v2 signing path.
    """
    feature = _id(feature, "feature")
    tenant_id = _id(tenant_id, "tenant_id")
    run_id = _id(run_id, "run_id")
    selected = list(required_lanes)
    if set(selected) - set(EXTENDED_LANES) or len(selected) != len(set(selected)):
        raise AgenticControlError(
            "E_EXTENDED_LANES", "required_lanes must be a unique subset of lanes 7-8"
        )
    evidence = evidence or {}
    if not isinstance(evidence, dict):
        raise AgenticControlError("E_EXTENDED_EVIDENCE", "evidence must be an object")
    lane_results: dict[str, dict[str, Any]] = {}
    if not extended_assurance:
        for lane in EXTENDED_LANES:
            lane_results[lane] = {
                "status": "NOT_REQUESTED",
                "required": lane in selected,
            }
    else:
        lane_results["supply_chain_provenance"] = {
            **_supply_chain_lane(evidence.get("supply_chain_provenance")),
            "required": "supply_chain_provenance" in selected,
        }
        lane_results["semantic_robustness"] = {
            **_semantic_lane(evidence.get("semantic_robustness")),
            "required": "semantic_robustness" in selected,
        }
    blocking = [
        lane
        for lane, result in lane_results.items()
        if result.get("required") and result.get("status") != "PASSED"
    ]
    ok = not blocking
    now = timestamp or datetime.now(timezone.utc).isoformat()
    if not isinstance(now, str) or not now.strip():
        raise AgenticControlError(
            "E_EXTENDED_TIME", "timestamp must be a non-empty timestamp"
        )
    events = []
    previous = None
    for sequence, lane in enumerate(EXTENDED_LANES):
        event = new_swimlane_event(
            feature,
            lane,
            "verify",
            lane_results[lane]["status"],
            sequence=sequence,
            previous_event_digest=previous,
        )
        events.append(event)
        previous = event["event_digest"]
    payload = {
        "schema": EXTENDED_RECEIPT_SCHEMA,
        "module": "agentic-control",
        "stage": "extended-assurance",
        "feature": feature,
        "ok": ok,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "ts": now,
        "assurance_schema": EXTENDED_ASSURANCE_SCHEMA,
        "extended_assurance": bool(extended_assurance),
        "baseline_lanes": list(BASELINE_LANES),
        "extended_lanes": lane_results,
        "blocking_lanes": blocking,
        "swimlane_events": events,
        "authority": dict(_AUTHORITY),
        "claim_boundary": "Receipt payload validates supplied lane evidence only; sign with the existing enterprise Receipt v2 DSSE path before treating signer identity as verified.",
    }
    payload["subject_sha256"] = _sha(
        {"feature": feature, "extended_lanes": lane_results, "swimlane_events": events}
    )
    # Validate the common Receipt v2 shape without requiring cryptographic keys.
    try:
        from .enterprise_receipts import validate_receipt_v2

        validate_receipt_v2(payload)
    except ImportError:
        pass
    except Exception as exc:
        raise AgenticControlError("E_EXTENDED_RECEIPT", str(exc)) from exc
    return payload


def verify_extended_assurance_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Verify Receipt v2 shape, lane challenge results, and swim-lane lineage."""
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != EXTENDED_RECEIPT_SCHEMA
    ):
        raise AgenticControlError(
            "E_EXTENDED_RECEIPT", "a factory.receipt.v2 payload is required"
        )
    if receipt.get("assurance_schema") != EXTENDED_ASSURANCE_SCHEMA:
        raise AgenticControlError(
            "E_EXTENDED_RECEIPT", "extended assurance schema marker is missing"
        )
    lane_results = receipt.get("extended_lanes")
    if not isinstance(lane_results, dict) or set(lane_results) != set(EXTENDED_LANES):
        raise AgenticControlError(
            "E_EXTENDED_RECEIPT", "both extended lanes must be present"
        )
    verify_swimlane(receipt.get("swimlane_events", []))
    blocking = [
        lane
        for lane, result in lane_results.items()
        if result.get("required") and result.get("status") != "PASSED"
    ]
    expected_ok = not blocking
    if (
        receipt.get("ok") is not expected_ok
        or receipt.get("blocking_lanes") != blocking
    ):
        raise AgenticControlError(
            "E_EXTENDED_RECEIPT", "blocking lane summary does not match lane results"
        )
    return {
        "schema": EXTENDED_ASSURANCE_SCHEMA,
        "ok": expected_ok,
        "blocking_lanes": blocking,
        "marker": "EXTENDED_ASSURANCE_RECEIPT_VERIFIED",
        "claim_boundary": receipt.get("claim_boundary"),
    }
