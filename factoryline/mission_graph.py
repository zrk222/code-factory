"""Durable, receipt-governed Product Mission graph runtime.

The stdlib SQLite store is authoritative.  LangGraph is an optional adapter
that checkpoints calls into the same transition validator; a framework
checkpoint never proves that a Code Factory transition is valid.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict
import hashlib
import importlib.util
import json
import math
import re
import sqlite3

from .failure_guidance import explain_failure
from .migration import verify_repository_context
from .product_missions import verify_mission, verify_mission_completion


GRAPH_SCHEMA = "factory.mission.graph.v1"
EVENT_SCHEMA = "factory.mission.graph.event.v1"
VERIFICATION_SCHEMA = "factory.mission.graph.verification.v1"
USAGE_SCHEMA = "factory.mission.usage.v1"
MAX_EVENT_BYTES = 65536
MAX_TEXT = 120
QUALITY_TIERS = ("economy", "balanced", "frontier")
ACTIVE_STATES = frozenset({
    "planned", "deferred", "creator_running", "independent_verification",
    "correction_required", "paused_for_review", "completion_receipted",
    "awaiting_release_authority", "release_decided",
})
TERMINAL_STATES = frozenset({"rejected", "budget_exhausted", "outcome_observed"})


class MissionGraphError(ValueError):
    """Closed, machine-readable mission graph failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.guidance = explain_failure(code, message)


class LangGraphState(TypedDict, total=False):
    """JSON-safe input and result state used by the optional adapter."""

    mission_path: str
    root: str
    event: str
    actor: str
    role: str
    idempotency_key: str
    receipt_path: str | None
    payload: dict[str, Any]
    result: dict[str, Any]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MissionGraphError("MISSION_GRAPH_EVENT_INVALID", f"event must be canonical JSON: {exc}") from exc


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MissionGraphError("MISSION_GRAPH_RECEIPT_INVALID", f"cannot read JSON receipt {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MissionGraphError("MISSION_GRAPH_RECEIPT_INVALID", f"receipt must be a JSON object: {path}")
    return value


def _bounded_text(value: str, field: str) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not text or len(text) > MAX_TEXT:
        raise MissionGraphError("MISSION_GRAPH_EVENT_INVALID", f"{field} must contain 1-{MAX_TEXT} characters")
    return text


def _reject_sensitive_payload(value: Any, path: str = "payload") -> None:
    sensitive = re.compile(r"(?:api[_-]?key|secret|token|credential|password)", re.I)
    if isinstance(value, dict):
        for key, item in value.items():
            if sensitive.search(str(key)):
                raise MissionGraphError("MISSION_GRAPH_SENSITIVE_PAYLOAD", f"sensitive field is forbidden: {path}.{key}")
            _reject_sensitive_payload(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive_payload(item, f"{path}[{index}]")


def _resolve_under(root: Path, value: Path, code: str) -> Path:
    root = Path(root).resolve()
    path = Path(value).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise MissionGraphError(code, f"path must be beneath {root}: {path}") from exc
    return path


def _mission(root: Path, mission_path: Path) -> tuple[Path, dict[str, Any]]:
    path = _resolve_under(root, mission_path, "MISSION_GRAPH_MISSION_OUTSIDE_ROOT")
    verification = verify_mission(path)
    if not verification["valid"]:
        raise MissionGraphError("MISSION_GRAPH_MISSION_INVALID", "; ".join(verification["errors"]))
    mission = _load_json(path)
    return path, mission


def _db_path(root: Path, mission_path: Path) -> Path:
    path = _resolve_under(root, mission_path, "MISSION_GRAPH_MISSION_OUTSIDE_ROOT")
    return path.parent / "mission-graph.sqlite3"


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS graph_threads (
            thread_id TEXT PRIMARY KEY,
            schema_name TEXT NOT NULL,
            mission_path TEXT NOT NULL,
            mission_file_sha TEXT NOT NULL,
            mission_sha TEXT NOT NULL,
            state TEXT NOT NULL,
            version INTEGER NOT NULL,
            attempts INTEGER NOT NULL,
            creator_id TEXT,
            verifier_id TEXT,
            paused_from TEXT,
            usage_json TEXT NOT NULL,
            milestones_json TEXT NOT NULL,
            plan_receipt_json TEXT,
            context_receipt_json TEXT,
            event_tip TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS graph_events (
            thread_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            idempotency_key TEXT NOT NULL,
            intent_sha TEXT NOT NULL,
            event_json TEXT NOT NULL,
            event_sha TEXT NOT NULL,
            receipt_path TEXT,
            receipt_sha TEXT,
            PRIMARY KEY (thread_id, version),
            UNIQUE (thread_id, idempotency_key),
            FOREIGN KEY (thread_id) REFERENCES graph_threads(thread_id)
        );
        """
    )
    return connection


def _milestones(mission: dict[str, Any]) -> list[dict[str, Any]]:
    hypotheses = {
        item.get("criterion_id"): item.get("id")
        for item in mission.get("completion_contract", {}).get("hypotheses", [])
        if isinstance(item, dict)
    }
    return [
        {
            "id": criterion["id"],
            "verification_kind": criterion.get("verification_kind", "deterministic"),
            "hypothesis_id": hypotheses.get(criterion["id"]),
            "status": "pending",
        }
        for criterion in mission.get("completion_contract", {}).get("criteria", [])
    ]


def _readiness(mission: dict[str, Any]) -> dict[str, Any]:
    gates = {str(item).lower() for item in mission.get("slice", {}).get("required_gates", [])}
    criteria = mission.get("completion_contract", {}).get("criteria", [])
    joined = " ".join([*gates, *(str(item.get("id", "")) for item in criteria)]).lower()
    checks = {
        "tests": any(word in joined for word in ("test", "unit", "integration", "browser")),
        "lint_or_static_analysis": any(word in joined for word in ("lint", "static", "type", "architecture")),
        "acceptance_validators": bool(criteria),
    }
    ready = all(checks.values())
    return {
        "ready_for_autonomous": ready,
        "governance": "supervised" if ready else "human_controlled",
        "checks": checks,
        "marker": "MISSION_GRAPH_READINESS_GATED",
    }


def _row_state(row: sqlite3.Row, mission: dict[str, Any]) -> dict[str, Any]:
    usage = json.loads(row["usage_json"])
    milestones = json.loads(row["milestones_json"])
    return {
        "schema": GRAPH_SCHEMA,
        "mission_id": row["thread_id"],
        "mission_sha256": row["mission_sha"],
        "state": row["state"],
        "version": row["version"],
        "attempts": row["attempts"],
        "max_iterations": mission["budgets"]["max_iterations"],
        "creator_id": row["creator_id"],
        "verifier_id": row["verifier_id"],
        "usage": usage,
        "budgets": mission["budgets"],
        "milestones": milestones,
        "milestone_progress": {
            "passed": sum(item["status"] == "passed" for item in milestones),
            "failed": sum(item["status"] == "failed" for item in milestones),
            "total": len(milestones),
        },
        "plan_receipt": json.loads(row["plan_receipt_json"]) if row["plan_receipt_json"] else None,
        "context_receipt": json.loads(row["context_receipt_json"]) if row["context_receipt_json"] else None,
        "event_tip": row["event_tip"],
        "readiness": _readiness(mission),
        "authority": {
            "execute_external_effect": False,
            "merge": False,
            "publish": False,
            "deploy": False,
            "external_message": False,
        },
        "markers": [
            "MISSION_GRAPH_RESUMABLE", "MISSION_GRAPH_MILESTONES_BOUND",
            "MISSION_GRAPH_RELEASE_AUTHORITY_SEPARATE", "MISSION_GRAPH_READINESS_GATED",
        ],
    }


def _thread(connection: sqlite3.Connection, mission_id: str) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM graph_threads WHERE thread_id=?", (mission_id,)).fetchone()
    if row is None:
        raise MissionGraphError("MISSION_GRAPH_NOT_INITIALIZED", "run `factory langgraph init` first")
    return row


def init_mission_graph(mission_path: Path, root: Path) -> dict:
    """Initialize or reopen the canonical durable graph for one verified mission."""
    mission_path, mission = _mission(root, mission_path)
    database = _db_path(root, mission_path)
    connection = _connect(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT * FROM graph_threads WHERE thread_id=?", (mission["id"],),
        ).fetchone()
        if existing is not None:
            if existing["mission_sha"] != mission["mission_sha256"] or existing["mission_file_sha"] != _sha_path(mission_path):
                raise MissionGraphError("MISSION_GRAPH_DRIFT", "stored mission binding differs from the current mission")
            connection.commit()
            result = _row_state(existing, mission)
            return {**result, "database": str(database), "idempotent": True, "marker": "MISSION_GRAPH_IDEMPOTENT"}
        timestamp = _now()
        usage = {"tokens": None, "cost_usd": None, "wall_seconds": None, "evidence_class": "unknown"}
        connection.execute(
            """INSERT INTO graph_threads
               (thread_id,schema_name,mission_path,mission_file_sha,mission_sha,state,version,attempts,
                creator_id,verifier_id,paused_from,usage_json,milestones_json,plan_receipt_json,
                context_receipt_json,event_tip,created_at,updated_at)
               VALUES (?,?,?,?,?,'planned',0,0,NULL,NULL,NULL,?,?,NULL,NULL,'',?,?)""",
            (
                mission["id"], GRAPH_SCHEMA, str(mission_path), _sha_path(mission_path),
                mission["mission_sha256"], json.dumps(usage, sort_keys=True),
                json.dumps(_milestones(mission), sort_keys=True), timestamp, timestamp,
            ),
        )
        connection.commit()
        row = _thread(connection, mission["id"])
        result = _row_state(row, mission)
        return {
            **result,
            "database": str(database),
            "idempotent": False,
            "marker": "MISSION_GRAPH_INITIALIZED",
            "markers": result["markers"] + ["MISSION_GRAPH_INITIALIZED", "MISSION_GRAPH_HASH_CHAIN_BOUND"],
        }
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _bound_receipt(root: Path, receipt_path: Path | None, mission_id: str) -> tuple[Path, dict[str, Any], str]:
    if receipt_path is None:
        raise MissionGraphError("MISSION_GRAPH_RECEIPT_REQUIRED", "this transition requires a local receipt")
    path = _resolve_under(root, receipt_path, "MISSION_GRAPH_RECEIPT_OUTSIDE_ROOT")
    if not path.is_file() or path.stat().st_size > MAX_EVENT_BYTES:
        raise MissionGraphError("MISSION_GRAPH_RECEIPT_INVALID", f"receipt must be a file of at most {MAX_EVENT_BYTES} bytes")
    receipt = _load_json(path)
    if not isinstance(receipt.get("schema"), str) or not receipt["schema"]:
        raise MissionGraphError("MISSION_GRAPH_RECEIPT_INVALID", "receipt schema is required")
    receipt_mission = receipt.get("mission_id")
    if receipt_mission is not None and receipt_mission != mission_id:
        raise MissionGraphError("MISSION_GRAPH_RECEIPT_INVALID", "receipt mission_id mismatch")
    return path, receipt, _sha_path(path)


def _decision_receipt(receipt: dict[str, Any], mission: dict[str, Any], event: str, actor: str) -> None:
    expected = {"approve": "approved_execution", "defer": "deferred", "reject": "rejected"}[event]
    core = {key: value for key, value in receipt.items() if key not in {"decision_sha256", "generated_at", "path"}}
    if (
        receipt.get("schema") != "factory.mission.decision.v1"
        or receipt.get("mission_id") != mission["id"]
        or receipt.get("owner") != actor
        or receipt.get("decision") != expected
        or _sha_bytes(_canonical(core)) != receipt.get("decision_sha256")
        or receipt.get("mission", {}).get("mission_sha256") != mission["mission_sha256"]
    ):
        raise MissionGraphError("MISSION_GRAPH_OWNER_DECISION_INVALID", "owner decision receipt does not verify for this event")


def _completion_receipt(path: Path, receipt: dict[str, Any], mission: dict[str, Any], actor: str, creator_id: str | None) -> None:
    verification = verify_mission_completion(path)
    if not verification["valid"]:
        raise MissionGraphError("MISSION_GRAPH_COMPLETION_INVALID", "; ".join(verification["errors"]))
    if (
        receipt.get("mission", {}).get("mission_sha256") != mission["mission_sha256"]
        or receipt.get("verifier_id") != actor
        or receipt.get("creator_id") != creator_id
        or receipt.get("creator_id") == receipt.get("verifier_id")
    ):
        raise MissionGraphError("MISSION_GRAPH_COMPLETION_INVALID", "completion identities or mission binding do not match the graph")


def _usage(receipt: dict[str, Any], mission_id: str) -> dict[str, Any]:
    if receipt.get("schema") != USAGE_SCHEMA or receipt.get("mission_id") != mission_id:
        raise MissionGraphError("MISSION_GRAPH_USAGE_INVALID", f"usage receipt must use {USAGE_SCHEMA} and the current mission_id")
    evidence_class = receipt.get("evidence_class")
    if evidence_class not in {"measured", "modeled", "unknown"}:
        raise MissionGraphError("MISSION_GRAPH_USAGE_INVALID", "usage evidence_class must be measured, modeled, or unknown")
    values: dict[str, Any] = {"evidence_class": evidence_class}
    for name in ("tokens", "cost_usd", "wall_seconds"):
        value = receipt.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0):
            raise MissionGraphError("MISSION_GRAPH_USAGE_INVALID", f"{name} must be a finite non-negative number or null")
        values[name] = value
    return values


def _allowed_events(state: str) -> list[str]:
    fixed = {
        "planned": ["approve", "defer", "reject"],
        "deferred": ["approve", "reject"],
        "creator_running": ["candidate_ready", "pause"],
        "independent_verification": ["validation_failed", "validation_passed", "pause"],
        "correction_required": ["retry", "pause"],
        "paused_for_review": ["plan_revised", "resume", "reject"],
        "completion_receipted": ["release_requested"],
        "awaiting_release_authority": ["release_decided"],
        "release_decided": ["outcome_recorded"],
    }.get(state, [])
    if state in ACTIVE_STATES:
        fixed = [*fixed, "usage_recorded", "context_refreshed"]
    return sorted(set(fixed))


def _transition(state: str, event: str) -> tuple[str, frozenset[str]]:
    rules = {
        ("planned", "approve"): ("creator_running", frozenset({"owner"})),
        ("planned", "defer"): ("deferred", frozenset({"owner"})),
        ("planned", "reject"): ("rejected", frozenset({"owner"})),
        ("deferred", "approve"): ("creator_running", frozenset({"owner"})),
        ("deferred", "reject"): ("rejected", frozenset({"owner"})),
        ("creator_running", "candidate_ready"): ("independent_verification", frozenset({"worker"})),
        ("creator_running", "pause"): ("paused_for_review", frozenset({"owner"})),
        ("independent_verification", "validation_failed"): ("correction_required", frozenset({"validator"})),
        ("independent_verification", "validation_passed"): ("completion_receipted", frozenset({"validator"})),
        ("independent_verification", "pause"): ("paused_for_review", frozenset({"owner"})),
        ("correction_required", "retry"): ("creator_running", frozenset({"owner"})),
        ("correction_required", "pause"): ("paused_for_review", frozenset({"owner"})),
        ("paused_for_review", "plan_revised"): ("paused_for_review", frozenset({"owner"})),
        ("paused_for_review", "resume"): ("creator_running", frozenset({"owner"})),
        ("paused_for_review", "reject"): ("rejected", frozenset({"owner"})),
        ("completion_receipted", "release_requested"): ("awaiting_release_authority", frozenset({"owner"})),
        ("awaiting_release_authority", "release_decided"): ("release_decided", frozenset({"owner"})),
        ("release_decided", "outcome_recorded"): ("outcome_observed", frozenset({"owner"})),
    }
    if event in {"usage_recorded", "context_refreshed"} and state in ACTIVE_STATES:
        return state, frozenset({"owner", "worker", "validator", "operator"})
    try:
        return rules[(state, event)]
    except KeyError as exc:
        raise MissionGraphError(
            "MISSION_GRAPH_TRANSITION_INVALID",
            f"event {event!r} is not allowed from {state!r}; allowed: {', '.join(_allowed_events(state)) or 'none'}",
        ) from exc


def _verify_chain(connection: sqlite3.Connection, row: sqlite3.Row, mission_path: Path, mission: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if row["mission_path"] != str(mission_path) or row["mission_file_sha"] != _sha_path(mission_path) or row["mission_sha"] != mission["mission_sha256"]:
        errors.append("mission binding drift")
    previous = ""
    expected_version = 1
    last_state = "planned"
    events = connection.execute(
        "SELECT * FROM graph_events WHERE thread_id=? ORDER BY version", (mission["id"],),
    ).fetchall()
    for stored in events:
        try:
            core = json.loads(stored["event_json"])
        except json.JSONDecodeError:
            errors.append(f"event {expected_version} JSON invalid")
            break
        calculated = _sha_bytes(_canonical(core))
        if stored["version"] != expected_version or core.get("version") != expected_version:
            errors.append(f"event version discontinuity at {expected_version}")
        if core.get("previous_sha256") != previous or stored["event_sha"] != calculated:
            errors.append(f"event hash-chain drift at {expected_version}")
        if core.get("source_state") != last_state:
            errors.append(f"event source-state drift at {expected_version}")
        receipt_ref = core.get("receipt") if isinstance(core.get("receipt"), dict) else {}
        calculated_intent = _intent(
            core.get("event", ""), core.get("actor", ""), core.get("role", ""),
            core.get("payload", {}), receipt_ref.get("sha256"),
        )
        if stored["intent_sha"] != calculated_intent:
            errors.append(f"event intent drift at {expected_version}")
        if stored["receipt_path"]:
            path = Path(stored["receipt_path"])
            if not path.is_file() or _sha_path(path) != stored["receipt_sha"]:
                errors.append(f"receipt drift at event {expected_version}")
        previous = calculated
        last_state = core.get("target_state", "")
        expected_version += 1
    if row["version"] != len(events) or row["event_tip"] != previous or row["state"] != last_state:
        errors.append("thread head differs from event chain")
    return errors


def _intent(event: str, actor: str, role: str, payload: dict[str, Any], receipt_sha: str | None) -> str:
    return _sha_bytes(_canonical({
        "event": event, "actor": actor, "role": role, "payload": payload, "receipt_sha256": receipt_sha,
    }))


def _guard_actor(row: sqlite3.Row, mission: dict[str, Any], event: str,
                 actor: str, role: str, roles: frozenset[str]) -> None:
    if role not in roles:
        raise MissionGraphError("MISSION_GRAPH_ROLE_INVALID", f"role {role!r} cannot submit {event!r}")
    if role == "owner" and actor != mission["owner"]:
        raise MissionGraphError("MISSION_GRAPH_OWNER_MISMATCH", "owner actor must match the mission owner")
    if event in {"validation_failed", "validation_passed"} and actor == row["creator_id"]:
        raise MissionGraphError("MISSION_GRAPH_VERIFIER_NOT_DISTINCT", "worker and validator identities must differ")


def _guard_decision_candidate(receipt: dict[str, Any], mission: dict[str, Any],
                              event: str, actor: str) -> None:
    if event in {"approve", "defer", "reject"}:
        _decision_receipt(receipt, mission, event, actor)
    if event == "candidate_ready" and receipt.get("schema") != "factory.mission.candidate.v1":
        raise MissionGraphError("MISSION_GRAPH_CANDIDATE_INVALID", "candidate receipt schema must be factory.mission.candidate.v1")


def _guard_validation(row: sqlite3.Row, receipt_file: Path, receipt: dict[str, Any],
                      mission: dict[str, Any], event: str, actor: str,
                      payload: dict[str, Any]) -> None:
    if event == "validation_passed":
        _completion_receipt(receipt_file, receipt, mission, actor, row["creator_id"])
    if event != "validation_failed":
        return
    criterion_id = payload.get("criterion_id")
    if receipt.get("schema") != "factory.mission.validation-failure.v1" or not criterion_id:
        raise MissionGraphError("MISSION_GRAPH_VALIDATION_INVALID", "failed validation requires its schema and criterion_id")
    if criterion_id not in {item["id"] for item in json.loads(row["milestones_json"])}:
        raise MissionGraphError("MISSION_GRAPH_VALIDATION_INVALID", "criterion_id is not a mission milestone")


def _guard_retry_review(receipt: dict[str, Any], event: str, payload: dict[str, Any]) -> None:
    if event == "retry" and payload.get("fresh_context") is not True:
        raise MissionGraphError("MISSION_GRAPH_FRESH_CONTEXT_REQUIRED", "retry must attest fresh_context=true")
    if event == "pause" and receipt.get("schema") != "factory.mission.human-interrupt.v1":
        raise MissionGraphError("MISSION_GRAPH_INTERRUPT_INVALID", "pause requires factory.mission.human-interrupt.v1")
    if event in {"plan_revised", "resume"} and receipt.get("schema") != "factory.mission.plan-revision.v1":
        raise MissionGraphError("MISSION_GRAPH_PLAN_INVALID", "plan revision receipt schema is required")
    if event == "resume" and payload.get("fresh_context") is not True:
        raise MissionGraphError("MISSION_GRAPH_FRESH_CONTEXT_REQUIRED", "resume must attest fresh_context=true")


def _guard_context(receipt_file: Path, event: str) -> None:
    if event != "context_refreshed":
        return
    context_check = verify_repository_context(receipt_file)
    if not context_check["valid"]:
        raise MissionGraphError("MISSION_GRAPH_CONTEXT_INVALID", "; ".join(context_check["errors"]))


def _reduce_usage(row: sqlite3.Row, receipt: dict[str, Any], mission: dict[str, Any],
                  event: str, target: str) -> tuple[dict[str, Any], str, str]:
    usage = json.loads(row["usage_json"])
    if event != "usage_recorded":
        return usage, target, "MISSION_GRAPH_TRANSITION_GUARDED"
    sample = _usage(receipt, mission["id"])
    if sample["evidence_class"] == "measured":
        for name in ("tokens", "cost_usd", "wall_seconds"):
            if sample[name] is not None:
                usage[name] = (usage[name] or 0) + sample[name]
        usage["evidence_class"] = "measured"
    elif usage["evidence_class"] == "unknown":
        usage = sample
    limits = (("tokens", "max_tokens"), ("cost_usd", "max_cost_usd"), ("wall_seconds", "max_wall_seconds"))
    exhausted = any(usage[name] is not None and usage[name] >= mission["budgets"][budget] for name, budget in limits)
    return (usage, "budget_exhausted", "MISSION_GRAPH_BUDGET_ENFORCED") if exhausted else (usage, target, "MISSION_GRAPH_USAGE_RECEIPT_BOUND")


def _reduce_milestones(row: sqlite3.Row, receipt: dict[str, Any], event: str,
                       payload: dict[str, Any]) -> list[dict[str, Any]]:
    milestones = json.loads(row["milestones_json"])
    if event == "validation_failed":
        for item in milestones:
            if item["id"] == payload["criterion_id"]:
                item["status"] = "failed"
    if event == "retry":
        for item in milestones:
            if item["status"] == "failed":
                item["status"] = "pending"
    if event == "validation_passed":
        passed = {item["id"] for item in receipt.get("criteria", []) if item.get("passed") is True}
        if passed != {item["id"] for item in milestones}:
            raise MissionGraphError("MISSION_GRAPH_COMPLETION_INVALID", "completion receipt must pass every milestone")
        for item in milestones:
            item["status"] = "passed"
    return milestones


def _reduce_thread(row: sqlite3.Row, event: str, actor: str, target: str,
                   receipt_file: Path, receipt_sha: str, marker: str) -> dict[str, Any]:
    state = {
        "attempts": row["attempts"], "creator_id": row["creator_id"], "verifier_id": row["verifier_id"],
        "paused_from": row["paused_from"], "plan_json": row["plan_receipt_json"],
        "context_json": row["context_receipt_json"], "marker": marker,
    }
    event_markers = {
        "defer": "MISSION_GRAPH_OWNER_DECISION_BOUND", "reject": "MISSION_GRAPH_OWNER_DECISION_BOUND",
        "candidate_ready": "MISSION_GRAPH_CANDIDATE_BOUND", "validation_failed": "MISSION_GRAPH_VALIDATION_FAILED_BOUND",
        "validation_passed": "MISSION_GRAPH_COMPLETION_BOUND", "pause": "MISSION_GRAPH_HUMAN_INTERRUPT",
        "plan_revised": "MISSION_GRAPH_PLAN_REVISION_BOUND", "resume": "MISSION_GRAPH_PLAN_REVISION_BOUND",
        "context_refreshed": "MISSION_GRAPH_CONTEXT_REFRESH_BOUND", "release_requested": "MISSION_GRAPH_RELEASE_AUTHORITY_SEPARATE",
        "release_decided": "MISSION_GRAPH_RELEASE_AUTHORITY_SEPARATE",
    }
    state["marker"] = event_markers.get(event, state["marker"])
    if event == "approve" and state["attempts"] == 0:
        state.update(attempts=1, marker="MISSION_GRAPH_OWNER_DECISION_BOUND")
    if event == "candidate_ready":
        state.update(creator_id=actor, verifier_id=None)
    if event in {"validation_failed", "validation_passed"}:
        state["verifier_id"] = actor
    if event == "retry":
        state.update(marker="MISSION_GRAPH_BUDGET_ENFORCED" if target == "budget_exhausted" else "MISSION_GRAPH_FRESH_CONTEXT_BOUND")
        if target != "budget_exhausted":
            state.update(attempts=state["attempts"] + 1, creator_id=None, verifier_id=None)
    if event == "pause":
        state["paused_from"] = row["state"]
    receipt_ref = json.dumps({"path": str(receipt_file), "sha256": receipt_sha}, sort_keys=True)
    if event in {"plan_revised", "resume"}:
        state["plan_json"] = receipt_ref
    if event == "resume":
        state.update(creator_id=None, verifier_id=None)
    if event == "context_refreshed":
        state["context_json"] = receipt_ref
    return state


def apply_mission_event(mission_path: Path, root: Path, event: str, actor: str, role: str,
                        idempotency_key: str, receipt_path: Path | None = None,
                        payload: dict[str, Any] | None = None) -> dict:
    """Validate and atomically append one governed mission transition."""
    root = Path(root).resolve()
    mission_path, mission = _mission(root, mission_path)
    actor = _bounded_text(actor, "actor")
    role = _bounded_text(role, "role")
    event = _bounded_text(event, "event")
    idempotency_key = _bounded_text(idempotency_key, "idempotency_key")
    payload = dict(payload or {})
    _reject_sensitive_payload(payload)
    if len(_canonical(payload)) > MAX_EVENT_BYTES:
        raise MissionGraphError("MISSION_GRAPH_EVENT_INVALID", f"payload exceeds {MAX_EVENT_BYTES} canonical UTF-8 bytes")
    receipt_file, receipt, receipt_sha = _bound_receipt(root, receipt_path, mission["id"])
    intent_sha = _intent(event, actor, role, payload, receipt_sha)
    database = _db_path(root, mission_path)
    if not database.exists():
        init_mission_graph(mission_path, root)
    connection = _connect(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = _thread(connection, mission["id"])
        errors = _verify_chain(connection, row, mission_path, mission)
        if errors:
            raise MissionGraphError("MISSION_GRAPH_DRIFT", "; ".join(errors))
        duplicate = connection.execute(
            "SELECT * FROM graph_events WHERE thread_id=? AND idempotency_key=?",
            (mission["id"], idempotency_key),
        ).fetchone()
        if duplicate is not None:
            if duplicate["intent_sha"] != intent_sha:
                raise MissionGraphError("MISSION_GRAPH_IDEMPOTENCY_CONFLICT", "idempotency key was already used for different event bytes")
            connection.commit()
            current = _row_state(row, mission)
            return {**current, "event": json.loads(duplicate["event_json"]), "marker": "MISSION_GRAPH_IDEMPOTENT"}
        target, roles = _transition(row["state"], event)
        _guard_actor(row, mission, event, actor, role, roles)
        _guard_decision_candidate(receipt, mission, event, actor)
        _guard_validation(row, receipt_file, receipt, mission, event, actor, payload)
        _guard_retry_review(receipt, event, payload)
        _guard_context(receipt_file, event)
        if event == "retry" and row["attempts"] + 1 > mission["budgets"]["max_iterations"]:
            target = "budget_exhausted"
        usage, target, marker = _reduce_usage(row, receipt, mission, event, target)
        milestones = _reduce_milestones(row, receipt, event, payload)
        version = row["version"] + 1
        event_core = {
            "schema": EVENT_SCHEMA,
            "mission_id": mission["id"],
            "mission_sha256": mission["mission_sha256"],
            "version": version,
            "idempotency_key": idempotency_key,
            "event": event,
            "actor": actor,
            "role": role,
            "source_state": row["state"],
            "target_state": target,
            "payload": payload,
            "receipt": {"path": str(receipt_file), "sha256": receipt_sha, "schema": receipt["schema"]},
            "previous_sha256": row["event_tip"],
            "authority": {"merge": False, "publish": False, "deploy": False, "external_message": False},
            "created_at": _now(),
        }
        event_sha = _sha_bytes(_canonical(event_core))
        reduced = _reduce_thread(row, event, actor, target, receipt_file, receipt_sha, marker)
        marker = reduced["marker"]
        connection.execute(
            """INSERT INTO graph_events
               (thread_id,version,idempotency_key,intent_sha,event_json,event_sha,receipt_path,receipt_sha)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                mission["id"], version, idempotency_key, intent_sha,
                json.dumps(event_core, sort_keys=True), event_sha, str(receipt_file), receipt_sha,
            ),
        )
        connection.execute(
            """UPDATE graph_threads SET state=?,version=?,attempts=?,creator_id=?,verifier_id=?,
               paused_from=?,usage_json=?,milestones_json=?,plan_receipt_json=?,context_receipt_json=?,
               event_tip=?,updated_at=? WHERE thread_id=?""",
            (
                target, version, reduced["attempts"], reduced["creator_id"], reduced["verifier_id"], reduced["paused_from"],
                json.dumps(usage, sort_keys=True), json.dumps(milestones, sort_keys=True),
                reduced["plan_json"], reduced["context_json"], event_sha, _now(), mission["id"],
            ),
        )
        connection.commit()
        current = _row_state(_thread(connection, mission["id"]), mission)
        return {
            **current,
            "event": {**event_core, "event_sha256": event_sha},
            "marker": marker,
            "markers": current["markers"] + [marker, "MISSION_GRAPH_HASH_CHAIN_BOUND", "MISSION_GRAPH_TRANSITION_GUARDED"],
        }
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def mission_graph_status(mission_path: Path, root: Path) -> dict:
    """Return current durable graph state, budgets, milestones, and next events."""
    mission_path, mission = _mission(root, mission_path)
    database = _db_path(root, mission_path)
    if not database.exists():
        return init_mission_graph(mission_path, root)
    connection = _connect(database)
    try:
        row = _thread(connection, mission["id"])
        errors = _verify_chain(connection, row, mission_path, mission)
        if errors:
            raise MissionGraphError("MISSION_GRAPH_DRIFT", "; ".join(errors))
        result = _row_state(row, mission)
        return {**result, "database": str(database), "allowed_events": _allowed_events(row["state"]), "marker": "MISSION_GRAPH_RESUMABLE"}
    finally:
        connection.close()


def mission_graph_history(mission_path: Path, root: Path) -> dict:
    """Return the verified ordered transition history for one mission thread."""
    status = mission_graph_status(mission_path, root)
    mission_path, mission = _mission(root, mission_path)
    connection = _connect(_db_path(root, mission_path))
    try:
        events = [
            {**json.loads(row["event_json"]), "event_sha256": row["event_sha"]}
            for row in connection.execute(
                "SELECT * FROM graph_events WHERE thread_id=? ORDER BY version", (mission["id"],),
            )
        ]
    finally:
        connection.close()
    return {
        "schema": "factory.mission.graph.history.v1",
        "mission_id": mission["id"],
        "state": status["state"],
        "version": status["version"],
        "events": events,
        "chain_head": status["event_tip"],
        "marker": "MISSION_GRAPH_HASH_CHAIN_BOUND",
    }


def verify_mission_graph(mission_path: Path, root: Path) -> dict:
    """Verify the mission binding, event hash chain, and every receipt file hash."""
    try:
        mission_path, mission = _mission(root, mission_path)
        database = _db_path(root, mission_path)
        if not database.exists():
            raise MissionGraphError("MISSION_GRAPH_NOT_INITIALIZED", "mission graph database is missing")
        connection = _connect(database)
        try:
            row = _thread(connection, mission["id"])
            errors = _verify_chain(connection, row, mission_path, mission)
        finally:
            connection.close()
    except MissionGraphError as exc:
        errors = [exc.message]
        mission = {"id": None}
    result = {
        "schema": VERIFICATION_SCHEMA,
        "mission_id": mission.get("id"),
        "valid": not errors,
        "status": "verified" if not errors else "invalid",
        "marker": "MISSION_GRAPH_HASH_CHAIN_BOUND" if not errors else "MISSION_GRAPH_DRIFT",
        "errors": errors,
        "authority": "verification only; no execution or release authority",
    }
    if errors:
        result["failure"] = explain_failure("MISSION_GRAPH_DRIFT", "; ".join(errors), errors=errors)
    return result


def export_mission_graph(mission_path: Path, root: Path) -> dict:
    """Export the declared topology and highlight the current state as Mermaid."""
    status = mission_graph_status(mission_path, root)
    mission_path = _resolve_under(root, mission_path, "MISSION_GRAPH_MISSION_OUTSIDE_ROOT")
    states = [
        "planned", "creator_running", "independent_verification", "correction_required",
        "paused_for_review", "completion_receipted", "awaiting_release_authority",
        "release_decided", "outcome_observed", "deferred", "rejected", "budget_exhausted",
    ]
    lines = ["stateDiagram-v2", "    [*] --> planned"]
    edges = [
        ("planned", "creator_running", "approve"), ("planned", "deferred", "defer"),
        ("planned", "rejected", "reject"), ("creator_running", "independent_verification", "candidate_ready"),
        ("independent_verification", "correction_required", "validation_failed"),
        ("correction_required", "creator_running", "retry + fresh context"),
        ("independent_verification", "completion_receipted", "validation_passed"),
        ("creator_running", "paused_for_review", "owner pause"),
        ("independent_verification", "paused_for_review", "owner pause"),
        ("paused_for_review", "creator_running", "revised plan + resume"),
        ("completion_receipted", "awaiting_release_authority", "release_requested"),
        ("awaiting_release_authority", "release_decided", "human decision only"),
        ("release_decided", "outcome_observed", "outcome_recorded"),
    ]
    lines.extend(f"    {source} --> {target}: {label}" for source, target, label in edges)
    lines.extend(f"    {state} --> budget_exhausted: hard budget reached" for state in states if state in ACTIVE_STATES)
    lines.append(f"    classDef current fill:#fef3c7,stroke:#d97706,color:#451a03")
    lines.append(f"    class {status['state']} current")
    output = mission_path.parent / "mission-graph.mmd"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "schema": "factory.mission.graph.export.v1",
        "mission_id": status["mission_id"],
        "state": status["state"],
        "path": str(output),
        "sha256": _sha_path(output),
        "marker": "MISSION_GRAPH_MERMAID_EXPORTED",
    }


def langgraph_doctor() -> dict:
    """Report optional LangGraph readiness without importing unavailable packages."""
    available = importlib.util.find_spec("langgraph") is not None
    sqlite_available = importlib.util.find_spec("langgraph.checkpoint.sqlite") is not None if available else False
    ready = available and sqlite_available
    return {
        "schema": "factory.langgraph.doctor.v1",
        "available": available,
        "sqlite_checkpointer_available": sqlite_available,
        "ready": ready,
        "install": 'python -m pip install "factoryline-code-factory[langgraph]"',
        "native_runtime_available": True,
        "marker": "LANGGRAPH_ADAPTER_BOUND" if ready else "LANGGRAPH_OPTIONAL_FALLBACK",
        "authority": "LangGraph checkpoints are secondary; Code Factory receipts remain authoritative",
        "markers": ["LANGGRAPH_CHECKPOINT_SECONDARY", "LANGGRAPH_OPERATOR_COMMANDS"],
    }


def _remaining_budget_ratio(status: dict[str, Any]) -> float | None:
    remaining = []
    for usage_name, budget_name in (
        ("tokens", "max_tokens"), ("cost_usd", "max_cost_usd"), ("wall_seconds", "max_wall_seconds"),
    ):
        used, maximum = status["usage"][usage_name], status["budgets"][budget_name]
        if used is not None and maximum:
            remaining.append(max(0.0, 1.0 - (used / maximum)))
    return min(remaining) if remaining else None


def _route_reasons(risk: str, floor: str, failures: int, progress: float,
                   remaining: float | None, cache_continuity: bool) -> list[str]:
    reasons = [f"declared risk={risk}", f"quality floor={floor}"]
    if failures:
        reasons.append("failed milestone requires stronger reasoning")
    if progress >= 0.8 and not failures:
        reasons.append("completion is near; lower-cost tier is permitted above the quality floor")
    if remaining is not None:
        reasons.append(f"minimum remaining measured budget ratio={remaining:.3f}")
    if cache_continuity:
        reasons.append("preserve model family when switching would break a useful prompt cache")
    return reasons


def recommend_mission_route(mission_path: Path, root: Path, risk: str,
                            quality_floor: str = "balanced", cache_continuity: bool = True) -> dict:
    """Recommend an abstract model tier from verified state and budget facts."""
    if risk not in {"low", "medium", "high"}:
        raise MissionGraphError("MISSION_GRAPH_ROUTE_INVALID", "risk must be low, medium, or high")
    if quality_floor not in QUALITY_TIERS:
        raise MissionGraphError("MISSION_GRAPH_ROUTE_INVALID", "quality_floor must be economy, balanced, or frontier")
    status = mission_graph_status(mission_path, root)
    floor = QUALITY_TIERS.index(quality_floor)
    tier = max(floor, {"low": 0, "medium": 1, "high": 2}[risk])
    failures = status["milestone_progress"]["failed"]
    if failures or status["attempts"] >= 2:
        tier = max(tier, 2)
    progress = (
        status["milestone_progress"]["passed"] / status["milestone_progress"]["total"]
        if status["milestone_progress"]["total"] else 0.0
    )
    if progress >= 0.8 and not failures:
        tier = max(floor, tier - 1)
    remaining_ratio = _remaining_budget_ratio(status)
    reasons = _route_reasons(risk, quality_floor, failures, progress, remaining_ratio, cache_continuity)
    return {
        "schema": "factory.mission.route-recommendation.v1",
        "mission_id": status["mission_id"],
        "tier": QUALITY_TIERS[tier],
        "quality_floor": quality_floor,
        "risk": risk,
        "progress_ratio": progress,
        "remaining_measured_budget_ratio": remaining_ratio,
        "cache_policy": "preserve_family" if cache_continuity else "switch_allowed",
        "reasons": reasons,
        "provider_or_model": None,
        "marker": "MISSION_GRAPH_ROUTING_EXPLAINED",
        "authority": "recommendation only; provider selection and spend authorization remain external",
    }


def build_langgraph_adapter(mission_path: Path, root: Path, checkpointer: Any | None = None) -> Any:
    """Compile an optional resumable LangGraph adapter over the native transition guard."""
    doctor = langgraph_doctor()
    if not doctor["available"]:
        raise MissionGraphError("LANGGRAPH_NOT_INSTALLED", doctor["install"])
    from langgraph.graph import END, START, StateGraph

    init_mission_graph(mission_path, root)
    if checkpointer is None:
        if not doctor["sqlite_checkpointer_available"]:
            raise MissionGraphError("LANGGRAPH_SQLITE_NOT_INSTALLED", doctor["install"])
        from langgraph.checkpoint.sqlite import SqliteSaver

        checkpoint_path = _db_path(Path(root), Path(mission_path)).with_name("langgraph-checkpoints.sqlite3")
        checkpoint_connection = sqlite3.connect(checkpoint_path, check_same_thread=False)
        saver = SqliteSaver(checkpoint_connection)
    else:
        saver = checkpointer
    bound_mission = str(Path(mission_path).resolve())
    bound_root = str(Path(root).resolve())

    def validate_transition(state: LangGraphState) -> LangGraphState:
        result = apply_mission_event(
            Path(state.get("mission_path", bound_mission)),
            Path(state.get("root", bound_root)),
            state["event"], state["actor"], state["role"], state["idempotency_key"],
            Path(state["receipt_path"]) if state.get("receipt_path") else None,
            state.get("payload", {}),
        )
        return {"result": {**result, "adapter_marker": "LANGGRAPH_ADAPTER_BOUND"}}

    builder = StateGraph(LangGraphState)
    builder.add_node("code_factory_transition", validate_transition)
    builder.add_edge(START, "code_factory_transition")
    builder.add_edge("code_factory_transition", END)
    return builder.compile(checkpointer=saver)
