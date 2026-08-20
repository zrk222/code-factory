"""Deterministic, proof-bound comparison of completed governed agent runs.

Combine does not invoke an agent executable.  The selected harness owns process
execution and must first produce a ready admission packet; Combine then compares
immutable, independently verified run events on one sealed local task.  This
keeps the scoreboard useful without making a vendor claim, speed claim, or
agent-authored self-assessment into evidence.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .agent_license import (
    AGENT_IDENTITY_SCHEMA,
    AGENT_RUN_SCHEMA,
    AgentLicenseError,
    _TASK_IDENTIFIER,
    _canonical,
    _iso,
    _load_json,
    _now,
    _relative,
    _sha,
    _text,
    _timestamp,
    _validate_ledger_event,
    load_governed_runs,
    normalize_agent_identity,
)
from .attribution import FailureClass


COMBINE_TASK_SCHEMA = "factory.combine-task.v1"
COMBINE_SCOREBOARD_SCHEMA = "factory.combine-scoreboard.v1"
TASK_DIR = Path(".factory") / "combines" / "tasks"
SCOREBOARD_DIR = Path(".factory") / "combines" / "scoreboards"
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class CombineError(ValueError):
    """A stable, fail-closed Combine error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _atomic_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(_canonical(payload) + b"\n")
    os.replace(temporary, path)
    return path


def _task_input(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {"schema", "id", "description", "agents"} or value.get("schema") != COMBINE_TASK_SCHEMA:
        raise CombineError("COMBINE_TASK_INVALID", f"task must use {COMBINE_TASK_SCHEMA} and contain schema, id, description, and agents")
    task_id = _text(value.get("id"), "id", maximum=96)
    if not _TASK_IDENTIFIER.fullmatch(task_id):
        raise CombineError("COMBINE_TASK_INVALID", "task id must use lowercase letters, digits, and hyphens")
    description = _text(value.get("description"), "description", maximum=600)
    raw_agents = value.get("agents")
    if not isinstance(raw_agents, list) or not 2 <= len(raw_agents) <= 8:
        raise CombineError("COMBINE_TASK_INVALID", "agents must contain 2 through 8 declared identities")
    agents = [normalize_agent_identity(item, f"agents[{index}]") for index, item in enumerate(raw_agents)]
    hashes = [item["identity_sha256"] for item in agents]
    if len(set(hashes)) != len(hashes):
        raise CombineError("COMBINE_TASK_INVALID", "agents must be unique declared identities")
    return {"schema": COMBINE_TASK_SCHEMA, "id": task_id, "description": description, "agents": sorted(agents, key=lambda item: item["identity_sha256"])}


def _task_core(value: dict[str, Any]) -> dict[str, Any]:
    fields = {"schema", "marker", "task_id", "created_at", "description_sha256", "agents", "task_sha256", "authority", "scope_limits"}
    if set(value) != fields or value.get("schema") != COMBINE_TASK_SCHEMA or value.get("marker") != "COMBINE_TASK_SEALED":
        raise CombineError("COMBINE_TASK_INVALID", "unsupported sealed task fields")
    core = {key: value[key] for key in fields - {"task_sha256"}}
    if value.get("task_sha256") != _sha(core):
        raise CombineError("COMBINE_TASK_INVALID", "sealed task hash mismatch")
    task_id = _text(core.get("task_id"), "task_id", maximum=96)
    if not _TASK_IDENTIFIER.fullmatch(task_id):
        raise CombineError("COMBINE_TASK_INVALID", "task_id is invalid")
    _text(core.get("description_sha256"), "description_sha256", maximum=64)
    agents = core.get("agents")
    if not isinstance(agents, list) or not 2 <= len(agents) <= 8:
        raise CombineError("COMBINE_TASK_INVALID", "sealed task agent list is invalid")
    normalized = [normalize_agent_identity(item, f"agents[{index}]") for index, item in enumerate(agents)]
    if [item["identity_sha256"] for item in normalized] != sorted(item["identity_sha256"] for item in normalized):
        raise CombineError("COMBINE_TASK_INVALID", "sealed task agents must be deterministically ordered")
    if len({item["identity_sha256"] for item in normalized}) != len(normalized):
        raise CombineError("COMBINE_TASK_INVALID", "sealed task agents must be unique")
    return {**core, "task_id": task_id, "agents": normalized, "task_sha256": value["task_sha256"]}


def seal_combine_task(root: Path, source_path: Path, *, out: Path | None = None) -> dict[str, Any]:
    """Seal one human-written task declaration without starting any agent."""
    workspace = Path(root).resolve()
    source, _ = _relative(workspace, source_path, "source")
    task = _task_input(_load_json(source))
    core = {
        "schema": COMBINE_TASK_SCHEMA,
        "marker": "COMBINE_TASK_SEALED",
        "task_id": task["id"],
        "created_at": _iso(_now()),
        "description_sha256": hashlib.sha256(task["description"].encode("utf-8")).hexdigest(),
        "agents": task["agents"],
        "authority": dict(_AUTHORITY),
        "scope_limits": [
            "Task sealing never invokes an agent or a model.",
            "The description is hashed, not copied into the task receipt or scoreboard.",
            "Declared identities are not external identity verification.",
        ],
    }
    sealed = {**core, "task_sha256": _sha(core)}
    target = Path(out) if out is not None else workspace / TASK_DIR / f"{task['id']}.json"
    target = target if target.is_absolute() else workspace / target
    try:
        target.resolve().relative_to(workspace)
    except ValueError as exc:
        raise CombineError("COMBINE_PATH_OUT_OF_SCOPE", "task output must remain inside workspace") from exc
    if target.exists():
        existing = _load_json(target)
        if existing.get("task_sha256") == sealed["task_sha256"]:
            return {"marker": "COMBINE_TASK_ALREADY_SEALED", "task": existing, "path": str(target.resolve())}
        raise CombineError("COMBINE_TASK_EXISTS", "task id is already bound to different immutable content")
    _atomic_json(target, sealed)
    return {"marker": "COMBINE_TASK_SEALED", "task": sealed, "path": str(target.resolve())}


def _load_task(root: Path, task_path: Path) -> tuple[dict[str, Any], Path]:
    try:
        path, _ = _relative(root, task_path, "task")
        return _task_core(_load_json(path)), path
    except (AgentLicenseError, CombineError) as exc:
        raise CombineError("COMBINE_TASK_INVALID", str(exc)) from exc


def _rank(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(row: dict[str, Any]) -> tuple[int, int, int, str]:
        failures = row["result"]["failure_classes"]
        severe = sum(item in {"hollow_test", "hollow_validator", "scope_escape"} for item in failures)
        return (0 if row["result"]["passed"] else 1, severe, len(failures), row["agent"]["identity_sha256"])
    ordered = sorted(rows, key=key)
    return [{**row, "rank": index + 1} for index, row in enumerate(ordered)]


def _scoreboard_core(task: dict[str, Any], rows: list[dict[str, Any]], *, now: datetime) -> dict[str, Any]:
    ranked = _rank(rows)
    counts = Counter(item for row in ranked for item in row["result"]["failure_classes"])
    summary = {
        "candidate_count": len(ranked),
        "passed_count": sum(1 for row in ranked if row["result"]["passed"]),
        "failure_class_counts": {key: counts.get(key, 0) for key in sorted(item.value for item in FailureClass)},
        "unobserved": {"elapsed_seconds": None, "tokens": None, "cost_usd": None, "quality_score": None},
    }
    return {
        "schema": COMBINE_SCOREBOARD_SCHEMA,
        "marker": "COMBINE_SCOREBOARD_SCORED",
        "scored_at": _iso(now),
        "task": {"task_id": task["task_id"], "task_sha256": task["task_sha256"], "description_sha256": task["description_sha256"]},
        "candidates": ranked,
        "summary": summary,
        "ranking_basis": "passed status, severe-failure count, total failure-class count, then declared identity digest; no speed, cost, token, vendor, or quality measurement is inferred",
        "authority": dict(_AUTHORITY),
        "scope_limits": [
            "Combine scores completed governed evidence; it never invokes an agent executable or runs a model.",
            "A rank is a deterministic ordering of supplied proof facts, not a global agent benchmark or a quality claim.",
            "Agent and verifier identities are declared unless the selected harness independently authenticates them.",
        ],
    }


def _event_rows(root: Path, task: dict[str, Any], event_paths: list[Path] | None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if event_paths is None:
        events = [event for event in load_governed_runs(root) if event.get("task_id") == task["task_id"]]
    else:
        for source in event_paths:
            try:
                path, _ = _relative(root, source, "event")
                event = _validate_ledger_event(root, _load_json(path), require_evidence_files=True)
                events.append({**event, "event_sha256": _sha(event)})
            except AgentLicenseError as exc:
                raise CombineError("COMBINE_EVENT_INVALID", str(exc)) from exc
    expected = {agent["identity_sha256"]: agent for agent in task["agents"]}
    selected: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("task_id") != task["task_id"]:
            raise CombineError("COMBINE_TASK_MISMATCH", "each event must bind exactly this sealed task id")
        identity = event["agent"]["identity_sha256"]
        if identity not in expected:
            raise CombineError("COMBINE_UNDECLARED_AGENT", "event agent is absent from the sealed task")
        if identity in selected:
            raise CombineError("COMBINE_DUPLICATE_RESULT", "exactly one event is allowed per declared agent")
        selected[identity] = event
    missing = sorted(set(expected) - set(selected))
    if missing:
        raise CombineError("COMBINE_EVENT_MISSING", "one governed event is required for each declared agent")
    rows: list[dict[str, Any]] = []
    for identity in sorted(expected):
        event = selected[identity]
        rows.append({
            "agent": expected[identity],
            "event": {
                "event_id": event["event_id"], "event_sha256": event["event_sha256"], "recorded_at": event["recorded_at"],
                "admission_packet_sha256": event["admission"]["packet_sha256"],
                "verification_subject": event["verification"]["subject"],
                "verification_receipt_sha256": event["verification"]["receipt"]["sha256"],
            },
            "result": {
                "passed": event["passed"], "failure_classes": event["failure_classes"],
                "result_receipt_sha256": event["result_receipt"]["sha256"],
            },
        })
    return rows


def score_combine(root: Path, task_path: Path, *, event_paths: list[Path] | None = None, out: Path | None = None) -> dict[str, Any]:
    """Score one complete set of sealed, governed task events without execution."""
    workspace = Path(root).resolve()
    task, _ = _load_task(workspace, task_path)
    rows = _event_rows(workspace, task, event_paths)
    core = _scoreboard_core(task, rows, now=_now())
    scoreboard = {**core, "scoreboard_sha256": _sha(core)}
    target = Path(out) if out is not None else workspace / SCOREBOARD_DIR / f"{task['task_id']}-{scoreboard['scoreboard_sha256'][:12]}.json"
    target = target if target.is_absolute() else workspace / target
    try:
        target.resolve().relative_to(workspace)
    except ValueError as exc:
        raise CombineError("COMBINE_PATH_OUT_OF_SCOPE", "scoreboard output must remain inside workspace") from exc
    _atomic_json(target, scoreboard)
    return {"marker": "COMBINE_SCOREBOARD_SCORED", "scoreboard": scoreboard, "path": str(target.resolve())}


def verify_combine_scoreboard(path: Path) -> dict[str, Any]:
    """Verify a Combine scoreboard completely offline from embedded proof hashes."""
    try:
        value = _load_json(Path(path), code="COMBINE_SCOREBOARD_INVALID")
        expected_fields = {"schema", "marker", "scored_at", "task", "candidates", "summary", "ranking_basis", "authority", "scope_limits", "scoreboard_sha256"}
        if set(value) != expected_fields or value.get("schema") != COMBINE_SCOREBOARD_SCHEMA or value.get("marker") != "COMBINE_SCOREBOARD_SCORED":
            raise CombineError("COMBINE_SCOREBOARD_INVALID", "unsupported scoreboard schema or fields")
        core = {key: value[key] for key in expected_fields - {"scoreboard_sha256"}}
        if value.get("scoreboard_sha256") != _sha(core):
            raise CombineError("COMBINE_SCOREBOARD_INVALID", "scoreboard hash mismatch")
        _timestamp(value.get("scored_at"), "scored_at")
        task = value.get("task")
        if not isinstance(task, dict) or set(task) != {"task_id", "task_sha256", "description_sha256"} or not _TASK_IDENTIFIER.fullmatch(str(task.get("task_id", ""))):
            raise CombineError("COMBINE_SCOREBOARD_INVALID", "task binding is invalid")
        rows = value.get("candidates")
        if not isinstance(rows, list) or not 2 <= len(rows) <= 8:
            raise CombineError("COMBINE_SCOREBOARD_INVALID", "candidate list is invalid")
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"agent", "event", "result", "rank"}:
                raise CombineError("COMBINE_SCOREBOARD_INVALID", "candidate row is invalid")
            agent = normalize_agent_identity(row["agent"])
            if agent["identity_sha256"] in seen:
                raise CombineError("COMBINE_SCOREBOARD_INVALID", "candidate identities must be unique")
            seen.add(agent["identity_sha256"])
            event = row["event"]
            result = row["result"]
            if not isinstance(event, dict) or set(event) != {"event_id", "event_sha256", "recorded_at", "admission_packet_sha256", "verification_subject", "verification_receipt_sha256"}:
                raise CombineError("COMBINE_SCOREBOARD_INVALID", "candidate event binding is invalid")
            if not isinstance(result, dict) or set(result) != {"passed", "failure_classes", "result_receipt_sha256"} or not isinstance(result["passed"], bool):
                raise CombineError("COMBINE_SCOREBOARD_INVALID", "candidate result is invalid")
            failures = result["failure_classes"]
            if not isinstance(failures, list) or any(item not in {entry.value for entry in FailureClass} for item in failures):
                raise CombineError("COMBINE_SCOREBOARD_INVALID", "candidate failure class is invalid")
            if result["passed"] and failures:
                raise CombineError("COMBINE_SCOREBOARD_INVALID", "passing candidate cannot have failures")
            _timestamp(event["recorded_at"], "candidate.recorded_at")
            normalized.append({"agent": agent, "event": event, "result": {**result, "failure_classes": sorted(failures)}})
        reranked = _rank(normalized)
        if [(row["agent"]["identity_sha256"], row["rank"]) for row in rows] != [(row["agent"]["identity_sha256"], row["rank"]) for row in reranked]:
            raise CombineError("COMBINE_SCOREBOARD_INVALID", "candidate ranks are not deterministic")
        expected_summary = _scoreboard_core({"task_id": task["task_id"], "task_sha256": task["task_sha256"], "description_sha256": task["description_sha256"]}, normalized, now=_timestamp(value["scored_at"], "scored_at"))["summary"]
        if value.get("summary") != expected_summary:
            raise CombineError("COMBINE_SCOREBOARD_INVALID", "scoreboard summary does not match candidates")
    except (AgentLicenseError, CombineError) as exc:
        return {"schema": COMBINE_SCOREBOARD_SCHEMA, "marker": "COMBINE_SCOREBOARD_INVALID", "ok": False, "reason": getattr(exc, "code", "COMBINE_SCOREBOARD_INVALID")}
    return {"schema": COMBINE_SCOREBOARD_SCHEMA, "marker": "COMBINE_SCOREBOARD_VERIFIED", "ok": True, "scoreboard_sha256": value["scoreboard_sha256"], "signature": "not_supplied"}


def seal_combine_scoreboard(path: Path, *, private_key_path: Path, keyid: str, identity: str, issuer: str, tenant_id: str, out: Path) -> dict[str, Any]:
    """Optionally bind a valid scoreboard to a Receipt v2 DSSE envelope."""
    verified = verify_combine_scoreboard(path)
    if not verified["ok"]:
        raise CombineError("COMBINE_SIGNING_FAILED", "scoreboard must verify before sealing")
    scoreboard = _load_json(Path(path))
    try:
        from .enterprise_receipts import EnterpriseReceiptError, seal_receipt_v2
        payload = {
            "schema": "factory.receipt.v2", "module": "combine", "stage": "scoreboard",
            "feature": scoreboard["task"]["task_id"], "ok": True, "tenant_id": _text(tenant_id, "tenant_id"),
            "run_id": scoreboard["scoreboard_sha256"][:32], "ts": _iso(_now()), "subject_sha256": scoreboard["scoreboard_sha256"],
        }
        envelope = seal_receipt_v2(payload, Path(private_key_path), _text(keyid, "keyid"), _text(identity, "identity"), _text(issuer, "issuer"), Path(out))
    except (ImportError, OSError, EnterpriseReceiptError) as exc:
        raise CombineError("COMBINE_SIGNING_FAILED", str(exc)) from exc
    return {"schema": COMBINE_SCOREBOARD_SCHEMA, "marker": "COMBINE_SCOREBOARD_SEALED", "scoreboard_sha256": scoreboard["scoreboard_sha256"], "path": str(Path(out).resolve()), "payload_sha256": envelope["payload_sha256"], "authority": {**_AUTHORITY, "signing": True}}


def combine_projection(root: Path) -> dict[str, Any]:
    """Return bounded scorecard facts for Graph Ops and MCP without execution."""
    workspace = Path(root).resolve()
    scoreboards: list[dict[str, Any]] = []
    for path in sorted((workspace / SCOREBOARD_DIR).glob("*.json")):
        verified = verify_combine_scoreboard(path)
        if not verified.get("ok"):
            continue
        value = _load_json(path)
        scoreboards.append({
            "task_id": value["task"]["task_id"], "scoreboard_sha256": value["scoreboard_sha256"],
            "scored_at": value["scored_at"], "summary": value["summary"],
            "candidates": [{"agent": row["agent"], "rank": row["rank"], "passed": row["result"]["passed"], "failure_classes": row["result"]["failure_classes"]} for row in value["candidates"]],
        })
    return {"marker": "COMBINE_STATUS_READ_ONLY", "available": bool(scoreboards), "scoreboards": scoreboards, "authority": dict(_AUTHORITY), "scope_limits": ["Projection does not execute agent commands or use scores as a vendor-quality claim."]}
