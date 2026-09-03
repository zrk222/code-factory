"""Proof-carrying runner-admission packets for the enterprise pilot boundary.

This module binds an already-admitted local enterprise decision to one exact
argv digest.  It never runs the argv.  A real PEP integration must ensure its
runner accepts only a current packet and separately prove that topology.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .enterprise_enforcement import EnterpriseEnforcementError, canonical_json, verify_enterprise_decision


INPUT_SCHEMA = "factory.runner-admission-input.v1"
PACKET_SCHEMA = "factory.runner-admission-packet.v1"
PROJECTION_SCHEMA = "factory.runner-admission-projection.v1"
PACKET_DIR = Path(".factory/enterprise-enforcement/runner-admissions")
FORBIDDEN_ARGV_TOKENS = frozenset({"&&", ";", "|", ">", "<", "`"})


class EnterpriseRunnerAdmissionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _text(value: object, field: str, *, limit: int = 160) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_INPUT", f"{field} must be a non-empty string up to {limit} characters")
    return value.strip()


def _paths(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_INPUT", f"{field} must contain 1 through 64 relative paths")
    result: list[str] = []
    for raw in value:
        item = _text(raw, field, limit=512).replace("\\", "/")
        path = Path(item)
        if path.is_absolute() or ".." in path.parts:
            raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_INPUT", f"{field} cannot escape a workspace")
        result.append(item.rstrip("/") or ".")
    return sorted(set(result))


def _load(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    workspace = Path(root).resolve()
    candidate = (workspace / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_PATH", "input must remain in the workspace") from exc
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_INPUT", str(exc)) from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_INPUT", f"schema must be {schema}")
    return value, candidate


def _argv(value: object) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 128 or any(not isinstance(item, str) or not item.strip() or len(item) > 2048 for item in value):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_COMMAND_INVALID", "argv must contain 1 through 128 non-empty strings")
    argv = [item.strip() for item in value]
    if any(item in FORBIDDEN_ARGV_TOKENS for item in argv):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_COMMAND_INVALID", "shell operators are forbidden; use argv only")
    return argv


def _now() -> datetime:
    """Return the explicit UTC clock used only for local freshness checks."""
    return datetime.now(timezone.utc)


def _stamp(value: object, field: str) -> str:
    """Normalize one required RFC3339 timestamp without accepting local time."""
    if not isinstance(value, str) or not value.strip():
        raise EnterpriseRunnerAdmissionError("E_RUNNER_FRESHNESS_MISSING", f"{field} must be present")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_FRESHNESS_INVALID", f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_FRESHNESS_INVALID", f"{field} must include an offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _admission_expiry(decision: dict[str, Any], *, now: datetime | None = None) -> str:
    """Derive a packet expiry from signed identity evidence, never caller input."""
    identity = decision.get("workload_identity") if isinstance(decision.get("workload_identity"), dict) else {}
    expires_at = _stamp(identity.get("expires_at"), "decision.workload_identity.expires_at")
    if datetime.fromisoformat(expires_at.replace("Z", "+00:00")) <= (now or _now()):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_EXPIRED", "the bound workload identity has expired; record a new decision")
    return expires_at


def prepare_runner_admission(root: Path, input_path: Path, out: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Seal an immutable non-executing packet for one exact admitted runner argv."""
    workspace = Path(root).resolve()
    value, _ = _load(workspace, input_path, INPUT_SCHEMA)
    required = {"schema", "id", "decision", "run_id", "action_class", "scope_paths", "argv"}
    missing = sorted(required - set(value))
    if missing:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_INPUT", f"missing fields: {missing}")
    decision_path = _text(value["decision"], "decision", limit=512)
    try:
        checked = verify_enterprise_decision(workspace, Path(decision_path))
    except EnterpriseEnforcementError as exc:
        raise EnterpriseRunnerAdmissionError(exc.code, exc.message) from exc
    decision = checked["decision"]
    admission_expires_at = _admission_expiry(decision, now=now)
    request = decision.get("request") if isinstance(decision.get("request"), dict) else {}
    action_class = _text(value["action_class"], "action_class", limit=80).lower()
    scope_paths = _paths(value["scope_paths"], "scope_paths")
    argv = _argv(value["argv"])
    if action_class != request.get("action_class"):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ACTION_MISMATCH", "runner action does not match the admitted decision")
    if scope_paths != request.get("scope_paths"):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_SCOPE_MISMATCH", "runner scope does not match the admitted decision")
    target = (workspace / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_PATH", "output must remain in the workspace") from exc
    if not target.is_relative_to((workspace / PACKET_DIR).resolve()):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_PATH", f"output must stay under {PACKET_DIR.as_posix()}")
    if target.exists():
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_IMMUTABLE", "refusing to overwrite a runner packet")
    packet = {
        "schema": PACKET_SCHEMA, "marker": "RUNNER_ADMISSION_PACKET_SEALED", "packet_id": _text(value["id"], "id"), "run_id": _text(value["run_id"], "run_id"),
        "decision": {"path": checked["path"], "decision_sha256": checked["decision_sha256"]}, "action_class": action_class, "scope_paths": scope_paths,
        "argv": argv, "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(), "admission_expires_at": admission_expires_at,
        "authority": {"execution": False, "approval": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False},
        "claim_boundary": "Runner input contract only. This packet did not execute argv, authenticate a workload, prove PEP topology, enforce isolation, or grant external authority.",
    }
    packet["packet_sha256"] = hashlib.sha256(canonical_json(packet)).hexdigest()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_json(packet) + b"\n")
    return {**packet, "path": target.relative_to(workspace).as_posix()}


def _packet_path(workspace: Path, path: Path) -> Path:
    """Resolve one packet path without allowing a workspace escape."""
    candidate = (workspace / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    packet_root = (workspace / PACKET_DIR).resolve()
    try:
        candidate.relative_to(packet_root)
    except ValueError as exc:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_PATH", f"packet must stay under {PACKET_DIR.as_posix()}") from exc
    return candidate


def _packet_value(candidate: Path) -> tuple[dict[str, Any], str]:
    """Load one canonical, zero-authority runner packet."""
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ADMISSION_INPUT", str(exc)) from exc
    if not isinstance(value, dict) or value.get("schema") != PACKET_SCHEMA or value.get("marker") != "RUNNER_ADMISSION_PACKET_SEALED":
        raise EnterpriseRunnerAdmissionError("E_RUNNER_PACKET_INVALID", "packet schema or marker is invalid")
    supplied = value.get("packet_sha256")
    unsigned = dict(value)
    unsigned.pop("packet_sha256", None)
    if not isinstance(supplied, str) or hashlib.sha256(canonical_json(unsigned)).hexdigest() != supplied:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_PACKET_HASH_INVALID", "packet hash is invalid")
    if not isinstance(value.get("authority"), dict) or any(item is not False for item in value["authority"].values()):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_PACKET_AUTHORITY", "packet must grant zero authority")
    return value, supplied


def _packet_binding(workspace: Path, value: dict[str, Any], *, now: datetime | None = None) -> tuple[str, str]:
    """Verify the decision, action, scope, and argv bindings in one packet."""
    decision_ref = value.get("decision") if isinstance(value.get("decision"), dict) else {}
    decision_path = _text(decision_ref.get("path"), "decision.path", limit=512)
    try:
        decision = verify_enterprise_decision(workspace, Path(decision_path))
    except EnterpriseEnforcementError as exc:
        raise EnterpriseRunnerAdmissionError(exc.code, exc.message) from exc
    if decision_ref.get("decision_sha256") != decision["decision_sha256"]:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_DECISION_MISMATCH", "packet decision digest does not match its verified receipt")
    request = decision["decision"].get("request") if isinstance(decision["decision"].get("request"), dict) else {}
    action_class = _text(value.get("action_class"), "action_class", limit=80).lower()
    scope_paths = _paths(value.get("scope_paths"), "scope_paths")
    argv = _argv(value.get("argv"))
    if value.get("argv_sha256") != hashlib.sha256(canonical_json(argv)).hexdigest():
        raise EnterpriseRunnerAdmissionError("E_RUNNER_COMMAND_HASH_INVALID", "argv hash is invalid")
    if action_class != request.get("action_class"):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_ACTION_MISMATCH", "packet action does not match its decision")
    if scope_paths != request.get("scope_paths"):
        raise EnterpriseRunnerAdmissionError("E_RUNNER_SCOPE_MISMATCH", "packet scope does not match its decision")
    admission_expires_at = _admission_expiry(decision["decision"], now=now)
    if _stamp(value.get("admission_expires_at"), "admission_expires_at") != admission_expires_at:
        raise EnterpriseRunnerAdmissionError("E_RUNNER_FRESHNESS_MISMATCH", "packet expiry does not match its bound signed identity evidence")
    return decision["decision_sha256"], admission_expires_at


def verify_runner_admission_packet(root: Path, path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Verify one fresh non-executing runner packet and exact decision binding."""
    workspace = Path(root).resolve()
    candidate = _packet_path(workspace, path)
    value, supplied = _packet_value(candidate)
    decision_sha256, admission_expires_at = _packet_binding(workspace, value, now=now)
    return {"packet": value, "packet_sha256": supplied, "decision_sha256": decision_sha256, "admission_expires_at": admission_expires_at, "path": candidate.relative_to(workspace).as_posix()}


def runner_admission_projection(root: Path) -> dict[str, Any]:
    """Read bounded runner-packet facts for Graph Ops and MCP without execution."""
    workspace = Path(root).resolve()
    directory = workspace / PACKET_DIR
    result: dict[str, Any] = {"schema": PROJECTION_SCHEMA, "marker": "RUNNER_ADMISSION_READ_ONLY", "packet_count": 0, "verified_count": 0, "fresh_count": 0, "expired_count": 0, "invalid_count": 0, "packets": [], "authority": {"execution": False, "approval": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False}, "claim_boundary": "Read-only local runner-packet projection. Freshness is derived from sealed identity expiry; it does not execute argv, authenticate a workload, re-check live revocations, prove runner topology, enforce isolation, or grant authority."}
    for path in sorted(directory.glob("*.json"))[:500] if directory.is_dir() else []:
        result["packet_count"] += 1
        try:
            checked = verify_runner_admission_packet(workspace, path)
            packet = checked["packet"]
            result["verified_count"] += 1
            result["fresh_count"] += 1
            result["packets"].append({"path": checked["path"], "packet_sha256": checked["packet_sha256"], "decision_sha256": checked["decision_sha256"], "run_id": packet.get("run_id"), "action_class": packet.get("action_class"), "scope_count": len(packet.get("scope_paths", [])), "argv_sha256": packet.get("argv_sha256"), "admission_expires_at": checked["admission_expires_at"]})
        except EnterpriseRunnerAdmissionError as exc:
            if exc.code == "E_RUNNER_ADMISSION_EXPIRED":
                result["expired_count"] += 1
            else:
                result["invalid_count"] += 1
    return result
