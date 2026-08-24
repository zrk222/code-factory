"""Sealed, local admission packets for externally enforced agent harnesses."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .graph_ops import graph_ops_snapshot
from .loop_passport import verify_loop_passport
from .agent_license import AgentLicenseError, admission_license_decision, normalize_agent_identity


ADMISSION_REQUEST_SCHEMA = "factory.run-admission.request.v1"
ADMISSION_PACKET_SCHEMA = "factory.run-admission.packet.v1"
_SKIP_PARTS = {".git", ".factory", "__pycache__", "node_modules", ".venv", "venv"}
_AUTHORITY = {
    "execution": False, "approval": False, "repair": False, "merge": False,
    "publication": False, "deployment": False, "signing": False, "messaging": False,
    "credential": False, "connector": False,
}


class AdmissionError(ValueError):
    """Stable admission error with no hidden side effect."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError("ADMISSION_INPUT_UNREADABLE", f"cannot read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise AdmissionError("ADMISSION_INPUT_INVALID", "JSON input must be an object")
    return value


def _inside(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise AdmissionError("ADMISSION_PATH_OUT_OF_SCOPE", "path must remain inside the workspace") from exc
    return resolved


def _relative_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdmissionError("ADMISSION_REQUEST_INVALID", f"{field} must be a non-empty path")
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise AdmissionError("ADMISSION_PATH_OUT_OF_SCOPE", f"{field} must be workspace relative")
    return path.as_posix().rstrip("/") or "."


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise AdmissionError("ADMISSION_REQUEST_INVALID", f"{field} must be RFC3339 text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdmissionError("ADMISSION_REQUEST_INVALID", f"{field} must be RFC3339 text") from exc
    if parsed.tzinfo is None:
        raise AdmissionError("ADMISSION_REQUEST_INVALID", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _fingerprint(root: Path) -> str:
    """Hash workspace content while excluding mutable VCS and Factory outputs."""
    records: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _SKIP_PARTS.intersection(path.relative_to(root).parts):
            continue
        relative = path.relative_to(root).as_posix()
        records.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        if len(records) > 10_000:
            raise AdmissionError("ADMISSION_WORKSPACE_TOO_LARGE", "workspace fingerprint exceeds 10000 files")
    return _sha(records)


def _string_list(value: object, field: str, *, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise AdmissionError("ADMISSION_REQUEST_INVALID", f"{field} must contain 1 through {maximum} entries")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise AdmissionError("ADMISSION_REQUEST_INVALID", f"{field} entries must be non-empty strings")
    result = sorted(set(item.strip() for item in value))
    if len(result) != len(value):
        raise AdmissionError("ADMISSION_REQUEST_INVALID", f"{field} entries must be unique")
    return result


def _validate_request(root: Path, request: dict[str, Any], passport: dict[str, Any]) -> dict[str, Any]:
    if request.get("schema") != ADMISSION_REQUEST_SCHEMA:
        raise AdmissionError("ADMISSION_REQUEST_INVALID", "unsupported admission request schema")
    request_id = request.get("id")
    if not isinstance(request_id, str) or not request_id or len(request_id) > 160:
        raise AdmissionError("ADMISSION_REQUEST_INVALID", "id must be 1 through 160 characters")
    now = datetime.now(timezone.utc)
    valid_until = _utc(request.get("valid_until"), "valid_until")
    if valid_until <= now:
        raise AdmissionError("ADMISSION_EXPIRED", "valid_until must be after current UTC time")
    if valid_until > now + timedelta(hours=1):
        raise AdmissionError("ADMISSION_VALIDITY_TOO_LONG", "valid_until may be at most one hour ahead")
    trigger = request.get("trigger")
    if not isinstance(trigger, dict) or trigger != passport.get("trigger"):
        raise AdmissionError("ADMISSION_TRIGGER_MISMATCH", "request trigger must exactly match the Loop Passport")
    actions = _string_list(request.get("actions"), "actions")
    declared_actions = set(passport.get("capabilities", {}).get("actions", []))
    if not set(actions).issubset(declared_actions):
        raise AdmissionError("ADMISSION_ACTION_UNDECLARED", "request action is absent from the Loop Passport")
    paths = [_relative_path(value, "paths") for value in _string_list(request.get("paths"), "paths")]
    allowed_paths = passport.get("workspace", {}).get("allowed_paths", [])
    if not isinstance(allowed_paths, list) or not all(isinstance(item, str) for item in allowed_paths):
        raise AdmissionError("ADMISSION_PASSPORT_INVALID", "Loop Passport has invalid allowed paths")
    for item in paths:
        if not any(scope == "." or item == scope or item.startswith(scope.rstrip("/") + "/") for scope in allowed_paths):
            raise AdmissionError("ADMISSION_PATH_OUT_OF_SCOPE", "request path is absent from the Loop Passport")
        _inside(root, root / item)
    budget = request.get("budget")
    declared_budget = passport.get("budgets")
    if not isinstance(budget, dict) or not isinstance(declared_budget, dict) or set(budget) != set(declared_budget):
        raise AdmissionError("ADMISSION_BUDGET_INVALID", "request budget must match Loop Passport budget keys")
    for key, cap in declared_budget.items():
        value = budget.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or value > cap:
            raise AdmissionError("ADMISSION_BUDGET_INVALID", f"request {key} exceeds the Loop Passport")
    approvals = request.get("approvals")
    required = set(passport.get("approvals", {}).get("required_for", [])) & set(actions)
    if not isinstance(approvals, list) or len(approvals) != len(required):
        raise AdmissionError("ADMISSION_APPROVAL_MISSING", "one named approval is required for every requested protected action")
    normalized_approvals: list[dict[str, str]] = []
    seen_actions: set[str] = set()
    for item in approvals:
        if not isinstance(item, dict) or set(item) != {"action", "approved_by", "expires_at"}:
            raise AdmissionError("ADMISSION_REQUEST_INVALID", "approval must have action, approved_by, and expires_at")
        action, approver = item["action"], item["approved_by"]
        if action not in required or action in seen_actions or not isinstance(approver, str) or not approver.strip():
            raise AdmissionError("ADMISSION_APPROVAL_MISSING", "approval action or named approver is invalid")
        if _utc(item["expires_at"], "approval.expires_at") <= now:
            raise AdmissionError("ADMISSION_APPROVAL_EXPIRED", "approval expiry must be after current UTC time")
        if valid_until > _utc(item["expires_at"], "approval.expires_at"):
            raise AdmissionError("ADMISSION_VALIDITY_EXCEEDS_APPROVAL", "valid_until may not outlive a required approval")
        seen_actions.add(action)
        normalized_approvals.append({"action": action, "approved_by": approver.strip(), "expires_at": item["expires_at"]})
    normalized = {
        "schema": ADMISSION_REQUEST_SCHEMA,
        "id": request_id,
        "valid_until": request["valid_until"],
        "trigger": trigger,
        "actions": actions,
        "paths": paths,
        "budget": budget,
        "approvals": sorted(normalized_approvals, key=lambda item: item["action"]),
    }
    if "agent" in request:
        normalized["agent"] = normalize_agent_identity(request.get("agent"), "agent")
    return normalized


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(_canonical(payload) + b"\n")
    os.replace(temporary, path)


def prepare_admission(root: Path, passport_path: Path, request_path: Path, out_dir: Path | None = None) -> dict[str, Any]:
    """Seal one admissible external-run proposal without invoking a harness."""
    workspace = Path(root).resolve()
    passport_path = _inside(workspace, Path(passport_path))
    request_path = _inside(workspace, Path(request_path))
    if not passport_path.is_file() or not request_path.is_file():
        raise AdmissionError("ADMISSION_INPUT_UNREADABLE", "passport and request files must exist")
    try:
        passport_result = verify_loop_passport(passport_path)
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError("ADMISSION_PASSPORT_INVALID", "Loop Passport cannot be verified") from exc
    if not passport_result["valid"]:
        raise AdmissionError("ADMISSION_PASSPORT_INVALID", "Loop Passport does not verify")
    passport = _load(passport_path)
    snapshot = graph_ops_snapshot(workspace)
    if not snapshot.get("complete"):
        raise AdmissionError("ADMISSION_GRAPH_INCOMPLETE", "Graph Ops snapshot is incomplete")
    request = _validate_request(workspace, _load(request_path), passport)
    try:
        license_value = admission_license_decision(workspace, passport, request)
    except AgentLicenseError as exc:
        raise AdmissionError(exc.code, str(exc)) from exc
    target_dir = _inside(workspace, Path(out_dir) if out_dir is not None else workspace / ".factory" / "admissions")
    workspace_sha256 = _fingerprint(workspace)
    core = {
        "schema": ADMISSION_PACKET_SCHEMA,
        "id": request["id"],
        "verdict": "SEALED",
        "markers": ["ADMISSION_PACKET_SEALED", "ADMISSION_EXTERNAL_EFFECTS_DENIED"],
        "workspace": {"fingerprint_sha256": workspace_sha256},
        "graph": {"sha256": snapshot.get("base_graph_sha256", snapshot["graph_sha256"])},
        "passport": {"path": str(passport_path.relative_to(workspace)), "sha256": passport["passport_sha256"]},
        "request": request,
        "request_sha256": _sha(request),
        "authority": dict(_AUTHORITY),
        "scope_limits": [
            "Packet verification is local metadata validation only.",
            "The selected harness must enforce identity, sandboxing, network policy, credentials, and execution.",
        ],
    }
    if license_value is not None:
        core["agent_license"] = {
            "license_sha256": license_value["license_sha256"],
            "tier": license_value["tier"],
            "allowed_paths": license_value["allowed_paths"],
            "expires_at": license_value["expires_at"],
            "identity_provenance": license_value["identity_provenance"],
        }
    packet = {**core, "packet_sha256": _sha(core)}
    path = target_dir / f"{request['id']}.admission.json"
    if path.exists():
        raise AdmissionError("ADMISSION_PACKET_EXISTS", "admission packet already exists")
    _atomic_json(path, packet)
    return {**packet, "path": str(path.resolve())}


def _packet_valid(payload: dict[str, Any]) -> bool:
    if payload.get("schema") != ADMISSION_PACKET_SCHEMA:
        return False
    core = {key: value for key, value in payload.items() if key not in {"packet_sha256", "path"}}
    return payload.get("packet_sha256") == _sha(core)


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "schema": ADMISSION_PACKET_SCHEMA, "verdict": "BLOCKED",
        "marker": "ADMISSION_PACKET_BLOCKED", "reason": reason,
        "authority": dict(_AUTHORITY),
    }


def _bound_passport_path(workspace: Path, packet: dict[str, Any]) -> Path | None:
    passport_ref = packet.get("passport", {}).get("path")
    if not isinstance(passport_ref, str) or not passport_ref:
        return None
    try:
        return _inside(workspace, workspace / passport_ref)
    except AdmissionError:
        return None


def _passport_binding_is_current(path: Path, packet: dict[str, Any]) -> bool:
    try:
        result = verify_loop_passport(path)
    except (OSError, json.JSONDecodeError):
        return False
    return bool(result["valid"] and result.get("passport_sha256") == packet.get("passport", {}).get("sha256"))


def _request_binding_is_current(workspace: Path, packet: dict[str, Any], passport_path: Path) -> str | None:
    try:
        _validate_request(workspace, packet.get("request", {}), _load(passport_path))
    except AdmissionError as exc:
        return exc.code
    return None if _sha(packet.get("request")) == packet.get("request_sha256") else "request_sha256_mismatch"


def verify_admission(root: Path, packet_path: Path) -> dict[str, Any]:
    """Revalidate a packet immediately before an external harness may consume it."""
    workspace = Path(root).resolve()
    packet_path = _inside(workspace, Path(packet_path))
    if not packet_path.is_file():
        return _blocked("packet_unreadable")
    try:
        packet = _load(packet_path)
    except AdmissionError:
        return _blocked("packet_unreadable")
    if not _packet_valid(packet):
        return _blocked("packet_sha256_mismatch")
    passport_path = _bound_passport_path(workspace, packet)
    if passport_path is None or not _passport_binding_is_current(passport_path, packet):
        return _blocked("passport_binding_invalid")
    snapshot = graph_ops_snapshot(workspace)
    graph_sha256 = snapshot.get("base_graph_sha256", snapshot.get("graph_sha256"))
    if not snapshot.get("complete"):
        return _blocked("graph_incomplete")
    current_workspace = _fingerprint(workspace)
    if current_workspace != packet.get("workspace", {}).get("fingerprint_sha256") or graph_sha256 != packet.get("graph", {}).get("sha256"):
        return {"schema": ADMISSION_PACKET_SCHEMA, "verdict": "STALE", "marker": "ADMISSION_STALE", "reason": "workspace_or_graph_changed", "authority": dict(_AUTHORITY)}
    request_error = _request_binding_is_current(workspace, packet, passport_path)
    if request_error:
        return _blocked(request_error)
    return {
        "schema": ADMISSION_PACKET_SCHEMA,
        "verdict": "READY",
        "marker": "ADMISSION_READY",
        "packet_sha256": packet["packet_sha256"],
        "authority": dict(_AUTHORITY),
        "scope_limits": ["A ready packet does not execute the selected harness."],
    }
