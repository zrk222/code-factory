"""Observed, receipt-governed execution for arbitrary local agent CLIs.

This module is deliberately not a sandbox.  It verifies a sealed admission
immediately before launch, observes workspace deltas, runs explicit validators,
and records bounded hashes and exit facts.  Host identity, credentials, network
egress, and process containment remain responsibilities of the selected harness.
"""
from __future__ import annotations

from base64 import b64decode
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from .agent_license import AGENT_RUN_SCHEMA, normalize_agent_identity, record_bound_governed_event
from .attribution import FailureClass
from .e2e_proof import _run_command
from .run_admission import verify_admission


SESSION_RECEIPT_SCHEMA = "factory.observed-session.v1"
VALIDATOR_MANIFEST_SCHEMA = "factory.session-recorder.validators.v1"
VALIDATION_RECEIPT_SCHEMA = "factory.session-recorder.validation.v1"
RESULT_RECEIPT_SCHEMA = "factory.session-recorder.result.v1"
_SKIP = {".git", "__pycache__", "node_modules", ".venv", "venv"}
_ID = re.compile(r"^[a-z][a-z0-9-]{0,95}$")
_AUTHORITY = {
    "execution": True, "observation": True, "validation": True,
    "sandboxing": False, "network_enforcement": False, "identity_proof": False,
    "approval": False, "repair": False, "merge": False, "publication": False,
    "deployment": False, "signing": False, "messaging": False, "credential": False,
}


class SessionRecorderError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative(root: Path, path: Path, field: str) -> tuple[Path, str]:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise SessionRecorderError("SESSION_PATH_OUT_OF_SCOPE", f"{field} must stay inside the workspace") from exc
    return resolved, relative


def _load_json(root: Path, path: Path, field: str) -> tuple[dict[str, Any], Path, str]:
    resolved, relative = _relative(root, path, field)
    try:
        value = json.loads(resolved.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionRecorderError("SESSION_INPUT_UNREADABLE", f"cannot read {field}: {relative}") from exc
    if not isinstance(value, dict):
        raise SessionRecorderError("SESSION_INPUT_INVALID", f"{field} must be a JSON object")
    return value, resolved, relative


def _snapshot(root: Path) -> dict[str, str]:
    records: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _SKIP.intersection(path.relative_to(root).parts):
            continue
        records[path.relative_to(root).as_posix()] = _file_sha(path)
        if len(records) > 10_000:
            raise SessionRecorderError("SESSION_WORKSPACE_TOO_LARGE", "workspace observation exceeds 10000 files")
    return records


def _changed(before: dict[str, str], after: dict[str, str]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for path in sorted(set(before) | set(after)):
        if before.get(path) == after.get(path):
            continue
        status = "created" if path not in before else "deleted" if path not in after else "modified"
        item = {"path": path, "status": status}
        if path in before:
            item["before_sha256"] = before[path]
        if path in after:
            item["after_sha256"] = after[path]
        changes.append(item)
    return changes


def _argv(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise SessionRecorderError("SESSION_INPUT_INVALID", f"{field} must contain 1 through 64 argv items")
    if any(not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096 for item in value):
        raise SessionRecorderError("SESSION_INPUT_INVALID", f"{field} contains an invalid argv item")
    return list(value)


def _validators(root: Path, path: Path) -> tuple[str, list[dict[str, Any]], str, str]:
    value, resolved, relative = _load_json(root, path, "validator manifest")
    if set(value) != {"schema", "verifier_subject", "validators"} or value.get("schema") != VALIDATOR_MANIFEST_SCHEMA:
        raise SessionRecorderError("SESSION_VALIDATORS_INVALID", f"validator manifest must use {VALIDATOR_MANIFEST_SCHEMA}")
    subject = value.get("verifier_subject")
    entries = value.get("validators")
    if not isinstance(subject, str) or not subject.strip() or not isinstance(entries, list) or not entries or len(entries) > 32:
        raise SessionRecorderError("SESSION_VALIDATORS_INVALID", "verifier_subject and 1 through 32 validators are required")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"id", "argv", "timeout_seconds"}:
            raise SessionRecorderError("SESSION_VALIDATORS_INVALID", "each validator requires id, argv, and timeout_seconds")
        validator_id, timeout = item.get("id"), item.get("timeout_seconds")
        if not isinstance(validator_id, str) or not _ID.fullmatch(validator_id) or validator_id in seen:
            raise SessionRecorderError("SESSION_VALIDATORS_INVALID", "validator ids must be unique lowercase identifiers")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
            raise SessionRecorderError("SESSION_VALIDATORS_INVALID", "validator timeout_seconds must be 1 through 900")
        seen.add(validator_id)
        normalized.append({"id": validator_id, "argv": _argv(item.get("argv"), "validator.argv"), "timeout_seconds": timeout})
    return subject.strip(), normalized, relative, _file_sha(resolved)


def _run(argv: list[str], root: Path, timeout: int) -> dict[str, Any]:
    result, captures = _run_command(argv, cwd=root, timeout_seconds=timeout)
    return {
        "argv_sha256": _sha(argv), "argv_count": len(argv), "status": result["status"], "exit_code": result["exit_code"],
        "duration_ms": result["duration_ms"],
        "stdout_sha256": result["stdout_sha256"], "stdout_bytes": len(b64decode(captures["stdout"])),
        "stderr_sha256": result["stderr_sha256"], "stderr_bytes": len(b64decode(captures["stderr"])),
    }


def _inside_scope(path: str, scopes: list[str]) -> bool:
    return any(scope == "." or path == scope or path.startswith(scope.rstrip("/") + "/") for scope in scopes)


def _write(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _canonical(payload) + b"\n"
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)
    return path


def _previous_session(root: Path) -> str | None:
    latest: tuple[str, str, str] | None = None
    for candidate in (root / ".factory" / "session-recorder").glob("*/session.json"):
        try:
            value = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        recorded_at, run_id, digest = value.get("recorded_at"), value.get("run_id"), value.get("session_sha256")
        if not all(isinstance(item, str) for item in (recorded_at, run_id, digest)) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            continue
        candidate_key = (recorded_at, run_id, digest)
        if latest is None or candidate_key[:2] > latest[:2]:
            latest = candidate_key
    return latest[2] if latest else None


def _admission_context(workspace: Path, admission_path: Path, validator_manifest_path: Path) -> dict[str, Any]:
    admission, admission_file, admission_relative = _load_json(workspace, admission_path, "admission")
    ready = verify_admission(workspace, admission_file)
    if ready.get("verdict") != "READY":
        raise SessionRecorderError("SESSION_ADMISSION_NOT_READY", f"admission must verify READY: {ready.get('reason', ready.get('verdict'))}")
    request = admission.get("request")
    if not isinstance(request, dict) or "agent" not in request:
        raise SessionRecorderError("SESSION_AGENT_REQUIRED", "admission request must declare an agent identity")
    agent = normalize_agent_identity(request["agent"], "admission.request.agent")
    verifier, validators, manifest, manifest_sha256 = _validators(workspace, validator_manifest_path)
    if verifier == agent["subject"]:
        raise SessionRecorderError("SESSION_VERIFIER_NOT_INDEPENDENT", "verifier_subject must differ from the admitted agent")
    scopes, budget = request.get("paths"), request.get("budget")
    if not isinstance(scopes, list) or not all(isinstance(item, str) for item in scopes):
        raise SessionRecorderError("SESSION_ADMISSION_INVALID", "admission request paths are invalid")
    timeout = budget.get("max_wall_seconds") if isinstance(budget, dict) else None
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 3600:
        raise SessionRecorderError("SESSION_BUDGET_INVALID", "admission budget must provide max_wall_seconds from 1 through 3600")
    return {"admission_relative": admission_relative, "ready": ready, "request": request, "agent": agent, "verifier": verifier, "validators": validators, "manifest": manifest, "manifest_sha256": manifest_sha256, "scopes": scopes, "timeout": int(timeout)}


def _failure_classes(agent_result: dict[str, Any], validator_results: list[dict[str, Any]], scope_escapes: list[str], manifest_drifted: bool) -> list[str]:
    failures: set[str] = set()
    if agent_result["status"] == "timed_out":
        failures.add(FailureClass.RUNTIME_TIMEOUT.value)
    elif agent_result["status"] != "completed" or agent_result["exit_code"] != 0:
        failures.add(FailureClass.RUNTIME_CRASH.value)
    if scope_escapes:
        failures.add(FailureClass.SCOPE_ESCAPE.value)
    if any(result["status"] == "timed_out" for result in validator_results):
        failures.add(FailureClass.RUNTIME_TIMEOUT.value)
    if any(result["status"] != "completed" or result["exit_code"] != 0 for result in validator_results):
        failures.add(FailureClass.WRONG_OUTPUT.value)
    if manifest_drifted:
        failures.add(FailureClass.HOLLOW_VALIDATOR.value)
    return sorted(failures)


def _execute_observed(workspace: Path, argv: list[str], context: dict[str, Any]) -> dict[str, Any]:
    before = _snapshot(workspace)
    agent_result = _run(argv, workspace, context["timeout"])
    changes = _changed(before, _snapshot(workspace))
    scope_escapes = [item["path"] for item in changes if not _inside_scope(item["path"], context["scopes"])]
    validator_results = [{"id": item["id"], **_run(item["argv"], workspace, item["timeout_seconds"])} for item in context["validators"]]
    manifest_drifted = _file_sha((workspace / context["manifest"]).resolve()) != context["manifest_sha256"]
    return {"agent_result": agent_result, "changes": changes, "scope_escapes": scope_escapes, "validator_results": validator_results, "manifest_drifted": manifest_drifted, "failures": _failure_classes(agent_result, validator_results, scope_escapes, manifest_drifted)}


def _write_evidence_receipts(workspace: Path, run_id: str, context: dict[str, Any], observed: dict[str, Any]) -> tuple[Path, Path]:
    output_dir = workspace / ".factory" / "session-recorder" / run_id
    result_core = {
        "schema": RESULT_RECEIPT_SCHEMA, "marker": "NO_RAW_CONTENT_RETAINED", "run_id": run_id,
        "admission": {"path": context["admission_relative"], "packet_sha256": context["ready"]["packet_sha256"], "pre_run_verdict": "READY"},
        "agent_command": observed["agent_result"], "workspace_delta": observed["changes"], "scope_escapes": observed["scope_escapes"],
        "authority": dict(_AUTHORITY),
        "scope_limits": ["Observed execution is not sandboxed execution.", "No raw command output, prompt text, credentials, or environment values are retained."],
    }
    result_path = _write(output_dir / "result.json", {**result_core, "result_sha256": _sha(result_core)})
    verification_core = {
        "schema": VALIDATION_RECEIPT_SCHEMA, "run_id": run_id, "verifier_subject": context["verifier"],
        "manifest": {"path": context["manifest"], "sha256": context["manifest_sha256"], "drifted": observed["manifest_drifted"]},
        "validators": observed["validator_results"], "passed": not observed["failures"], "failure_classes": observed["failures"],
        "authority": dict(_AUTHORITY),
    }
    verification_path = _write(output_dir / "verification.json", {**verification_core, "verification_sha256": _sha(verification_core)})
    return result_path, verification_path


def _event_task_id(request: dict[str, Any]) -> str | None:
    value = request.get("id")
    return value if isinstance(value, str) and _ID.fullmatch(value) else None


def _record_session(workspace: Path, run_id: str, context: dict[str, Any], observed: dict[str, Any], result_path: Path, verification_path: Path) -> dict[str, Any]:
    recorded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    event_core = {
        "schema": AGENT_RUN_SCHEMA, "event_id": run_id, "recorded_at": recorded_at,
        "agent": context["agent"], "task_id": _event_task_id(context["request"]),
        "admission": {"path": context["admission_relative"], "packet_sha256": context["ready"]["packet_sha256"]},
        "result_receipt": {"path": result_path.relative_to(workspace).as_posix(), "sha256": _file_sha(result_path)},
        "verification": {"subject": context["verifier"], "receipt": {"path": verification_path.relative_to(workspace).as_posix(), "sha256": _file_sha(verification_path)}},
        "passed": not observed["failures"], "failure_classes": observed["failures"], "paths": context["scopes"],
    }
    ledger = record_bound_governed_event(workspace, {**event_core, "event_sha256": _sha(event_core)})
    session_core = {
        "schema": SESSION_RECEIPT_SCHEMA, "marker": "OBSERVED_SESSION_RECORDED", "run_id": run_id,
        "recorded_at": recorded_at, "previous_session_sha256": _previous_session(workspace),
        "result": {"path": result_path.relative_to(workspace).as_posix(), "sha256": _file_sha(result_path)},
        "verification": {"path": verification_path.relative_to(workspace).as_posix(), "sha256": _file_sha(verification_path)},
        "agent_event": {"path": Path(ledger["path"]).relative_to(workspace).as_posix(), "sha256": ledger["event"]["event_sha256"]},
        "passed": not observed["failures"], "failure_classes": observed["failures"], "authority": dict(_AUTHORITY),
        "scope_limits": ["Observed execution is not sandboxed execution.", "The host must enforce process, network, credential, identity, and filesystem isolation."],
    }
    session = {**session_core, "session_sha256": _sha(session_core)}
    session_path = _write(workspace / ".factory" / "session-recorder" / run_id / "session.json", session)
    return {"session": session, "path": str(session_path), "ledger": ledger}


def run_observed_session(root: Path, admission_path: Path, validator_manifest_path: Path, command: list[str], run_id: str) -> dict[str, Any]:
    """Run an admitted command, observe its delta, validate, and record evidence."""
    workspace = Path(root).resolve()
    if not workspace.is_dir() or not _ID.fullmatch(run_id):
        raise SessionRecorderError("SESSION_INPUT_INVALID", "root and lowercase run_id are required")
    argv = _argv(command, "command")
    output_dir = workspace / ".factory" / "session-recorder" / run_id
    ledger_path = workspace / ".factory" / "agent-licenses" / "events" / f"{run_id}.json"
    if output_dir.exists() or ledger_path.exists():
        raise SessionRecorderError("SESSION_RUN_EXISTS", "the admitted run id has already been consumed")
    context = _admission_context(workspace, admission_path, validator_manifest_path)
    if context["request"].get("id") != run_id:
        raise SessionRecorderError("SESSION_RUN_ID_MISMATCH", "run_id must exactly match the admitted request id")
    observed = _execute_observed(workspace, argv, context)
    result_path, verification_path = _write_evidence_receipts(workspace, run_id, context, observed)
    return _record_session(workspace, run_id, context, observed, result_path, verification_path)


def verify_session_receipt(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify the receipt digest and its bound result and validation files."""
    workspace = Path(root).resolve()
    value, _path, relative = _load_json(workspace, receipt_path, "session receipt")
    digest = value.get("session_sha256")
    core = {key: item for key, item in value.items() if key != "session_sha256"}
    if value.get("schema") != SESSION_RECEIPT_SCHEMA or digest != _sha(core):
        return {"schema": SESSION_RECEIPT_SCHEMA, "marker": "OBSERVED_SESSION_INVALID", "ok": False, "path": relative}
    for name in ("result", "verification"):
        binding = value.get(name)
        if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
            return {"schema": SESSION_RECEIPT_SCHEMA, "marker": "OBSERVED_SESSION_INVALID", "ok": False, "path": relative}
        bound, _ = _relative(workspace, workspace / binding["path"], name)
        if not bound.is_file() or _file_sha(bound) != binding["sha256"]:
            return {"schema": SESSION_RECEIPT_SCHEMA, "marker": "OBSERVED_SESSION_STALE", "ok": False, "path": relative, "reason": name}
    return {"schema": SESSION_RECEIPT_SCHEMA, "marker": "OBSERVED_SESSION_VERIFIED", "ok": True, "path": relative, "session_sha256": digest, "passed": value.get("passed")}
