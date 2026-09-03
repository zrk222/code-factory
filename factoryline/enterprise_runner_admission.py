"""Proof-carrying runner-admission packets for the enterprise pilot boundary.

This module binds an already-admitted local enterprise decision to one exact
argv digest.  It never runs the argv.  A real PEP integration must ensure its
runner accepts only a current packet and separately prove that topology.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .enterprise_enforcement import EnterpriseEnforcementError, canonical_json, verify_enterprise_decision


INPUT_SCHEMA = "factory.runner-admission-input.v1"
PACKET_SCHEMA = "factory.runner-admission-packet.v1"
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


def prepare_runner_admission(root: Path, input_path: Path, out: Path) -> dict[str, Any]:
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
        "argv": argv, "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
        "authority": {"execution": False, "approval": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False},
        "claim_boundary": "Runner input contract only. This packet did not execute argv, authenticate a workload, prove PEP topology, enforce isolation, or grant external authority.",
    }
    packet["packet_sha256"] = hashlib.sha256(canonical_json(packet)).hexdigest()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_json(packet) + b"\n")
    return {**packet, "path": target.relative_to(workspace).as_posix()}
