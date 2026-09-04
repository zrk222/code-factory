"""Deterministic bindings between public capability claims and local evidence."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path, PureWindowsPath
from typing import Any

from .runtime_audit_process import run_bounded_command

SCHEMA = "factory.capability-evidence-manifest.v1"
MATURITY = frozenset({"locally_verified_core", "controlled_pilot", "reference_pilot", "candidate_bound_preflight"})


class CapabilityEvidenceError(ValueError):
    """A stable refusal for an invalid capability-evidence contract."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _file(root: Path, value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value.strip():
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_PATH", f"{field} must be a relative file path")
    relative = Path(value)
    if relative.is_absolute() or PureWindowsPath(value).drive or ".." in relative.parts:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_PATH", f"{field} must stay inside the workspace")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_PATH", f"{field} escapes the workspace") from exc
    if not path.is_file():
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_MISSING", f"{field} does not name an existing file: {value}")
    with path.open("rb") as stream:
        content = stream.read(10_000_001)
    if len(content) > 10_000_000:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_SIZE", f"{field} exceeds 10000000 bytes")
    if not content:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_HOLLOW", f"{field} is empty: {value}")
    return {"path": relative.as_posix(), "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}


def _argv(value: object, capability_id: str, tests: list[dict[str, Any]]) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(arg, str) and arg for arg in value):
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_COMMAND", f"{capability_id}.verify.argv must be a non-empty string array")
    expected = ["python", "-m", "pytest", "-q", *[item["path"] for item in tests]]
    if any(item["path"].startswith("-") or not item["path"].endswith(".py") for item in tests):
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_COMMAND", "Test paths must be Python files, not pytest options")
    if value != expected:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_COMMAND", f"{capability_id}.verify.argv must run exactly its declared test files through python -m pytest -q")
    return [sys.executable, *value[1:]]


def _claim(workspace: Path, item: object, index: int, seen: set[str]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_SCHEMA", f"capabilities[{index}] must be an object")
    capability_id = item.get("id")
    if not isinstance(capability_id, str) or not capability_id or capability_id in seen:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_ID", f"capabilities[{index}].id must be unique and non-empty")
    seen.add(capability_id)
    if not isinstance(item.get("maturity"), str) or item["maturity"] not in MATURITY:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_MATURITY", f"{capability_id}.maturity is not approved")
    implementation, tests = item.get("implementation"), item.get("tests")
    if not isinstance(implementation, list) or not 1 <= len(implementation) <= 64 or not isinstance(tests, list) or not 1 <= len(tests) <= 64:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_SCHEMA", f"{capability_id} requires implementation and tests")
    files = {"implementation": [_file(workspace, path, f"{capability_id}.implementation") for path in implementation], "tests": [_file(workspace, path, f"{capability_id}.tests") for path in tests]}
    verify = item.get("verify")
    if not isinstance(verify, dict):
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_COMMAND", f"{capability_id}.verify must be an object")
    timeout = verify.get("timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_TIMEOUT", f"{capability_id}.verify.timeout_seconds must be 1..300")
    return {"id": capability_id, "maturity": item["maturity"], **files, "verification_declared": True, "_argv": _argv(verify.get("argv"), capability_id, files["tests"]), "_timeout": timeout}


def _execute(workspace: Path, claim: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="factory-capability-") as scratch:
        observed = run_bounded_command(claim["_argv"], workspace, claim["_timeout"], Path(scratch))
    passed = (
        observed["exit_code"] == 0
        and observed["timed_out"] is False
        and observed["launch_error"] is False
        and observed["output_limit_exceeded"] is False
        and observed["cleanup_confirmed"] is True
    )
    return {"id": claim["id"], "passed": passed, "returncode": observed["exit_code"], "duration_ms": round((time.monotonic() - started) * 1000), **observed}


def _evidence_unchanged(workspace: Path, claim: dict[str, Any]) -> bool:
    try:
        return all(_file(workspace, item["path"], claim["id"])["sha256"] == item["sha256"] for group in ("implementation", "tests") for item in claim[group])
    except (OSError, CapabilityEvidenceError):
        return False


def _manifest(workspace: Path, source: dict[str, Any]) -> dict[str, Any]:
    try:
        data = (workspace / source["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != source["sha256"]:
            raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_CHANGED", "Manifest changed before validation")
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_SCHEMA", "manifest is not valid UTF-8 JSON") from exc
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA or not isinstance(raw.get("capabilities"), list) or not 1 <= len(raw["capabilities"]) <= 64:
        raise CapabilityEvidenceError("E_CAPABILITY_EVIDENCE_SCHEMA", f"manifest must use {SCHEMA} with non-empty capabilities")
    return raw


def _report(source: dict[str, Any], claims: list[dict[str, Any]], executions: list[dict[str, Any]], execute: bool) -> dict[str, Any]:
    passed = bool(execute and executions and all(item["passed"] for item in executions))
    marker = "CAPABILITY_EVIDENCE_VERIFIED" if passed else ("CAPABILITY_EVIDENCE_BLOCKED" if execute else "CAPABILITY_EVIDENCE_BOUND")
    public_claims = [{key: value for key, value in claim.items() if not key.startswith("_")} for claim in claims]
    findings = [{"code": "E_CAPABILITY_EVIDENCE_CHECK_FAILED", "id": item["id"]} for item in executions if not item["passed"]]
    return {"schema": "factory.capability-evidence-audit.v1", "marker": marker, "ok": passed if execute else True, "executed": execute, "execution_count": len(executions), "manifest": source, "claims": public_claims, "executions": executions, "findings": findings, "authority": {"source_change": False, "approval": False, "publication": False, "deployment": False, "credential_access": False}, "claim_boundary": "Structural binding and local test execution are not independent battle-testing, production proof, certification, or customer validation. Execution runs reviewed repository code as the caller, not in a sandbox."}


def audit_capability_evidence(root: Path, manifest_path: Path, *, execute: bool = False) -> dict[str, Any]:
    """Validate claim bindings and optionally run their declared local checks."""
    workspace = Path(root).resolve()
    source = _file(workspace, str(manifest_path), "manifest")
    raw = _manifest(workspace, source)
    seen: set[str] = set()
    claims = [_claim(workspace, item, index, seen) for index, item in enumerate(raw["capabilities"])]
    executions = [_execute(workspace, claim) for claim in claims] if execute else []
    source_unchanged = _file(workspace, source["path"], "manifest")["sha256"] == source["sha256"]
    for claim, execution in zip(claims, executions):
        if not source_unchanged or not _evidence_unchanged(workspace, claim):
            execution.update(passed=False, evidence_changed=True)
    return _report(source, claims, executions, execute)
