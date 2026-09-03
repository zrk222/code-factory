"""No-shell supervised execution for already-verified runtime audit plans."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from .runtime_audit_process import run_bounded_command
from .runtime_audit_common import RuntimeAuditError, canonical_bytes, read_stable_json, sha256_bytes


def _inside(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuntimeAuditError("E_OUTPUT_ESCAPE", str(candidate)) from exc
    return resolved


def _run_one(lane: dict[str, Any], command_name: str, argv_key: str, run_root: Path, workspace: Path) -> dict[str, Any]:
    command_root = run_root / lane["id"] / command_name
    command_root.mkdir(parents=True, exist_ok=False)
    artifact_path = command_root / "artifact.json"
    argv = [str(artifact_path) if item == "{artifact}" else item for item in lane[argv_key]]
    command = run_bounded_command(
        argv, cwd=workspace, timeout_seconds=lane["timeout_seconds"], scratch=command_root
    )
    artifact: dict[str, Any] | None = None
    artifact_sha256: str | None = None
    artifact_error: dict[str, str] | None = None
    try:
        artifact, artifact_sha256 = read_stable_json(artifact_path)
    except RuntimeAuditError as exc:
        artifact_error = {"code": exc.code, "message": exc.message}
    return {
        "command": command_name,
        "signed_argv": list(lane[argv_key]),
        "timeout_seconds": lane["timeout_seconds"],
        "supervision": "supervised_subprocess_not_sandboxed",
        "execution": command,
        "artifact": artifact,
        "artifact_sha256": artifact_sha256,
        "normalized_artifact_sha256": sha256_bytes(canonical_bytes(artifact)) if artifact is not None else None,
        "artifact_error": artifact_error,
    }


def run_runtime_audit_plan(plan: dict[str, Any], workspace_root: Path, output_root: Path) -> dict[str, Any]:
    """Run exact target and known-bad argv for a previously verified plan in distinct evidence directories."""
    workspace = Path(workspace_root).resolve()
    output = _inside(workspace, Path(output_root) if Path(output_root).is_absolute() else workspace / output_root)
    output.mkdir(parents=True, exist_ok=True)
    run_root = output / f"run-{uuid.uuid4()}"
    run_root.mkdir(parents=False, exist_ok=False)
    executions = []
    for lane in plan["lanes"]:
        executions.append({
            "id": lane["id"],
            "kind": lane["kind"],
            "target": _run_one(lane, "target", "target_argv", run_root, workspace),
            "known_bad": _run_one(lane, "known_bad", "known_bad_argv", run_root, workspace),
        })
    return {
        "schema": "factory.runtime-audit-execution.v1",
        "run_root": str(run_root),
        "executions": executions,
        "authority": "none",
    }
