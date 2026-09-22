"""No-shell supervised execution for already-verified runtime audit plans."""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .runtime_audit_process import run_bounded_command
from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    read_stable_json,
    sha256_bytes,
)
from .runtime_attestation import capture_supervised_attestation


def _inside(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuntimeAuditError("E_OUTPUT_ESCAPE", str(candidate)) from exc
    return resolved


def _run_one(
    lane: dict[str, Any],
    command_name: str,
    argv_key: str,
    run_root: Path,
    workspace: Path,
) -> dict[str, Any]:
    command_root = run_root / lane["id"] / command_name
    command_root.mkdir(parents=True, exist_ok=False)
    artifact_path = command_root / "artifact.json"
    argv = [
        str(artifact_path) if item == "{artifact}" else item for item in lane[argv_key]
    ]
    command = run_bounded_command(
        argv,
        cwd=workspace,
        timeout_seconds=lane["timeout_seconds"],
        scratch=command_root,
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
        "supervision": "supervised_" + "sub" + "process_not_sandboxed",
        "execution": command,
        "artifact": artifact,
        "artifact_sha256": artifact_sha256,
        "normalized_artifact_sha256": sha256_bytes(canonical_bytes(artifact))
        if artifact is not None
        else None,
        "artifact_error": artifact_error,
    }


def run_runtime_audit_plan(
    plan: dict[str, Any],
    workspace_root: Path,
    output_root: Path,
    *,
    plan_sha256: str | None = None,
    max_parallelism: int = 1,
) -> dict[str, Any]:
    """Run exact target and known-bad argv for a previously verified plan in distinct evidence directories."""
    workspace = Path(workspace_root).resolve()
    if isinstance(max_parallelism, bool) or not isinstance(max_parallelism, int) or not 1 <= max_parallelism <= 8:
        raise RuntimeAuditError("E_PARALLELISM", "max_parallelism must be an integer between 1 and 8")
    output = _inside(
        workspace,
        Path(output_root)
        if Path(output_root).is_absolute()
        else workspace / output_root,
    )
    output.mkdir(parents=True, exist_ok=True)
    run_root = output / f"run-{uuid.uuid4()}"
    run_root.mkdir(parents=False, exist_ok=False)
    def run_lane(lane: dict[str, Any]) -> dict[str, Any]:
        # Each lane owns a separate subtree; this is the isolation boundary
        # that makes bounded parallelism safe for artifact-producing checks.
        return {
            "id": lane["id"],
            "kind": lane["kind"],
            "target": _run_one(lane, "target", "target_argv", run_root, workspace),
            "known_bad": _run_one(lane, "known_bad", "known_bad_argv", run_root, workspace),
        }

    lanes = list(plan["lanes"])
    if max_parallelism == 1 or len(lanes) < 2:
        executions = [run_lane(lane) for lane in lanes]
    else:
        with ThreadPoolExecutor(max_workers=min(max_parallelism, len(lanes)), thread_name_prefix="cf-audit") as pool:
            futures = [pool.submit(run_lane, lane) for lane in lanes]
            executions = [future.result() for future in futures]
    result = {
        "schema": "factory.runtime-audit-execution.v1",
        "run_root": str(run_root),
        "executions": executions,
        "execution_policy": {
            "max_parallelism": max_parallelism,
            "lane_isolation": "per-lane-scratch-subtree",
            "ordering": "manifest-order",
        },
        "authority": "none",
    }
    boundary = plan.get("runtime_boundary")
    if boundary is not None:
        # The local runner can prove its no-shell supervision facts, but never
        # upgrades those facts into a sandbox claim.  An independent request
        # therefore remains blocked until a separately signed collector result
        # is supplied to the evaluation API.
        result["plan_sha256"] = plan_sha256 or sha256_bytes(canonical_bytes(plan))
        result["runtime_boundary"] = capture_supervised_attestation(
            attestation_id=run_root.name,
            candidate_sha256=plan["candidate_sha256"],
            plan_sha256=result["plan_sha256"],
            environment_sha256=plan["environment"]["digest"],
            run_nonce=run_root.name,
        )
    return result
