"""No-shell supervised execution for already-verified runtime audit plans."""

from __future__ import annotations

import re
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
from .runtime_audit_contract import _hash_regular_file_bounded, _relative_file


def _inside(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuntimeAuditError("E_OUTPUT_ESCAPE", str(candidate)) from exc
    return resolved


def _verify_admission_sources(plan: dict[str, Any], workspace: Path) -> str:
    sources = plan.get("sources")
    if not isinstance(sources, list):
        raise RuntimeAuditError(
            "E_PARALLELISM_POLICY", "verified source manifest is missing"
        )
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise RuntimeAuditError(
                "E_PARALLELISM_POLICY", "verified source binding is invalid"
            )
        try:
            path = _relative_file(workspace, source["path"], "sources.path")
            actual_hash, actual_bytes = _hash_regular_file_bounded(
                path, source.get("bytes", -1)
            )
        except OSError as exc:
            raise RuntimeAuditError(
                "E_PARALLELISM_POLICY", "verified source changed before launch"
            ) from exc
        if actual_bytes != source.get("bytes") or actual_hash != source.get("sha256"):
            raise RuntimeAuditError(
                "E_PARALLELISM_POLICY", "verified source changed before launch"
            )
    return sha256_bytes(
        canonical_bytes(sorted(sources, key=lambda item: item.get("path", "")))
    )


def _check_parallel_admission(plan, workspace, requested, plan_sha256, admission):
    """Check stale-input integrity after public signature verification."""
    policy = plan.get("execution_policy")
    if requested == 1:
        return policy if isinstance(policy, dict) else None
    if not isinstance(policy, dict) or not isinstance(admission, dict):
        raise RuntimeAuditError(
            "E_PARALLELISM_POLICY",
            "parallel execution requires verified signed-plan admission",
        )
    actual_plan = sha256_bytes(canonical_bytes(plan))
    actual_sources = _verify_admission_sources(plan, workspace)
    environment = plan.get("environment")
    actual_environment = (
        environment.get("digest") if isinstance(environment, dict) else None
    )
    matches = (
        admission.get("payload_sha256") == plan_sha256
        and admission.get("plan_canonical_sha256") == actual_plan
        and admission.get("source_manifest_sha256") == actual_sources
        and admission.get("environment_sha256") == actual_environment
        and admission.get("max_parallelism") == policy.get("max_parallelism")
        and admission.get("non_mutating") is policy.get("non_mutating")
        and admission.get("resource_safe") is policy.get("resource_safe")
    )
    maximum = policy.get("max_parallelism")
    if (
        not matches
        or policy.get("non_mutating") is not True
        or policy.get("resource_safe") is not True
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or requested > maximum
    ):
        raise RuntimeAuditError(
            "E_PARALLELISM_POLICY",
            "parallel admission is stale or exceeds signed policy",
        )
    return policy


def _require_parallelism(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 8:
        raise RuntimeAuditError(
            "E_PARALLELISM", "max_parallelism must be an integer between 1 and 8"
        )
    return value


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
        # Path-aware reader messages can disclose absolute workspace paths.
        code = (
            exc.code
            if re.fullmatch(r"[A-Z0-9_]{1,64}", exc.code)
            else "E_ARTIFACT_INVALID"
        )
        artifact_error = {"code": code}
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


def _run_one_guarded(
    lane: dict[str, Any],
    command_name: str,
    argv_key: str,
    run_root: Path,
    workspace: Path,
) -> dict[str, Any]:
    """Preserve an explicit incomplete leg instead of aborting sibling lanes."""
    try:
        return _run_one(lane, command_name, argv_key, run_root, workspace)
    except RuntimeAuditError as exc:
        code = exc.code
    except OSError:
        code = "RUNTIME_AUDIT_IO_ERROR"
    except Exception:
        # Do not leak exception text: it may contain absolute paths or secrets.
        code = "RUNTIME_AUDIT_LANE_ERROR"
    return {
        "command": command_name,
        "signed_argv": list(lane[argv_key]),
        "timeout_seconds": lane["timeout_seconds"],
        "supervision": "supervised_subprocess_not_sandboxed",
        "execution": {
            "exit_code": None,
            "timed_out": False,
            "launch_error": True,
            "output_limit_exceeded": False,
            "cleanup_confirmed": False,
        },
        "artifact": None,
        "artifact_sha256": None,
        "normalized_artifact_sha256": None,
        "artifact_error": {
            "code": (
                code
                if re.fullmatch(r"[A-Z0-9_]{1,64}", code)
                else "RUNTIME_AUDIT_LANE_ERROR"
            ),
        },
    }


def run_runtime_audit_plan(
    plan: dict[str, Any],
    workspace_root: Path,
    output_root: Path,
    *,
    plan_sha256: str | None = None,
    max_parallelism: int = 1,
    execution_admission: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run exact target and known-bad argv for a previously verified plan in distinct evidence directories."""
    workspace = Path(workspace_root).resolve()
    max_parallelism = _require_parallelism(max_parallelism)
    policy = _check_parallel_admission(
        plan, workspace, max_parallelism, plan_sha256, execution_admission
    )
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
        # Scratch paths avoid artifact collisions; the signed execution policy,
        # not these directories, declares whether shared-workspace execution is safe.
        return {
            "id": lane["id"],
            "kind": lane["kind"],
            "target": _run_one_guarded(
                lane, "target", "target_argv", run_root, workspace
            ),
            "known_bad": _run_one_guarded(
                lane, "known_bad", "known_bad_argv", run_root, workspace
            ),
        }

    lanes = list(plan["lanes"])
    if max_parallelism == 1 or len(lanes) < 2:
        executions = [run_lane(lane) for lane in lanes]
    else:
        with ThreadPoolExecutor(
            max_workers=min(max_parallelism, len(lanes)), thread_name_prefix="cf-audit"
        ) as pool:
            futures = [pool.submit(run_lane, lane) for lane in lanes]
            executions = [future.result() for future in futures]
    result = {
        "schema": "factory.runtime-audit-execution.v1",
        "run_root": run_root.relative_to(workspace).as_posix(),
        "executions": executions,
        "execution_policy": {
            "max_parallelism": max_parallelism,
            "signed_policy": policy
            or {"max_parallelism": 1, "non_mutating": False, "resource_safe": False},
            "lane_isolation": "per-lane-scratch-subtree",
            "ordering": "manifest-order",
            "partial_lane_failure_policy": "record-incomplete-leg-and-preserve-sibling-evidence",
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
