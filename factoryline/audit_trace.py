"""Deterministic, source-bound trace chains for read-only audit decisions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any


TRACE_SCHEMA = "factory.audit-trace.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LANE_STATES = frozenset({"PASS", "FAIL", "NOT_RUN", "INCOMPLETE", "UNBOUND"})
_MAX_PATHS = 20
_MAX_STEP_PATHS = 20
_MAX_STEPS = 40
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 20 * 1024 * 1024
_TRACE_INPUT = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRACE_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


class AuditTraceError(ValueError):
    """Raised when trace input cannot be safely and reproducibly bound."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _workspace_path(root: Path, raw: object) -> tuple[str, Path]:
    if not isinstance(raw, str) or not raw or len(raw) > 512:
        raise AuditTraceError(
            "trace source path must be a non-empty path of at most 512 characters"
        )
    normalized = raw.replace("\\", "/")
    relative = PurePosixPath(normalized)
    if (
        normalized != raw
        or relative.as_posix() != normalized
        or normalized.startswith("/")
        or not relative.parts
        or ":" in relative.parts[0]
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise AuditTraceError(
            "trace source path must be normalized and workspace-relative"
        )
    workspace = root.resolve()
    target = (workspace / Path(*relative.parts)).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise AuditTraceError("trace source path escapes the workspace") from exc
    if not target.is_file():
        raise AuditTraceError("trace source path must name an existing regular file")
    size = target.stat().st_size
    if size > _MAX_SOURCE_BYTES:
        raise AuditTraceError("trace source file exceeds the 2 MiB per-file limit")
    return relative.as_posix(), target


def _git_identity(root: Path) -> dict[str, Any]:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuditTraceError(
            "current Git commit and worktree identity are unavailable"
        ) from exc
    if not re.fullmatch(r"[0-9a-f]{40,64}", head):
        raise AuditTraceError("Git HEAD is not a full lowercase commit identifier")
    status_bytes = status.encode("utf-8")
    if len(status_bytes) > 1024 * 1024:
        raise AuditTraceError("Git worktree status exceeds the 1 MiB trace limit")
    return {
        "commit": head,
        "branch": branch or None,
        "dirty": bool(status),
        "worktree_status_sha256": _digest(status_bytes),
    }


def _source_hashes(root: Path, paths: list[object]) -> dict[str, str]:
    if not isinstance(paths, list) or not 1 <= len(paths) <= _MAX_PATHS:
        raise AuditTraceError("changed_paths must contain 1 to 20 entries")
    normalized: list[tuple[str, Path]] = [_workspace_path(root, item) for item in paths]
    names = [name for name, _ in normalized]
    if len(names) != len(set(names)):
        raise AuditTraceError("trace paths must be unique after normalization")
    total = sum(path.stat().st_size for _, path in normalized)
    if total > _MAX_TOTAL_BYTES:
        raise AuditTraceError("total trace source bytes exceed 20 MiB")
    return {name: _digest(path.read_bytes()) for name, path in sorted(normalized)}


def _projection_binding(value: object, *, field: str) -> dict[str, Any]:
    if value is None:
        return {"state": "UNBOUND", "sha256": None}
    if not isinstance(value, dict):
        raise AuditTraceError(f"{field} evidence must be an object or absent")
    supplied = (
        value.get("impact_sha256")
        if field == "graph_impact"
        else value.get("source_sha256")
    )
    if field == "graph_impact":
        core = {key: item for key, item in value.items() if key != "impact_sha256"}
        valid_digest = (
            isinstance(supplied, str)
            and _SHA256.fullmatch(supplied)
            and supplied == _digest(_canonical(core))
        )
        complete = value.get("complete") is True and value.get("source_errors") == []
        state = (
            "BOUND"
            if valid_digest and complete
            else "INCOMPLETE"
            if valid_digest
            else "UNBOUND"
        )
        return {
            "state": state,
            "sha256": supplied if valid_digest and complete else None,
            "observed_sha256": supplied if valid_digest and not complete else None,
            "complete": complete,
            "matched_proof_count": _count(value.get("matched_proofs")),
            "verified_current_proof_count": _count(
                value.get("verified_current_proofs")
            ),
            "rerun_proof_count": _count(value.get("rerun_proofs")),
            "unmatched_changed_paths": _string_paths(
                value.get("unmatched_changed_paths")
            ),
        }
    status = value.get("receipt_status")
    candidate = value.get("candidate_binding")
    matched = (
        status == "MATCHED_UNAUTHENTICATED"
        and candidate in {"CI_SOURCE_HASH_MATCH", "LOCAL_SOURCE_HASH_MATCH"}
        and isinstance(supplied, str)
        and _SHA256.fullmatch(supplied)
    )
    reason = value.get("state")
    if matched:
        receipt_digest = value.get("receipt_sha256")
        if not isinstance(receipt_digest, str) or not _SHA256.fullmatch(receipt_digest):
            return {"state": "UNBOUND", "report_sha256": None, "receipt_sha256": None}
        return {
            "state": "BOUND_UNAUTHENTICATED",
            "report_sha256": supplied,
            "receipt_sha256": receipt_digest,
            "report_time": value.get("report_time"),
            "statements": _metric_summary(value.get("statements")),
            "branches": _metric_summary(value.get("branches")),
            "file_count": value.get("file_count")
            if type(value.get("file_count")) is int
            else None,
        }
    state = reason if reason in {"NOT_RUN", "INCOMPLETE", "FAIL"} else "UNBOUND"
    if reason == "OBSERVED":
        state = "INCOMPLETE"
    return {"state": state, "report_sha256": None, "receipt_sha256": None}


def _count(value: object) -> int | None:
    return len(value) if isinstance(value, list) else None


def _string_paths(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item
        for item in value[:_MAX_PATHS]
        if isinstance(item, str) and len(item) <= 512
    ]


def _metric_summary(value: object) -> dict[str, int] | None:
    fields = ("covered", "total", "missing")
    if not isinstance(value, dict) or any(
        type(value.get(key)) is not int for key in fields
    ):
        return None
    return {key: value[key] for key in fields}


def _steps(
    root: Path, values: object, source_hashes: dict[str, str]
) -> list[dict[str, Any]]:
    if not isinstance(values, list) or not 1 <= len(values) <= _MAX_STEPS:
        raise AuditTraceError(
            "steps must contain 1 to 40 input-to-guard-to-decision records"
        )
    result: list[dict[str, Any]] = []
    previous = "0" * 64
    seen: set[str] = set()
    for value in values:
        core = _step_core(root, value, source_hashes, seen, previous)
        previous = _digest(_canonical(core))
        result.append({**core, "step_sha256": previous})
    return result


def _step_core(
    root: Path,
    value: object,
    source_hashes: dict[str, str],
    seen: set[str],
    previous: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "step_id",
        "input",
        "guard",
        "decision",
        "state",
        "source_paths",
    }:
        raise AuditTraceError(
            "each trace step must have the exact input/guard/decision schema"
        )
    step_id = value["step_id"]
    if (
        not isinstance(step_id, str)
        or not step_id
        or len(step_id) > 80
        or step_id in seen
    ):
        raise AuditTraceError(
            "trace step identifiers must be unique non-empty strings up to 80 characters"
        )
    seen.add(step_id)
    _validate_step_values(value)
    source_names = _step_source_names(root, value["source_paths"], source_hashes)
    return {
        "step_id": step_id,
        "input": value["input"],
        "guard": value["guard"],
        "decision": value["decision"],
        "state": value["state"],
        "sources": {name: source_hashes[name] for name in sorted(source_names)},
        "previous_sha256": previous,
    }


def _validate_step_values(value: dict[str, Any]) -> None:
    if not isinstance(value["input"], str) or not _TRACE_INPUT.fullmatch(
        value["input"]
    ):
        raise AuditTraceError(
            "trace input must be a SHA-256 reference, never raw untrusted content"
        )
    for field in ("guard", "decision"):
        if not isinstance(value[field], str) or not _TRACE_TOKEN.fullmatch(
            value[field]
        ):
            raise AuditTraceError(
                f"trace step {field} must be a stable uppercase identifier"
            )
    state = value["state"]
    if not isinstance(state, str) or state not in _LANE_STATES:
        raise AuditTraceError("trace step state is outside the closed state vocabulary")


def _step_source_names(
    root: Path, paths: object, source_hashes: dict[str, str]
) -> list[str]:
    if not isinstance(paths, list) or not 1 <= len(paths) <= _MAX_STEP_PATHS:
        raise AuditTraceError("each trace step needs 1 to 10 source paths")
    names = [_workspace_path(root, raw)[0] for raw in paths]
    if any(name not in source_hashes for name in names):
        raise AuditTraceError(
            "every step source path must also be a bound changed path"
        )
    if len(names) != len(set(names)):
        raise AuditTraceError("trace step source paths must be unique")
    return names


def _normalized_lanes(lane_states: object) -> dict[str, str]:
    if not isinstance(lane_states, dict) or not lane_states or len(lane_states) > 40:
        raise AuditTraceError("lane_states must contain 1 to 40 named lane states")
    normalized_lanes = {}
    for lane, state in lane_states.items():
        if not isinstance(lane, str) or not re.fullmatch(
            r"[a-z][a-z0-9_-]{0,63}", lane
        ):
            raise AuditTraceError("lane names must be normalized lowercase identifiers")
        if not isinstance(state, str) or state not in _LANE_STATES:
            raise AuditTraceError("lane state is outside the closed state vocabulary")
        normalized_lanes[lane] = state
    return normalized_lanes


def _projections(
    workspace: Path, source_hashes: dict[str, str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        from .graph_ops import graph_ops_impact

        graph_projection = graph_ops_impact(workspace, list(source_hashes))
    except (OSError, TypeError, ValueError, RecursionError):
        graph_projection = None
    from .runtime_coverage import read_runtime_coverage_report

    runtime_projection = read_runtime_coverage_report(workspace)
    return (
        _projection_binding(graph_projection, field="graph_impact"),
        _projection_binding(runtime_projection, field="runtime_coverage"),
    )


def _projected_lanes(
    lanes: dict[str, str],
    graph_binding: dict[str, Any],
    runtime_binding: dict[str, Any],
) -> dict[str, str]:
    normalized = dict(lanes)
    graph_state = graph_binding["state"]
    normalized["graph_impact"] = (
        "PASS"
        if graph_state == "BOUND"
        else "UNBOUND"
        if graph_state == "UNBOUND"
        else "INCOMPLETE"
    )
    runtime_state = runtime_binding["state"]
    normalized["runtime_coverage"] = (
        "INCOMPLETE"
        if runtime_state == "BOUND_UNAUTHENTICATED"
        else runtime_state
        if runtime_state in _LANE_STATES
        else "INCOMPLETE"
    )
    return normalized


def _trace_body(
    candidate: dict[str, Any],
    source_hashes: dict[str, str],
    graph_binding: dict[str, Any],
    runtime_binding: dict[str, Any],
    lanes: dict[str, str],
    chain: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": TRACE_SCHEMA,
        "marker": "FACTORYLINE_AUDIT_TRACE_V1",
        "candidate": candidate,
        "changed_files": source_hashes,
        "graph_impact": graph_binding,
        "runtime_coverage": runtime_binding,
        "lanes": dict(sorted(lanes.items())),
        "steps": chain,
        "chain_head": chain[-1]["step_sha256"],
        "authority": {
            "execution": False,
            "approval": False,
            "merge": False,
            "publication": False,
            "deployment": False,
            "signing": False,
            "credential": False,
            "network": False,
        },
        "authentication": "UNSIGNED_INTEGRITY_ONLY",
    }


def build_audit_trace(
    root: Path,
    *,
    changed_paths: list[str],
    steps: list[dict[str, Any]],
    lane_states: dict[str, str],
) -> dict[str, Any]:
    """Create a deterministic trace binding source, evidence, lane states and guard decisions."""
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise AuditTraceError("workspace root must be an existing directory")
    lanes = _normalized_lanes(lane_states)
    source_hashes = _source_hashes(workspace, changed_paths)
    chain = _steps(workspace, steps, source_hashes)
    graph_binding, runtime_binding = _projections(workspace, source_hashes)
    lanes = _projected_lanes(lanes, graph_binding, runtime_binding)
    core = _trace_body(
        _git_identity(workspace),
        source_hashes,
        graph_binding,
        runtime_binding,
        lanes,
        chain,
    )
    trace_id = f"audit:{_digest(_canonical(core))}"
    return {
        **core,
        "trace_id": trace_id,
        "trace_sha256": _digest(_canonical({**core, "trace_id": trace_id})),
    }


def _candidate_errors(candidate: object) -> list[str]:
    if (
        not isinstance(candidate, dict)
        or set(candidate) != {"commit", "branch", "dirty", "worktree_status_sha256"}
        or not isinstance(candidate.get("commit"), str)
        or not re.fullmatch(r"[0-9a-f]{40,64}", candidate.get("commit", ""))
        or (
            candidate.get("branch") is not None
            and not isinstance(candidate.get("branch"), str)
        )
        or type(candidate.get("dirty")) is not bool
        or not isinstance(candidate.get("worktree_status_sha256"), str)
        or not _SHA256.fullmatch(candidate.get("worktree_status_sha256", ""))
    ):
        return ["candidate identity has an invalid commit, branch, or worktree binding"]
    return []


def _source_hash_errors(source_hashes: object) -> tuple[list[str], dict[str, str]]:
    valid = (
        isinstance(source_hashes, dict)
        and 1 <= len(source_hashes) <= _MAX_PATHS
        and all(
            isinstance(path, str)
            and len(path) <= 512
            and not PurePosixPath(path).is_absolute()
            and ".." not in PurePosixPath(path).parts
            and PurePosixPath(path).as_posix() == path
            and isinstance(digest, str)
            and _SHA256.fullmatch(digest)
            for path, digest in source_hashes.items()
        )
    )
    return (
        ([], source_hashes)
        if valid
        else (["changed-file paths or hashes are invalid"], {})
    )


def _lane_errors(lanes: object) -> list[str]:
    valid = (
        isinstance(lanes, dict)
        and 1 <= len(lanes) <= 40
        and all(
            isinstance(name, str)
            and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name)
            and isinstance(state, str)
            and state in _LANE_STATES
            for name, state in lanes.items()
        )
    )
    return [] if valid else ["lane names or states are invalid"]


def _projection_errors(core: dict[str, Any]) -> list[str]:
    errors = []
    graph = core.get("graph_impact")
    if not isinstance(graph, dict) or graph.get("state") not in {
        "BOUND",
        "INCOMPLETE",
        "UNBOUND",
    }:
        errors.append("graph impact state is invalid")
    elif graph.get("state") == "BOUND" and not _valid_digest(graph.get("sha256")):
        errors.append("bound graph impact lacks a valid digest")
    runtime = core.get("runtime_coverage")
    runtime_states = {
        "BOUND_UNAUTHENTICATED",
        "NOT_RUN",
        "INCOMPLETE",
        "FAIL",
        "UNBOUND",
    }
    if not isinstance(runtime, dict) or runtime.get("state") not in runtime_states:
        errors.append("runtime coverage state is invalid")
    elif runtime.get("state") == "BOUND_UNAUTHENTICATED" and not all(
        _valid_digest(runtime.get(key)) for key in ("report_sha256", "receipt_sha256")
    ):
        errors.append("bound runtime coverage lacks a report or receipt digest")
    return errors


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _verify_step_chain(
    steps: object, source_hashes: dict[str, str]
) -> tuple[list[str], str]:
    if not isinstance(steps, list) or not 1 <= len(steps) <= _MAX_STEPS:
        return ["trace step count is outside the supported range"], "0" * 64
    previous = "0" * 64
    seen: set[str] = set()
    for step in steps:
        error = _step_chain_error(step, source_hashes, seen, previous)
        if error:
            return [error], previous
        previous = step["step_sha256"]
    return [], previous


def _step_chain_error(
    step: object, source_hashes: dict[str, str], seen: set[str], previous: str
) -> str | None:
    fields = {
        "step_id",
        "input",
        "guard",
        "decision",
        "state",
        "sources",
        "previous_sha256",
        "step_sha256",
    }
    if not isinstance(step, dict):
        return "trace step is not an object"
    if set(step) != fields:
        return "trace step has missing or unknown fields"
    if not _valid_step_fields(step, source_hashes, seen):
        return "trace step fields or changed-file source bindings are invalid"
    step_core = {key: item for key, item in step.items() if key != "step_sha256"}
    if step.get("previous_sha256") != previous or step.get("step_sha256") != _digest(
        _canonical(step_core)
    ):
        return "trace step hash chain is invalid"
    return None


def _valid_step_fields(
    step: dict[str, Any], source_hashes: dict[str, str], seen: set[str]
) -> bool:
    step_id, sources = step.get("step_id"), step.get("sources")
    valid_id = (
        isinstance(step_id, str)
        and bool(step_id)
        and len(step_id) <= 80
        and step_id not in seen
    )
    valid_tokens = (
        isinstance(step.get("input"), str)
        and bool(_TRACE_INPUT.fullmatch(step.get("input", "")))
        and all(
            isinstance(step.get(key), str)
            and bool(_TRACE_TOKEN.fullmatch(step.get(key, "")))
            for key in ("guard", "decision")
        )
    )
    valid_state = (
        isinstance(step.get("state"), str) and step.get("state") in _LANE_STATES
    )
    valid_sources = (
        isinstance(sources, dict)
        and 1 <= len(sources) <= _MAX_STEP_PATHS
        and all(source_hashes.get(path) == digest for path, digest in sources.items())
    )
    if valid_id:
        seen.add(step_id)
    return valid_id and valid_tokens and valid_state and valid_sources


def _envelope_errors(value: dict[str, Any], core: dict[str, Any]) -> list[str]:
    errors = []
    expected_id = f"audit:{_digest(_canonical(core))}"
    if value.get("trace_id") != expected_id:
        errors.append("trace identifier does not bind the trace body")
    expected_hash = _digest(_canonical({**core, "trace_id": expected_id}))
    if value.get("trace_sha256") != expected_hash:
        errors.append("trace envelope digest does not match")
    if not isinstance(value.get("trace_id"), str) or not re.fullmatch(
        r"audit:[0-9a-f]{64}", value.get("trace_id", "")
    ):
        errors.append("trace identifier has an invalid format")
    if not _valid_digest(value.get("trace_sha256")):
        errors.append("trace envelope digest has an invalid format")
    return errors


def _authority_errors(core: dict[str, Any]) -> list[str]:
    authority = {
        "execution": False,
        "approval": False,
        "merge": False,
        "publication": False,
        "deployment": False,
        "signing": False,
        "credential": False,
        "network": False,
    }
    errors = []
    if core.get("authority") != authority:
        errors.append("trace authority boundary is missing or was changed")
    if core.get("authentication") != "UNSIGNED_INTEGRITY_ONLY":
        errors.append("trace must state that integrity is unsigned and unauthenticated")
    return errors


def verify_audit_trace(value: object) -> dict[str, Any]:
    """Check trace shape, source digest chain and trace identifier integrity."""
    if not isinstance(value, dict) or value.get("schema") != TRACE_SCHEMA:
        return {"valid": False, "errors": ["unsupported or missing audit trace schema"]}
    errors: list[str] = []
    try:
        core = {
            key: item
            for key, item in value.items()
            if key not in {"trace_id", "trace_sha256"}
        }
        if set(core) != {
            "schema",
            "marker",
            "candidate",
            "changed_files",
            "graph_impact",
            "runtime_coverage",
            "lanes",
            "steps",
            "chain_head",
            "authority",
            "authentication",
        }:
            errors.append("trace body has missing or unknown top-level fields")
        if core.get("marker") != "FACTORYLINE_AUDIT_TRACE_V1":
            errors.append("trace marker is missing or unsupported")
        errors.extend(_candidate_errors(core.get("candidate")))
        source_errors, source_hashes = _source_hash_errors(core.get("changed_files"))
        errors.extend(source_errors)
        errors.extend(_lane_errors(core.get("lanes")))
        errors.extend(_projection_errors(core))
        step_errors, previous = _verify_step_chain(core.get("steps"), source_hashes)
        errors.extend(step_errors)
        if core.get("chain_head") != previous:
            errors.append("trace chain head does not match the final step")
        errors.extend(_envelope_errors(value, core))
        errors.extend(_authority_errors(core))
    except (TypeError, ValueError, RecursionError):
        errors.append("trace contains values that cannot be canonically encoded")
    return {"valid": not errors, "errors": errors}
