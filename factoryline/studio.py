"""Loopback-only local browser surface for the Factoryline target compiler."""

from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import socket
import stat
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import monotonic
from typing import Any, Callable

from .capability_packs import builtin_packs, validate_pack
from .continuation import ContinuationError, continue_assembly, discover_features
from .deep_audit_loop import read_junit_report
from .developer_memory import developer_memory_brief
from .failure_guidance import explain_failure
from .graph_authorization import (
    GraphAuthorizationError,
    create_graph_authorization,
    run_authorized_reality_check,
)
from .graph_ops import graph_ops_html, graph_ops_snapshot
from .live_activity import activity_snapshot, request_stop
from .meter import MeterLog, live_snapshot
from .product_missions import (
    ProductMissionError,
    compile_product_text,
    create_mission,
    decide_mission,
    plan_value_slices,
)
from .prd_grill import grill_prd, verify_prd_grill
from .run_metrics import public_metrics
from .runtime_coverage import read_runtime_coverage_report
from .savings import SavingsError, public_savings_report, record_savings_pair
from .target_compiler import TARGETS, TargetCompileError, create_target_from_prompt

STUDIO_SCHEMA = "factory.studio.v1"
MAX_BODY_BYTES = 64 * 1024
MAX_GUIDED_PRD_BYTES = 64 * 1024
MAX_GUIDED_ANSWER_BYTES = 2_000
MAX_GUIDED_ANSWERS = 5
MAX_GUIDED_ARTIFACT_BYTES = 32 * 1024
GUIDED_SESSION_SCHEMA = "factory.studio.guided-prd-session.v1"
GUIDED_CONFIRMATION_SCHEMA = "factory.studio.guided-prd-confirmation.v1"
UNAUTHORIZED_DRAIN_TIMEOUT_SECONDS = 0.25
LOOPBACK_HOST = "127.0.0.1"
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}")
FORBIDDEN_ACTIONS = {
    "deploy",
    "publish",
    "sign",
    "external-message",
    "credential",
    "connector-grant",
}
RESOLUTION_MODES = {"human_approval", "auto_resolve_safe"}
DEVELOPER_MEMORY_REFRESH_INTERVAL_MS = 5_000
_developer_memory_cache_lock = threading.Lock()
_developer_memory_cache: dict[str, tuple[float, dict[str, Any]]] = {}


class StudioRequestError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status
        self.guidance = explain_failure(code, message)


def developer_memory_snapshot(root: Path) -> dict[str, Any]:
    """Return a cache-bounded local next-proof projection for Studio surfaces."""
    workspace = Path(root).resolve()
    key = str(workspace)
    now = monotonic()
    with _developer_memory_cache_lock:
        cached = _developer_memory_cache.get(key)
        if (
            cached is not None
            and (now - cached[0]) * 1000 < DEVELOPER_MEMORY_REFRESH_INTERVAL_MS
        ):
            brief = cached[1]
            cache_state = "reused"
            age_ms = int((now - cached[0]) * 1000)
        else:
            brief = developer_memory_brief(workspace)
            _developer_memory_cache[key] = (now, brief)
            cache_state = "fresh"
            age_ms = 0
    return {
        "schema": "factory.studio.developer-memory.v1",
        "marker": "DEVELOPER_MEMORY_STUDIO_CACHED",
        "brief": brief,
        "cache": {
            "state": cache_state,
            "age_ms": age_ms,
            "refresh_interval_ms": DEVELOPER_MEMORY_REFRESH_INTERVAL_MS,
            "scope": "Only one new brief calculation per local Studio root and five-second interval.",
        },
    }


def studio_status(root: Path, port: int) -> dict[str, Any]:
    """Return the exact local Studio authority without opening a listener."""
    resolved = Path(root).resolve()
    return {
        "schema": STUDIO_SCHEMA,
        "marker": "STUDIO_STATUS_EXACT",
        "root": str(resolved),
        "listener": {"host": LOOPBACK_HOST, "port": port, "production": False},
        "targets": TARGETS,
        "limits": {
            "max_body_bytes": MAX_BODY_BYTES,
            "output_scope": "beneath_root",
            "overwrite": False,
        },
        "authority": {
            "can_create_starters": True,
            "can_compile_product_missions": True,
            "can_record_mission_execution_decision": True,
            "can_auto_resolve_safe_local_gaps": True,
            "can_continue_assembly_to_human_boundary": True,
            "can_record_exact_savings_pairs": True,
            "can_record_graph_ops_human_authorization": True,
            "can_execute_one_authorized_reality_check": True,
            "can_deploy": False,
            "can_publish": False,
            "can_sign": False,
            "can_send_external_messages": False,
            "can_inject_credentials": False,
            "can_grant_connectors": False,
        },
    }


def _json_or_none(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _mission_rows(root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(
        (Path(root).resolve() / ".factory" / "missions").glob("*/mission.json")
    ):
        mission = _json_or_none(path)
        if mission is None:
            continue
        decision = _json_or_none(path.parent / "execution_decision.json")
        completion = _json_or_none(path.parent / "completion.json")
        rows.append(
            {
                "id": mission.get("id"),
                "owner": mission.get("owner"),
                "slice_id": mission.get("slice_id"),
                "risk": mission.get("slice", {}).get("risk"),
                "score": mission.get("slice", {}).get("score", {}).get("priority"),
                "worktree": mission.get("workspace_contract", {}).get("path"),
                "branch": mission.get("workspace_contract", {}).get("branch"),
                "criteria": len(
                    mission.get("completion_contract", {}).get("criteria", [])
                ),
                "decision": decision.get("decision") if decision else "awaiting_owner",
                "completion": (
                    ("verified_receipt_present" if completion else "pending")
                    + " | readiness "
                    + (
                        "bound"
                        if mission.get("inputs", {}).get("migration_readiness")
                        else "not bound"
                    )
                ),
                "path": str(path),
            }
        )
    return rows


def _product_rows(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    products: list[dict[str, Any]] = []
    queue: list[dict[str, Any]] = []
    product_root = Path(root).resolve() / ".factory" / "products"
    for path in sorted(product_root.glob("*/product_graph.json")):
        graph = _json_or_none(path)
        if graph is None:
            continue
        slices = _json_or_none(path.parent / "value_slices.json")
        product = {
            "project": graph.get("project"),
            "status": graph.get("status"),
            "requirements": len(graph.get("requirements", [])),
            "journeys": graph.get("journeys", []),
            "blocking_gaps": sum(
                item.get("severity") == "blocking" for item in graph.get("gaps", [])
            ),
            "advisory_gaps": sum(
                item.get("severity") == "advisory" for item in graph.get("gaps", [])
            ),
            "graph_path": str(path),
            "graph_mermaid": str(path.parent / "product_graph.mmd"),
            "slice_count": len(slices.get("slices", [])) if slices else 0,
        }
        products.append(product)
        if slices:
            for item in slices.get("slices", []):
                queue.append(
                    {
                        "project": graph.get("project"),
                        "id": item.get("id"),
                        "theme": item.get("theme"),
                        "priority": item.get("score", {}).get("priority"),
                        "risk": item.get("risk"),
                        "requirements": item.get("requirement_ids", []),
                        "depends_on": item.get("depends_on", []),
                        "path": str(path.parent / "value_slices.json"),
                    }
                )
    queue.sort(
        key=lambda item: (
            -(item["priority"] if isinstance(item["priority"], int) else -1),
            str(item["id"]),
        )
    )
    return products, queue


def _proof_timeline(missions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline = []
    for row in missions:
        mission = _json_or_none(Path(row["path"])) or {}
        completion = _json_or_none(Path(row["path"]).parent / "completion.json")
        for requirement_id in mission.get("slice", {}).get("requirement_ids", []):
            evidence = []
            if completion:
                evidence = [
                    item.get("path")
                    for item in completion.get("evidence", [])
                    if item.get("path")
                ]
            timeline.append(
                {
                    "requirement_id": requirement_id,
                    "slice_id": row["slice_id"],
                    "mission_id": row["id"],
                    "code_state": "candidate_workspace_bound"
                    if row.get("worktree")
                    else "not_bound",
                    "test_state": row["completion"],
                    "receipt": str(Path(row["path"]).parent / "completion.json")
                    if completion
                    else None,
                    "evidence": evidence,
                }
            )
    return timeline


def _receipt_comparison(root: Path) -> dict[str, Any]:
    groups: dict[str, list[Any]] = {}
    for stage in MeterLog(root).stages():
        if stage.run_id:
            groups.setdefault(stage.run_id, []).append(stage)
    run_ids = list(groups)[-2:]
    if len(run_ids) < 2:
        return {
            "schema": "factory.receipt_comparison.v1",
            "status": "insufficient_runs",
            "current": None,
            "previous": None,
            "delta": None,
        }

    def summary(run_id: str) -> dict[str, Any]:
        stages = groups[run_id]
        return {
            "run_id": run_id,
            "wall_ms": sum(item.wall_ms for item in stages),
            "model_calls": sum(item.model_calls for item in stages),
            "tokens": sum(item.tokens_in + item.tokens_out for item in stages),
            "failed_stages": sum(not item.ok for item in stages),
            "token_quality": sorted(
                {item.token_quality or item.usage_quality for item in stages}
            ),
        }

    previous, current = (summary(run_id) for run_id in run_ids)
    return {
        "schema": "factory.receipt_comparison.v1",
        "status": "compared",
        "current": current,
        "previous": previous,
        "delta": {
            "wall_ms": current["wall_ms"] - previous["wall_ms"],
            "model_calls": current["model_calls"] - previous["model_calls"],
            "tokens": current["tokens"] - previous["tokens"],
            "failed_stages": current["failed_stages"] - previous["failed_stages"],
        },
    }


def _run_feature(ordered: list[Any]) -> str | None:
    return next((item.feature for item in reversed(ordered) if item.feature), None)


def _run_cost(ordered: list[Any]) -> float | None:
    if not all(item.cost_usd is not None for item in ordered):
        return None
    return sum(item.cost_usd or 0 for item in ordered)


def _run_outcome(observed: list[str], failed_stages: int) -> str:
    if observed:
        return observed[-1]
    return "failed_stage_observed" if failed_stages else "stages_recorded"


def _summarize_run(run_id: str, stages: list[Any]) -> dict[str, Any]:
    ordered = sorted(stages, key=lambda item: item.recorded_at or "")
    latest = ordered[-1]
    token_qualities = sorted(
        {item.token_quality or item.usage_quality for item in ordered}
    )
    cost_qualities = sorted({item.cost_quality for item in ordered})
    observed_outcomes = [item.outcome_status for item in ordered if item.outcome_status]
    failed_stages = sum(not item.ok for item in ordered)
    return {
        "run_id": run_id,
        "feature": _run_feature(ordered),
        "first_recorded_at": ordered[0].recorded_at or None,
        "last_recorded_at": latest.recorded_at or None,
        "stages_recorded": len(ordered),
        "failed_stages": failed_stages,
        "wall_ms": sum(item.wall_ms for item in ordered),
        "model_calls": sum(item.model_calls for item in ordered),
        "tokens": sum(item.tokens_in + item.tokens_out for item in ordered),
        "token_quality": token_qualities,
        "cost_usd": _run_cost(ordered),
        "cost_quality": cost_qualities,
        "outcome": _run_outcome(observed_outcomes, failed_stages),
    }


def _recent_run_stats(root: Path, *, limit: int = 8) -> list[dict[str, Any]]:
    """Return observed, append-only run history without inferring unrecorded outcomes.

    Meter rows are stage receipts, not a claim that an entire run succeeded.  The
    UI therefore names failures and unknown usage quality directly instead of
    turning a partial ledger into a green completion badge.
    """
    groups: dict[str, list[Any]] = {}
    for stage in MeterLog(root).stages():
        if stage.run_id:
            groups.setdefault(stage.run_id, []).append(stage)

    rows = [_summarize_run(run_id, stages) for run_id, stages in groups.items()]
    rows.sort(key=lambda item: item["last_recorded_at"] or "", reverse=True)
    return rows[:limit]


def _context_engine_value(root: Path) -> dict[str, Any]:
    """Project aggregate observations only; cached packets are not live proof."""
    from .context_efficiency import context_efficiency_status

    status = context_efficiency_status(root)
    fields = (
        "packet_count",
        "invalid_count",
        "cache_hits",
        "estimated_tokens",
        "reusable_packet_count",
        "stale_packet_count",
        "missing_evidence_count",
        "paired_sample_count",
        "observed_latency_reduction",
        "observed_cost_delta",
        "observed_token_delta",
        "deep_evidence_file_count",
        "evidence_role_count",
        "missing_evidence_role_count",
    )
    result = {key: _context_number(status.get(key)) for key in fields}
    for key in (
        "state",
        "source_selection_status",
        "experiment_status",
        "experiment_evidence_level",
        "experiment_quality_status",
        "experiment_freshness",
        "structural_evidence_status",
    ):
        value = status.get(key)
        result[key] = (
            value if isinstance(value, str) and len(value) <= 80 else "MISSING"
        )
    result.update(
        schema="factory.studio.context-value.v1",
        target_latency_reduction=0.5,
        claim_boundary="50% less elapsed time is a target, not an observed result. "
        "Paired observations include context preparation and repair; estimated tokens "
        "are not provider usage. Cache counts alone do not establish current validity.",
        next_action="Build and verify a task context packet; record paired baseline "
        "and context runs against the same acceptance checks.",
    )
    return result


def _context_number(value: Any) -> int | float | None:
    return value if type(value) in (int, float) and -1e15 <= value <= 1e15 else None


def studio_dashboard(root: Path) -> dict[str, Any]:
    """Return live local telemetry, approvals, and pack trust without side effects."""
    meter = live_snapshot(Path(root))
    packs = []
    for item in builtin_packs():
        validation = validate_pack(Path(item["path"]))
        packs.append(
            {
                "id": item["id"],
                "target_kind": item.get("target_kind"),
                "version": item["version"],
                "valid": validation["valid"],
                "signature_verified": validation["signature"]["verified"],
                "mutations_rejected": validation["mutations"]["rejected"],
                "mutations_attempted": validation["mutations"]["attempted"],
                "deployment_profiles": item.get("deployment_profiles", []),
            }
        )
    missions = _mission_rows(Path(root))
    products, slice_queue = _product_rows(Path(root))
    developer_memory = developer_memory_snapshot(Path(root))
    return {
        "schema": "factory.studio.dashboard.v1",
        "generated_at": meter["generated_at"],
        "meter": meter,
        "live_activity": activity_snapshot(Path(root)),
        "missions": missions,
        "products": products,
        "slice_queue": slice_queue,
        "proof_timeline": _proof_timeline(missions),
        "receipt_comparison": _receipt_comparison(Path(root)),
        "recent_runs": _recent_run_stats(Path(root)),
        "developer_memory": developer_memory,
        "context_engine": _context_engine_value(Path(root)),
        "approvals": {
            "awaiting_owner": sum(
                item["decision"] == "awaiting_owner" for item in missions
            ),
            "approved_execution": sum(
                item["decision"] == "approved_execution" for item in missions
            ),
            "deferred": sum(item["decision"] == "deferred" for item in missions),
            "rejected": sum(item["decision"] == "rejected" for item in missions),
            "auto_resolve_mode": "safe_local_gaps_only",
        },
        "packs": packs,
        "authority": studio_status(Path(root), 0)["authority"],
        "assembly": {
            "features": discover_features(Path(root)),
            "metrics": public_metrics(Path(root)),
        },
        "savings": public_savings_report(Path(root)),
        "markers": [
            "STUDIO_LIVE_TELEMETRY",
            "STUDIO_APPROVAL_QUEUE",
            "STUDIO_PACK_TRUST_VISIBLE",
            "STUDIO_PRODUCT_GRAPH_VISIBLE",
            "STUDIO_SLICE_QUEUE_VISIBLE",
            "STUDIO_PROOF_TIMELINE_VISIBLE",
            "STUDIO_RECEIPT_COMPARISON_VISIBLE",
            "STUDIO_PRIOR_RUNS_VISIBLE",
            "STUDIO_DEVELOPER_MEMORY_VISIBLE",
        ],
    }


def continue_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Continue one local assembly through the same engine used by the CLI."""
    if str(payload.get("action", "")) != "continue":
        raise StudioRequestError(
            "ACTION_UNSUPPORTED", "assembly endpoint requires continue"
        )
    feature = payload.get("feature")
    if feature is not None and not isinstance(feature, str):
        raise StudioRequestError("FEATURE_INVALID", "feature must be a string")
    try:
        result = continue_assembly(
            Path(root), feature.strip() or None if isinstance(feature, str) else None
        )
    except ContinuationError as exc:
        raise StudioRequestError(exc.code, exc.message, 409) from exc
    return {**result, "studio_marker": "STUDIO_ASSEMBLY_CONTAINED"}


def savings_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Record one contained exact pair through the same engine used by the CLI."""
    if str(payload.get("action", "")) != "savings-record":
        raise StudioRequestError(
            "ACTION_UNSUPPORTED", "savings endpoint requires savings-record"
        )
    resolved_root = Path(root).resolve()
    evidence = payload.get("evidence")
    evidence_path = (
        (resolved_root / evidence).resolve()
        if isinstance(evidence, str) and evidence
        else None
    )
    if evidence_path is not None and not evidence_path.is_relative_to(resolved_root):
        raise StudioRequestError(
            "PATH_REJECTED", "evidence must stay beneath Studio root"
        )
    baseline = {
        "elapsed_ms": payload.get("baseline_elapsed_ms"),
        "tokens": payload.get("baseline_tokens"),
        "cost_usd": payload.get("baseline_cost_usd"),
    }
    factory_observation = {
        "elapsed_ms": payload.get("factory_elapsed_ms"),
        "tokens": payload.get("factory_tokens"),
        "cost_usd": payload.get("factory_cost_usd"),
    }
    try:
        result = record_savings_pair(
            resolved_root,
            payload.get("pair_id"),
            baseline,
            factory_observation,
            equivalent_outcome=payload.get("equivalent_outcome") is True,
            evidence=evidence_path,
            replace=payload.get("replace") is True,
        )
    except SavingsError as exc:
        raise StudioRequestError(
            exc.code, str(exc), 409 if exc.code == "PAIR_OVERWRITE_REFUSED" else 400
        ) from exc
    return {**result, "studio_marker": "SAVINGS_STUDIO_CONTAINED"}


def _contained_output(root: Path, name: str) -> Path:
    if not NAME_PATTERN.fullmatch(name):
        raise StudioRequestError(
            "PATH_REJECTED",
            "name must use 1-48 letters, digits, hyphens, or underscores",
        )
    resolved_root = Path(root).resolve()
    output = (resolved_root / name).resolve()
    if output.parent != resolved_root:
        raise StudioRequestError(
            "PATH_REJECTED", "output must be a direct child of Studio root"
        )
    return output


def _validate_action(payload: dict[str, Any]) -> None:
    action = str(payload.get("action", "create"))
    if action in FORBIDDEN_ACTIONS:
        raise StudioRequestError(
            "ACTION_FORBIDDEN", f"Studio cannot perform {action}", 403
        )
    if action != "create":
        raise StudioRequestError("ACTION_UNSUPPORTED", "only create is available")


def _target_and_prompt(payload: dict[str, Any]) -> tuple[str, str]:
    target = str(payload.get("target", ""))
    if target not in TARGETS:
        raise StudioRequestError(
            "TARGET_UNSUPPORTED", f"target must be one of {', '.join(TARGETS)}"
        )
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise StudioRequestError("SOURCE_REQUIRED", "prompt must be a non-empty string")
    return target, prompt


def _output_name(payload: dict[str, Any], prompt: str) -> str:
    requested_name = payload.get("name")
    if requested_name is not None and not isinstance(requested_name, str):
        raise StudioRequestError("NAME_INVALID", "name must be a string")
    default_name = (
        re.sub(r"[^a-zA-Z0-9]+", "-", prompt.strip().lower()).strip("-")[:48]
        or "factory-target"
    )
    return (
        requested_name.strip()
        if isinstance(requested_name, str) and requested_name.strip()
        else default_name
    )


def create_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Compile one contained target from a validated Studio request."""
    _validate_action(payload)
    target, prompt = _target_and_prompt(payload)
    output_name = _output_name(payload, prompt)
    output = _contained_output(root, output_name)
    try:
        result = create_target_from_prompt(
            prompt,
            target=target,
            out_dir=output,
            name=output_name,
            purpose=str(payload.get("purpose", "auto")),
            trigger=str(payload.get("trigger", "manual")),
            deployment_profile=str(payload.get("deployment_profile", "")).strip()
            or None,
        )
    except TargetCompileError as exc:
        status = 409 if exc.code == "OUTPUT_EXISTS" else 400
        raise StudioRequestError(exc.code, exc.message, status) from exc
    return {**result, "studio_marker": "STUDIO_CONTAINED"}


def _guided_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _guided_is_digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _guided_canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _guided_relative(relative: Any) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or "\x00" in relative
    ):
        raise StudioRequestError("PATH_REJECTED", "artifact path must be relative")
    rel = Path(relative)
    if rel.is_absolute() or rel.drive or any(part in {".", ".."} for part in rel.parts):
        raise StudioRequestError(
            "PATH_REJECTED", "artifact path must stay in Studio root"
        )
    return rel


def _guided_path(root: Path, relative: Any, *, required: bool = False) -> Path:
    rel = _guided_relative(relative)
    base = Path(root).resolve()
    path = base
    for part in rel.parts:
        path /= part
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise StudioRequestError("PATH_REJECTED", "artifact path contains a link")
    if not path.is_relative_to(base) or (required and not path.is_file()):
        raise StudioRequestError(
            "ARTIFACT_NOT_FOUND",
            "guided artifact is missing or outside Studio root",
            409,
        )
    return path


def _guided_read(path: Path, limit: int = 32 * 1024) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise StudioRequestError(
                    "ARTIFACT_SIZE_INVALID",
                    "guided artifact exceeds its regular-file bound",
                    409,
                )
            data = stream.read(limit + 1)
    except OSError as exc:
        raise StudioRequestError(
            "ARTIFACT_INVALID", "guided artifact cannot be read", 409
        ) from exc
    if len(data) > limit:
        raise StudioRequestError(
            "ARTIFACT_SIZE_INVALID", "guided artifact exceeds its byte bound", 409
        )
    return data


def _guided_write(root: Path, relative: str, data: bytes) -> Path:
    path = _guided_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    _guided_path(root, relative)
    if path.exists():
        if _guided_read(path, max(len(data), 64 * 1024)) == data:
            return path
        raise StudioRequestError(
            "ARTIFACT_EXISTS", "refusing to replace immutable guided artifact", 409
        )
    try:
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise StudioRequestError(
            "ARTIFACT_EXISTS", "guided artifact already exists", 409
        ) from exc
    _guided_path(root, relative, required=True)
    return path


def _guided_rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(Path(root).resolve()).as_posix()


def _guided_record(
    root: Path,
    relative: Any,
    expected: Any,
    schema: str,
    field: str,
    binding_code: str = "ARTIFACT_BINDING_INVALID",
) -> dict[str, Any]:
    path = _guided_path(root, relative, required=True)
    try:
        record = json.loads(_guided_read(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StudioRequestError(
            "ARTIFACT_INVALID", "guided receipt is invalid", 409
        ) from exc
    if not isinstance(record, dict) or record.get("schema") != schema:
        raise StudioRequestError(
            "ARTIFACT_INVALID", "guided receipt schema is invalid", 409
        )
    core = {key: value for key, value in record.items() if key != field}
    try:
        digest = _guided_digest(_guided_canonical(core))
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise StudioRequestError(
            "ARTIFACT_INVALID", "guided receipt contains invalid text", 409
        ) from exc
    if record.get(field) != digest or expected != digest:
        raise StudioRequestError(binding_code, "guided receipt hash mismatch", 409)
    return record


def _guided_shape(record: dict[str, Any], fields: set[str]) -> None:
    if set(record) != fields:
        raise StudioRequestError(
            "ARTIFACT_INVALID", "guided receipt fields are invalid", 409
        )


def _guided_verified_grill(path: Path, payload: bytes) -> dict[str, Any]:
    try:
        receipt = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StudioRequestError(
            "RECEIPT_INVALID", "PRD Grill receipt is invalid", 409
        ) from exc
    if (
        not isinstance(receipt, dict)
        or not isinstance(receipt.get("source"), dict)
        or not _guided_is_digest(receipt["source"].get("sha256"))
    ):
        raise StudioRequestError(
            "RECEIPT_INVALID", "PRD Grill receipt fields are invalid", 409
        )
    try:
        verified = verify_prd_grill(path)
    except (ProductMissionError, KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise StudioRequestError(
            "RECEIPT_INVALID", "PRD Grill receipt failed verification", 409
        ) from exc
    if not verified.get("valid"):
        raise StudioRequestError(
            "RECEIPT_INVALID", "PRD Grill receipt failed verification", 409
        )
    return receipt


def _guided_saved_answers(answers: Any) -> None:
    if not isinstance(answers, list) or len(answers) > MAX_GUIDED_ANSWERS:
        raise StudioRequestError("SESSION_INVALID", "saved answer list is invalid", 409)
    seen: set[str] = set()
    for item in answers:
        seen.add(_guided_saved_answer(item, seen))


def _guided_saved_answer(item: Any, seen: set[str]) -> str:
    if not isinstance(item, dict) or set(item) != {"question_id", "answer"}:
        raise StudioRequestError(
            "SESSION_INVALID", "saved answer record is invalid", 409
        )
    question_id = item["question_id"]
    if (
        not isinstance(question_id, str)
        or not question_id
        or len(question_id) > 128
        or question_id in seen
    ):
        raise StudioRequestError("SESSION_INVALID", "saved question id is invalid", 409)
    try:
        _guided_answer_text(item["answer"])
    except StudioRequestError as exc:
        raise StudioRequestError(
            "SESSION_INVALID", "saved answer text is invalid", 409
        ) from exc
    return question_id


def _guided_source_and_grill(
    root: Path, record: dict[str, Any]
) -> tuple[Path, Path, dict[str, Any]]:
    source = _guided_path(root, record["source_path"], required=True)
    grill_path = _guided_path(root, record["grill_path"], required=True)
    source_bytes = _guided_read(source, MAX_GUIDED_PRD_BYTES)
    grill_bytes = _guided_read(grill_path)
    if (
        _guided_digest(source_bytes) != record["source_sha256"]
        or _guided_digest(grill_bytes) != record["grill_sha256"]
    ):
        raise StudioRequestError(
            "SOURCE_BINDING_INVALID", "guided PRD or Grill receipt changed", 409
        )
    grill_record = _guided_verified_grill(grill_path, grill_bytes)
    if grill_record["source"]["sha256"] != record["source_sha256"]:
        raise StudioRequestError(
            "RECEIPT_INVALID", "PRD Grill receipt failed verification", 409
        )
    return source, grill_path, json.loads(grill_bytes)


def _guided_session(
    root: Path, relative: Any, expected: Any
) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    session = _guided_record(
        root, relative, expected, GUIDED_SESSION_SCHEMA, "session_sha256"
    )
    _guided_shape(
        session,
        {
            "schema",
            "project",
            "mode",
            "source_path",
            "source_sha256",
            "grill_path",
            "grill_sha256",
            "answers",
            "previous",
            "session_sha256",
        },
    )
    _guided_session_identity(session)
    _guided_saved_answers(session["answers"])
    _guided_previous_session(root, session.get("previous"))
    source, _, grill = _guided_source_and_grill(root, session)
    return session, source, grill


def _guided_session_identity(session: dict[str, Any]) -> None:
    if (
        not isinstance(session["project"], str)
        or not NAME_PATTERN.fullmatch(session["project"])
        or not isinstance(session["mode"], str)
        or session["mode"] not in {"quick", "deep"}
        or not isinstance(session["source_path"], str)
        or not _guided_is_digest(session["source_sha256"])
        or not isinstance(session["grill_path"], str)
        or not _guided_is_digest(session["grill_sha256"])
    ):
        raise StudioRequestError(
            "SESSION_INVALID", "guided session identity is invalid", 409
        )


def _guided_previous_session(root: Path, previous: Any) -> None:
    if previous is not None:
        if (
            not isinstance(previous, dict)
            or set(previous) != {"path", "sha256"}
            or not isinstance(previous["path"], str)
            or not isinstance(previous["sha256"], str)
            or not _guided_is_digest(previous["sha256"])
        ):
            raise StudioRequestError(
                "SESSION_INVALID", "prior session link is invalid", 409
            )
        prior_path = _guided_path(root, previous["path"], required=True)
        if _guided_digest(_guided_read(prior_path)) != previous["sha256"]:
            raise StudioRequestError(
                "SESSION_INVALID", "prior session link changed", 409
            )


def _guided_run_grill(
    root: Path,
    project: str,
    mode: str,
    source: Path,
    answers: list[dict[str, str]],
    previous: dict[str, str] | None,
) -> dict[str, Any]:
    _guided_path(root, f".factory/prd-grills/{project}")
    try:
        grill = grill_prd(source, root, mode=mode, project=project)
    except ProductMissionError as exc:
        raise StudioRequestError(
            exc.code, str(exc), 409 if exc.code.endswith("EXISTS") else 400
        ) from exc
    grill_path = _guided_path(
        root, _guided_rel(root, Path(grill["path"])), required=True
    )
    grill_bytes = _guided_read(grill_path)
    grill_record = _guided_verified_grill(grill_path, grill_bytes)
    if grill_record["source"]["sha256"] != grill["source"]["sha256"]:
        raise StudioRequestError(
            "RECEIPT_INVALID", "new PRD Grill receipt failed verification", 409
        )
    core = {
        "schema": GUIDED_SESSION_SCHEMA,
        "project": project,
        "mode": mode,
        "source_path": _guided_rel(root, source),
        "source_sha256": grill["source"]["sha256"],
        "grill_path": _guided_rel(root, grill_path),
        "grill_sha256": _guided_digest(grill_bytes),
        "answers": answers,
        "previous": previous,
    }
    digest = _guided_digest(_guided_canonical(core))
    session_path = _guided_write(
        root,
        f".factory/studio-guided/{project}/{digest}.json",
        json.dumps({**core, "session_sha256": digest}, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    return {
        "schema": "factory.studio.guided-prd.v1",
        "status": _guided_grill_status(grill),
        "next_action": _guided_grill_next_action(grill),
        "session": {"path": _guided_rel(root, session_path), "session_sha256": digest},
        "source_sha256": core["source_sha256"],
        "source_text": _guided_source_text(source, core["source_sha256"]),
        "grill": {
            "path": core["grill_path"],
            "sha256": core["grill_sha256"],
            "status": grill["status"],
        },
        "questions": grill["questions"],
        "deferred_questions": grill["deferred_questions"],
        "confirmation_required": True,
        "implementation_authorized": False,
    }


def _guided_source_text(source: Path, expected: str) -> str:
    data = _guided_read(source, MAX_GUIDED_PRD_BYTES)
    if _guided_digest(data) != expected:
        raise StudioRequestError(
            "SOURCE_BINDING_INVALID", "guided PRD changed before display", 409
        )
    return data.decode("utf-8")


def _guided_grill_status(grill: dict[str, Any]) -> str:
    if grill["status"] == "ready_for_confirmation":
        return "ready_for_confirmation"
    if (
        not grill["questions"]
        and not grill["deferred_questions"]
        and grill["observed_gaps"]
    ):
        return "deep_review_required"
    return "needs_answers"


def _guided_grill_next_action(grill: dict[str, Any]) -> str:
    return {
        "ready_for_confirmation": "confirm",
        "needs_answers": "answer_current_questions",
        "deep_review_required": "start_deep_review",
    }[_guided_grill_status(grill)]


def _guided_start(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != {"action", "prompt", "name", "mode"}:
        raise StudioRequestError("REQUEST_INVALID", "guided start fields are invalid")
    prompt, mode = payload.get("prompt"), payload.get("mode")
    if (
        not isinstance(prompt, str)
        or not prompt.strip()
        or not isinstance(mode, str)
        or mode not in {"quick", "deep"}
    ):
        raise StudioRequestError("REQUEST_INVALID", "prompt and mode are required")
    try:
        source_bytes = prompt.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise StudioRequestError("SOURCE_INVALID", "PRD must be valid UTF-8") from exc
    if len(source_bytes) > MAX_GUIDED_PRD_BYTES:
        raise StudioRequestError("SOURCE_TOO_LARGE", "PRD exceeds the 65536-byte limit")
    project = _output_name(payload, prompt)
    _contained_output(root, project)
    digest = _guided_digest(source_bytes)
    source = _guided_write(
        root, f".factory/studio-guided/{project}/sources/{digest}.md", source_bytes
    )
    return _guided_run_grill(root, project, mode, source, [], None)


def _guided_answer_text(answer: Any) -> str:
    if not isinstance(answer, str) or not answer.strip():
        raise StudioRequestError("ANSWER_INVALID", "answer must be non-empty text")
    try:
        answer_size = len(answer.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise StudioRequestError(
            "ANSWER_INVALID", "answer must be valid UTF-8"
        ) from exc
    if answer_size > MAX_GUIDED_ANSWER_BYTES:
        raise StudioRequestError("ANSWER_INVALID", "answer must be 1-2000 UTF-8 bytes")
    return answer.strip()


def _guided_answer_row(item: Any, known: set[Any], seen: set[str]) -> dict[str, str]:
    if not isinstance(item, dict) or set(item) != {"question_id", "answer"}:
        raise StudioRequestError("ANSWERS_INVALID", "answer record fields are invalid")
    question_id, answer = item["question_id"], item["answer"]
    if (
        not isinstance(question_id, str)
        or question_id not in known
        or question_id in seen
    ):
        raise StudioRequestError(
            "QUESTION_ID_INVALID", "unknown or duplicate question id"
        )
    seen.add(question_id)
    return {"question_id": question_id, "answer": _guided_answer_text(answer)}


def _guided_answers(
    answers: Any, questions: list[dict[str, Any]]
) -> list[dict[str, str]]:
    if not isinstance(answers, list) or not 1 <= len(answers) <= MAX_GUIDED_ANSWERS:
        raise StudioRequestError(
            "ANSWERS_INVALID", "provide 1-5 explicit answer records"
        )
    known, seen = {item.get("id") for item in questions}, set()
    return [_guided_answer_row(item, known, seen) for item in answers]


def _guided_insert_section_answer(text: str, section: str, answer: str) -> str:
    lines = text.splitlines()
    heading = re.compile(r"^(#{1,6})\s+" + re.escape(section) + r"\s*#*\s*$", re.I)
    for index, line in enumerate(lines):
        match = heading.match(line)
        if match:
            level = len(match.group(1))
            end = next(
                (
                    position
                    for position in range(index + 1, len(lines))
                    if re.match(r"^#{1," + str(level) + r"}\s+", lines[position])
                ),
                len(lines),
            )
            rendered = _guided_section_answer_lines(section, answer)
            lines[end:end] = ["", *rendered]
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    rendered = "\n".join(_guided_section_answer_lines(section, answer))
    addition = f"## {section}\n\n" + rendered
    return text.rstrip() + "\n\n" + addition + "\n"


def _guided_section_answer_lines(section: str, answer: str) -> list[str]:
    lines = answer.splitlines()
    if section.casefold() == "acceptance":
        return lines
    return ["- " + lines[0], *("  " + line if line else "" for line in lines[1:])]


def _guided_apply_answers(
    text: str, answers: list[dict[str, str]], questions: list[dict[str, Any]]
) -> str:
    targets = {item["id"]: item["section"] for item in questions}
    for answer in answers:
        question_id = answer["question_id"]
        if question_id not in targets:
            raise StudioRequestError("QUESTION_ID_INVALID", "unknown question id")
        text = _guided_insert_section_answer(
            text, targets[question_id], answer["answer"]
        )
    return text


def _guided_answer(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != {"action", "session_path", "session_sha256", "answers"}:
        raise StudioRequestError("REQUEST_INVALID", "guided answer fields are invalid")
    session, source, grill = _guided_session(
        root, payload.get("session_path"), payload.get("session_sha256")
    )
    if not grill.get("questions"):
        raise StudioRequestError(
            "ANSWERS_NOT_AVAILABLE", "session has no current questions", 409
        )
    answers = _guided_answers(payload.get("answers"), grill["questions"])
    source_bytes = _guided_read(source, MAX_GUIDED_PRD_BYTES)
    if _guided_digest(source_bytes) != session["source_sha256"]:
        raise StudioRequestError(
            "SOURCE_BINDING_INVALID", "guided PRD changed before answer", 409
        )
    text = _guided_apply_answers(
        source_bytes.decode("utf-8"), answers, grill["questions"]
    )
    data = text.encode("utf-8")
    if len(data) > MAX_GUIDED_PRD_BYTES:
        raise StudioRequestError(
            "SOURCE_TOO_LARGE", "answered PRD exceeds the 65536-byte limit"
        )
    digest = _guided_digest(data)
    next_source = _guided_write(
        root, f".factory/studio-guided/{session['project']}/sources/{digest}.md", data
    )
    previous = {
        "path": payload["session_path"],
        "sha256": _guided_digest(
            _guided_read(_guided_path(root, payload["session_path"], required=True))
        ),
    }
    return _guided_run_grill(
        root, session["project"], session["mode"], next_source, answers, previous
    )


def _guided_confirm(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != {"action", "session_path", "session_sha256", "confirmed"}:
        raise StudioRequestError(
            "REQUEST_INVALID", "guided confirmation fields are invalid"
        )
    if payload.get("confirmed") is not True:
        raise StudioRequestError(
            "CONFIRMATION_REQUIRED", "explicit confirmation is required"
        )
    session, source, grill = _guided_session(
        root, payload.get("session_path"), payload.get("session_sha256")
    )
    if (
        grill.get("questions")
        or grill.get("deferred_questions")
        or grill.get("status") != "ready_for_confirmation"
    ):
        raise StudioRequestError(
            "PRD_UNRESOLVED",
            "answer all current Grill questions before confirmation",
            409,
        )
    project = f"{session['project'][:27]}-confirmed-{session['source_sha256'][:8]}"
    _guided_path(root, f".factory/prd-grills/{project}")
    try:
        confirmed = grill_prd(
            source, root, mode=session["mode"], project=project, confirm=True
        )
    except ProductMissionError as exc:
        raise StudioRequestError(
            exc.code, str(exc), 409 if exc.code.endswith("EXISTS") else 400
        ) from exc
    confirmed_path = _guided_path(
        root, _guided_rel(root, Path(confirmed["path"])), required=True
    )
    confirmed_bytes = _guided_read(confirmed_path)
    confirmed_record = _guided_verified_grill(confirmed_path, confirmed_bytes)
    if (
        confirmed_record["source"]["sha256"] != session["source_sha256"]
        or "PRD_GRILL_SHARED_UNDERSTANDING_CONFIRMED" not in confirmed["markers"]
    ):
        raise StudioRequestError(
            "CONFIRMATION_INVALID", "confirmed Grill receipt failed verification", 409
        )
    core = {
        "schema": GUIDED_CONFIRMATION_SCHEMA,
        "confirmed": True,
        "session_path": payload["session_path"],
        "session_sha256": session["session_sha256"],
        "source_path": session["source_path"],
        "source_sha256": session["source_sha256"],
        "grill_path": session["grill_path"],
        "grill_sha256": session["grill_sha256"],
        "confirmed_grill_path": _guided_rel(root, confirmed_path),
        "confirmed_grill_sha256": _guided_digest(confirmed_bytes),
        "confirmed_grill_id": confirmed["grill_sha256"],
    }
    digest = _guided_digest(_guided_canonical(core))
    path = _guided_write(
        root,
        f".factory/studio-guided/{session['project']}/confirmations/{digest}.json",
        json.dumps({**core, "confirmation_sha256": digest}, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n",
    )
    return {
        "schema": "factory.studio.guided-prd-confirmed.v1",
        "status": "confirmed",
        "confirmation": {"path": _guided_rel(root, path), "sha256": digest},
        "source_sha256": session["source_sha256"],
        "implementation_authorized": False,
    }


def _guided_confirmation(
    root: Path, payload: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    confirmation = _guided_record(
        root,
        payload.get("confirmation_path"),
        payload.get("confirmation_sha256"),
        GUIDED_CONFIRMATION_SCHEMA,
        "confirmation_sha256",
        "CONFIRMATION_BINDING_INVALID",
    )
    _guided_shape(
        confirmation,
        {
            "schema",
            "confirmed",
            "session_path",
            "session_sha256",
            "source_path",
            "source_sha256",
            "grill_path",
            "grill_sha256",
            "confirmed_grill_path",
            "confirmed_grill_sha256",
            "confirmed_grill_id",
            "confirmation_sha256",
        },
    )
    if confirmation.get("confirmed") is not True:
        raise StudioRequestError(
            "CONFIRMATION_REQUIRED", "confirmation state is not true", 409
        )
    session, source, _ = _guided_session(
        root, confirmation["session_path"], confirmation["session_sha256"]
    )
    if any(
        confirmation.get(key) != session.get(key)
        for key in ("source_path", "source_sha256", "grill_path", "grill_sha256")
    ):
        raise StudioRequestError(
            "CONFIRMATION_BINDING_INVALID",
            "confirmation does not match the current PRD",
            409,
        )
    confirmed_path = _guided_path(
        root, confirmation["confirmed_grill_path"], required=True
    )
    confirmed_bytes = _guided_read(confirmed_path)
    if _guided_digest(confirmed_bytes) != confirmation.get("confirmed_grill_sha256"):
        raise StudioRequestError(
            "CONFIRMATION_INVALID", "confirmed Grill receipt failed verification", 409
        )
    confirmed = _guided_verified_grill(confirmed_path, confirmed_bytes)
    if (
        confirmed.get("status") != "confirmed"
        or confirmed.get("source", {}).get("sha256") != session["source_sha256"]
        or confirmed.get("grill_sha256") != confirmation.get("confirmed_grill_id")
    ):
        raise StudioRequestError(
            "CONFIRMATION_INVALID", "confirmed receipt is not bound to the source", 409
        )
    return confirmation, session, source


def _guided_compile_owner_executor(payload: dict[str, Any]) -> tuple[str, str]:
    owner, executor = (
        payload.get("owner", "local-studio-user"),
        payload.get("executor", "manual"),
    )
    if (
        not isinstance(owner, str)
        or not owner.strip()
        or len(owner) > 80
        or not isinstance(executor, str)
        or not executor.strip()
        or len(executor) > 64
    ):
        raise StudioRequestError(
            "REQUEST_INVALID", "owner/executor lengths are invalid"
        )
    return owner.strip(), executor.strip()


def _guided_compile_options(payload: dict[str, Any]) -> tuple[str, str, str]:
    required, optional = (
        {"action", "confirmation_path", "confirmation_sha256"},
        {"owner", "executor", "resolution_mode"},
    )
    if not required <= set(payload) or set(payload) - required - optional:
        raise StudioRequestError("REQUEST_INVALID", "guided compile fields are invalid")
    owner, executor = _guided_compile_owner_executor(payload)
    resolution = payload.get("resolution_mode", "human_approval")
    if not isinstance(resolution, str) or resolution not in RESOLUTION_MODES:
        raise StudioRequestError(
            "RESOLUTION_MODE_INVALID", "resolution mode is unsupported"
        )
    return owner, executor, resolution


def _guided_compile_graph(
    root: Path,
    session: dict[str, Any],
    source: Path,
    resolution: str,
    confirmation: dict[str, Any],
) -> dict[str, Any]:
    source_bytes = _guided_read(source, MAX_GUIDED_PRD_BYTES)
    if _guided_digest(source_bytes) != session["source_sha256"]:
        raise StudioRequestError(
            "SOURCE_BINDING_INVALID", "guided PRD changed before compile", 409
        )
    graph = compile_product_text(
        source_bytes.decode("utf-8"),
        root=Path(root),
        source_name=source.name,
        project=session["project"],
    )
    if graph["status"] != "ready":
        return {
            **_product_gap_response(graph, resolution),
            "guided_confirmation_sha256": confirmation["confirmation_sha256"],
        }
    return graph


def _guided_compile_ready(
    root: Path,
    graph: dict[str, Any],
    owner: str,
    executor: str,
    resolution: str,
    confirmation: dict[str, Any],
    session: dict[str, Any],
) -> dict[str, Any]:
    try:
        slices, mission = _first_product_mission(Path(root), graph, owner, executor)
    except ProductMissionError as exc:
        raise StudioRequestError(
            exc.code, str(exc), 409 if exc.code.endswith("EXISTS") else 400
        ) from exc
    response = _planned_product_mission_response(graph, slices, mission, resolution)
    response["guided_confirmation_sha256"] = confirmation["confirmation_sha256"]
    response["guided_source_sha256"] = session["source_sha256"]
    return response


def _guided_compile(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    owner, executor, resolution = _guided_compile_options(payload)
    confirmation, session, source = _guided_confirmation(root, payload)
    try:
        graph = _guided_compile_graph(root, session, source, resolution, confirmation)
    except ProductMissionError as exc:
        raise StudioRequestError(
            exc.code, str(exc), 409 if exc.code.endswith("EXISTS") else 400
        ) from exc
    if graph.get("status") != "ready":
        return graph
    return _guided_compile_ready(
        root, graph, owner, executor, resolution, confirmation, session
    )


def product_grill_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Handle the explicit Grill, answer, confirmation and guided compile stages."""
    handlers = {
        "product-grill-start": _guided_start,
        "product-grill-answer": _guided_answer,
        "product-grill-confirm": _guided_confirm,
        "product-guided-compile": _guided_compile,
    }
    action = payload.get("action")
    handler = handlers.get(action) if isinstance(action, str) else None
    if handler is None:
        raise StudioRequestError("ACTION_UNSUPPORTED", "unknown guided product action")
    return handler(root, payload)


def _validated_product_mission_request(
    root: Path, payload: dict[str, Any]
) -> tuple[str, str, str, str, str]:
    """Validate the user-controlled values used to compile a product mission."""
    action = str(payload.get("action", ""))
    if action in FORBIDDEN_ACTIONS:
        raise StudioRequestError(
            "ACTION_FORBIDDEN", f"Studio cannot perform {action}", 403
        )
    if action != "product-mission":
        raise StudioRequestError(
            "ACTION_UNSUPPORTED", "product endpoint requires product-mission"
        )
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise StudioRequestError("SOURCE_REQUIRED", "PRD must be a non-empty string")
    name = _output_name(payload, prompt)
    _contained_output(root, name)  # Validate the user-controlled project slug.
    owner = (
        str(payload.get("owner", "local-studio-user")).strip() or "local-studio-user"
    )
    executor = str(payload.get("executor", "manual"))
    resolution_mode = str(payload.get("resolution_mode", "human_approval"))
    if resolution_mode not in RESOLUTION_MODES:
        raise StudioRequestError(
            "RESOLUTION_MODE_INVALID",
            f"resolution mode must be one of {', '.join(sorted(RESOLUTION_MODES))}",
        )
    return prompt, name, owner, executor, resolution_mode


def _product_gap_response(
    graph: dict[str, Any], resolution_mode: str
) -> dict[str, Any]:
    """Return actionable, human-owned feedback for an incomplete PRD."""
    items = [
        {
            "id": f"resolve-{gap['code'].lower().replace('_', '-')}",
            "code": gap["code"],
            "severity": gap["severity"],
            "why": gap["message"],
            "next_action": gap["message"],
            "auto_resolvable": False,
            "approval_required": True,
        }
        for gap in graph["gaps"]
    ]
    return {
        "schema": "factory.studio.product_mission.v1",
        "status": "needs_input",
        "graph": graph,
        "mission": None,
        "resolution": {
            "mode": resolution_mode,
            "status": "human_input_required",
            "auto_resolved": [],
            "items": items,
            "why_auto_stopped": "Product facts, UX intent, and acceptance criteria cannot be invented by safe auto-resolution.",
            "next_action": "Add the listed facts to the PRD and compile again.",
        },
        "studio_marker": "STUDIO_PRODUCT_MISSION_CONTAINED",
    }


def _first_product_mission(
    root: Path, graph: dict[str, Any], owner: str, executor: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Plan the product graph and return its first dependency-ready mission."""
    slices = plan_value_slices(Path(graph["path"]), root)
    ready = [item for item in slices["slices"] if not item["depends_on"]]
    if not ready:
        raise ProductMissionError(
            "MISSION_DEPENDENCY_CYCLE", "no dependency-ready value slice is available"
        )
    mission = create_mission(
        Path(slices["path"]), ready[0]["id"], root, owner, executor
    )
    return slices, mission


def _planned_product_mission_response(
    graph: dict[str, Any],
    slices: dict[str, Any],
    mission: dict[str, Any],
    resolution_mode: str,
) -> dict[str, Any]:
    """Project the bounded, approval-ready product mission response."""
    return {
        "schema": "factory.studio.product_mission.v1",
        "status": "planned",
        "graph": graph,
        "slices": slices,
        "mission": mission,
        "resolution": {
            "mode": resolution_mode,
            "status": "nothing_safe_to_resolve",
            "auto_resolved": [],
            "items": [],
            "next_action": "Review the bounded mission and record an execution decision.",
        },
        "approval": {
            "schema": "factory.studio.approval_ready.v1",
            "state": "ready_for_human_decision",
            "owner": mission["owner"],
            "mission_path": mission["path"],
            "slice_id": mission["slice_id"],
            "risk": mission["slice"]["risk"],
            "budgets": mission["budgets"],
            "completion_criteria": mission["completion_contract"]["criteria"],
            "decisions": ["approved_execution", "deferred", "rejected"],
            "authority_after_approval": {
                "execute_bounded_mission": True,
                "merge": False,
                "publish": False,
                "deploy": False,
                "external_message": False,
                "connector_grant": False,
            },
        },
        "studio_marker": "STUDIO_PRODUCT_MISSION_CONTAINED",
    }


def create_product_mission_from_studio(
    root: Path, payload: dict[str, Any]
) -> dict[str, Any]:
    """Legacy compatibility endpoint; guided clients must use product-grill."""
    prompt, name, owner, executor, resolution_mode = _validated_product_mission_request(
        root, payload
    )
    try:
        graph = compile_product_text(
            prompt, root=Path(root), source_name="studio-prd.md", project=name
        )
        if graph["status"] != "ready":
            return {
                **_product_gap_response(graph, resolution_mode),
                "compatibility_path": "legacy-product-mission-v1",
            }
        slices, mission = _first_product_mission(Path(root), graph, owner, executor)
    except ProductMissionError as exc:
        status = 409 if exc.code.endswith("EXISTS") else 400
        raise StudioRequestError(exc.code, exc.message, status) from exc
    return {
        **_planned_product_mission_response(graph, slices, mission, resolution_mode),
        "compatibility_path": "legacy-product-mission-v1",
    }


def decide_product_mission_from_studio(
    root: Path, payload: dict[str, Any]
) -> dict[str, Any]:
    """Record an actionable human decision for one contained mission."""
    if str(payload.get("action", "")) != "mission-decision":
        raise StudioRequestError(
            "ACTION_UNSUPPORTED", "mission decision endpoint requires mission-decision"
        )
    mission_value = payload.get("mission")
    if not isinstance(mission_value, str) or not mission_value.strip():
        raise StudioRequestError("MISSION_REQUIRED", "mission path is required")
    mission = Path(mission_value).resolve()
    root = Path(root).resolve()
    try:
        mission.relative_to(root)
    except ValueError as exc:
        raise StudioRequestError(
            "PATH_REJECTED", "mission must be beneath the Studio root", 403
        ) from exc
    try:
        return decide_mission(
            mission,
            root,
            owner=str(payload.get("owner", "")),
            decision=str(payload.get("decision", "")),
            rationale=str(payload.get("rationale", "")),
        )
    except ProductMissionError as exc:
        raise StudioRequestError(exc.code, exc.message, 400) from exc


def authorize_graph_ops_from_studio(
    root: Path, payload: dict[str, Any]
) -> dict[str, Any]:
    """Record a named human authorization that stays bounded to one graph node."""
    try:
        return create_graph_authorization(root, payload)
    except GraphAuthorizationError as exc:
        raise StudioRequestError(
            exc.code,
            str(exc),
            409 if exc.code.endswith(("REPLAY", "STALE", "EXPIRED")) else 400,
        ) from exc


def run_graph_ops_reality_check_from_studio(
    root: Path, payload: dict[str, Any]
) -> dict[str, Any]:
    """Consume one local authorization to re-run one sealed Reality Check."""
    if set(payload) != {"authorization"} or not isinstance(
        payload.get("authorization"), str
    ):
        raise StudioRequestError(
            "GRAPH_AUTHORIZATION_INVALID",
            "execution request must contain exactly authorization",
        )
    try:
        return run_authorized_reality_check(root, Path(payload["authorization"]))
    except GraphAuthorizationError as exc:
        raise StudioRequestError(
            exc.code,
            str(exc),
            409
            if exc.code.endswith(
                ("REPLAY", "STALE", "EXPIRED", "EXECUTABLE", "IN_PROGRESS")
            )
            else 400,
        ) from exc


def _studio_html(token: str) -> str:
    target_buttons = "".join(
        f'''<label class="target"><input type="radio" name="target" value="{key}" {"checked" if key == "web" else ""}>
<span><strong>{value["label"]}</strong><small>{value["summary"]}</small></span></label>'''
        for key, value in TARGETS.items()
    )
    target_inventory_json = json.dumps(TARGETS, separators=(",", ":"))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Factory Studio</title><link rel="icon" href="/favicon.ico">
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#5f6b7a; --line:#d8e0e8; --blue:#1d4ed8; --green:#166534; --orange:#c2410c; --paper:#f4f7fa; }}
* {{ box-sizing:border-box; }} body {{ margin:0; font-family:Inter,ui-sans-serif,system-ui,sans-serif; line-height:1.65; color:var(--ink); background:var(--paper); }}
.topbar {{ height:64px; display:flex; align-items:center; justify-content:space-between; padding:0 5vw; color:white; background:#111827; }}
.topbar span {{ color:#93c5fd; font-size:16px; }} main {{ width:min(1180px,90vw); margin:0 auto; padding:38px 0 64px; }}
.intro {{ display:grid; grid-template-columns:1fr auto; gap:24px; align-items:end; padding-bottom:28px; border-bottom:1px solid var(--line); }}
.eyebrow {{ margin:0; color:var(--blue); font-size:16px; font-weight:800; }} h1 {{ margin:8px 0 0; font-size:38px; letter-spacing:0; }}
.boundary {{ padding:14px 16px; border-left:4px solid var(--green); background:#ecfdf5; font-size:16px; }}
form {{ margin-top:30px; display:grid; gap:24px; }} fieldset {{ border:0; padding:0; margin:0; }} legend,label {{ font-weight:700; }}
.modes {{ display:inline-flex; gap:4px; padding:4px; border:1px solid var(--line); border-radius:8px; background:white; }}
.mode {{ padding:10px 14px; border-radius:5px; color:var(--ink); background:transparent; }} .mode.active {{ color:white; background:var(--blue); }}
.hidden {{ display:none!important; }}
.targets {{ margin-top:10px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
.target {{ min-height:126px; display:flex; gap:10px; padding:16px; border:1px solid var(--line); border-radius:8px; background:white; cursor:pointer; }}
.target:has(input:checked) {{ border-color:var(--blue); box-shadow:inset 0 0 0 1px var(--blue); }} .target small {{ display:block; margin-top:8px; color:var(--muted); line-height:1.6; font-weight:400; }}
.inputs {{ display:grid; grid-template-columns:2fr repeat(3,minmax(0,1fr)); gap:16px; }} .field {{ display:grid; gap:8px; }}
input[type=text],input[type=number],select,textarea {{ width:100%; border:1px solid #94a3b8; border-radius:6px; padding:12px; background:white; color:var(--ink); font:inherit; }}
textarea {{ min-height:180px; resize:vertical; }} button {{ justify-self:start; border:0; border-radius:6px; padding:13px 18px; color:white; background:var(--green); font-weight:800; cursor:pointer; }}
button {{ transition:transform .15s ease,box-shadow .15s ease,background-color .15s ease; }} button:hover:not(:disabled) {{ transform:translateY(-1px); box-shadow:0 5px 14px rgba(15,23,42,.14); }}
button:disabled {{ opacity:.55; cursor:wait; }} #result {{ min-height:48px; padding:16px; border:1px solid var(--line); border-radius:8px; background:white; white-space:pre-wrap; font:16px/1.65 ui-monospace,SFMono-Regular,Consolas,monospace; }}
.error {{ color:#991b1b; border-color:#fecaca!important; background:#fff1f2!important; }}
.decision-bar {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }} .decision-bar button {{ padding:9px 12px; }}
.decision-bar .defer {{ color:#78350f; background:#fef3c7; }} .decision-bar .reject {{ color:#991b1b; background:#fee2e2; }}
.result-title {{ margin:0 0 8px; font:700 16px/1.4 Inter,ui-sans-serif,system-ui,sans-serif; }}
.result-row {{ margin:6px 0; color:var(--muted); font:16px/1.6 Inter,ui-sans-serif,system-ui,sans-serif; }}
.resolution-list {{ display:grid; gap:8px; margin-top:12px; }} .resolution-item {{ padding:10px; border-left:3px solid var(--orange); background:#fff7ed; font:16px/1.6 Inter,ui-sans-serif,system-ui,sans-serif; }}
.dashboard {{ margin-top:24px; padding:28px 0; }} .stats {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
.stat {{ min-height:104px; padding:16px; border:1px solid var(--line); border-radius:8px; background:white; }} .stat small {{ display:block; color:var(--muted); }} .stat strong {{ display:block; margin-top:10px; font-size:25px; }}
.dash-grid {{ display:grid; grid-template-columns:1.2fr 1fr; gap:16px; margin-top:16px; }} .panel {{ padding:18px; border:1px solid var(--line); border-radius:8px; background:white; }} .panel h2 {{ margin:0 0 12px; font-size:18px; }}
.data-list {{ display:grid; gap:8px; }} .data-row {{ display:flex; justify-content:space-between; gap:16px; padding:9px 0; border-bottom:1px solid #edf1f5; color:var(--muted); font-size:16px; }} .data-row strong {{ color:var(--ink); text-align:right; }}
.data-row-actions {{ align-items:center; }} .mini-actions {{ display:flex; flex-wrap:wrap; justify-content:flex-end; gap:6px; }} .mini-actions button {{ padding:7px 9px; font-size:16px; }}
.empty-data {{ color:var(--muted); font-size:16px; }} .wide-panel {{ grid-column:1/-1; }}
.live-dot {{ display:inline-block; width:8px; height:8px; margin-right:7px; border-radius:50%; background:#22c55e; }}
.memory-studio-flow {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin-top:14px; }} .memory-studio-step {{ min-height:104px; padding:12px; border:1px solid #b9cbe0; border-radius:9px; background:linear-gradient(145deg,#f8fbff,#eef5ff); }} .memory-studio-step[data-state="blocking"] {{ border-color:#fca5a5; background:#fff1f2; }} .memory-studio-step[data-state="required"],.memory-studio-step[data-state="review"] {{ border-color:#f5c46a; background:#fffbeb; }} .memory-studio-step[data-state="ready"] {{ border-color:#86d2a5; background:#ecfdf5; }} .memory-studio-step strong,.memory-studio-step span {{ display:block; }} .memory-studio-step span {{ margin-top:6px; color:var(--muted); font-size:16px; line-height:1.6; }} .memory-studio-actions {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; margin-top:12px; }} .memory-studio-action {{ padding:12px; border:1px solid #bfdbfe; border-left:4px solid #3b82f6; border-radius:8px; background:#f8fbff; }} .memory-studio-action[data-severity="blocking"] {{ border-color:#fca5a5; border-left-color:#dc2626; background:#fff1f2; }} .memory-studio-action[data-severity="required"],.memory-studio-action[data-severity="review"] {{ border-color:#f5c46a; border-left-color:#d97706; background:#fffbeb; }} .memory-studio-action[data-severity="ready"] {{ border-color:#86d2a5; border-left-color:#15803d; background:#ecfdf5; }} .memory-studio-action strong,.memory-studio-action span {{ display:block; }} .memory-studio-action span {{ margin-top:5px; color:var(--muted); font-size:16px; line-height:1.6; }} .memory-studio-team {{ margin-top:12px; padding:12px; border-radius:8px; background:#f8fafc; color:var(--muted); font-size:16px; }}
@media(max-width:900px) {{ .targets {{ grid-template-columns:1fr 1fr; }} .inputs {{ grid-template-columns:1fr; }} .intro {{ grid-template-columns:1fr; }} }}
@media(max-width:900px) {{ .stats {{ grid-template-columns:1fr 1fr; }} .dash-grid {{ grid-template-columns:1fr; }} .memory-studio-flow,.memory-studio-actions {{ grid-template-columns:1fr 1fr; }} }}
@media(max-width:560px) {{ .targets,.stats,.memory-studio-flow,.memory-studio-actions {{ grid-template-columns:1fr; }} h1 {{ font-size:31px; }} }}
[hidden] {{ display:none !important; }}
.panel,.field,fieldset {{ min-width:0; }} .data-row {{ overflow-wrap:anywhere; }}
@media(max-width:560px) {{ .topbar {{ min-height:64px; height:auto; flex-wrap:wrap; gap:8px; padding:12px 5vw; }} .modes {{ display:flex; flex-wrap:wrap; max-width:100%; }} .data-row {{ flex-wrap:wrap; }} }}
:focus-visible {{ outline:3px solid #166534; outline-offset:3px; }} .empty-data {{ max-width:75ch; }}
</style></head><body>
<header class="topbar"><strong>Factory Studio</strong><span id="surface-label">Local target compiler</span><a href="/graph-ops" style="color:#dbeafe;font-weight:800">Graph Ops</a></header>
<main data-marker="FACTORY_DUAL_TRACK_START GRAPH_OPS_UNIFIED_READ_ONLY"><section class="intro"><div><p class="eyebrow" id="workflow-label">INSTANT MVP TO PROFESSIONAL PROOF</p><h1 id="workflow-title">Describe the outcome. Get a local MVP.</h1></div><div class="boundary">Loopback only. No publish, deploy, signing, credentials, connectors, or external messages.</div></section>
<div class="modes" role="tablist"><button class="mode" id="starter-mode" type="button">Instant MVP</button><button class="mode active" id="dashboard-mode" type="button">Professional workflow</button><button class="mode" id="assembly-mode" type="button">Assembly</button><button class="mode" id="savings-mode" type="button">Savings</button><button class="mode" id="mission-mode" type="button">Product mission</button></div>
<section id="dashboard" class="dashboard"><div class="stats"><div class="stat"><small>Stages measured</small><strong id="stat-stages">not available</strong></div><div class="stat"><small>First-pass gates</small><strong id="stat-first-pass">not available</strong></div><div class="stat"><small>Runs observed</small><strong id="stat-runs">not available</strong></div><div class="stat"><small>Flow efficiency</small><strong id="stat-flow">not available</strong></div></div><div class="dash-grid"><div class="panel wide-panel"><h2>Professional workflow</h2><p class="empty-data">Inspect the <a href="/graph-ops">read-only Graph Ops map</a>, compile Product Missions, reuse verified proofs, apply policy and assurance controls, then keep release decisions human-owned. The same artifacts can graduate from a first MVP into team and enterprise workflows.</p></div><div class="panel"><h2><span class="live-dot"></span>Live factory activity</h2><div id="activity-list" class="data-list"></div></div><div class="panel wide-panel" aria-labelledby="context-value-title"><h2 id="context-value-title">Context engine: measured user value</h2><p class="empty-data">Target: 50% less total elapsed time with acceptance checks preserved. Preparation and repair count toward the result. Operator-recorded comparisons are unverified until independently validated.</p><div id="context-value-list" class="data-list" aria-live="polite"></div><p id="context-value-next" class="empty-data"></p></div><div class="panel"><h2>Paired savings</h2><div id="savings-list" class="data-list"></div></div><div class="panel"><h2>Human approval inbox</h2><div id="approval-list" class="data-list"></div></div><div class="panel wide-panel"><h2>Product Graph and journey map</h2><div id="product-list" class="data-list"></div></div><div class="panel"><h2>Dependency-aware slice queue</h2><div id="slice-list" class="data-list"></div></div><div class="panel"><h2>Mission board</h2><div id="mission-list" class="data-list"></div></div><div class="panel wide-panel"><h2>Proof timeline: requirement to receipt</h2><div id="proof-list" class="data-list"></div></div><div class="panel"><h2>Current vs previous run</h2><div id="comparison-list" class="data-list"></div></div><div class="panel"><h2>Capability Pack trust</h2><div id="pack-list" class="data-list"></div></div><div class="panel"><h2>Deployment routes</h2><div id="deployment-list" class="data-list"></div></div><div class="panel"><h2>Authority boundary</h2><div id="authority-list" class="data-list"></div></div></div></section>
<section id="assembly" class="dashboard hidden"><div class="panel"><h2>Continue an assembly</h2><p class="empty-data">Runs safe local stages, then stops with one explicit human action. Leave feature blank only when exactly one is discoverable.</p><label class="field">Feature<input id="assembly-feature" type="text" maxlength="80" placeholder="feature-name (optional)"></label><button id="assembly-continue" type="button">Continue to next boundary</button><div id="assembly-result" role="status">No continuation started.</div></div></section>
<section id="savings" class="dashboard hidden"><div class="panel"><h2>Record paired savings</h2><p class="empty-data">Compare exact baseline and Factory observations. Productivity stays unavailable unless you explicitly assert equivalent outcomes and provide a validation receipt beneath this workspace.</p><div class="inputs"><label class="field">Pair ID<input id="savings-pair" type="text" maxlength="80" placeholder="checkout-2026-07-25"></label><label class="field">Baseline ms<input id="baseline-ms" type="number" min="1"></label><label class="field">Factory ms<input id="factory-ms" type="number" min="1"></label><label class="field">Evidence path<input id="savings-evidence" type="text" placeholder=".factory/receipts/validation.json"></label></div><div class="inputs"><label class="field">Baseline tokens<input id="baseline-tokens" type="number" min="0"></label><label class="field">Factory tokens<input id="factory-tokens" type="number" min="0"></label><label class="field">Baseline cost USD<input id="baseline-cost" type="number" min="0" step="0.0001"></label><label class="field">Factory cost USD<input id="factory-cost" type="number" min="0" step="0.0001"></label></div><label class="field"><span><input id="equivalent-outcome" type="checkbox"> Outcomes are equivalent and the evidence file proves it</span></label><button id="savings-record" type="button">Record exact pair</button><div id="savings-result" role="status">No pair recorded.</div></div></section>
<form id="builder" class="hidden"><fieldset id="target-fieldset"><legend>Target</legend><div class="targets">{target_buttons}</div></fieldset>
<div class="inputs"><label class="field">Project name<input id="name" type="text" maxlength="48" placeholder="derived from intent"></label><label class="field starter-only">Purpose<select id="purpose"><option>auto</option><option>developer</option><option>healthcare</option><option>fintech</option><option>marketplace</option><option>saas</option></select></label><label class="field starter-only">Trigger<select id="trigger"><option>manual</option><option>cron</option><option>hook</option><option>goal</option><option>heartbeat</option></select></label><label class="field starter-only">Deployment route<select id="deployment-profile"></select></label><label class="field mission-only hidden">Executor<select id="executor"><option>manual</option><option>codex</option><option>copilot</option><option>claude</option><option>custom</option></select></label><label class="field mission-only hidden">Mission owner<input id="owner" type="text" maxlength="120" value="local-studio-user"></label><label class="field mission-only hidden">Resolution mode<select id="resolution-mode"><option value="human_approval">Human approval</option><option value="auto_resolve_safe">Auto-resolve safe gaps</option></select></label></div>
<div id="deployment-detail" class="boundary starter-only"></div>
<label class="field">Intent<textarea id="prompt" maxlength="60000" required placeholder="Describe the worker, app, mobile experience, or operator workflow."></textarea></label>
<button id="compile" type="submit">Compile starter</button><div id="result" role="status">Ready. Generated targets begin blocked until their proof gates pass.</div></form></main>
<script>
const token={json.dumps(token)}; const targetInventory={target_inventory_json}; const form=document.getElementById('builder'); const dashboard=document.getElementById('dashboard'); const assembly=document.getElementById('assembly'); const savings=document.getElementById('savings'); const result=document.getElementById('result'); const button=document.getElementById('compile'); let mode='dashboard'; let currentMission=null;
function updateDeploymentProfiles(){{const target=new FormData(form).get('target')||'web';const profiles=targetInventory[target].deployment_profiles;const select=document.getElementById('deployment-profile');const previous=select.value;select.textContent='';profiles.forEach((profile,index)=>{{const option=document.createElement('option');option.value=profile.id;option.textContent=`${{profile.label}} (${{profile.approval}})`;option.selected=profile.id===previous||(!previous&&index===0);select.appendChild(option);}});updateDeploymentDetail();}}
function updateDeploymentDetail(){{const target=new FormData(form).get('target')||'web';const selected=document.getElementById('deployment-profile').value;const profile=targetInventory[target].deployment_profiles.find(item=>item.id===selected);document.getElementById('deployment-detail').textContent=profile?`Build: ${{profile.build}} | Verify: ${{profile.verify}} | Release: ${{profile.release}} | Approval: ${{profile.approval}}`:'';}}
function setMode(next){{const mission=next==='mission';const dash=next==='dashboard';const assemblyMode=next==='assembly';const savingsMode=next==='savings';const instantMvp=next==='starter';mode=next;document.getElementById('dashboard-mode').classList.toggle('active',dash);document.getElementById('assembly-mode').classList.toggle('active',assemblyMode);document.getElementById('savings-mode').classList.toggle('active',savingsMode);document.getElementById('starter-mode').classList.toggle('active',instantMvp);document.getElementById('mission-mode').classList.toggle('active',mission);dashboard.classList.toggle('hidden',!dash);assembly.classList.toggle('hidden',!assemblyMode);savings.classList.toggle('hidden',!savingsMode);form.classList.toggle('hidden',dash||assemblyMode||savingsMode);document.getElementById('target-fieldset').classList.toggle('hidden',mission||instantMvp);document.querySelectorAll('.starter-only').forEach(el=>el.classList.toggle('hidden',mission||instantMvp));document.querySelectorAll('.mission-only').forEach(el=>el.classList.toggle('hidden',!mission));document.getElementById('surface-label').textContent=dash?'Professional evidence workflow':assemblyMode?'State-aware local assembly':savingsMode?'Exact paired measurement':mission?'Guided product plan':'Instant local MVP';document.getElementById('workflow-label').textContent=dash?'PROFESSIONAL EVIDENCE WORKFLOW':assemblyMode?'SAFE STAGES TO EXPLICIT HUMAN BOUNDARY':savingsMode?'BASELINE TO HASH-BOUND SAVINGS RECEIPT':mission?'PRD TO SUPERVISED VALUE MISSION':'OUTCOME TO CONTAINED WEB MVP';document.getElementById('workflow-title').textContent=dash?'Inspect and advance proven work.':assemblyMode?'Resume without reconstructing state.':savingsMode?'Measure savings without inventing them.':mission?'Clarify your idea. Confirm the plan.':'Describe the outcome. Get a local MVP.';button.textContent=mission?'Start PRD interview':instantMvp?'Build my MVP':'Compile starter';if(dash)refreshDashboard();}}
document.getElementById('dashboard-mode').onclick=()=>setMode('dashboard');document.getElementById('assembly-mode').onclick=()=>setMode('assembly');document.getElementById('savings-mode').onclick=()=>setMode('savings');document.getElementById('starter-mode').onclick=()=>setMode('starter');document.getElementById('mission-mode').onclick=()=>setMode('mission');const requestedMode=new URLSearchParams(location.search).get('mode');if(requestedMode==='dashboard')setMode('dashboard');else if(requestedMode==='product')setMode('mission');else if(requestedMode==='assembly')setMode('assembly');else if(requestedMode==='savings')setMode('savings');else setMode('starter');
document.getElementById('assembly-continue').onclick=async()=>{{const host=document.getElementById('assembly-result');host.textContent='Continuing safe local stages...';const response=await fetch('/api/continue',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify({{action:'continue',feature:document.getElementById('assembly-feature').value}})}});const payload=await response.json();host.textContent=response.ok?`Status: ${{payload.status}}\nFeature: ${{payload.feature}}\nNext: ${{payload.next_action?.label||'Assembly complete'}}\nReceipt: ${{payload.receipt||'dry run'}}`:`${{payload.code}}: ${{payload.message}}`;}}
document.getElementById('savings-record').onclick=async()=>{{const host=document.getElementById('savings-result');host.textContent='Recording exact pair...';const numberOrNull=id=>{{const value=document.getElementById(id).value;return value===''?null:Number(value);}};const body={{action:'savings-record',pair_id:document.getElementById('savings-pair').value,baseline_elapsed_ms:numberOrNull('baseline-ms'),factory_elapsed_ms:numberOrNull('factory-ms'),baseline_tokens:numberOrNull('baseline-tokens'),factory_tokens:numberOrNull('factory-tokens'),baseline_cost_usd:numberOrNull('baseline-cost'),factory_cost_usd:numberOrNull('factory-cost'),equivalent_outcome:document.getElementById('equivalent-outcome').checked,evidence:document.getElementById('savings-evidence').value}};const response=await fetch('/api/savings',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify(body)}});const payload=await response.json();host.textContent=response.ok?`Time saved: ${{payload.savings.time_saved_ms}} ms\nTokens saved: ${{textValue(payload.savings.tokens_saved)}}\nCost saved: ${{textValue(payload.savings.cost_saved_usd)}}\nProductivity gain: ${{payload.savings.productivity_gain_rate===null?'withheld':(payload.savings.productivity_gain_rate*100).toFixed(1)+'%'}}\nReceipt: ${{payload.receipt}}`:`${{payload.code}}: ${{payload.message}}`;}}
document.querySelectorAll('input[name="target"]').forEach(input=>input.addEventListener('change',updateDeploymentProfiles));document.getElementById('deployment-profile').addEventListener('change',updateDeploymentDetail);updateDeploymentProfiles();
function textValue(value,suffix=''){{return value===null||value===undefined?'not available':`${{value}}${{suffix}}`;}}
function rows(id,items){{const host=document.getElementById(id);host.textContent='';items.forEach(([label,value])=>{{const row=document.createElement('div');row.className='data-row';const a=document.createElement('span');a.textContent=label;const b=document.createElement('strong');b.textContent=value;row.append(a,b);host.appendChild(row);}});}}
function approvalRows(missions){{const host=document.getElementById('approval-list');host.textContent='';const pending=missions.filter(item=>item.decision==='awaiting_owner');if(!pending.length){{const empty=document.createElement('div');empty.className='empty-data';empty.textContent='No mission is waiting for an owner decision.';host.appendChild(empty);return;}}pending.forEach(item=>{{const row=document.createElement('div');row.className='data-row data-row-actions';const label=document.createElement('span');label.textContent=`${{item.id}} | ${{item.risk}} risk | ${{item.criteria}} criteria`;const actions=document.createElement('div');actions.className='mini-actions';[['approved_execution','Approve'],['deferred','Defer'],['rejected','Reject']].forEach(([decision,title])=>{{const action=document.createElement('button');action.type='button';action.textContent=title;action.onclick=()=>decideDashboardMission(item,decision);actions.appendChild(action);}});row.append(label,actions);host.appendChild(row);}});}}
function renderContextValue(value){{
const c=value||{{}};
const measured=(v,suffix='')=>typeof v==='number'&&Number.isFinite(v)?`${{v}}${{suffix}}`:'not measured';
const reduction=typeof c.observed_latency_reduction==='number'&&Number.isFinite(c.observed_latency_reduction)?`${{(c.observed_latency_reduction*100).toFixed(1)}}%`:'not measured';
rows('context-value-list',[["Stored packet integrity",c.state||'MISSING'],["Selection",c.source_selection_status||'not assessed'],["Structural evidence",c.structural_evidence_status||'not assessed'],["Evidence files / roles",`${{measured(c.deep_evidence_file_count)}} / ${{measured(c.evidence_role_count)}}`],["Missing required evidence roles",measured(c.missing_evidence_role_count)],["Reusable candidates / stale packets",`${{measured(c.reusable_packet_count)}} / ${{measured(c.stale_packet_count)}}`],["Recorded cache reuses",measured(c.cache_hits)],["Estimated context tokens",measured(c.estimated_tokens)],["Paired evaluation",c.experiment_status||'not measured'],["Paired samples",measured(c.paired_sample_count)],["Evidence level",c.experiment_evidence_level||'unverified'],["Quality / freshness",`${{c.experiment_quality_status||'UNKNOWN'}} / ${{c.experiment_freshness||'UNVERIFIED'}}`],["Operator-recorded elapsed-time reduction",reduction],["Cost delta (context minus baseline)",measured(c.observed_cost_delta,' USD')],["Token delta (context minus baseline)",measured(c.observed_token_delta,' tokens')],["Missing evidence",measured(c.missing_evidence_count)]]);
document.getElementById('context-value-next').textContent=c.next_action||'Build and verify context, then record paired runs. No measured gain is available.';
}}
async function refreshDashboard(){{try{{const response=await fetch('/api/dashboard',{{headers:{{'X-Factory-Studio-Token':token}}}});const payload=await response.json();if(!response.ok)throw new Error('dashboard unavailable');const summary=payload.meter.summary||{{}};const activity=payload.meter.activity||{{}};const flow=summary.flow||{{}};const firstPass=flow.first_pass_gate_rate?.value;document.getElementById('stat-stages').textContent=textValue(summary.stages_measured);document.getElementById('stat-first-pass').textContent=firstPass===null||firstPass===undefined?'not available':`${{(firstPass*100).toFixed(1)}}%`;document.getElementById('stat-runs').textContent=textValue(activity.runs_observed);document.getElementById('stat-flow').textContent=flow.flow_efficiency===null||flow.flow_efficiency===undefined?'not available':`${{(flow.flow_efficiency*100).toFixed(1)}}%`;const latest=activity.latest_stage;rows('activity-list',[["Latest stage",latest?`${{latest.module}}:${{latest.stage}} (${{latest.ok?'ok':'failed'}})`:'none yet'],["Agent / tool time",`${{textValue(flow.agent_ms?.value,' ms')}} / ${{textValue(flow.deterministic_tool_ms?.value,' ms')}}`],["Queue / review time",`${{textValue(flow.queue_ms?.value,' ms')}} / ${{textValue(flow.human_review_ms?.value,' ms')}}`],["Requirements / token",textValue(flow.requirements_per_token)],["Rollback rate",flow.rollback_rate===null||flow.rollback_rate===undefined?'not available':`${{(flow.rollback_rate*100).toFixed(1)}}%`],["Token / cost quality",`${{JSON.stringify(flow.token_quality||{{}})}} / ${{JSON.stringify(flow.cost_quality||{{}})}}`]]);const paired=payload.savings||{{}};rows('savings-list',[["Exact pairs",textValue(paired.pairs)],["Time saved",textValue(paired.time?.saved_total,' ms')],["Tokens saved",textValue(paired.tokens?.saved_total)],["Productivity",paired.productivity?.gain_rate===null||paired.productivity?.gain_rate===undefined?'withheld until equivalence proof':`${{(paired.productivity.gain_rate*100).toFixed(1)}}%`]]);renderContextValue(payload.context_engine);approvalRows(payload.missions);rows('product-list',payload.products.map(item=>[`${{item.project}} | ${{item.requirements}} requirements | ${{item.slice_count}} slices`,`${{item.status}} | journey: ${{item.journeys[0]||'missing'}} | gaps: ${{item.blocking_gaps}} blocking, ${{item.advisory_gaps}} advisory`]));rows('slice-list',payload.slice_queue.map(item=>[`${{item.id}} | priority ${{textValue(item.priority)}}`,`${{item.theme}} | ${{item.risk}} risk | dependencies ${{item.depends_on.length}}`]));rows('mission-list',payload.missions.map(item=>[`${{item.id}} | ${{item.decision}}`,`${{item.branch||'branch unavailable'}} | ${{item.completion}}`]));rows('proof-list',payload.proof_timeline.map(item=>[`${{item.requirement_id}} -> ${{item.slice_id}} -> ${{item.mission_id}}`,item.receipt?`receipt: ${{item.receipt}}`:`${{item.test_state}}; receipt pending`]));const compare=payload.receipt_comparison;rows('comparison-list',compare.status==='compared'?[["Run",`${{compare.previous.run_id}} -> ${{compare.current.run_id}}`],["Wall delta",`${{compare.delta.wall_ms}} ms`],["Token delta",String(compare.delta.tokens)],["Failed-stage delta",String(compare.delta.failed_stages)]]:[["Status","Two run IDs are required before comparison."]]);rows('pack-list',payload.packs.map(pack=>[`${{pack.target_kind}} ${{pack.version}}`,pack.valid&&pack.signature_verified?`verified; ${{pack.mutations_rejected}}/${{pack.mutations_attempted}} mutations rejected`:'invalid']));rows('deployment-list',payload.packs.flatMap(pack=>pack.deployment_profiles.map(profile=>[`${{pack.target_kind}}: ${{profile.label}}`,`${{profile.verify}} | approval: ${{profile.approval}}`])));rows('authority-list',[["Create starters",payload.authority.can_create_starters?'allowed':'denied'],["Record exact savings",payload.authority.can_record_exact_savings_pairs?'allowed':'denied'],["Approve bounded mission",payload.authority.can_record_mission_execution_decision?'allowed':'denied'],["Deploy / publish / sign",'denied until a route is selected and separately approved'],["Credentials / connectors / messages",'denied']]);}}catch(_error){{renderContextValue({{state:'UNAVAILABLE',next_action:'Refresh telemetry before using these results. Previous metrics have been cleared.'}});document.getElementById('stat-first-pass').textContent='telemetry unavailable';}}}}
let dashboardAutoRefresh=true;
function ensureLiveControls(){{if(document.getElementById('dashboard-refresh'))return;const panel=document.getElementById('activity-list').parentElement;const controls=document.createElement('div');controls.className='mini-actions';controls.setAttribute('aria-label','Live activity controls');const refresh=document.createElement('button');refresh.id='dashboard-refresh';refresh.type='button';refresh.textContent='Refresh now';const auto=document.createElement('button');auto.id='dashboard-auto-refresh';auto.type='button';auto.setAttribute('aria-pressed','true');auto.textContent='Auto-refresh on';const stop=document.createElement('button');stop.id='dashboard-stop';stop.type='button';stop.disabled=true;stop.textContent='Request safe stop';const result=document.createElement('div');result.id='dashboard-live-result';result.setAttribute('role','status');result.textContent='Polling local telemetry every second.';refresh.onclick=()=>refreshDashboard();auto.onclick=event=>{{dashboardAutoRefresh=!dashboardAutoRefresh;event.currentTarget.setAttribute('aria-pressed',String(dashboardAutoRefresh));event.currentTarget.textContent=dashboardAutoRefresh?'Auto-refresh on':'Auto-refresh off';}};stop.onclick=async()=>{{if(!window.confirm('Request a cooperative stop for the active local assembly? It cannot publish, deploy, sign, or contact external services.'))return;const response=await fetch('/api/activity/stop',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify({{action:'request-stop'}})}});const payload=await response.json();result.textContent=response.ok?'Stop requested. The current stage will stop at its next local heartbeat.':`${{payload.code||'STOP_FAILED'}}: ${{payload.message||'request rejected'}}`;await refreshDashboard();}};controls.append(refresh,auto,stop);panel.append(controls,result);}}
const dashboardBaseRefresh=refreshDashboard;refreshDashboard=async()=>{{await dashboardBaseRefresh();ensureLiveControls();try{{const response=await fetch('/api/dashboard',{{headers:{{'X-Factory-Studio-Token':token}}}});const payload=await response.json();if(!response.ok)throw new Error(payload.code||'dashboard unavailable');const live=payload.live_activity||{{}};const activeStage=live.current_stage?`${{live.current_stage.module}}:${{live.current_stage.stage}}`:'none';rows('activity-list',[['Operation',live.available?`${{live.status||'unknown'}} · ${{live.feature||'local workspace'}}`:'idle — no active local assembly'],['Current stage',activeStage],['Elapsed',live.elapsed_ms===null||live.elapsed_ms===undefined?'not available':`${{live.elapsed_ms}} ms`],['Completed / failed / skipped',live.available?`${{live.completed_stages||0}} / ${{live.failed_stages||0}} / ${{live.skipped_stages||0}}`:'not available'],['Latest heartbeat',live.heartbeat_at||'not available']]);document.getElementById('dashboard-stop').disabled=live.status!=='active';document.getElementById('dashboard-live-result').textContent=`Updated ${{new Date().toLocaleTimeString()}} · local telemetry only`;}}catch(error){{const result=document.getElementById('dashboard-live-result');if(result)result.textContent=`Telemetry error: ${{String(error)}}`;}}}};
function ensurePriorRunPanel(){{if(document.getElementById('previous-run-list'))return;const grid=document.querySelector('#dashboard .dash-grid');if(!grid)return;const panel=document.createElement('section');panel.className='panel';const heading=document.createElement('h3');heading.textContent='Prior measured runs';const note=document.createElement('p');note.className='muted';note.textContent='Append-only meter receipts. A recorded stage is not inferred to be a successful release.';const list=document.createElement('div');list.id='previous-run-list';list.className='data-list';panel.append(heading,note,list);grid.appendChild(panel);}}
let studioMemoryAutoRefresh=true;
function ensureStudioMemoryPanel(){{if(document.getElementById('studio-memory-actions'))return;const grid=document.querySelector('#dashboard .dash-grid');if(!grid)return;const panel=document.createElement('section');panel.className='panel wide-panel';const heading=document.createElement('h2');heading.textContent='Memory Spine: next safe proof';const note=document.createElement('p');note.className='empty-data';note.textContent='A visual, read-only explanation of what changed, why the evidence state matters, and the next smallest proof. Live telemetry refreshes every second; this brief is recalculated no more than once per five seconds.';const controls=document.createElement('div');controls.className='mini-actions';const refresh=document.createElement('button');refresh.id='studio-memory-refresh';refresh.type='button';refresh.textContent='Refresh stats and proof brief';const team=document.createElement('button');team.id='studio-team-refresh';team.type='button';team.textContent='Refresh team attribution';const auto=document.createElement('button');auto.id='studio-memory-auto';auto.type='button';auto.setAttribute('aria-pressed','true');auto.textContent='Brief auto-refresh on';const flow=document.createElement('div');flow.id='studio-memory-flow';flow.className='memory-studio-flow';const actions=document.createElement('div');actions.id='studio-memory-actions';actions.className='memory-studio-actions';const teamSummary=document.createElement('div');teamSummary.id='studio-memory-team';teamSummary.className='memory-studio-team';const status=document.createElement('p');status.id='studio-memory-status';status.className='empty-data';refresh.onclick=()=>refreshDashboard();team.onclick=()=>loadStudioMemory();auto.onclick=event=>{{studioMemoryAutoRefresh=!studioMemoryAutoRefresh;event.currentTarget.setAttribute('aria-pressed',String(studioMemoryAutoRefresh));event.currentTarget.textContent=studioMemoryAutoRefresh?'Brief auto-refresh on':'Brief auto-refresh off';}};controls.append(refresh,team,auto);panel.append(heading,note,controls,flow,actions,teamSummary,status);grid.appendChild(panel);}}
function studioMemoryStep(parent,state,title,detail){{const step=document.createElement('article');step.className='memory-studio-step';step.dataset.state=state||'review';const label=document.createElement('strong');label.textContent=title;const description=document.createElement('span');description.textContent=detail;step.append(label,description);parent.appendChild(step);}}
function renderStudioMemory(snapshot){{ensureStudioMemoryPanel();const brief=snapshot?.brief||{{}},actions=Array.isArray(brief.actions)?brief.actions:[],next=actions[0]||{{}},review=brief.change_review||{{}},team=brief.team||{{}},seats=Array.isArray(team.seats)?team.seats:[];const flow=document.getElementById('studio-memory-flow'),list=document.getElementById('studio-memory-actions');if(!flow||!list)return;flow.textContent='';const state=next.severity||'review',changed=Array.isArray(review.changed_paths)?review.changed_paths:[];studioMemoryStep(flow,review.available===false?'blocking':state,'1 · What changed',review.available===false?'Change set unavailable; no proof is inferred.':`${{changed.length}} exact path${{changed.length===1?'':'s'}} from ${{review.input_source||'unknown'}} input.`);studioMemoryStep(flow,state,'2 · Why it matters',next.why_it_matters||'No evidence state was supplied.');studioMemoryStep(flow,state,'3 · Do this next',next.do_this_next||'Refresh local facts.');studioMemoryStep(flow,team.available?'ready':'review','4 · Team contribution',team.available?`${{seats.length}} observed Git contributor${{seats.length===1?'':'s'}}; not a verified seat roster.`:'No local Git attribution is available.');list.textContent='';actions.slice(0,4).forEach(action=>{{const card=document.createElement('article');card.className='memory-studio-action';card.dataset.severity=action.severity||'review';const title=document.createElement('strong');title.textContent=action.title||action.kind||'Evidence action';const detail=document.createElement('span');detail.textContent=`What changed: ${{action.what_changed||'not supplied'}}`;const nextStep=document.createElement('span');nextStep.textContent=`Next: ${{action.do_this_next||'not supplied'}}`;card.append(title,detail,nextStep);list.appendChild(card);}});if(!actions.length){{const empty=document.createElement('span');empty.className='empty-data';empty.textContent='No action is available; Studio will not invent one.';list.appendChild(empty);}}const teamText=document.getElementById('studio-memory-team');teamText.textContent=team.available?`Observed local Git contributors: ${{seats.map(seat=>`${{seat.display_name}} (${{seat.contribution?.selected_path_commit_count??0}} selected-path commits)`).join(', ')||'none'}}. Git authorship is not seat licensing, ownership, approval, or productivity evidence.`:'Team attribution unavailable: no contributor, identity, or approval claim is made.';const cache=snapshot?.cache||{{}};const status=document.getElementById('studio-memory-status');status.textContent=`Brief ${{cache.state||'unknown'}} · cache age ${{cache.age_ms??'unknown'}} ms · refresh interval ${{cache.refresh_interval_ms??5000}} ms · local analysis only.`;}}
async function loadStudioMemory(){{ensureStudioMemoryPanel();try{{const response=await fetch('/api/developer-memory',{{headers:{{'X-Factory-Studio-Token':token}}}});const payload=await response.json();if(!response.ok)throw new Error(payload.code||'developer memory unavailable');renderStudioMemory(payload);}}catch(error){{const status=document.getElementById('studio-memory-status');if(status)status.textContent=`Developer Memory error: ${{String(error)}}. No next proof is inferred.`;}}}}
async function refreshPriorRuns(){{if(mode!=='dashboard')return;ensurePriorRunPanel();try{{const response=await fetch('/api/dashboard',{{headers:{{'X-Factory-Studio-Token':token}}}});const payload=await response.json();if(!response.ok)return;const runs=Array.isArray(payload.recent_runs)?payload.recent_runs:[];rows('previous-run-list',runs.length?runs.map(run=>[`${{run.feature||'feature unavailable'}} · ${{run.outcome}}`,`${{run.stages_recorded}} stages · ${{run.wall_ms}} ms · tokens ${{run.tokens}} (${{(run.token_quality||[]).join(', ')||'unknown'}}) · failed stages ${{run.failed_stages}}`]):[['Status','No measured run IDs have been recorded yet.']]);}}catch(_error){{}}}}
const nativeStudioFetch=window.fetch.bind(window);window.fetch=async(...args)=>{{const response=await nativeStudioFetch(...args);const url=String(args[0] instanceof Request?args[0].url:args[0]);if(url.includes('/api/dashboard'))window.__factoryDashboardPromise=response.clone().json().catch(()=>null);return response;}};
function syncDashboardLivePanels(payload){{const live=payload.live_activity||{{}};const activeStage=live.current_stage?`${{live.current_stage.module}}:${{live.current_stage.stage}}`:'none';rows('activity-list',[['Operation',live.available?`${{live.status||'unknown'}} · ${{live.feature||'local workspace'}}`:'idle — no active local assembly'],['Current stage',activeStage],['Elapsed',live.elapsed_ms===null||live.elapsed_ms===undefined?'not available':`${{live.elapsed_ms}} ms`],['Completed / failed / skipped',live.available?`${{live.completed_stages||0}} / ${{live.failed_stages||0}} / ${{live.skipped_stages||0}}`:'not available'],['Latest heartbeat',live.heartbeat_at||'not available']]);const stop=document.getElementById('dashboard-stop');if(stop)stop.disabled=live.status!=='active';const result=document.getElementById('dashboard-live-result');if(result)result.textContent=`Updated ${{new Date().toLocaleTimeString()}} · local telemetry only`;ensurePriorRunPanel();const runs=Array.isArray(payload.recent_runs)?payload.recent_runs:[];rows('previous-run-list',runs.length?runs.map(run=>[`${{run.feature||'feature unavailable'}} · ${{run.outcome}}`,`${{run.stages_recorded}} stages · ${{run.wall_ms}} ms · tokens ${{run.tokens}} (${{(run.token_quality||[]).join(', ')||'unknown'}}) · failed stages ${{run.failed_stages}}`]):[['Status','No measured run IDs have been recorded yet.']]);if(studioMemoryAutoRefresh)renderStudioMemory(payload.developer_memory);}}
refreshDashboard=async()=>{{ensureLiveControls();await dashboardBaseRefresh();const payload=await window.__factoryDashboardPromise;if(payload)syncDashboardLivePanels(payload);}};refreshPriorRuns=async()=>{{}};
setInterval(()=>{{if(mode==='dashboard'&&dashboardAutoRefresh)refreshDashboard();}},1000);refreshDashboard();
function addText(className,text){{const el=document.createElement('div');el.className=className;el.textContent=text;result.appendChild(el);return el;}}
function renderFailure(payload){{result.className='error';result.textContent='';addText('result-title',`${{payload.code||'FAILED'}} at ${{payload.failure?.point_of_failure||'workflow'}}`);addText('result-row',payload.failure?.why||payload.message||'The workflow failed.');addText('result-row',`Next: ${{payload.failure?.next_action||'Inspect the failure evidence and retry.'}}`);}}
async function decideDashboardMission(item,decision){{const rationale=window.prompt(`Rationale for ${{decision.replace('_',' ')}} on ${{item.id}}:`);if(!rationale)return;const response=await fetch('/api/mission-decision',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify({{action:'mission-decision',mission:item.path,owner:item.owner,decision,rationale}})}});const payload=await response.json();if(!response.ok){{window.alert(`${{payload.code||'FAILED'}}: ${{payload.failure?.why||payload.message}} Next: ${{payload.failure?.next_action||'inspect evidence'}}`);return;}}await refreshDashboard();}}
async function decideMission(decision){{const rationale=window.prompt(`Rationale for ${{decision.replace('_',' ')}}:`);if(!rationale)return;const response=await fetch('/api/mission-decision',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify({{action:'mission-decision',mission:currentMission,owner:document.getElementById('owner').value,decision,rationale}})}});const payload=await response.json();if(!response.ok){{renderFailure(payload);return;}}result.className='';result.textContent='';addText('result-title',decision==='approved_execution'?'Bounded execution approved':decision==='deferred'?'Mission deferred':'Mission rejected');addText('result-row',`Decision receipt: ${{payload.path}}`);addText('result-row','Merge, publish, deploy, connectors, credentials, and external messages remain unauthorized.');}}
function renderMission(payload){{result.className='';result.textContent='';if(!payload.mission){{addText('result-title','Product Graph needs human input');addText('result-row',payload.resolution.next_action);const list=document.createElement('div');list.className='resolution-list';payload.resolution.items.forEach(item=>{{const el=document.createElement('div');el.className='resolution-item';el.textContent=`${{item.code}}: ${{item.next_action}}`;list.appendChild(el);}});result.appendChild(list);addText('result-row',payload.resolution.why_auto_stopped);return;}}currentMission=payload.mission.path;addText('result-title',`Approval ready: ${{payload.mission.id}}`);addText('result-row',`Slice ${{payload.mission.slice_id}} | Risk ${{payload.approval.risk}} | Owner ${{payload.approval.owner}}`);addText('result-row',`Budget: ${{payload.approval.budgets.max_iterations}} iterations, ${{payload.approval.budgets.max_wall_seconds}}s, ${{payload.approval.budgets.max_tokens}} tokens, $${{payload.approval.budgets.max_cost_usd}}`);addText('result-row',`${{payload.approval.completion_criteria.length}} completion criteria require independent evidence.`);const bar=document.createElement('div');bar.className='decision-bar';[['approved_execution','Approve execution',''],['deferred','Defer','defer'],['rejected','Reject','reject']].forEach(([value,label,kind])=>{{const b=document.createElement('button');b.type='button';b.className=kind;b.textContent=label;b.onclick=()=>decideMission(value);bar.appendChild(b);}});result.appendChild(bar);addText('result-row','Approval authorizes only the bounded executor; release effects stay human-owned.');}}
let guidedSession=null, guidedConfirmation=null, guidedDraft=null, guidedBusy=false, guidedGeneration=0;
function guidedButton(label,action){{const control=document.createElement('button');control.type='button';control.textContent=label;control.onclick=action;result.appendChild(control);return control;}}
function validateGuidedAnswer(input){{if(input.value.trim())return true;input.setCustomValidity('Choose an answer or write your own before continuing.');input.focus();input.reportValidity();return false;}}
function guidedStepper(answers,save){{let active=0;const progress=document.createElement('p');progress.className='result-row';progress.setAttribute('aria-live','polite');result.insertBefore(progress,answers[0].field);const back=guidedButton('Back',()=>show(active-1));const next=guidedButton('Next question',()=>{{if(validateGuidedAnswer(answers[active].input))show(active+1);}});function show(index){{active=index;answers.forEach((row,i)=>row.field.hidden=i!==active);progress.textContent=`Question ${{active+1}} of ${{answers.length}} in this step`;back.hidden=active===0;next.hidden=active===answers.length-1;save.hidden=active!==answers.length-1;}}show(0);}}
function guidedAnswerOptions(question){{const choices={{
'Q-REQUIREMENTS':['REQ-CORE: The user must create, view, edit, and delete their own records.','REQ-CORE: The user must submit an input and receive a reviewable result.','REQ-CORE: The operator must review a prioritized list and export a selected report.'],
'Q-ACTORS':['User: performs the main task. Owner: approves irreversible actions.','Operator: reviews results. Reviewer: independently checks evidence. Owner: approves release.','Workspace member: manages their own records. Administrator: manages access.'],
'Q-OUTCOMES':['The primary user completes the main task within five minutes; validate this target with users.','At least 9 of 10 trial users complete the primary task without assistance; measure before claiming success.','Record task completion and errors first; the target remains undecided until a baseline is measured.'],
'Q-JOURNEY':['Journey: User opens the app, provides an input, reviews the result, and confirms completion.','Journey: Operator opens the dashboard, selects an item, reviews its evidence, and exports a local report.'],
'Q-ACCEPTANCE':['Scenario: Complete the primary task\\n  Given a signed-in user with permission\\n  When the user submits valid input\\n  Then the expected result is visible and saved','Scenario: Reject invalid input\\n  Given a user completing the primary form\\n  When required input is missing\\n  Then the app explains the error and preserves the draft'],
'Q-DATA-OWNERSHIP':['The workspace owner controls data retention, export, and deletion; users can export their own data.','The individual user owns their records and controls export and deletion; retention must be agreed before release.'],
'Q-TRUST':['Trust boundary: authenticated users can access only records in their own workspace.','Trust boundary: data stays on the local device; network access requires explicit approval.'],
'Q-APPROVAL':['Publishing, deployment, deletion, payments, credentials, and external messages require human approval.','This first release only reads local data; any future external or destructive action requires separate human approval.'],
'Q-SUCCESS-EVENT':['task_completed: record completion, elapsed time, and errors within the selected workspace.','report_exported: record a successful local export and its elapsed time without logging private report contents.']
}};if(question.id.startsWith('Q-UX-')){{const state=question.id.slice(5).toLowerCase();const states={{loading:['Show progress and keep the layout stable.','Show the current step and offer cancellation where safe.'],empty:['Explain how to add the first item.','Show a clearly labelled example and a button to create a real item.'],error:['Preserve the draft, explain the problem, and offer retry.','Keep the last safe result and provide a safe recovery action.'],success:['Confirm what completed and show the next useful action.','Show the saved result and how to review or undo it where possible.'],permission:['Explain the required role and how to request access.','Hide private data and provide a safe route back.'],offline:['Preserve read-only cached data and explain how to reconnect.','Preserve the draft locally and require reconnection before submission.'],recovery:['Resume the interrupted action without duplication.','Restore the last safe draft and require confirmation before retry.'],accessibility:['Expose control names, roles, keyboard focus order, and status announcements.','Support keyboard operation, visible focus, readable contrast, and associated form errors.']}};return (states[state]||['Explain the current state and the next safe action.']).map(answer=>`${{state}}: ${{answer}}`);}}return choices[question.id]||['This decision needs clarification from the product owner before implementation.'];}}
function guidedAnswerFormat(question){{if(question.id==='Q-ACTORS')return ' Use Role: responsibility, for example Operator: reviews signals.';if(question.id.startsWith('Q-UX-'))return ` Begin with ${{question.id.slice(5).toLowerCase()}}: followed by the visible state and next safe action.`;return '';}}
async function sendGuided(body){{if(guidedBusy)return null;guidedBusy=true;const generation=guidedGeneration,requestedMode=mode;button.disabled=true;const controls=[...result.querySelectorAll('button')];controls.forEach(control=>control.disabled=true);try{{const response=await fetch('/api/product-grill',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify(body)}});const payload=await response.json();if(generation!==guidedGeneration||mode!==requestedMode)return null;if(!response.ok){{renderFailure(payload);return null;}}return payload;}}catch(error){{if(generation===guidedGeneration&&mode===requestedMode)renderFailure({{code:'NETWORK_ERROR',message:String(error)}});return null;}}finally{{guidedBusy=false;button.disabled=false;controls.forEach(control=>control.disabled=false);}}}}
function renderGuided(payload){{guidedSession=payload.session;guidedConfirmation=null;guidedDraft=payload;currentMission=null;result.className='';result.textContent='';addText('result-title',payload.status==='ready_for_confirmation'?'Review your PRD before confirming':'Clarify your product, one decision at a time');addText('result-row','Choose a starting point, then edit it to fit your app. Choices are examples, not verified facts. Your answers become the PRD; confirmation does not approve execution or release.');const preview=document.createElement('details');preview.open=payload.status==='ready_for_confirmation';const summary=document.createElement('summary');summary.textContent='Review the exact current PRD';const source=document.createElement('pre');source.style.whiteSpace='pre-wrap';source.style.overflowWrap='anywhere';source.textContent=payload.source_text;preview.append(summary,source);result.appendChild(preview);addText('result-row',`PRD SHA-256: ${{payload.source_sha256}}`);const answers=[];payload.questions.forEach((question,index)=>{{const field=document.createElement('div');field.className='field';const label=document.createElement('label');const input=document.createElement('textarea');input.id=`guided-answer-${{index}}`;input.maxLength=2000;label.htmlFor=input.id;label.textContent=question.title;const explanation=document.createElement('p');explanation.className='result-row';explanation.textContent=question.prompt;const hint=document.createElement('p');hint.className='result-row';hint.textContent=`Suggested starting point: ${{question.recommendation}}${{guidedAnswerFormat(question)}}`;input.setAttribute('aria-describedby',`guided-hint-${{index}}`);hint.id=`guided-hint-${{index}}`;const choiceLabel=document.createElement('label');const choice=document.createElement('select');choice.id=`guided-choice-${{index}}`;choiceLabel.htmlFor=choice.id;choiceLabel.textContent='Choose a starting point or write your own';const custom=document.createElement('option');custom.value='';custom.textContent='Custom answer / edit a choice';choice.appendChild(custom);guidedAnswerOptions(question).forEach((answer,optionIndex)=>{{const option=document.createElement('option');option.value=String(optionIndex);option.textContent=answer;choice.appendChild(option);}});choice.setAttribute('aria-describedby',hint.id);choice.onchange=()=>{{if(choice.value!=='')input.value=guidedAnswerOptions(question)[Number(choice.value)];input.setCustomValidity('');input.focus();}};input.addEventListener('input',()=>{{choice.value='';input.setCustomValidity('');}});field.append(label,explanation,hint,choiceLabel,choice,input);result.appendChild(field);answers.push({{question,input,field}});}});if(payload.deferred_questions.length)addText('result-row',`${{payload.deferred_questions.length}} dependent questions will follow after these decisions.`);if(answers.length){{const save=guidedButton('Save my answers',async()=>{{const invalid=answers.find(row=>!row.input.value.trim());if(invalid){{invalid.field.hidden=false;validateGuidedAnswer(invalid.input);return;}}const rows=answers.filter(row=>row.input.value.trim()).map(row=>({{question_id:row.question.id,answer:row.input.value}}));if(!rows.length){{answers[0].input.focus();answers[0].input.setCustomValidity('Write at least one answer.');answers[0].input.reportValidity();answers[0].input.oninput=()=>answers[0].input.setCustomValidity('');return;}}const next=await sendGuided({{action:'product-grill-answer',session_path:guidedSession.path,session_sha256:guidedSession.session_sha256,answers:rows}});if(next)renderGuided(next);}});guidedStepper(answers,save);}}else if(payload.status==='ready_for_confirmation')guidedButton('Confirm this PRD',confirmGuided);else if(payload.status==='deep_review_required')guidedButton('Continue with deeper questions',async()=>{{const next=await sendGuided({{action:'product-grill-start',prompt:payload.source_text,name:document.getElementById('name').value,mode:'deep'}});if(next)renderGuided(next);}});result.scrollIntoView({{block:'start'}});}}
async function confirmGuided(){{const payload=await sendGuided({{action:'product-grill-confirm',session_path:guidedSession.path,session_sha256:guidedSession.session_sha256,confirmed:true}});if(!payload)return;guidedConfirmation=payload.confirmation;result.textContent='';addText('result-title','PRD confirmed. Prepare the first mission.');addText('result-row',`Confirmed PRD: ${{payload.source_sha256}}`);addText('result-row','The next step prepares a bounded mission for separate execution approval.');guidedButton('Compile reviewed PRD',compileGuided);}}
async function compileGuided(){{const payload=await sendGuided({{action:'product-guided-compile',confirmation_path:guidedConfirmation.path,confirmation_sha256:guidedConfirmation.sha256,owner:document.getElementById('owner').value,executor:document.getElementById('executor').value,resolution_mode:document.getElementById('resolution-mode').value}});if(payload)renderMission(payload);}}
['prompt','name'].forEach(id=>document.getElementById(id).addEventListener('input',()=>{{guidedGeneration++;guidedSession=null;guidedConfirmation=null;guidedDraft=null;if(mode==='mission'){{result.textContent='Draft changed. Start the PRD interview again before confirming.';currentMission=null;}}}}));
form.addEventListener('submit',async(event)=>{{event.preventDefault();button.disabled=true;result.className='';result.textContent=mode==='mission'?'Preparing your PRD questions...':'Compiling locally...';
const target=new FormData(form).get('target'); const body=mode==='mission'?{{action:'product-grill-start',prompt:document.getElementById('prompt').value,name:document.getElementById('name').value,mode:'deep'}}:{{action:'create',target,prompt:document.getElementById('prompt').value,name:document.getElementById('name').value,purpose:document.getElementById('purpose').value,trigger:document.getElementById('trigger').value,deployment_profile:document.getElementById('deployment-profile').value}};
try{{if(mode==='mission'){{guidedGeneration++;const payload=await sendGuided(body);if(payload)renderGuided(payload);return;}}const response=await fetch('/api/create',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify(body)}});const payload=await response.json();if(!response.ok){{renderFailure(payload);return;}}result.textContent=`Compiled ${{payload.target_kind}}\n${{payload.out_dir}}\nDeployment: ${{payload.deployment.profile.label}}\nApproval: ${{payload.deployment.profile.approval}}\nExternal effects authorized: ${{payload.deployment.external_effects_authorized}}\nReceipt: ${{payload.receipt}}\nState: ${{payload.status}}`;}}
catch(error){{renderFailure({{code:'NETWORK_ERROR',message:String(error)}});}}finally{{button.disabled=false;}}}});
</script></body></html>"""


class _StudioHandler(BaseHTTPRequestHandler):
    server_version = "FactoryStudio/1"
    studio_root = Path(".")
    studio_token = ""
    status_payload: dict[str, Any] = {}

    def _headers(self, status: int, content_type: str, content_length: int = 0) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()

    def _json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _error(self, status: int, code: str, message: str) -> None:
        self._json(
            status,
            {
                "schema": "factory.studio.error.v1",
                "code": code,
                "message": message,
                "failure": explain_failure(code, message),
            },
        )

    def _has_valid_token(self) -> bool:
        return secrets.compare_digest(
            self.headers.get("X-Factory-Studio-Token", ""), self.studio_token
        )

    def _serve_favicon(self) -> None:
        self._headers(204, "image/x-icon")

    def _serve_html(self, renderer: Callable[[str], str]) -> None:
        body = renderer(self.studio_token).encode("utf-8")
        self._headers(200, "text/html; charset=utf-8", len(body))
        self.wfile.write(body)

    def _serve_status(self) -> None:
        payload = dict(self.status_payload)
        payload["listener"] = {**payload["listener"], "port": self.server.server_port}
        self._json(200, payload)

    def _serve_token_json(self, operation: Callable[[Path], dict[str, Any]]) -> None:
        if not self._has_valid_token():
            self._error(403, "TOKEN_REQUIRED", "valid Studio session token required")
            return
        self._json(200, operation(self.studio_root))

    def _graph_ops_payload(self, root: Path) -> dict[str, Any]:
        payload = graph_ops_snapshot(root)
        payload["live_telemetry"] = {
            "activity": activity_snapshot(root),
            "meter": live_snapshot(root),
            "recent_runs": _recent_run_stats(root, limit=3),
            "refresh_interval_ms": 1000,
            "scope_limits": [
                "Live telemetry is local and aggregate-safe.",
                "Unknown usage, cost, queue, and productivity values remain unavailable.",
            ],
        }
        return payload

    def _get_route_handler(self) -> Callable[[], None] | None:
        if self.path == "/favicon.ico":
            return self._serve_favicon
        page_routes = {"/": _studio_html, "/graph-ops": graph_ops_html}
        renderer = page_routes.get(self.path.split("?", 1)[0])
        if renderer is not None:
            return lambda: self._serve_html(renderer)
        api_routes: dict[str, Callable[[], None]] = {
            "/api/status": self._serve_status,
            "/api/dashboard": lambda: self._serve_token_json(studio_dashboard),
            "/api/savings": lambda: self._serve_token_json(public_savings_report),
            "/api/developer-memory": lambda: self._serve_token_json(
                developer_memory_snapshot
            ),
            "/api/graph-ops": lambda: self._serve_token_json(self._graph_ops_payload),
            "/api/test-report": lambda: self._serve_token_json(read_junit_report),
            "/api/coverage-report": lambda: self._serve_token_json(
                lambda root: read_runtime_coverage_report(root, include_files=True)
            ),
        }
        return api_routes.get(self.path)

    def do_GET(self) -> None:
        """Serve only the Studio shell and its public boundary status."""
        handler = self._get_route_handler()
        if handler is None:
            self._error(404, "NOT_FOUND", "route not found")
            return
        handler()

    def _content_length(self) -> int | None:
        try:
            return int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(400, "LENGTH_INVALID", "invalid content length")
            return None

    def _is_post_route(self) -> bool:
        return self.path in {
            "/api/create",
            "/api/product",
            "/api/product-grill",
            "/api/mission-decision",
            "/api/continue",
            "/api/savings",
            "/api/graph-ops-authorize",
            "/api/graph-ops-run",
            "/api/activity/stop",
        }

    def _drain_rejected_body(self, content_length: int) -> None:
        if 0 < content_length <= MAX_BODY_BYTES:
            self.connection.settimeout(UNAUTHORIZED_DRAIN_TIMEOUT_SECONDS)
            try:
                self.rfile.read(content_length)
            except (TimeoutError, socket.timeout, OSError):
                pass

    def _reject_unauthorized_post(self) -> None:
        rejected_length = self._content_length()
        if rejected_length is None:
            self.close_connection = True
            return
        self._drain_rejected_body(rejected_length)
        self.close_connection = True
        self._error(403, "TOKEN_REQUIRED", "valid Studio session token required")

    def _read_post_payload(self) -> dict[str, Any] | None:
        length = self._content_length()
        if length is None:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            self.close_connection = True
            self._error(413, "BODY_LIMIT", f"body must be 1-{MAX_BODY_BYTES} bytes")
            return None
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise StudioRequestError(
                "JSON_OBJECT_REQUIRED", "request must be a JSON object"
            )
        return payload

    def _stop_activity_from_studio(self, payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("action") != "request-stop":
            raise StudioRequestError(
                "ACTION_UNSUPPORTED", "activity stop endpoint requires request-stop"
            )
        try:
            return request_stop(self.studio_root)
        except ValueError as exc:
            raise StudioRequestError("NO_ACTIVE_ASSEMBLY", str(exc), 409) from exc

    def _dispatch_post_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.path == "/api/activity/stop":
            return self._stop_activity_from_studio(payload)
        handlers: dict[str, Callable[[Path, dict[str, Any]], dict[str, Any]]] = {
            "/api/create": create_from_studio,
            "/api/product": create_product_mission_from_studio,
            "/api/product-grill": product_grill_from_studio,
            "/api/mission-decision": decide_product_mission_from_studio,
            "/api/continue": continue_from_studio,
            "/api/savings": savings_from_studio,
            "/api/graph-ops-authorize": authorize_graph_ops_from_studio,
            "/api/graph-ops-run": run_graph_ops_reality_check_from_studio,
        }
        return handlers[self.path](self.studio_root, payload)

    def do_POST(self) -> None:
        """Accept one token-bound target creation request within the size limit."""
        if not self._is_post_route():
            self.close_connection = True
            self._error(404, "NOT_FOUND", "route not found")
            return
        if not self._has_valid_token():
            # Consume only a bounded, well-framed request body before closing.
            # Otherwise Windows may reset a socket that still has unread data,
            # hiding the deterministic 403 response from the client.
            self._reject_unauthorized_post()
            return
        try:
            payload = self._read_post_payload()
            if payload is None:
                return
            result = self._dispatch_post_payload(payload)
        except StudioRequestError as exc:
            self._json(
                exc.status,
                {
                    "schema": "factory.studio.error.v1",
                    "code": exc.code,
                    "message": exc.message,
                    "failure": exc.guidance,
                },
            )
            return
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, "JSON_INVALID", "request body must be valid UTF-8 JSON")
            return
        except Exception as exc:
            self._error(
                500,
                "INTERNAL_ERROR",
                f"{type(exc).__name__}: request failed before an artifact was committed",
            )
            return
        self._json(201, result)

    def log_message(self, format: str, *args: object) -> None:
        """Suppress the default request log so request data stays out of stdout."""
        return


def make_handler(root: Path, token: str) -> type[BaseHTTPRequestHandler]:
    """Bind immutable root and session data to a request handler class."""
    return type(
        "StudioHandler",
        (_StudioHandler,),
        {
            "studio_root": root,
            "studio_token": token,
            "status_payload": studio_status(root, 0),
        },
    )


def create_server(root: Path, port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Create a loopback-only threaded development server and session token."""
    if port < 0 or port > 65535:
        raise StudioRequestError("PORT_INVALID", "port must be between 0 and 65535")
    resolved = Path(root).resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer((LOOPBACK_HOST, port), make_handler(resolved, token))
    server.daemon_threads = True
    return server, token


def serve_studio(
    root: Path,
    port: int = 0,
    open_browser: bool = True,
    on_started: Callable[[str], None] | None = None,
) -> None:
    """Run Factory Studio until interrupted and always close its listener."""
    server, _token = create_server(root, port)
    url = f"http://{LOOPBACK_HOST}:{server.server_port}/"
    print(f"Factory Studio: {url}", flush=True)
    print(
        "Boundary: loopback development server; no deploy, publish, sign, credential, connector, or external-message authority.",
        flush=True,
    )
    if on_started:
        on_started(url)
    if open_browser:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
