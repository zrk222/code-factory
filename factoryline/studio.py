"""Loopback-only local browser surface for the Factoryline target compiler."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
import json
import re
import secrets
import threading
import webbrowser
from time import monotonic

from .target_compiler import TARGETS, TargetCompileError, create_target_from_prompt
from .product_missions import (
    ProductMissionError,
    compile_product_text,
    create_mission,
    decide_mission,
    plan_value_slices,
)
from .failure_guidance import explain_failure
from .meter import MeterLog, live_snapshot
from .capability_packs import builtin_packs, validate_pack
from .continuation import ContinuationError, continue_assembly, discover_features
from .run_metrics import public_metrics
from .savings import SavingsError, public_savings_report, record_savings_pair
from .graph_ops import graph_ops_html, graph_ops_snapshot
from .graph_authorization import GraphAuthorizationError, create_graph_authorization, run_authorized_reality_check
from .developer_memory import developer_memory_brief
from .live_activity import activity_snapshot, request_stop


STUDIO_SCHEMA = "factory.studio.v1"
MAX_BODY_BYTES = 64 * 1024
LOOPBACK_HOST = "127.0.0.1"
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}")
FORBIDDEN_ACTIONS = {"deploy", "publish", "sign", "external-message", "credential", "connector-grant"}
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
        if cached is not None and (now - cached[0]) * 1000 < DEVELOPER_MEMORY_REFRESH_INTERVAL_MS:
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
        "limits": {"max_body_bytes": MAX_BODY_BYTES, "output_scope": "beneath_root", "overwrite": False},
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
    for path in sorted((Path(root).resolve() / ".factory" / "missions").glob("*/mission.json")):
        mission = _json_or_none(path)
        if mission is None:
            continue
        decision = _json_or_none(path.parent / "execution_decision.json")
        completion = _json_or_none(path.parent / "completion.json")
        rows.append({
            "id": mission.get("id"), "owner": mission.get("owner"),
            "slice_id": mission.get("slice_id"), "risk": mission.get("slice", {}).get("risk"),
            "score": mission.get("slice", {}).get("score", {}).get("priority"),
            "worktree": mission.get("workspace_contract", {}).get("path"),
            "branch": mission.get("workspace_contract", {}).get("branch"),
            "criteria": len(mission.get("completion_contract", {}).get("criteria", [])),
            "decision": decision.get("decision") if decision else "awaiting_owner",
            "completion": (
                ("verified_receipt_present" if completion else "pending")
                + " | readiness "
                + ("bound" if mission.get("inputs", {}).get("migration_readiness") else "not bound")
            ),
            "path": str(path),
        })
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
            "blocking_gaps": sum(item.get("severity") == "blocking" for item in graph.get("gaps", [])),
            "advisory_gaps": sum(item.get("severity") == "advisory" for item in graph.get("gaps", [])),
            "graph_path": str(path),
            "graph_mermaid": str(path.parent / "product_graph.mmd"),
            "slice_count": len(slices.get("slices", [])) if slices else 0,
        }
        products.append(product)
        if slices:
            for item in slices.get("slices", []):
                queue.append({
                    "project": graph.get("project"), "id": item.get("id"),
                    "theme": item.get("theme"), "priority": item.get("score", {}).get("priority"),
                    "risk": item.get("risk"), "requirements": item.get("requirement_ids", []),
                    "depends_on": item.get("depends_on", []), "path": str(path.parent / "value_slices.json"),
                })
    queue.sort(key=lambda item: (-(item["priority"] if isinstance(item["priority"], int) else -1), str(item["id"])))
    return products, queue


def _proof_timeline(missions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline = []
    for row in missions:
        mission = _json_or_none(Path(row["path"])) or {}
        completion = _json_or_none(Path(row["path"]).parent / "completion.json")
        for requirement_id in mission.get("slice", {}).get("requirement_ids", []):
            evidence = []
            if completion:
                evidence = [item.get("path") for item in completion.get("evidence", []) if item.get("path")]
            timeline.append({
                "requirement_id": requirement_id,
                "slice_id": row["slice_id"],
                "mission_id": row["id"],
                "code_state": "candidate_workspace_bound" if row.get("worktree") else "not_bound",
                "test_state": row["completion"],
                "receipt": str(Path(row["path"]).parent / "completion.json") if completion else None,
                "evidence": evidence,
            })
    return timeline


def _receipt_comparison(root: Path) -> dict[str, Any]:
    groups: dict[str, list[Any]] = {}
    for stage in MeterLog(root).stages():
        if stage.run_id:
            groups.setdefault(stage.run_id, []).append(stage)
    run_ids = list(groups)[-2:]
    if len(run_ids) < 2:
        return {"schema": "factory.receipt_comparison.v1", "status": "insufficient_runs", "current": None, "previous": None, "delta": None}

    def summary(run_id: str) -> dict[str, Any]:
        stages = groups[run_id]
        return {
            "run_id": run_id,
            "wall_ms": sum(item.wall_ms for item in stages),
            "model_calls": sum(item.model_calls for item in stages),
            "tokens": sum(item.tokens_in + item.tokens_out for item in stages),
            "failed_stages": sum(not item.ok for item in stages),
            "token_quality": sorted({item.token_quality or item.usage_quality for item in stages}),
        }

    previous, current = (summary(run_id) for run_id in run_ids)
    return {
        "schema": "factory.receipt_comparison.v1", "status": "compared",
        "current": current, "previous": previous,
        "delta": {
            "wall_ms": current["wall_ms"] - previous["wall_ms"],
            "model_calls": current["model_calls"] - previous["model_calls"],
            "tokens": current["tokens"] - previous["tokens"],
            "failed_stages": current["failed_stages"] - previous["failed_stages"],
        },
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

    def summary(run_id: str, stages: list[Any]) -> dict[str, Any]:
        ordered = sorted(stages, key=lambda item: item.recorded_at or "")
        latest = ordered[-1]
        token_qualities = sorted({item.token_quality or item.usage_quality for item in ordered})
        cost_qualities = sorted({item.cost_quality for item in ordered})
        observed_outcomes = [item.outcome_status for item in ordered if item.outcome_status]
        failed_stages = sum(not item.ok for item in ordered)
        return {
            "run_id": run_id,
            "feature": next((item.feature for item in reversed(ordered) if item.feature), None),
            "first_recorded_at": ordered[0].recorded_at or None,
            "last_recorded_at": latest.recorded_at or None,
            "stages_recorded": len(ordered),
            "failed_stages": failed_stages,
            "wall_ms": sum(item.wall_ms for item in ordered),
            "model_calls": sum(item.model_calls for item in ordered),
            "tokens": sum(item.tokens_in + item.tokens_out for item in ordered),
            "token_quality": token_qualities,
            "cost_usd": (sum(item.cost_usd or 0 for item in ordered)
                         if all(item.cost_usd is not None for item in ordered) else None),
            "cost_quality": cost_qualities,
            "outcome": (observed_outcomes[-1] if observed_outcomes
                        else "failed_stage_observed" if failed_stages
                        else "stages_recorded"),
        }

    rows = [summary(run_id, stages) for run_id, stages in groups.items()]
    rows.sort(key=lambda item: item["last_recorded_at"] or "", reverse=True)
    return rows[:limit]


def studio_dashboard(root: Path) -> dict[str, Any]:
    """Return live local telemetry, approvals, and pack trust without side effects."""
    meter = live_snapshot(Path(root))
    packs = []
    for item in builtin_packs():
        validation = validate_pack(Path(item["path"]))
        packs.append({
            "id": item["id"], "target_kind": item.get("target_kind"),
            "version": item["version"], "valid": validation["valid"],
            "signature_verified": validation["signature"]["verified"],
            "mutations_rejected": validation["mutations"]["rejected"],
            "mutations_attempted": validation["mutations"]["attempted"],
            "deployment_profiles": item.get("deployment_profiles", []),
        })
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
        "approvals": {
            "awaiting_owner": sum(item["decision"] == "awaiting_owner" for item in missions),
            "approved_execution": sum(item["decision"] == "approved_execution" for item in missions),
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
            "STUDIO_LIVE_TELEMETRY", "STUDIO_APPROVAL_QUEUE", "STUDIO_PACK_TRUST_VISIBLE",
            "STUDIO_PRODUCT_GRAPH_VISIBLE", "STUDIO_SLICE_QUEUE_VISIBLE",
            "STUDIO_PROOF_TIMELINE_VISIBLE", "STUDIO_RECEIPT_COMPARISON_VISIBLE",
            "STUDIO_PRIOR_RUNS_VISIBLE", "STUDIO_DEVELOPER_MEMORY_VISIBLE",
        ],
    }


def continue_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Continue one local assembly through the same engine used by the CLI."""
    if str(payload.get("action", "")) != "continue":
        raise StudioRequestError("ACTION_UNSUPPORTED", "assembly endpoint requires continue")
    feature = payload.get("feature")
    if feature is not None and not isinstance(feature, str):
        raise StudioRequestError("FEATURE_INVALID", "feature must be a string")
    try:
        result = continue_assembly(Path(root), feature.strip() or None if isinstance(feature, str) else None)
    except ContinuationError as exc:
        raise StudioRequestError(exc.code, exc.message, 409) from exc
    return {**result, "studio_marker": "STUDIO_ASSEMBLY_CONTAINED"}


def savings_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Record one contained exact pair through the same engine used by the CLI."""
    if str(payload.get("action", "")) != "savings-record":
        raise StudioRequestError("ACTION_UNSUPPORTED", "savings endpoint requires savings-record")
    resolved_root = Path(root).resolve()
    evidence = payload.get("evidence")
    evidence_path = (resolved_root / evidence).resolve() if isinstance(evidence, str) and evidence else None
    if evidence_path is not None and not evidence_path.is_relative_to(resolved_root):
        raise StudioRequestError("PATH_REJECTED", "evidence must stay beneath Studio root")
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
            resolved_root, payload.get("pair_id"), baseline, factory_observation,
            equivalent_outcome=payload.get("equivalent_outcome") is True,
            evidence=evidence_path,
            replace=payload.get("replace") is True,
        )
    except SavingsError as exc:
        raise StudioRequestError(exc.code, str(exc), 409 if exc.code == "PAIR_OVERWRITE_REFUSED" else 400) from exc
    return {**result, "studio_marker": "SAVINGS_STUDIO_CONTAINED"}


def _contained_output(root: Path, name: str) -> Path:
    if not NAME_PATTERN.fullmatch(name):
        raise StudioRequestError("PATH_REJECTED", "name must use 1-48 letters, digits, hyphens, or underscores")
    resolved_root = Path(root).resolve()
    output = (resolved_root / name).resolve()
    if output.parent != resolved_root:
        raise StudioRequestError("PATH_REJECTED", "output must be a direct child of Studio root")
    return output


def _validate_action(payload: dict[str, Any]) -> None:
    action = str(payload.get("action", "create"))
    if action in FORBIDDEN_ACTIONS:
        raise StudioRequestError("ACTION_FORBIDDEN", f"Studio cannot perform {action}", 403)
    if action != "create":
        raise StudioRequestError("ACTION_UNSUPPORTED", "only create is available")


def _target_and_prompt(payload: dict[str, Any]) -> tuple[str, str]:
    target = str(payload.get("target", ""))
    if target not in TARGETS:
        raise StudioRequestError("TARGET_UNSUPPORTED", f"target must be one of {', '.join(TARGETS)}")
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise StudioRequestError("SOURCE_REQUIRED", "prompt must be a non-empty string")
    return target, prompt


def _output_name(payload: dict[str, Any], prompt: str) -> str:
    requested_name = payload.get("name")
    if requested_name is not None and not isinstance(requested_name, str):
        raise StudioRequestError("NAME_INVALID", "name must be a string")
    default_name = re.sub(r"[^a-zA-Z0-9]+", "-", prompt.strip().lower()).strip("-")[:48] or "factory-target"
    return requested_name.strip() if isinstance(requested_name, str) and requested_name.strip() else default_name


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
            deployment_profile=str(payload.get("deployment_profile", "")).strip() or None,
        )
    except TargetCompileError as exc:
        status = 409 if exc.code == "OUTPUT_EXISTS" else 400
        raise StudioRequestError(exc.code, exc.message, status) from exc
    return {**result, "studio_marker": "STUDIO_CONTAINED"}


def create_product_mission_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Compile a PRD to the first dependency-ready supervised mission."""
    action = str(payload.get("action", ""))
    if action in FORBIDDEN_ACTIONS:
        raise StudioRequestError("ACTION_FORBIDDEN", f"Studio cannot perform {action}", 403)
    if action != "product-mission":
        raise StudioRequestError("ACTION_UNSUPPORTED", "product endpoint requires product-mission")
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise StudioRequestError("SOURCE_REQUIRED", "PRD must be a non-empty string")
    name = _output_name(payload, prompt)
    _contained_output(root, name)  # Validate the user-controlled project slug.
    owner = str(payload.get("owner", "local-studio-user")).strip() or "local-studio-user"
    executor = str(payload.get("executor", "manual"))
    resolution_mode = str(payload.get("resolution_mode", "human_approval"))
    if resolution_mode not in RESOLUTION_MODES:
        raise StudioRequestError("RESOLUTION_MODE_INVALID", f"resolution mode must be one of {', '.join(sorted(RESOLUTION_MODES))}")
    try:
        graph = compile_product_text(prompt, root=Path(root), source_name="studio-prd.md", project=name)
        if graph["status"] != "ready":
            items = [{
                "id": f"resolve-{gap['code'].lower().replace('_', '-')}",
                "code": gap["code"],
                "severity": gap["severity"],
                "why": gap["message"],
                "next_action": gap["message"],
                "auto_resolvable": False,
                "approval_required": True,
            } for gap in graph["gaps"]]
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
        slices = plan_value_slices(Path(graph["path"]), Path(root))
        ready = [item for item in slices["slices"] if not item["depends_on"]]
        if not ready:
            raise ProductMissionError("MISSION_DEPENDENCY_CYCLE", "no dependency-ready value slice is available")
        mission = create_mission(Path(slices["path"]), ready[0]["id"], Path(root), owner, executor)
    except ProductMissionError as exc:
        status = 409 if exc.code.endswith("EXISTS") else 400
        raise StudioRequestError(exc.code, exc.message, status) from exc
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


def decide_product_mission_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Record an actionable human decision for one contained mission."""
    if str(payload.get("action", "")) != "mission-decision":
        raise StudioRequestError("ACTION_UNSUPPORTED", "mission decision endpoint requires mission-decision")
    mission_value = payload.get("mission")
    if not isinstance(mission_value, str) or not mission_value.strip():
        raise StudioRequestError("MISSION_REQUIRED", "mission path is required")
    mission = Path(mission_value).resolve()
    root = Path(root).resolve()
    try:
        mission.relative_to(root)
    except ValueError as exc:
        raise StudioRequestError("PATH_REJECTED", "mission must be beneath the Studio root", 403) from exc
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


def authorize_graph_ops_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Record a named human authorization that stays bounded to one graph node."""
    try:
        return create_graph_authorization(root, payload)
    except GraphAuthorizationError as exc:
        raise StudioRequestError(exc.code, str(exc), 409 if exc.code.endswith(("REPLAY", "STALE", "EXPIRED")) else 400) from exc


def run_graph_ops_reality_check_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Consume one local authorization to re-run one sealed Reality Check."""
    if set(payload) != {"authorization"} or not isinstance(payload.get("authorization"), str):
        raise StudioRequestError("GRAPH_AUTHORIZATION_INVALID", "execution request must contain exactly authorization")
    try:
        return run_authorized_reality_check(root, Path(payload["authorization"]))
    except GraphAuthorizationError as exc:
        raise StudioRequestError(exc.code, str(exc), 409 if exc.code.endswith(("REPLAY", "STALE", "EXPIRED", "EXECUTABLE", "IN_PROGRESS")) else 400) from exc


def _studio_html(token: str) -> str:
    target_buttons = "".join(
        f'''<label class="target"><input type="radio" name="target" value="{key}" {'checked' if key == 'web' else ''}>
<span><strong>{value['label']}</strong><small>{value['summary']}</small></span></label>'''
        for key, value in TARGETS.items()
    )
    target_inventory_json = json.dumps(TARGETS, separators=(",", ":"))
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Factory Studio</title><link rel="icon" href="/favicon.ico">
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#5f6b7a; --line:#d8e0e8; --blue:#1d4ed8; --green:#166534; --orange:#c2410c; --paper:#f4f7fa; }}
* {{ box-sizing:border-box; }} body {{ margin:0; font-family:Inter,ui-sans-serif,system-ui,sans-serif; line-height:1.65; color:var(--ink); background:var(--paper); }}
.topbar {{ height:64px; display:flex; align-items:center; justify-content:space-between; padding:0 5vw; color:white; background:#111827; }}
.topbar span {{ color:#93c5fd; font-size:13px; }} main {{ width:min(1180px,90vw); margin:0 auto; padding:38px 0 64px; }}
.intro {{ display:grid; grid-template-columns:1fr auto; gap:24px; align-items:end; padding-bottom:28px; border-bottom:1px solid var(--line); }}
.eyebrow {{ margin:0; color:var(--blue); font-size:12px; font-weight:800; }} h1 {{ margin:8px 0 0; font-size:38px; letter-spacing:0; }}
.boundary {{ padding:14px 16px; border-left:4px solid var(--green); background:#ecfdf5; font-size:13px; }}
form {{ margin-top:30px; display:grid; gap:24px; }} fieldset {{ border:0; padding:0; margin:0; }} legend,label {{ font-weight:700; }}
.modes {{ display:inline-flex; gap:4px; padding:4px; border:1px solid var(--line); border-radius:8px; background:white; }}
.mode {{ padding:10px 14px; border-radius:5px; color:var(--ink); background:transparent; }} .mode.active {{ color:white; background:var(--blue); }}
.hidden {{ display:none!important; }}
.targets {{ margin-top:10px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
.target {{ min-height:126px; display:flex; gap:10px; padding:16px; border:1px solid var(--line); border-radius:8px; background:white; cursor:pointer; }}
.target:has(input:checked) {{ border-color:var(--blue); box-shadow:inset 0 0 0 1px var(--blue); }} .target small {{ display:block; margin-top:8px; color:var(--muted); line-height:1.45; font-weight:400; }}
.inputs {{ display:grid; grid-template-columns:2fr repeat(3,minmax(0,1fr)); gap:16px; }} .field {{ display:grid; gap:8px; }}
input[type=text],input[type=number],select,textarea {{ width:100%; border:1px solid #94a3b8; border-radius:6px; padding:12px; background:white; color:var(--ink); font:inherit; }}
textarea {{ min-height:180px; resize:vertical; }} button {{ justify-self:start; border:0; border-radius:6px; padding:13px 18px; color:white; background:var(--green); font-weight:800; cursor:pointer; }}
button {{ transition:transform .15s ease,box-shadow .15s ease,background-color .15s ease; }} button:hover:not(:disabled) {{ transform:translateY(-1px); box-shadow:0 5px 14px rgba(15,23,42,.14); }}
button:disabled {{ opacity:.55; cursor:wait; }} #result {{ min-height:48px; padding:16px; border:1px solid var(--line); border-radius:8px; background:white; white-space:pre-wrap; font:13px/1.65 ui-monospace,SFMono-Regular,Consolas,monospace; }}
.error {{ color:#991b1b; border-color:#fecaca!important; background:#fff1f2!important; }}
.decision-bar {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }} .decision-bar button {{ padding:9px 12px; }}
.decision-bar .defer {{ color:#78350f; background:#fef3c7; }} .decision-bar .reject {{ color:#991b1b; background:#fee2e2; }}
.result-title {{ margin:0 0 8px; font:700 16px/1.4 Inter,ui-sans-serif,system-ui,sans-serif; }}
.result-row {{ margin:6px 0; color:var(--muted); font:13px/1.5 Inter,ui-sans-serif,system-ui,sans-serif; }}
.resolution-list {{ display:grid; gap:8px; margin-top:12px; }} .resolution-item {{ padding:10px; border-left:3px solid var(--orange); background:#fff7ed; font:13px/1.45 Inter,ui-sans-serif,system-ui,sans-serif; }}
.dashboard {{ margin-top:24px; padding:28px 0; }} .stats {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
.stat {{ min-height:104px; padding:16px; border:1px solid var(--line); border-radius:8px; background:white; }} .stat small {{ display:block; color:var(--muted); }} .stat strong {{ display:block; margin-top:10px; font-size:25px; }}
.dash-grid {{ display:grid; grid-template-columns:1.2fr 1fr; gap:16px; margin-top:16px; }} .panel {{ padding:18px; border:1px solid var(--line); border-radius:8px; background:white; }} .panel h2 {{ margin:0 0 12px; font-size:18px; }}
.data-list {{ display:grid; gap:8px; }} .data-row {{ display:flex; justify-content:space-between; gap:16px; padding:9px 0; border-bottom:1px solid #edf1f5; color:var(--muted); font-size:13px; }} .data-row strong {{ color:var(--ink); text-align:right; }}
.data-row-actions {{ align-items:center; }} .mini-actions {{ display:flex; flex-wrap:wrap; justify-content:flex-end; gap:6px; }} .mini-actions button {{ padding:7px 9px; font-size:12px; }}
.empty-data {{ color:var(--muted); font-size:13px; }} .wide-panel {{ grid-column:1/-1; }}
.live-dot {{ display:inline-block; width:8px; height:8px; margin-right:7px; border-radius:50%; background:#22c55e; }}
.memory-studio-flow {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin-top:14px; }} .memory-studio-step {{ min-height:104px; padding:12px; border:1px solid #b9cbe0; border-radius:9px; background:linear-gradient(145deg,#f8fbff,#eef5ff); }} .memory-studio-step[data-state="blocking"] {{ border-color:#fca5a5; background:#fff1f2; }} .memory-studio-step[data-state="required"],.memory-studio-step[data-state="review"] {{ border-color:#f5c46a; background:#fffbeb; }} .memory-studio-step[data-state="ready"] {{ border-color:#86d2a5; background:#ecfdf5; }} .memory-studio-step strong,.memory-studio-step span {{ display:block; }} .memory-studio-step span {{ margin-top:6px; color:var(--muted); font-size:12px; line-height:1.45; }} .memory-studio-actions {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; margin-top:12px; }} .memory-studio-action {{ padding:12px; border:1px solid #bfdbfe; border-left:4px solid #3b82f6; border-radius:8px; background:#f8fbff; }} .memory-studio-action[data-severity="blocking"] {{ border-color:#fca5a5; border-left-color:#dc2626; background:#fff1f2; }} .memory-studio-action[data-severity="required"],.memory-studio-action[data-severity="review"] {{ border-color:#f5c46a; border-left-color:#d97706; background:#fffbeb; }} .memory-studio-action[data-severity="ready"] {{ border-color:#86d2a5; border-left-color:#15803d; background:#ecfdf5; }} .memory-studio-action strong,.memory-studio-action span {{ display:block; }} .memory-studio-action span {{ margin-top:5px; color:var(--muted); font-size:12px; line-height:1.45; }} .memory-studio-team {{ margin-top:12px; padding:12px; border-radius:8px; background:#f8fafc; color:var(--muted); font-size:13px; }}
@media(max-width:900px) {{ .targets {{ grid-template-columns:1fr 1fr; }} .inputs {{ grid-template-columns:1fr; }} .intro {{ grid-template-columns:1fr; }} }}
@media(max-width:900px) {{ .stats {{ grid-template-columns:1fr 1fr; }} .dash-grid {{ grid-template-columns:1fr; }} .memory-studio-flow,.memory-studio-actions {{ grid-template-columns:1fr 1fr; }} }}
@media(max-width:560px) {{ .targets,.stats,.memory-studio-flow,.memory-studio-actions {{ grid-template-columns:1fr; }} h1 {{ font-size:31px; }} }}
</style></head><body>
<header class="topbar"><strong>Factory Studio</strong><span id="surface-label">Local target compiler</span><a href="/graph-ops" style="color:#dbeafe;font-weight:800">Graph Ops</a></header>
<main data-marker="FACTORY_DUAL_TRACK_START GRAPH_OPS_UNIFIED_READ_ONLY"><section class="intro"><div><p class="eyebrow" id="workflow-label">INSTANT MVP TO PROFESSIONAL PROOF</p><h1 id="workflow-title">Describe the outcome. Get a local MVP.</h1></div><div class="boundary">Loopback only. No publish, deploy, signing, credentials, connectors, or external messages.</div></section>
<div class="modes" role="tablist"><button class="mode" id="starter-mode" type="button">Instant MVP</button><button class="mode active" id="dashboard-mode" type="button">Professional workflow</button><button class="mode" id="assembly-mode" type="button">Assembly</button><button class="mode" id="savings-mode" type="button">Savings</button><button class="mode" id="mission-mode" type="button">Product mission</button></div>
<section id="dashboard" class="dashboard"><div class="stats"><div class="stat"><small>Stages measured</small><strong id="stat-stages">not available</strong></div><div class="stat"><small>First-pass gates</small><strong id="stat-first-pass">not available</strong></div><div class="stat"><small>Runs observed</small><strong id="stat-runs">not available</strong></div><div class="stat"><small>Flow efficiency</small><strong id="stat-flow">not available</strong></div></div><div class="dash-grid"><div class="panel wide-panel"><h2>Professional workflow</h2><p class="empty-data">Inspect the <a href="/graph-ops">read-only Graph Ops map</a>, compile Product Missions, reuse verified proofs, apply policy and assurance controls, then keep release decisions human-owned. The same artifacts can graduate from a first MVP into team and enterprise workflows.</p></div><div class="panel"><h2><span class="live-dot"></span>Live factory activity</h2><div id="activity-list" class="data-list"></div></div><div class="panel"><h2>Paired savings</h2><div id="savings-list" class="data-list"></div></div><div class="panel"><h2>Human approval inbox</h2><div id="approval-list" class="data-list"></div></div><div class="panel wide-panel"><h2>Product Graph and journey map</h2><div id="product-list" class="data-list"></div></div><div class="panel"><h2>Dependency-aware slice queue</h2><div id="slice-list" class="data-list"></div></div><div class="panel"><h2>Mission board</h2><div id="mission-list" class="data-list"></div></div><div class="panel wide-panel"><h2>Proof timeline: requirement to receipt</h2><div id="proof-list" class="data-list"></div></div><div class="panel"><h2>Current vs previous run</h2><div id="comparison-list" class="data-list"></div></div><div class="panel"><h2>Capability Pack trust</h2><div id="pack-list" class="data-list"></div></div><div class="panel"><h2>Deployment routes</h2><div id="deployment-list" class="data-list"></div></div><div class="panel"><h2>Authority boundary</h2><div id="authority-list" class="data-list"></div></div></div></section>
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
function setMode(next){{const mission=next==='mission';const dash=next==='dashboard';const assemblyMode=next==='assembly';const savingsMode=next==='savings';const instantMvp=next==='starter';mode=next;document.getElementById('dashboard-mode').classList.toggle('active',dash);document.getElementById('assembly-mode').classList.toggle('active',assemblyMode);document.getElementById('savings-mode').classList.toggle('active',savingsMode);document.getElementById('starter-mode').classList.toggle('active',instantMvp);document.getElementById('mission-mode').classList.toggle('active',mission);dashboard.classList.toggle('hidden',!dash);assembly.classList.toggle('hidden',!assemblyMode);savings.classList.toggle('hidden',!savingsMode);form.classList.toggle('hidden',dash||assemblyMode||savingsMode);document.getElementById('target-fieldset').classList.toggle('hidden',mission||instantMvp);document.querySelectorAll('.starter-only').forEach(el=>el.classList.toggle('hidden',mission||instantMvp));document.querySelectorAll('.mission-only').forEach(el=>el.classList.toggle('hidden',!mission));document.getElementById('surface-label').textContent=dash?'Professional evidence workflow':assemblyMode?'State-aware local assembly':savingsMode?'Exact paired measurement':mission?'Local product compiler':'Instant local MVP';document.getElementById('workflow-label').textContent=dash?'PROFESSIONAL EVIDENCE WORKFLOW':assemblyMode?'SAFE STAGES TO EXPLICIT HUMAN BOUNDARY':savingsMode?'BASELINE TO HASH-BOUND SAVINGS RECEIPT':mission?'PRD TO SUPERVISED VALUE MISSION':'OUTCOME TO CONTAINED WEB MVP';document.getElementById('workflow-title').textContent=dash?'Inspect and advance proven work.':assemblyMode?'Resume without reconstructing state.':savingsMode?'Measure savings without inventing them.':mission?'Compile the next reviewable value slice.':'Describe the outcome. Get a local MVP.';button.textContent=mission?'Compile product mission':instantMvp?'Build my MVP':'Compile starter';if(dash)refreshDashboard();}}
document.getElementById('dashboard-mode').onclick=()=>setMode('dashboard');document.getElementById('assembly-mode').onclick=()=>setMode('assembly');document.getElementById('savings-mode').onclick=()=>setMode('savings');document.getElementById('starter-mode').onclick=()=>setMode('starter');document.getElementById('mission-mode').onclick=()=>setMode('mission');const requestedMode=new URLSearchParams(location.search).get('mode');if(requestedMode==='product')setMode('mission');else if(requestedMode==='assembly')setMode('assembly');else if(requestedMode==='savings')setMode('savings');else setMode('starter');
document.getElementById('assembly-continue').onclick=async()=>{{const host=document.getElementById('assembly-result');host.textContent='Continuing safe local stages...';const response=await fetch('/api/continue',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify({{action:'continue',feature:document.getElementById('assembly-feature').value}})}});const payload=await response.json();host.textContent=response.ok?`Status: ${{payload.status}}\nFeature: ${{payload.feature}}\nNext: ${{payload.next_action?.label||'Assembly complete'}}\nReceipt: ${{payload.receipt||'dry run'}}`:`${{payload.code}}: ${{payload.message}}`;}}
document.getElementById('savings-record').onclick=async()=>{{const host=document.getElementById('savings-result');host.textContent='Recording exact pair...';const numberOrNull=id=>{{const value=document.getElementById(id).value;return value===''?null:Number(value);}};const body={{action:'savings-record',pair_id:document.getElementById('savings-pair').value,baseline_elapsed_ms:numberOrNull('baseline-ms'),factory_elapsed_ms:numberOrNull('factory-ms'),baseline_tokens:numberOrNull('baseline-tokens'),factory_tokens:numberOrNull('factory-tokens'),baseline_cost_usd:numberOrNull('baseline-cost'),factory_cost_usd:numberOrNull('factory-cost'),equivalent_outcome:document.getElementById('equivalent-outcome').checked,evidence:document.getElementById('savings-evidence').value}};const response=await fetch('/api/savings',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify(body)}});const payload=await response.json();host.textContent=response.ok?`Time saved: ${{payload.savings.time_saved_ms}} ms\nTokens saved: ${{textValue(payload.savings.tokens_saved)}}\nCost saved: ${{textValue(payload.savings.cost_saved_usd)}}\nProductivity gain: ${{payload.savings.productivity_gain_rate===null?'withheld':(payload.savings.productivity_gain_rate*100).toFixed(1)+'%'}}\nReceipt: ${{payload.receipt}}`:`${{payload.code}}: ${{payload.message}}`;}}
document.querySelectorAll('input[name="target"]').forEach(input=>input.addEventListener('change',updateDeploymentProfiles));document.getElementById('deployment-profile').addEventListener('change',updateDeploymentDetail);updateDeploymentProfiles();
function textValue(value,suffix=''){{return value===null||value===undefined?'not available':`${{value}}${{suffix}}`;}}
function rows(id,items){{const host=document.getElementById(id);host.textContent='';items.forEach(([label,value])=>{{const row=document.createElement('div');row.className='data-row';const a=document.createElement('span');a.textContent=label;const b=document.createElement('strong');b.textContent=value;row.append(a,b);host.appendChild(row);}});}}
function approvalRows(missions){{const host=document.getElementById('approval-list');host.textContent='';const pending=missions.filter(item=>item.decision==='awaiting_owner');if(!pending.length){{const empty=document.createElement('div');empty.className='empty-data';empty.textContent='No mission is waiting for an owner decision.';host.appendChild(empty);return;}}pending.forEach(item=>{{const row=document.createElement('div');row.className='data-row data-row-actions';const label=document.createElement('span');label.textContent=`${{item.id}} | ${{item.risk}} risk | ${{item.criteria}} criteria`;const actions=document.createElement('div');actions.className='mini-actions';[['approved_execution','Approve'],['deferred','Defer'],['rejected','Reject']].forEach(([decision,title])=>{{const action=document.createElement('button');action.type='button';action.textContent=title;action.onclick=()=>decideDashboardMission(item,decision);actions.appendChild(action);}});row.append(label,actions);host.appendChild(row);}});}}
async function refreshDashboard(){{try{{const response=await fetch('/api/dashboard',{{headers:{{'X-Factory-Studio-Token':token}}}});const payload=await response.json();if(!response.ok)return;const summary=payload.meter.summary||{{}};const activity=payload.meter.activity||{{}};const flow=summary.flow||{{}};const firstPass=flow.first_pass_gate_rate?.value;document.getElementById('stat-stages').textContent=textValue(summary.stages_measured);document.getElementById('stat-first-pass').textContent=firstPass===null||firstPass===undefined?'not available':`${{(firstPass*100).toFixed(1)}}%`;document.getElementById('stat-runs').textContent=textValue(activity.runs_observed);document.getElementById('stat-flow').textContent=flow.flow_efficiency===null||flow.flow_efficiency===undefined?'not available':`${{(flow.flow_efficiency*100).toFixed(1)}}%`;const latest=activity.latest_stage;rows('activity-list',[["Latest stage",latest?`${{latest.module}}:${{latest.stage}} (${{latest.ok?'ok':'failed'}})`:'none yet'],["Agent / tool time",`${{textValue(flow.agent_ms?.value,' ms')}} / ${{textValue(flow.deterministic_tool_ms?.value,' ms')}}`],["Queue / review time",`${{textValue(flow.queue_ms?.value,' ms')}} / ${{textValue(flow.human_review_ms?.value,' ms')}}`],["Requirements / token",textValue(flow.requirements_per_token)],["Rollback rate",flow.rollback_rate===null||flow.rollback_rate===undefined?'not available':`${{(flow.rollback_rate*100).toFixed(1)}}%`],["Token / cost quality",`${{JSON.stringify(flow.token_quality||{{}})}} / ${{JSON.stringify(flow.cost_quality||{{}})}}`]]);const paired=payload.savings||{{}};rows('savings-list',[["Exact pairs",textValue(paired.pairs)],["Time saved",textValue(paired.time?.saved_total,' ms')],["Tokens saved",textValue(paired.tokens?.saved_total)],["Productivity",paired.productivity?.gain_rate===null||paired.productivity?.gain_rate===undefined?'withheld until equivalence proof':`${{(paired.productivity.gain_rate*100).toFixed(1)}}%`]]);approvalRows(payload.missions);rows('product-list',payload.products.map(item=>[`${{item.project}} | ${{item.requirements}} requirements | ${{item.slice_count}} slices`,`${{item.status}} | journey: ${{item.journeys[0]||'missing'}} | gaps: ${{item.blocking_gaps}} blocking, ${{item.advisory_gaps}} advisory`]));rows('slice-list',payload.slice_queue.map(item=>[`${{item.id}} | priority ${{textValue(item.priority)}}`,`${{item.theme}} | ${{item.risk}} risk | dependencies ${{item.depends_on.length}}`]));rows('mission-list',payload.missions.map(item=>[`${{item.id}} | ${{item.decision}}`,`${{item.branch||'branch unavailable'}} | ${{item.completion}}`]));rows('proof-list',payload.proof_timeline.map(item=>[`${{item.requirement_id}} -> ${{item.slice_id}} -> ${{item.mission_id}}`,item.receipt?`receipt: ${{item.receipt}}`:`${{item.test_state}}; receipt pending`]));const compare=payload.receipt_comparison;rows('comparison-list',compare.status==='compared'?[["Run",`${{compare.previous.run_id}} -> ${{compare.current.run_id}}`],["Wall delta",`${{compare.delta.wall_ms}} ms`],["Token delta",String(compare.delta.tokens)],["Failed-stage delta",String(compare.delta.failed_stages)]]:[["Status","Two run IDs are required before comparison."]]);rows('pack-list',payload.packs.map(pack=>[`${{pack.target_kind}} ${{pack.version}}`,pack.valid&&pack.signature_verified?`verified; ${{pack.mutations_rejected}}/${{pack.mutations_attempted}} mutations rejected`:'invalid']));rows('deployment-list',payload.packs.flatMap(pack=>pack.deployment_profiles.map(profile=>[`${{pack.target_kind}}: ${{profile.label}}`,`${{profile.verify}} | approval: ${{profile.approval}}`])));rows('authority-list',[["Create starters",payload.authority.can_create_starters?'allowed':'denied'],["Record exact savings",payload.authority.can_record_exact_savings_pairs?'allowed':'denied'],["Approve bounded mission",payload.authority.can_record_mission_execution_decision?'allowed':'denied'],["Deploy / publish / sign",'denied until a route is selected and separately approved'],["Credentials / connectors / messages",'denied']]);}}catch(_error){{document.getElementById('stat-first-pass').textContent='telemetry unavailable';}}}}
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
form.addEventListener('submit',async(event)=>{{event.preventDefault();button.disabled=true;result.className='';result.textContent='Compiling locally...';
const target=new FormData(form).get('target'); const body=mode==='mission'?{{action:'product-mission',prompt:document.getElementById('prompt').value,name:document.getElementById('name').value,executor:document.getElementById('executor').value,owner:document.getElementById('owner').value,resolution_mode:document.getElementById('resolution-mode').value}}:{{action:'create',target,prompt:document.getElementById('prompt').value,name:document.getElementById('name').value,purpose:document.getElementById('purpose').value,trigger:document.getElementById('trigger').value,deployment_profile:document.getElementById('deployment-profile').value}};
try{{const response=await fetch(mode==='mission'?'/api/product':'/api/create',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify(body)}});const payload=await response.json();if(!response.ok){{renderFailure(payload);return;}}if(mode==='mission')renderMission(payload);else result.textContent=`Compiled ${{payload.target_kind}}\n${{payload.out_dir}}\nDeployment: ${{payload.deployment.profile.label}}\nApproval: ${{payload.deployment.profile.approval}}\nExternal effects authorized: ${{payload.deployment.external_effects_authorized}}\nReceipt: ${{payload.receipt}}\nState: ${{payload.status}}`;}}
catch(error){{renderFailure({{code:'NETWORK_ERROR',message:String(error)}});}}finally{{button.disabled=false;}}}});
</script></body></html>'''


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
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
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
        self._json(status, {
            "schema": "factory.studio.error.v1",
            "code": code,
            "message": message,
            "failure": explain_failure(code, message),
        })

    def do_GET(self) -> None:
        """Serve only the Studio shell and its public boundary status."""
        if self.path == "/favicon.ico":
            self._headers(204, "image/x-icon")
            return
        if self.path.split("?", 1)[0] == "/":
            body = _studio_html(self.studio_token).encode("utf-8")
            self._headers(200, "text/html; charset=utf-8", len(body))
            self.wfile.write(body)
            return
        if self.path.split("?", 1)[0] == "/graph-ops":
            body = graph_ops_html(self.studio_token).encode("utf-8")
            self._headers(200, "text/html; charset=utf-8", len(body))
            self.wfile.write(body)
            return
        if self.path == "/api/status":
            payload = dict(self.status_payload)
            payload["listener"] = {**payload["listener"], "port": self.server.server_port}
            self._json(200, payload)
            return
        if self.path == "/api/dashboard":
            if not secrets.compare_digest(self.headers.get("X-Factory-Studio-Token", ""), self.studio_token):
                self._error(403, "TOKEN_REQUIRED", "valid Studio session token required")
                return
            self._json(200, studio_dashboard(self.studio_root))
            return
        if self.path == "/api/savings":
            if not secrets.compare_digest(self.headers.get("X-Factory-Studio-Token", ""), self.studio_token):
                self._error(403, "TOKEN_REQUIRED", "valid Studio session token required")
                return
            self._json(200, public_savings_report(self.studio_root))
            return
        if self.path == "/api/developer-memory":
            if not secrets.compare_digest(self.headers.get("X-Factory-Studio-Token", ""), self.studio_token):
                self._error(403, "TOKEN_REQUIRED", "valid Studio session token required")
                return
            self._json(200, developer_memory_snapshot(self.studio_root))
            return
        if self.path == "/api/graph-ops":
            if not secrets.compare_digest(self.headers.get("X-Factory-Studio-Token", ""), self.studio_token):
                self._error(403, "TOKEN_REQUIRED", "valid Studio session token required")
                return
            payload = graph_ops_snapshot(self.studio_root)
            payload["live_telemetry"] = {
                "activity": activity_snapshot(self.studio_root),
                "meter": live_snapshot(self.studio_root),
                "recent_runs": _recent_run_stats(self.studio_root, limit=3),
                "refresh_interval_ms": 1000,
                "scope_limits": ["Live telemetry is local and aggregate-safe.", "Unknown usage, cost, queue, and productivity values remain unavailable."],
            }
            self._json(200, payload)
            return
        self._error(404, "NOT_FOUND", "route not found")

    def _content_length(self) -> int | None:
        try:
            return int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(400, "LENGTH_INVALID", "invalid content length")
            return None

    def do_POST(self) -> None:
        """Accept one token-bound target creation request within the size limit."""
        if self.path not in {"/api/create", "/api/product", "/api/mission-decision", "/api/continue", "/api/savings", "/api/graph-ops-authorize", "/api/graph-ops-run", "/api/activity/stop"}:
            self.close_connection = True
            self._error(404, "NOT_FOUND", "route not found")
            return
        if not secrets.compare_digest(self.headers.get("X-Factory-Studio-Token", ""), self.studio_token):
            # Consume only a bounded, well-framed request body before closing.
            # Otherwise Windows may reset a socket that still has unread data,
            # hiding the deterministic 403 response from the client.
            rejected_length = self._content_length()
            if rejected_length is None:
                self.close_connection = True
                return
            if 0 < rejected_length <= MAX_BODY_BYTES:
                self.rfile.read(rejected_length)
            self.close_connection = True
            self._error(403, "TOKEN_REQUIRED", "valid Studio session token required")
            return
        length = self._content_length()
        if length is None:
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self.close_connection = True
            self._error(413, "BODY_LIMIT", f"body must be 1-{MAX_BODY_BYTES} bytes")
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise StudioRequestError("JSON_OBJECT_REQUIRED", "request must be a JSON object")
            if self.path == "/api/activity/stop":
                if payload.get("action") != "request-stop":
                    raise StudioRequestError("ACTION_UNSUPPORTED", "activity stop endpoint requires request-stop")
                try:
                    result = request_stop(self.studio_root)
                except ValueError as exc:
                    raise StudioRequestError("NO_ACTIVE_ASSEMBLY", str(exc), 409) from exc
            elif self.path == "/api/product":
                result = create_product_mission_from_studio(self.studio_root, payload)
            elif self.path == "/api/mission-decision":
                result = decide_product_mission_from_studio(self.studio_root, payload)
            elif self.path == "/api/continue":
                result = continue_from_studio(self.studio_root, payload)
            elif self.path == "/api/savings":
                result = savings_from_studio(self.studio_root, payload)
            elif self.path == "/api/graph-ops-authorize":
                result = authorize_graph_ops_from_studio(self.studio_root, payload)
            elif self.path == "/api/graph-ops-run":
                result = run_graph_ops_reality_check_from_studio(self.studio_root, payload)
            else:
                result = create_from_studio(self.studio_root, payload)
        except StudioRequestError as exc:
            self._json(exc.status, {
                "schema": "factory.studio.error.v1",
                "code": exc.code,
                "message": exc.message,
                "failure": exc.guidance,
            })
            return
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, "JSON_INVALID", "request body must be valid UTF-8 JSON")
            return
        except Exception as exc:
            self._error(500, "INTERNAL_ERROR", f"{type(exc).__name__}: request failed before an artifact was committed")
            return
        self._json(201, result)

    def log_message(self, format: str, *args: object) -> None:
        """Suppress the default request log so request data stays out of stdout."""
        return


def make_handler(root: Path, token: str) -> type[BaseHTTPRequestHandler]:
    """Bind immutable root and session data to a request handler class."""
    return type("StudioHandler", (_StudioHandler,), {
        "studio_root": root,
        "studio_token": token,
        "status_payload": studio_status(root, 0),
    })


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


def serve_studio(root: Path, port: int = 0, open_browser: bool = True,
                 on_started: Callable[[str], None] | None = None) -> None:
    """Run Factory Studio until interrupted and always close its listener."""
    server, _token = create_server(root, port)
    url = f"http://{LOOPBACK_HOST}:{server.server_port}/"
    print(f"Factory Studio: {url}", flush=True)
    print("Boundary: loopback development server; no deploy, publish, sign, credential, connector, or external-message authority.", flush=True)
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
