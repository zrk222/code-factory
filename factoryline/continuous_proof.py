"""Continuous Proof Operations over existing local Factory evidence.

This is a coordinator, not a new execution engine. It binds human intent,
changed bytes, Change Review, observed-session evidence, and optional Repair
Sandbox evidence into one fail-closed record. It never runs a command or grants
approval authority.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Any


CONTINUOUS_PROOF_SCHEMA = "factory.continuous-proof.v1"
CONTINUOUS_PROOF_HISTORY_SCHEMA = "factory.continuous-proof-history.v1"
MAX_RECEIPTS = 500
MAX_SOURCE_BYTES = 1_048_576
_ID = re.compile(r"^[a-z][a-z0-9-]{0,95}$")
_AUTHORITY = {
    "execution": False,
    "source_modify": False,
    "patch_apply": False,
    "approval": False,
    "commit": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
    "network": False,
}
_RECEIPT_KEYS = {
    "schema", "marker", "workflow_id", "recorded_at", "intent", "changed_paths", "changed_bindings",
    "change_review", "session", "repair", "prior", "repair_reverified", "route", "next_action",
    "final_approval", "authority", "claim_limits", "receipt_sha256",
}
_ROUTES = {"evidence_required", "human_required", "reverification_required", "review_ready"}


class ContinuousProofError(ValueError):
    """A closed, machine-readable continuous-proof failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _receipt_integrity(value: dict[str, Any]) -> bool:
    digest = value.get("receipt_sha256")
    core = {key: item for key, item in value.items() if key != "receipt_sha256"}
    return (
        set(value) == _RECEIPT_KEYS
        and value.get("schema") == CONTINUOUS_PROOF_SCHEMA
        and value.get("marker") == "CONTINUOUS_PROOF_RECORDED"
        and isinstance(value.get("workflow_id"), str)
        and _ID.fullmatch(value["workflow_id"]) is not None
        and isinstance(value.get("recorded_at"), str)
        and isinstance(value.get("changed_paths"), list)
        and isinstance(value.get("changed_bindings"), list)
        and isinstance(value.get("change_review"), dict)
        and isinstance(value.get("session"), dict)
        and isinstance(value.get("repair"), dict)
        and (value.get("prior") is None or isinstance(value.get("prior"), dict))
        and isinstance(value.get("repair_reverified"), bool)
        and value.get("route") in _ROUTES
        and isinstance(value.get("next_action"), dict)
        and value.get("final_approval") is False
        and value.get("authority") == _AUTHORITY
        and isinstance(value.get("claim_limits"), list)
        and isinstance(digest, str)
        and re.fullmatch(r"[a-f0-9]{64}", digest) is not None
        and digest == _sha(core)
    )


def _file_sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _workspace(root: Path) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise ContinuousProofError("CONTINUOUS_PROOF_ROOT_INVALID", f"root must be an existing directory: {workspace}")
    return workspace


def _workspace_file(workspace: Path, value: Path, field: str) -> tuple[Path, str]:
    candidate = Path(value)
    path = (candidate if candidate.is_absolute() else workspace / candidate).resolve()
    try:
        relative = path.relative_to(workspace).as_posix()
    except ValueError as exc:
        raise ContinuousProofError("CONTINUOUS_PROOF_PATH_REJECTED", f"{field} must stay inside the workspace") from exc
    if not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
        raise ContinuousProofError("CONTINUOUS_PROOF_INPUT_UNREADABLE", f"{field} must be a regular file no larger than {MAX_SOURCE_BYTES} bytes")
    return path, relative


def _binding(workspace: Path, value: Path, field: str) -> dict[str, str]:
    path, relative = _workspace_file(workspace, value, field)
    return {"path": relative, "sha256": _file_sha(path)}


def _changed_binding(workspace: Path, relative: str) -> dict[str, Any]:
    path = (workspace / relative).resolve()
    try:
        path.relative_to(workspace)
    except ValueError as exc:
        raise ContinuousProofError("CONTINUOUS_PROOF_PATH_REJECTED", "changed path escaped the workspace") from exc
    if not path.exists():
        return {"path": relative, "exists": False, "sha256": None, "size_bytes": 0}
    if not path.is_file():
        raise ContinuousProofError("CONTINUOUS_PROOF_PATH_REJECTED", f"changed path must be a file or deletion: {relative}")
    data = path.read_bytes()
    if len(data) > MAX_SOURCE_BYTES:
        raise ContinuousProofError("CONTINUOUS_PROOF_INPUT_TOO_LARGE", f"changed path exceeds {MAX_SOURCE_BYTES} bytes: {relative}")
    return {"path": relative, "exists": True, "sha256": sha256(data).hexdigest(), "size_bytes": len(data)}


def _load_json(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContinuousProofError(code, f"cannot read JSON evidence: {path.name}") from exc
    if not isinstance(value, dict):
        raise ContinuousProofError(code, "JSON evidence must be an object")
    return value


def _session_evidence(workspace: Path, session_path: Path | None) -> dict[str, Any]:
    if session_path is None:
        return {"state": "missing", "binding": None, "passed": None, "failure_classes": []}
    from .session_recorder import verify_session_receipt

    path, relative = _workspace_file(workspace, session_path, "observed-session receipt")
    verification = verify_session_receipt(workspace, path)
    value = _load_json(path, "CONTINUOUS_PROOF_SESSION_INVALID")
    failures = value.get("failure_classes")
    if not isinstance(failures, list) or not all(isinstance(item, str) for item in failures):
        raise ContinuousProofError("CONTINUOUS_PROOF_SESSION_INVALID", "observed-session failure_classes must be a string list")
    return {
        "state": "verified_passed" if verification.get("ok") and verification.get("passed") is True else "verified_failed" if verification.get("ok") else "invalid_or_stale",
        "binding": {"path": relative, "sha256": _file_sha(path), "session_sha256": value.get("session_sha256")},
        "passed": verification.get("passed") if verification.get("ok") else None,
        "failure_classes": sorted(failures),
        "verification_marker": verification.get("marker"),
    }


def _repair_evidence(workspace: Path, scope_path: Path | None, patch_path: Path | None) -> dict[str, Any]:
    if scope_path is None and patch_path is None:
        return {"state": "not_requested", "scope": None, "patch": None, "candidate_sha256": None, "touched_paths": []}
    if scope_path is None or patch_path is None:
        raise ContinuousProofError("CONTINUOUS_PROOF_REPAIR_INCOMPLETE", "repair scope and repair patch must be supplied together")
    from .repair_sandbox import RepairSandboxError, inspect_repair_candidate

    scope_binding = _binding(workspace, scope_path, "repair scope")
    patch_binding = _binding(workspace, patch_path, "repair patch")
    try:
        candidate = inspect_repair_candidate(workspace, workspace / scope_binding["path"], workspace / patch_binding["path"])
    except RepairSandboxError as exc:
        raise ContinuousProofError(exc.code, str(exc)) from exc
    return {
        "state": "candidate_scoped",
        "scope": scope_binding,
        "patch": patch_binding,
        "candidate_sha256": candidate["candidate_sha256"],
        "touched_paths": candidate["touched_paths"],
    }


def _prior_evidence(workspace: Path, prior_path: Path | None) -> dict[str, Any] | None:
    if prior_path is None:
        return None
    path, relative = _workspace_file(workspace, prior_path, "prior continuous-proof receipt")
    value = _load_json(path, "CONTINUOUS_PROOF_PRIOR_INVALID")
    if not _receipt_integrity(value):
        raise ContinuousProofError("CONTINUOUS_PROOF_PRIOR_INVALID", "prior continuous-proof receipt digest is invalid")
    checked = verify_continuous_proof(workspace, path)
    expected_source_drift = checked.get("marker") == "CONTINUOUS_PROOF_STALE" and checked.get("reason") == "changed_bytes"
    if not checked.get("ok") and not expected_source_drift:
        raise ContinuousProofError("CONTINUOUS_PROOF_PRIOR_INVALID", "prior continuous-proof receipt must verify against current bound evidence")
    repair = value.get("repair")
    if value.get("route") != "reverification_required" or not isinstance(repair, dict) or repair.get("state") != "candidate_scoped":
        raise ContinuousProofError("CONTINUOUS_PROOF_PRIOR_INVALID", "prior receipt must contain a scoped repair awaiting re-verification")
    touched = repair.get("touched_paths")
    if not isinstance(touched, list) or not touched or not all(isinstance(item, str) for item in touched):
        raise ContinuousProofError("CONTINUOUS_PROOF_PRIOR_INVALID", "prior repair touched paths are invalid")
    return {
        "path": relative,
        "sha256": _file_sha(path),
        "receipt_sha256": value["receipt_sha256"],
        "workflow_id": value["workflow_id"],
        "candidate_sha256": repair.get("candidate_sha256"),
        "touched_paths": touched,
    }


def _post_repair_matches(workspace: Path, session: dict[str, Any], repair: dict[str, Any], phase: str) -> bool:
    if phase != "post_repair" or session["state"] != "verified_passed" or repair["state"] != "candidate_scoped_prior":
        return False
    session_value = _load_json(workspace / session["binding"]["path"], "CONTINUOUS_PROOF_SESSION_INVALID")
    result_binding = session_value.get("result")
    if not isinstance(result_binding, dict) or not isinstance(result_binding.get("path"), str):
        return False
    result_path = (workspace / result_binding["path"]).resolve()
    try:
        result_path.relative_to(workspace)
    except ValueError:
        return False
    result = _load_json(result_path, "CONTINUOUS_PROOF_SESSION_INVALID")
    deltas = result.get("workspace_delta")
    if not isinstance(deltas, list):
        return False
    after = {item.get("path"): item.get("after_sha256") for item in deltas if isinstance(item, dict)}
    for relative in repair["touched_paths"]:
        current = _changed_binding(workspace, relative)
        if not current["exists"] or after.get(relative) != current["sha256"]:
            return False
    return True


def _route(review: dict[str, Any], session: dict[str, Any], repair: dict[str, Any], repair_reverified: bool) -> tuple[str, dict[str, str]]:
    severities = {item.get("severity") for item in review.get("findings", []) if isinstance(item, dict)}
    if repair["state"] in {"candidate_scoped", "candidate_scoped_prior"} and not repair_reverified:
        return "reverification_required", {"action": "run_post_repair_observed_session", "reason": "The scoped repair candidate is not bound to fresh passing evidence over its resulting bytes."}
    if session["state"] == "missing":
        return "evidence_required", {"action": "record_observed_session", "reason": "No independently validated observed-session receipt is bound to this change."}
    if session["state"] != "verified_passed" or severities.intersection({"blocking", "required"}):
        return "human_required", {"action": review.get("next_action", {}).get("action", "inspect_failed_evidence"), "reason": "Execution evidence failed, drifted, or the deterministic change review still has a blocking proof gap."}
    return "review_ready", {"action": "human_review_record", "reason": "Current bytes have passing observed evidence and no blocking deterministic review finding; final approval remains human-controlled."}


def _markdown(receipt: dict[str, Any]) -> str:
    changed = "\n".join(f"- `{item['path']}` - {'present' if item['exists'] else 'deleted'}" for item in receipt["changed_bindings"])
    return "\n".join((
        "# Continuous Proof Operations",
        "",
        f"Workflow: `{receipt['workflow_id']}`",
        f"Route: **{receipt['route']}**",
        f"Receipt SHA-256: `{receipt['receipt_sha256']}`",
        "",
        "## Bound change",
        "",
        changed,
        "",
        "## Next action",
        "",
        f"- `{receipt['next_action']['action']}` - {receipt['next_action']['reason']}",
        "",
        "## Evidence state",
        "",
        f"- Intent: `{receipt['intent']['path']}`",
        f"- Session: `{receipt['session']['state']}`",
        f"- Repair: `{receipt['repair']['state']}`",
        f"- Repair reverified: `{str(receipt['repair_reverified']).lower()}`",
        "",
        "## Authority boundary",
        "",
        "This record did not run a command, apply a patch, approve, commit, merge, publish, deploy, sign, send a message, access credentials, or grant a connector.",
        "",
    ))


def _mermaid(receipt: dict[str, Any]) -> str:
    return "\n".join((
        "flowchart LR",
        '  I["Human intent"] --> C["Exact changed bytes"]',
        '  C --> R["Deterministic change review"]',
        f'  R --> S["Observed session: {receipt["session"]["state"]}"]',
        f'  S --> P["Repair: {receipt["repair"]["state"]}"]',
        f'  P --> O["Route: {receipt["route"]}"]',
        '  O --> H["Human final approval"]',
        "",
    ))


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def assess_continuous_proof(
    root: Path,
    workflow_id: str,
    intent_path: Path,
    changed: list[str],
    *,
    session_path: Path | None = None,
    session_phase: str = "change",
    repair_scope_path: Path | None = None,
    repair_patch_path: Path | None = None,
    prior_receipt_path: Path | None = None,
    out_dir: Path | None = None,
    recorded_at: datetime | None = None,
) -> dict[str, Any]:
    """Assess current local evidence and atomically write one unified record."""
    workspace = _workspace(root)
    if not _ID.fullmatch(workflow_id):
        raise ContinuousProofError("CONTINUOUS_PROOF_ID_INVALID", "workflow_id must be a lowercase identifier")
    if session_phase not in {"change", "post_repair"}:
        raise ContinuousProofError("CONTINUOUS_PROOF_PHASE_INVALID", "session_phase must be change or post_repair")
    from .change_review import ChangeReviewError, review_change

    try:
        review = review_change(workspace, changed=changed)
    except ChangeReviewError as exc:
        raise ContinuousProofError(exc.code, str(exc)) from exc
    intent = _binding(workspace, intent_path, "intent artifact")
    changed_bindings = [_changed_binding(workspace, item) for item in review["changed_paths"]]
    session = _session_evidence(workspace, session_path)
    session["phase"] = session_phase
    repair = _repair_evidence(workspace, repair_scope_path, repair_patch_path)
    prior = _prior_evidence(workspace, prior_receipt_path)
    if prior is not None:
        if repair["state"] != "not_requested":
            raise ContinuousProofError("CONTINUOUS_PROOF_REPAIR_CONFLICT", "a follow-up prior receipt cannot be combined with a new repair candidate")
        repair = {
            "state": "candidate_scoped_prior",
            "scope": None,
            "patch": None,
            "candidate_sha256": prior["candidate_sha256"],
            "touched_paths": prior["touched_paths"],
        }
        if not set(repair["touched_paths"]).issubset(review["changed_paths"]):
            raise ContinuousProofError("CONTINUOUS_PROOF_REPAIR_PATH_MISMATCH", "follow-up changed paths must include every prior repair path")
    repair_reverified = _post_repair_matches(workspace, session, repair, session_phase)
    route, next_action = _route(review, session, repair, repair_reverified)
    instant = recorded_at or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ContinuousProofError("CONTINUOUS_PROOF_TIME_INVALID", "recorded_at must include a timezone")
    core = {
        "schema": CONTINUOUS_PROOF_SCHEMA,
        "marker": "CONTINUOUS_PROOF_RECORDED",
        "workflow_id": workflow_id,
        "recorded_at": instant.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "intent": intent,
        "changed_paths": review["changed_paths"],
        "changed_bindings": changed_bindings,
        "change_review": {
            "review_sha256": review["review_sha256"],
            "findings": [{"kind": item["kind"], "severity": item["severity"]} for item in review["findings"]],
            "next_action": review["next_action"],
        },
        "session": session,
        "repair": repair,
        "prior": prior,
        "repair_reverified": repair_reverified,
        "route": route,
        "next_action": next_action,
        "final_approval": False,
        "authority": dict(_AUTHORITY),
        "claim_limits": [
            "One record is not one unique user.",
            "No time, token, cost, quality, productivity, release, or compliance outcome is claimed.",
        ],
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    if out_dir:
        out_candidate = Path(out_dir)
        destination = (out_candidate if out_candidate.is_absolute() else workspace / out_candidate).resolve()
    else:
        destination = workspace / ".factory" / "continuous-proof" / workflow_id
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise ContinuousProofError("CONTINUOUS_PROOF_PATH_REJECTED", "output directory must stay inside the workspace") from exc
    stem = f"continuous-proof-{receipt['receipt_sha256'][:12]}"
    paths = {"json": destination / f"{stem}.json", "markdown": destination / f"{stem}.md", "mermaid": destination / f"{stem}.mmd"}
    _atomic(paths["json"], _canonical(receipt) + b"\n")
    _atomic(paths["markdown"], _markdown(receipt).encode("utf-8"))
    _atomic(paths["mermaid"], _mermaid(receipt).encode("utf-8"))
    return {**receipt, "artifacts": {name: str(path) for name, path in paths.items()}}


def verify_continuous_proof(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify receipt integrity and every bound local byte without writing."""
    workspace = _workspace(root)
    path, relative = _workspace_file(workspace, receipt_path, "continuous-proof receipt")
    value = _load_json(path, "CONTINUOUS_PROOF_INVALID")
    digest = value.get("receipt_sha256")
    if not _receipt_integrity(value):
        return {"schema": CONTINUOUS_PROOF_SCHEMA, "marker": "CONTINUOUS_PROOF_INVALID", "ok": False, "path": relative, "reason": "receipt_digest"}
    if not isinstance(value.get("intent"), dict) or not isinstance(value.get("changed_bindings"), list):
        return {"schema": CONTINUOUS_PROOF_SCHEMA, "marker": "CONTINUOUS_PROOF_INVALID", "ok": False, "path": relative, "reason": "required_fields"}
    bindings: list[tuple[str, dict[str, Any]]] = [("intent", value["intent"])]
    for name in ("session", "repair"):
        evidence = value.get(name)
        if not isinstance(evidence, dict):
            return {"schema": CONTINUOUS_PROOF_SCHEMA, "marker": "CONTINUOUS_PROOF_INVALID", "ok": False, "path": relative, "reason": name}
    session_binding = value["session"].get("binding")
    if session_binding:
        bindings.append(("session", session_binding))
    for name in ("scope", "patch"):
        binding = value["repair"].get(name)
        if binding:
            bindings.append((f"repair_{name}", binding))
    if value.get("prior"):
        bindings.append(("prior", value["prior"]))
    for name, binding in bindings:
        if not isinstance(binding, dict) or not isinstance(binding.get("path"), str) or not isinstance(binding.get("sha256"), str):
            return {"schema": CONTINUOUS_PROOF_SCHEMA, "marker": "CONTINUOUS_PROOF_INVALID", "ok": False, "path": relative, "reason": f"{name}_binding"}
        candidate = (workspace / binding["path"]).resolve()
        try:
            candidate.relative_to(workspace)
        except ValueError:
            return {"schema": CONTINUOUS_PROOF_SCHEMA, "marker": "CONTINUOUS_PROOF_INVALID", "ok": False, "path": relative, "reason": f"{name}_path"}
        if not candidate.is_file() or _file_sha(candidate) != binding["sha256"]:
            return {"schema": CONTINUOUS_PROOF_SCHEMA, "marker": "CONTINUOUS_PROOF_STALE", "ok": False, "path": relative, "reason": name}
    current = [_changed_binding(workspace, item["path"]) for item in value.get("changed_bindings", []) if isinstance(item, dict) and isinstance(item.get("path"), str)]
    if current != value.get("changed_bindings"):
        return {"schema": CONTINUOUS_PROOF_SCHEMA, "marker": "CONTINUOUS_PROOF_STALE", "ok": False, "path": relative, "reason": "changed_bytes"}
    return {"schema": CONTINUOUS_PROOF_SCHEMA, "marker": "CONTINUOUS_PROOF_VERIFIED", "ok": True, "path": relative, "receipt_sha256": digest, "workflow_id": value["workflow_id"], "recorded_at": value["recorded_at"], "route": value["route"]}


def continuous_proof_history(root: Path) -> dict[str, Any]:
    """Aggregate verified local records without inferring users or savings."""
    workspace = _workspace(root)
    records: list[dict[str, Any]] = []
    invalid_count = 0
    stale_count = 0
    current_count = 0
    directory = workspace / ".factory" / "continuous-proof"
    candidates = sorted(directory.glob("*/continuous-proof-*.json"))[: MAX_RECEIPTS + 1]
    truncated = len(candidates) > MAX_RECEIPTS
    for path in candidates[:MAX_RECEIPTS]:
        try:
            value = _load_json(path, "CONTINUOUS_PROOF_INVALID")
        except ContinuousProofError:
            invalid_count += 1
            continue
        if not _receipt_integrity(value):
            invalid_count += 1
            continue
        checked = verify_continuous_proof(workspace, path)
        current_count += int(checked["ok"])
        stale_count += int(not checked["ok"])
        records.append({
            "workflow_id": value["workflow_id"], "recorded_at": value["recorded_at"], "route": value["route"],
            "receipt_sha256": value["receipt_sha256"], "path": path.relative_to(workspace).as_posix(),
            "current": checked["ok"], "current_marker": checked["marker"], "current_reason": checked.get("reason"),
        })
    records.sort(key=lambda item: (item["recorded_at"], item["workflow_id"], item["receipt_sha256"]))
    routes = Counter(item["route"] for item in records)
    return {
        "schema": CONTINUOUS_PROOF_HISTORY_SCHEMA,
        "marker": "CONTINUOUS_PROOF_HISTORY_READ_ONLY",
        "verified_record_count": len(records),
        "current_record_count": current_count,
        "stale_record_count": stale_count,
        "invalid_record_count": invalid_count,
        "invalid_or_stale_count": invalid_count + stale_count,
        "truncated": truncated,
        "route_counts": {key: routes[key] for key in sorted(routes)},
        "latest": records[-1] if records else None,
        "records": records,
        "authority": dict(_AUTHORITY),
        "claim_limits": ["Records are not unique users.", "No time, token, cost, quality, or productivity savings are inferred."],
    }


def continuous_proof_projection(root: Path) -> dict[str, Any]:
    """Return the bounded Graph Ops projection."""
    history = continuous_proof_history(root)
    return {
        "count": history["verified_record_count"],
        "current_count": history["current_record_count"],
        "stale_count": history["stale_record_count"],
        "invalid_count": history["invalid_record_count"],
        "route_counts": history["route_counts"],
        "latest": history["latest"],
        "truncated": history["truncated"],
        "authority": dict(_AUTHORITY),
    }
