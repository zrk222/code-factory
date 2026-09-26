"""Sealed, local admission packets for externally enforced agent harnesses."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .graph_ops import graph_ops_snapshot
from .loop_passport import verify_loop_passport
from .agent_license import (
    AgentLicenseError,
    admission_license_decision,
    normalize_agent_identity,
)
from .oracle_firewall import OracleFirewallError, admission_oracle_decision
from .intake_parameters import REQUIRED_AUDIT_LANES, verify_intake_binding
from .first_lap import verify_activation_receipt


ADMISSION_REQUEST_SCHEMA = "factory.run-admission.request.v1"
ADMISSION_PACKET_SCHEMA = "factory.run-admission.packet.v1"
_SKIP_PARTS = {".git", ".factory", "__pycache__", "node_modules", ".venv", "venv"}
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class AdmissionError(ValueError):
    """Stable admission error with no hidden side effect."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(
            "ADMISSION_INPUT_UNREADABLE", f"cannot read JSON: {path}"
        ) from exc
    if not isinstance(value, dict):
        raise AdmissionError("ADMISSION_INPUT_INVALID", "JSON input must be an object")
    return value


def _inside(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise AdmissionError(
            "ADMISSION_PATH_OUT_OF_SCOPE", "path must remain inside the workspace"
        ) from exc
    return resolved


def _relative_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID", f"{field} must be a non-empty path"
        )
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise AdmissionError(
            "ADMISSION_PATH_OUT_OF_SCOPE", f"{field} must be workspace relative"
        )
    return path.as_posix().rstrip("/") or "."


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID", f"{field} must be RFC3339 text"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID", f"{field} must be RFC3339 text"
        ) from exc
    if parsed.tzinfo is None:
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID", f"{field} must include a timezone"
        )
    return parsed.astimezone(timezone.utc)


def _fingerprint(root: Path) -> str:
    """Hash workspace content while excluding mutable VCS and Factory outputs."""
    records: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _SKIP_PARTS.intersection(path.relative_to(root).parts):
            continue
        relative = path.relative_to(root).as_posix()
        records.append(
            {"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        )
        if len(records) > 10_000:
            raise AdmissionError(
                "ADMISSION_WORKSPACE_TOO_LARGE",
                "workspace fingerprint exceeds 10000 files",
            )
    return _sha(records)


def _string_list(value: object, field: str, *, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID",
            f"{field} must contain 1 through {maximum} entries",
        )
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID", f"{field} entries must be non-empty strings"
        )
    result = sorted(set(item.strip() for item in value))
    if len(result) != len(value):
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID", f"{field} entries must be unique"
        )
    return result


def _checkpoint_fix(
    root: Path,
    value: object,
    *,
    request_paths: list[str],
    actions: list[str],
    valid_until: datetime,
) -> dict[str, Any]:
    """Validate a human-approved, hash-bound fix that a harness may consume at a checkpoint."""
    value = _checkpoint_fix_object(value)
    checkpoint_id = _checkpoint_fix_id(value)
    _require_checkpoint_write(actions)
    paths = _checkpoint_fix_paths(value, request_paths)
    patch_path, patch_sha256 = _checkpoint_fix_patch(root, value)
    reason, approver, expires_at = _checkpoint_fix_approval(value, valid_until)
    return {
        "checkpoint_id": checkpoint_id,
        "patch_path": patch_path,
        "patch_sha256": patch_sha256,
        "paths": paths,
        "reason": reason,
        "approved_by": approver,
        "approval_expires_at": expires_at,
    }


def _checkpoint_fix_object(value: object) -> dict[str, Any]:
    """Require the exact serialized checkpoint-fix fields."""
    if not isinstance(value, dict) or set(value) != {
        "checkpoint_id",
        "patch_path",
        "patch_sha256",
        "paths",
        "reason",
        "approved_by",
        "approval_expires_at",
    }:
        raise AdmissionError(
            "ADMISSION_CHECKPOINT_FIX_INVALID",
            "checkpoint_fix must contain the exact checkpoint, patch, scope, reason, and approval fields",
        )
    return value


def _checkpoint_fix_id(value: dict[str, Any]) -> str:
    """Validate and return the checkpoint identifier."""
    checkpoint_id = value.get("checkpoint_id")
    if not isinstance(checkpoint_id, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_.:-]{0,95}", checkpoint_id
    ):
        raise AdmissionError(
            "ADMISSION_CHECKPOINT_FIX_INVALID",
            "checkpoint_id must be a safe identifier",
        )
    return checkpoint_id


def _require_checkpoint_write(actions: list[str]) -> None:
    """Require workspace-write authority in the declared request actions."""
    if "write_workspace" not in actions:
        raise AdmissionError(
            "ADMISSION_CHECKPOINT_FIX_UNAUTHORIZED",
            "checkpoint fixes require the declared write_workspace action",
        )


def _checkpoint_fix_paths(value: dict[str, Any], request_paths: list[str]) -> list[str]:
    """Normalize patch scope and reject paths outside the admitted request."""
    paths = [
        _relative_path(item, "checkpoint_fix.paths")
        for item in _string_list(value.get("paths"), "checkpoint_fix.paths")
    ]
    if any(
        not any(
            scope == "." or item == scope or item.startswith(scope.rstrip("/") + "/")
            for scope in request_paths
        )
        for item in paths
    ):
        raise AdmissionError(
            "ADMISSION_CHECKPOINT_FIX_SCOPE_ESCAPE",
            "checkpoint fix paths must remain inside the admitted request scope",
        )
    return paths


def _checkpoint_fix_patch(root: Path, value: dict[str, Any]) -> tuple[str, str]:
    """Validate the workspace-bound patch path and content digest."""
    patch_path = _relative_path(value.get("patch_path"), "checkpoint_fix.patch_path")
    patch = _inside(root, root / patch_path)
    if not patch.is_file():
        raise AdmissionError(
            "ADMISSION_CHECKPOINT_FIX_INVALID",
            "checkpoint_fix.patch_path must name an existing file",
        )
    patch_sha256 = value.get("patch_sha256")
    if (
        not isinstance(patch_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", patch_sha256)
        or hashlib.sha256(patch.read_bytes()).hexdigest() != patch_sha256
    ):
        raise AdmissionError(
            "ADMISSION_CHECKPOINT_FIX_INVALID",
            "checkpoint_fix.patch_sha256 does not match the current patch artifact",
        )
    return patch_path, patch_sha256


def _checkpoint_fix_approval(
    value: dict[str, Any], valid_until: datetime
) -> tuple[str, str, str]:
    """Require named human approval that outlives the admitted run."""
    reason = value.get("reason")
    approved_by = value.get("approved_by")
    if (
        not isinstance(reason, str)
        or not 8 <= len(reason.strip()) <= 500
        or not isinstance(approved_by, str)
        or not approved_by.strip()
    ):
        raise AdmissionError(
            "ADMISSION_CHECKPOINT_FIX_INVALID",
            "checkpoint fix reason and approver are required",
        )
    approval_expires = _utc(
        value.get("approval_expires_at"), "checkpoint_fix.approval_expires_at"
    )
    now = datetime.now(timezone.utc)
    if approval_expires <= now or approval_expires < valid_until:
        raise AdmissionError(
            "ADMISSION_CHECKPOINT_FIX_APPROVAL_INVALID",
            "checkpoint fix approval must outlive the admitted run",
        )
    return reason.strip(), approved_by.strip(), value["approval_expires_at"]


def _request_identifier(request: dict[str, Any]) -> str:
    """Validate the request protocol and bounded identifier."""
    if request.get("schema") != ADMISSION_REQUEST_SCHEMA:
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID", "unsupported admission request schema"
        )
    request_id = request.get("id")
    if not isinstance(request_id, str) or not request_id or len(request_id) > 160:
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID", "id must be 1 through 160 characters"
        )
    return request_id


def _request_validity(request: dict[str, Any]) -> tuple[datetime, datetime]:
    """Require a current expiry no more than one hour in the future."""
    now = datetime.now(timezone.utc)
    valid_until = _utc(request.get("valid_until"), "valid_until")
    if valid_until <= now:
        raise AdmissionError(
            "ADMISSION_EXPIRED", "valid_until must be after current UTC time"
        )
    if valid_until > now + timedelta(hours=1):
        raise AdmissionError(
            "ADMISSION_VALIDITY_TOO_LONG", "valid_until may be at most one hour ahead"
        )
    return now, valid_until


def _request_trigger(
    request: dict[str, Any], passport: dict[str, Any]
) -> dict[str, Any]:
    """Require the request trigger to match its Loop Passport."""
    trigger = request.get("trigger")
    if not isinstance(trigger, dict) or trigger != passport.get("trigger"):
        raise AdmissionError(
            "ADMISSION_TRIGGER_MISMATCH",
            "request trigger must exactly match the Loop Passport",
        )
    return trigger


def _request_actions(request: dict[str, Any], passport: dict[str, Any]) -> list[str]:
    """Normalize actions and enforce the Loop Passport capability set."""
    actions = _string_list(request.get("actions"), "actions")
    declared_actions = set(passport.get("capabilities", {}).get("actions", []))
    if not set(actions).issubset(declared_actions):
        raise AdmissionError(
            "ADMISSION_ACTION_UNDECLARED",
            "request action is absent from the Loop Passport",
        )
    return actions


def _request_paths(
    root: Path, request: dict[str, Any], passport: dict[str, Any]
) -> list[str]:
    """Normalize requested paths and enforce passport scope and containment."""
    paths = [
        _relative_path(value, "paths")
        for value in _string_list(request.get("paths"), "paths")
    ]
    allowed_paths = passport.get("workspace", {}).get("allowed_paths", [])
    if not isinstance(allowed_paths, list) or not all(
        isinstance(item, str) for item in allowed_paths
    ):
        raise AdmissionError(
            "ADMISSION_PASSPORT_INVALID", "Loop Passport has invalid allowed paths"
        )
    for item in paths:
        if not any(
            scope == "." or item == scope or item.startswith(scope.rstrip("/") + "/")
            for scope in allowed_paths
        ):
            raise AdmissionError(
                "ADMISSION_PATH_OUT_OF_SCOPE",
                "request path is absent from the Loop Passport",
            )
        _inside(root, root / item)
    return paths


def _request_budget(
    request: dict[str, Any], passport: dict[str, Any]
) -> dict[str, Any]:
    """Require budget keys and values to stay within the Loop Passport."""
    budget = request.get("budget")
    declared_budget = passport.get("budgets")
    if (
        not isinstance(budget, dict)
        or not isinstance(declared_budget, dict)
        or set(budget) != set(declared_budget)
    ):
        raise AdmissionError(
            "ADMISSION_BUDGET_INVALID",
            "request budget must match Loop Passport budget keys",
        )
    for key, cap in declared_budget.items():
        value = budget.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or value < 0
            or value > cap
        ):
            raise AdmissionError(
                "ADMISSION_BUDGET_INVALID", f"request {key} exceeds the Loop Passport"
            )
    return budget


def _normalize_approval(
    item: object,
    required: set[str],
    seen_actions: set[str],
    valid_until: datetime,
    now: datetime,
) -> dict[str, str]:
    """Validate one named approval and normalize its recorded fields."""
    if not isinstance(item, dict) or set(item) != {
        "action",
        "approved_by",
        "expires_at",
    }:
        raise AdmissionError(
            "ADMISSION_REQUEST_INVALID",
            "approval must have action, approved_by, and expires_at",
        )
    action, approver = item["action"], item["approved_by"]
    if (
        action not in required
        or action in seen_actions
        or not isinstance(approver, str)
        or not approver.strip()
    ):
        raise AdmissionError(
            "ADMISSION_APPROVAL_MISSING",
            "approval action or named approver is invalid",
        )
    if _utc(item["expires_at"], "approval.expires_at") <= now:
        raise AdmissionError(
            "ADMISSION_APPROVAL_EXPIRED",
            "approval expiry must be after current UTC time",
        )
    if valid_until > _utc(item["expires_at"], "approval.expires_at"):
        raise AdmissionError(
            "ADMISSION_VALIDITY_EXCEEDS_APPROVAL",
            "valid_until may not outlive a required approval",
        )
    return {
        "action": action,
        "approved_by": approver.strip(),
        "expires_at": item["expires_at"],
    }


def _request_approvals(
    request: dict[str, Any],
    passport: dict[str, Any],
    actions: list[str],
    valid_until: datetime,
    now: datetime,
) -> list[dict[str, str]]:
    """Validate the exact approval set required for protected actions."""
    approvals = request.get("approvals")
    required = set(passport.get("approvals", {}).get("required_for", [])) & set(actions)
    if not isinstance(approvals, list) or len(approvals) != len(required):
        raise AdmissionError(
            "ADMISSION_APPROVAL_MISSING",
            "one named approval is required for every requested protected action",
        )
    normalized_approvals: list[dict[str, str]] = []
    seen_actions: set[str] = set()
    for item in approvals:
        normalized = _normalize_approval(item, required, seen_actions, valid_until, now)
        action = normalized["action"]
        seen_actions.add(action)
        normalized_approvals.append(normalized)
    return sorted(normalized_approvals, key=lambda item: item["action"])


def _request_intake_binding(root: Path, binding: object) -> dict[str, str]:
    """Validate and normalize the request's content-bound intake reference."""
    if not isinstance(binding, dict) or set(binding) != {
        "path",
        "parameter_sha256",
    }:
        raise AdmissionError(
            "ADMISSION_INTAKE_BINDING_INVALID",
            "intake_parameters must contain path and parameter_sha256",
        )
    path = _relative_path(binding.get("path"), "intake_parameters.path")
    if not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("parameter_sha256"))):
        raise AdmissionError(
            "ADMISSION_INTAKE_BINDING_INVALID",
            "intake_parameters.parameter_sha256 must be a lowercase SHA-256 digest",
        )
    if not (_inside(root, root / path).is_file()):
        raise AdmissionError(
            "ADMISSION_INTAKE_BINDING_INVALID",
            "intake_parameters.path must name an existing file",
        )
    return {"path": path, "parameter_sha256": binding["parameter_sha256"]}


def _validate_request(
    root: Path, request: dict[str, Any], passport: dict[str, Any]
) -> dict[str, Any]:
    """Validate request phases in protocol order and return a canonical shape."""
    request_id = _request_identifier(request)
    now, valid_until = _request_validity(request)
    trigger = _request_trigger(request, passport)
    actions = _request_actions(request, passport)
    paths = _request_paths(root, request, passport)
    budget = _request_budget(request, passport)
    approvals = _request_approvals(request, passport, actions, valid_until, now)
    normalized = {
        "schema": ADMISSION_REQUEST_SCHEMA,
        "id": request_id,
        "valid_until": request["valid_until"],
        "trigger": trigger,
        "actions": actions,
        "paths": paths,
        "budget": budget,
        "approvals": approvals,
    }
    if "agent" in request:
        normalized["agent"] = normalize_agent_identity(request.get("agent"), "agent")
    if "oracle_contract" in request:
        normalized["oracle_contract"] = _relative_path(
            request.get("oracle_contract"), "oracle_contract"
        )
    if "intake_parameters" in request:
        normalized["intake_parameters"] = _request_intake_binding(
            root, request.get("intake_parameters")
        )
    if "checkpoint_fix" in request:
        normalized["checkpoint_fix"] = _checkpoint_fix(
            root,
            request.get("checkpoint_fix"),
            request_paths=paths,
            actions=actions,
            valid_until=valid_until,
        )
    return normalized


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(_canonical(payload) + b"\n")
    os.replace(temporary, path)


def _verified_passport(passport_path: Path) -> dict[str, Any]:
    """Load a Loop Passport only after its verifier confirms the sealed form."""
    try:
        passport_result = verify_loop_passport(passport_path)
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(
            "ADMISSION_PASSPORT_INVALID", "Loop Passport cannot be verified"
        ) from exc
    if not passport_result["valid"]:
        raise AdmissionError(
            "ADMISSION_PASSPORT_INVALID", "Loop Passport does not verify"
        )
    return _load(passport_path)


def _agent_license_for_admission(
    workspace: Path, passport: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any] | None:
    """Translate license policy failures into stable admission failures."""
    try:
        return admission_license_decision(workspace, passport, request)
    except AgentLicenseError as exc:
        raise AdmissionError(exc.code, str(exc)) from exc


def _intake_for_admission(
    workspace: Path,
    intake_binding: object,
    request: dict[str, Any],
    requested_autonomy: str,
    require_intake: bool,
) -> None:
    """Require and verify authoritative intake evidence when bound."""
    if intake_binding is None and require_intake:
        raise AdmissionError(
            "E_INTAKE_BINDING_REQUIRED",
            "strict admission requires an authoritative intake_parameters binding",
        )
    if isinstance(intake_binding, dict):
        _verify_admission_intake(workspace, intake_binding, request, requested_autonomy)


def _verify_admission_intake(
    workspace: Path,
    intake_binding: dict[str, Any],
    request: dict[str, Any],
    requested_autonomy: str,
) -> None:
    """Check the intake digest, lanes, scope, budget, mode, and expiry."""
    binding = verify_intake_binding(
        workspace,
        Path(intake_binding["path"]),
        scope_paths=request["paths"],
        required_lanes=list(REQUIRED_AUDIT_LANES),
        budgets=request["budget"],
        mode=requested_autonomy,
        expires_at=request["valid_until"],
        binding_sha256=intake_binding["parameter_sha256"],
    )
    if not binding.get("ok"):
        first = (
            binding.get("errors")
            or [
                {
                    "code": "E_INTAKE_PARAMETER_DRIFT",
                    "detail": "intake binding failed",
                }
            ]
        )[0]
        raise AdmissionError(
            str(first.get("code", "E_INTAKE_PARAMETER_DRIFT")),
            str(first.get("detail", "intake binding failed")),
        )


def _oracle_for_admission(
    workspace: Path,
    request: dict[str, Any],
    requested_autonomy: str,
    license_value: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Verify an optional Oracle contract and require one for licensed autonomy."""
    oracle_value = None
    if request.get("oracle_contract"):
        try:
            oracle_value = admission_oracle_decision(
                workspace,
                Path(request["oracle_contract"]),
                requested_autonomy,
                request["paths"],
            )
        except OracleFirewallError as exc:
            raise AdmissionError(exc.code, str(exc)) from exc
    elif (
        requested_autonomy == "autonomous"
        and license_value is not None
        and license_value.get("tier") == "autonomous"
    ):
        raise AdmissionError(
            "ORACLE_CONTRACT_REQUIRED",
            "autonomous admission requires a current sealed Oracle Firewall contract",
        )
    return oracle_value


def _activation_for_admission(
    workspace: Path, requested_autonomy: str
) -> dict[str, Any] | None:
    """Require a strict First Lap receipt when the passport permits autonomy."""
    if requested_autonomy != "autonomous":
        return None
    activation = verify_activation_receipt(workspace, require_strict=True)
    if activation.get("state") != "READY" or activation.get("verified") is not True:
        raise AdmissionError(
            "FIRST_LAP_ACTIVATION_REQUIRED",
            "autonomous admission requires a strict, immutable First Lap activation receipt",
        )
    return activation


def _seal_admission_packet(
    workspace: Path,
    passport_path: Path,
    passport: dict[str, Any],
    request: dict[str, Any],
    snapshot: dict[str, Any],
    out_dir: Path | None,
    intake_binding: object,
    license_value: dict[str, Any] | None,
    oracle_value: dict[str, Any] | None,
    activation: dict[str, Any] | None,
) -> dict[str, Any]:
    """Bind admission evidence into a new immutable local packet."""
    target_dir = _inside(
        workspace,
        Path(out_dir) if out_dir is not None else workspace / ".factory" / "admissions",
    )
    workspace_sha256 = _fingerprint(workspace)
    core = {
        "schema": ADMISSION_PACKET_SCHEMA,
        "id": request["id"],
        "verdict": "SEALED",
        "markers": ["ADMISSION_PACKET_SEALED", "ADMISSION_EXTERNAL_EFFECTS_DENIED"],
        "workspace": {"fingerprint_sha256": workspace_sha256},
        "graph": {
            "sha256": snapshot.get("base_graph_sha256", snapshot["graph_sha256"])
        },
        "passport": {
            "path": str(passport_path.relative_to(workspace)),
            "sha256": passport["passport_sha256"],
        },
        "request": request,
        "request_sha256": _sha(request),
        "authority": dict(_AUTHORITY),
        "scope_limits": [
            "Packet verification is local metadata validation only.",
            "The selected harness must enforce identity, sandboxing, network policy, credentials, and execution.",
        ],
    }
    if isinstance(intake_binding, dict):
        core["intake_parameters"] = dict(intake_binding)
    if license_value is not None:
        core["agent_license"] = {
            "license_sha256": license_value["license_sha256"],
            "state_sha256": _license_state_sha256(license_value),
            "tier": license_value["tier"],
            "allowed_paths": license_value["allowed_paths"],
            "expires_at": license_value["expires_at"],
            "identity_provenance": license_value["identity_provenance"],
        }
    if oracle_value is not None:
        core["oracle"] = {
            "contract_path": oracle_value["contract_path"],
            "contract_sha256": oracle_value["contract_sha256"],
            "requested_autonomy": oracle_value["requested_autonomy"],
            "scope_paths": oracle_value["scope_paths"],
        }
    if activation is not None:
        core["first_lap_activation"] = {
            "receipt_sha256": activation["receipt_sha256"],
            "path": activation["path"],
        }
    packet = {**core, "packet_sha256": _sha(core)}
    path = target_dir / f"{request['id']}.admission.json"
    if path.exists():
        raise AdmissionError(
            "ADMISSION_PACKET_EXISTS", "admission packet already exists"
        )
    _atomic_json(path, packet)
    return {**packet, "path": str(path.resolve())}


def prepare_admission(
    root: Path,
    passport_path: Path,
    request_path: Path,
    out_dir: Path | None = None,
    *,
    require_intake: bool = False,
) -> dict[str, Any]:
    """Seal one admissible external-run proposal without invoking a harness."""
    workspace = Path(root).resolve()
    passport_path = _inside(workspace, Path(passport_path))
    request_path = _inside(workspace, Path(request_path))
    if not passport_path.is_file() or not request_path.is_file():
        raise AdmissionError(
            "ADMISSION_INPUT_UNREADABLE", "passport and request files must exist"
        )
    passport = _verified_passport(passport_path)
    snapshot = graph_ops_snapshot(workspace)
    if not snapshot.get("complete"):
        raise AdmissionError(
            "ADMISSION_GRAPH_INCOMPLETE", "Graph Ops snapshot is incomplete"
        )
    request = _validate_request(workspace, _load(request_path), passport)
    license_value = _agent_license_for_admission(workspace, passport, request)
    requested_autonomy = str(passport.get("autonomy") or "human_controlled")
    intake_binding = request.get("intake_parameters")
    _intake_for_admission(
        workspace, intake_binding, request, requested_autonomy, require_intake
    )
    oracle_value = _oracle_for_admission(
        workspace, request, requested_autonomy, license_value
    )
    activation = _activation_for_admission(workspace, requested_autonomy)
    return _seal_admission_packet(
        workspace,
        passport_path,
        passport,
        request,
        snapshot,
        out_dir,
        intake_binding,
        license_value,
        oracle_value,
        activation,
    )


def _packet_valid(payload: dict[str, Any]) -> bool:
    if payload.get("schema") != ADMISSION_PACKET_SCHEMA:
        return False
    core = {
        key: value
        for key, value in payload.items()
        if key not in {"packet_sha256", "path"}
    }
    return payload.get("packet_sha256") == _sha(core)


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "schema": ADMISSION_PACKET_SCHEMA,
        "verdict": "BLOCKED",
        "marker": "ADMISSION_PACKET_BLOCKED",
        "reason": reason,
        "authority": dict(_AUTHORITY),
    }


def _license_state_sha256(value: dict[str, Any]) -> str:
    """Hash durable license state without the per-read issued-at timestamp."""
    fields = (
        "tier",
        "reason",
        "allowed_paths",
        "expires_at",
        "identity_provenance",
        "evidence",
        "incidents",
        "policy",
    )
    return _sha({field: value.get(field) for field in fields})


def _bound_passport_path(workspace: Path, packet: dict[str, Any]) -> Path | None:
    passport_ref = packet.get("passport", {}).get("path")
    if not isinstance(passport_ref, str) or not passport_ref:
        return None
    try:
        return _inside(workspace, workspace / passport_ref)
    except AdmissionError:
        return None


def _passport_binding_is_current(path: Path, packet: dict[str, Any]) -> bool:
    try:
        result = verify_loop_passport(path)
    except (OSError, json.JSONDecodeError):
        return False
    return bool(
        result["valid"]
        and result.get("passport_sha256") == packet.get("passport", {}).get("sha256")
    )


def _request_binding_is_current(
    workspace: Path, packet: dict[str, Any], passport_path: Path
) -> str | None:
    try:
        _validate_request(workspace, packet.get("request", {}), _load(passport_path))
    except AdmissionError as exc:
        return exc.code
    return (
        None
        if _sha(packet.get("request")) == packet.get("request_sha256")
        else "request_sha256_mismatch"
    )


def _intake_binding_is_current(
    workspace: Path, packet: dict[str, Any], passport_path: Path
) -> str | None:
    binding = packet.get("intake_parameters")
    if binding is None:
        return None
    if not isinstance(binding, dict) or set(binding) != {"path", "parameter_sha256"}:
        return "E_INTAKE_BINDING_INVALID"
    request = packet.get("request", {})
    passport = _load(passport_path)
    try:
        result = verify_intake_binding(
            workspace,
            Path(str(binding.get("path"))),
            scope_paths=request.get("paths"),
            required_lanes=list(REQUIRED_AUDIT_LANES),
            budgets=request.get("budget"),
            mode=str(passport.get("autonomy") or "human_controlled"),
            expires_at=request.get("valid_until"),
            binding_sha256=binding.get("parameter_sha256"),
        )
    except (TypeError, ValueError, OSError):
        return "E_INTAKE_PARAMETER_DRIFT"
    if result.get("ok"):
        return None
    first = (result.get("errors") or [{"code": "E_INTAKE_PARAMETER_DRIFT"}])[0]
    return str(first.get("code", "E_INTAKE_PARAMETER_DRIFT"))


def _read_admission_packet(packet_path: Path) -> dict[str, Any] | None:
    """Read a packet when present and syntactically valid."""
    if not packet_path.is_file():
        return None
    try:
        return _load(packet_path)
    except AdmissionError:
        return None


def _workspace_binding_status(
    workspace: Path, packet: dict[str, Any]
) -> dict[str, Any] | None:
    """Fail closed for incomplete graph evidence and mark changed workspaces stale."""
    snapshot = graph_ops_snapshot(workspace)
    graph_sha256 = snapshot.get("base_graph_sha256", snapshot.get("graph_sha256"))
    if not snapshot.get("complete"):
        return _blocked("graph_incomplete")
    current_workspace = _fingerprint(workspace)
    if current_workspace != packet.get("workspace", {}).get(
        "fingerprint_sha256"
    ) or graph_sha256 != packet.get("graph", {}).get("sha256"):
        return {
            "schema": ADMISSION_PACKET_SCHEMA,
            "verdict": "STALE",
            "marker": "ADMISSION_STALE",
            "reason": "workspace_or_graph_changed",
            "authority": dict(_AUTHORITY),
        }
    return None


def _current_license_state(
    workspace: Path, packet: dict[str, Any], passport: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """Re-derive license scope and compare the sealed policy state."""
    stored_license = packet.get("agent_license")
    try:
        current_license = admission_license_decision(
            workspace, passport, packet.get("request", {})
        )
    except AgentLicenseError as exc:
        return None, exc.code
    if isinstance(stored_license, dict):
        if not isinstance(current_license, dict):
            return current_license, "agent_license_binding_invalid"
        for field in ("tier", "allowed_paths", "expires_at", "identity_provenance"):
            if stored_license.get(field) != current_license.get(field):
                return current_license, "agent_license_binding_invalid"
        if stored_license.get("state_sha256") != _license_state_sha256(current_license):
            return current_license, "agent_license_binding_invalid"
    return current_license, None


def _oracle_binding_error(
    workspace: Path,
    packet: dict[str, Any],
    passport: dict[str, Any],
    current_license: dict[str, Any] | None,
) -> str | None:
    """Revalidate autonomous Oracle requirements and the sealed contract digest."""
    oracle = packet.get("oracle")
    requested_autonomy = str(passport.get("autonomy") or "human_controlled")
    if _oracle_contract_required(requested_autonomy, current_license, oracle):
        return "ORACLE_CONTRACT_REQUIRED"
    if isinstance(oracle, dict):
        return _verify_oracle_packet_contract(workspace, packet, oracle)
    return None


def _oracle_contract_required(
    requested_autonomy: str,
    current_license: dict[str, Any] | None,
    oracle: object,
) -> bool:
    """Determine whether an autonomous license requires a sealed Oracle contract."""
    return (
        requested_autonomy == "autonomous"
        and isinstance(current_license, dict)
        and current_license.get("tier") == "autonomous"
        and not isinstance(oracle, dict)
    )


def _verify_oracle_packet_contract(
    workspace: Path, packet: dict[str, Any], oracle: dict[str, Any]
) -> str | None:
    """Re-run Oracle policy and compare the result with its sealed digest."""
    try:
        decision = admission_oracle_decision(
            workspace,
            Path(str(oracle.get("contract_path") or "")),
            str(oracle.get("requested_autonomy") or "human_controlled"),
            packet.get("request", {}).get("paths", []),
        )
    except (OracleFirewallError, TypeError, ValueError) as exc:
        return getattr(exc, "code", "oracle_binding_invalid")
    if decision.get("contract_sha256") != oracle.get("contract_sha256"):
        return "oracle_contract_sha256_mismatch"
    return None


def _ready_admission_result(packet: dict[str, Any]) -> dict[str, Any]:
    """Build the authority-free READY projection and optional checkpoint binding."""
    result = {
        "schema": ADMISSION_PACKET_SCHEMA,
        "verdict": "READY",
        "marker": "ADMISSION_READY",
        "packet_sha256": packet["packet_sha256"],
        "authority": dict(_AUTHORITY),
        "scope_limits": ["A ready packet does not execute the selected harness."],
    }
    fix = packet.get("request", {}).get("checkpoint_fix")
    if isinstance(fix, dict):
        result["checkpoint_fix"] = {
            "checkpoint_id": fix.get("checkpoint_id"),
            "patch_path": fix.get("patch_path"),
            "patch_sha256": fix.get("patch_sha256"),
            "state": "BOUND_FOR_EXTERNAL_HARNESS",
            "authority": "none",
        }
    return result


def verify_admission(root: Path, packet_path: Path) -> dict[str, Any]:
    """Revalidate a packet immediately before an external harness may consume it."""
    workspace = Path(root).resolve()
    packet_path = _inside(workspace, Path(packet_path))
    packet = _read_admission_packet(packet_path)
    if packet is None:
        return _blocked("packet_unreadable")
    if not _packet_valid(packet):
        return _blocked("packet_sha256_mismatch")
    passport_path = _bound_passport_path(workspace, packet)
    if passport_path is None or not _passport_binding_is_current(passport_path, packet):
        return _blocked("passport_binding_invalid")
    workspace_status = _workspace_binding_status(workspace, packet)
    if workspace_status is not None:
        return workspace_status
    request_error = _request_binding_is_current(workspace, packet, passport_path)
    if request_error:
        return _blocked(request_error)
    intake_error = _intake_binding_is_current(workspace, packet, passport_path)
    if intake_error:
        return _blocked(intake_error)
    # A packet is only an immutable snapshot if its derived license cap is also
    # re-derived at consumption time.  Otherwise an agent could keep a packet
    # after a demotion or a scope reduction and present yesterday's authority.
    passport = _load(passport_path)
    current_license, license_error = _current_license_state(workspace, packet, passport)
    if license_error:
        return _blocked(license_error)
    oracle_error = _oracle_binding_error(workspace, packet, passport, current_license)
    if oracle_error:
        return _blocked(oracle_error)
    return _ready_admission_result(packet)
