"""Local, deterministic enterprise admission reference for FactoryLine.

The module proves a narrowly defined *decision* before a separate runner can
perform a consequential operation.  It deliberately does not invoke a tool,
authenticate a cloud workload, or enforce an Envoy/eBPF/container boundary.
Those deployment controls must call this decision surface and independently
prove their topology in a production integration.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any
from .agent_license import normalize_agent_identity
from .enterprise_receipts import (
    EnterpriseReceiptError,
    canonical_json,
    sign_payload,
    verify_signed_document,
)
from .semantic_authority import verify_semantic_binding
from dataclasses import dataclass
from datetime import date
from .enterprise_ops import (
    CommercialUsageError,
    Reservation,
    UsageLedger,
    default_home,
)
from .enterprise_receipts import (
    PRODUCT,
    CommercialEntitlementError,
    covering_entitlement,
    load_entitlements,
    verify_entitlement_envelope,
)
from .enterprise_ops import RERUN_BINDING_FIELDS
from . import utc_now as _now
from . import PrefixedCodedError
from . import PrefixedCodedRuntimeError

WORKLOAD_IDENTITY_SCHEMA = "factory.workload-identity.v1"
WORKLOAD_IDENTITY_PAYLOAD_TYPE = "application/vnd.factory.workload-identity.v1+json"
ENFORCEMENT_POLICY_SCHEMA = "factory.enforcement-policy.v1"
ENFORCEMENT_POLICY_PAYLOAD_TYPE = "application/vnd.factory.enforcement-policy.v1+json"
WORKLOAD_REVOCATIONS_SCHEMA = "factory.workload-revocations.v1"
WORKLOAD_REVOCATIONS_PAYLOAD_TYPE = (
    "application/vnd.factory.workload-revocations.v1+json"
)
DECISION_SCHEMA = "factory.enterprise-enforcement-decision.v1"
PROJECTION_SCHEMA = "factory.enterprise-enforcement-projection.v1"
MAX_IDENTITY_LIFETIME = timedelta(hours=24)
ACTION_CLASSES = frozenset(
    {
        "read",
        "test",
        "repair",
        "merge",
        "deploy",
        "publish",
        "credential",
        "message",
        "purchase",
    }
)
AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class EnterpriseEnforcementError(PrefixedCodedRuntimeError):
    pass


def _stamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise EnterpriseEnforcementError(
            "E_WORKLOAD_IDENTITY_INVALID", f"{field} must be an RFC3339 timestamp"
        )
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnterpriseEnforcementError(
            "E_WORKLOAD_IDENTITY_INVALID", f"{field} is invalid"
        ) from exc
    if result.tzinfo is None:
        raise EnterpriseEnforcementError(
            "E_WORKLOAD_IDENTITY_INVALID", f"{field} must include an offset"
        )
    return result.astimezone(timezone.utc)


def _text(value: object, field: str, *, limit: int = 160) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT",
            f"{field} must be a non-empty string up to {limit} characters",
        )
    return value.strip()


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(ch not in "0123456789abcdef" for ch in result):
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", f"{field} must be a SHA-256 hex digest"
        )
    return result


def _paths(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", f"{field} must contain 1 through 64 relative paths"
        )
    result: list[str] = []
    for raw in value:
        item = _text(raw, field, limit=512).replace("\\", "/")
        path = Path(item)
        if path.is_absolute() or ".." in path.parts:
            raise EnterpriseEnforcementError(
                "E_ENFORCEMENT_INPUT", f"{field} cannot escape a workspace"
            )
        result.append(item.rstrip("/") or ".")
    return sorted(set(result))


def _within_scope(requested: list[str], allowed: list[str]) -> bool:
    for candidate in requested:
        if not any(
            base == "." or candidate == base or candidate.startswith(base + "/")
            for base in allowed
        ):
            return False
    return True


def _actions(value: object, field: str, *, require_known: bool = True) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", f"{field} must contain 1 through 32 actions"
        )
    result = sorted({_text(item, field, limit=80).lower() for item in value})
    if require_known and any(item not in ACTION_CLASSES for item in result):
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", f"{field} includes an unknown action class"
        )
    return result


def _write_new(root: Path, output: Path, payload: dict[str, Any]) -> Path:
    root = Path(root).resolve()
    target = (
        (root / output).resolve()
        if not Path(output).is_absolute()
        else Path(output).resolve()
    )
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_PATH", "output must remain inside the workspace"
        ) from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_IMMUTABLE", "refusing to overwrite an enforcement decision"
        ) from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json(payload) + b"\n")
    return target


def _decision_target(workspace: Path, output: Path, directory: Path) -> Path:
    target = (
        (workspace / output).resolve()
        if not Path(output).is_absolute()
        else Path(output).resolve()
    )
    try:
        target.relative_to(directory.resolve())
    except ValueError as exc:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_PATH",
            "decision output must stay under .factory/enterprise-enforcement/decisions",
        ) from exc
    return target


def _verification_input_path(
    workspace: Path, value: object, label: str, *, required: bool = True
) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, Path):
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", f"{label} must be a path"
        )
    candidate = (
        value.resolve() if value.is_absolute() else (workspace / value).resolve()
    )
    try:
        relative = candidate.relative_to(workspace).as_posix()
    except ValueError as exc:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_PATH", f"{label} must remain inside the workspace"
        ) from exc
    if not candidate.is_file():
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", f"{label} is unavailable"
        )
    return relative


def _claim_action_id(directory: Path, action_id: str) -> Path:
    """Atomically claim an action id before its immutable decision is written."""
    claim_dir = directory / ".claims"
    claim_dir.mkdir(parents=True, exist_ok=True)
    claim = claim_dir / f"{hashlib.sha256(action_id.encode('utf-8')).hexdigest()}.claim"
    try:
        descriptor = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_REPLAY",
            "action_id already has an immutable enterprise decision",
        ) from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json({"action_id": action_id}) + b"\n")
    return claim


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", str(exc)) from exc
    if not isinstance(value, dict):
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", "JSON must be an object"
        )
    return value


def validate_workload_identity(payload: object) -> dict[str, Any]:
    """Normalize one bounded workload identity before it is signed or trusted."""
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != WORKLOAD_IDENTITY_SCHEMA
    ):
        raise EnterpriseEnforcementError(
            "E_WORKLOAD_IDENTITY_INVALID", f"schema must be {WORKLOAD_IDENTITY_SCHEMA}"
        )
    required = {
        "schema",
        "tenant_id",
        "workload_id",
        "subject",
        "audience",
        "issued_at",
        "expires_at",
        "agent",
        "allowed_action_classes",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise EnterpriseEnforcementError(
            "E_WORKLOAD_IDENTITY_INVALID", f"missing fields: {missing}"
        )
    issued_at = _time(payload["issued_at"], "issued_at")
    expires_at = _time(payload["expires_at"], "expires_at")
    if expires_at <= issued_at or expires_at - issued_at > MAX_IDENTITY_LIFETIME:
        raise EnterpriseEnforcementError(
            "E_WORKLOAD_IDENTITY_INVALID",
            "identity must expire after issuance and within 24 hours",
        )
    return {
        "schema": WORKLOAD_IDENTITY_SCHEMA,
        "tenant_id": _text(payload["tenant_id"], "tenant_id"),
        "workload_id": _text(payload["workload_id"], "workload_id"),
        "subject": _text(payload["subject"], "subject"),
        "audience": _text(payload["audience"], "audience", limit=320),
        "issued_at": _stamp(issued_at),
        "expires_at": _stamp(expires_at),
        "agent": normalize_agent_identity(payload["agent"], "agent"),
        "allowed_action_classes": _actions(
            payload["allowed_action_classes"], "allowed_action_classes"
        ),
    }


def validate_enforcement_policy(payload: object) -> dict[str, Any]:
    """Normalize one tenant policy without granting an action or contacting a service."""
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != ENFORCEMENT_POLICY_SCHEMA
    ):
        raise EnterpriseEnforcementError(
            "E_POLICY_INVALID", f"schema must be {ENFORCEMENT_POLICY_SCHEMA}"
        )
    required = {
        "schema",
        "policy_id",
        "version",
        "tenant_id",
        "audience",
        "allowed_action_classes",
        "allowed_scope_paths",
        "require_semantic_lease",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise EnterpriseEnforcementError(
            "E_POLICY_INVALID", f"missing fields: {missing}"
        )
    if not isinstance(payload["require_semantic_lease"], bool):
        raise EnterpriseEnforcementError(
            "E_POLICY_INVALID", "require_semantic_lease must be boolean"
        )
    return {
        "schema": ENFORCEMENT_POLICY_SCHEMA,
        "policy_id": _text(payload["policy_id"], "policy_id"),
        "version": _text(payload["version"], "version", limit=64),
        "tenant_id": _text(payload["tenant_id"], "tenant_id"),
        "audience": _text(payload["audience"], "audience", limit=320),
        "allowed_action_classes": _actions(
            payload["allowed_action_classes"], "allowed_action_classes"
        ),
        "allowed_scope_paths": _paths(
            payload["allowed_scope_paths"], "allowed_scope_paths"
        ),
        "require_semantic_lease": payload["require_semantic_lease"],
    }


def _signed_payload(
    path: Path, *, payload_type: str, schema: str, trust_root_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        verified = verify_signed_document(
            path,
            payload_type=payload_type,
            schema=schema,
            trust_root_path=trust_root_path,
        )
    except EnterpriseReceiptError as exc:
        raise EnterpriseEnforcementError(exc.code, exc.message) from exc
    return verified["payload"], verified


def verify_workload_identity(
    path: Path,
    *,
    trust_root_path: Path,
    revocations_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify signed local identity, bounded lifetime, and optional signed revocations."""
    payload, verified = _signed_payload(
        Path(path),
        payload_type=WORKLOAD_IDENTITY_PAYLOAD_TYPE,
        schema=WORKLOAD_IDENTITY_SCHEMA,
        trust_root_path=Path(trust_root_path),
    )
    identity = validate_workload_identity(payload)
    current = now or _now()
    if _time(identity["issued_at"], "issued_at") > current:
        raise EnterpriseEnforcementError(
            "E_WORKLOAD_NOT_ACTIVE", "workload identity is not active yet"
        )
    if _time(identity["expires_at"], "expires_at") <= current:
        raise EnterpriseEnforcementError(
            "E_WORKLOAD_EXPIRED", "workload identity has expired"
        )
    revocation_status = "NOT_CHECKED"
    if revocations_path is not None:
        revocations, _ = _signed_payload(
            Path(revocations_path),
            payload_type=WORKLOAD_REVOCATIONS_PAYLOAD_TYPE,
            schema=WORKLOAD_REVOCATIONS_SCHEMA,
            trust_root_path=Path(trust_root_path),
        )
        entries = revocations.get("entries")
        if not isinstance(entries, list):
            raise EnterpriseEnforcementError(
                "E_REVOCATIONS_INVALID", "revocation entries must be a list"
            )
        for entry in entries:
            if not isinstance(entry, dict):
                raise EnterpriseEnforcementError(
                    "E_REVOCATIONS_INVALID", "revocation entry must be an object"
                )
            if all(
                entry.get(key) == identity[key]
                for key in ("tenant_id", "workload_id", "subject")
            ):
                revoked_at = _time(entry.get("revoked_at"), "revoked_at")
                if revoked_at <= current:
                    raise EnterpriseEnforcementError(
                        "E_WORKLOAD_REVOKED", "workload identity is revoked"
                    )
        revocation_status = "CHECKED"
    return {
        "identity": identity,
        "identity_sha256": verified["payload_sha256"],
        "signature": verified["signature"],
        "revocation_status": revocation_status,
        "verification": verified["verification"],
    }


def verify_enforcement_policy(path: Path, *, trust_root_path: Path) -> dict[str, Any]:
    """Verify one signed tenant policy against the explicit offline trust root."""
    payload, verified = _signed_payload(
        Path(path),
        payload_type=ENFORCEMENT_POLICY_PAYLOAD_TYPE,
        schema=ENFORCEMENT_POLICY_SCHEMA,
        trust_root_path=Path(trust_root_path),
    )
    return {
        "policy": validate_enforcement_policy(payload),
        "policy_sha256": verified["payload_sha256"],
        "signature": verified["signature"],
        "verification": verified["verification"],
    }


def sign_workload_identity(
    payload: object,
    *,
    private_key_path: Path,
    keyid: str,
    identity: str,
    issuer: str,
    out: Path,
) -> dict[str, Any]:
    """Create a development or integration DSSE workload-identity envelope locally."""
    value = validate_workload_identity(payload)
    try:
        envelope = sign_payload(
            value,
            payload_type=WORKLOAD_IDENTITY_PAYLOAD_TYPE,
            private_key_path=private_key_path,
            keyid=keyid,
            identity=identity,
            issuer=issuer,
        )
    except EnterpriseReceiptError as exc:
        raise EnterpriseEnforcementError(exc.code, exc.message) from exc
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(canonical_json(envelope) + b"\n")
    return envelope


def sign_enforcement_policy(
    payload: object,
    *,
    private_key_path: Path,
    keyid: str,
    identity: str,
    issuer: str,
    out: Path,
) -> dict[str, Any]:
    """Create a reviewed DSSE tenant-policy envelope without granting runtime authority."""
    value = validate_enforcement_policy(payload)
    try:
        envelope = sign_payload(
            value,
            payload_type=ENFORCEMENT_POLICY_PAYLOAD_TYPE,
            private_key_path=private_key_path,
            keyid=keyid,
            identity=identity,
            issuer=issuer,
        )
    except EnterpriseReceiptError as exc:
        raise EnterpriseEnforcementError(exc.code, exc.message) from exc
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(canonical_json(envelope) + b"\n")
    return envelope


def sign_workload_revocations(
    entries: object,
    *,
    private_key_path: Path,
    keyid: str,
    identity: str,
    issuer: str,
    out: Path,
) -> dict[str, Any]:
    """Create a signed local workload-revocation list for deterministic denial checks."""
    if not isinstance(entries, list) or any(
        not isinstance(item, dict) for item in entries
    ):
        raise EnterpriseEnforcementError(
            "E_REVOCATIONS_INVALID", "entries must be a list of objects"
        )
    normalized = []
    for item in entries:
        normalized.append(
            {
                "tenant_id": _text(item.get("tenant_id"), "tenant_id"),
                "workload_id": _text(item.get("workload_id"), "workload_id"),
                "subject": _text(item.get("subject"), "subject"),
                "revoked_at": _stamp(_time(item.get("revoked_at"), "revoked_at")),
                "reason": _text(item.get("reason"), "reason", limit=320),
            }
        )
    payload = {
        "schema": WORKLOAD_REVOCATIONS_SCHEMA,
        "generated_at": _stamp(),
        "entries": sorted(
            normalized,
            key=lambda item: (item["tenant_id"], item["workload_id"], item["subject"]),
        ),
    }
    try:
        envelope = sign_payload(
            payload,
            payload_type=WORKLOAD_REVOCATIONS_PAYLOAD_TYPE,
            private_key_path=private_key_path,
            keyid=keyid,
            identity=identity,
            issuer=issuer,
        )
    except EnterpriseReceiptError as exc:
        raise EnterpriseEnforcementError(exc.code, exc.message) from exc
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(canonical_json(envelope) + b"\n")
    return envelope


def _request(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", "request must be an object"
        )
    required = {
        "tenant_id",
        "workload_id",
        "subject",
        "audience",
        "action_id",
        "action_class",
        "scope_paths",
        "oracle_contract_sha256",
    }
    missing = sorted(required - set(value))
    if missing:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", f"missing request fields: {missing}"
        )
    action = _text(value["action_class"], "action_class", limit=80).lower()
    if action not in ACTION_CLASSES:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_INPUT", "action_class is unknown"
        )
    result: dict[str, Any] = {
        "tenant_id": _text(value["tenant_id"], "tenant_id"),
        "workload_id": _text(value["workload_id"], "workload_id"),
        "subject": _text(value["subject"], "subject"),
        "audience": _text(value["audience"], "audience", limit=320),
        "action_id": _text(value["action_id"], "action_id"),
        "action_class": action,
        "scope_paths": _paths(value["scope_paths"], "scope_paths"),
        "oracle_contract_sha256": _digest(
            value["oracle_contract_sha256"], "oracle_contract_sha256"
        ),
    }
    binding = value.get("semantic_authority")
    if binding is not None:
        if not isinstance(binding, dict):
            raise EnterpriseEnforcementError(
                "E_ENFORCEMENT_INPUT", "semantic_authority must be an object"
            )
        result["semantic_authority"] = binding
    return result


def _assert_identity_binding(identity: dict[str, Any], request: dict[str, Any]) -> None:
    for field in ("tenant_id", "workload_id", "subject", "audience"):
        if identity[field] != request[field]:
            raise EnterpriseEnforcementError(
                "E_WORKLOAD_BINDING",
                f"request {field} does not match signed workload identity",
            )


def _assert_policy_admission(
    identity: dict[str, Any], policy: dict[str, Any], request: dict[str, Any]
) -> None:
    if (
        policy["tenant_id"] != request["tenant_id"]
        or policy["audience"] != request["audience"]
    ):
        raise EnterpriseEnforcementError(
            "E_POLICY_BINDING", "signed policy does not match tenant or audience"
        )
    if request["action_class"] not in identity["allowed_action_classes"]:
        raise EnterpriseEnforcementError(
            "E_ACTION_UNGRANTED", "workload identity does not grant this action class"
        )
    if request["action_class"] not in policy["allowed_action_classes"]:
        raise EnterpriseEnforcementError(
            "E_POLICY_DENY", "policy does not permit this action class"
        )
    if not _within_scope(request["scope_paths"], policy["allowed_scope_paths"]):
        raise EnterpriseEnforcementError(
            "E_SCOPE_ESCAPE", "requested paths exceed the signed policy"
        )


def _semantic_status(
    root: Path,
    identity: dict[str, Any],
    policy: dict[str, Any],
    request: dict[str, Any],
) -> str:
    if not policy["require_semantic_lease"]:
        return "NOT_REQUIRED"
    binding = request.get("semantic_authority")
    if binding is None:
        raise EnterpriseEnforcementError(
            "E_SEMANTIC_LEASE_REQUIRED",
            "policy requires an active semantic authority lease",
        )
    try:
        bound = verify_semantic_binding(
            root, binding, identity["agent"], request["scope_paths"]
        )
    except Exception as exc:
        raise EnterpriseEnforcementError(
            "E_SEMANTIC_AUTHORIZATION", "semantic authority binding was rejected"
        ) from exc
    if bound.get("action") != request["action_class"]:
        raise EnterpriseEnforcementError(
            "E_SEMANTIC_AUTHORIZATION",
            "semantic action does not match requested action class",
        )
    return "VERIFIED"


def authorize_enterprise_action(
    root: Path,
    request: object,
    *,
    workload_identity_path: Path,
    policy_path: Path,
    trust_root_path: Path,
    revocations_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a fail-closed, non-executing admission decision for one action."""
    parsed = _request(request)
    checked_identity = verify_workload_identity(
        workload_identity_path,
        trust_root_path=trust_root_path,
        revocations_path=revocations_path,
        now=now,
    )
    checked_policy = verify_enforcement_policy(
        policy_path, trust_root_path=trust_root_path
    )
    identity = checked_identity["identity"]
    policy = checked_policy["policy"]
    _assert_identity_binding(identity, parsed)
    _assert_policy_admission(identity, policy, parsed)
    semantic_status = _semantic_status(Path(root), identity, policy, parsed)
    return {
        "schema": DECISION_SCHEMA,
        "marker": "ENTERPRISE_PEP_REFERENCE_ADMITTED",
        "admitted": True,
        "recorded_at": _stamp(now or _now()),
        "request": parsed,
        "workload_identity_sha256": checked_identity["identity_sha256"],
        "workload_identity": {
            "issued_at": identity["issued_at"],
            "expires_at": identity["expires_at"],
        },
        "policy_sha256": checked_policy["policy_sha256"],
        "semantic_authority_status": semantic_status,
        "revocation_status": checked_identity["revocation_status"],
        "authority": dict(AUTHORITY),
        "claim_boundary": "Offline PEP reference admission only. It did not execute a tool, prove workload federation, enforce a sidecar/eBPF/container boundary, approve a release, or establish enterprise production readiness.",
    }


def record_enterprise_decision(
    root: Path, request: object, output: Path, **kwargs: Any
) -> dict[str, Any]:
    """Record one immutable non-executing decision and reject a replayed action ID."""
    workspace = Path(root).resolve()
    decision = authorize_enterprise_action(workspace, request, **kwargs)
    directory = workspace / ".factory" / "enterprise-enforcement" / "decisions"
    action_id = decision["request"]["action_id"]
    target = _decision_target(workspace, output, directory)
    verification_inputs = {
        "workload_identity_path": _verification_input_path(
            workspace, kwargs.get("workload_identity_path"), "workload_identity_path"
        ),
        "policy_path": _verification_input_path(
            workspace, kwargs.get("policy_path"), "policy_path"
        ),
        "trust_root_path": _verification_input_path(
            workspace, kwargs.get("trust_root_path"), "trust_root_path"
        ),
        "revocations_path": _verification_input_path(
            workspace,
            kwargs.get("revocations_path"),
            "revocations_path",
            required=False,
        ),
    }
    # Preserve pre-claim legacy receipts; new receipts use the atomic claim
    # below and never rely on a bounded directory scan for replay prevention.
    for prior_path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            prior = _load_json(prior_path)
        except EnterpriseEnforcementError:
            continue
        if (
            prior.get("schema") == DECISION_SCHEMA
            and prior.get("decision_sha256")
            and prior.get("request", {}).get("action_id") == action_id
        ):
            raise EnterpriseEnforcementError(
                "E_ENFORCEMENT_REPLAY",
                "action_id already has an immutable enterprise decision",
            )
    core = dict(decision)
    core["verification_inputs"] = verification_inputs
    core["decision_sha256"] = hashlib.sha256(canonical_json(core)).hexdigest()
    claim = _claim_action_id(directory, action_id)
    try:
        target = _write_new(workspace, target, core)
    except Exception:
        claim.unlink(missing_ok=True)
        raise
    return {**core, "path": target.relative_to(workspace).as_posix()}


def _decision_candidate(workspace: Path, path: Path) -> Path:
    candidate = (
        (workspace / path).resolve()
        if not Path(path).is_absolute()
        else Path(path).resolve()
    )
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise EnterpriseEnforcementError(
            "E_ENFORCEMENT_PATH", "decision must remain inside the workspace"
        ) from exc
    return candidate


def _verified_decision(candidate: Path) -> tuple[dict[str, Any], str]:
    value = _load_json(candidate)
    supplied = value.get("decision_sha256")
    unsigned = dict(value)
    unsigned.pop("decision_sha256", None)
    if (
        value.get("schema") != DECISION_SCHEMA
        or value.get("admitted") is not True
        or not isinstance(supplied, str)
    ):
        raise EnterpriseEnforcementError(
            "E_DECISION_INVALID",
            "decision is not an admitted enterprise reference receipt",
        )
    if hashlib.sha256(canonical_json(unsigned)).hexdigest() != supplied:
        raise EnterpriseEnforcementError(
            "E_DECISION_HASH_INVALID", "decision hash is invalid"
        )
    return value, supplied


def _decision_verification_inputs(value: dict[str, Any]) -> dict[str, Any]:
    inputs = value.get("verification_inputs")
    if not isinstance(inputs, dict) or set(inputs) != {
        "workload_identity_path",
        "policy_path",
        "trust_root_path",
        "revocations_path",
    }:
        raise EnterpriseEnforcementError(
            "E_DECISION_INPUT_BINDING",
            "decision must retain its signed verification inputs",
        )
    return inputs


def _reauthorize_decision(
    workspace: Path, value: dict[str, Any], inputs: dict[str, Any]
) -> dict[str, Any]:
    try:
        return authorize_enterprise_action(
            workspace,
            value.get("request"),
            workload_identity_path=workspace
            / Path(
                _text(
                    inputs["workload_identity_path"],
                    "verification_inputs.workload_identity_path",
                    limit=512,
                )
            ),
            policy_path=workspace
            / Path(
                _text(
                    inputs["policy_path"], "verification_inputs.policy_path", limit=512
                )
            ),
            trust_root_path=workspace
            / Path(
                _text(
                    inputs["trust_root_path"],
                    "verification_inputs.trust_root_path",
                    limit=512,
                )
            ),
            revocations_path=workspace
            / Path(
                _text(
                    inputs["revocations_path"],
                    "verification_inputs.revocations_path",
                    limit=512,
                )
            )
            if inputs["revocations_path"] is not None
            else None,
        )
    except EnterpriseEnforcementError:
        raise


def _verify_reauthorization(
    value: dict[str, Any], reauthorized: dict[str, Any]
) -> None:
    for field in (
        "workload_identity_sha256",
        "policy_sha256",
        "semantic_authority_status",
        "revocation_status",
    ):
        if value.get(field) != reauthorized.get(field):
            raise EnterpriseEnforcementError(
                "E_DECISION_REAUTHORIZATION_MISMATCH",
                f"{field} no longer matches the signed input reauthorization",
            )


def verify_enterprise_decision(root: Path, path: Path) -> dict[str, Any]:
    """Verify one immutable local decision receipt before a separate runner consumes it."""
    workspace = Path(root).resolve()
    candidate = _decision_candidate(workspace, path)
    value, supplied = _verified_decision(candidate)
    inputs = _decision_verification_inputs(value)
    reauthorized = _reauthorize_decision(workspace, value, inputs)
    _verify_reauthorization(value, reauthorized)
    return {
        "decision": value,
        "decision_sha256": supplied,
        "path": candidate.relative_to(workspace).as_posix(),
    }


def enterprise_enforcement_projection(root: Path) -> dict[str, Any]:
    """Read bounded local decision evidence for Graph Ops/MCP; never admits work."""
    workspace = Path(root).resolve()
    directory = workspace / ".factory" / "enterprise-enforcement" / "decisions"
    result: dict[str, Any] = {
        "schema": PROJECTION_SCHEMA,
        "marker": "ENTERPRISE_ENFORCEMENT_READ_ONLY",
        "decision_count": 0,
        "admitted_count": 0,
        "invalid_count": 0,
        "decisions": [],
        "authority": dict(AUTHORITY),
        "claim_boundary": "Read-only local projection of PEP reference decisions. It does not authenticate a cloud workload, execute a tool, enforce a network boundary, or grant authority.",
    }
    for path in sorted(directory.glob("*.json"))[:500] if directory.is_dir() else []:
        try:
            checked = verify_enterprise_decision(workspace, path)
            value, supplied = checked["decision"], checked["decision_sha256"]
            result["decision_count"] += 1
            if value.get("admitted") is True:
                result["admitted_count"] += 1
            result["decisions"].append(
                {
                    "path": path.relative_to(workspace).as_posix(),
                    "decision_sha256": supplied,
                    "admitted": value.get("admitted") is True,
                    "action_id": value.get("request", {}).get("action_id"),
                    "action_class": value.get("request", {}).get("action_class"),
                    "semantic_authority_status": value.get("semantic_authority_status"),
                    "revocation_status": value.get("revocation_status"),
                }
            )
        except EnterpriseEnforcementError:
            result["invalid_count"] += 1
    from .enterprise_runner_admission import runner_admission_projection

    result["runner_admission"] = runner_admission_projection(workspace)
    return result


"""factoryline.commercial_policy - approved commercial policy, parsed and applied.

This module records the commercial model approved by the project owner on
2026-11-21 and turns it into deterministic admission decisions:

- Free: 5 complete proof workflows per person per calendar month (UTC).
- Paid: 100 workflows per named human seat per month at USD 12.95 per seat,
  starting 2027-01-01. Everything before that date is PRELAUNCH_FREE.
- Each workflow includes 2 repair reruns for the same change within 7 days.
- One seat covers that person's agents and devices; the seat subject is the
  human owner supplied by the caller, never an AI agent's declared identity.
- Reading and exporting results is free. Rejected starts and internal tool
  errors never consume allowance. There are no overage charges: a person over
  allowance gets UPGRADE_REQUIRED, never a bill.

The bundled DEFAULT_POLICY has activation=False, so even an explicitly enabled
commercial gate returns PRELAUNCH_FREE for every run. Nothing here restricts,
bills, phones home, or changes a proof result.

This module decides admission only. It never interrupts an admitted workflow,
never changes PASS/BLOCKED/INCOMPLETE, and is unrelated to agent_license.py,
which records agent-autonomy evidence, not paid access.
"""


COMMERCIAL_POLICY_SCHEMA = "factory.commercial.policy.v1"

PRELAUNCH_FREE = "PRELAUNCH_FREE"
ALLOW = "ALLOW"
ALLOW_INCLUDED_RERUN = "ALLOW_INCLUDED_RERUN"
UPGRADE_REQUIRED = "UPGRADE_REQUIRED"
ENTITLEMENT_INVALID = "ENTITLEMENT_INVALID"
DISABLED = "DISABLED"

DECISIONS = frozenset(
    {
        PRELAUNCH_FREE,
        ALLOW,
        ALLOW_INCLUDED_RERUN,
        UPGRADE_REQUIRED,
        ENTITLEMENT_INVALID,
        DISABLED,
    }
)


class CommercialPolicyError(PrefixedCodedError):
    pass


def _commercial_require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CommercialPolicyError(code, message)


def _parse_date(value: Any, field: str) -> date:
    _commercial_require(
        isinstance(value, str) and bool(value.strip()),
        "E_POLICY_FIELD",
        f"{field} is required",
    )
    try:
        return date.fromisoformat(value.strip())
    except ValueError as exc:
        raise CommercialPolicyError(
            "E_POLICY_FIELD", f"{field} must be an ISO calendar date"
        ) from exc


def _require_int(value: Any, field: str, minimum: int) -> int:
    _commercial_require(
        isinstance(value, int) and not isinstance(value, bool) and value >= minimum,
        "E_POLICY_FIELD",
        f"{field} must be an integer >= {minimum}",
    )
    return value


@dataclass(frozen=True)
class Policy:
    """One immutable, versioned commercial policy revision."""

    revision: str
    activation: bool
    prelaunch_free_until: date
    currency: str
    seat_monthly_price: float
    price_effective_from: date
    free_monthly_workflows: int
    paid_monthly_workflows: int
    repair_reruns_per_workflow: int
    repair_rerun_window_days: int

    def monthly_limit(self, paid: bool) -> int:
        """Return the configured monthly limit for the selected tier."""
        return self.paid_monthly_workflows if paid else self.free_monthly_workflows


def parse_policy(value: Any) -> Policy:
    """Validate one policy document or raise CommercialPolicyError fail closed."""
    _commercial_require(
        isinstance(value, dict), "E_POLICY_SCHEMA", "policy must be an object"
    )
    _commercial_require(
        value.get("schema") == COMMERCIAL_POLICY_SCHEMA,
        "E_POLICY_SCHEMA",
        f"policy schema must be {COMMERCIAL_POLICY_SCHEMA}",
    )
    _commercial_require(
        isinstance(value.get("revision"), str) and value["revision"].strip(),
        "E_POLICY_FIELD",
        "revision is required",
    )
    _commercial_require(
        isinstance(value.get("activation"), bool),
        "E_POLICY_FIELD",
        "activation must be an explicit boolean",
    )
    pricing = value.get("pricing")
    _commercial_require(
        isinstance(pricing, dict), "E_POLICY_FIELD", "pricing block is required"
    )
    _commercial_require(
        isinstance(pricing.get("currency"), str) and len(pricing["currency"]) == 3,
        "E_POLICY_FIELD",
        "pricing.currency must be a 3-letter code",
    )
    price = pricing.get("seat_monthly")
    _commercial_require(
        isinstance(price, (int, float)) and not isinstance(price, bool) and price >= 0,
        "E_POLICY_FIELD",
        "pricing.seat_monthly must be a non-negative number",
    )
    allowances = value.get("allowances")
    _commercial_require(
        isinstance(allowances, dict), "E_POLICY_FIELD", "allowances block is required"
    )
    return Policy(
        revision=value["revision"].strip(),
        activation=value["activation"],
        prelaunch_free_until=_parse_date(
            value.get("prelaunch_free_until"), "prelaunch_free_until"
        ),
        currency=pricing["currency"].upper(),
        seat_monthly_price=float(price),
        price_effective_from=_parse_date(
            pricing.get("effective_from"), "pricing.effective_from"
        ),
        free_monthly_workflows=_require_int(
            allowances.get("free_monthly_workflows"), "free_monthly_workflows", 0
        ),
        paid_monthly_workflows=_require_int(
            allowances.get("paid_monthly_workflows"), "paid_monthly_workflows", 1
        ),
        repair_reruns_per_workflow=_require_int(
            allowances.get("repair_reruns_per_workflow"),
            "repair_reruns_per_workflow",
            0,
        ),
        repair_rerun_window_days=_require_int(
            allowances.get("repair_rerun_window_days"), "repair_rerun_window_days", 1
        ),
    )


def load_policy(path: str | Path) -> Policy:
    """Read and validate a local commercial policy document."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise CommercialPolicyError("E_POLICY_IO", str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise CommercialPolicyError("E_POLICY_SCHEMA", f"invalid JSON: {exc}") from exc
    return parse_policy(raw)


DEFAULT_POLICY: dict[str, Any] = {
    "schema": COMMERCIAL_POLICY_SCHEMA,
    "revision": "2026-11-21-approved-start",
    "activation": False,
    "prelaunch_free_until": "2027-01-01",
    "pricing": {
        "currency": "USD",
        "seat_monthly": 12.95,
        "effective_from": "2027-01-01",
        "promotion_end": None,
    },
    "allowances": {
        "free_monthly_workflows": 5,
        "paid_monthly_workflows": 100,
        "repair_reruns_per_workflow": 2,
        "repair_rerun_window_days": 7,
    },
    "seat": {"subject": "named_human", "includes": ["agents", "devices"]},
    "never_charged": [
        "read_results",
        "export_receipts",
        "rejected_starts",
        "internal_tool_errors",
    ],
    "overage": "none_hard_stop",
}


def default_policy() -> Policy:
    """Parse the bundled inactive commercial policy without side effects."""
    return parse_policy(DEFAULT_POLICY)


def period_for(now: datetime) -> str:
    """Return the UTC calendar-month period key, e.g. '2026-11'."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m")


@dataclass(frozen=True)
class RerunView:
    """Pre-evaluated repair-rerun eligibility for one candidate admission."""

    requested: bool
    eligible: bool
    reason: str = ""


@dataclass(frozen=True)
class Decision:
    outcome: str
    period: str
    limit: int | None
    used: int
    remaining: int | None
    reason: str
    counts_against_allowance: bool

    def as_dict(self) -> dict[str, Any]:
        """Return the stable JSON-serializable public representation."""
        return {
            "outcome": self.outcome,
            "period": self.period,
            "limit": self.limit,
            "used": self.used,
            "remaining": self.remaining,
            "reason": self.reason,
            "counts_against_allowance": self.counts_against_allowance,
        }


def _commercial_rerun_reason_prefix(rerun: RerunView | None) -> str:
    """Explain why a requested repair is admitted as a new workflow."""
    if rerun is not None and rerun.requested and not rerun.eligible:
        return f"rerun not eligible ({rerun.reason}); admitted as a new workflow. "
    return ""


def decide(
    policy: Policy,
    *,
    now: datetime,
    used: int,
    entitlement_valid: bool,
    entitlement_invalid_reason: str | None = None,
    rerun: RerunView | None = None,
) -> Decision:
    """Pure admission decision. Quota state is supplied; nothing is mutated here.

    used is the count of allowance-consuming workflows already admitted for the
    subject in the current period. An invalid presented entitlement rejects the
    start without consuming allowance; an absent entitlement simply means the
    free tier applies.
    """
    period = period_for(now)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if not policy.activation or now.date() < policy.prelaunch_free_until:
        return Decision(
            PRELAUNCH_FREE,
            period,
            None,
            used,
            None,
            "commercial policy is not active before 2027-01-01",
            False,
        )
    if entitlement_invalid_reason is not None:
        return Decision(
            ENTITLEMENT_INVALID,
            period,
            None,
            used,
            None,
            entitlement_invalid_reason,
            False,
        )
    if rerun is not None and rerun.requested and rerun.eligible:
        return Decision(
            ALLOW_INCLUDED_RERUN,
            period,
            None,
            used,
            None,
            "included repair rerun for the same change",
            False,
        )
    limit = policy.monthly_limit(entitlement_valid)
    reason_prefix = _commercial_rerun_reason_prefix(rerun)
    if used < limit:
        return Decision(
            ALLOW,
            period,
            limit,
            used,
            limit - used,
            reason_prefix + "within monthly allowance",
            True,
        )
    return Decision(
        UPGRADE_REQUIRED,
        period,
        limit,
        used,
        0,
        reason_prefix
        + f"monthly allowance of {limit} workflows used; no overage charges apply",
        False,
    )


"""factoryline.enterprise_enforcement - admission orchestration for the commercial model.

The gate combines the versioned policy, the local usage ledger and any imported
signed entitlements into one admission call used by execution entry points.

Modes (FACTORY_COMMERCIAL_MODE):
- off (default): fully inert. No files are created, no decision is recorded,
  admission always returns DISABLED. This is the shipped default.
- shadow: the decision and hypothetical counts are computed and returned to
  the caller for inspection, but nothing is persisted and nothing is refused.
- enforce: soft local enforcement. Over-allowance starts are refused with
  E_COMMERCIAL_UPGRADE_REQUIRED before dispatch; invalid presented entitlements
  with E_COMMERCIAL_ENTITLEMENT_INVALID. "Soft" is literal: the ledger is a
  local file a determined user can reset, and enforcement only covers entry
  points actually wired to this gate.

Invariants enforced here and by the wiring in runtime_audit:
- Quota status never changes a proof finding, never skips a check or negative
  control, and never interrupts an admitted run.
- Admission happens after safety preflight and before dispatch; settlement
  happens once, at the terminal result.
- Internal tool errors and rejected starts release the reservation; only a
  workflow that actually ran to a terminal result consumes allowance.
- Payment status never replaces signed-plan verification or human approval.
"""


MODE_ENV = "FACTORY_COMMERCIAL_MODE"
POLICY_ENV = "FACTORY_COMMERCIAL_POLICY"
MODES = frozenset({"off", "shadow", "enforce"})


class CommercialAdmissionError(RuntimeError):
    def __init__(self, code: str, message: str, decision: Decision | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.decision = decision


@dataclass
class Admission:
    decision: Decision
    reservation: Reservation | None = None
    mode: str = "off"
    shadow: bool = False

    @property
    def admitted(self) -> bool:
        """Report whether this admission permits workflow dispatch."""
        return (
            self.decision.outcome
            in {
                DISABLED,
                PRELAUNCH_FREE,
                ALLOW,
                ALLOW_INCLUDED_RERUN,
            }
            or self.shadow
        )


def commercial_mode(env: dict[str, str] | None = None) -> str:
    """Read the local opt-in mode, defaulting safely to off."""
    selected_env = os.environ if env is None else env
    mode = (selected_env.get(MODE_ENV) or "off").strip().lower()
    return mode if mode in MODES else "off"


def load_configured_policy(env: dict[str, str] | None = None) -> Policy:
    """Load an explicit policy override or the inactive bundled policy."""
    selected_env = os.environ if env is None else env
    override = selected_env.get(POLICY_ENV)
    if override:
        return load_policy(override)
    return default_policy()


def _commercial_gate_utc(now: datetime) -> datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


class CommercialGate:
    """One admission boundary per execution entry point."""

    def __init__(
        self,
        *,
        policy: Policy | None = None,
        ledger: UsageLedger | None = None,
        home: str | Path | None = None,
        mode: str | None = None,
    ):
        self.policy = policy if policy is not None else load_configured_policy()
        self.mode = commercial_mode() if mode is None else mode
        self.ledger = ledger if ledger is not None else UsageLedger(home)
        self.home = Path(home) if home is not None else default_home()

    def _rerun_view(
        self,
        *,
        subject: str,
        rerun_of: str | None,
        binding: dict[str, Any],
        now: datetime,
        state,
    ) -> RerunView:
        if rerun_of is None:
            return RerunView(requested=False, eligible=False)
        original = state.find_original(subject, rerun_of)
        if original is None:
            return RerunView(
                requested=True, eligible=False, reason="original workflow not found"
            )
        if original.closed_at is None:
            return RerunView(
                requested=True,
                eligible=False,
                reason="original workflow has no terminal result",
            )
        window = timedelta(days=self.policy.repair_rerun_window_days)
        closed = _commercial_gate_utc(datetime.fromisoformat(original.closed_at))
        if _commercial_gate_utc(now) > closed + window:
            return RerunView(
                requested=True, eligible=False, reason="repair window expired"
            )
        for field in RERUN_BINDING_FIELDS:
            if binding.get(field) != original.binding.get(field):
                return RerunView(
                    requested=True,
                    eligible=False,
                    reason=f"{field} differs from the original change",
                )
        used = state.reruns_used(subject, rerun_of)
        if used >= self.policy.repair_reruns_per_workflow:
            return RerunView(
                requested=True,
                eligible=False,
                reason="included repair reruns already used",
            )
        return RerunView(requested=True, eligible=True)

    def _entitlement_status(
        self,
        *,
        subject: str,
        version: str,
        presented_envelope: dict[str, Any] | None,
        presented_trust_root: dict[str, Any] | None,
        state,
        now: datetime,
    ) -> tuple[bool, str | None]:
        """Resolve offline entitlement coverage without changing admission state."""
        entitlement_valid = False
        entitlement_invalid_reason: str | None = None
        if presented_envelope is not None:
            try:
                if presented_trust_root is None:
                    raise CommercialEntitlementError(
                        "E_TRUST_ROOT_REQUIRED",
                        "a presented entitlement needs its commercial trust root",
                    )
                presented = verify_entitlement_envelope(
                    presented_envelope, trust_root=presented_trust_root
                )
                entitlement_valid = presented.covers(
                    subject=subject,
                    product=PRODUCT,
                    version=version,
                    now=state.effective_now(now),
                )
                if not entitlement_valid:
                    entitlement_invalid_reason = "entitlement does not cover this subject, product, version or date"
            except CommercialEntitlementError as exc:
                entitlement_invalid_reason = f"{exc.code}: {exc.message}"
        else:
            covering = covering_entitlement(
                load_entitlements(self.home),
                subject=subject,
                product=PRODUCT,
                version=version,
                now=state.effective_now(now),
            )
            entitlement_valid = covering is not None
        return entitlement_valid, entitlement_invalid_reason

    def admit(
        self,
        *,
        subject: str,
        workflow_id: str,
        idempotency_key: str,
        binding: dict[str, Any] | None = None,
        rerun_of: str | None = None,
        version: str = "0.0.0",
        presented_envelope: dict[str, Any] | None = None,
        presented_trust_root: dict[str, Any] | None = None,
        now: datetime,
    ) -> Admission:
        """Decide and (in enforce mode) atomically reserve one workflow start."""
        if not subject:
            raise CommercialAdmissionError(
                "E_COMMERCIAL_SUBJECT", "a human seat subject is required"
            )
        if self.mode == "off":
            return Admission(
                Decision(
                    DISABLED,
                    period_for(now),
                    None,
                    0,
                    None,
                    "commercial gate is disabled",
                    False,
                ),
                mode="off",
            )
        binding = binding or {}
        now = _commercial_gate_utc(now)
        state = self.ledger.load(now)
        period = period_for(state.effective_now(now))
        used = state.used(subject, period)

        entitlement_valid, entitlement_invalid_reason = self._entitlement_status(
            subject=subject,
            version=version,
            presented_envelope=presented_envelope,
            presented_trust_root=presented_trust_root,
            state=state,
            now=now,
        )

        rerun = self._rerun_view(
            subject=subject,
            rerun_of=rerun_of,
            binding=binding,
            now=state.effective_now(now),
            state=state,
        )
        decision = decide(
            self.policy,
            now=state.effective_now(now),
            used=used,
            entitlement_valid=entitlement_valid,
            entitlement_invalid_reason=entitlement_invalid_reason,
            rerun=rerun,
        )

        if self.mode == "shadow":
            return Admission(decision, mode="shadow", shadow=True)

        # enforce
        if decision.outcome == ENTITLEMENT_INVALID:
            raise CommercialAdmissionError(
                "E_COMMERCIAL_ENTITLEMENT_INVALID", decision.reason, decision
            )
        if decision.outcome in {PRELAUNCH_FREE, DISABLED}:
            return Admission(decision, mode="enforce")
        if decision.outcome == ALLOW_INCLUDED_RERUN:
            reservation = self.ledger.try_reserve(
                subject=subject,
                period=period,
                workflow_id=workflow_id,
                idempotency_key=idempotency_key,
                binding=binding,
                rerun_of=rerun_of,
                limit=None,
                now=now,
            )
            return Admission(decision, reservation=reservation, mode="enforce")
        # ALLOW or UPGRADE_REQUIRED: the ledger re-checks the limit atomically.
        limit = self.policy.monthly_limit(entitlement_valid)
        reservation = self.ledger.try_reserve(
            subject=subject,
            period=period,
            workflow_id=workflow_id,
            idempotency_key=idempotency_key,
            binding=binding,
            rerun_of=None,
            limit=limit,
            now=now,
        )
        if reservation is None:
            refused = Decision(
                UPGRADE_REQUIRED,
                period,
                limit,
                limit,
                0,
                f"monthly allowance of {limit} workflows used; no overage charges apply",
                False,
            )
            raise CommercialAdmissionError(
                "E_COMMERCIAL_UPGRADE_REQUIRED", refused.reason, refused
            )
        if decision.outcome != ALLOW:
            # The atomic ledger recheck won the race against a stale pre-check.
            decision = Decision(
                ALLOW,
                period,
                limit,
                decision.used,
                None,
                "within monthly allowance",
                True,
            )
        return Admission(decision, reservation=reservation, mode="enforce")

    def settle(self, admission: Admission, *, outcome: str, now: datetime) -> None:
        """Settle one admitted workflow at its terminal result.

        completed counts against the allowance; tool_error and rejected release
        the reservation. Never call this mid-run.
        """
        if admission.reservation is None:
            return
        try:
            self.ledger.settle(
                admission.reservation.reservation_id, outcome=outcome, now=now
            )
        except CommercialUsageError:
            # Settlement must never crash the workflow it meters.
            pass
