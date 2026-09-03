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
from .enterprise_receipts import EnterpriseReceiptError, canonical_json, sign_payload, verify_signed_document
from .semantic_authority import verify_semantic_binding


WORKLOAD_IDENTITY_SCHEMA = "factory.workload-identity.v1"
WORKLOAD_IDENTITY_PAYLOAD_TYPE = "application/vnd.factory.workload-identity.v1+json"
ENFORCEMENT_POLICY_SCHEMA = "factory.enforcement-policy.v1"
ENFORCEMENT_POLICY_PAYLOAD_TYPE = "application/vnd.factory.enforcement-policy.v1+json"
WORKLOAD_REVOCATIONS_SCHEMA = "factory.workload-revocations.v1"
WORKLOAD_REVOCATIONS_PAYLOAD_TYPE = "application/vnd.factory.workload-revocations.v1+json"
DECISION_SCHEMA = "factory.enterprise-enforcement-decision.v1"
PROJECTION_SCHEMA = "factory.enterprise-enforcement-projection.v1"
MAX_IDENTITY_LIFETIME = timedelta(hours=24)
ACTION_CLASSES = frozenset({"read", "test", "repair", "merge", "deploy", "publish", "credential", "message", "purchase"})
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


class EnterpriseEnforcementError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise EnterpriseEnforcementError("E_WORKLOAD_IDENTITY_INVALID", f"{field} must be an RFC3339 timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnterpriseEnforcementError("E_WORKLOAD_IDENTITY_INVALID", f"{field} is invalid") from exc
    if result.tzinfo is None:
        raise EnterpriseEnforcementError("E_WORKLOAD_IDENTITY_INVALID", f"{field} must include an offset")
    return result.astimezone(timezone.utc)


def _text(value: object, field: str, *, limit: int = 160) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", f"{field} must be a non-empty string up to {limit} characters")
    return value.strip()


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(ch not in "0123456789abcdef" for ch in result):
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", f"{field} must be a SHA-256 hex digest")
    return result


def _paths(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", f"{field} must contain 1 through 64 relative paths")
    result: list[str] = []
    for raw in value:
        item = _text(raw, field, limit=512).replace("\\", "/")
        path = Path(item)
        if path.is_absolute() or ".." in path.parts:
            raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", f"{field} cannot escape a workspace")
        result.append(item.rstrip("/") or ".")
    return sorted(set(result))


def _within_scope(requested: list[str], allowed: list[str]) -> bool:
    for candidate in requested:
        if not any(base == "." or candidate == base or candidate.startswith(base + "/") for base in allowed):
            return False
    return True


def _actions(value: object, field: str, *, require_known: bool = True) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", f"{field} must contain 1 through 32 actions")
    result = sorted({_text(item, field, limit=80).lower() for item in value})
    if require_known and any(item not in ACTION_CLASSES for item in result):
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", f"{field} includes an unknown action class")
    return result


def _write_new(root: Path, output: Path, payload: dict[str, Any]) -> Path:
    root = Path(root).resolve()
    target = (root / output).resolve() if not Path(output).is_absolute() else Path(output).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_PATH", "output must remain inside the workspace") from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_IMMUTABLE", "refusing to overwrite an enforcement decision") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json(payload) + b"\n")
    return target


def _decision_target(workspace: Path, output: Path, directory: Path) -> Path:
    target = (workspace / output).resolve() if not Path(output).is_absolute() else Path(output).resolve()
    try:
        target.relative_to(directory.resolve())
    except ValueError as exc:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_PATH", "decision output must stay under .factory/enterprise-enforcement/decisions") from exc
    return target


def _claim_action_id(directory: Path, action_id: str) -> Path:
    """Atomically claim an action id before its immutable decision is written."""
    claim_dir = directory / ".claims"
    claim_dir.mkdir(parents=True, exist_ok=True)
    claim = claim_dir / f"{hashlib.sha256(action_id.encode('utf-8')).hexdigest()}.claim"
    try:
        descriptor = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_REPLAY", "action_id already has an immutable enterprise decision") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json({"action_id": action_id}) + b"\n")
    return claim


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", str(exc)) from exc
    if not isinstance(value, dict):
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", "JSON must be an object")
    return value


def validate_workload_identity(payload: object) -> dict[str, Any]:
    """Normalize one bounded workload identity before it is signed or trusted."""
    if not isinstance(payload, dict) or payload.get("schema") != WORKLOAD_IDENTITY_SCHEMA:
        raise EnterpriseEnforcementError("E_WORKLOAD_IDENTITY_INVALID", f"schema must be {WORKLOAD_IDENTITY_SCHEMA}")
    required = {"schema", "tenant_id", "workload_id", "subject", "audience", "issued_at", "expires_at", "agent", "allowed_action_classes"}
    missing = sorted(required - set(payload))
    if missing:
        raise EnterpriseEnforcementError("E_WORKLOAD_IDENTITY_INVALID", f"missing fields: {missing}")
    issued_at = _time(payload["issued_at"], "issued_at")
    expires_at = _time(payload["expires_at"], "expires_at")
    if expires_at <= issued_at or expires_at - issued_at > MAX_IDENTITY_LIFETIME:
        raise EnterpriseEnforcementError("E_WORKLOAD_IDENTITY_INVALID", "identity must expire after issuance and within 24 hours")
    return {
        "schema": WORKLOAD_IDENTITY_SCHEMA,
        "tenant_id": _text(payload["tenant_id"], "tenant_id"),
        "workload_id": _text(payload["workload_id"], "workload_id"),
        "subject": _text(payload["subject"], "subject"),
        "audience": _text(payload["audience"], "audience", limit=320),
        "issued_at": _stamp(issued_at),
        "expires_at": _stamp(expires_at),
        "agent": normalize_agent_identity(payload["agent"], "agent"),
        "allowed_action_classes": _actions(payload["allowed_action_classes"], "allowed_action_classes"),
    }


def validate_enforcement_policy(payload: object) -> dict[str, Any]:
    """Normalize one tenant policy without granting an action or contacting a service."""
    if not isinstance(payload, dict) or payload.get("schema") != ENFORCEMENT_POLICY_SCHEMA:
        raise EnterpriseEnforcementError("E_POLICY_INVALID", f"schema must be {ENFORCEMENT_POLICY_SCHEMA}")
    required = {"schema", "policy_id", "version", "tenant_id", "audience", "allowed_action_classes", "allowed_scope_paths", "require_semantic_lease"}
    missing = sorted(required - set(payload))
    if missing:
        raise EnterpriseEnforcementError("E_POLICY_INVALID", f"missing fields: {missing}")
    if not isinstance(payload["require_semantic_lease"], bool):
        raise EnterpriseEnforcementError("E_POLICY_INVALID", "require_semantic_lease must be boolean")
    return {
        "schema": ENFORCEMENT_POLICY_SCHEMA,
        "policy_id": _text(payload["policy_id"], "policy_id"),
        "version": _text(payload["version"], "version", limit=64),
        "tenant_id": _text(payload["tenant_id"], "tenant_id"),
        "audience": _text(payload["audience"], "audience", limit=320),
        "allowed_action_classes": _actions(payload["allowed_action_classes"], "allowed_action_classes"),
        "allowed_scope_paths": _paths(payload["allowed_scope_paths"], "allowed_scope_paths"),
        "require_semantic_lease": payload["require_semantic_lease"],
    }


def _signed_payload(path: Path, *, payload_type: str, schema: str, trust_root_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        verified = verify_signed_document(path, payload_type=payload_type, schema=schema, trust_root_path=trust_root_path)
    except EnterpriseReceiptError as exc:
        raise EnterpriseEnforcementError(exc.code, exc.message) from exc
    return verified["payload"], verified


def verify_workload_identity(path: Path, *, trust_root_path: Path, revocations_path: Path | None = None, now: datetime | None = None) -> dict[str, Any]:
    """Verify signed local identity, bounded lifetime, and optional signed revocations."""
    payload, verified = _signed_payload(Path(path), payload_type=WORKLOAD_IDENTITY_PAYLOAD_TYPE, schema=WORKLOAD_IDENTITY_SCHEMA, trust_root_path=Path(trust_root_path))
    identity = validate_workload_identity(payload)
    current = now or _now()
    if _time(identity["issued_at"], "issued_at") > current:
        raise EnterpriseEnforcementError("E_WORKLOAD_NOT_ACTIVE", "workload identity is not active yet")
    if _time(identity["expires_at"], "expires_at") <= current:
        raise EnterpriseEnforcementError("E_WORKLOAD_EXPIRED", "workload identity has expired")
    revocation_status = "NOT_CHECKED"
    if revocations_path is not None:
        revocations, _ = _signed_payload(Path(revocations_path), payload_type=WORKLOAD_REVOCATIONS_PAYLOAD_TYPE, schema=WORKLOAD_REVOCATIONS_SCHEMA, trust_root_path=Path(trust_root_path))
        entries = revocations.get("entries")
        if not isinstance(entries, list):
            raise EnterpriseEnforcementError("E_REVOCATIONS_INVALID", "revocation entries must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise EnterpriseEnforcementError("E_REVOCATIONS_INVALID", "revocation entry must be an object")
            if all(entry.get(key) == identity[key] for key in ("tenant_id", "workload_id", "subject")):
                revoked_at = _time(entry.get("revoked_at"), "revoked_at")
                if revoked_at <= current:
                    raise EnterpriseEnforcementError("E_WORKLOAD_REVOKED", "workload identity is revoked")
        revocation_status = "CHECKED"
    return {"identity": identity, "identity_sha256": verified["payload_sha256"], "signature": verified["signature"], "revocation_status": revocation_status, "verification": verified["verification"]}


def verify_enforcement_policy(path: Path, *, trust_root_path: Path) -> dict[str, Any]:
    """Verify one signed tenant policy against the explicit offline trust root."""
    payload, verified = _signed_payload(Path(path), payload_type=ENFORCEMENT_POLICY_PAYLOAD_TYPE, schema=ENFORCEMENT_POLICY_SCHEMA, trust_root_path=Path(trust_root_path))
    return {"policy": validate_enforcement_policy(payload), "policy_sha256": verified["payload_sha256"], "signature": verified["signature"], "verification": verified["verification"]}


def sign_workload_identity(payload: object, *, private_key_path: Path, keyid: str, identity: str, issuer: str, out: Path) -> dict[str, Any]:
    """Create a development or integration DSSE workload-identity envelope locally."""
    value = validate_workload_identity(payload)
    try:
        envelope = sign_payload(value, payload_type=WORKLOAD_IDENTITY_PAYLOAD_TYPE, private_key_path=private_key_path, keyid=keyid, identity=identity, issuer=issuer)
    except EnterpriseReceiptError as exc:
        raise EnterpriseEnforcementError(exc.code, exc.message) from exc
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(canonical_json(envelope) + b"\n")
    return envelope


def sign_enforcement_policy(payload: object, *, private_key_path: Path, keyid: str, identity: str, issuer: str, out: Path) -> dict[str, Any]:
    """Create a reviewed DSSE tenant-policy envelope without granting runtime authority."""
    value = validate_enforcement_policy(payload)
    try:
        envelope = sign_payload(value, payload_type=ENFORCEMENT_POLICY_PAYLOAD_TYPE, private_key_path=private_key_path, keyid=keyid, identity=identity, issuer=issuer)
    except EnterpriseReceiptError as exc:
        raise EnterpriseEnforcementError(exc.code, exc.message) from exc
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(canonical_json(envelope) + b"\n")
    return envelope


def sign_workload_revocations(entries: object, *, private_key_path: Path, keyid: str, identity: str, issuer: str, out: Path) -> dict[str, Any]:
    """Create a signed local workload-revocation list for deterministic denial checks."""
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise EnterpriseEnforcementError("E_REVOCATIONS_INVALID", "entries must be a list of objects")
    normalized = []
    for item in entries:
        normalized.append({"tenant_id": _text(item.get("tenant_id"), "tenant_id"), "workload_id": _text(item.get("workload_id"), "workload_id"), "subject": _text(item.get("subject"), "subject"), "revoked_at": _stamp(_time(item.get("revoked_at"), "revoked_at")), "reason": _text(item.get("reason"), "reason", limit=320)})
    payload = {"schema": WORKLOAD_REVOCATIONS_SCHEMA, "generated_at": _stamp(), "entries": sorted(normalized, key=lambda item: (item["tenant_id"], item["workload_id"], item["subject"]))}
    try:
        envelope = sign_payload(payload, payload_type=WORKLOAD_REVOCATIONS_PAYLOAD_TYPE, private_key_path=private_key_path, keyid=keyid, identity=identity, issuer=issuer)
    except EnterpriseReceiptError as exc:
        raise EnterpriseEnforcementError(exc.code, exc.message) from exc
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(canonical_json(envelope) + b"\n")
    return envelope


def _request(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", "request must be an object")
    required = {"tenant_id", "workload_id", "subject", "audience", "action_id", "action_class", "scope_paths", "oracle_contract_sha256"}
    missing = sorted(required - set(value))
    if missing:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", f"missing request fields: {missing}")
    action = _text(value["action_class"], "action_class", limit=80).lower()
    if action not in ACTION_CLASSES:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", "action_class is unknown")
    result = {"tenant_id": _text(value["tenant_id"], "tenant_id"), "workload_id": _text(value["workload_id"], "workload_id"), "subject": _text(value["subject"], "subject"), "audience": _text(value["audience"], "audience", limit=320), "action_id": _text(value["action_id"], "action_id"), "action_class": action, "scope_paths": _paths(value["scope_paths"], "scope_paths"), "oracle_contract_sha256": _digest(value["oracle_contract_sha256"], "oracle_contract_sha256")}
    binding = value.get("semantic_authority")
    if binding is not None:
        if not isinstance(binding, dict):
            raise EnterpriseEnforcementError("E_ENFORCEMENT_INPUT", "semantic_authority must be an object")
        result["semantic_authority"] = binding
    return result


def _assert_identity_binding(identity: dict[str, Any], request: dict[str, Any]) -> None:
    for field in ("tenant_id", "workload_id", "subject", "audience"):
        if identity[field] != request[field]:
            raise EnterpriseEnforcementError("E_WORKLOAD_BINDING", f"request {field} does not match signed workload identity")


def _assert_policy_admission(identity: dict[str, Any], policy: dict[str, Any], request: dict[str, Any]) -> None:
    if policy["tenant_id"] != request["tenant_id"] or policy["audience"] != request["audience"]:
        raise EnterpriseEnforcementError("E_POLICY_BINDING", "signed policy does not match tenant or audience")
    if request["action_class"] not in identity["allowed_action_classes"]:
        raise EnterpriseEnforcementError("E_ACTION_UNGRANTED", "workload identity does not grant this action class")
    if request["action_class"] not in policy["allowed_action_classes"]:
        raise EnterpriseEnforcementError("E_POLICY_DENY", "policy does not permit this action class")
    if not _within_scope(request["scope_paths"], policy["allowed_scope_paths"]):
        raise EnterpriseEnforcementError("E_SCOPE_ESCAPE", "requested paths exceed the signed policy")


def _semantic_status(root: Path, identity: dict[str, Any], policy: dict[str, Any], request: dict[str, Any]) -> str:
    if not policy["require_semantic_lease"]:
        return "NOT_REQUIRED"
    binding = request.get("semantic_authority")
    if binding is None:
        raise EnterpriseEnforcementError("E_SEMANTIC_LEASE_REQUIRED", "policy requires an active semantic authority lease")
    try:
        bound = verify_semantic_binding(root, binding, identity["agent"], request["scope_paths"])
    except Exception as exc:
        raise EnterpriseEnforcementError("E_SEMANTIC_AUTHORIZATION", "semantic authority binding was rejected") from exc
    if bound.get("action") != request["action_class"]:
        raise EnterpriseEnforcementError("E_SEMANTIC_AUTHORIZATION", "semantic action does not match requested action class")
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
    checked_identity = verify_workload_identity(workload_identity_path, trust_root_path=trust_root_path, revocations_path=revocations_path, now=now)
    checked_policy = verify_enforcement_policy(policy_path, trust_root_path=trust_root_path)
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


def record_enterprise_decision(root: Path, request: object, output: Path, **kwargs: Any) -> dict[str, Any]:
    """Record one immutable non-executing decision and reject a replayed action ID."""
    workspace = Path(root).resolve()
    decision = authorize_enterprise_action(workspace, request, **kwargs)
    directory = workspace / ".factory" / "enterprise-enforcement" / "decisions"
    action_id = decision["request"]["action_id"]
    target = _decision_target(workspace, output, directory)
    # Preserve pre-claim legacy receipts; new receipts use the atomic claim
    # below and never rely on a bounded directory scan for replay prevention.
    for prior_path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            prior = _load_json(prior_path)
        except EnterpriseEnforcementError:
            continue
        if prior.get("schema") == DECISION_SCHEMA and prior.get("decision_sha256") and prior.get("request", {}).get("action_id") == action_id:
            raise EnterpriseEnforcementError("E_ENFORCEMENT_REPLAY", "action_id already has an immutable enterprise decision")
    core = dict(decision)
    core["decision_sha256"] = hashlib.sha256(canonical_json(core)).hexdigest()
    claim = _claim_action_id(directory, action_id)
    try:
        target = _write_new(workspace, target, core)
    except Exception:
        claim.unlink(missing_ok=True)
        raise
    return {**core, "path": target.relative_to(workspace).as_posix()}


def verify_enterprise_decision(root: Path, path: Path) -> dict[str, Any]:
    """Verify one immutable local decision receipt before a separate runner consumes it."""
    workspace = Path(root).resolve()
    candidate = (workspace / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise EnterpriseEnforcementError("E_ENFORCEMENT_PATH", "decision must remain inside the workspace") from exc
    value = _load_json(candidate)
    supplied = value.get("decision_sha256")
    unsigned = dict(value)
    unsigned.pop("decision_sha256", None)
    if value.get("schema") != DECISION_SCHEMA or value.get("admitted") is not True or not isinstance(supplied, str):
        raise EnterpriseEnforcementError("E_DECISION_INVALID", "decision is not an admitted enterprise reference receipt")
    if hashlib.sha256(canonical_json(unsigned)).hexdigest() != supplied:
        raise EnterpriseEnforcementError("E_DECISION_HASH_INVALID", "decision hash is invalid")
    return {"decision": value, "decision_sha256": supplied, "path": candidate.relative_to(workspace).as_posix()}


def enterprise_enforcement_projection(root: Path) -> dict[str, Any]:
    """Read bounded local decision evidence for Graph Ops/MCP; never admits work."""
    workspace = Path(root).resolve()
    directory = workspace / ".factory" / "enterprise-enforcement" / "decisions"
    result: dict[str, Any] = {"schema": PROJECTION_SCHEMA, "marker": "ENTERPRISE_ENFORCEMENT_READ_ONLY", "decision_count": 0, "admitted_count": 0, "invalid_count": 0, "decisions": [], "authority": dict(AUTHORITY), "claim_boundary": "Read-only local projection of PEP reference decisions. It does not authenticate a cloud workload, execute a tool, enforce a network boundary, or grant authority."}
    for path in sorted(directory.glob("*.json"))[:500] if directory.is_dir() else []:
        try:
            checked = verify_enterprise_decision(workspace, path)
            value, supplied = checked["decision"], checked["decision_sha256"]
            result["decision_count"] += 1
            if value.get("admitted") is True:
                result["admitted_count"] += 1
            result["decisions"].append({"path": path.relative_to(workspace).as_posix(), "decision_sha256": supplied, "admitted": value.get("admitted") is True, "action_id": value.get("request", {}).get("action_id"), "action_class": value.get("request", {}).get("action_class"), "semantic_authority_status": value.get("semantic_authority_status"), "revocation_status": value.get("revocation_status")})
        except EnterpriseEnforcementError:
            result["invalid_count"] += 1
    from .enterprise_runner_admission import runner_admission_projection
    result["runner_admission"] = runner_admission_projection(workspace)
    return result
