"""Fail-closed, intent-scoped handoffs for local agent workflows.

This module is the deterministic boundary between a probabilistic agent's
message and any future runner.  It validates only bounded facts: a sealed
Oracle contract, a versioned context identifier, declared sender/receiver,
scoped actions, expiration, and replay.  It deliberately does *not* infer
meaning, execute a tool, contact a network, or grant external authority.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .agent_license import normalize_agent_identity
from .oracle_firewall import AUTHORITY, AUTHORITY_ORIGINS, OracleFirewallError, verify_oracle_contract


HANDOFF_INPUT_SCHEMA = "factory.semantic-handoff-input.v1"
HANDOFF_SCHEMA = "factory.semantic-handoff.v1"
LEASE_INPUT_SCHEMA = "factory.authority-lease-input.v1"
LEASE_SCHEMA = "factory.authority-lease.v1"
DECISION_SCHEMA = "factory.semantic-action-decision.v1"
PROJECTION_SCHEMA = "factory.semantic-authority-projection.v1"
MAX_BYTES = 1_048_576
MAX_ITEMS = 64
MAX_LEASE = timedelta(hours=24)
IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
CONTEXT = re.compile(r"^urn:factory:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]*$")
PERFORMATIVES = frozenset({"REQUEST", "INFORM", "PROPOSE", "AGREE", "REFUSE", "QUERY", "ACCEPT", "REJECT", "COUNTER_PROPOSE"})
# A local receipt never authorizes an externally consequential operation.
FORBIDDEN_ACTIONS = frozenset({"merge", "publish", "deploy", "sign", "message", "credential", "connector", "purchase"})


class SemanticAuthorityError(ValueError):
    """Stable, safe error suitable for a local incident or adapter receipt."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", f"{field} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", f"{field} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _text(value: object, field: str, *, limit: int = 800) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", f"{field} must be a non-empty string up to {limit} characters")
    return result


def _identifier(value: object, field: str) -> str:
    result = _text(value, field, limit=96)
    if not IDENTIFIER.fullmatch(result):
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", f"{field} must match {IDENTIFIER.pattern}")
    return result


def _context(value: object) -> str:
    result = _text(value, "context_urn", limit=160)
    if not CONTEXT.fullmatch(result):
        raise SemanticAuthorityError("SEMANTIC_CONTEXT_INVALID", "context_urn must be a versioned urn:factory:<context>:vN identifier")
    return result


def _inside(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise SemanticAuthorityError("SEMANTIC_PATH_OUT_OF_SCOPE", "all paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise SemanticAuthorityError("SEMANTIC_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _relative_paths(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ITEMS:
        raise SemanticAuthorityError("SEMANTIC_SCOPE_INVALID", f"{field} must contain 1 through {MAX_ITEMS} workspace-relative paths")
    paths: list[str] = []
    for raw in value:
        if not isinstance(raw, str) or not raw.strip():
            raise SemanticAuthorityError("SEMANTIC_SCOPE_INVALID", f"{field} contains an empty path")
        path = Path(raw.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise SemanticAuthorityError("SEMANTIC_SCOPE_INVALID", f"{field} paths must remain workspace-relative")
        normal = path.as_posix().removeprefix("./") or "."
        paths.append(normal)
    return sorted(set(paths))


def _within_scope(requested: list[str], allowed: list[str]) -> bool:
    for path in requested:
        if not any(scope == "." or path == scope or path.startswith(scope.rstrip("/") + "/") for scope in allowed):
            return False
    return True


def _actions(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ITEMS:
        raise SemanticAuthorityError("SEMANTIC_ACTION_INVALID", f"{field} must contain 1 through {MAX_ITEMS} actions")
    actions = sorted({_identifier(item, field) for item in value})
    if any(action.lower() in FORBIDDEN_ACTIONS for action in actions):
        raise SemanticAuthorityError("SEMANTIC_ACTION_FORBIDDEN", "local semantic authority never grants an external or consequential action")
    return actions


def _epistemic_entry(value: object, field: str, *, source_ids: set[str], require_source: bool) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticAuthorityError("SEMANTIC_EPISTEMIC_INVALID", f"{field} entries must be objects")
    result = {"id": _identifier(value.get("id"), f"{field}.id")}
    if require_source:
        source_id = _identifier(value.get("source_id"), f"{field}.source_id")
        if source_id not in source_ids:
            raise SemanticAuthorityError("SEMANTIC_EPISTEMIC_INVALID", f"{field}.source_id must be bound by the sealed Oracle Contract")
        result.update({"statement": _text(value.get("statement"), f"{field}.statement", limit=320), "source_id": source_id})
    else:
        result.update({"statement": _text(value.get("statement"), f"{field}.statement", limit=320), "impact": _text(value.get("impact"), f"{field}.impact", limit=320)})
        if field.startswith("unknown"):
            blocking = value.get("blocking")
            if not isinstance(blocking, bool):
                raise SemanticAuthorityError("SEMANTIC_EPISTEMIC_INVALID", f"{field}.blocking must be boolean")
            result["blocking"] = blocking
    return result


def _epistemic(value: object, sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticAuthorityError("SEMANTIC_EPISTEMIC_INVALID", "epistemic must declare known, unknown, uncertain, and capability_limits")
    source_ids = set(sources)
    groups = {"known": (True, "known"), "unknown": (False, "unknown"), "uncertain": (False, "uncertain")}
    result: dict[str, Any] = {}
    for key, (require_source, field) in groups.items():
        items = value.get(key)
        if not isinstance(items, list) or not items or len(items) > 16:
            raise SemanticAuthorityError("SEMANTIC_EPISTEMIC_INVALID", f"epistemic.{key} must contain 1 through 16 explicit declarations")
        parsed = [_epistemic_entry(item, field, source_ids=source_ids, require_source=require_source) for item in items]
        if len({item["id"] for item in parsed}) != len(parsed):
            raise SemanticAuthorityError("SEMANTIC_EPISTEMIC_INVALID", f"epistemic.{key} identifiers must be unique")
        result[key] = parsed
    limits = value.get("capability_limits")
    if not isinstance(limits, list) or not limits or len(limits) > 16:
        raise SemanticAuthorityError("SEMANTIC_EPISTEMIC_INVALID", "epistemic.capability_limits must contain 1 through 16 declared limits")
    result["capability_limits"] = sorted({_text(item, "epistemic.capability_limits", limit=240) for item in limits})
    return result


def _read_json(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _inside(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise SemanticAuthorityError("SEMANTIC_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", "input must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise SemanticAuthorityError("SEMANTIC_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _valid(value: object, schema: str, field: str) -> bool:
    if not isinstance(value, dict) or value.get("schema") != schema or not isinstance(value.get(field), str):
        return False
    return _sha({key: item for key, item in value.items() if key != field}) == value[field]


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write_new(root: Path, path: Path, payload: dict[str, Any], digest_field: str) -> Path:
    target = _inside(root, path, exists=False)
    if target.exists():
        raise SemanticAuthorityError("SEMANTIC_OUTPUT_EXISTS", "destination already exists; receipts are immutable")
    core = dict(payload)
    core[digest_field] = _sha(core)
    _atomic_json(target, core)
    return target


def _contract(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    checked = verify_oracle_contract(root, path)
    if not checked.get("ok") or not isinstance(checked.get("contract"), dict):
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "the referenced Oracle contract is not hash-valid and current")
    return checked["contract"], _inside(root, path)


def _identity_matches(left: object, right: object) -> bool:
    return isinstance(left, dict) and isinstance(right, dict) and left.get("subject") == right.get("subject") and left.get("provider") == right.get("provider") and left.get("model") == right.get("model")


def seal_semantic_handoff(root: Path, input_path: Path, out: Path) -> dict[str, Any]:
    """Seal a typed, context-bound message; it is not an execution grant."""
    workspace = Path(root).resolve()
    value, source = _read_json(workspace, input_path, HANDOFF_INPUT_SCHEMA)
    contract_raw = value.get("oracle_contract")
    if not isinstance(contract_raw, str):
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", "oracle_contract is required")
    contract, contract_path = _contract(workspace, Path(contract_raw))
    sender = normalize_agent_identity(value.get("sender"), "sender")
    receiver = normalize_agent_identity(value.get("receiver"), "receiver")
    performative = _text(value.get("performative"), "performative", limit=32).upper()
    if performative not in PERFORMATIVES:
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", "performative is unsupported")
    context_urn = _context(value.get("context_urn"))
    context_source_id = _identifier(value.get("context_source_id"), "context_source_id")
    sources = {item.get("id"): item for item in contract.get("sources", []) if isinstance(item, dict)}
    bound_source = sources.get(context_source_id)
    if not isinstance(bound_source, dict) or bound_source.get("origin") not in AUTHORITY_ORIGINS:
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "context source must be a human-confirmed or trusted-source Oracle input")
    scope_paths = _relative_paths(value.get("scope_paths"), "scope_paths")
    contract_scope = list(contract.get("scope_paths", []))
    if not _within_scope(scope_paths, contract_scope):
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "handoff scope exceeds the sealed Oracle contract")
    sensitivity = value.get("sensitivities", [])
    if not isinstance(sensitivity, list) or len(sensitivity) > 16 or any(not isinstance(item, dict) for item in sensitivity):
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", "sensitivities must be up to 16 structured, non-executable observations")
    cleaned_sensitivity = [{"id": _identifier(item.get("id"), "sensitivity.id"), "when": _text(item.get("when"), "sensitivity.when", limit=240), "impact": _text(item.get("impact"), "sensitivity.impact", limit=240)} for item in sensitivity]
    epistemic = _epistemic(value.get("epistemic"), sources)
    core = {
        "schema": HANDOFF_SCHEMA, "marker": "SEMANTIC_HANDOFF_SEALED", "handoff_id": _identifier(value.get("id"), "id"), "sealed_at": _stamp(),
        "performative": performative, "goal": _text(value.get("goal"), "goal", limit=320), "sender": sender, "receiver": receiver, "context": {"urn": context_urn, "source_id": context_source_id, "source_sha256": bound_source.get("sha256")},
        "oracle": {"path": contract_path.relative_to(workspace).as_posix(), "contract_sha256": contract.get("contract_sha256")}, "scope_paths": scope_paths,
        "allowed_actions": _actions(value.get("allowed_actions"), "allowed_actions"), "sensitivities": cleaned_sensitivity, "epistemic": epistemic,
        "authority": dict(AUTHORITY), "claim_boundary": "Hash-sealed local message envelope only. It validates declared context, sourced facts, explicit unknowns/uncertainties, stated limits, and scope. It does not prove semantic truth, external identity, private reasoning, tool execution, approval, or network authorization.",
    }
    target = _write_new(workspace, out, core, "handoff_sha256")
    return {**json.loads(target.read_text(encoding="utf-8")), "path": target.relative_to(workspace).as_posix()}


def verify_semantic_handoff(root: Path, path: Path) -> dict[str, Any]:
    """Verify a sealed local handoff and its current Oracle Contract binding."""
    workspace = Path(root).resolve()
    try:
        value, source = _read_json(workspace, path, HANDOFF_SCHEMA)
        if not _valid(value, HANDOFF_SCHEMA, "handoff_sha256"):
            return {"ok": False, "code": "SEMANTIC_HANDOFF_HASH_INVALID"}
        contract, _ = _contract(workspace, Path(str(value.get("oracle", {}).get("path", ""))))
        if contract.get("contract_sha256") != value.get("oracle", {}).get("contract_sha256"):
            return {"ok": False, "code": "E_SEMANTIC_AUTHORIZATION"}
        return {"ok": True, "handoff": value, "path": source.relative_to(workspace).as_posix()}
    except (SemanticAuthorityError, OracleFirewallError):
        return {"ok": False, "code": "E_SEMANTIC_AUTHORIZATION"}


def seal_authority_lease(root: Path, input_path: Path, out: Path) -> dict[str, Any]:
    """Seal a short-lived, least-privilege lease derived from one handoff."""
    workspace = Path(root).resolve()
    value, _ = _read_json(workspace, input_path, LEASE_INPUT_SCHEMA)
    raw_handoff = value.get("handoff")
    if not isinstance(raw_handoff, str):
        raise SemanticAuthorityError("SEMANTIC_INPUT_INVALID", "handoff is required")
    verified = verify_semantic_handoff(workspace, Path(raw_handoff))
    if not verified.get("ok"):
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "the semantic handoff is not current and hash-valid")
    handoff = verified["handoff"]
    delegatee = normalize_agent_identity(value.get("delegatee"), "delegatee")
    if not _identity_matches(delegatee, handoff.get("receiver")):
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "lease delegatee must exactly match the handoff receiver")
    scope_paths = _relative_paths(value.get("scope_paths"), "scope_paths")
    actions = _actions(value.get("allowed_actions"), "allowed_actions")
    if not _within_scope(scope_paths, handoff["scope_paths"]) or not set(actions).issubset(set(handoff["allowed_actions"])):
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "lease cannot widen the sealed handoff scope or actions")
    expires_at = _parse_time(value.get("expires_at"), "expires_at")
    if expires_at <= _now() or expires_at - _now() > MAX_LEASE:
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "lease must expire in the next 24 hours")
    approval_origin = _text(value.get("approval_origin"), "approval_origin", limit=64)
    if approval_origin not in AUTHORITY_ORIGINS:
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "only human-confirmed or trusted-source approval may issue a lease")
    core = {
        "schema": LEASE_SCHEMA, "marker": "AUTHORITY_LEASE_SEALED", "lease_id": _identifier(value.get("id"), "id"), "issued_at": _stamp(), "expires_at": _stamp(expires_at),
        "handoff": {"path": verified["path"], "handoff_sha256": handoff["handoff_sha256"], "oracle_contract_sha256": handoff["oracle"]["contract_sha256"], "context_urn": handoff["context"]["urn"]},
        "delegatee": delegatee, "scope_paths": scope_paths, "allowed_actions": actions, "approval": {"origin": approval_origin, "approved_by": _text(value.get("approved_by"), "approved_by", limit=160), "rationale": _text(value.get("rationale"), "rationale")},
        "authority": dict(AUTHORITY), "claim_boundary": "Hash-sealed local, expiring scope receipt only. A runner must independently enforce it; this artifact never calls a tool, changes code, approves work, or grants external authority.",
    }
    target = _write_new(workspace, out, core, "lease_sha256")
    return {**json.loads(target.read_text(encoding="utf-8")), "path": target.relative_to(workspace).as_posix()}


def verify_authority_lease(root: Path, path: Path) -> dict[str, Any]:
    """Verify a hash-valid, current lease without treating it as external authority."""
    workspace = Path(root).resolve()
    try:
        lease, source = _read_json(workspace, path, LEASE_SCHEMA)
        if not _valid(lease, LEASE_SCHEMA, "lease_sha256"):
            return {"ok": False, "code": "SEMANTIC_LEASE_HASH_INVALID"}
        handoff_result = verify_semantic_handoff(workspace, Path(str(lease.get("handoff", {}).get("path", ""))))
        if not handoff_result.get("ok") or handoff_result["handoff"].get("handoff_sha256") != lease.get("handoff", {}).get("handoff_sha256"):
            return {"ok": False, "code": "E_SEMANTIC_AUTHORIZATION"}
        if _parse_time(lease.get("expires_at"), "expires_at") <= _now():
            return {"ok": False, "code": "SEMANTIC_LEASE_EXPIRED"}
        return {"ok": True, "lease": lease, "path": source.relative_to(workspace).as_posix()}
    except (SemanticAuthorityError, OracleFirewallError):
        return {"ok": False, "code": "E_SEMANTIC_AUTHORIZATION"}


def authorize_semantic_action(root: Path, lease_path: Path, request: object) -> dict[str, Any]:
    """Deterministically reject a request unless every bounded constraint holds."""
    workspace = Path(root).resolve()
    checked = verify_authority_lease(workspace, lease_path)
    if not checked.get("ok"):
        return {"marker": "E_SEMANTIC_AUTHORIZATION", "allowed": False, "reason": checked.get("code"), "authority": dict(AUTHORITY)}
    lease = checked["lease"]
    if not isinstance(request, dict):
        return {"marker": "E_SEMANTIC_AUTHORIZATION", "allowed": False, "reason": "request_invalid", "authority": dict(AUTHORITY)}
    try:
        actor = normalize_agent_identity(request.get("actor"), "actor")
        action = _identifier(request.get("action"), "action")
        action_id = _identifier(request.get("action_id"), "action_id")
        scope_paths = _relative_paths(request.get("scope_paths"), "scope_paths")
        context_urn = _context(request.get("context_urn"))
    except (SemanticAuthorityError, OracleFirewallError) as exc:
        return {"marker": "E_SEMANTIC_AUTHORIZATION", "allowed": False, "reason": getattr(exc, "code", "request_invalid"), "authority": dict(AUTHORITY)}
    reason = None
    if not _identity_matches(actor, lease.get("delegatee")):
        reason = "lease_subject_mismatch"
    elif action not in lease.get("allowed_actions", []):
        reason = "action_not_granted"
    elif not _within_scope(scope_paths, lease.get("scope_paths", [])):
        reason = "scope_escape"
    elif context_urn != lease.get("handoff", {}).get("context_urn"):
        reason = "context_mismatch"
    if reason:
        return {"marker": "E_SEMANTIC_AUTHORIZATION", "allowed": False, "reason": reason, "action_id": action_id, "authority": dict(AUTHORITY)}
    return {"marker": "SEMANTIC_ACTION_CONSTRAINED", "allowed": True, "reason": "deterministic_constraints_satisfied", "action_id": action_id, "action": action, "scope_paths": scope_paths, "lease_sha256": lease["lease_sha256"], "authority": dict(AUTHORITY), "claim_boundary": "This is an admission decision for a separate runner, not execution, approval, tool authorization, or proof that the requested action is semantically correct."}


def verify_semantic_binding(root: Path, binding: object, actor: object, scope_paths: object) -> dict[str, Any]:
    """Verify a provider-neutral evidence envelope names its exact active lease.

    This is a retrospective integrity binding, not evidence that an external
    provider enforced the lease while it ran.
    """
    workspace = Path(root).resolve()
    if not isinstance(binding, dict) or set(binding) != {"lease_path", "lease_sha256", "action_id", "action", "context_urn"}:
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", "semantic_authority must contain only the exact lease and action binding fields")
    lease_path = _inside(workspace, Path(_text(binding["lease_path"], "semantic_authority.lease_path", limit=512)))
    supplied = _text(binding["lease_sha256"], "semantic_authority.lease_sha256", limit=64)
    request = {"actor": actor, "action_id": binding["action_id"], "action": binding["action"], "context_urn": binding["context_urn"], "scope_paths": scope_paths}
    decision = authorize_semantic_action(workspace, lease_path, request)
    if not decision.get("allowed") or decision.get("lease_sha256") != supplied:
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", str(decision.get("reason", "lease binding rejected")))
    return {"lease_path": lease_path.relative_to(workspace).as_posix(), "lease_sha256": supplied, "action_id": decision["action_id"], "action": decision["action"], "context_urn": binding["context_urn"], "claim_boundary": "Current local lease and envelope binding only; not external provider enforcement, tool execution, semantic correctness, approval, or release authority."}


def record_semantic_action_decision(root: Path, lease_path: Path, request: object, out: Path) -> dict[str, Any]:
    """Record one replay-safe local admission result without running the requested action."""
    workspace = Path(root).resolve()
    decision = authorize_semantic_action(workspace, lease_path, request)
    if not decision.get("allowed"):
        raise SemanticAuthorityError("E_SEMANTIC_AUTHORIZATION", str(decision.get("reason")))
    directory = workspace / ".factory" / "semantic-authority" / "decisions"
    for path in sorted(directory.glob("*.json"))[:200] if directory.is_dir() else []:
        try:
            prior, _ = _read_json(workspace, path, DECISION_SCHEMA)
        except SemanticAuthorityError:
            continue
        if _valid(prior, DECISION_SCHEMA, "decision_sha256") and prior.get("lease_sha256") == decision["lease_sha256"] and prior.get("action_id") == decision["action_id"]:
            raise SemanticAuthorityError("E_SEMANTIC_REPLAY", "action_id was already recorded for this lease")
    core = {"schema": DECISION_SCHEMA, **decision, "marker": "SEMANTIC_ACTION_DECISION_RECORDED", "recorded_at": _stamp()}
    target = _write_new(workspace, out, core, "decision_sha256")
    return {**json.loads(target.read_text(encoding="utf-8")), "path": target.relative_to(workspace).as_posix()}


def _project_handoff_or_lease(result: dict[str, Any], kind: str, checked: dict[str, Any], path: Path, workspace: Path) -> None:
    summary = {"path": path.relative_to(workspace).as_posix(), "ok": bool(checked.get("ok")), "code": checked.get("code")}
    if checked.get("ok"):
        item = checked["handoff"] if kind == "handoffs" else checked["lease"]
        summary.update(_handoff_or_lease_identity(kind, item))
        if kind == "handoffs":
            summary.update(_epistemic_counts(item))
            result["handoff_count"] += 1
            result["current_handoff_count"] += 1
        else:
            result["lease_count"] += 1
            result["active_lease_count"] += 1
    elif kind == "leases" and checked.get("code") == "SEMANTIC_LEASE_EXPIRED":
        result["lease_count"] += 1
        result["expired_lease_count"] += 1
    else:
        result["invalid_count"] += 1
    result[kind].append(summary)


def _handoff_or_lease_identity(kind: str, item: dict[str, Any]) -> dict[str, Any]:
    if kind == "handoffs":
        return {"sha256": item.get("handoff_sha256"), "id": item.get("handoff_id"), "context_urn": item.get("context", {}).get("urn"), "contract_sha256": item.get("oracle", {}).get("contract_sha256")}
    return {"sha256": item.get("lease_sha256"), "id": item.get("lease_id"), "context_urn": item.get("handoff", {}).get("context_urn"), "contract_sha256": item.get("handoff", {}).get("oracle_contract_sha256")}


def _epistemic_counts(handoff: dict[str, Any]) -> dict[str, int]:
    epistemic = handoff.get("epistemic", {}) if isinstance(handoff.get("epistemic"), dict) else {}
    unknown = epistemic.get("unknown", [])
    return {"known_count": len(epistemic.get("known", [])), "unknown_count": len(unknown), "uncertain_count": len(epistemic.get("uncertain", [])), "blocking_unknown_count": sum(1 for entry in unknown if isinstance(entry, dict) and entry.get("blocking") is True), "capability_limit_count": len(epistemic.get("capability_limits", []))}


def _project_handoffs_and_leases(workspace: Path, base: Path, result: dict[str, Any]) -> None:
    kinds = (("handoffs", verify_semantic_handoff), ("leases", verify_authority_lease))
    for kind, verifier in kinds:
        directory = base / kind
        paths = sorted(directory.glob("*.json"))[:200] if directory.is_dir() else []
        for path in paths:
            _project_handoff_or_lease(result, kind, verifier(workspace, path), path, workspace)


def _project_decisions(workspace: Path, base: Path, result: dict[str, Any]) -> None:
    directory = base / "decisions"
    paths = sorted(directory.glob("*.json"))[:200] if directory.is_dir() else []
    for path in paths:
        try:
            item, _ = _read_json(workspace, path, DECISION_SCHEMA)
            if not _valid(item, DECISION_SCHEMA, "decision_sha256"):
                raise SemanticAuthorityError("SEMANTIC_DECISION_HASH_INVALID", "invalid decision")
            result["decision_count"] += 1
            result["decisions"].append({"path": path.relative_to(workspace).as_posix(), "sha256": item["decision_sha256"], "lease_sha256": item.get("lease_sha256"), "action_id": item.get("action_id"), "action": item.get("action")})
        except SemanticAuthorityError:
            result["invalid_count"] += 1


def semantic_authority_projection(root: Path) -> dict[str, Any]:
    """Read bounded local handoffs, leases, and decisions for Graph Ops/MCP."""
    workspace = Path(root).resolve()
    base = workspace / ".factory" / "semantic-authority"
    result: dict[str, Any] = {"schema": PROJECTION_SCHEMA, "marker": "SEMANTIC_AUTHORITY_READ_ONLY", "handoff_count": 0, "current_handoff_count": 0, "lease_count": 0, "active_lease_count": 0, "expired_lease_count": 0, "decision_count": 0, "invalid_count": 0, "handoffs": [], "leases": [], "decisions": [], "authority": dict(AUTHORITY), "claim_boundary": "Read-only local hash-valid receipt projection. It does not authenticate a real-world identity, inspect semantic truth, run a sandbox, execute a tool, or grant any authority."}
    _project_handoffs_and_leases(workspace, base, result)
    _project_decisions(workspace, base, result)
    for key in ("handoffs", "leases", "decisions"):
        result[key].sort(key=lambda item: str(item.get("path")))
    return result
