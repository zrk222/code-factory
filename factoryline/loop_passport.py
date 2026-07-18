"""Portable Loop Passport contracts for governed autonomous work."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import math
import re
import uuid


LOOP_MANIFEST_SCHEMA = "factory.loop.manifest.v1"
LOOP_VALIDATION_SCHEMA = "factory.loop.validation.v1"
LOOP_PASSPORT_SCHEMA = "factory.loop.passport.v1"
LOOP_BUDGET_RECEIPT_SCHEMA = "factory.loop.budget-receipt.v1"

TRIGGER_TYPES = frozenset({"manual", "cron", "hook", "goal", "heartbeat"})
AUTONOMY_LEVELS = frozenset({"human_controlled", "supervised", "autonomous"})
STATES = frozenset({"planned", "running", "waiting_for_approval", "completed", "failed", "budget_exceeded", "cancelled"})
DESTRUCTIVE_ACTIONS = frozenset({"merge", "publish", "deploy", "delete", "production_write"})
DEFAULT_TRANSITIONS = {
    "planned": ["running", "cancelled"],
    "running": ["waiting_for_approval", "completed", "failed", "budget_exceeded", "cancelled"],
    "waiting_for_approval": ["running", "failed", "cancelled"],
    "completed": [],
    "failed": [],
    "budget_exceeded": [],
    "cancelled": [],
}
_SECRET_KEYS = frozenset({"api_key", "password", "private_key", "secret", "token", "credential"})
_SENSITIVE_PREFIXES = ("sk-", "pypi-", "ghp_", "github_pat_")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _error(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def _nonempty_string(value: object, path: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        _error(errors, path, "must be a non-empty string")
        return None
    return value.strip()


def _string_list(value: object, path: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list):
        _error(errors, path, "must be a list of strings")
        return []
    result = []
    for index, item in enumerate(value):
        text = _nonempty_string(item, f"{path}[{index}]", errors)
        if text is not None:
            result.append(text)
    return result


def _nonnegative_number(value: object, path: str, errors: list[str]) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        _error(errors, path, "must be a non-negative number")
        return None
    return float(value)


def _scan_for_secrets(value: object, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if key_text in _SECRET_KEYS or key_text.endswith(("_token", "_secret", "_password", "_key")):
                _error(errors, child_path, "secret-like fields are forbidden; reference a managed connector by name")
            _scan_for_secrets(child, child_path, errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_for_secrets(child, f"{path}[{index}]", errors)
    elif isinstance(value, str) and value.lower().startswith(_SENSITIVE_PREFIXES):
        _error(errors, path, "secret-like values are forbidden in loop manifests")


def _validate_trigger(trigger: object, errors: list[str]) -> None:
    if not isinstance(trigger, dict):
        _error(errors, "trigger", "must be an object")
        return
    kind = _nonempty_string(trigger.get("type"), "trigger.type", errors)
    if kind not in TRIGGER_TYPES:
        _error(errors, "trigger.type", f"must be one of {sorted(TRIGGER_TYPES)}")
        return
    required = {"cron": "schedule", "hook": "event", "goal": "success_condition", "heartbeat": "interval_seconds"}
    field = required.get(kind)
    if field == "interval_seconds":
        value = _nonnegative_number(trigger.get(field), f"trigger.{field}", errors)
        if value is not None and value < 1:
            _error(errors, f"trigger.{field}", "must be at least 1")
    elif field:
        _nonempty_string(trigger.get(field), f"trigger.{field}", errors)


def _validate_workspace(workspace: object, autonomy: str | None, errors: list[str]) -> None:
    if not isinstance(workspace, dict):
        _error(errors, "workspace", "must be an object")
        return
    mode = _nonempty_string(workspace.get("mode"), "workspace.mode", errors)
    if mode not in {"isolated", "ephemeral"}:
        _error(errors, "workspace.mode", "must be isolated or ephemeral")
    if autonomy == "autonomous" and mode != "ephemeral":
        _error(errors, "workspace.mode", "autonomous loops require an ephemeral workspace contract")
    paths = _string_list(workspace.get("allowed_paths"), "workspace.allowed_paths", errors)
    if not paths:
        _error(errors, "workspace.allowed_paths", "must declare at least one relative path")
    for item in paths:
        candidate = Path(item)
        if candidate.is_absolute() or re.match(r"^[A-Za-z]:[\\/]", item) or ".." in candidate.parts:
            _error(errors, "workspace.allowed_paths", "must not contain absolute or parent-traversal paths")
    network = _nonempty_string(workspace.get("network"), "workspace.network", errors)
    if network not in {"deny", "allowlist"}:
        _error(errors, "workspace.network", "must be deny or allowlist")
    if network == "allowlist" and not _string_list(workspace.get("network_hosts"), "workspace.network_hosts", errors):
        _error(errors, "workspace.network_hosts", "allowlist mode requires at least one host")


def _validate_capabilities(capabilities: object, approvals: object, errors: list[str]) -> None:
    if not isinstance(capabilities, dict):
        _error(errors, "capabilities", "must be an object")
        return
    _string_list(capabilities.get("skills"), "capabilities.skills", errors)
    _string_list(capabilities.get("connectors"), "capabilities.connectors", errors)
    actions = _string_list(capabilities.get("actions"), "capabilities.actions", errors)
    if not isinstance(approvals, dict):
        return
    required_for = set(_string_list(approvals.get("required_for"), "approvals.required_for", errors))
    missing = sorted(set(actions) & DESTRUCTIVE_ACTIONS - required_for)
    if missing:
        _error(errors, "approvals.required_for", f"must cover declared destructive actions: {', '.join(missing)}")


def _validate_budgets(budgets: object, errors: list[str]) -> None:
    if not isinstance(budgets, dict):
        _error(errors, "budgets", "must be an object")
        return
    for field in ("max_iterations", "max_wall_seconds", "max_tokens", "max_cost_usd"):
        value = _nonnegative_number(budgets.get(field), f"budgets.{field}", errors)
        if field in {"max_iterations", "max_wall_seconds"} and value is not None and value < 1:
            _error(errors, f"budgets.{field}", "must be at least 1")


def _validate_validators(validators: object, autonomy: str | None, errors: list[str]) -> None:
    if not isinstance(validators, dict):
        _error(errors, "validators", "must be an object")
        return
    values = {field: _string_list(validators.get(field), f"validators.{field}", errors) for field in ("pre", "post", "invariant")}
    required = {"human_controlled": (), "supervised": ("pre", "post"), "autonomous": ("pre", "post", "invariant")}
    for field in required.get(autonomy, ()):
        if not values[field]:
            _error(errors, f"validators.{field}", f"{autonomy} loops require at least one {field} validator")


def _validate_approvals(approvals: object, errors: list[str]) -> None:
    if not isinstance(approvals, dict):
        _error(errors, "approvals", "must be an object")
        return
    required_for = _string_list(approvals.get("required_for"), "approvals.required_for", errors)
    missing = sorted(DESTRUCTIVE_ACTIONS - set(required_for))
    if missing:
        _error(errors, "approvals.required_for", f"must include baseline destructive actions: {', '.join(missing)}")
    if approvals.get("distinct_approver") is not True:
        _error(errors, "approvals.distinct_approver", "must be true")
    expiry = _nonnegative_number(approvals.get("expires_minutes"), "approvals.expires_minutes", errors)
    if expiry is not None and expiry < 1:
        _error(errors, "approvals.expires_minutes", "must be at least 1")


def _validate_states(states: object, errors: list[str]) -> None:
    if not isinstance(states, dict):
        _error(errors, "states", "must be an object")
        return
    if states.get("initial") != "planned":
        _error(errors, "states.initial", "must be planned")
    transitions = states.get("transitions")
    if not isinstance(transitions, dict):
        _error(errors, "states.transitions", "must be an object")
        return
    missing = sorted(STATES - set(transitions))
    if missing:
        _error(errors, "states.transitions", f"must declare every state: {', '.join(missing)}")
    for source, targets in transitions.items():
        if source not in STATES:
            _error(errors, f"states.transitions.{source}", "is not a known state")
        target_list = _string_list(targets, f"states.transitions.{source}", errors)
        unknown = sorted(set(target_list) - STATES)
        if unknown:
            _error(errors, f"states.transitions.{source}", f"has unknown target states: {', '.join(unknown)}")
        if source in {"completed", "failed", "budget_exceeded", "cancelled"} and target_list:
            _error(errors, f"states.transitions.{source}", "terminal states must not transition further")


def default_manifest(loop_id: str, owner: str) -> dict[str, Any]:
    """Return a bounded, human-controlled starter manifest for a reusable agent loop."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", loop_id):
        raise ValueError("loop id must use lowercase letters, digits, and hyphens, starting with a letter")
    if not owner.strip():
        raise ValueError("owner is required")
    return {
        "schema": LOOP_MANIFEST_SCHEMA,
        "id": loop_id,
        "owner": owner.strip(),
        "autonomy": "human_controlled",
        "trigger": {"type": "manual"},
        "workspace": {"mode": "isolated", "allowed_paths": ["."], "network": "deny"},
        "capabilities": {"skills": [], "connectors": [], "actions": ["read_repository", "write_workspace"]},
        "budgets": {"max_iterations": 1, "max_wall_seconds": 900, "max_tokens": 0, "max_cost_usd": 0},
        "validators": {"pre": [], "post": [], "invariant": []},
        "approvals": {"required_for": sorted(DESTRUCTIVE_ACTIONS), "distinct_approver": True, "expires_minutes": 60},
        "states": {"initial": "planned", "transitions": DEFAULT_TRANSITIONS},
        "scope": "Contract only. Runtime credential injection, sandboxing, and provider billing must be enforced by the selected harness.",
    }


def init_loop(root: Path, loop_id: str, owner: str, *, force: bool = False) -> dict[str, Any]:
    """Initialize a loop manifest, refusing to replace governance by default."""
    manifest = default_manifest(loop_id, owner)
    path = Path(root) / ".factory" / "loops" / f"{loop_id}.loop.json"
    if path.exists() and not force:
        raise ValueError(f"loop manifest already exists: {path}; use --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"schema": LOOP_MANIFEST_SCHEMA, "path": str(path.resolve()), "manifest": manifest}


def load_manifest(path: Path) -> dict[str, Any]:
    """Load a loop manifest object or raise a precise validation error."""
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("loop manifest must be a JSON object")
    return payload


def validate_manifest(path: Path) -> dict[str, Any]:
    """Validate loop topology, budgets, capabilities, approvals, and secret hygiene."""
    path = Path(path)
    manifest = load_manifest(path)
    errors: list[str] = []
    if manifest.get("schema") != LOOP_MANIFEST_SCHEMA:
        _error(errors, "schema", f"must equal {LOOP_MANIFEST_SCHEMA}")
    loop_id = _nonempty_string(manifest.get("id"), "id", errors)
    if loop_id is not None and not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", loop_id):
        _error(errors, "id", "must use lowercase letters, digits, and hyphens, starting with a letter")
    _nonempty_string(manifest.get("owner"), "owner", errors)
    autonomy = _nonempty_string(manifest.get("autonomy"), "autonomy", errors)
    if autonomy not in AUTONOMY_LEVELS:
        _error(errors, "autonomy", f"must be one of {sorted(AUTONOMY_LEVELS)}")
    _validate_trigger(manifest.get("trigger"), errors)
    _validate_workspace(manifest.get("workspace"), autonomy, errors)
    _validate_approvals(manifest.get("approvals"), errors)
    _validate_capabilities(manifest.get("capabilities"), manifest.get("approvals"), errors)
    _validate_budgets(manifest.get("budgets"), errors)
    _validate_validators(manifest.get("validators"), autonomy, errors)
    _validate_states(manifest.get("states"), errors)
    _scan_for_secrets(manifest, "", errors)
    return {
        "schema": LOOP_VALIDATION_SCHEMA,
        "loop_id": manifest.get("id"),
        "manifest_path": str(path.resolve()),
        "manifest_sha256": _sha256_path(path),
        "valid": not errors,
        "errors": errors,
        "scope_limits": [
            "Validates the declared contract only.",
            "Does not prove a selected runtime actually injects credentials, isolates a host, or enforces network egress.",
        ],
    }


def _loop_mermaid(passport: dict[str, Any]) -> str:
    loop_id = str(passport.get("loop_id", "loop")).replace('"', "'")
    status = str(passport.get("verdict", "BLOCKED"))
    return "\n".join([
        "flowchart LR",
        f'    M["Loop manifest: {loop_id}"] --> V["Static contract validation"]',
        '    M --> C["Capability and approval grants"]',
        '    M --> B["Hard budget contract"]',
        '    M --> S["Declared state machine"]',
        f'    V --> P["Loop Passport: {status}"]',
        '    C --> P',
        '    B --> P',
        '    S --> P',
    ]) + "\n"


def build_loop_passport(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Build a hash-bound loop passport only after its manifest validates cleanly."""
    root = Path(root)
    validation = validate_manifest(manifest_path)
    manifest = load_manifest(manifest_path)
    core = {
        "schema": LOOP_PASSPORT_SCHEMA,
        "loop_id": manifest.get("id"),
        "owner": manifest.get("owner"),
        "autonomy": manifest.get("autonomy"),
        "manifest_path": validation["manifest_path"],
        "manifest_sha256": validation["manifest_sha256"],
        "trigger": manifest.get("trigger"),
        "workspace": manifest.get("workspace"),
        "capabilities": manifest.get("capabilities"),
        "budgets": manifest.get("budgets"),
        "validators": manifest.get("validators"),
        "approvals": manifest.get("approvals"),
        "states": manifest.get("states"),
        "validation": {"valid": validation["valid"], "errors": validation["errors"]},
        "verdict": "VERIFIED" if validation["valid"] else "BLOCKED",
        "scope_limits": [
            "Proves the manifest bytes and static contract validation at generation time.",
            "Does not prove actual connector authorization, runtime sandboxing, credential injection, external tool execution, or provider billing.",
        ],
    }
    passport = {**core, "passport_sha256": hashlib.sha256(_canonical(core)).hexdigest()}
    out_dir = root / ".factory" / "loop-passports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = str(manifest.get("id", "loop"))
    json_path = out_dir / f"{stem}.loop-passport.json"
    mermaid_path = out_dir / f"{stem}.loop-passport.mmd"
    json_path.write_text(json.dumps(passport, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    mermaid_path.write_text(_loop_mermaid(passport), encoding="utf-8")
    return {**passport, "paths": {"json": str(json_path.resolve()), "mermaid": str(mermaid_path.resolve())}}


def verify_loop_passport(path: Path) -> dict[str, Any]:
    """Verify a loop passport schema and manifest hash without trusting its claims."""
    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if payload.get("schema") != LOOP_PASSPORT_SCHEMA:
        errors.append("unsupported loop passport schema")
    core = {key: value for key, value in payload.items() if key not in {"passport_sha256", "paths"}}
    if hashlib.sha256(_canonical(core)).hexdigest() != payload.get("passport_sha256"):
        errors.append("loop passport hash mismatch")
    manifest_path = Path(str(payload.get("manifest_path", "")))
    if not manifest_path.exists():
        errors.append(f"missing loop manifest: {manifest_path}")
    elif _sha256_path(manifest_path) != payload.get("manifest_sha256"):
        errors.append("loop manifest hash mismatch")
    else:
        validation = validate_manifest(manifest_path)
        if not validation["valid"]:
            errors.append("loop manifest no longer satisfies the contract")
    if payload.get("verdict") != "VERIFIED":
        errors.append("loop passport verdict is blocked")
    return {"valid": not errors, "errors": errors, "loop_id": payload.get("loop_id"), "passport_sha256": payload.get("passport_sha256")}


def evaluate_budget(root: Path, manifest_path: Path, usage_path: Path) -> dict[str, Any]:
    """Compare measured loop usage with declared limits and report every overrun."""
    validation = validate_manifest(manifest_path)
    manifest = load_manifest(manifest_path)
    usage = json.loads(Path(usage_path).read_text(encoding="utf-8-sig"))
    if not isinstance(usage, dict):
        raise ValueError("usage must be a JSON object")
    errors: list[str] = []
    actual = {}
    for field in ("iterations", "wall_seconds", "tokens", "cost_usd"):
        value = _nonnegative_number(usage.get(field), f"usage.{field}", errors)
        if value is not None:
            actual[field] = value
    if errors:
        raise ValueError("; ".join(errors))
    budgets = manifest.get("budgets") if isinstance(manifest.get("budgets"), dict) else {}
    limits = {
        "iterations": budgets.get("max_iterations"),
        "wall_seconds": budgets.get("max_wall_seconds"),
        "tokens": budgets.get("max_tokens"),
        "cost_usd": budgets.get("max_cost_usd"),
    }
    exceeded = {
        field: {"actual": actual[field], "limit": limits[field]}
        for field in actual
        if validation["valid"] and actual[field] > limits[field]
    }
    if not validation["valid"]:
        verdict = "MANIFEST_INVALID"
    elif exceeded:
        verdict = "BUDGET_EXCEEDED"
    else:
        verdict = "WITHIN_BUDGET"
    receipt = {
        "schema": LOOP_BUDGET_RECEIPT_SCHEMA,
        "run_id": uuid.uuid4().hex,
        "observed_at": _now(),
        "loop_id": manifest.get("id"),
        "manifest_path": validation["manifest_path"],
        "manifest_sha256": validation["manifest_sha256"],
        "usage_path": str(Path(usage_path).resolve()),
        "usage_sha256": _sha256_path(usage_path),
        "actual": actual,
        "limits": limits,
        "exceeded": exceeded,
        "validation_errors": validation["errors"],
        "verdict": verdict,
        "ok": verdict == "WITHIN_BUDGET",
        "scope_limits": [
            "Usage values are supplied by the caller or runtime adapter.",
            "This receipt enforces declared bounds over supplied values; it does not independently query a provider billing system.",
        ],
    }
    out_dir = Path(root) / ".factory" / "loop-receipts"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{manifest.get('id', 'loop')}-budget-{receipt['run_id'][:12]}.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {**receipt, "path": str(path.resolve())}
