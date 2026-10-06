"""Portable Loop Passport contracts for governed autonomous work."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
import hashlib
import json
import math
import re
import sqlite3
import uuid


LOOP_MANIFEST_SCHEMA = "factory.loop.manifest.v1"
LOOP_VALIDATION_SCHEMA = "factory.loop.validation.v1"
LOOP_PASSPORT_SCHEMA = "factory.loop.passport.v1"
LOOP_BUDGET_RECEIPT_SCHEMA = "factory.loop.budget-receipt.v1"

TRIGGER_TYPES = frozenset({"manual", "cron", "hook", "goal", "heartbeat"})
AUTONOMY_LEVELS = frozenset({"human_controlled", "supervised", "autonomous"})
STATES = frozenset(
    {
        "planned",
        "running",
        "waiting_for_approval",
        "completed",
        "failed",
        "budget_exceeded",
        "cancelled",
    }
)
DESTRUCTIVE_ACTIONS = frozenset(
    {"merge", "publish", "deploy", "delete", "production_write"}
)
DEFAULT_TRANSITIONS = {
    "planned": ["running", "cancelled"],
    "running": [
        "waiting_for_approval",
        "completed",
        "failed",
        "budget_exceeded",
        "cancelled",
    ],
    "waiting_for_approval": ["running", "failed", "cancelled"],
    "completed": [],
    "failed": [],
    "budget_exceeded": [],
    "cancelled": [],
}
_SECRET_KEYS = frozenset(
    {"api_key", "password", "private_key", "secret", "token", "credential"}
)
_SENSITIVE_PREFIXES = ("sk-", "pypi-", "ghp_", "github_pat_")
_RUNTIME_FIELDS = ("iterations", "wall_seconds", "tokens", "cost_usd")
_RUNTIME_SCALE = {
    "iterations": 1,
    "wall_seconds": 1_000_000,
    "tokens": 1,
    "cost_usd": 1_000_000,
}
_RUNTIME_MAX_UNITS = 9_223_372_036_854_775_807
_RUNTIME_SCOPE_LIMITS = [
    "Adapters must call admission before work and settle afterward.",
    "Unenrolled adapters are outside enforcement.",
    "Provider billing is not queried.",
    "The local SQLite ledger is not protected from a hostile process that can concurrently rewrite this workspace.",
]


def _runtime_id_digest(value: object, field: str) -> str:
    """Validate a 128-bit opaque token and return only its digest."""
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ValueError(
            f"{field} must be a 128-bit lowercase hex token from secrets.token_hex(16)"
        )
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _runtime_database_path(root: Path, loop_id: str, run_digest: str) -> Path:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", loop_id):
        raise ValueError("loop_id must be a validated manifest identifier")
    workspace_root = Path(root).resolve()
    factory_lexical = workspace_root / ".factory"
    ledger_lexical = factory_lexical / "loop-runs"
    loop_lexical = ledger_lexical / loop_id
    for component in (factory_lexical, ledger_lexical, loop_lexical):
        is_junction = getattr(component, "is_junction", lambda: False)()
        if component.is_symlink() or is_junction:
            raise ValueError(
                "runtime ledger directory uses a link in the configured root"
            )
    factory_root = factory_lexical.resolve()
    ledger_root = ledger_lexical.resolve()
    try:
        factory_root.relative_to(workspace_root)
        ledger_root.relative_to(factory_root)
    except ValueError as error:
        raise ValueError(
            "runtime ledger directory escapes the configured root"
        ) from error
    lexical_candidate = loop_lexical / f"{run_digest}.sqlite"
    is_junction = getattr(lexical_candidate, "is_junction", lambda: False)()
    if lexical_candidate.is_symlink() or is_junction:
        raise ValueError("runtime ledger database file uses a link")
    candidate = lexical_candidate.resolve()
    try:
        candidate.relative_to(ledger_root)
    except ValueError as error:
        raise ValueError("runtime ledger path escapes the configured root") from error
    return candidate


def _runtime_fraction_units(
    digits: tuple[int, ...], fractional_digits: int, field: str, scale_digits: int
) -> int:
    if fractional_digits > len(digits):
        raise ValueError(f"{field} supports at most {scale_digits} fractional digits")
    significant = "".join(map(str, digits))
    if not significant.endswith("0" * fractional_digits):
        raise ValueError(f"{field} supports at most {scale_digits} fractional digits")
    integer_digits = significant[:-fractional_digits].lstrip("0")
    return int(integer_digits) if integer_digits else 0


def _runtime_decimal_units(amount: Decimal, field: str, scale_digits: int) -> int:
    decimal_tuple = amount.as_tuple()
    digits = decimal_tuple.digits
    coefficient_digits = "".join(map(str, digits)).lstrip("0")
    if not coefficient_digits:
        return 0
    shift = decimal_tuple.exponent + scale_digits
    if shift < 0:
        return _runtime_fraction_units(digits, -shift, field, scale_digits)
    if len(coefficient_digits) + shift > 19:
        raise ValueError(f"{field} exceeds the supported exact range")
    return int(coefficient_digits + ("0" * shift))


def _runtime_units(value: object, field: str) -> int:
    """Normalize one exact runtime value to its bounded integer base unit."""
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ValueError(f"{field} must be a non-negative decimal number")
    try:
        amount = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError(f"{field} must be a non-negative decimal number") from error
    if not amount.is_finite() or amount < 0 or amount.is_signed():
        raise ValueError(f"{field} must be a finite non-negative decimal number")
    # Tuple conversion avoids ambient Decimal-context rounding.
    scale_digits = 0 if _RUNTIME_SCALE[field] == 1 else 6
    units = _runtime_decimal_units(amount, field, scale_digits)
    if units > _RUNTIME_MAX_UNITS:
        raise ValueError(f"{field} exceeds the supported exact range")
    return units


def _runtime_values_to_units(values: dict[str, Any]) -> dict[str, int]:
    return {field: _runtime_units(values[field], field) for field in _RUNTIME_FIELDS}


def _runtime_wire_values(values: dict[str, int] | None) -> dict[str, Any] | None:
    if values is None:
        return None
    output: dict[str, Any] = {}
    for field in _RUNTIME_FIELDS:
        units = values[field]
        scale = _RUNTIME_SCALE[field]
        if scale == 1 or units % scale == 0:
            output[field] = units // scale
        else:
            output[field] = format(Decimal(units) / Decimal(scale), "f")
    return output


def _runtime_migrate_receipt(receipt_json: str | None) -> str | None:
    if receipt_json is None:
        return None
    receipt = json.loads(receipt_json)
    if isinstance(receipt.get("usage"), dict):
        receipt["usage"] = _runtime_wire_values(
            _runtime_values_to_units(receipt["usage"])
        )
    if isinstance(receipt.get("limits"), dict):
        receipt["limits"] = _runtime_wire_values(
            _runtime_values_to_units(receipt["limits"])
        )
    action = receipt.get("action")
    if isinstance(action, dict) and isinstance(action.get("usage"), dict):
        action["usage"] = _runtime_wire_values(
            _runtime_values_to_units(action["usage"])
        )
    return json.dumps(receipt, sort_keys=True)


def _runtime_connection(path: Path, *, root: Path | None = None) -> sqlite3.Connection:
    if root is not None:
        _runtime_assert_safe_database_path(path, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    if root is not None:
        _runtime_assert_safe_database_path(path, root)
    connection = sqlite3.connect(path, timeout=5, isolation_level=None)
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS session ("
        "id INTEGER PRIMARY KEY CHECK (id = 1), loop_id TEXT NOT NULL, "
        "manifest_sha256 TEXT NOT NULL, manifest_path TEXT NOT NULL, "
        "limits_json TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, "
        "accounting_version INTEGER NOT NULL DEFAULT 2)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS action ("
        "action_digest TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, "
        "estimate_json TEXT NOT NULL, admission_json TEXT, actual_json TEXT, settlement_sha256 TEXT, "
        "settlement_json TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, "
        "settled_at TEXT, accounting_version INTEGER NOT NULL DEFAULT 2)"
    )
    session_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(session)").fetchall()
    }
    if "accounting_version" not in session_columns:
        connection.execute(
            "ALTER TABLE session ADD COLUMN accounting_version INTEGER NOT NULL DEFAULT 1"
        )
    action_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(action)").fetchall()
    }
    if "admission_json" not in action_columns:
        connection.execute("ALTER TABLE action ADD COLUMN admission_json TEXT")
    if "accounting_version" not in action_columns:
        connection.execute(
            "ALTER TABLE action ADD COLUMN accounting_version INTEGER NOT NULL DEFAULT 1"
        )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS one_pending_action "
        "ON action(status) WHERE status = 'ADMITTED'"
    )
    return connection


def _runtime_assert_safe_database_path(path: Path, root: Path) -> None:
    """Recheck workspace containment immediately before opening SQLite."""
    path = Path(path)
    workspace_root = Path(root).resolve()
    loop_id = path.parent.name
    run_digest = path.stem
    expected = _runtime_database_path(workspace_root, loop_id, run_digest)
    if expected != path.resolve():
        raise ValueError("runtime ledger path changed after workspace validation")
    components = (
        workspace_root / ".factory",
        workspace_root / ".factory" / "loop-runs",
        workspace_root / ".factory" / "loop-runs" / loop_id,
    )
    for component in components:
        is_junction = getattr(component, "is_junction", lambda: False)()
        if component.is_symlink() or is_junction:
            raise ValueError(
                "runtime ledger directory uses a link in the configured root"
            )
    database_is_junction = getattr(path, "is_junction", lambda: False)()
    if path.is_symlink() or database_is_junction:
        raise ValueError("runtime ledger database file uses a link")


def _runtime_payload(passport_path: Path) -> tuple[dict[str, Any], dict[str, int]]:
    passport_path = Path(passport_path)
    verification = verify_loop_passport(passport_path)
    if not verification["valid"]:
        raise ValueError(
            "Loop Passport is invalid: " + "; ".join(verification["errors"])
        )
    passport = json.loads(
        passport_path.read_text(encoding="utf-8"), parse_float=Decimal
    )
    manifest_path = Path(str(passport.get("manifest_path", "")))
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != passport.get("manifest_sha256"):
        raise ValueError("loop manifest changed after passport verification")
    manifest = json.loads(manifest_bytes.decode("utf-8-sig"), parse_float=Decimal)
    if not isinstance(manifest, dict):
        raise ValueError("verified loop manifest must be a JSON object")
    budgets = manifest.get("budgets")
    if not isinstance(budgets, dict):
        raise ValueError("verified loop manifest budgets are missing")
    if passport.get("loop_id") != manifest.get("id"):
        raise ValueError("Loop Passport loop_id does not match its verified manifest")
    if passport.get("budgets") != budgets:
        raise ValueError("Loop Passport budgets do not match its verified manifest")
    passport["loop_id"] = manifest["id"]
    passport["budgets"] = budgets
    limits = {
        "iterations": budgets.get("max_iterations"),
        "wall_seconds": budgets.get("max_wall_seconds"),
        "tokens": budgets.get("max_tokens"),
        "cost_usd": budgets.get("max_cost_usd"),
    }
    return passport, _runtime_values_to_units(limits)


def _runtime_measurements(value: object, field: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a JSON object")
    missing = [name for name in _RUNTIME_FIELDS if name not in value]
    if missing:
        raise ValueError(f"{field} is missing measurements: {', '.join(missing)}")
    measured = _runtime_values_to_units(value)
    if measured["iterations"] != 1:
        raise ValueError(f"{field}.iterations must equal 1 for one action")
    return measured


def _runtime_session(connection: sqlite3.Connection) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT loop_id, manifest_sha256, manifest_path, limits_json, status, accounting_version "
        "FROM session WHERE id = 1"
    ).fetchone()
    if row is None:
        return None
    limits = json.loads(row[3])
    if row[5] == 1:
        limits = _runtime_values_to_units(limits)
        connection.execute(
            "UPDATE session SET limits_json = ?, accounting_version = 2 WHERE id = 1",
            (json.dumps(limits, sort_keys=True),),
        )
    return {
        "loop_id": row[0],
        "manifest_sha256": row[1],
        "manifest_path": row[2],
        "limits": limits,
        "status": row[4],
    }


def _runtime_usage(connection: sqlite3.Connection) -> dict[str, int]:
    totals = dict.fromkeys(_RUNTIME_FIELDS, 0)
    rows = connection.execute(
        "SELECT action_digest, request_sha256, estimate_json, admission_json, actual_json, "
        "settlement_sha256, settlement_json, status, accounting_version "
        "FROM action ORDER BY created_at, action_digest"
    ).fetchall()
    for (
        digest,
        request_sha,
        estimate_json,
        admission_json,
        actual_json,
        settlement_sha,
        settlement_json,
        status,
        version,
    ) in rows:
        if version == 1:
            estimate = _runtime_values_to_units(json.loads(estimate_json))
            actual = (
                _runtime_values_to_units(json.loads(actual_json))
                if actual_json
                else None
            )
            request_sha = hashlib.sha256(_canonical(estimate)).hexdigest()
            settlement_sha = (
                hashlib.sha256(_canonical(actual)).hexdigest()
                if actual is not None
                else None
            )
            admission_json = _runtime_migrate_receipt(admission_json)
            settlement_json = _runtime_migrate_receipt(settlement_json)
            estimate_json = json.dumps(estimate, sort_keys=True)
            actual_json = (
                json.dumps(actual, sort_keys=True) if actual is not None else None
            )
            connection.execute(
                "UPDATE action SET request_sha256 = ?, estimate_json = ?, admission_json = ?, "
                "actual_json = ?, settlement_sha256 = ?, settlement_json = ?, accounting_version = 2 "
                "WHERE action_digest = ?",
                (
                    request_sha,
                    estimate_json,
                    admission_json,
                    actual_json,
                    settlement_sha,
                    settlement_json,
                    digest,
                ),
            )
        values = (
            json.loads(actual_json)
            if status == "SETTLED"
            else json.loads(estimate_json)
        )
        for field in _RUNTIME_FIELDS:
            totals[field] += int(values[field])
    return totals


def _runtime_next_action(status: str) -> str:
    actions = {
        "ACTIVE": "Reserve the next action before starting it.",
        "ADMITTED": "Run only the reserved action, then settle it with all four measured values.",
        "SETTLED": "Review the receipt, then reserve the next action if headroom remains.",
        "BUDGET_EXCEEDED": "Stop this run; retain the measured overrun and do not raise the passport budget.",
        "INCOMPLETE": "Restore a valid passport or complete missing evidence; no new operation is authorized.",
        "ACTION_IN_PROGRESS": "Settle the unresolved reservation; its estimate remains charged across restart.",
        "ACTION_CONFLICT": "Use a fresh 128-bit action or run token for changed input.",
    }
    return actions.get(
        status, "Inspect the runtime receipt and preserve the fail-closed state."
    )


def _runtime_exceeded(
    usage: dict[str, int], limits: dict[str, int]
) -> dict[str, dict[str, Any]]:
    return {
        field: {
            "actual": _runtime_wire_values(usage)[field],
            "limit": _runtime_wire_values(limits)[field],
        }
        for field in _RUNTIME_FIELDS
        if usage[field] > limits[field]
    }


def _runtime_result(
    connection: sqlite3.Connection,
    path: Path,
    status: str,
    *,
    action: dict[str, Any] | None = None,
    error: str | None = None,
    markers: list[str] | None = None,
) -> dict[str, Any]:
    session = _runtime_session(connection)
    payload = {
        "schema": "factory.loop.runtime.v1",
        "status": status,
        "markers": [
            "RUNTIME_ADAPTER_SCOPE_NOTICE",
            "RUNTIME_ENROLLMENT_SCOPE_NOTICE",
            "RUNTIME_PROVIDER_BILLING_SCOPE_NOTICE",
            "RUNTIME_LEDGER_SECRET_FREE",
            "RUNTIME_IDENTIFIERS_OPAQUE",
            "RUNTIME_USAGE_ACCOUNTING_EXACT",
            "RUNTIME_PASSPORT_CLAIMS_BOUND",
            "RUNTIME_LEDGER_PATH_CONFINED",
            *(markers or []),
        ],
        "loop_id": session["loop_id"] if session else None,
        "manifest_sha256": session["manifest_sha256"] if session else None,
        "usage": _runtime_wire_values(_runtime_usage(connection)),
        "limits": _runtime_wire_values(session["limits"]) if session else None,
        "path": str(path.resolve()),
        "scope_limits": list(_RUNTIME_SCOPE_LIMITS),
        "next_action": _runtime_next_action(status),
    }
    if action:
        payload["action"] = action
    if error:
        payload["error"] = error
    return payload


def _runtime_guard(
    connection: sqlite3.Connection,
    passport: dict[str, Any],
    limits: dict[str, int],
) -> tuple[dict[str, Any] | None, str | None]:
    session = _runtime_session(connection)
    if session is None:
        return None, "INCOMPLETE"
    if session["manifest_sha256"] != passport.get("manifest_sha256"):
        connection.execute("UPDATE session SET status = 'INCOMPLETE' WHERE id = 1")
        return session, "INCOMPLETE"
    if session["limits"] != limits:
        connection.execute("UPDATE session SET status = 'INCOMPLETE' WHERE id = 1")
        return session, "INCOMPLETE"
    if session["status"] != "ACTIVE":
        return session, session["status"]
    return session, None


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


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
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        _error(errors, path, "must be a non-negative number")
        return None
    return float(value)


def _scan_for_secrets(value: object, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if key_text in _SECRET_KEYS or key_text.endswith(
                ("_token", "_secret", "_password", "_key")
            ):
                _error(
                    errors,
                    child_path,
                    "secret-like fields are forbidden; reference a managed connector by name",
                )
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
    required = {
        "cron": "schedule",
        "hook": "event",
        "goal": "success_condition",
        "heartbeat": "interval_seconds",
    }
    field = required.get(kind)
    if field == "interval_seconds":
        value = _nonnegative_number(trigger.get(field), f"trigger.{field}", errors)
        if value is not None and value < 1:
            _error(errors, f"trigger.{field}", "must be at least 1")
    elif field:
        _nonempty_string(trigger.get(field), f"trigger.{field}", errors)


def _validate_workspace(
    workspace: object, autonomy: str | None, errors: list[str]
) -> None:
    if not isinstance(workspace, dict):
        _error(errors, "workspace", "must be an object")
        return
    _validate_workspace_mode(workspace, autonomy, errors)
    _validate_workspace_paths(workspace, errors)
    _validate_workspace_network(workspace, errors)


def _validate_workspace_mode(
    workspace: dict[str, Any], autonomy: str | None, errors: list[str]
) -> None:
    mode = _nonempty_string(workspace.get("mode"), "workspace.mode", errors)
    if mode not in {"isolated", "ephemeral"}:
        _error(errors, "workspace.mode", "must be isolated or ephemeral")
    if autonomy == "autonomous" and mode != "ephemeral":
        _error(
            errors,
            "workspace.mode",
            "autonomous loops require an ephemeral workspace contract",
        )


def _validate_workspace_paths(workspace: dict[str, Any], errors: list[str]) -> None:
    paths = _string_list(
        workspace.get("allowed_paths"), "workspace.allowed_paths", errors
    )
    if not paths:
        _error(
            errors, "workspace.allowed_paths", "must declare at least one relative path"
        )
    for item in paths:
        candidate = Path(item)
        if (
            candidate.is_absolute()
            or re.match(r"^[A-Za-z]:[\\/]", item)
            or ".." in candidate.parts
        ):
            _error(
                errors,
                "workspace.allowed_paths",
                "must not contain absolute or parent-traversal paths",
            )


def _validate_workspace_network(workspace: dict[str, Any], errors: list[str]) -> None:
    network = _nonempty_string(workspace.get("network"), "workspace.network", errors)
    if network not in {"deny", "allowlist"}:
        _error(errors, "workspace.network", "must be deny or allowlist")
    if network == "allowlist" and not _string_list(
        workspace.get("network_hosts"), "workspace.network_hosts", errors
    ):
        _error(
            errors,
            "workspace.network_hosts",
            "allowlist mode requires at least one host",
        )


def _validate_capabilities(
    capabilities: object, approvals: object, errors: list[str]
) -> None:
    if not isinstance(capabilities, dict):
        _error(errors, "capabilities", "must be an object")
        return
    _string_list(capabilities.get("skills"), "capabilities.skills", errors)
    _string_list(capabilities.get("connectors"), "capabilities.connectors", errors)
    actions = _string_list(capabilities.get("actions"), "capabilities.actions", errors)
    if not isinstance(approvals, dict):
        return
    required_for = set(
        _string_list(approvals.get("required_for"), "approvals.required_for", errors)
    )
    missing = sorted(set(actions) & DESTRUCTIVE_ACTIONS - required_for)
    if missing:
        _error(
            errors,
            "approvals.required_for",
            f"must cover declared destructive actions: {', '.join(missing)}",
        )


def _validate_budgets(budgets: object, errors: list[str]) -> None:
    if not isinstance(budgets, dict):
        _error(errors, "budgets", "must be an object")
        return
    for field in ("max_iterations", "max_wall_seconds", "max_tokens", "max_cost_usd"):
        value = _nonnegative_number(budgets.get(field), f"budgets.{field}", errors)
        if (
            field in {"max_iterations", "max_wall_seconds"}
            and value is not None
            and value < 1
        ):
            _error(errors, f"budgets.{field}", "must be at least 1")


def _validate_validators(
    validators: object, autonomy: str | None, errors: list[str]
) -> None:
    if not isinstance(validators, dict):
        _error(errors, "validators", "must be an object")
        return
    values = {
        field: _string_list(validators.get(field), f"validators.{field}", errors)
        for field in ("pre", "post", "invariant")
    }
    required = {
        "human_controlled": (),
        "supervised": ("pre", "post"),
        "autonomous": ("pre", "post", "invariant"),
    }
    for field in required.get(autonomy, ()):
        if not values[field]:
            _error(
                errors,
                f"validators.{field}",
                f"{autonomy} loops require at least one {field} validator",
            )


def _validate_approvals(approvals: object, errors: list[str]) -> None:
    if not isinstance(approvals, dict):
        _error(errors, "approvals", "must be an object")
        return
    required_for = _string_list(
        approvals.get("required_for"), "approvals.required_for", errors
    )
    missing = sorted(DESTRUCTIVE_ACTIONS - set(required_for))
    if missing:
        _error(
            errors,
            "approvals.required_for",
            f"must include baseline destructive actions: {', '.join(missing)}",
        )
    if approvals.get("distinct_approver") is not True:
        _error(errors, "approvals.distinct_approver", "must be true")
    expiry = _nonnegative_number(
        approvals.get("expires_minutes"), "approvals.expires_minutes", errors
    )
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
        _error(
            errors,
            "states.transitions",
            f"must declare every state: {', '.join(missing)}",
        )
    for source, targets in transitions.items():
        if source not in STATES:
            _error(errors, f"states.transitions.{source}", "is not a known state")
        target_list = _string_list(targets, f"states.transitions.{source}", errors)
        unknown = sorted(set(target_list) - STATES)
        if unknown:
            _error(
                errors,
                f"states.transitions.{source}",
                f"has unknown target states: {', '.join(unknown)}",
            )
        if (
            source in {"completed", "failed", "budget_exceeded", "cancelled"}
            and target_list
        ):
            _error(
                errors,
                f"states.transitions.{source}",
                "terminal states must not transition further",
            )


def default_manifest(loop_id: str, owner: str) -> dict[str, Any]:
    """Return a bounded, human-controlled starter manifest for a reusable agent loop."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", loop_id):
        raise ValueError(
            "loop id must use lowercase letters, digits, and hyphens, starting with a letter"
        )
    if not owner.strip():
        raise ValueError("owner is required")
    return {
        "schema": LOOP_MANIFEST_SCHEMA,
        "id": loop_id,
        "owner": owner.strip(),
        "autonomy": "human_controlled",
        "trigger": {"type": "manual"},
        "workspace": {"mode": "isolated", "allowed_paths": ["."], "network": "deny"},
        "capabilities": {
            "skills": [],
            "connectors": [],
            "actions": ["read_repository", "write_workspace"],
        },
        "budgets": {
            "max_iterations": 1,
            "max_wall_seconds": 900,
            "max_tokens": 0,
            "max_cost_usd": 0,
        },
        "validators": {"pre": [], "post": [], "invariant": []},
        "approvals": {
            "required_for": sorted(DESTRUCTIVE_ACTIONS),
            "distinct_approver": True,
            "expires_minutes": 60,
        },
        "states": {"initial": "planned", "transitions": DEFAULT_TRANSITIONS},
        "scope": "Contract only. Runtime credential injection, sandboxing, and provider billing must be enforced by the selected harness.",
    }


def init_loop(
    root: Path, loop_id: str, owner: str, *, force: bool = False
) -> dict[str, Any]:
    """Initialize a loop manifest, refusing to replace governance by default."""
    manifest = default_manifest(loop_id, owner)
    path = Path(root) / ".factory" / "loops" / f"{loop_id}.loop.json"
    if path.exists() and not force:
        raise ValueError(
            f"loop manifest already exists: {path}; use --force to replace it"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "schema": LOOP_MANIFEST_SCHEMA,
        "path": str(path.resolve()),
        "manifest": manifest,
    }


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
        _error(
            errors,
            "id",
            "must use lowercase letters, digits, and hyphens, starting with a letter",
        )
    _nonempty_string(manifest.get("owner"), "owner", errors)
    autonomy = _nonempty_string(manifest.get("autonomy"), "autonomy", errors)
    if autonomy not in AUTONOMY_LEVELS:
        _error(errors, "autonomy", f"must be one of {sorted(AUTONOMY_LEVELS)}")
    _validate_trigger(manifest.get("trigger"), errors)
    _validate_workspace(manifest.get("workspace"), autonomy, errors)
    _validate_approvals(manifest.get("approvals"), errors)
    _validate_capabilities(
        manifest.get("capabilities"), manifest.get("approvals"), errors
    )
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
    return (
        "\n".join(
            [
                "flowchart LR",
                f'    M["Loop manifest: {loop_id}"] --> V["Static contract validation"]',
                '    M --> C["Capability and approval grants"]',
                '    M --> B["Hard budget contract"]',
                '    M --> S["Declared state machine"]',
                f'    V --> P["Loop Passport: {status}"]',
                "    C --> P",
                "    B --> P",
                "    S --> P",
            ]
        )
        + "\n"
    )


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
    json_path.write_text(
        json.dumps(passport, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    mermaid_path.write_text(_loop_mermaid(passport), encoding="utf-8")
    return {
        **passport,
        "paths": {
            "json": str(json_path.resolve()),
            "mermaid": str(mermaid_path.resolve()),
        },
    }


def _read_passport_payload(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "loop passport JSON is malformed"
    if not isinstance(payload, dict):
        return None, "loop passport must be a JSON object"
    return payload, None


def _passport_manifest_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    manifest_path = Path(str(payload.get("manifest_path", "")))
    if not manifest_path.exists():
        errors.append(f"missing loop manifest: {manifest_path}")
    elif _sha256_path(manifest_path) != payload.get("manifest_sha256"):
        errors.append("loop manifest hash mismatch")
    else:
        validation = validate_manifest(manifest_path)
        if not validation["valid"]:
            errors.append("loop manifest no longer satisfies the contract")
        manifest = load_manifest(manifest_path)
        if payload.get("loop_id") != manifest.get("id"):
            errors.append("loop passport loop_id does not match its manifest")
        if payload.get("budgets") != manifest.get("budgets"):
            errors.append("loop passport budgets do not match its manifest")
    return errors


def verify_loop_passport(path: Path) -> dict[str, Any]:
    """Verify a loop passport schema and manifest hash without trusting its claims."""
    path = Path(path)
    payload, parse_error = _read_passport_payload(path)
    if payload is None:
        return {
            "valid": False,
            "errors": [parse_error],
            "loop_id": None,
            "passport_sha256": None,
        }
    errors: list[str] = []
    if payload.get("schema") != LOOP_PASSPORT_SCHEMA:
        errors.append("unsupported loop passport schema")
    core = {
        key: value
        for key, value in payload.items()
        if key not in {"passport_sha256", "paths"}
    }
    if hashlib.sha256(_canonical(core)).hexdigest() != payload.get("passport_sha256"):
        errors.append("loop passport hash mismatch")
    errors.extend(_passport_manifest_errors(payload))
    if payload.get("verdict") != "VERIFIED":
        errors.append("loop passport verdict is blocked")
    return {
        "valid": not errors,
        "errors": errors,
        "loop_id": payload.get("loop_id"),
        "passport_sha256": payload.get("passport_sha256"),
    }


def _usage_measurements(usage: dict[str, Any]) -> tuple[dict[str, float], list[str]]:
    actual: dict[str, float] = {}
    missing = []
    errors: list[str] = []
    for field in ("iterations", "wall_seconds", "tokens", "cost_usd"):
        if field not in usage:
            missing.append(field)
            continue
        value = _nonnegative_number(usage[field], f"usage.{field}", errors)
        if value is not None:
            actual[field] = value
    if errors:
        raise ValueError("; ".join(errors))
    return actual, missing


def evaluate_budget(
    root: Path, manifest_path: Path, usage_path: Path
) -> dict[str, Any]:
    """Compare measured loop usage with declared limits and report every overrun."""
    validation = validate_manifest(manifest_path)
    manifest = load_manifest(manifest_path)
    usage = json.loads(Path(usage_path).read_text(encoding="utf-8-sig"))
    if not isinstance(usage, dict):
        raise ValueError("usage must be a JSON object")
    actual, missing_measurements = _usage_measurements(usage)
    budgets = (
        manifest.get("budgets") if isinstance(manifest.get("budgets"), dict) else {}
    )
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
    elif missing_measurements:
        verdict = "INCOMPLETE"
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
        "missing_measurements": missing_measurements,
        "validation_errors": validation["errors"],
        "verdict": verdict,
        "ok": verdict == "WITHIN_BUDGET",
        "scope_limits": [
            "Usage values are supplied by the caller or runtime adapter.",
            "Missing usage measurements result in INCOMPLETE rather than a budget pass.",
            "This receipt compares supplied usage with declared bounds; it does not independently query a provider billing system.",
        ],
    }
    out_dir = Path(root) / ".factory" / "loop-receipts"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = (
        out_dir / f"{manifest.get('id', 'loop')}-budget-{receipt['run_id'][:12]}.json"
    )
    path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {**receipt, "path": str(path.resolve())}


def _runtime_failure(
    status: str, path: Path | None, error: str, *, marker: str | None = None
) -> dict[str, Any]:
    markers = [
        "RUNTIME_ADAPTER_SCOPE_NOTICE",
        "RUNTIME_ENROLLMENT_SCOPE_NOTICE",
        "RUNTIME_PROVIDER_BILLING_SCOPE_NOTICE",
    ]
    if status == "INCOMPLETE":
        markers.append("RUNTIME_OPERATION_FAIL_CLOSED")
    elif status == "BUDGET_EXCEEDED":
        markers.append("RUNTIME_OVERRUN_RECORDED")
    elif status == "ACTION_IN_PROGRESS":
        markers.append("RUNTIME_PENDING_PRESERVED")
    if marker:
        markers.append(marker)
    result = {
        "schema": "factory.loop.runtime.v1",
        "status": status,
        "markers": markers,
        "scope_limits": list(_RUNTIME_SCOPE_LIMITS),
        "next_action": _runtime_next_action(status),
        "error": error,
    }
    if path is not None:
        result["path"] = str(path.resolve())
    return result


def _runtime_input_failure(error: Exception) -> dict[str, Any]:
    message = str(error)
    lowered = message.casefold()
    marker = None
    if "runtime ledger" in lowered:
        marker = "RUNTIME_LEDGER_PATH_BLOCKED"
    elif "passport" in lowered or "manifest" in lowered:
        marker = "RUNTIME_SESSION_INCOMPLETE"
    return _runtime_failure("INCOMPLETE", None, message, marker=marker)


def _runtime_connection_failure(error: Exception, path: Path) -> dict[str, Any]:
    message = f"runtime ledger unavailable: {type(error).__name__}"
    marker = (
        "RUNTIME_LEDGER_PATH_BLOCKED"
        if isinstance(error, ValueError) and "runtime ledger" in str(error)
        else None
    )
    return _runtime_failure("INCOMPLETE", path, message, marker=marker)


def start_budget_session(
    root: Path, passport_path: Path, run_id: str
) -> dict[str, Any]:
    """Create or resume a manifest-bound SQLite budget session."""
    try:
        run_digest = _runtime_id_digest(run_id, "run_id")
        passport, limits = _runtime_payload(passport_path)
        path = _runtime_database_path(root, passport["loop_id"], run_digest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return _runtime_input_failure(error)
    connection = None
    try:
        connection = _runtime_connection(path, root=Path(root))
        connection.execute("BEGIN IMMEDIATE")
        current = _runtime_session(connection)
        if current and current["manifest_sha256"] != passport["manifest_sha256"]:
            connection.commit()
            return _runtime_failure(
                "ACTION_CONFLICT", path, "run token is bound to a different passport"
            )
        is_replay = current is not None
        if current is None:
            connection.execute(
                "INSERT INTO session (id, loop_id, manifest_sha256, manifest_path, limits_json, status, created_at, accounting_version) "
                "VALUES (1, ?, ?, ?, ?, 'ACTIVE', ?, 2)",
                (
                    passport["loop_id"],
                    passport["manifest_sha256"],
                    passport["manifest_path"],
                    json.dumps(limits, sort_keys=True),
                    _now(),
                ),
            )
        marker = (
            "RUNTIME_SESSION_REPLAY_SAFE"
            if is_replay
            else "RUNTIME_SESSION_PASSPORT_BOUND"
        )
        result = _runtime_result(
            connection, path, _runtime_session(connection)["status"], markers=[marker]
        )
        connection.commit()
        return result
    except (OSError, sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        return _runtime_connection_failure(error, path)
    finally:
        if connection is not None:
            connection.close()


def _runtime_action_result(
    connection: sqlite3.Connection,
    path: Path,
    status: str,
    action_status: str,
    values: dict[str, int] | None = None,
) -> dict[str, Any]:
    action = {"status": action_status}
    if values is not None:
        action["usage"] = _runtime_wire_values(values)
    markers = ["RUNTIME_RESERVATIONS_SERIALIZED"]
    if action_status == "ADMITTED":
        markers.append("RUNTIME_ACTION_RESERVED")
    elif action_status == "SETTLED":
        markers.append("RUNTIME_USAGE_SETTLED")
    if status == "BUDGET_EXCEEDED":
        markers.append("RUNTIME_OVERRUN_RECORDED")
    return _runtime_result(connection, path, status, action=action, markers=markers)


def _runtime_admission_replay(
    connection: sqlite3.Connection,
    path: Path,
    action_digest: str,
    request_sha: str,
    blocked: str | None,
) -> dict[str, Any] | None:
    existing = connection.execute(
        "SELECT request_sha256, admission_json, status, settlement_json "
        "FROM action WHERE action_digest = ?",
        (action_digest,),
    ).fetchone()
    if existing is None:
        return None
    if existing[0] != request_sha:
        return _runtime_failure(
            "ACTION_CONFLICT", path, "action token is bound to different input"
        )
    if blocked:
        return _runtime_failure(
            blocked,
            path,
            "session does not authorize replayed admission",
            marker="RUNTIME_ACTION_REPLAY_BLOCKED",
        )
    if existing[2] == "SETTLED":
        result = json.loads(existing[3])
        result["markers"].append("RUNTIME_ACTION_IDEMPOTENT")
        result["markers"].append("RUNTIME_ACTION_ALREADY_SETTLED")
        return result
    result = json.loads(existing[1])
    result["markers"].append("RUNTIME_ACTION_IDEMPOTENT")
    return result


def _runtime_reserve_action(
    connection: sqlite3.Connection,
    path: Path,
    action_digest: str,
    request_sha: str,
    reserved: dict[str, int],
    limits: dict[str, int],
    blocked: str | None,
) -> dict[str, Any]:
    if blocked:
        return _runtime_failure(blocked, path, "session does not admit new actions")
    pending = connection.execute(
        "SELECT 1 FROM action WHERE status = 'ADMITTED' LIMIT 1"
    ).fetchone()
    if pending:
        return _runtime_failure(
            "ACTION_IN_PROGRESS",
            path,
            "settle the unresolved action before admitting another",
        )
    usage = _runtime_usage(connection)
    projected = {key: usage[key] + reserved[key] for key in _RUNTIME_FIELDS}
    if _runtime_exceeded(projected, limits):
        connection.execute("UPDATE session SET status = 'BUDGET_EXCEEDED' WHERE id = 1")
        return _runtime_result(connection, path, "BUDGET_EXCEEDED")
    connection.execute(
        "INSERT INTO action (action_digest, request_sha256, estimate_json, status, created_at, accounting_version) "
        "VALUES (?, ?, ?, 'ADMITTED', ?, 2)",
        (action_digest, request_sha, json.dumps(reserved, sort_keys=True), _now()),
    )
    result = _runtime_action_result(connection, path, "ADMITTED", "ADMITTED", reserved)
    connection.execute(
        "UPDATE action SET admission_json = ? WHERE action_digest = ?",
        (json.dumps(result, sort_keys=True), action_digest),
    )
    return result


def _runtime_settlement_replay(
    connection: sqlite3.Connection,
    path: Path,
    action_digest: str,
    settlement_sha: str,
) -> dict[str, Any] | None:
    existing = connection.execute(
        "SELECT settlement_sha256, settlement_json, status "
        "FROM action WHERE action_digest = ?",
        (action_digest,),
    ).fetchone()
    if existing is None or existing[2] != "SETTLED":
        return None
    if existing[0] == settlement_sha:
        result = json.loads(existing[1])
        result["markers"].append("RUNTIME_SETTLEMENT_IDEMPOTENT")
        return result
    return _runtime_failure(
        "ACTION_CONFLICT", path, "settlement token is bound to different measurements"
    )


def _runtime_settle_existing(
    connection: sqlite3.Connection,
    path: Path,
    action_digest: str,
    measured: dict[str, int],
    limits: dict[str, int],
) -> dict[str, Any]:
    connection.execute(
        "UPDATE action SET actual_json = ?, settlement_sha256 = ?, status = 'SETTLED', settled_at = ? "
        "WHERE action_digest = ?",
        (
            json.dumps(measured, sort_keys=True),
            hashlib.sha256(_canonical(measured)).hexdigest(),
            _now(),
            action_digest,
        ),
    )
    usage = _runtime_usage(connection)
    status = "BUDGET_EXCEEDED" if _runtime_exceeded(usage, limits) else "SETTLED"
    if status == "BUDGET_EXCEEDED":
        connection.execute("UPDATE session SET status = ? WHERE id = 1", (status,))
    result = _runtime_action_result(connection, path, status, "SETTLED", measured)
    connection.execute(
        "UPDATE action SET settlement_json = ? WHERE action_digest = ?",
        (json.dumps(result, sort_keys=True), action_digest),
    )
    return result


def _runtime_has_admitted_action(
    connection: sqlite3.Connection, action_digest: str
) -> bool:
    row = connection.execute(
        "SELECT status FROM action WHERE action_digest = ?", (action_digest,)
    ).fetchone()
    return row is not None and row[0] == "ADMITTED"


def admit_budget_action(
    root: Path,
    passport_path: Path,
    run_id: str,
    action_id: str,
    estimate: dict[str, Any],
) -> dict[str, Any]:
    """Atomically reserve one action before its external operation begins."""
    try:
        run_digest = _runtime_id_digest(run_id, "run_id")
        action_digest = _runtime_id_digest(action_id, "action_id")
        passport, limits = _runtime_payload(passport_path)
        reserved = _runtime_measurements(estimate, "estimate")
        path = _runtime_database_path(root, passport["loop_id"], run_digest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return _runtime_input_failure(error)
    request_sha = hashlib.sha256(_canonical(reserved)).hexdigest()
    connection = None
    try:
        connection = _runtime_connection(path, root=Path(root))
        connection.execute("BEGIN IMMEDIATE")
        _, blocked = _runtime_guard(connection, passport, limits)
        replay = _runtime_admission_replay(
            connection, path, action_digest, request_sha, blocked
        )
        if replay is not None:
            connection.commit()
            return replay
        if blocked == "INCOMPLETE":
            result = _runtime_failure(
                "INCOMPLETE",
                path,
                "session or current passport is incomplete",
                marker="RUNTIME_SESSION_INCOMPLETE",
            )
        else:
            result = _runtime_reserve_action(
                connection, path, action_digest, request_sha, reserved, limits, blocked
            )
        connection.commit()
        return result
    except (OSError, sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        return _runtime_connection_failure(error, path)
    finally:
        if connection is not None:
            connection.close()


def settle_budget_action(
    root: Path,
    passport_path: Path,
    run_id: str,
    action_id: str,
    actual: dict[str, Any],
) -> dict[str, Any]:
    """Replace one durable reservation with measured usage exactly once."""
    try:
        run_digest = _runtime_id_digest(run_id, "run_id")
        action_digest = _runtime_id_digest(action_id, "action_id")
        passport, limits = _runtime_payload(passport_path)
        measured = _runtime_measurements(actual, "actual")
        path = _runtime_database_path(root, passport["loop_id"], run_digest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return _runtime_input_failure(error)
    settlement_sha = hashlib.sha256(_canonical(measured)).hexdigest()
    connection = None
    try:
        connection = _runtime_connection(path, root=Path(root))
        connection.execute("BEGIN IMMEDIATE")
        _, blocked = _runtime_guard(connection, passport, limits)
        if blocked == "INCOMPLETE":
            result = _runtime_failure(
                "INCOMPLETE",
                path,
                "session or current passport is incomplete",
                marker="RUNTIME_SESSION_INCOMPLETE",
            )
            connection.commit()
            return result
        replay = _runtime_settlement_replay(
            connection, path, action_digest, settlement_sha
        )
        if replay is not None:
            connection.commit()
            return replay
        if blocked:
            connection.commit()
            return _runtime_failure(blocked, path, "session does not accept settlement")
        if not _runtime_has_admitted_action(connection, action_digest):
            connection.commit()
            return _runtime_failure(
                "INCOMPLETE", path, "no admitted action is available to settle"
            )
        result = _runtime_settle_existing(
            connection, path, action_digest, measured, limits
        )
        connection.commit()
        return result
    except (OSError, sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        return _runtime_connection_failure(error, path)
    finally:
        if connection is not None:
            connection.close()


def budget_session_status(
    root: Path, passport_path: Path, run_id: str
) -> dict[str, Any]:
    """Read current projected usage without exposing caller-supplied IDs."""
    connection = None
    path = None
    try:
        run_digest = _runtime_id_digest(run_id, "run_id")
        passport, limits = _runtime_payload(passport_path)
        path = _runtime_database_path(root, passport["loop_id"], run_digest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return _runtime_input_failure(error)
    try:
        connection = _runtime_connection(path, root=Path(root))
        connection.execute("BEGIN IMMEDIATE")
        session, blocked = _runtime_guard(connection, passport, limits)
        if session is None or blocked == "INCOMPLETE":
            connection.commit()
            return _runtime_failure(
                "INCOMPLETE",
                path,
                "session or current passport is incomplete",
                marker="RUNTIME_SESSION_INCOMPLETE",
            )
        status = blocked or session["status"]
        result = _runtime_result(connection, path, status)
        pending = connection.execute(
            "SELECT 1 FROM action WHERE status = 'ADMITTED' LIMIT 1"
        ).fetchone()
        result["pending_action"] = pending is not None
        connection.commit()
        return result
    except (OSError, sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        return _runtime_connection_failure(error, path)
    finally:
        if connection is not None:
            connection.close()
