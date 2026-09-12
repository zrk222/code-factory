"""Fail-closed, source-bound parameters for a Code Factory intake.

An Intake Grill records the human's intent and external-effects decision.  This
module records the *operating parameters* that an agent may propose for that
intake, while keeping authority separate from execution.  A parameter envelope
is useful because a worker can otherwise silently change budgets, scope, or
which audit lanes it intends to run.  Every value is bounded, provenance tagged,
and tied to the verified human confirmation.  Agent-proposed values remain
advisory and can never block or release work until a human or trusted source
promotes them.

The module is local and read-only at verification time.  It does not start a
runner, alter a contract, grant credentials, or authorize a release.
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

from .intake_grill import verify_intake_confirmation
from .product_missions import MISSION_MAXIMA


REQUEST_SCHEMA = "factory.intake-parameters-request.v1"
RECEIPT_SCHEMA = "factory.intake-parameters.v1"
VERIFICATION_SCHEMA = "factory.intake-parameters-verification.v1"
STATUS_SCHEMA = "factory.intake-parameters-status.v1"

ORIGINS = frozenset({"human_confirmed", "trusted_source", "observed_production", "agent_proposed"})
AUTHORITATIVE_ORIGINS = frozenset({"human_confirmed", "trusted_source"})
MODES = frozenset({"human_controlled", "supervised", "autonomous"})
RISKS = frozenset({"low", "medium", "high", "critical"})
EXTERNAL_EFFECTS = frozenset({"local_only", "human_controlled"})
REQUIRED_AUDIT_LANES = (
    "stateful_invariant",
    "tenant_isolation",
    "failure_recovery",
    "consumer_compatibility",
    "migration_integrity",
    "performance_regression",
)
PARAMETER_KEYS = ("mode", "risk", "budgets", "scope_paths", "required_lanes", "external_effects")
BUDGET_KEYS = ("max_iterations", "max_wall_seconds", "max_tokens", "max_cost_usd")
REQUEST_KEYS = {"schema", "intake_confirmation", "parameters", "provenance", "approved_by", "expires_at", "rationale"}
RECEIPT_CORE_EXCLUDED = {"parameter_sha256", "sealed_at"}
MAX_SCOPE_PATHS = 64
MAX_SCAN_RECEIPTS = 100
MAX_TEXT = 500
MAX_EXPIRY_DAYS = 30
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SECRET_NAME = re.compile(r"(?:^|[._-])(secret|token|password|passwd|credential|credentials|private[-_]?key|api[-_]?key|pat)(?:$|[._-])", re.I)
_SECRET_VALUE = re.compile(r"(?:ghp_|github_pat_|pypi-|vsce[_-]?pat|sk-[A-Za-z0-9_-]{12,}|-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----)", re.I)
_PROJECT = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")

AUTHORITY = {
    "implementation": "not_authorized",
    "execution": "not_authorized",
    "external_effects": "not_authorized",
    "publication": "not_authorized",
    "deployment": "not_authorized",
}


class IntakeParametersError(ValueError):
    """Stable, machine-readable intake-parameter failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IntakeParametersError("INTAKE_PARAMETERS_CANONICAL", "value is not canonical JSON") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any, field: str, *, minimum: int = 2, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise IntakeParametersError("INTAKE_PARAMETERS_FIELDS", f"{field} must be text")
    cleaned = value.strip()
    if not minimum <= len(cleaned) <= maximum or any(ord(char) < 32 for char in cleaned) or _SECRET_VALUE.search(cleaned):
        raise IntakeParametersError("INTAKE_PARAMETERS_FIELDS", f"{field} must be {minimum}-{maximum} printable non-secret characters")
    return cleaned


def _reject_secrets(value: Any, path: str = "request", depth: int = 0) -> None:
    if depth > 12:
        raise IntakeParametersError("INTAKE_PARAMETERS_DEPTH", "nested values exceed the bounded depth")
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_NAME.search(str(key)):
                raise IntakeParametersError("INTAKE_PARAMETERS_SECRET", f"secret-shaped field at {path}.{key}")
            _reject_secrets(child, f"{path}.{key}", depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]", depth + 1)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise IntakeParametersError("INTAKE_PARAMETERS_SECRET", f"credential-like value at {path}")


def _relative(root: Path, raw: Any, field: str, *, exists: bool = True, allow_absolute: bool = False) -> tuple[Path, str]:
    if isinstance(raw, (Path, os.PathLike)):
        raw = os.fspath(raw)
    value = _text(raw, field, maximum=512).replace("\\", "/")
    candidate_raw = Path(value)
    absolute = candidate_raw.is_absolute() or bool(re.match(r"^[A-Za-z]:/", value))
    if (absolute and not allow_absolute) or (not absolute and any(part in {"", ".", ".."} for part in candidate_raw.parts)):
        raise IntakeParametersError("INTAKE_PARAMETERS_PATH_BOUNDARY", f"{field} must be a safe workspace-relative path")
    workspace = root.resolve()
    candidate = candidate_raw if absolute else workspace.joinpath(candidate_raw)
    ancestor = workspace
    for part in candidate_raw.parts if not absolute else ():
        ancestor = ancestor / part
        if ancestor.is_symlink():
            raise IntakeParametersError("INTAKE_PARAMETERS_PATH_BOUNDARY", f"{field} may not traverse a symlink")
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(workspace)
    except (ValueError, OSError) as exc:
        raise IntakeParametersError("INTAKE_PARAMETERS_PATH_BOUNDARY", f"{field} escapes the workspace") from exc
    if candidate.is_symlink() or resolved.is_symlink():
        raise IntakeParametersError("INTAKE_PARAMETERS_PATH_BOUNDARY", f"{field} may not be a symlink")
    if exists and not resolved.is_file():
        raise IntakeParametersError("INTAKE_PARAMETERS_SOURCE_NOT_FOUND", f"{field} must name a readable file")
    return resolved, resolved.relative_to(workspace).as_posix()


def _read_json(root: Path, raw: Any, field: str, *, allow_absolute: bool = False) -> tuple[Path, str, dict[str, Any]]:
    path, relative = _relative(root, raw, field, allow_absolute=allow_absolute)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeParametersError("INTAKE_PARAMETERS_SOURCE_INVALID", f"{field} must be readable JSON") from exc
    if not isinstance(value, dict):
        raise IntakeParametersError("INTAKE_PARAMETERS_SOURCE_INVALID", f"{field} must contain a JSON object")
    return path, relative, value


def _bounded_number(value: Any, field: str, minimum: int | float, maximum: int | float, *, integer: bool = False) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
        kind = "integer" if integer else "number"
        raise IntakeParametersError("INTAKE_PARAMETERS_BUDGET_INVALID", f"{field} must be a {kind} in {minimum}..{maximum}")
    if integer and not isinstance(value, int):
        raise IntakeParametersError("INTAKE_PARAMETERS_BUDGET_INVALID", f"{field} must be an integer in {minimum}..{maximum}")
    return value


def _parse_expiry(value: Any, *, now: datetime | None = None) -> tuple[str, datetime]:
    expiry = _text(value, "expires_at", minimum=10, maximum=64)
    try:
        parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntakeParametersError("INTAKE_PARAMETERS_EXPIRY_INVALID", "expires_at must be ISO-8601 UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IntakeParametersError("INTAKE_PARAMETERS_EXPIRY_INVALID", "expires_at must include a UTC offset")
    parsed = parsed.astimezone(timezone.utc)
    current = now or _now()
    if parsed <= current:
        raise IntakeParametersError("INTAKE_PARAMETERS_EXPIRED", "expires_at must be in the future")
    if parsed > current + timedelta(days=MAX_EXPIRY_DAYS):
        raise IntakeParametersError("INTAKE_PARAMETERS_EXPIRY_INVALID", f"expires_at may be at most {MAX_EXPIRY_DAYS} days ahead")
    return _iso(parsed), parsed


def _validate_confirmation(root: Path, raw: Any) -> tuple[Path, str, dict[str, Any], dict[str, Any]]:
    path, relative, confirmation = _read_json(root, raw, "intake_confirmation")
    if confirmation.get("schema") != "factory.intake-confirmation.v1":
        raise IntakeParametersError("INTAKE_PARAMETERS_CONFIRMATION_INVALID", "intake_confirmation must be a confirmation receipt")
    check = verify_intake_confirmation(root, path)
    if check.get("valid") is not True or not isinstance(check.get("confirmation"), dict):
        raise IntakeParametersError("INTAKE_PARAMETERS_CONFIRMATION_INVALID", "; ".join(check.get("errors", [])) or "confirmation is not verified")
    return path, relative, confirmation, check["confirmation"]


def _validate_request(root: Path, request: Any) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        raise IntakeParametersError("INTAKE_PARAMETERS_REQUEST_FIELDS", "request has missing or unknown fields")
    _reject_secrets(request)
    if request.get("schema") != REQUEST_SCHEMA:
        raise IntakeParametersError("INTAKE_PARAMETERS_SCHEMA", f"expected {REQUEST_SCHEMA}")
    _, confirmation_relative, _, confirmation = _validate_confirmation(root, request["intake_confirmation"])
    parameters = request.get("parameters")
    if not isinstance(parameters, dict) or set(parameters) != set(PARAMETER_KEYS):
        raise IntakeParametersError("INTAKE_PARAMETERS_FIELDS", "parameters must contain the exact operating fields")
    mode = parameters.get("mode")
    risk = parameters.get("risk")
    if mode not in MODES or risk not in RISKS:
        raise IntakeParametersError("INTAKE_PARAMETERS_FIELDS", "mode or risk is unsupported")
    budgets = parameters.get("budgets")
    if not isinstance(budgets, dict) or set(budgets) != set(BUDGET_KEYS):
        raise IntakeParametersError("INTAKE_PARAMETERS_BUDGET_INVALID", "budgets must contain the four bounded mission values")
    normalized_budgets = {
        "max_iterations": _bounded_number(budgets["max_iterations"], "max_iterations", 1, MISSION_MAXIMA["max_iterations"], integer=True),
        "max_wall_seconds": _bounded_number(budgets["max_wall_seconds"], "max_wall_seconds", 1, MISSION_MAXIMA["max_wall_seconds"], integer=True),
        "max_tokens": _bounded_number(budgets["max_tokens"], "max_tokens", 256, MISSION_MAXIMA["max_tokens"], integer=True),
        "max_cost_usd": _bounded_number(budgets["max_cost_usd"], "max_cost_usd", 0, MISSION_MAXIMA["max_cost_usd"]),
    }
    scope = parameters.get("scope_paths")
    if not isinstance(scope, list) or not 1 <= len(scope) <= MAX_SCOPE_PATHS:
        raise IntakeParametersError("INTAKE_PARAMETERS_SCOPE_INVALID", f"scope_paths must contain 1..{MAX_SCOPE_PATHS} paths")
    normalized_scope: list[str] = []
    for index, raw in enumerate(scope):
        _, relative = _relative(root, raw, f"scope_paths[{index}]", exists=False)
        if relative in normalized_scope:
            raise IntakeParametersError("INTAKE_PARAMETERS_SCOPE_INVALID", f"duplicate scope path: {relative}")
        normalized_scope.append(relative)
    lanes = parameters.get("required_lanes")
    if lanes != list(REQUIRED_AUDIT_LANES) and lanes != sorted(REQUIRED_AUDIT_LANES):
        raise IntakeParametersError("INTAKE_PARAMETERS_LANES_INVALID", "required_lanes must contain the complete canonical six-lane audit set")
    normalized_lanes = list(REQUIRED_AUDIT_LANES)
    external = parameters.get("external_effects")
    if external not in EXTERNAL_EFFECTS:
        raise IntakeParametersError("INTAKE_PARAMETERS_FIELDS", "external_effects must be local_only or human_controlled")
    confirmation_external = confirmation.get("decision", {}).get("external_effects")
    if external != confirmation_external:
        raise IntakeParametersError("INTAKE_PARAMETERS_EXTERNAL_EFFECTS_MISMATCH", "external_effects must match the verified human confirmation")
    provenance = request.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != set(PARAMETER_KEYS):
        raise IntakeParametersError("INTAKE_PARAMETERS_PROVENANCE_INVALID", "provenance must cover every parameter group")
    normalized_provenance: dict[str, dict[str, str]] = {}
    for key in PARAMETER_KEYS:
        item = provenance[key]
        if not isinstance(item, dict) or set(item) != {"origin", "source"} or item.get("origin") not in ORIGINS:
            raise IntakeParametersError("INTAKE_PARAMETERS_PROVENANCE_INVALID", f"provenance for {key} is invalid")
        normalized_provenance[key] = {"origin": item["origin"], "source": _text(item["source"], f"provenance.{key}.source", minimum=2, maximum=240)}
    approved_by = _text(request.get("approved_by"), "approved_by")
    rationale = _text(request.get("rationale"), "rationale", minimum=8)
    expires_at, _ = _parse_expiry(request.get("expires_at"))
    if mode == "autonomous":
        non_authoritative = [key for key, item in normalized_provenance.items() if item["origin"] not in AUTHORITATIVE_ORIGINS]
        if external != "local_only" or non_authoritative:
            raise IntakeParametersError("INTAKE_PARAMETERS_AUTONOMY_REJECTED", "autonomous mode requires local_only effects and authoritative mode/scope/budget provenance")
    authoritative = [key for key, item in normalized_provenance.items() if item["origin"] in AUTHORITATIVE_ORIGINS]
    advisory = [key for key in PARAMETER_KEYS if key not in authoritative]
    return {
        "schema": REQUEST_SCHEMA,
        "intake_confirmation": confirmation_relative,
        "parameters": {
            "mode": mode,
            "risk": risk,
            "budgets": normalized_budgets,
            "scope_paths": sorted(normalized_scope),
            "required_lanes": normalized_lanes,
            "external_effects": external,
        },
        "provenance": normalized_provenance,
        "approved_by": approved_by,
        "expires_at": expires_at,
        "rationale": rationale,
        "project": confirmation.get("project"),
        "confirmation_sha256": confirmation.get("confirmation_sha256"),
        "authoritative_parameters": authoritative,
        "advisory_parameters": advisory,
    }


def _core(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key not in RECEIPT_CORE_EXCLUDED}


def _atomic_write(path: Path, data: bytes, *, force: bool) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == data:
            return path
        if not force:
            raise IntakeParametersError("INTAKE_PARAMETERS_ARTIFACT_EXISTS", f"refusing to replace {path}; use --force")
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def seal_intake_parameters(root: Path, request_path: Path, out_path: Path | None = None, force: bool = False) -> dict[str, Any]:
    """Seal a validated request into a confirmation-bound parameter envelope."""
    workspace = Path(root).resolve()
    request_file, request_relative, request = _read_json(workspace, request_path, "request", allow_absolute=True)
    normalized = _validate_request(workspace, request)
    request_sha = hashlib.sha256(request_file.read_bytes()).hexdigest()
    project = normalized["project"]
    if not isinstance(project, str) or not _PROJECT.fullmatch(project):
        raise IntakeParametersError("INTAKE_PARAMETERS_PROJECT_INVALID", "confirmation project is invalid")
    core = {
        "schema": RECEIPT_SCHEMA,
        "project": project,
        "request": {"path": request_relative, "sha256": request_sha},
        "intake": {"path": normalized["intake_confirmation"], "confirmation_sha256": normalized["confirmation_sha256"]},
        "parameters": normalized["parameters"],
        "provenance": normalized["provenance"],
        "approved_by": normalized["approved_by"],
        "rationale": normalized["rationale"],
        "expires_at": normalized["expires_at"],
        "status": "READY" if not normalized["advisory_parameters"] else "REVIEW_REQUIRED",
        "authoritative_parameters": normalized["authoritative_parameters"],
        "advisory_parameters": normalized["advisory_parameters"],
        "markers": ["INTAKE_PARAMETERS_SOURCE_BOUND", "INTAKE_PARAMETERS_CANONICAL_SIX_LANES", "INTAKE_PARAMETERS_FAIL_CLOSED", "INTAKE_PARAMETERS_ZERO_EXECUTION_AUTHORITY"],
        "authority": AUTHORITY,
        "claim_boundary": "Hash-bound local intake parameters only; not execution, approval, credentials, publication, deployment, or provider state.",
    }
    receipt = {**core, "parameter_sha256": _sha(core), "sealed_at": _iso(_now())}
    default = workspace / ".factory" / "intake-parameters" / project / f"{request_sha}.json"
    path = Path(out_path).resolve() if out_path and Path(out_path).is_absolute() else (workspace / Path(out_path) if out_path else default)
    _, relative = _relative(workspace, path, "out", exists=False, allow_absolute=True)
    payload = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    reused = path.is_file() and path.read_bytes() == payload
    _atomic_write(path, payload, force=force)
    return {**receipt, "path": str(path), "relative_path": relative, "idempotent": reused}


def _load_receipt(root: Path, receipt_path: Path) -> tuple[Path, str, dict[str, Any]]:
    path, relative, receipt = _read_json(root, receipt_path, "receipt", allow_absolute=True)
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise IntakeParametersError("INTAKE_PARAMETERS_SCHEMA", f"expected {RECEIPT_SCHEMA}")
    return path, relative, receipt


def verify_intake_parameters(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify envelope integrity, confirmation binding, provenance and expiry."""
    workspace = Path(root).resolve()
    path, relative, receipt = _load_receipt(workspace, receipt_path)
    errors: list[str] = []
    digest = receipt.get("parameter_sha256")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest) or digest != _sha(_core(receipt)):
        errors.append("parameter receipt hash mismatch")
    if receipt.get("authority") != AUTHORITY:
        errors.append("authority boundary invalid")
    try:
        intake_path, _, _, confirmation = _validate_confirmation(workspace, receipt.get("intake", {}).get("path"))
        if receipt.get("intake", {}).get("confirmation_sha256") != confirmation.get("confirmation_sha256"):
            errors.append("confirmation hash mismatch")
        request_path, _, request = _read_json(workspace, receipt.get("request", {}).get("path"), "request")
        if receipt.get("request", {}).get("sha256") != hashlib.sha256(request_path.read_bytes()).hexdigest():
            errors.append("request source drift")
        normalized = _validate_request(workspace, request)
        if normalized["parameters"] != receipt.get("parameters") or normalized["provenance"] != receipt.get("provenance"):
            errors.append("parameter semantic drift")
        if normalized["confirmation_sha256"] != receipt.get("intake", {}).get("confirmation_sha256"):
            errors.append("confirmation binding drift")
        _parse_expiry(receipt.get("expires_at"))
        if receipt.get("status") not in {"READY", "REVIEW_REQUIRED"}:
            errors.append("status invalid")
        expected_status = "READY" if not normalized["advisory_parameters"] else "REVIEW_REQUIRED"
        if receipt.get("status") != expected_status:
            errors.append("status does not match provenance")
    except IntakeParametersError as exc:
        errors.append(f"{exc.code}: {exc.message}")
    except (OSError, TypeError, AttributeError) as exc:
        errors.append(f"INTAKE_PARAMETERS_DRIFT: {exc}")
    valid = not errors
    if valid:
        state = receipt["status"]
        marker = "INTAKE_PARAMETERS_VERIFIED" if state == "READY" else "INTAKE_PARAMETERS_REVIEW_REQUIRED"
    else:
        state = "BLOCKED"
        marker = "INTAKE_PARAMETERS_DRIFT"
    return {
        "schema": VERIFICATION_SCHEMA,
        "valid": valid,
        "state": state,
        "marker": marker,
        "path": relative,
        "errors": errors,
        "authoritative": valid and state == "READY",
        "authority": AUTHORITY,
        "claim_boundary": "Verification is local and read-only; it never authorizes execution or provider actions.",
    }


def intake_parameters_status(root: Path) -> dict[str, Any]:
    """Return bounded local envelope facts without changing or executing anything."""
    workspace = Path(root).resolve()
    rows: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []
    directory = workspace / ".factory" / "intake-parameters"
    paths = sorted(directory.glob("*/*.json"))[:MAX_SCAN_RECEIPTS]
    truncated = len(list(directory.glob("*/*.json"))) > MAX_SCAN_RECEIPTS
    for path in paths:
        try:
            check = verify_intake_parameters(workspace, path)
            row = {"path": check["path"], "valid": check["valid"], "state": check["state"], "marker": check["marker"]}
            rows.append(row)
            if not check["valid"]:
                invalid.append({"path": check["path"], "error": "; ".join(check["errors"])[:240]})
        except IntakeParametersError as exc:
            invalid.append({"path": path.relative_to(workspace).as_posix(), "error": f"{exc.code}: {exc.message}"})
    latest = rows[-1] if rows else None
    if invalid:
        state = "BLOCKED"
    elif not latest:
        state = "MISSING"
    elif latest["state"] == "REVIEW_REQUIRED":
        state = "REVIEW_REQUIRED"
    else:
        state = "READY"
    return {
        "schema": STATUS_SCHEMA,
        "marker": "INTAKE_PARAMETERS_STATUS_READ_ONLY",
        "state": state,
        "receipt_count": len(rows),
        "ready_count": sum(row["state"] == "READY" and row["valid"] for row in rows),
        "review_required_count": sum(row["state"] == "REVIEW_REQUIRED" and row["valid"] for row in rows),
        "invalid_count": len(invalid),
        "truncated": truncated,
        "latest": latest,
        "invalid": invalid,
        "authority": AUTHORITY,
        "claim_boundary": "Bounded local envelope metadata only; not a gate decision, execution, approval, credentials, publication, deployment, or provider status.",
    }
