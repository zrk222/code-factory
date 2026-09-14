"""A small, fail-closed first-lap control plane for Code Factory.

The first lap is intentionally boring and human-readable.  It turns the
existing Oracle, candidate-lineage, Gauntlet, and session-recorder primitives
into one activation boundary without executing an agent or granting release
authority.  The module records only bounded hashes and declared facts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Iterable


SCHEMA = "factory.first-lap.v1"
RECEIPT_SCHEMA = "factory.first-lap.receipt.v1"
INCIDENT_SCHEMA = "factory.incident.v1"
PROMOTED_SCHEMA = "factory.incident-promotion.v1"
CALIBRATION_SCHEMA = "factory.verifier-calibration.v1"
HOLDOUT_SCHEMA = "factory.holdout-boundary.v1"
OBSERVED_SCHEMA = "factory.observed-first-lap.v1"
FAILURE_SCHEMA = "factory.failure-classification.v1"

PHASES = ("intake", "candidate_binding", "validation", "failure_handling", "cleanup", "handoff")
FAILURE_CLASSES = (
    "definitive_product_failure",
    "transient_provider_failure",
    "unverifiable_candidate_identity",
    "stale_evidence",
    "environment_setup_failure",
)
RETRYABLE = frozenset({"transient_provider_failure"})
_MAX_TEXT = 2048
_MAX_ITEMS = 64


class FirstLapError(ValueError):
    """Stable, machine-readable fail-closed first-lap error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: object, field: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise FirstLapError("E_FIRST_LAP_FIELD", f"{field} must be non-empty and bounded")
    return value.strip()


def _relative(root: Path, value: object, field: str) -> str:
    raw = _text(value, field, 512).replace("\\", "/")
    candidate = Path(raw)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise FirstLapError("E_FIRST_LAP_PATH", f"{field} must stay inside the workspace")
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise FirstLapError("E_FIRST_LAP_PATH", f"{field} escapes the workspace") from exc
    return candidate.as_posix()


def _atomic_text(path: Path, content: str, *, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        return
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_json(path: Path, payload: dict[str, Any], *, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FirstLapError("E_FIRST_LAP_IMMUTABLE", f"receipt already exists: {path}")
    data = _canonical(payload) + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FirstLapError("E_FIRST_LAP_INPUT", f"cannot read JSON input: {path}") from exc
    if not isinstance(value, dict):
        raise FirstLapError("E_FIRST_LAP_INPUT", "JSON input must be one object")
    return value


def _hash_paths(root: Path, paths: Iterable[Path]) -> list[dict[str, Any]]:
    result = []
    for path in paths:
        if not path.is_file():
            raise FirstLapError("E_FIRST_LAP_ARTIFACT", f"missing generated artifact: {path}")
        result.append({"path": path.relative_to(root).as_posix(), "sha256": _file_sha(path), "bytes": path.stat().st_size})
    return result


def initialize_first_lap(
    root: Path,
    *,
    mission: str = "Deliver the requested outcome without violating the forbidden outcomes.",
    journeys: Iterable[str] | None = None,
    holdouts: Iterable[str] | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Create the three plain-language first-lap files and a local receipt."""
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise FirstLapError("E_FIRST_LAP_ROOT", "root must be an existing directory")
    journey_values = [_text(item, "journey", 512) for item in (journeys or ("The declared happy path completes with the expected result.",))]
    holdout_values = [_text(item, "holdout", 512) for item in (holdouts or ("A declared negative case must fail closed and leave no partial state.",))]
    if not 1 <= len(journey_values) <= 5 or not 1 <= len(holdout_values) <= _MAX_ITEMS:
        raise FirstLapError("E_FIRST_LAP_BOUNDS", "first lap requires 1-5 journeys and 1-64 holdouts")
    mission_text = "# Mission\n\n## Intended outcomes\n\n" + mission.strip() + "\n\n## Forbidden outcomes\n\n- Scope expands beyond the approved intent.\n- A failed or stale proof is presented as a release approval.\n- An agent changes gates, exceptions, or the intent contract.\n\n## Human release authority\n\nThe first lap prepares evidence only; a human retains merge, publication, deployment, and signing authority.\n"
    e2e_text = "# End-to-End Journeys\n\nObservable journeys used to calibrate and review the factory:\n\n" + "\n".join(f"- [ ] {item}" for item in journey_values) + "\n\nEach journey must name its expected result, forbidden result, and evidence producer before activation.\n"
    holdout_text = "# Holdout Scenarios (verifier-only)\n\nThese scenarios are independent negative cases. The implementing agent must not read or modify them.\n\n" + "\n".join(f"- {item}" for item in holdout_values) + "\n\nAccess is monitored by the verifier boundary; any builder access contaminates the run and blocks activation.\n"
    mission_path = workspace / "MISSION.md"
    e2e_path = workspace / "END-TO-END.md"
    holdout_path = workspace / ".factory" / "holdouts" / "HOLDOUT.md"
    _atomic_text(mission_path, mission_text, overwrite=overwrite)
    _atomic_text(e2e_path, e2e_text, overwrite=overwrite)
    _atomic_text(holdout_path, holdout_text, overwrite=overwrite)
    ledger = workspace / ".factory" / "incidents" / "ledger.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.touch(exist_ok=True)
    artifacts = _hash_paths(workspace, (mission_path, e2e_path, holdout_path))
    core = {
        "schema": SCHEMA,
        "marker": "FIRST_LAP_FILES_READY",
        "mission": mission.strip(),
        "journey_count": len(journey_values),
        "holdout_count": len(holdout_values),
        "artifacts": artifacts,
        "incident_ledger": {"path": ledger.relative_to(workspace).as_posix(), "sha256": _file_sha(ledger)},
        "authority": {"agent_execution": False, "release": False, "merge": False, "publication": False, "deployment": False, "signing": False},
        "claim_boundary": "Onboarding files and verifier boundary metadata only; no code correctness, store approval, or production-readiness claim.",
    }
    receipt = {**core, "receipt_sha256": _sha(core), "generated_at": _now()}
    receipt_path = workspace / ".factory" / "first-lap" / "init.json"
    _atomic_json(receipt_path, receipt, overwrite=overwrite)
    return {**receipt, "paths": {"mission": "MISSION.md", "journeys": "END-TO-END.md", "holdouts": ".factory/holdouts/HOLDOUT.md", "receipt": receipt_path.relative_to(workspace).as_posix()}}


def first_lap_status(root: Path) -> dict[str, Any]:
    """Read the local First Lap contract and verify its generated files.

    This is deliberately a projection, not a verifier runner: it checks the
    immutable initialization receipt and the three human-readable artifacts,
    but never executes a journey, opens the holdout, or changes workspace
    state.  Agents and IDEs can therefore use it as their first discovery call
    without receiving execution or release authority.
    """
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise FirstLapError("E_FIRST_LAP_ROOT", "root must be an existing directory")
    receipt_path = workspace / ".factory" / "first-lap" / "init.json"
    required = ("MISSION.md", "END-TO-END.md", ".factory/holdouts/HOLDOUT.md")
    if not receipt_path.is_file():
        return {
            "schema": RECEIPT_SCHEMA,
            "marker": "FIRST_LAP_NOT_INITIALIZED",
            "state": "NOT_INITIALIZED",
            "required_paths": list(required),
            "next_actions": ["factory first-lap init --root .", "factory first-lap calibrate <cases.json> --root ."],
            "authority": {"execution": False, "release": False, "merge": False, "publication": False, "deployment": False, "signing": False},
            "claim_boundary": "No First Lap contract was found; no code, test, holdout, provider, or release claim is made.",
        }
    try:
        receipt = _json(receipt_path)
    except FirstLapError as exc:
        return {
            "schema": RECEIPT_SCHEMA,
            "marker": "FIRST_LAP_STATUS_BLOCKED",
            "state": "BLOCKED",
            "code": exc.code,
            "message": str(exc),
            "authority": "none",
        }
    artifact_status: list[dict[str, Any]] = []
    stale: list[str] = []
    for item in receipt.get("artifacts", []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            stale.append("<malformed-artifact>")
            continue
        relative = item["path"]
        path = workspace / relative
        if not path.is_file():
            artifact_status.append({"path": relative, "state": "MISSING"})
            stale.append(relative)
            continue
        actual = _file_sha(path)
        expected = item.get("sha256")
        state = "VERIFIED" if isinstance(expected, str) and actual == expected else "STALE"
        artifact_status.append({"path": relative, "state": state, "sha256": actual})
        if state != "VERIFIED":
            stale.append(relative)
    state = "INITIALIZED" if not stale else "BLOCKED"
    result: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "FIRST_LAP_INITIALIZED" if state == "INITIALIZED" else "FIRST_LAP_STATUS_BLOCKED",
        "state": state,
        "receipt_path": ".factory/first-lap/init.json",
        "receipt_sha256": _file_sha(receipt_path),
        "mission": receipt.get("mission"),
        "journey_count": receipt.get("journey_count"),
        "holdout_count": receipt.get("holdout_count"),
        "artifacts": artifact_status,
        "stale_paths": stale,
        "next_actions": [
            "factory first-lap calibrate <cases.json> --root .",
            "factory first-lap holdout <boundary.json> --root .",
            "factory first-lap observe <events.json>",
            "factory first-lap verify --calibration <calibration.json> --holdout <holdout.json> --observed <observed.json> --root .",
        ] if state == "INITIALIZED" else ["Restore or re-initialize only the generated First Lap files, then re-check this status."],
        "authority": {"execution": False, "release": False, "merge": False, "publication": False, "deployment": False, "signing": False},
        "claim_boundary": "Initialization and file-integrity metadata only; calibration, holdout isolation, observed execution, code correctness, store approval, and production readiness remain unproven.",
    }
    return result


def verify_verifier_calibration(root: Path, cases: dict[str, Any]) -> dict[str, Any]:
    """Require pass/fail/inconclusive calibration before a verifier activates."""
    if not isinstance(cases, dict):
        raise FirstLapError("E_CALIBRATION_SCHEMA", "calibration cases must be an object")
    expected = {"approved_candidate": "pass", "defective_candidate": "fail", "wrong_candidate": {"inconclusive", "blocked"}}
    observed: dict[str, str] = {}
    for name, acceptable in expected.items():
        value = cases.get(name)
        status = value.get("status") if isinstance(value, dict) else value
        if not isinstance(status, str):
            raise FirstLapError("E_CALIBRATION_INCOMPLETE", f"missing calibration status: {name}")
        normalized = status.strip().lower()
        observed[name] = normalized
        if normalized not in (acceptable if isinstance(acceptable, set) else {acceptable}):
            return {"schema": CALIBRATION_SCHEMA, "marker": "VERIFIER_ACTIVATION_BLOCKED", "state": "BLOCKED", "code": "E_CALIBRATION_FAILED", "failed_case": name, "observed": observed, "required": {key: sorted(value) if isinstance(value, set) else [value] for key, value in expected.items()}, "authority": "none"}
    core = {"schema": CALIBRATION_SCHEMA, "marker": "VERIFIER_CALIBRATED", "state": "CALIBRATED", "observed": observed, "required": {key: sorted(value) if isinstance(value, set) else [value] for key, value in expected.items()}, "authority": "none"}
    return {**core, "calibration_sha256": _sha(core)}


def record_incident(root: Path, incident: dict[str, Any]) -> dict[str, Any]:
    """Append an incident and its complete promotion chain to the scar ledger."""
    required = ("incident_id", "failure_code", "invariant", "reproducer", "mutation", "owner")
    if not isinstance(incident, dict) or any(not isinstance(incident.get(key), str) or not incident[key].strip() for key in required):
        raise FirstLapError("E_INCIDENT_INCOMPLETE", "incident requires failure code, invariant, reproducer, mutation, and owner")
    incident_id = _text(incident["incident_id"], "incident_id", 128)
    ledger = workspace = Path(root).resolve() / ".factory" / "incidents" / "ledger.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    existing = ledger.read_text(encoding="utf-8") if ledger.exists() else ""
    if any(f'"incident_id":"{incident_id}"' in line for line in existing.splitlines()):
        raise FirstLapError("E_INCIDENT_DUPLICATE", f"incident already recorded: {incident_id}")
    core = {"schema": INCIDENT_SCHEMA, "incident_id": incident_id, "failure_code": _text(incident["failure_code"], "failure_code", 128), "invariant": _text(incident["invariant"], "invariant"), "reproducer": _text(incident["reproducer"], "reproducer"), "mutation": _text(incident["mutation"], "mutation"), "owner": _text(incident["owner"], "owner", 256), "recorded_at": _now(), "status": "PROMOTION_READY"}
    row = {**core, "incident_sha256": _sha(core)}
    with ledger.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    return {**row, "path": ledger.relative_to(workspace).as_posix()}


def promote_incident(root: Path, incident: dict[str, Any]) -> dict[str, Any]:
    """Compile an incident into an executable regression-gate requirement."""
    required = ("incident_id", "failure_code", "invariant", "reproducer", "mutation", "owner")
    if not isinstance(incident, dict) or any(not isinstance(incident.get(key), str) or not incident[key].strip() for key in required):
        raise FirstLapError("E_INCIDENT_INCOMPLETE", "incident cannot be promoted without the full chain")
    core = {"schema": PROMOTED_SCHEMA, "marker": "INCIDENT_PROMOTED_TO_GATE", "incident_id": _text(incident["incident_id"], "incident_id", 128), "failure_code": _text(incident["failure_code"], "failure_code", 128), "invariant": _text(incident["invariant"], "invariant"), "reproducer": _text(incident["reproducer"], "reproducer"), "mutation": _text(incident["mutation"], "mutation"), "owner": _text(incident["owner"], "owner", 256), "gate": {"type": "permanent_regression", "required": True, "human_approval": True}, "authority": "none"}
    result = {**core, "promotion_sha256": _sha(core)}
    path = Path(root).resolve() / ".factory" / "incidents" / "promoted" / f"{core['incident_id']}.json"
    _atomic_json(path, result)
    return {**result, "path": path.relative_to(Path(root).resolve()).as_posix()}


def verify_holdout_boundary(root: Path, holdout: dict[str, Any]) -> dict[str, Any]:
    """Verify verifier-only holdout metadata and fail closed on builder access."""
    workspace = Path(root).resolve()
    if not isinstance(holdout, dict):
        raise FirstLapError("E_HOLDOUT_SCHEMA", "holdout boundary must be an object")
    path_value = holdout.get("path")
    if not isinstance(path_value, str) or not path_value.strip():
        raise FirstLapError("E_HOLDOUT_SCHEMA", "holdout path is required")
    resolved = Path(path_value)
    if not resolved.is_absolute():
        resolved = workspace / resolved
    resolved = resolved.resolve()
    accessed = holdout.get("builder_accessed_paths", [])
    if not isinstance(accessed, list) or any(not isinstance(item, str) for item in accessed):
        raise FirstLapError("E_HOLDOUT_SCHEMA", "builder_accessed_paths must be a string list")
    contaminated = bool(accessed)
    try:
        relative = resolved.relative_to(workspace).as_posix()
        in_workspace = True
    except ValueError:
        relative = str(resolved)
        in_workspace = False
    if not resolved.is_file():
        return {"schema": HOLDOUT_SCHEMA, "marker": "HOLDOUT_BOUNDARY_BLOCKED", "state": "BLOCKED", "code": "E_HOLDOUT_UNAVAILABLE", "path": relative, "authority": "none"}
    expected = holdout.get("sha256")
    actual = _file_sha(resolved)
    if not isinstance(expected, str) or expected.lower() != actual:
        return {"schema": HOLDOUT_SCHEMA, "marker": "HOLDOUT_BOUNDARY_BLOCKED", "state": "BLOCKED", "code": "E_HOLDOUT_STALE", "path": relative, "expected_sha256": expected, "actual_sha256": actual, "authority": "none"}
    if contaminated:
        return {"schema": HOLDOUT_SCHEMA, "marker": "HOLDOUT_CONTAMINATED", "state": "BLOCKED", "code": "E_HOLDOUT_BUILDER_ACCESS", "path": relative, "builder_accessed_paths": accessed, "authority": "none"}
    if in_workspace and not relative.startswith(".factory/holdouts/"):
        return {"schema": HOLDOUT_SCHEMA, "marker": "HOLDOUT_BOUNDARY_BLOCKED", "state": "BLOCKED", "code": "E_HOLDOUT_SCOPE", "path": relative, "authority": "none"}
    core = {"schema": HOLDOUT_SCHEMA, "marker": "HOLDOUT_BOUNDARY_VERIFIED", "state": "VERIFIED", "path": relative, "sha256": actual, "builder_accessed_paths": [], "authority": "none", "claim_boundary": "Metadata verifies a verifier-only reference; host/filesystem isolation remains the harness responsibility."}
    return {**core, "boundary_sha256": _sha(core)}


def verify_observed_first_lap(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Require exactly one ordered, human-observed lifecycle."""
    rows = list(events)
    names = [row.get("phase") if isinstance(row, dict) else None for row in rows]
    if names != list(PHASES):
        return {"schema": OBSERVED_SCHEMA, "marker": "FIRST_LAP_OBSERVATION_BLOCKED", "state": "BLOCKED", "code": "E_FIRST_LAP_SEQUENCE", "observed_phases": names, "required_phases": list(PHASES), "authority": "none"}
    if any(not isinstance(row.get("evidence_sha256"), str) or len(row["evidence_sha256"]) != 64 for row in rows):
        return {"schema": OBSERVED_SCHEMA, "marker": "FIRST_LAP_OBSERVATION_BLOCKED", "state": "BLOCKED", "code": "E_FIRST_LAP_EVIDENCE", "authority": "none"}
    core = {"schema": OBSERVED_SCHEMA, "marker": "FIRST_LAP_OBSERVED", "state": "OBSERVED", "phases": [{"phase": row["phase"], "evidence_sha256": row["evidence_sha256"]} for row in rows], "human_observer": True, "authority": {"approval": False, "release": False, "autonomy_grant": False}}
    return {**core, "observation_sha256": _sha(core)}


def classify_failure(kind: str, *, provider: str | None = None, retry_after_seconds: int | None = None) -> dict[str, Any]:
    """Normalize failure taxonomy; only transient provider failures retry."""
    normalized = _text(kind, "failure_kind", 64).lower()
    if normalized not in FAILURE_CLASSES:
        raise FirstLapError("E_FAILURE_CLASS", f"unsupported failure class: {normalized}")
    if retry_after_seconds is not None and (isinstance(retry_after_seconds, bool) or not isinstance(retry_after_seconds, int) or not 1 <= retry_after_seconds <= 3600):
        raise FirstLapError("E_FAILURE_RETRY", "retry_after_seconds must be 1-3600")
    core = {"schema": FAILURE_SCHEMA, "failure_class": normalized, "provider": provider.strip() if isinstance(provider, str) and provider.strip() else None, "retry_allowed": normalized in RETRYABLE, "retry_after_seconds": retry_after_seconds if normalized in RETRYABLE else None, "authority": "none", "claim_boundary": "Classification is a retry policy hint; it does not prove provider health or product correctness."}
    return {**core, "classification_sha256": _sha(core)}


def verify_activation(root: Path, *, calibration: dict[str, Any], holdout: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """Compose the mandatory activation gate from all first-lap controls."""
    reasons: list[str] = []
    if calibration.get("state") != "CALIBRATED":
        reasons.append("verifier calibration is not complete")
    if holdout.get("state") != "VERIFIED":
        reasons.append("holdout boundary is not verified")
    if observed.get("state") != "OBSERVED":
        reasons.append("human-observed first lap is not complete")
    if reasons:
        return {"schema": RECEIPT_SCHEMA, "marker": "FIRST_LAP_ACTIVATION_BLOCKED", "state": "BLOCKED", "code": "E_FIRST_LAP_ACTIVATION", "reasons": reasons, "authority": "none"}
    core = {"schema": RECEIPT_SCHEMA, "marker": "FIRST_LAP_ACTIVATION_READY", "state": "READY", "calibration_sha256": calibration.get("calibration_sha256"), "holdout_boundary_sha256": holdout.get("boundary_sha256"), "observation_sha256": observed.get("observation_sha256"), "authority": {"autonomy": "supervised", "release": False, "merge": False, "publication": False, "deployment": False}}
    return {**core, "receipt_sha256": _sha(core)}
