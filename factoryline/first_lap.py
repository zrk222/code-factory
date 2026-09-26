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
ACTIVATION_SCHEMA = "factory.first-lap.activation.v1"

PHASES = (
    "intake",
    "candidate_binding",
    "validation",
    "failure_handling",
    "cleanup",
    "handoff",
)
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


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _is_iso8601(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


class FirstLapError(ValueError):
    """Stable, machine-readable fail-closed first-lap error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(
        value if isinstance(value, bytes) else _canonical(value)
    ).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: object, field: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise FirstLapError(
            "E_FIRST_LAP_FIELD", f"{field} must be non-empty and bounded"
        )
    return value.strip()


def _relative(root: Path, value: object, field: str) -> str:
    raw = _text(value, field, 512).replace("\\", "/")
    candidate = Path(raw)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise FirstLapError(
            "E_FIRST_LAP_PATH", f"{field} must stay inside the workspace"
        )
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise FirstLapError(
            "E_FIRST_LAP_PATH", f"{field} escapes the workspace"
        ) from exc
    return candidate.as_posix()


def _atomic_text(path: Path, content: str, *, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        return
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
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


def _atomic_json(
    path: Path, payload: dict[str, Any], *, overwrite: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FirstLapError("E_FIRST_LAP_IMMUTABLE", f"receipt already exists: {path}")
    data = _canonical(payload) + b"\n"
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
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
        raise FirstLapError(
            "E_FIRST_LAP_INPUT", f"cannot read JSON input: {path}"
        ) from exc
    if not isinstance(value, dict):
        raise FirstLapError("E_FIRST_LAP_INPUT", "JSON input must be one object")
    return value


def _hash_paths(root: Path, paths: Iterable[Path]) -> list[dict[str, Any]]:
    result = []
    for path in paths:
        if not path.is_file():
            raise FirstLapError(
                "E_FIRST_LAP_ARTIFACT", f"missing generated artifact: {path}"
            )
        result.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": _file_sha(path),
                "bytes": path.stat().st_size,
            }
        )
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
    journey_values = [
        _text(item, "journey", 512)
        for item in (
            journeys
            or (
                "The declared happy path completes with the expected result.",
                "A forbidden authorization or tenant access attempt is rejected without data leakage.",
                "A transient failure retries within policy and resumes from the last durable checkpoint.",
                "A migration or compatibility change preserves data and supported consumers.",
            )
        )
    ]
    holdout_values = [
        _text(item, "holdout", 512)
        for item in (
            holdouts
            or (
                "A declared negative case must fail closed and leave no partial state.",
            )
        )
    ]
    if not 1 <= len(journey_values) <= 5 or not 1 <= len(holdout_values) <= _MAX_ITEMS:
        raise FirstLapError(
            "E_FIRST_LAP_BOUNDS", "first lap requires 1-5 journeys and 1-64 holdouts"
        )
    mission_text = (
        "# Mission\n\n## Intended outcomes\n\n"
        + mission.strip()
        + "\n\n## Forbidden outcomes\n\n- Scope expands beyond the approved intent.\n- A failed or stale proof is presented as a release approval.\n- An agent changes gates, exceptions, or the intent contract.\n\n## Human release authority\n\nThe first lap prepares evidence only; a human retains merge, publication, deployment, and signing authority.\n"
    )
    e2e_text = (
        "# End-to-End Journeys\n\nObservable journeys used to calibrate and review the factory:\n\n"
        + "\n".join(f"- [ ] {item}" for item in journey_values)
        + "\n\nEach journey must name its expected result, forbidden result, and evidence producer before activation.\n"
    )
    # Keep the builder-facing manifest intentionally free of scenario content.
    # The real negative cases live in a sibling verifier store outside the
    # workspace; reading them from the builder root is therefore contamination.
    external_store = workspace.parent / f".{workspace.name}.factory-holdouts"
    external_store.mkdir(parents=True, exist_ok=True)
    external_scenarios = (
        "# Verifier holdout scenarios\n\n"
        + "\n".join(f"- {item}" for item in holdout_values)
        + "\n"
    )
    external_scenario_path = external_store / "scenarios.md"
    _atomic_text(external_scenario_path, external_scenarios, overwrite=overwrite)
    external_scenario_sha = _file_sha(external_scenario_path)
    holdout_text = (
        "# Holdout Scenarios (verifier-only)\n\n"
        "This is a builder-safe manifest. The independent negative scenarios are stored outside the workspace and are never exposed to the implementing agent.\n\n"
        f"- scenario_count: {len(holdout_values)}\n"
        f"- external_store_sha256: `{external_scenario_sha}`\n"
        "- isolation: external\n\n"
        "The verifier records access attempts; any builder access contaminates the run and blocks activation.\n"
    )
    mission_path = workspace / "MISSION.md"
    e2e_path = workspace / "END-TO-END.md"
    holdout_path = workspace / ".factory" / "holdouts" / "HOLDOUT.md"
    _atomic_text(mission_path, mission_text, overwrite=overwrite)
    _atomic_text(e2e_path, e2e_text, overwrite=overwrite)
    _atomic_text(holdout_path, holdout_text, overwrite=overwrite)
    root_holdout_path = workspace / "HOLDOUT.md"
    _atomic_text(root_holdout_path, holdout_text, overwrite=overwrite)
    ledger = workspace / ".factory" / "incidents" / "ledger.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.touch(exist_ok=True)
    artifacts = _hash_paths(
        workspace, (mission_path, e2e_path, root_holdout_path, holdout_path)
    )
    core = {
        "schema": SCHEMA,
        "marker": "FIRST_LAP_FILES_READY",
        "mission": mission.strip(),
        "journey_count": len(journey_values),
        "holdout_count": len(holdout_values),
        "holdout_isolation": {
            "mode": "external",
            "store": str(external_scenario_path),
            "sha256": external_scenario_sha,
        },
        "artifacts": artifacts,
        "incident_ledger": {
            "path": ledger.relative_to(workspace).as_posix(),
            "sha256": _file_sha(ledger),
        },
        "authority": {
            "agent_execution": False,
            "release": False,
            "merge": False,
            "publication": False,
            "deployment": False,
            "signing": False,
        },
        "claim_boundary": "Onboarding files and verifier boundary metadata only; no code correctness, store approval, or production-readiness claim.",
    }
    receipt = {**core, "receipt_sha256": _sha(core), "generated_at": _now()}
    receipt_path = workspace / ".factory" / "first-lap" / "init.json"
    _atomic_json(receipt_path, receipt, overwrite=overwrite)
    return {
        **receipt,
        "paths": {
            "mission": "MISSION.md",
            "journeys": "END-TO-END.md",
            "holdout_manifest": "HOLDOUT.md",
            "holdouts": ".factory/holdouts/HOLDOUT.md",
            "receipt": receipt_path.relative_to(workspace).as_posix(),
        },
    }


def _uninitialized_status(required: tuple[str, ...]) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "marker": "FIRST_LAP_NOT_INITIALIZED",
        "state": "NOT_INITIALIZED",
        "required_paths": list(required),
        "next_actions": [
            "factory first-lap init --root .",
            "factory first-lap calibrate <cases.json> --root .",
        ],
        "authority": {
            "execution": False,
            "release": False,
            "merge": False,
            "publication": False,
            "deployment": False,
            "signing": False,
        },
        "claim_boundary": "No First Lap contract was found; no code, test, holdout, provider, or release claim is made.",
    }


def _blocked_status(exc: FirstLapError) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "marker": "FIRST_LAP_STATUS_BLOCKED",
        "state": "BLOCKED",
        "code": exc.code,
        "message": str(exc),
        "authority": "none",
    }


def _status_artifacts(
    workspace: Path, receipt: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
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
        state = (
            "VERIFIED" if isinstance(expected, str) and actual == expected else "STALE"
        )
        artifact_status.append({"path": relative, "state": state, "sha256": actual})
        if state != "VERIFIED":
            stale.append(relative)
    return artifact_status, stale


def _status_next_actions(state: str) -> list[str]:
    if state == "INITIALIZED":
        return [
            "factory first-lap calibrate <cases.json> --root .",
            "factory first-lap holdout <boundary.json> --root .",
            "factory first-lap observe <events.json>",
            "factory first-lap verify --calibration <calibration.json> --holdout <holdout.json> --observed <observed.json> --root .",
        ]
    return [
        "Restore or re-initialize only the generated First Lap files, then re-check this status."
    ]


def _initialized_status(
    workspace: Path,
    receipt_path: Path,
    receipt: dict[str, Any],
    artifact_status: list[dict[str, Any]],
    stale: list[str],
) -> dict[str, Any]:
    state = "INITIALIZED" if not stale else "BLOCKED"
    return {
        "schema": RECEIPT_SCHEMA,
        "marker": "FIRST_LAP_INITIALIZED"
        if state == "INITIALIZED"
        else "FIRST_LAP_STATUS_BLOCKED",
        "state": state,
        "receipt_path": ".factory/first-lap/init.json",
        "receipt_sha256": _file_sha(receipt_path),
        "mission": receipt.get("mission"),
        "journey_count": receipt.get("journey_count"),
        "holdout_count": receipt.get("holdout_count"),
        "artifacts": artifact_status,
        "stale_paths": stale,
        "next_actions": _status_next_actions(state),
        "authority": {
            "execution": False,
            "release": False,
            "merge": False,
            "publication": False,
            "deployment": False,
            "signing": False,
        },
        "claim_boundary": "Initialization and file-integrity metadata only; calibration, holdout isolation, observed execution, code correctness, store approval, and production readiness remain unproven.",
    }


def first_lap_status(root: Path) -> dict[str, Any]:
    """Read First Lap initialization metadata without running verifiers."""
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise FirstLapError("E_FIRST_LAP_ROOT", "root must be an existing directory")
    receipt_path = workspace / ".factory" / "first-lap" / "init.json"
    required = (
        "MISSION.md",
        "END-TO-END.md",
        "HOLDOUT.md",
        ".factory/holdouts/HOLDOUT.md",
    )
    if not receipt_path.is_file():
        return _uninitialized_status(required)
    try:
        receipt = _json(receipt_path)
    except FirstLapError as exc:
        return _blocked_status(exc)
    artifact_status, stale = _status_artifacts(workspace, receipt)
    return _initialized_status(workspace, receipt_path, receipt, artifact_status, stale)


def _calibration_required(expected: dict[str, Any]) -> dict[str, list[str]]:
    return {
        key: sorted(value) if isinstance(value, set) else [value]
        for key, value in expected.items()
    }


def _calibration_blocked(
    code: str,
    *,
    failed_case: str | None = None,
    observed: dict[str, str] | None = None,
    required: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": CALIBRATION_SCHEMA,
        "marker": "VERIFIER_ACTIVATION_BLOCKED",
        "state": "BLOCKED",
        "code": code,
    }
    if failed_case is not None:
        result["failed_case"] = failed_case
    if observed is not None:
        result["observed"] = observed
    if required is not None:
        result["required"] = required
    result["authority"] = "none"
    return result


def _calibration_status(value: object, name: str) -> str:
    status = value.get("status") if isinstance(value, dict) else value
    if not isinstance(status, str):
        raise FirstLapError(
            "E_CALIBRATION_INCOMPLETE", f"missing calibration status: {name}"
        )
    return status.strip().lower()


def _strict_calibration_metadata(
    name: str,
    value: object,
    candidate_hashes: set[str],
    contract_hashes: set[str],
) -> tuple[dict[str, str] | None, str | None]:
    if (
        not isinstance(value, dict)
        or not _is_sha256(value.get("candidate_hash"))
        or not _is_sha256(value.get("contract_sha256"))
        or not _is_sha256(value.get("evidence_sha256"))
    ):
        return None, name
    candidate_hash = value["candidate_hash"].lower()
    contract_hash = value["contract_sha256"].lower()
    if candidate_hash in candidate_hashes:
        return None, name
    candidate_hashes.add(candidate_hash)
    contract_hashes.add(contract_hash)
    return {
        "candidate_hash": candidate_hash,
        "contract_sha256": contract_hash,
        "evidence_sha256": value["evidence_sha256"].lower(),
        "validator_id": _text(
            value.get("validator_id", "unknown"), "validator_id", 128
        ),
    }, None


def _calibration_core(
    observed: dict[str, str],
    required: dict[str, list[str]],
    metadata: dict[str, dict[str, str]],
    contract_hashes: set[str],
    strict: bool,
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": CALIBRATION_SCHEMA,
        "marker": "VERIFIER_CALIBRATED",
        "state": "CALIBRATED",
        "observed": observed,
        "required": required,
        "authority": "none",
    }
    if strict:
        core.update(
            {
                "identity_bound": True,
                "contract_sha256": next(iter(contract_hashes)),
                "cases": metadata,
            }
        )
    return core


def verify_verifier_calibration(
    root: Path, cases: dict[str, Any], *, strict: bool = False
) -> dict[str, Any]:
    """Require pass/fail/inconclusive calibration before a verifier activates.

    Strict calibration additionally binds each case to a distinct candidate
    fingerprint, one sealed contract digest, and independently produced
    evidence.  The legacy status-only form remains available for old receipts,
    but cannot be used for autonomous activation.
    """
    if not isinstance(cases, dict):
        raise FirstLapError(
            "E_CALIBRATION_SCHEMA", "calibration cases must be an object"
        )
    expected = {
        "approved_candidate": "pass",
        "defective_candidate": "fail",
        "wrong_candidate": {"inconclusive", "blocked"},
    }
    observed: dict[str, str] = {}
    metadata: dict[str, dict[str, str]] = {}
    candidate_hashes: set[str] = set()
    contract_hashes: set[str] = set()
    for name, acceptable in expected.items():
        value = cases.get(name)
        normalized = _calibration_status(value, name)
        observed[name] = normalized
        if normalized not in (
            acceptable if isinstance(acceptable, set) else {acceptable}
        ):
            return _calibration_blocked(
                "E_CALIBRATION_FAILED",
                failed_case=name,
                observed=observed,
                required=_calibration_required(expected),
            )
        if strict:
            case_metadata, failure = _strict_calibration_metadata(
                name, value, candidate_hashes, contract_hashes
            )
            if failure:
                return _calibration_blocked(
                    "E_CALIBRATION_IDENTITY", failed_case=failure
                )
            metadata[name] = case_metadata or {}
    if strict and len(contract_hashes) != 1:
        return _calibration_blocked("E_CALIBRATION_CONTRACT")
    core = _calibration_core(
        observed,
        _calibration_required(expected),
        metadata,
        contract_hashes,
        strict,
    )
    return {**core, "calibration_sha256": _sha(core)}


def record_incident(root: Path, incident: dict[str, Any]) -> dict[str, Any]:
    """Append an incident and its complete promotion chain to the scar ledger."""
    required = (
        "incident_id",
        "failure_code",
        "invariant",
        "reproducer",
        "mutation",
        "owner",
    )
    if not isinstance(incident, dict) or any(
        not isinstance(incident.get(key), str) or not incident[key].strip()
        for key in required
    ):
        raise FirstLapError(
            "E_INCIDENT_INCOMPLETE",
            "incident requires failure code, invariant, reproducer, mutation, and owner",
        )
    incident_id = _text(incident["incident_id"], "incident_id", 128)
    ledger = workspace = (
        Path(root).resolve() / ".factory" / "incidents" / "ledger.jsonl"
    )
    ledger.parent.mkdir(parents=True, exist_ok=True)
    existing = ledger.read_text(encoding="utf-8") if ledger.exists() else ""
    if any(f'"incident_id":"{incident_id}"' in line for line in existing.splitlines()):
        raise FirstLapError(
            "E_INCIDENT_DUPLICATE", f"incident already recorded: {incident_id}"
        )
    core = {
        "schema": INCIDENT_SCHEMA,
        "incident_id": incident_id,
        "failure_code": _text(incident["failure_code"], "failure_code", 128),
        "invariant": _text(incident["invariant"], "invariant"),
        "reproducer": _text(incident["reproducer"], "reproducer"),
        "mutation": _text(incident["mutation"], "mutation"),
        "owner": _text(incident["owner"], "owner", 256),
        "recorded_at": _now(),
        "status": "PROMOTION_READY",
    }
    row = {**core, "incident_sha256": _sha(core)}
    with ledger.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    return {**row, "path": ledger.relative_to(workspace).as_posix()}


def promote_incident(root: Path, incident: dict[str, Any]) -> dict[str, Any]:
    """Compile an incident into an executable regression-gate requirement."""
    required = (
        "incident_id",
        "failure_code",
        "invariant",
        "reproducer",
        "mutation",
        "owner",
    )
    if not isinstance(incident, dict) or any(
        not isinstance(incident.get(key), str) or not incident[key].strip()
        for key in required
    ):
        raise FirstLapError(
            "E_INCIDENT_INCOMPLETE",
            "incident cannot be promoted without the full chain",
        )
    core = {
        "schema": PROMOTED_SCHEMA,
        "marker": "INCIDENT_PROMOTED_TO_GATE",
        "incident_id": _text(incident["incident_id"], "incident_id", 128),
        "failure_code": _text(incident["failure_code"], "failure_code", 128),
        "invariant": _text(incident["invariant"], "invariant"),
        "reproducer": _text(incident["reproducer"], "reproducer"),
        "mutation": _text(incident["mutation"], "mutation"),
        "owner": _text(incident["owner"], "owner", 256),
        "gate": {
            "type": "permanent_regression",
            "required": True,
            "human_approval": True,
        },
        "authority": "none",
    }
    result = {**core, "promotion_sha256": _sha(core)}
    path = (
        Path(root).resolve()
        / ".factory"
        / "incidents"
        / "promoted"
        / f"{core['incident_id']}.json"
    )
    _atomic_json(path, result)
    return {**result, "path": path.relative_to(Path(root).resolve()).as_posix()}


def _promoted_receipt_valid(receipt: dict[str, Any]) -> bool:
    body = {key: value for key, value in receipt.items() if key != "promotion_sha256"}
    gate = receipt.get("gate")
    return (
        receipt.get("schema") == PROMOTED_SCHEMA
        and _is_sha256(receipt.get("promotion_sha256"))
        and _sha(body) == receipt.get("promotion_sha256")
        and isinstance(gate, dict)
        and gate.get("required") is True
        and gate.get("human_approval") is True
    )


def _promoted_receipt_names(directory: Path) -> tuple[list[str], list[str]]:
    invalid: list[str] = []
    verified: list[str] = []
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            try:
                receipt = _json(path)
            except FirstLapError:
                invalid.append(path.name)
                continue
            destination = verified if _promoted_receipt_valid(receipt) else invalid
            destination.append(path.name)
    return verified, invalid


def verify_promoted_incident_gates(root: Path) -> dict[str, Any]:
    """Verify every promoted incident receipt before activation."""
    directory = Path(root).resolve() / ".factory" / "incidents" / "promoted"
    verified, invalid = _promoted_receipt_names(directory)
    result = {
        "schema": "factory.incident-gates.v1",
        "state": "VERIFIED" if not invalid else "BLOCKED",
        "verified": verified,
        "invalid": invalid,
        "authority": "none",
    }
    if invalid:
        result["code"] = "E_INCIDENT_GATE_INVALID"
    return {**result, "digest": _sha(result)}


def _holdout_target(workspace: Path, path_value: object) -> tuple[Path, str, bool]:
    if not isinstance(path_value, str) or not path_value.strip():
        raise FirstLapError("E_HOLDOUT_SCHEMA", "holdout path is required")
    resolved = Path(path_value)
    if not resolved.is_absolute():
        resolved = workspace / resolved
    resolved = resolved.resolve()
    try:
        relative = resolved.relative_to(workspace).as_posix()
        return resolved, relative, True
    except ValueError:
        return resolved, str(resolved), False


def _holdout_accessed(holdout: dict[str, Any]) -> list[str]:
    accessed = holdout.get("builder_accessed_paths", [])
    if not isinstance(accessed, list) or any(
        not isinstance(item, str) for item in accessed
    ):
        raise FirstLapError(
            "E_HOLDOUT_SCHEMA", "builder_accessed_paths must be a string list"
        )
    return accessed


def _holdout_blocked(code: str, relative: str, **details: Any) -> dict[str, Any]:
    marker = (
        "HOLDOUT_CONTAMINATED"
        if code == "E_HOLDOUT_BUILDER_ACCESS"
        else "HOLDOUT_BOUNDARY_BLOCKED"
    )
    return {
        "schema": HOLDOUT_SCHEMA,
        "marker": marker,
        "state": "BLOCKED",
        "code": code,
        "path": relative,
        **details,
        "authority": "none",
    }


def _holdout_availability(resolved: Path, relative: str) -> dict[str, Any] | None:
    if resolved.is_file():
        return None
    return _holdout_blocked("E_HOLDOUT_UNAVAILABLE", relative)


def _holdout_digest(
    resolved: Path, holdout: dict[str, Any], relative: str
) -> tuple[str | None, dict[str, Any] | None]:
    expected = holdout.get("sha256")
    actual = _file_sha(resolved)
    if not isinstance(expected, str) or expected.lower() != actual:
        return None, _holdout_blocked(
            "E_HOLDOUT_STALE",
            relative,
            expected_sha256=expected,
            actual_sha256=actual,
        )
    return actual, None


def _holdout_contamination(accessed: list[str], relative: str) -> dict[str, Any] | None:
    if not accessed:
        return None
    return _holdout_blocked(
        "E_HOLDOUT_BUILDER_ACCESS", relative, builder_accessed_paths=accessed
    )


def _holdout_isolation(
    holdout: dict[str, Any], relative: str, in_workspace: bool, strict: bool
) -> dict[str, Any] | None:
    if strict and (holdout.get("isolation") != "external" or in_workspace):
        return _holdout_blocked("E_HOLDOUT_ISOLATION", relative)
    return None


def _holdout_identity(
    holdout: dict[str, Any], relative: str, strict: bool
) -> dict[str, Any] | None:
    if strict and not _is_sha256(holdout.get("sha256")):
        return _holdout_blocked("E_HOLDOUT_IDENTITY", relative)
    return None


def _holdout_scope(relative: str, in_workspace: bool) -> dict[str, Any] | None:
    if in_workspace and not relative.startswith(".factory/holdouts/"):
        return _holdout_blocked("E_HOLDOUT_SCOPE", relative)
    return None


def _holdout_verified(relative: str, actual: str, in_workspace: bool) -> dict[str, Any]:
    core = {
        "schema": HOLDOUT_SCHEMA,
        "marker": "HOLDOUT_BOUNDARY_VERIFIED",
        "state": "VERIFIED",
        "path": relative,
        "sha256": actual,
        "builder_accessed_paths": [],
        "isolation": "external" if not in_workspace else "workspace_verifier_only",
        "authority": "none",
        "claim_boundary": "Metadata verifies a verifier-only reference; host/filesystem isolation remains the harness responsibility.",
    }
    return {**core, "boundary_sha256": _sha(core)}


def _verify_holdout_target(
    holdout: dict[str, Any],
    resolved: Path,
    relative: str,
    in_workspace: bool,
    strict: bool,
) -> dict[str, Any]:
    unavailable = _holdout_availability(resolved, relative)
    if unavailable:
        return unavailable
    actual, stale = _holdout_digest(resolved, holdout, relative)
    if stale:
        return stale
    accessed = holdout.get("builder_accessed_paths", [])
    contaminated = _holdout_contamination(accessed, relative)
    if contaminated:
        return contaminated
    for failure in (
        _holdout_isolation(holdout, relative, in_workspace, strict),
        _holdout_identity(holdout, relative, strict),
        _holdout_scope(relative, in_workspace),
    ):
        if failure:
            return failure
    return _holdout_verified(relative, actual or "", in_workspace)


def verify_holdout_boundary(
    root: Path, holdout: dict[str, Any], *, strict: bool = False
) -> dict[str, Any]:
    """Verify verifier-only holdout metadata and fail closed on builder access."""
    workspace = Path(root).resolve()
    if not isinstance(holdout, dict):
        raise FirstLapError("E_HOLDOUT_SCHEMA", "holdout boundary must be an object")
    resolved, relative, in_workspace = _holdout_target(workspace, holdout.get("path"))
    _holdout_accessed(holdout)
    return _verify_holdout_target(holdout, resolved, relative, in_workspace, strict)


def _observation_blocked(
    code: str,
    *,
    observed_phases: list[Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": OBSERVED_SCHEMA,
        "marker": "FIRST_LAP_OBSERVATION_BLOCKED",
        "state": "BLOCKED",
        "code": code,
    }
    if observed_phases is not None:
        result["observed_phases"] = observed_phases
        result["required_phases"] = list(PHASES)
    result["authority"] = "none"
    return result


def _observation_phases(rows: list[Any]) -> list[Any] | None:
    names = [row.get("phase") if isinstance(row, dict) else None for row in rows]
    if names != list(PHASES):
        return names
    return None


def _observation_evidence_missing(rows: list[dict[str, Any]]) -> bool:
    return any(not _is_sha256(row.get("evidence_sha256")) for row in rows)


def _strict_observation_run_invalid(rows: list[dict[str, Any]]) -> bool:
    run_ids = {row.get("run_id") for row in rows}
    run_id = next(iter(run_ids)) if len(run_ids) == 1 else None
    return len(run_ids) != 1 or not isinstance(run_id, str) or not run_id.strip()


def _strict_observer_invalid(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        observer = row.get("observer_id")
        if (
            not isinstance(observer, str)
            or not observer.strip()
            or observer.strip().lower() in {"agent", "automation", "unknown"}
            or not _is_iso8601(row.get("observed_at"))
            or not isinstance(row.get("action"), str)
            or not row["action"].strip()
        ):
            return True
    return False


def _observation_core(rows: list[dict[str, Any]], strict: bool) -> dict[str, Any]:
    phases = []
    for row in rows:
        phase = {
            "phase": row["phase"],
            "evidence_sha256": row["evidence_sha256"],
        }
        if strict:
            phase.update(
                {
                    "run_id": row["run_id"],
                    "observer_id": row["observer_id"],
                    "observed_at": row["observed_at"],
                    "action": row["action"],
                }
            )
        phases.append(phase)
    core = {
        "schema": OBSERVED_SCHEMA,
        "marker": "FIRST_LAP_OBSERVED",
        "state": "OBSERVED",
        "phases": phases,
        "human_observer": True,
        "authority": {"approval": False, "release": False, "autonomy_grant": False},
    }
    if strict:
        core["strict_observation"] = True
    return core


def verify_observed_first_lap(
    events: Iterable[dict[str, Any]], *, strict: bool = False
) -> dict[str, Any]:
    """Require exactly one ordered, human-observed lifecycle."""
    rows = list(events)
    names = _observation_phases(rows)
    if names is not None:
        return _observation_blocked("E_FIRST_LAP_SEQUENCE", observed_phases=names)
    if _observation_evidence_missing(rows):
        return _observation_blocked("E_FIRST_LAP_EVIDENCE")
    if strict:
        if _strict_observation_run_invalid(rows):
            return _observation_blocked("E_FIRST_LAP_RUN_ID")
        if _strict_observer_invalid(rows):
            return _observation_blocked("E_FIRST_LAP_OBSERVER")
    core = _observation_core(rows, strict)
    return {**core, "observation_sha256": _sha(core)}


def _validate_failure_kind(kind: str) -> str:
    normalized = _text(kind, "failure_kind", 64).lower()
    if normalized not in FAILURE_CLASSES:
        raise FirstLapError(
            "E_FAILURE_CLASS", f"unsupported failure class: {normalized}"
        )
    return normalized


def _validate_retry_after(retry_after_seconds: int | None) -> None:
    if retry_after_seconds is not None and (
        isinstance(retry_after_seconds, bool)
        or not isinstance(retry_after_seconds, int)
        or not 1 <= retry_after_seconds <= 3600
    ):
        raise FirstLapError("E_FAILURE_RETRY", "retry_after_seconds must be 1-3600")


def _validate_provider_retry(
    normalized: str,
    provider: str | None,
    retry_after_seconds: int | None,
    strict: bool,
) -> None:
    if (
        strict
        and normalized == "transient_provider_failure"
        and (
            not isinstance(provider, str)
            or not provider.strip()
            or retry_after_seconds is None
        )
    ):
        raise FirstLapError(
            "E_FAILURE_PROVIDER",
            "transient provider failures require provider and bounded retry_after_seconds",
        )


def _failure_core(
    normalized: str, provider: str | None, retry_after_seconds: int | None
) -> dict[str, Any]:
    provider_name = (
        provider.strip() if isinstance(provider, str) and provider.strip() else None
    )
    retry_allowed = normalized in RETRYABLE
    return {
        "schema": FAILURE_SCHEMA,
        "failure_class": normalized,
        "provider": provider_name,
        "retry_allowed": retry_allowed,
        "retry_after_seconds": retry_after_seconds if retry_allowed else None,
        "authority": "none",
        "claim_boundary": "Classification is a retry policy hint; it does not prove provider health or product correctness.",
    }


def classify_failure(
    kind: str,
    *,
    provider: str | None = None,
    retry_after_seconds: int | None = None,
    strict: bool = False,
) -> dict[str, Any]:
    """Normalize failure taxonomy; only transient provider failures retry."""
    normalized = _validate_failure_kind(kind)
    _validate_retry_after(retry_after_seconds)
    _validate_provider_retry(normalized, provider, retry_after_seconds, strict)
    core = _failure_core(normalized, provider, retry_after_seconds)
    return {**core, "classification_sha256": _sha(core)}


def _activation_reasons(
    root: Path,
    calibration: dict[str, Any],
    holdout: dict[str, Any],
    observed: dict[str, Any],
    strict: bool,
) -> list[str]:
    reasons = []
    if calibration.get("state") != "CALIBRATED":
        reasons.append("verifier calibration is not complete")
    if holdout.get("state") != "VERIFIED":
        reasons.append("holdout boundary is not verified")
    if observed.get("state") != "OBSERVED":
        reasons.append("human-observed first lap is not complete")
    if strict:
        reasons.extend(_strict_activation_reasons(root, calibration, holdout, observed))
    return reasons


def _strict_activation_reasons(
    root: Path,
    calibration: dict[str, Any],
    holdout: dict[str, Any],
    observed: dict[str, Any],
) -> list[str]:
    reasons = []
    if not calibration.get("identity_bound"):
        reasons.append("calibration is not identity-bound")
    if holdout.get("isolation") != "external":
        reasons.append("holdout is not externally isolated")
    if not observed.get("strict_observation"):
        reasons.append("observation lacks a named human run record")
    if verify_promoted_incident_gates(root).get("state") != "VERIFIED":
        reasons.append("promoted incident regression gate is invalid")
    return reasons


def _activation_blocked(reasons: list[str]) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "marker": "FIRST_LAP_ACTIVATION_BLOCKED",
        "state": "BLOCKED",
        "code": "E_FIRST_LAP_ACTIVATION",
        "reasons": reasons,
        "authority": "none",
    }


def _activation_core(
    calibration: dict[str, Any],
    holdout: dict[str, Any],
    observed: dict[str, Any],
    strict: bool,
) -> dict[str, Any]:
    return {
        "schema": ACTIVATION_SCHEMA,
        "marker": "FIRST_LAP_ACTIVATION_READY",
        "state": "READY",
        "calibration_sha256": calibration.get("calibration_sha256"),
        "holdout_boundary_sha256": holdout.get("boundary_sha256"),
        "observation_sha256": observed.get("observation_sha256"),
        "strict": strict,
        "authority": {
            "autonomy": "supervised",
            "release": False,
            "merge": False,
            "publication": False,
            "deployment": False,
        },
    }


def verify_activation(
    root: Path,
    *,
    calibration: dict[str, Any],
    holdout: dict[str, Any],
    observed: dict[str, Any],
    strict: bool = False,
    persist: bool = False,
) -> dict[str, Any]:
    """Compose the mandatory activation gate from all first-lap controls.

    Strict activation is the only form accepted by autonomous admission.  It
    requires identity-bound calibration, an externally isolated holdout, and a
    run-specific human observation.  When ``persist`` is requested the signed
    projection is written immutably so later admission checks can re-verify it.
    """
    reasons = _activation_reasons(root, calibration, holdout, observed, strict)
    if reasons:
        return _activation_blocked(reasons)
    core = _activation_core(calibration, holdout, observed, strict)
    result = {**core, "receipt_sha256": _sha(core), "generated_at": _now()}
    if persist:
        path = Path(root).resolve() / ".factory" / "first-lap" / "activation.json"
        _atomic_json(path, result)
        result["path"] = path.relative_to(Path(root).resolve()).as_posix()
    return result


def verify_activation_receipt(
    root: Path, *, require_strict: bool = True
) -> dict[str, Any]:
    """Verify the immutable activation receipt used by autonomous admission."""
    workspace = Path(root).resolve()
    path = workspace / ".factory" / "first-lap" / "activation.json"
    if not path.is_file():
        return {
            "schema": ACTIVATION_SCHEMA,
            "marker": "FIRST_LAP_ACTIVATION_BLOCKED",
            "state": "BLOCKED",
            "code": "E_FIRST_LAP_ACTIVATION_MISSING",
            "authority": "none",
        }
    try:
        receipt = _json(path)
    except FirstLapError as exc:
        return {
            "schema": ACTIVATION_SCHEMA,
            "marker": "FIRST_LAP_ACTIVATION_BLOCKED",
            "state": "BLOCKED",
            "code": exc.code,
            "authority": "none",
        }
    expected = receipt.get("receipt_sha256")
    body = {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_sha256", "generated_at", "path"}
    }
    if not _is_sha256(expected) or _sha(body) != expected:
        return {
            "schema": ACTIVATION_SCHEMA,
            "marker": "FIRST_LAP_ACTIVATION_BLOCKED",
            "state": "BLOCKED",
            "code": "E_FIRST_LAP_ACTIVATION_TAMPERED",
            "authority": "none",
        }
    if receipt.get("state") != "READY" or (
        require_strict and receipt.get("strict") is not True
    ):
        return {
            "schema": ACTIVATION_SCHEMA,
            "marker": "FIRST_LAP_ACTIVATION_BLOCKED",
            "state": "BLOCKED",
            "code": "E_FIRST_LAP_ACTIVATION_NOT_STRICT",
            "authority": "none",
        }
    return {**receipt, "path": path.relative_to(workspace).as_posix(), "verified": True}
