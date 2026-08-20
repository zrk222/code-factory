"""Deterministic evidence-delta admission for supervised mission retries.

Proof Delta does not run a model, apply a repair, or decide that a candidate is
correct.  It proves a much narrower condition: a proposed retry is bound to the
last failed criterion and contains a new, hash-checked evidence reference plus
a different candidate diff.  The native Mission Graph still requires a fresh
worker context and an independent validator after the retry.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .product_missions import verify_mission


PROOF_DELTA_SCHEMA = "factory.mission.proof-delta.v1"
CANDIDATE_SCHEMA = "factory.mission.candidate.v1"
VALIDATION_FAILURE_SCHEMA = "factory.mission.validation-failure.v1"
MAX_SOURCE_BYTES = 1_048_576
MAX_EVIDENCE = 50
_SHA = re.compile(r"^[a-f0-9]{64}$")
_PATH = re.compile(r"^[^\x00\r\n]{1,512}$")
_EVIDENCE_KINDS = frozenset({"counterexample", "test_result", "trace", "proof_receipt", "external_artifact"})
_AUTHORITY = {
    "execution": False,
    "repair": False,
    "source_write": False,
    "approval": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class ProofDeltaError(ValueError):
    """Stable fail-closed error for a malformed or stale proof-delta receipt."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProofDeltaError("PROOF_DELTA_INVALID", f"receipt must be canonical JSON: {exc}") from exc


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _relative(root: Path, value: Path | str, field: str, *, exists: bool = True) -> tuple[Path, str]:
    raw = Path(value)
    path = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ProofDeltaError("PROOF_DELTA_PATH_OUTSIDE_ROOT", f"{field} must stay inside the workspace") from exc
    if not _PATH.fullmatch(relative) or relative.startswith("../"):
        raise ProofDeltaError("PROOF_DELTA_PATH_INVALID", f"{field} path is invalid")
    if exists and (not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES):
        raise ProofDeltaError("PROOF_DELTA_SOURCE_INVALID", f"{field} must be a readable file at most {MAX_SOURCE_BYTES} bytes")
    return path, relative


def _load_json(path: Path, field: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofDeltaError("PROOF_DELTA_SOURCE_INVALID", f"{field} must be readable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ProofDeltaError("PROOF_DELTA_SOURCE_INVALID", f"{field} must contain one JSON object")
    return value


def _reference(root: Path, value: Path | str, field: str) -> tuple[dict[str, str], dict[str, Any]]:
    path, relative = _relative(root, value, field)
    return {"path": relative, "sha256": _sha_bytes(path.read_bytes())}, _load_json(path, field)


def _sha_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ProofDeltaError("PROOF_DELTA_INVALID", f"{field} must be a lowercase SHA-256")
    return value


def _changed_paths(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ProofDeltaError("PROOF_DELTA_CANDIDATE_INVALID", f"{field} must contain at least one workspace-relative path")
    paths: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _PATH.fullmatch(item) or Path(item).is_absolute() or ".." in Path(item).parts:
            raise ProofDeltaError("PROOF_DELTA_CANDIDATE_INVALID", f"{field} contains an invalid workspace-relative path")
        paths.append(Path(item).as_posix())
    if paths != sorted(set(paths)):
        raise ProofDeltaError("PROOF_DELTA_CANDIDATE_INVALID", f"{field} must be sorted and unique")
    return paths


def _evidence(root: Path, value: object, field: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_EVIDENCE:
        raise ProofDeltaError("PROOF_DELTA_EVIDENCE_INVALID", f"{field} must contain 1 to {MAX_EVIDENCE} evidence references")
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "kind"}:
            raise ProofDeltaError("PROOF_DELTA_EVIDENCE_INVALID", f"{field}[{index}] must contain path, sha256, and kind")
        kind = item.get("kind")
        if kind not in _EVIDENCE_KINDS:
            raise ProofDeltaError("PROOF_DELTA_EVIDENCE_INVALID", f"{field}[{index}].kind is unsupported")
        path, relative = _relative(root, str(item.get("path", "")), f"{field}[{index}]")
        digest = _sha_text(item.get("sha256"), f"{field}[{index}].sha256")
        if _sha_bytes(path.read_bytes()) != digest:
            raise ProofDeltaError("PROOF_DELTA_EVIDENCE_STALE", f"{field}[{index}] bytes do not match sha256")
        key = (relative, digest)
        if key in seen:
            raise ProofDeltaError("PROOF_DELTA_EVIDENCE_INVALID", f"{field} must not repeat an evidence reference")
        seen.add(key)
        rows.append({"path": relative, "sha256": digest, "kind": str(kind)})
    return sorted(rows, key=lambda item: (item["path"], item["sha256"], item["kind"]))


def _candidate(root: Path, reference: dict[str, str], mission_id: str, field: str) -> dict[str, Any]:
    if set(reference) != {"path", "sha256"}:
        raise ProofDeltaError("PROOF_DELTA_INVALID", f"{field} reference must contain path and sha256")
    path, relative = _relative(root, reference["path"], field)
    digest = _sha_text(reference["sha256"], f"{field}.sha256")
    if _sha_bytes(path.read_bytes()) != digest:
        raise ProofDeltaError("PROOF_DELTA_SOURCE_STALE", f"{field} receipt bytes changed")
    value = _load_json(path, field)
    if value.get("schema") != CANDIDATE_SCHEMA or value.get("mission_id") != mission_id:
        raise ProofDeltaError("PROOF_DELTA_CANDIDATE_INVALID", f"{field} must be a mission-bound candidate receipt")
    candidate = value.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {"diff_sha256", "changed_paths"}:
        raise ProofDeltaError("PROOF_DELTA_CANDIDATE_INVALID", f"{field}.candidate must contain diff_sha256 and changed_paths")
    return {
        "path": relative,
        "sha256": digest,
        "candidate": {
            "diff_sha256": _sha_text(candidate.get("diff_sha256"), f"{field}.candidate.diff_sha256"),
            "changed_paths": _changed_paths(candidate.get("changed_paths"), f"{field}.candidate.changed_paths"),
        },
        "evidence": _evidence(root, value.get("evidence"), f"{field}.evidence"),
    }


def _failure(root: Path, reference: dict[str, str], mission_id: str) -> dict[str, str]:
    if set(reference) != {"path", "sha256"}:
        raise ProofDeltaError("PROOF_DELTA_INVALID", "failure reference must contain path and sha256")
    path, relative = _relative(root, reference["path"], "failure")
    digest = _sha_text(reference["sha256"], "failure.sha256")
    if _sha_bytes(path.read_bytes()) != digest:
        raise ProofDeltaError("PROOF_DELTA_SOURCE_STALE", "failure receipt bytes changed")
    value = _load_json(path, "failure")
    if value.get("schema") != VALIDATION_FAILURE_SCHEMA or value.get("mission_id") != mission_id:
        raise ProofDeltaError("PROOF_DELTA_FAILURE_INVALID", "failure must be a mission-bound validation failure receipt")
    return {"path": relative, "sha256": digest}


def _mission(root: Path, reference: dict[str, str], mission_id: str) -> dict[str, str]:
    if set(reference) != {"path", "mission_sha256"}:
        raise ProofDeltaError("PROOF_DELTA_INVALID", "mission reference must contain path and mission_sha256")
    path, relative = _relative(root, reference["path"], "mission")
    expected = _sha_text(reference["mission_sha256"], "mission.mission_sha256")
    verification = verify_mission(path)
    if not verification.get("valid"):
        raise ProofDeltaError("PROOF_DELTA_MISSION_INVALID", "; ".join(verification.get("errors", ["mission verification failed"])))
    value = _load_json(path, "mission")
    if value.get("id") != mission_id or value.get("mission_sha256") != expected:
        raise ProofDeltaError("PROOF_DELTA_MISSION_INVALID", "mission identity or hash does not match the receipt")
    return {"path": relative, "mission_sha256": expected}


def _new_evidence(prior: list[dict[str, str]], repair: list[dict[str, str]]) -> list[dict[str, str]]:
    previous = {(item["path"], item["sha256"]) for item in prior}
    return [item for item in repair if (item["path"], item["sha256"]) not in previous]


def _reason(disposition: str) -> str:
    return (
        "The repair candidate changes the bound diff and contributes at least one new hash-checked evidence reference. Independent validation remains required."
        if disposition == "advance"
        else "No new evidence gain is bound to this repair candidate. Keep the mission paused or revise the evidence packet; do not spend another retry."
    )


def _core(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "proof_delta_sha256"}


def _mission_identity(root: Path, mission_path: Path) -> tuple[dict[str, str], dict[str, Any], str]:
    reference, mission_value = _reference(root, mission_path, "mission")
    mission_id = mission_value.get("id")
    mission_sha = mission_value.get("mission_sha256")
    if not isinstance(mission_id, str) or not mission_id or not isinstance(mission_sha, str) or not _SHA.fullmatch(mission_sha):
        raise ProofDeltaError("PROOF_DELTA_MISSION_INVALID", "mission must have an id and mission_sha256")
    return {"path": reference["path"], "mission_sha256": mission_sha}, mission_value, mission_id


def _require_criterion(mission: dict[str, Any], criterion_id: str) -> None:
    if not isinstance(criterion_id, str) or not criterion_id or len(criterion_id) > 120:
        raise ProofDeltaError("PROOF_DELTA_CRITERION_INVALID", "criterion_id must contain 1 to 120 characters")
    criteria = mission.get("completion_contract", {}).get("criteria", [])
    if criterion_id not in {item.get("id") for item in criteria if isinstance(item, dict)}:
        raise ProofDeltaError("PROOF_DELTA_CRITERION_INVALID", "criterion_id is not declared by the mission completion contract")


def _candidate_from_path(root: Path, path: Path, mission_id: str, field: str) -> dict[str, Any]:
    reference, _ = _reference(root, path, field)
    return _candidate(root, reference, mission_id, field)


def _failure_from_path(root: Path, path: Path, mission_id: str) -> dict[str, str]:
    reference, _ = _reference(root, path, "failure")
    return _failure(root, reference, mission_id)


def _delta_marker(disposition: str) -> str:
    return "PROOF_DELTA_ADVANCE" if disposition == "advance" else "PROOF_DELTA_NO_EVIDENCE_GAIN"


def _write_delta(root: Path, out: Path, result: dict[str, Any], disposition: str) -> dict[str, Any]:
    path, _ = _relative(root, out, "out", exists=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = _canonical(result)
    if path.exists():
        try:
            if path.read_bytes() == encoded:
                return {"path": str(path), **result, "marker": _delta_marker(disposition), "idempotent": True}
        except OSError as exc:
            raise ProofDeltaError("PROOF_DELTA_WRITE_FAILED", f"cannot read existing receipt: {exc}") from exc
        raise ProofDeltaError("PROOF_DELTA_ARTIFACT_EXISTS", f"refusing to replace {path}")
    try:
        path.write_bytes(encoded)
    except OSError as exc:
        raise ProofDeltaError("PROOF_DELTA_WRITE_FAILED", f"cannot write receipt: {exc}") from exc
    return {"path": str(path), **result, "marker": _delta_marker(disposition), "idempotent": False}


def create_proof_delta(root: Path, mission_path: Path, prior_candidate_path: Path,
                       repair_candidate_path: Path, failure_path: Path, criterion_id: str,
                       out: Path) -> dict[str, Any]:
    """Write a deterministic retry-admission receipt without invoking a worker."""
    workspace = Path(root).resolve()
    mission, mission_value, mission_id = _mission_identity(workspace, mission_path)
    _require_criterion(mission_value, criterion_id)
    prior = _candidate_from_path(workspace, prior_candidate_path, mission_id, "prior_candidate")
    repair = _candidate_from_path(workspace, repair_candidate_path, mission_id, "repair_candidate")
    failure = _failure_from_path(workspace, failure_path, mission_id)
    changed = repair["candidate"]["diff_sha256"] != prior["candidate"]["diff_sha256"]
    new_evidence = _new_evidence(prior["evidence"], repair["evidence"])
    disposition = "advance" if changed and new_evidence else "halt"
    core = {
        "schema": PROOF_DELTA_SCHEMA,
        "mission_id": mission_id,
        "mission": mission,
        "criterion_id": criterion_id,
        "failure": failure,
        "prior_candidate": prior,
        "repair_candidate": repair,
        "new_evidence": new_evidence,
        "fresh_context_required": True,
        "disposition": disposition,
        "reason": _reason(disposition),
        "authority": _AUTHORITY,
        "markers": ["PROOF_DELTA_HASH_BOUND", "PROOF_DELTA_FRESH_CONTEXT_REQUIRED", "PROOF_DELTA_INDEPENDENT_VALIDATION_REQUIRED"],
    }
    result = {**core, "proof_delta_sha256": _sha(core)}
    return _write_delta(workspace, out, result, disposition)


def _load_delta(path: Path) -> dict[str, Any]:
    value = _load_json(path, "proof_delta")
    required = {
        "schema", "mission_id", "mission", "criterion_id", "failure", "prior_candidate", "repair_candidate",
        "new_evidence", "fresh_context_required", "disposition", "reason", "authority", "markers", "proof_delta_sha256",
    }
    if set(value) != required or value.get("schema") != PROOF_DELTA_SCHEMA:
        raise ProofDeltaError("PROOF_DELTA_INVALID", f"receipt must contain exactly the {PROOF_DELTA_SCHEMA} fields")
    if not isinstance(value.get("mission_id"), str) or not value["mission_id"]:
        raise ProofDeltaError("PROOF_DELTA_INVALID", "mission_id is required")
    if not isinstance(value.get("criterion_id"), str) or not value["criterion_id"]:
        raise ProofDeltaError("PROOF_DELTA_INVALID", "criterion_id is required")
    if value.get("fresh_context_required") is not True or value.get("authority") != _AUTHORITY:
        raise ProofDeltaError("PROOF_DELTA_INVALID", "fresh context and retained authority are required")
    if value.get("markers") != ["PROOF_DELTA_HASH_BOUND", "PROOF_DELTA_FRESH_CONTEXT_REQUIRED", "PROOF_DELTA_INDEPENDENT_VALIDATION_REQUIRED"]:
        raise ProofDeltaError("PROOF_DELTA_INVALID", "markers do not match the fixed Proof-Delta boundary")
    if value.get("proof_delta_sha256") != _sha(_core(value)):
        raise ProofDeltaError("PROOF_DELTA_INTEGRITY_INVALID", "proof_delta_sha256 does not match receipt bytes")
    return value


def _current_delta_inputs(workspace: Path, value: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any], dict[str, Any], dict[str, Any]]:
    mission = _mission(workspace, value["mission"], value["mission_id"])
    criteria = _load_json((workspace / mission["path"]).resolve(), "mission").get("completion_contract", {}).get("criteria", [])
    if value["criterion_id"] not in {item.get("id") for item in criteria if isinstance(item, dict)}:
        raise ProofDeltaError("PROOF_DELTA_CRITERION_INVALID", "criterion_id is not declared by the current mission")
    failure = _failure(workspace, value["failure"], value["mission_id"])
    prior_reference = {key: value["prior_candidate"].get(key) for key in ("path", "sha256")} if isinstance(value.get("prior_candidate"), dict) else {}
    repair_reference = {key: value["repair_candidate"].get(key) for key in ("path", "sha256")} if isinstance(value.get("repair_candidate"), dict) else {}
    prior = _candidate(workspace, prior_reference, value["mission_id"], "prior_candidate")
    repair = _candidate(workspace, repair_reference, value["mission_id"], "repair_candidate")
    return failure, prior, repair, mission


def _validate_delta_evidence(value: dict[str, Any], prior: dict[str, Any], repair: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    if value["prior_candidate"] != prior or value["repair_candidate"] != repair:
        raise ProofDeltaError("PROOF_DELTA_INTEGRITY_INVALID", "candidate bindings do not match current candidate receipts")
    expected_new = _new_evidence(prior["evidence"], repair["evidence"])
    if value["new_evidence"] != expected_new:
        raise ProofDeltaError("PROOF_DELTA_INTEGRITY_INVALID", "new_evidence does not equal the candidate evidence delta")
    changed = repair["candidate"]["diff_sha256"] != prior["candidate"]["diff_sha256"]
    expected = "advance" if changed and expected_new else "halt"
    if value.get("disposition") != expected or value.get("reason") != _reason(expected):
        raise ProofDeltaError("PROOF_DELTA_INTEGRITY_INVALID", "disposition does not match bound evidence")
    return expected, expected_new


def verify_proof_delta(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify one Proof-Delta receipt and report whether it admits a retry."""
    workspace = Path(root).resolve()
    path, relative = _relative(workspace, receipt_path, "proof_delta")
    value = _load_delta(path)
    failure, prior, repair, _mission_value = _current_delta_inputs(workspace, value)
    expected, expected_new = _validate_delta_evidence(value, prior, repair)
    return {
        "schema": "factory.mission.proof-delta.verification.v1",
        "valid": True,
        "eligible": expected == "advance",
        "marker": "PROOF_DELTA_ADVANCE" if expected == "advance" else "PROOF_DELTA_NO_EVIDENCE_GAIN",
        "path": relative,
        "mission_id": value["mission_id"],
        "criterion_id": value["criterion_id"],
        "failure": failure,
        "prior_candidate": prior,
        "repair_candidate": repair,
        "new_evidence": expected_new,
        "reason": value["reason"],
        "proof_delta_sha256": value["proof_delta_sha256"],
        "authority": _AUTHORITY,
    }


def proof_delta_status(root: Path, mission_id: str | None = None) -> dict[str, Any]:
    """Read the newest local Proof-Delta receipt without admitting or running work."""
    workspace = Path(root).resolve()
    directory = workspace / ".factory" / "proof-deltas"
    rows: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            verification = verify_proof_delta(workspace, path)
        except ProofDeltaError as exc:
            rows.append({"path": path.relative_to(workspace).as_posix(), "valid": False, "marker": exc.code, "message": exc.message})
            continue
        if mission_id is None or verification["mission_id"] == mission_id:
            rows.append(verification)
    if not rows:
        return {"schema": "factory.mission.proof-delta.status.v1", "found": False, "marker": "PROOF_DELTA_REQUIRED", "authority": _AUTHORITY}
    latest = rows[-1]
    return {
        "schema": "factory.mission.proof-delta.status.v1",
        "found": True,
        "marker": latest.get("marker", "PROOF_DELTA_INVALID"),
        "latest": latest,
        "receipt_count": len(rows),
        "authority": _AUTHORITY,
        "scope": "Read-only local evidence projection; this status never starts an agent, applies a repair, or authorizes release work.",
    }
