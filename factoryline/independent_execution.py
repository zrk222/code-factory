"""Verify independently collected execution attestations.

The worker that produces an attestation is deliberately outside this module.
Factory Line authenticates a bounded observation and its bindings; it does not
pretend that a local process is a sandbox or grant release authority.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from .enterprise_receipts import EnterpriseReceiptError, verify_signed_document
from .runtime_audit_common import (
    canonical_bytes,
    exact_keys,
    reject_secret_material,
    require_bool,
    require_digest,
    require_int,
    require_str,
)


SCHEMA = "factory.execution-attestation.v1"
PAYLOAD_TYPE = "application/vnd.factory.execution-attestation.v1+json"
ASSURANCE_LEVELS = ("supervised_local", "isolated_worker", "hardened_vm")
INDEPENDENT_LEVELS = {"isolated_worker", "hardened_vm"}
BACKENDS = {"local_supervised", "external_collector", "isolated_worker", "hardened_vm"}
COMPATIBLE_BACKENDS = {
    "supervised_local": {"local_supervised", "external_collector"},
    "isolated_worker": {"isolated_worker"},
    "hardened_vm": {"hardened_vm"},
}
_HEX = re.compile(r"^[0-9a-f]{64}$")


class ExecutionAttestationError(ValueError):
    """Stable, fail-closed validation error for an observation attestation."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ExecutionAttestationError("E_ATTESTATION_TIME", f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutionAttestationError("E_ATTESTATION_TIME", f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise ExecutionAttestationError("E_ATTESTATION_TIME", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _digest_or_null(value: object, field: str) -> str | None:
    if value is None:
        return None
    return require_digest(value, field)


def _exact(value: dict[str, Any], required: set[str], code: str) -> None:
    try:
        exact_keys(value, required)
    except Exception as exc:
        raise ExecutionAttestationError(code, str(exc)) from exc


def _validate_identity(value: dict[str, Any]) -> tuple[str, str, str, str, str]:
    if not isinstance(value, dict):
        raise ExecutionAttestationError("E_ATTESTATION_RUNNER", "runner must be an object")
    _exact(value, {"id", "version", "platform", "backend", "executable_sha256"}, "E_ATTESTATION_RUNNER")
    runner_id = require_str(value.get("id"), "runner.id", maximum=160)
    version = require_str(value.get("version"), "runner.version", maximum=80)
    platform = require_str(value.get("platform"), "runner.platform", maximum=80)
    backend = value.get("backend")
    if backend not in BACKENDS:
        raise ExecutionAttestationError("E_ATTESTATION_RUNNER", "unsupported runner backend")
    executable = require_digest(value.get("executable_sha256"), "runner.executable_sha256")
    return runner_id, version, platform, backend, executable


def _validate_observations(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExecutionAttestationError("E_ATTESTATION_INCOMPLETE", "observations must be an object")
    _exact(value, {"target_artifact_sha256", "known_bad_artifact_sha256", "target_stdout_sha256", "target_stderr_sha256", "cleanup_confirmed", "memory_peak_bytes", "latency_ms"}, "E_ATTESTATION_INCOMPLETE")
    target = _digest_or_null(value.get("target_artifact_sha256"), "observations.target_artifact_sha256")
    known_bad = _digest_or_null(value.get("known_bad_artifact_sha256"), "observations.known_bad_artifact_sha256")
    if target is None or known_bad is None:
        raise ExecutionAttestationError("E_ATTESTATION_INCOMPLETE", "target and known-bad artifact digests are required")
    cleanup = require_bool(value.get("cleanup_confirmed"), "observations.cleanup_confirmed")
    if not cleanup:
        raise ExecutionAttestationError("E_ATTESTATION_INCOMPLETE", "cleanup must be confirmed")
    memory = value.get("memory_peak_bytes")
    latency = value.get("latency_ms")
    if memory is not None:
        memory = require_int(memory, "observations.memory_peak_bytes", minimum=0, maximum=2**63 - 1)
    if latency is not None:
        latency = require_int(latency, "observations.latency_ms", minimum=0, maximum=2**63 - 1)
    return {"target_artifact_sha256": target, "known_bad_artifact_sha256": known_bad, "target_stdout_sha256": _digest_or_null(value.get("target_stdout_sha256"), "observations.target_stdout_sha256"), "target_stderr_sha256": _digest_or_null(value.get("target_stderr_sha256"), "observations.target_stderr_sha256"), "cleanup_confirmed": cleanup, "memory_peak_bytes": memory, "latency_ms": latency}


def _validate_header(value: dict[str, Any], *, candidate_sha256: str | None, plan_sha256: str | None, now: datetime | None, seen_nonces: Iterable[str], require_independent: bool) -> tuple[str, str, str, str, datetime, datetime, str]:
    if value.get("schema") != SCHEMA:
        raise ExecutionAttestationError("E_ATTESTATION_SCHEMA", f"schema must be {SCHEMA}")
    attestation_id = require_str(value.get("attestation_id"), "attestation_id", maximum=160)
    candidate = require_digest(value.get("candidate_sha256"), "candidate_sha256")
    plan = require_digest(value.get("plan_sha256"), "plan_sha256")
    expected_candidate = require_digest(candidate_sha256, "candidate_sha256 expectation") if candidate_sha256 is not None else None
    expected_plan = require_digest(plan_sha256, "plan_sha256 expectation") if plan_sha256 is not None else None
    if expected_candidate is not None and candidate != expected_candidate or expected_plan is not None and plan != expected_plan:
        raise ExecutionAttestationError("E_ATTESTATION_BINDING", "candidate or plan digest differs from the expected contract")
    nonce = require_str(value.get("run_nonce"), "run_nonce", maximum=160)
    if nonce in set(seen_nonces):
        raise ExecutionAttestationError("E_ATTESTATION_REPLAY", "run nonce has already been observed")
    issued = _timestamp(value.get("issued_at"), "issued_at")
    expires = _timestamp(value.get("expires_at"), "expires_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires <= issued or expires - issued > timedelta(hours=24):
        raise ExecutionAttestationError("E_ATTESTATION_TIME", "expiry must be after issue and within 24 hours")
    if expires <= current:
        raise ExecutionAttestationError("E_ATTESTATION_FRESHNESS", "attestation is expired")
    assurance = value.get("assurance_level")
    if assurance not in ASSURANCE_LEVELS or require_independent and assurance not in INDEPENDENT_LEVELS:
        raise ExecutionAttestationError("E_ATTESTATION_ASSURANCE", "independent assurance is required")
    if value.get("authority") != "none":
        raise ExecutionAttestationError("E_ATTESTATION_AUTHORITY", "execution attestations cannot carry authority")
    return attestation_id, candidate, plan, nonce, issued, expires, assurance


def validate_execution_attestation(
    value: dict[str, Any],
    *,
    candidate_sha256: str | None = None,
    plan_sha256: str | None = None,
    now: datetime | None = None,
    seen_nonces: Iterable[str] = (),
    require_independent: bool = True,
) -> dict[str, Any]:
    """Validate one exact, bounded execution observation without trusting it for release."""
    if not isinstance(value, dict):
        raise ExecutionAttestationError("E_ATTESTATION_SCHEMA", "attestation must be an object")
    reject_secret_material(value, path="attestation")
    _exact(value, {"schema", "attestation_id", "candidate_sha256", "plan_sha256", "run_nonce", "issued_at", "expires_at", "assurance_level", "runner", "observations", "authority"}, "E_ATTESTATION_SCHEMA")
    attestation_id, candidate, plan, nonce, issued, expires, assurance = _validate_header(value, candidate_sha256=candidate_sha256, plan_sha256=plan_sha256, now=now, seen_nonces=seen_nonces, require_independent=require_independent)
    runner_id, version, platform, backend, executable = _validate_identity(value["runner"])
    allowed_backends = COMPATIBLE_BACKENDS[assurance]
    if backend not in allowed_backends:
        raise ExecutionAttestationError("E_ATTESTATION_BACKEND", "runner backend is incompatible with assurance level")
    observations = _validate_observations(value["observations"])
    return {
        "schema": SCHEMA,
        "attestation_id": attestation_id,
        "candidate_sha256": candidate,
        "plan_sha256": plan,
        "run_nonce": nonce,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "assurance_level": assurance,
        "runner": {"id": runner_id, "version": version, "platform": platform, "backend": backend, "executable_sha256": executable},
        "observations": observations,
        "authority": "none",
    }


def verify_signed_execution_attestation(
    path: Path,
    trust_root_path: Path,
    *,
    candidate_sha256: str | None = None,
    plan_sha256: str | None = None,
    now: datetime | None = None,
    seen_nonces: Iterable[str] = (),
    revoked_keyids: Iterable[str] = (),
    revoked_identities: Iterable[str] = (),
) -> dict[str, Any]:
    """Verify a DSSE-signed attestation and return a review-only receipt."""
    try:
        verified = verify_signed_document(Path(path), payload_type=PAYLOAD_TYPE, schema=SCHEMA, trust_root_path=Path(trust_root_path))
    except EnterpriseReceiptError as exc:
        raise ExecutionAttestationError(exc.code, exc.message) from exc
    signature = verified["signature"]
    if signature.get("keyid") in set(revoked_keyids) or signature.get("identity") in set(revoked_identities):
        raise ExecutionAttestationError("E_ATTESTATION_REVOKED", "attestation signer is revoked")
    payload = validate_execution_attestation(verified["payload"], candidate_sha256=candidate_sha256, plan_sha256=plan_sha256, now=now, seen_nonces=seen_nonces)
    digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return {"schema": "factory.execution-attestation-verification.v1", "state": "VERIFIED", "verification": "offline_dsse_ed25519", "attestation_id": payload["attestation_id"], "attestation_sha256": digest, "keyid": signature["keyid"], "identity": signature["identity"], "issuer": signature["issuer"], "assurance_level": payload["assurance_level"], "authority": "none", "release_approval": False}
