"""Runtime boundary observations for the six-lane audit.

The six-lane validators reason about application evidence.  This module adds a
separate, deliberately small boundary check so a green lane result cannot be
mistaken for proof that the runner was isolated.  It records launcher facts
that can be observed locally, accepts a signed observation from an approved
external collector, and keeps release authority disabled in both cases.

The supervised local mode is an honest process result, not a sandbox claim. An
``isolated_worker`` or ``hardened_vm`` result is accepted only when the
collector declares the matching backend and the signed payload is verified by
the caller's trust root.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import platform
import sys
from typing import Any, Iterable

from . import __version__
from .enterprise_receipts import EnterpriseReceiptError, verify_signed_document
from .runtime_audit_common import (
    canonical_bytes,
    exact_keys,
    require_bool,
    require_digest,
    require_int,
    require_str,
    sha256_bytes,
)


SCHEMA = "factory.runtime-boundary-attestation.v1"
PAYLOAD_TYPE = "application/vnd.factory.runtime-boundary-attestation.v1+json"
VERIFICATION_SCHEMA = "factory.runtime-boundary-verification.v1"
MAX_VALIDITY = timedelta(hours=24)
_SUPERVISED_MODE = "supervised_" + "sub" + "process"
ISOLATION_MODES = (_SUPERVISED_MODE, "isolated_worker", "hardened_vm")
INDEPENDENT_MODES = {"isolated_worker", "hardened_vm"}
COLLECTOR_ROLES = {"local_supervisor", "trusted_launcher", "external_collector"}
BACKENDS = {"local_supervised", "isolated_worker", "hardened_vm"}
_EXPECTED_BACKENDS = {
    _SUPERVISED_MODE: {"local_supervised"},
    "isolated_worker": {"isolated_worker"},
    "hardened_vm": {"hardened_vm"},
}


class RuntimeAttestationError(ValueError):
    """Stable fail-closed error for runtime-boundary observations."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeAttestationError(
            "E_ATTESTATION_TIME", f"{field} must be an ISO-8601 timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeAttestationError(
            "E_ATTESTATION_TIME", f"{field} is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise RuntimeAttestationError(
            "E_ATTESTATION_TIME", f"{field} must include a timezone"
        )
    return parsed.astimezone(timezone.utc)


def _mode(value: object, field: str = "requested_isolation") -> str:
    if value not in ISOLATION_MODES:
        raise RuntimeAttestationError("E_ISOLATION_MODE", f"{field} is unsupported")
    return str(value)


def _file_digest(path: Path) -> str:
    try:
        if not path.is_file() or path.is_symlink():
            raise RuntimeAttestationError("E_EXECUTABLE_MISSING", str(path))
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            total = 0
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > 512 * 1024 * 1024:
                    raise RuntimeAttestationError(
                        "E_EXECUTABLE_SIZE",
                        "runtime executable exceeds the 512 MiB bound",
                    )
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise RuntimeAttestationError("E_EXECUTABLE_MISSING", str(path)) from exc


def _self_hash(value: dict[str, Any]) -> str:
    core = {key: item for key, item in value.items() if key != "attestation_sha256"}
    return sha256_bytes(canonical_bytes(core))


def _verification_hash(value: dict[str, Any]) -> str:
    """Hash the review receipt itself so a saved Graph Ops file is tamper-evident."""
    core = {key: item for key, item in value.items() if key != "verification_sha256"}
    return sha256_bytes(canonical_bytes(core))


def _validate_collector(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RuntimeAttestationError("E_COLLECTOR", "collector must be an object")
    try:
        exact_keys(value, {"id", "version", "role", "backend", "executable_sha256"})
    except Exception as exc:
        raise RuntimeAttestationError("E_COLLECTOR", str(exc)) from exc
    collector_id = require_str(value.get("id"), "collector.id", maximum=160)
    version = require_str(value.get("version"), "collector.version", maximum=80)
    role = value.get("role")
    if role not in COLLECTOR_ROLES:
        raise RuntimeAttestationError("E_COLLECTOR", "collector role is unsupported")
    backend = value.get("backend")
    if backend not in BACKENDS:
        raise RuntimeAttestationError("E_COLLECTOR", "collector backend is unsupported")
    executable = require_digest(
        value.get("executable_sha256"), "collector.executable_sha256"
    )
    return {
        "id": collector_id,
        "version": version,
        "role": str(role),
        "backend": str(backend),
        "executable_sha256": executable,
    }


def _validate_observations(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeAttestationError(
            "E_OBSERVATIONS", "observations must be an object"
        )
    try:
        exact_keys(
            value,
            {
                "shell",
                "stdin",
                "stdout_capture",
                "stderr_capture",
                "environment_policy",
                "platform",
                "python_version",
                "executable_sha256",
                "workspace_environment_sha256",
                "cleanup_confirmed",
                "memory_peak_bytes",
                "latency_ms",
            },
        )
    except Exception as exc:
        raise RuntimeAttestationError("E_OBSERVATIONS", str(exc)) from exc
    shell = require_bool(value.get("shell"), "observations.shell")
    if shell:
        raise RuntimeAttestationError(
            "E_SHELL_ENABLED", "runtime boundary requires shell=false"
        )
    stdin = require_str(value.get("stdin"), "observations.stdin", maximum=32)
    stdout_capture = require_str(
        value.get("stdout_capture"), "observations.stdout_capture", maximum=48
    )
    stderr_capture = require_str(
        value.get("stderr_capture"), "observations.stderr_capture", maximum=48
    )
    policy = require_str(
        value.get("environment_policy"), "observations.environment_policy", maximum=80
    )
    if policy != "minimal_allowlist":
        raise RuntimeAttestationError(
            "E_ENVIRONMENT_POLICY",
            "runtime environment policy is not the approved minimal allowlist",
        )
    platform_name = require_str(
        value.get("platform"), "observations.platform", maximum=120
    )
    python_version = require_str(
        value.get("python_version"), "observations.python_version", maximum=40
    )
    executable = require_digest(
        value.get("executable_sha256"), "observations.executable_sha256"
    )
    workspace = require_digest(
        value.get("workspace_environment_sha256"),
        "observations.workspace_environment_sha256",
    )
    cleanup = require_bool(
        value.get("cleanup_confirmed"), "observations.cleanup_confirmed"
    )
    if not cleanup:
        raise RuntimeAttestationError(
            "E_CLEANUP_UNCONFIRMED", "runtime cleanup is not confirmed"
        )
    memory = value.get("memory_peak_bytes")
    if memory is not None:
        memory = require_int(
            memory, "observations.memory_peak_bytes", minimum=0, maximum=2**63 - 1
        )
    latency = value.get("latency_ms")
    if latency is not None:
        latency = require_int(
            latency, "observations.latency_ms", minimum=0, maximum=2**63 - 1
        )
    return {
        "shell": False,
        "stdin": stdin,
        "stdout_capture": stdout_capture,
        "stderr_capture": stderr_capture,
        "environment_policy": policy,
        "platform": platform_name,
        "python_version": python_version,
        "executable_sha256": executable,
        "workspace_environment_sha256": workspace,
        "cleanup_confirmed": True,
        "memory_peak_bytes": memory,
        "latency_ms": latency,
    }


def _validate_attestation_shape(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeAttestationError(
            "E_ATTESTATION_SCHEMA", "attestation must be an object"
        )
    try:
        exact_keys(
            value,
            {
                "schema",
                "attestation_id",
                "candidate_sha256",
                "plan_sha256",
                "environment_sha256",
                "run_nonce",
                "issued_at",
                "expires_at",
                "requested_isolation",
                "collector",
                "observations",
                "isolation",
                "authority",
                "attestation_sha256",
            },
        )
    except Exception as exc:
        raise RuntimeAttestationError("E_ATTESTATION_SCHEMA", str(exc)) from exc
    if value.get("schema") != SCHEMA:
        raise RuntimeAttestationError(
            "E_ATTESTATION_SCHEMA", f"schema must be {SCHEMA}"
        )
    return value


def _validate_bindings(
    value: dict[str, Any],
    candidate_sha256: str | None,
    plan_sha256: str | None,
    environment_sha256: str | None,
) -> tuple[str, str, str]:
    candidate = require_digest(value.get("candidate_sha256"), "candidate_sha256")
    plan = require_digest(value.get("plan_sha256"), "plan_sha256")
    environment = require_digest(value.get("environment_sha256"), "environment_sha256")
    if candidate_sha256 is not None and candidate != require_digest(
        candidate_sha256, "candidate_sha256 expectation"
    ):
        raise RuntimeAttestationError(
            "E_ATTESTATION_BINDING", "candidate digest differs from the approved plan"
        )
    if plan_sha256 is not None and plan != require_digest(
        plan_sha256, "plan_sha256 expectation"
    ):
        raise RuntimeAttestationError(
            "E_ATTESTATION_BINDING", "plan digest differs from the approved plan"
        )
    if environment_sha256 is not None and environment != require_digest(
        environment_sha256, "environment_sha256 expectation"
    ):
        raise RuntimeAttestationError(
            "E_ATTESTATION_BINDING", "environment digest differs from the approved plan"
        )
    return candidate, plan, environment


def _validate_freshness(
    value: dict[str, Any], now: datetime | None, seen_nonces: Iterable[str]
) -> tuple[str, datetime, datetime]:
    nonce = require_str(value.get("run_nonce"), "run_nonce", maximum=160)
    if nonce in set(seen_nonces):
        raise RuntimeAttestationError(
            "E_ATTESTATION_REPLAY", "run nonce has already been observed"
        )
    issued = _timestamp(value.get("issued_at"), "issued_at")
    expires = _timestamp(value.get("expires_at"), "expires_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires <= issued or expires - issued > MAX_VALIDITY:
        raise RuntimeAttestationError(
            "E_ATTESTATION_TIME", "expiry must be after issue and within 24 hours"
        )
    if expires <= current:
        raise RuntimeAttestationError(
            "E_ATTESTATION_FRESHNESS", "attestation is expired"
        )
    return nonce, issued, expires


def _validate_runtime_parts(
    value: dict[str, Any],
) -> tuple[str, dict[str, str], dict[str, Any]]:
    mode = _mode(value.get("requested_isolation"))
    collector = _validate_collector(value.get("collector"))
    observations = _validate_observations(value.get("observations"))
    if observations["executable_sha256"] != collector["executable_sha256"]:
        raise RuntimeAttestationError(
            "E_ATTESTATION_BINDING",
            "observed executable differs from the collector executable",
        )
    return mode, collector, observations


def _validate_isolation_claim(
    value: dict[str, Any],
    mode: str,
    collector: dict[str, str],
    require_independent: bool,
) -> dict[str, Any]:
    if mode in INDEPENDENT_MODES and collector["role"] == "local_supervisor":
        raise RuntimeAttestationError(
            "E_ISOLATION_UNPROVEN",
            "a local supervisor cannot self-attest independent isolation",
        )
    isolation = value.get("isolation")
    if not isinstance(isolation, dict):
        raise RuntimeAttestationError("E_ISOLATION", "isolation must be an object")
    try:
        exact_keys(isolation, {"backend", "state", "proof", "claim_boundary"})
    except Exception as exc:
        raise RuntimeAttestationError("E_ISOLATION", str(exc)) from exc
    backend = isolation.get("backend")
    if backend not in BACKENDS or backend not in _EXPECTED_BACKENDS[mode]:
        raise RuntimeAttestationError(
            "E_ISOLATION_BACKEND",
            "observed backend does not satisfy requested isolation",
        )
    proof = require_bool(isolation.get("proof"), "isolation.proof")
    state = isolation.get("state")
    if mode == _SUPERVISED_MODE and (state != "SUPERVISED_ONLY" or proof):
        raise RuntimeAttestationError(
            "E_ISOLATION_CLAIM",
            "supervised process evidence cannot claim verified isolation",
        )
    if mode in INDEPENDENT_MODES and (state != "VERIFIED" or not proof):
        raise RuntimeAttestationError(
            "E_ISOLATION_UNPROVEN",
            "independent isolation requires a verified backend proof",
        )
    if require_independent and mode not in INDEPENDENT_MODES:
        raise RuntimeAttestationError(
            "E_ISOLATION_UNPROVEN", "an independent boundary is required"
        )
    return {
        "backend": str(backend),
        "state": str(state),
        "proof": proof,
        "claim_boundary": require_str(
            isolation.get("claim_boundary"), "isolation.claim_boundary", maximum=240
        ),
    }


def _validate_authority_and_seal(value: dict[str, Any]) -> str:
    if value.get("authority") != "none":
        raise RuntimeAttestationError(
            "E_ATTESTATION_AUTHORITY", "runtime attestations cannot carry authority"
        )
    if _self_hash(value) != require_digest(
        value.get("attestation_sha256"), "attestation_sha256"
    ):
        raise RuntimeAttestationError(
            "E_ATTESTATION_SELF_HASH",
            "attestation bytes do not match attestation_sha256",
        )
    return str(value["attestation_sha256"])


def validate_runtime_attestation(
    value: dict[str, Any],
    *,
    candidate_sha256: str | None = None,
    plan_sha256: str | None = None,
    environment_sha256: str | None = None,
    now: datetime | None = None,
    seen_nonces: Iterable[str] = (),
    require_independent: bool = False,
) -> dict[str, Any]:
    """Validate one exact boundary observation and return normalized facts.

    The collector's role is a provenance label, never permission.  A local
    supervisor is therefore returned as ``SUPERVISED_ONLY``; only a matching
    independent backend can return ``VERIFIED``.
    """
    value = _validate_attestation_shape(value)
    attestation_id = require_str(
        value.get("attestation_id"), "attestation_id", maximum=160
    )
    candidate, plan, environment = _validate_bindings(
        value, candidate_sha256, plan_sha256, environment_sha256
    )
    nonce, issued, expires = _validate_freshness(value, now, seen_nonces)
    mode, collector, observations = _validate_runtime_parts(value)
    isolation = _validate_isolation_claim(value, mode, collector, require_independent)
    attestation_sha256 = _validate_authority_and_seal(value)
    normalized = {
        "schema": SCHEMA,
        "attestation_id": attestation_id,
        "candidate_sha256": candidate,
        "plan_sha256": plan,
        "environment_sha256": environment,
        "run_nonce": nonce,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "requested_isolation": mode,
        "collector": collector,
        "observations": observations,
        "isolation": isolation,
        "authority": "none",
        "attestation_sha256": attestation_sha256,
    }
    return normalized


def capture_supervised_attestation(
    *,
    attestation_id: str,
    candidate_sha256: str,
    plan_sha256: str,
    environment_sha256: str,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    run_nonce: str = "local-supervisor",
    cleanup_confirmed: bool = True,
    memory_peak_bytes: int | None = None,
    latency_ms: int | None = None,
) -> dict[str, Any]:
    """Capture the facts the local no-shell supervisor can honestly prove."""
    if not isinstance(attestation_id, str) or not attestation_id.strip():
        raise RuntimeAttestationError("E_ATTESTATION_ID", "attestation_id is required")
    issued = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = (expires_at or issued + timedelta(hours=1)).astimezone(timezone.utc)
    executable = Path(sys.executable).resolve()
    executable_sha = _file_digest(executable)
    candidate = require_digest(candidate_sha256, "candidate_sha256")
    plan = require_digest(plan_sha256, "plan_sha256")
    environment = require_digest(environment_sha256, "environment_sha256")
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attestation_id": attestation_id,
        "candidate_sha256": candidate,
        "plan_sha256": plan,
        "environment_sha256": environment,
        "run_nonce": require_str(run_nonce, "run_nonce", maximum=160),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "requested_isolation": _SUPERVISED_MODE,
        "collector": {
            "id": "factoryline-supervisor",
            "version": __version__,
            "role": "local_supervisor",
            "backend": "local_supervised",
            "executable_sha256": executable_sha,
        },
        "observations": {
            "shell": False,
            "stdin": "devnull",
            "stdout_capture": "hashed_pipe",
            "stderr_capture": "hashed_pipe",
            "environment_policy": "minimal_allowlist",
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "executable_sha256": executable_sha,
            "workspace_environment_sha256": environment,
            "cleanup_confirmed": cleanup_confirmed,
            "memory_peak_bytes": memory_peak_bytes,
            "latency_ms": latency_ms,
        },
        "isolation": {
            "backend": "local_supervised",
            "state": "SUPERVISED_ONLY",
            "proof": False,
            "claim_boundary": "Bounded process supervision only; no kernel, container, network, credential, or descendant isolation is claimed.",
        },
        "authority": "none",
    }
    payload["attestation_sha256"] = _self_hash(payload)
    return validate_runtime_attestation(payload, now=issued, require_independent=False)


def runtime_boundary_decision(
    attestation: dict[str, Any] | None,
    *,
    candidate_sha256: str,
    plan_sha256: str,
    environment_sha256: str,
    requested_isolation: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a compact fail-closed decision suitable for the six-lane receipt."""
    mode = _mode(requested_isolation)
    if attestation is None:
        return {
            "schema": "factory.runtime-boundary-decision.v1",
            "state": "BLOCKED",
            "finding": "E_RUNTIME_ATTESTATION_MISSING",
            "requested_isolation": mode,
            "authority": "none",
            "release_approval": False,
            "claim_boundary": "No runtime-boundary observation was supplied.",
        }
    try:
        normalized = validate_runtime_attestation(
            attestation,
            candidate_sha256=candidate_sha256,
            plan_sha256=plan_sha256,
            environment_sha256=environment_sha256,
            now=now,
            require_independent=mode in INDEPENDENT_MODES,
        )
    except RuntimeAttestationError as exc:
        return {
            "schema": "factory.runtime-boundary-decision.v1",
            "state": "BLOCKED",
            "finding": exc.code,
            "message": exc.message,
            "requested_isolation": mode,
            "authority": "none",
            "release_approval": False,
            "claim_boundary": "Boundary evidence is invalid, stale, mismatched, or weaker than requested.",
        }
    verified = normalized["isolation"]["state"] == "VERIFIED"
    return {
        "schema": "factory.runtime-boundary-decision.v1",
        "state": "PASS" if verified else "SUPERVISED_ONLY",
        "finding": "RUNTIME_BOUNDARY_VERIFIED"
        if verified
        else "RUNTIME_BOUNDARY_SUPERVISED_ONLY",
        "requested_isolation": mode,
        "observed_backend": normalized["isolation"]["backend"],
        "attestation_sha256": normalized["attestation_sha256"],
        "authority": "none",
        "release_approval": False,
        "claim_boundary": normalized["isolation"]["claim_boundary"],
    }


def verify_signed_runtime_attestation(
    path: Path,
    trust_root_path: Path,
    *,
    candidate_sha256: str | None = None,
    plan_sha256: str | None = None,
    environment_sha256: str | None = None,
    now: datetime | None = None,
    seen_nonces: Iterable[str] = (),
) -> dict[str, Any]:
    """Verify a DSSE-signed independent boundary observation offline."""
    try:
        verified = verify_signed_document(
            Path(path),
            payload_type=PAYLOAD_TYPE,
            schema=SCHEMA,
            trust_root_path=Path(trust_root_path),
        )
    except EnterpriseReceiptError as exc:
        raise RuntimeAttestationError(exc.code, exc.message) from exc
    payload = validate_runtime_attestation(
        verified["payload"],
        candidate_sha256=candidate_sha256,
        plan_sha256=plan_sha256,
        environment_sha256=environment_sha256,
        now=now,
        seen_nonces=seen_nonces,
        require_independent=True,
    )
    result = {
        "schema": VERIFICATION_SCHEMA,
        "state": "VERIFIED",
        "verification": "offline_dsse_ed25519",
        "attestation_id": payload["attestation_id"],
        "attestation_sha256": payload["attestation_sha256"],
        "requested_isolation": payload["requested_isolation"],
        "observed_backend": payload["isolation"]["backend"],
        "keyid": verified["signature"]["keyid"],
        "identity": verified["signature"]["identity"],
        "issuer": verified["signature"]["issuer"],
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Signature and boundary facts were verified offline; this does not approve, publish, deploy, or prove application correctness.",
    }
    result["verification_sha256"] = _verification_hash(result)
    return result
