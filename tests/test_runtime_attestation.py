from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.runtime_attestation import (
    PAYLOAD_TYPE,
    SCHEMA,
    RuntimeAttestationError,
    capture_supervised_attestation,
    runtime_boundary_decision,
    validate_runtime_attestation,
    verify_signed_runtime_attestation,
)
from factoryline.runtime_audit_common import canonical_bytes, sha256_bytes


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _independent_payload(*, now: datetime | None = None) -> dict:
    issued = now or datetime.now(timezone.utc)
    executable = _digest("hardened-runner")
    payload = {
        "schema": SCHEMA,
        "attestation_id": "boundary-001",
        "candidate_sha256": _digest("candidate"),
        "plan_sha256": _digest("plan"),
        "environment_sha256": _digest("environment"),
        "run_nonce": "nonce-001",
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(hours=1)).isoformat(),
        "requested_isolation": "hardened_vm",
        "collector": {
            "id": "vm-collector",
            "version": "1",
            "role": "external_collector",
            "backend": "hardened_vm",
            "executable_sha256": executable,
        },
        "observations": {
            "shell": False,
            "stdin": "devnull",
            "stdout_capture": "hashed_pipe",
            "stderr_capture": "hashed_pipe",
            "environment_policy": "minimal_allowlist",
            "platform": "linux",
            "python_version": "3.12",
            "executable_sha256": executable,
            "workspace_environment_sha256": _digest("environment"),
            "cleanup_confirmed": True,
            "memory_peak_bytes": 128,
            "latency_ms": 4,
        },
        "isolation": {
            "backend": "hardened_vm",
            "state": "VERIFIED",
            "proof": True,
            "claim_boundary": "External collector supplied signed VM boundary evidence; application correctness remains unproven.",
        },
        "authority": "none",
    }
    payload["attestation_sha256"] = sha256_bytes(canonical_bytes(payload))
    return payload


def test_local_capture_is_explicitly_supervised_only(tmp_path: Path):
    attestation = capture_supervised_attestation(
        attestation_id="local-001",
        candidate_sha256=_digest("candidate"),
        plan_sha256=_digest("plan"),
        environment_sha256=_digest("environment"),
    )
    result = runtime_boundary_decision(
        attestation,
        candidate_sha256=_digest("candidate"),
        plan_sha256=_digest("plan"),
        environment_sha256=_digest("environment"),
        requested_isolation="supervised_subprocess",
    )
    assert result["state"] == "SUPERVISED_ONLY"
    blocked = runtime_boundary_decision(
        attestation,
        candidate_sha256=_digest("candidate"),
        plan_sha256=_digest("plan"),
        environment_sha256=_digest("environment"),
        requested_isolation="isolated_worker",
    )
    assert (
        blocked["state"] == "BLOCKED" and blocked["finding"] == "E_ISOLATION_UNPROVEN"
    )


def test_boundary_rejects_shell_executable_drift_and_stale_observations():
    payload = _independent_payload()
    payload["observations"]["shell"] = True
    payload["attestation_sha256"] = sha256_bytes(
        canonical_bytes(
            {
                key: value
                for key, value in payload.items()
                if key != "attestation_sha256"
            }
        )
    )
    with pytest.raises(RuntimeAttestationError, match="E_SHELL_ENABLED"):
        validate_runtime_attestation(payload)

    payload = _independent_payload()
    payload["observations"]["executable_sha256"] = _digest("different")
    payload["attestation_sha256"] = sha256_bytes(
        canonical_bytes(
            {
                key: value
                for key, value in payload.items()
                if key != "attestation_sha256"
            }
        )
    )
    with pytest.raises(RuntimeAttestationError, match="E_ATTESTATION_BINDING"):
        validate_runtime_attestation(payload)

    stale = _independent_payload(now=datetime.now(timezone.utc) - timedelta(hours=2))
    with pytest.raises(RuntimeAttestationError, match="E_ATTESTATION_FRESHNESS"):
        validate_runtime_attestation(stale)


def test_boundary_missing_or_tampered_evidence_blocks_without_authority():
    missing = runtime_boundary_decision(
        None,
        candidate_sha256=_digest("candidate"),
        plan_sha256=_digest("plan"),
        environment_sha256=_digest("environment"),
        requested_isolation="hardened_vm",
    )
    assert (
        missing["state"] == "BLOCKED"
        and missing["finding"] == "E_RUNTIME_ATTESTATION_MISSING"
    )
    payload = _independent_payload()
    payload["attestation_sha256"] = _digest("tampered")
    decision = runtime_boundary_decision(
        payload,
        candidate_sha256=payload["candidate_sha256"],
        plan_sha256=payload["plan_sha256"],
        environment_sha256=payload["environment_sha256"],
        requested_isolation="hardened_vm",
    )
    assert (
        decision["state"] == "BLOCKED"
        and decision["finding"] == "E_ATTESTATION_SELF_HASH"
    )


def test_signed_external_boundary_verifies_offline(tmp_path: Path):
    keys = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="boundary-key",
        identity="collector@example",
        issuer="local",
    )
    payload = _independent_payload()
    envelope = sign_payload(
        payload,
        payload_type=PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    receipt = tmp_path / "boundary.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    result = verify_signed_runtime_attestation(
        receipt,
        Path(keys["trust_root"]),
        candidate_sha256=payload["candidate_sha256"],
        plan_sha256=payload["plan_sha256"],
        environment_sha256=payload["environment_sha256"],
    )
    assert result["state"] == "VERIFIED"
    assert result["requested_isolation"] == "hardened_vm"
    assert result["authority"] == "none" and result["release_approval"] is False
    assert len(result["verification_sha256"]) == 64
