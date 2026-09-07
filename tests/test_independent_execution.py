from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.independent_execution import ExecutionAttestationError, PAYLOAD_TYPE, SCHEMA, validate_execution_attestation, verify_signed_execution_attestation


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _payload(**overrides):
    now = datetime.now(timezone.utc)
    value = {
        "schema": SCHEMA,
        "attestation_id": "att-001",
        "candidate_sha256": _digest("a"),
        "plan_sha256": _digest("b"),
        "run_nonce": "nonce-001",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "assurance_level": "isolated_worker",
        "runner": {"id": "runner-1", "version": "1.0.0", "platform": "linux", "backend": "isolated_worker", "executable_sha256": _digest("c")},
        "observations": {"target_artifact_sha256": _digest("d"), "known_bad_artifact_sha256": _digest("e"), "target_stdout_sha256": _digest("f"), "target_stderr_sha256": None, "cleanup_confirmed": True, "memory_peak_bytes": 128, "latency_ms": 7},
        "authority": "none",
    }
    value.update(overrides)
    return value


def test_valid_attestation_normalizes_and_has_no_authority():
    result = validate_execution_attestation(_payload())
    assert result["schema"] == SCHEMA
    assert result["observations"]["memory_peak_bytes"] == 128
    assert result["authority"] == "none"


def test_supervised_local_is_rejected_for_independent_lane():
    payload = _payload(assurance_level="supervised_local")
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_ASSURANCE"):
        validate_execution_attestation(payload)


def test_independent_assurance_rejects_local_backend():
    payload = _payload()
    payload["runner"] = {**payload["runner"], "backend": "local_supervised"}
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_BACKEND"):
        validate_execution_attestation(payload)


def test_binding_cleanup_expiry_replay_and_unknown_fields_fail_closed():
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_BINDING"):
        validate_execution_attestation(_payload(), candidate_sha256=_digest("z"))
    incomplete = _payload()
    incomplete["observations"]["cleanup_confirmed"] = False
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_INCOMPLETE"):
        validate_execution_attestation(incomplete)
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_REPLAY"):
        validate_execution_attestation(_payload(), seen_nonces=["nonce-001"])
    unknown = _payload()
    unknown["unexpected"] = True
    with pytest.raises(ExecutionAttestationError, match="E_ARTIFACT_FIELDS"):
        validate_execution_attestation(unknown)


def test_signed_attestation_verifies_against_local_trust_root(tmp_path):
    keys = generate_key_material(out_dir=tmp_path / "keys", keyid="runner-key", identity="runner@example", issuer="local")
    payload = _payload()
    envelope = sign_payload(payload, payload_type=PAYLOAD_TYPE, private_key_path=keys["private_key"], keyid=keys["keyid"], identity=keys["identity"], issuer=keys["issuer"])
    receipt = tmp_path / "attestation.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    result = verify_signed_execution_attestation(receipt, keys["trust_root"], candidate_sha256=payload["candidate_sha256"], plan_sha256=payload["plan_sha256"])
    assert result["state"] == "VERIFIED"
    assert result["release_approval"] is False
    other_root = tmp_path / "other-trust-root.json"
    other_root.write_text(json.dumps({"schema": "factory.trust.root.v1", "version": 1, "keys": []}), encoding="utf-8")
    with pytest.raises(ExecutionAttestationError, match="E_UNKNOWN_KEY"):
        verify_signed_execution_attestation(receipt, other_root)
