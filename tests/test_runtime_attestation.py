from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import base64

import pytest

from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.runtime_attestation import (
    PAYLOAD_TYPE,
    SCHEMA,
    TEST_ORACLE_PAYLOAD_TYPE,
    TEST_ORACLE_SCHEMA,
    RuntimeAttestationError,
    capture_supervised_attestation,
    runtime_boundary_decision,
    validate_runtime_attestation,
    verify_signed_test_oracles,
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


def _oracle_payload(*, now: datetime | None = None) -> dict:
    issued = now or datetime.now(timezone.utc)
    case = "tests/test_example.py::test_example[case-1]"
    return {
        "schema": TEST_ORACLE_SCHEMA,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(hours=1)).isoformat(),
        "source_manifest_sha256": _digest("manifest"),
        "environment_sha256": _digest("oracle-environment"),
        "authority": "none",
        "tests": [
            {
                "path": "tests/test_example.py",
                "line": 12,
                "symbol": "test_example",
                "test_sha256": _digest("test source"),
                "baseline": {
                    "status": "PASS",
                    "phase": "call",
                    "collection_complete": True,
                    "case_ids": [case],
                    "report_sha256": _digest("baseline report"),
                },
                "mutation": {
                    "source_path": "factoryline/example.py",
                    "source_sha256": _digest("original source"),
                    "mutant_sha256": _digest("mutated source"),
                    "status": "FAIL",
                    "phase": "call",
                    "case_ids": [case],
                    "failure_kind": "assertion",
                    "report_sha256": _digest("mutation report"),
                },
            }
        ],
    }


def _signed_oracle(tmp_path: Path, payload: dict | None = None):
    keys = generate_key_material(
        out_dir=tmp_path / "oracle-keys",
        keyid="oracle-key",
        identity="oracle@example",
        issuer="local",
    )
    trust_path = Path(keys["trust_root"])
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["keys"][0]["roles"] = ["oracle-verifier"]
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    payload = payload or _oracle_payload()
    envelope = sign_payload(
        payload,
        payload_type=TEST_ORACLE_PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    receipt_path = tmp_path / "test-oracle.json"
    receipt_path.write_text(json.dumps(envelope), encoding="utf-8")
    return receipt_path, trust_path, trust, payload


def _verify_oracle(
    receipt_path: Path,
    trust_path: Path,
    payload: dict,
    *,
    now=None,
    source_manifest_sha256=None,
    environment_sha256=None,
):
    trust_sha = sha256_bytes(trust_path.read_bytes())
    return verify_signed_test_oracles(
        receipt_path,
        trust_path,
        trust_root_sha256=trust_sha,
        source_manifest_sha256=source_manifest_sha256
        or payload["source_manifest_sha256"],
        environment_sha256=environment_sha256 or payload["environment_sha256"],
        now=now,
    )


def test_signed_test_oracle_verifies_bounded_signer_claim(tmp_path: Path):
    now = datetime.now(timezone.utc)
    payload = _oracle_payload(now=now)
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    result = _verify_oracle(receipt, trust, payload, now=now + timedelta(minutes=1))

    assert result["state"] == "VERIFIED"
    assert result["authority"] == "none"
    assert result["tests"][0]["baseline"]["collection_complete"] is True
    assert result["signature"]["role"] == "oracle-verifier"
    assert len(result["receipt_sha256"]) == 64
    assert "not established" in result["claim_boundary"]


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (lambda p: p.update(authority="release"), "E_ORACLE_SCHEMA"),
        (
            lambda p: p["tests"][0]["baseline"].update(collection_complete=False),
            "E_ORACLE_BASELINE",
        ),
        (
            lambda p: p["tests"][0]["baseline"].update(phase="setup"),
            "E_ORACLE_BASELINE",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(phase="teardown"),
            "E_ORACLE_MUTATION",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(failure_kind="timeout"),
            "E_ORACLE_MUTATION",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(
                case_ids=["tests/test_other.py::test_other"]
            ),
            "E_ORACLE_CASES",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(
                mutant_sha256=p["tests"][0]["mutation"]["source_sha256"]
            ),
            "E_ORACLE_MUTATION",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(
                source_path="tests/test_example.py"
            ),
            "E_ORACLE_PATH",
        ),
        (
            lambda p: p["tests"][0].update(path="../tests/test_example.py"),
            "E_ORACLE_PATH",
        ),
    ],
)
def test_signed_test_oracle_rejects_invalid_claims(tmp_path: Path, change, code):
    payload = _oracle_payload()
    change(payload)
    receipt, trust, _, payload = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match=code):
        _verify_oracle(receipt, trust, payload)


@pytest.mark.parametrize("field", ["source_manifest_sha256", "environment_sha256"])
def test_signed_test_oracle_rejects_wrong_expected_binding(tmp_path: Path, field: str):
    payload = _oracle_payload()
    receipt, trust, _, payload = _signed_oracle(tmp_path, payload)
    kwargs = {field: _digest("wrong expected binding")}

    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_BINDING"):
        _verify_oracle(receipt, trust, payload, **kwargs)


@pytest.mark.parametrize(
    ("issued_delta", "validity", "code"),
    [
        (timedelta(minutes=1), timedelta(hours=1), "E_ORACLE_FRESHNESS"),
        (-timedelta(hours=2), timedelta(hours=1), "E_ORACLE_FRESHNESS"),
        (timedelta(), timedelta(hours=25), "E_ORACLE_FRESHNESS"),
    ],
)
def test_signed_test_oracle_rejects_stale_or_long_lived_payload(
    tmp_path: Path, issued_delta, validity, code
):
    now = datetime.now(timezone.utc)
    payload = _oracle_payload(now=now + issued_delta)
    payload["expires_at"] = (now + issued_delta + validity).isoformat()
    receipt, trust, _, payload = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match=code):
        _verify_oracle(receipt, trust, payload, now=now)


def test_signed_test_oracle_rejects_missing_role_revocation_and_pin_mismatch(
    tmp_path: Path,
):
    receipt, trust_path, trust, payload = _signed_oracle(tmp_path)
    trust["keys"][0]["roles"] = []
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError, match="E_KEY_ROLE_MISMATCH"):
        _verify_oracle(receipt, trust_path, payload)

    trust["keys"][0]["roles"] = ["oracle-verifier"]
    trust["keys"][0]["revoked"] = True
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_KEY"):
        _verify_oracle(receipt, trust_path, payload)

    trust["keys"][0].pop("revoked")
    trust["keys"].append(dict(trust["keys"][0]))
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_KEY"):
        _verify_oracle(receipt, trust_path, payload)

    trust["keys"].pop()
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError, match="E_TRUST_ROOT_PIN"):
        verify_signed_test_oracles(
            receipt,
            trust_path,
            trust_root_sha256=_digest("wrong trust"),
            source_manifest_sha256=payload["source_manifest_sha256"],
            environment_sha256=payload["environment_sha256"],
        )


def test_signed_test_oracle_rejects_duplicate_json_and_tampered_signature(
    tmp_path: Path,
):
    receipt, trust, _, payload = _signed_oracle(tmp_path)
    raw = receipt.read_text(encoding="utf-8")
    receipt.write_text(
        raw.replace('"schema":', '"schema":"duplicate","schema":', 1), encoding="utf-8"
    )
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_JSON"):
        _verify_oracle(receipt, trust, payload)

    receipt, trust, _, payload = _signed_oracle(tmp_path / "tampered")
    envelope = json.loads(receipt.read_text(encoding="utf-8"))
    envelope["payload"] = base64.urlsafe_b64encode(b"{}").decode("ascii").rstrip("=")
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError):
        _verify_oracle(receipt, trust, payload)


def test_signed_test_oracle_rechecks_receipt_and_trust_bytes(
    tmp_path: Path, monkeypatch
):
    import factoryline.runtime_attestation as runtime_attestation

    receipt, trust, _, payload = _signed_oracle(tmp_path)
    original_verify = runtime_attestation.verify_signed_document

    def verify_then_drift(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        receipt.write_text("{}", encoding="utf-8")
        return result

    monkeypatch.setattr(
        runtime_attestation, "verify_signed_document", verify_then_drift
    )
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_DRIFT"):
        _verify_oracle(receipt, trust, payload)


def test_signed_test_oracle_rejects_oversized_receipt(tmp_path: Path):
    receipt, trust, _, payload = _signed_oracle(tmp_path)
    receipt.write_bytes(b" " * (1_048_577))
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_SIZE"):
        _verify_oracle(receipt, trust, payload)


def test_test_oracle_private_helpers_enforce_contracts(tmp_path: Path):
    import factoryline.runtime_attestation as oracle

    with pytest.raises(RuntimeAttestationError, match="E_TEST"):
        oracle._oracle_fail("E_TEST", "expected")
    path = tmp_path / "small.json"
    path.write_text('{"ok":true}', encoding="utf-8")
    assert oracle._oracle_read(path, "test") == b'{"ok":true}'
    assert oracle._oracle_json(b'{"ok":true}', "test") == {"ok": True}
    for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
        with pytest.raises(RuntimeAttestationError, match="E_ORACLE_JSON"):
            oracle._oracle_json(raw, "test")
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_SCHEMA"):
        oracle._oracle_exact({"x": 1, "extra": 2}, {"x"}, "test")
    assert (
        oracle._oracle_relative_py("src/mod.py", "source", test_source=False)
        == "src/mod.py"
    )
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_PATH"):
        oracle._oracle_relative_py("../test.py", "source", test_source=True)
    cases = oracle._oracle_case_ids(
        ["tests/test_x.py::Suite::test_x[param]"], "cases", "tests/test_x.py", "test_x"
    )
    assert cases == ["tests/test_x.py::Suite::test_x[param]"]
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_CASES"):
        oracle._oracle_case_ids(
            ["tests/test_y.py::test_y"], "cases", "tests/test_x.py", "test_x"
        )
    payload = _oracle_payload()
    assert oracle._oracle_test(payload["tests"][0])["mutation"]["status"] == "FAIL"
    normalized = oracle._oracle_payload(
        payload,
        source_manifest_sha256=payload["source_manifest_sha256"],
        environment_sha256=payload["environment_sha256"],
        now=datetime.now(timezone.utc),
    )
    assert normalized["authority"] == "none"
    receipt, trust_path, _, _ = _signed_oracle(tmp_path / "envelope", payload)
    envelope, _ = oracle._verify_oracle_envelope(
        receipt.read_bytes(), trust_path.read_bytes()
    )
    assert envelope["schema"] == TEST_ORACLE_SCHEMA
