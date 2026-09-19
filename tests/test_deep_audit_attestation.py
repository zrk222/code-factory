from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from test_deep_audit import inputs
from factoryline.deep_audit import execute_deep_audit
from factoryline.deep_audit_attestation import (
    DeepAuditAttestationError,
    PAYLOAD_TYPE,
    SCHEMA,
    verify_deep_audit_attestation,
)
from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.deep_audit_loop import compare_deep_audits
from factoryline.cli import main


def _signed_attestation(
    root: Path,
    receipt_path: str,
    receipt: dict,
    *,
    issued: datetime | None = None,
    expires: datetime | None = None,
    **overrides,
):
    keys = generate_key_material(
        out_dir=root / "attestation-keys",
        keyid="independent-key",
        identity="verifier@example.test",
        issuer="https://verifier.example.test",
    )
    issued = issued or datetime.now(timezone.utc) - timedelta(seconds=2)
    expires = expires or issued + timedelta(hours=1)
    payload = {
        "schema": SCHEMA,
        "attestation_id": "independent-001",
        "receipt_sha256": receipt["receipt_sha256"],
        "plan_sha256": receipt["plan_sha256"],
        "candidate_sha256": receipt["candidate_sha256"],
        "ruleset_sha256": receipt["ruleset_sha256"],
        "canary_set_sha256": receipt["canary_set_sha256"],
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "verifier": {
            "id": "independent-verifier",
            "version": "1.0.0",
            "independent": True,
        },
        "observations": {
            "report_hashes": receipt["report_hashes"],
            "canary_hashes": receipt["canary_hashes"],
        },
        "authority": "none",
    }
    payload.update(overrides)
    envelope = sign_payload(
        payload,
        payload_type=PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    path = root / "attestation.json"
    path.write_bytes(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    return path, Path(keys["trust_root"]), payload


def _receipt(root: Path):
    args, _, _, _ = inputs(root, clean=True)
    result = execute_deep_audit(*args)
    return result["receipt"], Path(result["receipt_path"]).relative_to(root).as_posix()


def test_fresh_independent_attestation_verifies(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, _ = _signed_attestation(tmp_path, receipt_path, receipt)
    result = verify_deep_audit_attestation(
        tmp_path, attestation, trust_root, tmp_path / receipt_path
    )
    assert result["marker"] == "DEEP_AUDIT_ATTESTATION_VERIFIED"
    assert result["authority"] == "none"
    assert result["release_approval"] is False


@pytest.mark.parametrize(
    "issued,expires",
    [
        (
            datetime.now(timezone.utc) + timedelta(minutes=5),
            datetime.now(timezone.utc) + timedelta(hours=1),
        ),
        (
            datetime.now(timezone.utc) - timedelta(hours=2),
            datetime.now(timezone.utc) + timedelta(hours=1),
        ),
    ],
)
def test_future_or_stale_attestation_fails_closed(tmp_path, issued, expires):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, _ = _signed_attestation(
        tmp_path, receipt_path, receipt, issued=issued, expires=expires
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_FRESHNESS"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )


def test_attestation_validity_window_and_clock_policy_are_bounded(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    issued = datetime.now(timezone.utc) - timedelta(seconds=2)
    attestation, trust_root, _ = _signed_attestation(
        tmp_path,
        receipt_path,
        receipt,
        issued=issued,
        expires=issued + timedelta(hours=25),
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_FRESHNESS"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )
    attestation, trust_root, _ = _signed_attestation(
        tmp_path,
        receipt_path,
        receipt,
        issued=issued,
        expires=issued + timedelta(hours=1),
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_FRESHNESS"):
        verify_deep_audit_attestation(
            tmp_path,
            attestation,
            trust_root,
            tmp_path / receipt_path,
            max_age_seconds=0,
        )


def test_analyzer_self_attestation_and_coverage_mismatch_are_rejected(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, _ = _signed_attestation(
        tmp_path,
        receipt_path,
        receipt,
        verifier={"id": "s", "version": "1.0.0", "independent": True},
    )
    with pytest.raises(
        DeepAuditAttestationError, match="E_DEEP_ATTESTATION_INDEPENDENCE"
    ):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )
    attestation, trust_root, _ = _signed_attestation(
        tmp_path,
        receipt_path,
        receipt,
        observations={"report_hashes": {}, "canary_hashes": receipt["canary_hashes"]},
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_BINDING"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )


def test_signature_and_receipt_binding_fail_closed(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, payload = _signed_attestation(
        tmp_path, receipt_path, receipt
    )
    envelope = json.loads(attestation.read_text())
    envelope["signatures"][0]["sig"] = "AAAA"
    attestation.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_SIGNATURE"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )
    attestation, trust_root, _ = _signed_attestation(
        tmp_path, receipt_path, receipt, candidate_sha256="a" * 64
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_BINDING"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )


def test_strict_comparison_requires_and_reports_attestations(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    missing = compare_deep_audits(
        tmp_path, receipt_path, receipt_path, require_attestation=True
    )
    assert missing["code"] == "E_DEEP_ATTESTATION_REQUIRED"
    attestation, trust_root, _ = _signed_attestation(tmp_path, receipt_path, receipt)
    result = compare_deep_audits(
        tmp_path,
        receipt_path,
        receipt_path,
        before_attestation=str(attestation),
        after_attestation=str(attestation),
        trust_root_path=trust_root,
        require_attestation=True,
    )
    assert result["state"] == "approval_required"
    assert result["verification"] == "offline_dsse_and_freshness"
    assert result["attestations"]["before"]["verifier"]["independent"] is True
    assert result["authority"] == "none"


def test_cli_attestation_returns_verified_receipt(tmp_path, capsys):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, _ = _signed_attestation(tmp_path, receipt_path, receipt)
    code = main(
        [
            "deep-audit",
            "attestation",
            "--root",
            str(tmp_path),
            str(attestation),
            "--receipt",
            receipt_path,
            "--trust-root",
            str(trust_root),
        ]
    )
    assert code == 0
    assert (
        json.loads(capsys.readouterr().out)["marker"]
        == "DEEP_AUDIT_ATTESTATION_VERIFIED"
    )
