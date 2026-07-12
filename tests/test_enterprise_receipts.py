import base64
import hashlib
import json
from pathlib import Path

import pytest

enterprise = pytest.importorskip("factoryline.enterprise_receipts")
from factoryline.enterprise_receipts import (  # noqa: E402
    DSSE_SCHEMA,
    POLICY_BUNDLE_SCHEMA,
    REVOCATIONS_SCHEMA,
    EnterpriseReceiptError,
    canonical_json,
    generate_key_material,
    receipt_v2_from_v1,
    seal_receipt_v2,
    sign_policy_bundle,
    sign_revocations,
    verify_receipt_v2,
)


IDENTITY = "https://github.com/example/factory/.github/workflows/proof.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


def _keys(tmp_path: Path) -> dict:
    return generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="ci-main",
        identity=IDENTITY,
        issuer=ISSUER,
    )


def _receipt(*, policy_sha256: str | None = None) -> dict:
    value = {
        "schema": "factory.receipt.v2",
        "module": "factoryline",
        "stage": "verify",
        "feature": "checkout",
        "ok": True,
        "tenant_id": "example-tenant",
        "run_id": "run-001",
        "ts": "2026-07-12T00:00:00+00:00",
        "inputs": {"paths": ["src/checkout.py"]},
    }
    if policy_sha256:
        value["policy_sha256"] = policy_sha256
    return value


def _seal(tmp_path: Path, payload: dict | None = None, keys: dict | None = None) -> tuple[Path, dict]:
    keys = keys or _keys(tmp_path)
    path = tmp_path / "receipt.v2.dsse.json"
    seal_receipt_v2(
        payload or _receipt(),
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
        out=path,
    )
    return path, keys


def test_canonical_json_and_dsse_envelope_are_stable(tmp_path):
    path, _ = _seal(tmp_path)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert envelope["schema"] == DSSE_SCHEMA
    assert envelope["payloadType"] == "application/vnd.factory.receipt.v2+json"
    assert envelope["payload_sha256"] == hashlib.sha256(
        base64.urlsafe_b64decode(envelope["payload"] + "==")
    ).hexdigest()
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_valid_receipt_verifies_offline(tmp_path):
    path, keys = _seal(tmp_path)
    result = verify_receipt_v2(path, trust_root_path=Path(keys["trust_root"]))
    assert result["verdict"] == "VERIFIED"
    assert result["verification"] == "offline_dsse_ed25519"
    assert result["tenant_id"] == "example-tenant"
    assert result["revocation_status"] == "NOT_CHECKED"


def test_payload_mutation_fails_signature(tmp_path):
    path, keys = _seal(tmp_path)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    payload = json.loads(base64.urlsafe_b64decode(envelope["payload"] + "=="))
    payload["ok"] = False
    raw = canonical_json(payload)
    envelope["payload"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    envelope["payload_sha256"] = hashlib.sha256(raw).hexdigest()
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(EnterpriseReceiptError, match="E_SIGNATURE_INVALID"):
        verify_receipt_v2(path, trust_root_path=Path(keys["trust_root"]))


def test_unknown_key_and_identity_mismatch_fail_closed(tmp_path):
    path, keys = _seal(tmp_path)
    root = json.loads(Path(keys["trust_root"]).read_text(encoding="utf-8"))
    root["keys"][0]["keyid"] = "different-key"
    Path(keys["trust_root"]).write_text(json.dumps(root), encoding="utf-8")
    with pytest.raises(EnterpriseReceiptError, match="E_UNKNOWN_KEY"):
        verify_receipt_v2(path, trust_root_path=Path(keys["trust_root"]))
    root["keys"][0]["keyid"] = "ci-main"
    root["keys"][0]["identity"] = "https://example.invalid/wrong"
    Path(keys["trust_root"]).write_text(json.dumps(root), encoding="utf-8")
    with pytest.raises(EnterpriseReceiptError, match="E_IDENTITY_MISMATCH"):
        verify_receipt_v2(path, trust_root_path=Path(keys["trust_root"]))


def test_policy_digest_is_bound_to_receipt(tmp_path):
    keys = _keys(tmp_path)
    policy = {"schema": "factory.policy.v1", "quality": {"min_goldens": 1.0}}
    policy_sha = hashlib.sha256(canonical_json(policy)).hexdigest()
    policy_path = tmp_path / "policy.dsse.json"
    sign_policy_bundle(
        policy,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
        out=policy_path,
    )
    receipt_path, _ = _seal(tmp_path, _receipt(policy_sha256=policy_sha), keys)
    result = verify_receipt_v2(receipt_path, trust_root_path=Path(keys["trust_root"]), policy_bundle_path=policy_path)
    assert result["policy_status"] == "VERIFIED"
    bad_receipt, _ = _seal(tmp_path, _receipt(policy_sha256="0" * 64), keys)
    with pytest.raises(EnterpriseReceiptError, match="E_POLICY_DIGEST_MISMATCH"):
        verify_receipt_v2(bad_receipt, trust_root_path=Path(keys["trust_root"]), policy_bundle_path=policy_path)


def test_revocation_list_rejects_signer_at_receipt_time(tmp_path):
    keys = _keys(tmp_path)
    receipt_path, _ = _seal(tmp_path, _receipt(), keys)
    revocations_path = tmp_path / "revocations.dsse.json"
    sign_revocations(
        [{"keyid": keys["keyid"], "revoked_at": "2026-07-11T00:00:00+00:00", "reason": "key rotation"}],
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
        out=revocations_path,
    )
    with pytest.raises(EnterpriseReceiptError, match="E_SIGNER_REVOKED"):
        verify_receipt_v2(receipt_path, trust_root_path=Path(keys["trust_root"]), revocations_path=revocations_path)


def test_v1_is_readable_but_not_enterprise_verified(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"schema": "factory.receipt.v1", "module": "hsf", "ok": True}), encoding="utf-8")
    keys = _keys(tmp_path)
    result = verify_receipt_v2(path, trust_root_path=Path(keys["trust_root"]))
    assert result["verdict"] == "LEGACY_UNVERIFIED"


def test_v1_conversion_binds_tenant(tmp_path):
    value = receipt_v2_from_v1({"schema": "factory.receipt.v1", "module": "hsf", "stage": "compile", "feature": "f", "ok": True}, tenant_id="tenant-a")
    assert value["schema"] == "factory.receipt.v2"
    assert value["tenant_id"] == "tenant-a"


def test_missing_private_key_is_closed(tmp_path):
    with pytest.raises(EnterpriseReceiptError, match="E_PRIVATE_KEY_UNAVAILABLE"):
        seal_receipt_v2(_receipt(), private_key_path=tmp_path / "missing.pem", keyid="k", identity=IDENTITY, issuer=ISSUER, out=tmp_path / "out.json")


def test_cli_keygen_seal_and_verify(tmp_path, capsys):
    from factoryline.cli import main

    payload_path = tmp_path / "payload.json"
    payload_path.write_bytes(canonical_json(_receipt()) + b"\n")
    out = tmp_path / "envelope.json"
    assert main([
        "enterprise", "keygen", "--out-dir", str(tmp_path / "cli-keys"),
        "--keyid", "cli-key", "--identity", IDENTITY, "--issuer", ISSUER,
    ]) == 0
    assert main([
        "enterprise", "receipt-seal", str(payload_path),
        "--private-key", str(tmp_path / "cli-keys" / "cli-key.private.pem"),
        "--keyid", "cli-key", "--identity", IDENTITY, "--issuer", ISSUER,
        "--out", str(out),
    ]) == 0
    assert main([
        "enterprise", "verify", str(out),
        "--trust-root", str(tmp_path / "cli-keys" / "trust-root.json"),
    ]) == 0
    assert '"verdict": "VERIFIED"' in capsys.readouterr().out


def test_enterprise_workflow_uses_optional_extra_and_no_network_service():
    workflow = Path(".github/workflows/enterprise-receipts.yml").read_text(encoding="utf-8")
    assert '.[dev,enterprise]' in workflow
    assert "offline-foundation" in workflow
    assert "tests/test_enterprise_receipts.py" in workflow
