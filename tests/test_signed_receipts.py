import json
from pathlib import Path
import subprocess

import pytest

from factoryline.signed_receipts import (
    SignedReceiptError,
    bundle_path_for,
    receipt_status,
    resolve_sigstore_command,
    sign_receipt,
    validate_receipt,
    verify_receipt,
)


def _receipt(tmp_path: Path) -> Path:
    path = tmp_path / "build.json"
    path.write_text(
        json.dumps({"schema": "factory.receipt.v2", "module": "factoryline", "ok": True}),
        encoding="utf-8",
    )
    return path


def test_receipt_validation_rejects_non_receipt_json(tmp_path):
    path = tmp_path / "not-receipt.json"
    path.write_text('{"schema":"other.v1"}', encoding="utf-8")
    with pytest.raises(SignedReceiptError, match="E_INVALID_RECEIPT"):
        validate_receipt(path)


def test_unsigned_receipt_is_never_reported_verified(tmp_path):
    result = receipt_status(_receipt(tmp_path))
    assert result.verdict == "UNSIGNED"
    assert result.to_dict()["schema"] == "factory.sigstore.result.v1"


def test_missing_sigstore_returns_install_action(monkeypatch):
    monkeypatch.setattr("factoryline.signed_receipts.shutil.which", lambda name: None)
    monkeypatch.setattr("factoryline.signed_receipts.importlib.util.find_spec", lambda name: None)
    with pytest.raises(SignedReceiptError, match="E_SIGSTORE_UNAVAILABLE") as error:
        resolve_sigstore_command()
    assert "factoryline-code-factory[sigstore]" in str(error.value)


def test_sign_receipt_delegates_to_sigstore_and_requires_bundle(tmp_path, monkeypatch):
    receipt = _receipt(tmp_path)

    def fake_run(args, **kwargs):
        assert args[-2:] == ["sign", str(receipt.resolve())]
        assert kwargs["timeout"] == 300
        bundle_path_for(receipt.resolve()).write_text('{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}')
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("factoryline.signed_receipts.subprocess.run", fake_run)
    result = sign_receipt(receipt, command=["sigstore"])
    assert result.verdict == "SIGNED"
    assert Path(result.bundle_path).exists()


def test_sign_receipt_fails_when_sigstore_produces_no_bundle(tmp_path, monkeypatch):
    receipt = _receipt(tmp_path)
    monkeypatch.setattr(
        "factoryline.signed_receipts.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, "", ""),
    )
    with pytest.raises(SignedReceiptError, match="E_SIGNING_FAILED"):
        sign_receipt(receipt, command=["sigstore"])


def test_verify_requires_expected_identity_before_running_sigstore(tmp_path):
    receipt = _receipt(tmp_path)
    with pytest.raises(SignedReceiptError, match="E_IDENTITY_REQUIRED"):
        verify_receipt(receipt, cert_identity="", cert_oidc_issuer="issuer", command=["sigstore"])


def test_verify_without_bundle_returns_unsigned_without_running_sigstore(tmp_path, monkeypatch):
    receipt = _receipt(tmp_path)
    monkeypatch.setattr(
        "factoryline.signed_receipts.subprocess.run",
        lambda *args, **kwargs: pytest.fail("Sigstore must not run without a bundle"),
    )
    result = verify_receipt(
        receipt,
        cert_identity="workflow@example",
        cert_oidc_issuer="https://issuer.example",
        command=["sigstore"],
    )
    assert result.verdict == "UNSIGNED"


def test_verify_delegates_identity_chain_and_transparency_checks(tmp_path, monkeypatch):
    receipt = _receipt(tmp_path)
    bundle_path_for(receipt).write_text("{}", encoding="utf-8")

    def fake_run(args, **kwargs):
        assert args[-4:] == [
            "--cert-identity", "workflow@example", "--cert-oidc-issuer", "https://issuer.example"
        ]
        return subprocess.CompletedProcess(args, 0, "Verified OK", "")

    monkeypatch.setattr("factoryline.signed_receipts.subprocess.run", fake_run)
    result = verify_receipt(
        receipt,
        cert_identity="workflow@example",
        cert_oidc_issuer="https://issuer.example",
        command=["sigstore"],
    )
    assert result.verdict == "SIGSTORE_IDENTITY_VERIFIED"
    assert result.verification_method == "sigstore_identity"


def test_verify_is_fail_closed_on_sigstore_rejection(tmp_path, monkeypatch):
    receipt = _receipt(tmp_path)
    bundle_path_for(receipt).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.signed_receipts.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 1, "", "signature mismatch"),
    )
    with pytest.raises(SignedReceiptError, match="E_VERIFICATION_FAILED"):
        verify_receipt(
            receipt,
            cert_identity="workflow@example",
            cert_oidc_issuer="https://issuer.example",
            command=["sigstore"],
        )


def test_cli_receipt_status_is_json_and_unsigned_is_nonzero(tmp_path, capsys):
    from factoryline.cli import main

    receipt = _receipt(tmp_path)
    assert main(["receipt", "status", str(receipt)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "factory.sigstore.result.v1"
    assert payload["verdict"] == "UNSIGNED"
    assert "module" not in payload


def test_cli_receipt_verify_requires_identity(capsys):
    from factoryline.cli import main

    with pytest.raises(SystemExit, match="2"):
        main(["receipt", "verify", "receipt.json"])
    assert "--cert-identity" in capsys.readouterr().err


def test_sigstore_workflow_uses_oidc_and_verifies_exact_workflow_identity():
    workflow = Path(".github/workflows/signed-receipts.yml").read_text(encoding="utf-8")
    assert "id-token: write" in workflow
    assert "persist-credentials: false" in workflow
    assert "verify: true" in workflow
    assert "signed-receipts.yml@refs/heads/main" in workflow
    assert "https://token.actions.githubusercontent.com" in workflow
    assert "tampered receipt unexpectedly verified" in workflow
    assert "PYPI_TOKEN" not in workflow
