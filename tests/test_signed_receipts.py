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
        json.dumps(
            {"schema": "factory.receipt.v2", "module": "factoryline", "ok": True}
        ),
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
    monkeypatch.setattr(
        "factoryline.signed_receipts.importlib.util.find_spec", lambda name: None
    )
    with pytest.raises(SignedReceiptError, match="E_SIGSTORE_UNAVAILABLE") as error:
        resolve_sigstore_command()
    assert "factoryline-code-factory[sigstore]" in str(error.value)


def test_sign_receipt_delegates_to_sigstore_and_requires_bundle(tmp_path, monkeypatch):
    receipt = _receipt(tmp_path)

    def fake_run(args, **kwargs):
        assert args[-2:] == ["sign", str(receipt.resolve())]
        assert kwargs["timeout"] == 300
        bundle_path_for(receipt.resolve()).write_text(
            '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}'
        )
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
        verify_receipt(
            receipt, cert_identity="", cert_oidc_issuer="issuer", command=["sigstore"]
        )


def test_verify_without_bundle_returns_unsigned_without_running_sigstore(
    tmp_path, monkeypatch
):
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
            "--cert-identity",
            "workflow@example",
            "--cert-oidc-issuer",
            "https://issuer.example",
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
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 1, "", "signature mismatch"
        ),
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
    assert "factory verify-receipts" in workflow
    assert ".factory/challenges/verify-receipts.json" in workflow
    assert "PYPI_TOKEN" not in workflow


def test_release_receipts_reject_local_runner(tmp_path, monkeypatch):
    from factoryline.signed_receipts import produce_ci_receipt

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(SignedReceiptError, match="E_CI_IDENTITY"):
        produce_ci_receipt(tmp_path, tmp_path / "receipt.json")


@pytest.mark.parametrize("index_flag", [None, "--assume-unchanged", "--skip-worktree"])
def test_ci_check_rejects_tracked_source_mutation(tmp_path, index_flag):
    import sys
    from factoryline.signed_receipts import _ci_run

    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    source = tmp_path / "candidate.py"
    source.write_text("VALUE = 1\n")
    subprocess.run(["git", "add", "candidate.py"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=CI fixture",
            "-c",
            "user.email=ci@example.invalid",
            "commit",
            "-m",
            "candidate",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    if index_flag:
        subprocess.run(
            ["git", "update-index", index_flag, "candidate.py"],
            cwd=tmp_path,
            check=True,
        )
    with pytest.raises(SignedReceiptError, match="E_CI_SOURCE_CHANGED"):
        _ci_run(
            tmp_path,
            "mutation",
            (
                sys.executable,
                "-c",
                "from pathlib import Path; Path('candidate.py').write_text('VALUE = 2\\n')",
            ),
        )
    assert not (tmp_path / "ci-mutation.log").exists()


def test_release_receipts_bind_commands_and_commit(tmp_path):
    from factoryline.signed_receipts import (
        CI_COMMANDS,
        CI_RECEIPT_SCHEMA,
        validate_ci_receipt,
    )

    path = tmp_path / "receipt.json"
    payload = {
        "schema": CI_RECEIPT_SCHEMA,
        "ok": True,
        "identity": {"commit": "a" * 40, "ref": "refs/heads/main"},
        "junit_sha256": "b" * 64,
        "commands": [
            {"name": n, "argv": list(a), "exit_code": 0} for n, a in CI_COMMANDS
        ],
    }
    path.write_text(json.dumps(payload))
    assert validate_ci_receipt(path, "a" * 40)["ok"]
    with pytest.raises(SignedReceiptError, match="E_CI_RECEIPT"):
        validate_ci_receipt(path, "c" * 40)
    payload["commands"][0]["exit_code"] = 1
    path.write_text(json.dumps(payload))
    with pytest.raises(SignedReceiptError, match="E_CI_RECEIPT"):
        validate_ci_receipt(path, "a" * 40)


def test_every_publisher_requires_attested_candidate_evidence():
    for name in (
        "publish",
        "jetbrains-marketplace",
        "vscode-marketplace",
        "openvsx",
        "huggingface-space",
    ):
        workflow = Path(f".github/workflows/{name}.yml").read_text()
        assert "factoryline.signed_receipts fetch-ci" in workflow, name


def test_ci_receipt_executes_only_one_fixed_check(tmp_path, monkeypatch):
    import factoryline.signed_receipts as receipts

    monkeypatch.setattr(receipts, "_ci_identity", lambda root: {"commit": "a" * 40})
    monkeypatch.setattr(receipts, "_ci_pristine", lambda root: None)
    executed = []

    def run(root, name, argv):
        executed.append(name)
        return {"name": name, "argv": list(argv), "exit_code": 0}

    monkeypatch.setattr(receipts, "_ci_run", run)
    monkeypatch.setattr(
        receipts.subprocess, "check_output", lambda *args, **kwargs: "pytest==8\n"
    )
    with pytest.raises(SignedReceiptError, match="E_CI_CHECK"):
        receipts.produce_ci_receipt(tmp_path, tmp_path / "receipt.json")
    result = receipts.produce_ci_receipt(tmp_path, tmp_path / "receipt.json", "quality")
    assert executed == ["quality"]
    assert result["schema"] == receipts.CI_CHECK_SCHEMA


def test_ci_aggregation_requires_all_source_bound_checks(tmp_path, monkeypatch):
    import factoryline.signed_receipts as receipts

    identity = {"commit": "a" * 40, "ref": "refs/heads/main"}
    monkeypatch.setattr(receipts, "_ci_identity", lambda root: identity)
    monkeypatch.setattr(receipts, "_ci_pristine", lambda root: None)
    for name, argv in receipts.CI_COMMANDS:
        check = {
            "schema": receipts.CI_CHECK_SCHEMA,
            "ok": True,
            "identity": identity,
            "commands": [{"name": name, "argv": list(argv), "exit_code": 0}],
            "environment": {},
            "dependencies": [],
            "junit_sha256": "b" * 64,
        }
        (tmp_path / f"ci-{name}.json").write_text(json.dumps(check))
    result = receipts.combine_ci_receipts(
        tmp_path, tmp_path, tmp_path / "combined.json"
    )
    assert receipts.validate_ci_payload(result, "a" * 40)["ok"]
    path = tmp_path / "ci-quality.json"
    invalid = json.loads(path.read_text())
    invalid["identity"]["commit"] = "c" * 40
    path.write_text(json.dumps(invalid))
    with pytest.raises(SignedReceiptError, match="E_CI_RECEIPT"):
        receipts.combine_ci_receipts(tmp_path, tmp_path, tmp_path / "bad.json")
    assert not (tmp_path / "bad.json").exists()


def test_ci_workflow_isolates_checks_and_signing_permissions():
    workflow = Path(".github/workflows/signed-receipts.yml").read_text()
    assert "check: [tests, architecture, quality, scanner_controls]" in workflow
    assert "needs: isolated-check" in workflow
    check_job, attestor = workflow.split("  sign-and-verify:", 1)
    check_permissions = check_job.split("    permissions:", 1)[1].split(
        "    steps:", 1
    )[0]
    assert "id-token:" not in check_permissions
    assert "attestations:" not in check_permissions
    assert "actions/checkout" not in attestor
    assert "pip install" not in attestor
    assert (
        "python -m pytest -n 2 -q --junitxml=ci-tests.xml > ci-tests.log" in check_job
    )
    assert "factoryline.signed_receipts run-ci" not in check_job
    assert check_job.index("factory verify-receipts") < check_job.index(
        "Record fixed-command evidence"
    )
    assert "recorded_hashes == [actual_hash]" in attestor
    assert "step['conclusion'] == 'success'" in attestor
    assert attestor.index("Validate isolated runner results") < attestor.index(
        "Attest the runner and source commit"
    )
