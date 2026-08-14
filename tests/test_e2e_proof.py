from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from factoryline.cli import main
from factoryline.e2e_proof import (
    E2EProofError,
    public_e2e_proof_receipt,
    validate_e2e_proof_manifest,
    validate_e2e_proof_receipt,
    verify_e2e_proof,
    write_e2e_proof_artifacts,
)


def _manifest(root: Path, *, positive: list[str] | None = None, negative: list[str] | None = None,
              artifacts: list[str] | None = None, timeout_seconds: int = 10, **overrides: object) -> Path:
    value: dict[str, object] = {
        "schema": "factory.e2e_proof_manifest.v1",
        "id": "login-e2e",
        "approval": {"state": "approved", "approved_by": "qa-owner"},
        "working_directory": ".",
        "timeout_seconds": timeout_seconds,
        "network_egress": "not_granted",
        "positive": {"argv": positive or [sys.executable, "-c", "from pathlib import Path; Path('artifact.txt').write_text('ok')"]},
        "negative": {"argv": negative or [sys.executable, "-c", "import sys; sys.exit(1)"]},
        "artifact_paths": artifacts or ["artifact.txt"],
    }
    value.update(overrides)
    path = root / "e2e-proof.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_native_e2e_gate_proves_a_declared_negative_case_and_writes_explicit_artifacts(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    validated_manifest = validate_e2e_proof_manifest(tmp_path, manifest)
    receipt = verify_e2e_proof(tmp_path, manifest)

    assert validated_manifest["approval"] == {"state": "approved", "approved_by": "qa-owner"}
    assert receipt["schema"] == "factory.e2e_proof_receipt.v1"
    assert receipt["marker"] == "E2E_PROOF_PASS"
    assert receipt["ok"] is True
    assert receipt["commands"]["positive"]["exit_code"] == 0
    assert receipt["commands"]["negative"]["exit_code"] == 1
    assert receipt["artifacts"][0]["path"] == "artifact.txt"
    assert receipt["authority"]["execution"] is True
    assert receipt["authority"]["publication"] is False
    assert "does not enforce host or process network isolation" in receipt["scope_limits"][1]
    assert "_captures" not in public_e2e_proof_receipt(receipt)
    assert validate_e2e_proof_receipt(receipt) is receipt

    packet = write_e2e_proof_artifacts(receipt, tmp_path / "packet")
    assert packet["marker"] == "E2E_PROOF_ARTIFACTS_WRITTEN"
    assert set(packet["paths"]) == {
        "json", "markdown", "mermaid", "positive_stdout", "positive_stderr", "negative_stdout", "negative_stderr",
    }
    public_file = json.loads(Path(packet["paths"]["json"]).read_text(encoding="utf-8"))
    assert "_captures" not in public_file
    assert public_file["receipt_sha256"] == receipt["receipt_sha256"]


def test_native_e2e_gate_reports_hollow_when_negative_command_succeeds(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, negative=[sys.executable, "-c", "pass"])

    receipt = verify_e2e_proof(tmp_path, manifest)

    assert receipt["marker"] == "HOLLOW_E2E_TEST"
    assert receipt["run_state"] == "negative_zero"
    assert receipt["ok"] is False
    assert receipt["commands"]["negative"]["exit_code"] == 0


def test_native_e2e_gate_records_positive_failures_and_timeouts_without_claiming_success(tmp_path: Path) -> None:
    positive_failure = _manifest(
        tmp_path,
        positive=[sys.executable, "-c", "import sys; sys.exit(7)"],
        artifacts=[],
    )
    failed = verify_e2e_proof(tmp_path, positive_failure)
    assert (failed["marker"], failed["run_state"], failed["ok"]) == ("E2E_POSITIVE_FAILED", "positive_nonzero", False)

    timeout_root = tmp_path / "timeout"
    timeout_root.mkdir()
    timed_manifest = _manifest(
        timeout_root,
        positive=[sys.executable, "-c", "import time; time.sleep(1.5)"],
        negative=[sys.executable, "-c", "import sys; sys.exit(1)"],
        artifacts=[],
        timeout_seconds=1,
    )
    timed = verify_e2e_proof(timeout_root, timed_manifest)
    assert (timed["marker"], timed["run_state"], timed["ok"]) == ("E2E_POSITIVE_TIMEOUT", "positive_timeout", False)


@pytest.mark.parametrize("overrides", [
    {"approval": {"state": "draft", "approved_by": "qa-owner"}},
    {"network_egress": "external_upload"},
    {"positive": {"argv": "python -m pytest"}},
    {"artifact_paths": ["../outside.txt"]},
])
def test_native_e2e_gate_rejects_unapproved_or_unsafe_manifests_before_execution(tmp_path: Path, overrides: dict[str, object]) -> None:
    positive = [sys.executable, "-c", "from pathlib import Path; Path('should-not-run.txt').write_text('bad')"]
    values: dict[str, object] = {"positive": positive, "artifacts": []}
    values.update(overrides)
    manifest = _manifest(tmp_path, **values)

    with pytest.raises(E2EProofError) as exc:
        verify_e2e_proof(tmp_path, manifest)

    assert exc.value.code in {"E2E_MANIFEST_UNAPPROVED", "E2E_EGRESS_NOT_GRANTED", "E2E_MANIFEST_INVALID"}
    assert not (tmp_path / "should-not-run.txt").exists()


def test_native_e2e_gate_reports_missing_declared_artifact_and_rejects_tampered_receipts(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, positive=[sys.executable, "-c", "pass"], artifacts=["missing.png"])
    receipt = verify_e2e_proof(tmp_path, manifest)

    assert (receipt["marker"], receipt["run_state"], receipt["ok"]) == ("E2E_ARTIFACT_MISSING", "artifact_missing", False)
    receipt["marker"] = "E2E_PROOF_PASS"
    with pytest.raises(E2EProofError) as exc:
        write_e2e_proof_artifacts(receipt, tmp_path / "tampered")
    assert exc.value.code == "E2E_PROOF_RECEIPT_INVALID"

    proof_manifest = _manifest(tmp_path, artifacts=[])
    proof_receipt = verify_e2e_proof(tmp_path, proof_manifest)
    proof_receipt["mermaid"] = "flowchart LR\n  A --> B\n"
    with pytest.raises(E2EProofError) as exc:
        public_e2e_proof_receipt(proof_receipt)
    assert exc.value.code == "E2E_PROOF_RECEIPT_INVALID"


def test_native_e2e_cli_is_json_safe_and_returns_one_for_a_hollow_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = _manifest(tmp_path, negative=[sys.executable, "-c", "pass"])

    code = main([
        "e2e", "verify", "--root", str(tmp_path), "--manifest", manifest.name,
        "--out-dir", str(tmp_path / "packet"), "--json",
    ])

    output = json.loads(capsys.readouterr().out)
    assert code == 1
    assert output["receipt"]["marker"] == "HOLLOW_E2E_TEST"
    assert output["artifacts"]["marker"] == "E2E_PROOF_ARTIFACTS_WRITTEN"
    assert "_captures" not in output["receipt"]
