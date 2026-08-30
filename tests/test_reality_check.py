from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.reality_check import RealityCheckError, inspect_reality_intent, run_reality_check, validate_reality_check_manifest, validate_reality_check_receipt, write_reality_check_artifacts


def _e2e() -> dict[str, object]:
    return {
        "schema": "factory.e2e_proof_manifest.v1", "id": "approval-flow-e2e",
        "approval": {"state": "approved", "approved_by": "reviewer"}, "working_directory": ".",
        "timeout_seconds": 10, "network_egress": "not_granted",
        "positive": {"argv": [sys.executable, "-c", "from pathlib import Path; Path('proof.txt').write_text('approved')"]},
        "negative": {"argv": [sys.executable, "-c", "import sys; sys.exit(1)"]}, "artifact_paths": ["proof.txt"],
    }


def _reality() -> dict[str, object]:
    return {
        "schema": "factory.reality-check-manifest.v1", "id": "approval-flow",
        "approval": {"state": "approved", "approved_by": "reviewer"},
        "behavior": {"promise": "A manager can approve a request.", "happy_path": "Approved request is recorded.", "failure_case": "A non-manager cannot approve."},
        "intent_assertions": [
            {"id": "manager-can-approve", "statement": "Manager approval is recorded.", "evidence": "positive"},
            {"id": "non-manager-blocked", "statement": "Non-manager approval is rejected.", "evidence": "negative"},
        ],
        "e2e_manifest": "approval.e2e.json",
    }


def _write(root: Path, *, negative: list[str] | None = None) -> Path:
    e2e = _e2e()
    if negative is not None:
        e2e["negative"] = {"argv": negative}
    (root / "approval.e2e.json").write_text(json.dumps(e2e), encoding="utf-8")
    manifest = root / "approval.reality.json"; manifest.write_text(json.dumps(_reality()), encoding="utf-8")
    return manifest


def test_validate_reality_check_manifest_requires_approved_behavior_contract(tmp_path: Path) -> None:
    manifest = _write(tmp_path)
    validated = validate_reality_check_manifest(tmp_path, manifest)
    assert validated["id"] == "approval-flow"
    assert validated["e2e_manifest"]["path"] == "approval.e2e.json"


def test_reality_check_rejects_unresolved_behavior_intent(tmp_path: Path) -> None:
    manifest = _write(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["behavior"]["promise"] = "Make it better."
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RealityCheckError) as exc:
        validate_reality_check_manifest(tmp_path, manifest)
    assert exc.value.code == "REALITY_CHECK_INTENT_UNCLEAR"


def test_inspect_reality_intent_reports_deep_positive_and_negative_coverage_without_execution(tmp_path: Path) -> None:
    inspection = inspect_reality_intent(tmp_path, _write(tmp_path))
    assert inspection["marker"] == "REALITY_INTENT_CONTRACT_READY"
    assert inspection["execution"] is False
    assert inspection["positive_assertion_ids"] == ["manager-can-approve"]
    assert inspection["negative_assertion_ids"] == ["non-manager-blocked"]


def test_reality_check_binds_a_behavior_to_proof_by_sabotage_and_writes_public_artifacts(tmp_path: Path) -> None:
    receipt = run_reality_check(tmp_path, _write(tmp_path))
    assert receipt["marker"] == "REALITY_CHECK_VERIFIED"
    assert receipt["ok"] is True
    assert receipt["manifest"]["behavior"]["failure_case"] == "A non-manager cannot approve."
    assert receipt["e2e_receipt"]["marker"] == "E2E_PROOF_PASS"
    assert all(item["verified"] for item in receipt["intent_verification"])
    assert all(value is False for key, value in receipt["authority"].items() if key not in {"execution", "test_execution"})
    assert validate_reality_check_receipt(receipt) is receipt
    paths = write_reality_check_artifacts(receipt, tmp_path / "packet")
    assert all(Path(path).is_file() for path in paths.values())


def test_reality_check_reports_hollow_negative_and_tamper_fails_closed(tmp_path: Path) -> None:
    receipt = run_reality_check(tmp_path, _write(tmp_path, negative=[sys.executable, "-c", "pass"]))
    assert (receipt["marker"], receipt["ok"]) == ("REALITY_CHECK_HOLLOW", False)
    receipt["manifest"]["behavior"]["promise"] = "tampered"
    with pytest.raises(RealityCheckError, match="SHA-256"):
        validate_reality_check_receipt(receipt)


def test_reality_check_cli_returns_zero_only_for_verified_behavior(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = _write(tmp_path)
    assert main(["reality", "inspect", "--root", str(tmp_path), "--manifest", manifest.name, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "REALITY_INTENT_CONTRACT_READY"
    assert main(["reality", "verify", "--root", str(tmp_path), "--manifest", manifest.name, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["receipt"]["marker"] == "REALITY_CHECK_VERIFIED"
    _write(tmp_path, negative=[sys.executable, "-c", "pass"])
    assert main(["reality", "verify", "--root", str(tmp_path), "--manifest", manifest.name, "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["receipt"]["marker"] == "REALITY_CHECK_HOLLOW"


def test_reality_check_rejects_unapproved_contract_without_executing(tmp_path: Path) -> None:
    manifest = _write(tmp_path)
    value = _reality(); value["approval"] = {"state": "pending", "approved_by": "reviewer"}
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RealityCheckError, match="approved"):
        run_reality_check(tmp_path, manifest)
