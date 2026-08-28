from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.external_evidence import (
    ExternalEvidenceError,
    diff_external_runtime_receipts,
    import_external_runtime_bundle,
    verify_external_runtime_receipt,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_bundle(
    root: Path,
    run_id: str,
    *,
    test_id: str = "checkout-approval",
    artifact_name: str = "runtime.txt",
    verdict: str = "failed",
    failure_kind: str = "assertion",
) -> Path:
    artifact = root / artifact_name
    artifact.write_text(f"{run_id}:{verdict}\n", encoding="utf-8")
    bundle = {
        "schema": "factory.external-runtime-bundle.v1",
        "provider": "testsprite",
        "project_id": "approval-tracker",
        "test_id": test_id,
        "run_id": run_id,
        "snapshot_id": f"snapshot-{run_id}",
        "code_version": f"commit-{run_id}",
        "environment": {"fingerprint": "linux-node-22", "label": "ci"},
        "verdict": verdict,
        "failure_kind": failure_kind,
        "first_failed_step": {"index": 2 if verdict == "failed" else None, "label": "submit" if verdict == "failed" else None},
        "hypothesis": "The approval transition is not persisted." if verdict == "failed" else "",
        "recommended_fix": "Check the transaction boundary." if verdict == "failed" else "",
        "artifacts": [{"path": artifact_name, "sha256": _sha(artifact), "kind": "runtime-log"}],
        "observed_at": "2026-08-24T12:00:00Z",
    }
    path = root / f"bundle-{run_id}.json"
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    return path


def test_testsprite_import_is_hash_bound_and_idempotent(tmp_path: Path):
    bundle = _write_bundle(tmp_path, "run-1")

    first = import_external_runtime_bundle(tmp_path, bundle, "testsprite")
    second = import_external_runtime_bundle(tmp_path, bundle, "testsprite")
    receipt_path = tmp_path / first["path"]

    assert first["status"] == "written"
    assert second["status"] == "idempotent"
    assert receipt_path.is_file()
    verified = verify_external_runtime_receipt(tmp_path, receipt_path)
    receipt = verified["receipt"]
    assert receipt["provider"] == "testsprite"
    assert receipt["trust"] == "observed_external"
    assert all(value is False for value in receipt["authority"].values())
    assert receipt["source_bundle"]["sha256"] == _sha(bundle)


def test_tampered_artifact_fails_closed_without_receipt(tmp_path: Path):
    bundle = _write_bundle(tmp_path, "run-tampered")
    (tmp_path / "runtime.txt").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(ExternalEvidenceError) as error:
        import_external_runtime_bundle(tmp_path, bundle, "testsprite")

    assert error.value.code == "EXTERNAL_EVIDENCE_ARTIFACT_STALE"
    assert not (tmp_path / ".factory" / "external-evidence").exists()


def test_diff_reports_deterministic_deltas_and_rejects_cross_test(tmp_path: Path):
    left_bundle = _write_bundle(tmp_path, "run-left", artifact_name="left.txt")
    right_bundle = _write_bundle(tmp_path, "run-right", artifact_name="right.txt", verdict="passed", failure_kind="none")
    left = import_external_runtime_bundle(tmp_path, left_bundle, "testsprite", tmp_path / ".factory" / "external-evidence" / "left.json")
    right = import_external_runtime_bundle(tmp_path, right_bundle, "testsprite", tmp_path / ".factory" / "external-evidence" / "right.json")

    diff = diff_external_runtime_receipts(tmp_path, Path(left["path"]), Path(right["path"]))
    assert diff["marker"] == "EXTERNAL_DIFF_COMPARABLE"
    assert diff["comparable"] is True
    assert diff["deltas"]["verdict"]["changed"] is True
    assert diff["deltas"]["artifacts"]["added"] == ["right.txt"]
    assert diff["deltas"]["artifacts"]["removed"] == ["left.txt"]
    assert all(value is False for value in diff["authority"].values())

    other_bundle = _write_bundle(tmp_path, "run-other", test_id="different-test", artifact_name="other.txt")
    other = import_external_runtime_bundle(tmp_path, other_bundle, "testsprite", tmp_path / ".factory" / "external-evidence" / "other.json")
    incomparable = diff_external_runtime_receipts(tmp_path, Path(left["path"]), Path(other["path"]))
    assert incomparable["marker"] == "EXTERNAL_DIFF_INCOMPARABLE"
    assert incomparable["comparable"] is False


def test_cli_import_and_diff_use_stable_status_codes(tmp_path: Path, capsys):
    left = _write_bundle(tmp_path, "cli-left", artifact_name="cli-left.txt")
    right = _write_bundle(tmp_path, "cli-right", artifact_name="cli-right.txt", verdict="passed", failure_kind="none")
    out_left = tmp_path / ".factory" / "external-evidence" / "left.json"
    out_right = tmp_path / ".factory" / "external-evidence" / "right.json"

    assert main(["external", "import", str(left), "--root", str(tmp_path), "--provider", "testsprite", "--out", str(out_left), "--json"]) == 0
    capsys.readouterr()
    assert main(["external", "import", str(right), "--root", str(tmp_path), "--provider", "testsprite", "--out", str(out_right), "--json"]) == 0
    capsys.readouterr()
    assert main(["external", "diff", str(out_left), str(out_right), "--root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == "EXTERNAL_DIFF_COMPARABLE"
