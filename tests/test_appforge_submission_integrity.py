from __future__ import annotations
import json
from pathlib import Path
import pytest
from factoryline.appforge_submission_integrity import CONTRACT_SCHEMA, verify_submission_integrity, submission_integrity_projection, reconcile_capture_evidence
from factoryline.revenueforge import RevenueForgeError

def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value), encoding="utf-8"); return path

def _candidate(root: Path) -> tuple[Path, dict[str, str]]:
    candidate = {"bundle_identifier": "com.example.proof", "version": "1.0", "build_number": "7", "source_commit": "a" * 40}
    return _write(root / "candidate.json", {"schema": "factory.appforge.release-candidate.v1", "candidate": candidate}), candidate

def _contract(candidate: dict[str, str]) -> dict[str, object]:
    rows = []
    for device, count in (("iphone", 10), ("ipad_13", 3)):
        for n in range(count):
            rows.append({"id": f"{device}-{n + 1}", "device": device, "journey": "onboard", "state": f"state-{n + 1}", "entrypoint": "launch", "steps": ["launch", "continue"], "evidence_class": "native_signed_build", "layout_assertions": ["desktop_class_layout"] if device == "ipad_13" else []})
    return {"schema": CONTRACT_SCHEMA, "candidate": candidate, "requirements": rows, "approval": {"origin": "human_confirmed", "source": "approved screenshot brief"}}

def test_submission_integrity_requires_explicit_native_candidate_bound_10_plus_3(tmp_path: Path) -> None:
    candidate_path, candidate = _candidate(tmp_path); contract = _write(tmp_path / "contract.json", _contract(candidate))
    receipt = verify_submission_integrity(tmp_path, candidate_path, contract, Path(".factory/appforge/submission-integrity.json"))
    assert receipt["ok"] is True and receipt["coverage"]["iphone"]["actual"] == 10 and receipt["coverage"]["ipad_13"]["actual"] == 3
    assert submission_integrity_projection(tmp_path)["current_count"] == 1

def test_submission_integrity_projection_skips_non_object_json(tmp_path: Path) -> None:
    path = tmp_path / ".factory" / "appforge" / "bad-submission-integrity.json"; path.parent.mkdir(parents=True); path.write_text("[]", encoding="utf-8")
    projection = submission_integrity_projection(tmp_path)
    assert projection["current_count"] == 0 and projection["invalid_count"] == 1

def test_submission_integrity_blocks_loose_or_collateral_requirements_with_repairs(tmp_path: Path) -> None:
    candidate_path, candidate = _candidate(tmp_path); value = _contract(candidate)
    value["requirements"] = value["requirements"][:-1]; value["requirements"][0]["steps"] = []; value["requirements"][1]["evidence_class"] = "web_preview"
    receipt = verify_submission_integrity(tmp_path, candidate_path, _write(tmp_path / "loose.json", value), Path(".factory/appforge/blocked-submission-integrity.json"))
    assert receipt["ok"] is False
    assert {item["code"] for item in receipt["findings"]} >= {"E_REQUIREMENT_LOOSE", "E_COLLATERAL_EVIDENCE_REJECTED", "E_CAPTURE_COVERAGE_MISSING"}
    assert receipt["repair_plan"]

def test_submission_integrity_requires_human_or_trusted_approval(tmp_path: Path) -> None:
    candidate_path, candidate = _candidate(tmp_path); value = _contract(candidate); value["approval"] = {"origin": "agent_proposed", "source": "guess"}
    with pytest.raises(RevenueForgeError, match="human_confirmed"):
        verify_submission_integrity(tmp_path, candidate_path, _write(tmp_path / "bad.json", value), Path(".factory/appforge/no.json"))

def test_capture_reconciliation_blocks_missing_or_collateral_files(tmp_path: Path) -> None:
    candidate_path, candidate = _candidate(tmp_path); integrity = verify_submission_integrity(tmp_path, candidate_path, _write(tmp_path / "contract.json", _contract(candidate)), Path(".factory/appforge/integrity.json"))
    image = tmp_path / "capture.png"; image.write_bytes(b"native-candidate-capture")
    evidence = {"candidate": candidate, "captures": [{"requirement_id": "iphone-1", "device": "iphone", "evidence_class": "web_preview", "path": "capture.png", "sha256": "0" * 64}]}
    receipt = reconcile_capture_evidence(tmp_path, Path(integrity["path"]), _write(tmp_path / "evidence.json", evidence), Path(".factory/appforge/reconciled.json"))
    assert receipt["ok"] is False and {item["code"] for item in receipt["findings"]} >= {"E_CAPTURE_EVIDENCE_MISMATCH", "E_CAPTURE_EVIDENCE_MISSING"}
