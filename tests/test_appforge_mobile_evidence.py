from __future__ import annotations

import hashlib
import json
from pathlib import Path

from factoryline.appforge_mobile_evidence import _sha as _canonical_sha, mobile_evidence_projection, verify_mobile_evidence
from factoryline.cli import main


CANDIDATE = {"bundle_identifier": "com.example.mobile", "version": "1.0.0", "build_number": "100", "source_commit": "a" * 40}
CHECKS = {
    "build", "tests", "snapshot", "device_frames", "layout", "contrast", "accessibility", "store_assets",
    "permissions", "privacy_manifest", "tracking_disclosure", "entitlements", "runtime_network", "listing_metadata",
    "design_system_conformance", "adaptive_layout", "r8_permissions", "play_metadata",
}
STAGES = ("build", "signing", "upload", "processing", "tester_group", "tester_invitation", "review_submission", "store_decision")


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _candidate(root: Path) -> Path:
    return _write(root / "candidate.json", {"schema": "factory.appforge.release-candidate.v1", "candidate": CANDIDATE})


def _contract(root: Path) -> Path:
    return _write(root / "contract.json", {
        "schema": "factory.appforge.mobile-evidence-contract.v1", "candidate": CANDIDATE, "platforms": ["ios", "android"],
        "user_design_input_sha256": hashlib.sha256(b"approved-design").hexdigest(),
        "required_checks": {key: True for key in CHECKS},
        "production_thresholds": {"crash_free_rate_min": 99.0, "anr_rate_max": 1.0, "hang_rate_max": 1.0, "startup_ms_max": 1200},
    })


def _report(root: Path, tool: str, platforms: list[str], checks: set[str], signals: dict[str, float] | None = None) -> dict[str, object]:
    source = root / "exports" / f"{tool}.json"
    _write(source, {"tool": tool, "observed": True})
    release_stages = {stage: "not_attempted" for stage in STAGES}
    # The fixture represents a locally signed candidate; store/provider stages
    # intentionally remain unattempted and are not treated as approval.
    release_stages["build"] = "passed"
    release_stages["signing"] = "passed"
    return {
        "tool": tool, "source_path": source.relative_to(root).as_posix(), "source_sha256": _sha(source), "platforms": platforms,
        "checks": {key: "passed" for key in checks},
        "release_stages": release_stages,
        "production_signals": signals or {},
    }


def _evidence(root: Path, contract: Path) -> Path:
    reports = [
        _report(root, "xcodebuild", ["ios"], {"build", "tests", "accessibility", "design_system_conformance"}),
        _report(root, "android_gradle", ["android"], {"build", "tests", "adaptive_layout", "accessibility", "r8_permissions", "play_metadata", "design_system_conformance"}),
        _report(root, "fastlane", ["ios"], {"snapshot", "device_frames", "layout", "contrast", "store_assets"}),
        _report(root, "device_cloud", ["android"], {"snapshot", "device_frames", "layout", "contrast", "store_assets"}),
        _report(root, "sentry", ["ios", "android"], {"permissions", "privacy_manifest", "tracking_disclosure", "entitlements", "runtime_network", "listing_metadata"}, {"crash_free_rate": 99.8, "anr_rate": 0.2, "hang_rate": 0.1, "startup_ms": 800}),
    ]
    return _write(root / "evidence.json", {"schema": "factory.appforge.mobile-evidence-input.v1", "candidate": CANDIDATE, "contract_sha256": _sha(contract), "reports": reports})


def test_mobile_evidence_normalizes_ios_android_and_store_gates(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    receipt = verify_mobile_evidence(tmp_path, candidate, contract, _evidence(tmp_path, contract), Path(".factory/appforge/mobile-evidence.json"))
    assert receipt["ok"] is True
    assert receipt["marker"] == "APPFORGE_MOBILE_EVIDENCE_READY"
    assert set(receipt["contract"]["platforms"]) == {"android", "ios"}
    assert mobile_evidence_projection(tmp_path)["latest"]["receipt_sha256"] == receipt["receipt_sha256"]


def test_mobile_evidence_fails_closed_when_a_source_report_changes(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    evidence = _evidence(tmp_path, contract)
    (tmp_path / "exports" / "sentry.json").write_text("tampered", encoding="utf-8")
    receipt = verify_mobile_evidence(tmp_path, candidate, contract, evidence, Path(".factory/appforge/mobile-evidence-blocked.json"))
    assert receipt["ok"] is False
    assert any(item["code"] == "APPFORGE_MOBILE_EVIDENCE_SOURCE_STALE" for item in receipt["findings"])


def test_mobile_evidence_cli_exposes_the_same_candidate_bound_gate(tmp_path: Path, capsys) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    evidence = _evidence(tmp_path, contract)
    assert main(["revenue", "appforge-mobile-evidence", "--root", str(tmp_path), "--candidate", candidate.name, "--contract", contract.name, "--evidence", evidence.name, "--out", ".factory/appforge/cli-mobile-evidence.json", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == "APPFORGE_MOBILE_EVIDENCE_READY"


def test_mobile_evidence_does_not_use_android_passes_for_missing_ios_checks(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    evidence = _evidence(tmp_path, contract)
    value = json.loads(evidence.read_text(encoding="utf-8"))
    value["reports"][0]["checks"] = {"build": "passed"}
    _write(evidence, value)
    receipt = verify_mobile_evidence(tmp_path, candidate, contract, evidence, Path("blocked.json"))
    assert receipt["ok"] is False
    assert any("ios:ios_native lacks passed evidence" in item["detail"] for item in receipt["findings"])


def test_mobile_evidence_rejects_failed_check_even_when_another_report_passes(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    evidence = _evidence(tmp_path, contract)
    value = json.loads(evidence.read_text(encoding="utf-8"))
    value["reports"][0]["checks"]["tests"] = "failed"
    _write(evidence, value)
    receipt = verify_mobile_evidence(tmp_path, candidate, contract, evidence, Path("blocked.json"))
    assert receipt["ok"] is False
    assert any(item["code"] == "APPFORGE_MOBILE_EVIDENCE_CHECK_FAILED" for item in receipt["findings"])


def test_mobile_evidence_rejects_nonfinite_production_metrics(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    evidence = _evidence(tmp_path, contract)
    value = json.loads(evidence.read_text(encoding="utf-8"))
    value["reports"][-1]["production_signals"]["anr_rate"] = float("nan")
    # The evidence input itself cannot be serialized with NaN in a canonical
    # receipt; write a raw JSON literal to exercise the parser boundary.
    evidence.write_text(json.dumps(value, allow_nan=True), encoding="utf-8")
    receipt = verify_mobile_evidence(tmp_path, candidate, contract, evidence, Path("blocked.json"))
    assert receipt["ok"] is False
    assert any(item["code"] == "APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID" for item in receipt["findings"])


def test_mobile_evidence_projection_uses_newest_receipt_not_lexical_path(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    first = verify_mobile_evidence(tmp_path, candidate, contract, _evidence(tmp_path, contract), Path(".factory/appforge/z-old-mobile-evidence.json"))
    second = verify_mobile_evidence(tmp_path, candidate, contract, _evidence(tmp_path, contract), Path(".factory/appforge/a-new-mobile-evidence.json"))
    import os
    old = tmp_path / first["path"]
    new = tmp_path / second["path"]
    os.utime(old, ns=(1_000_000_000, 1_000_000_000))
    os.utime(new, ns=(2_000_000_000, 2_000_000_000))

    assert mobile_evidence_projection(tmp_path)["latest"]["receipt_sha256"] == second["receipt_sha256"]


def test_mobile_evidence_requires_local_build_and_signing_per_platform(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    evidence = _evidence(tmp_path, contract)
    value = json.loads(evidence.read_text(encoding="utf-8"))
    for report in value["reports"]:
        report["release_stages"] = {stage: "not_attempted" for stage in STAGES}
    _write(evidence, value)
    receipt = verify_mobile_evidence(tmp_path, candidate, contract, evidence, Path("blocked.json"))
    assert receipt["ok"] is False
    assert any("release stage build" in item["detail"] for item in receipt["findings"])


def test_mobile_evidence_requires_platform_native_tool_provenance(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    evidence = _evidence(tmp_path, contract)
    value = json.loads(evidence.read_text(encoding="utf-8"))
    value["reports"][0]["platforms"] = ["android"]
    value["reports"][1]["platforms"] = ["ios"]
    _write(evidence, value)
    receipt = verify_mobile_evidence(tmp_path, candidate, contract, evidence, Path("blocked.json"))
    assert receipt["ok"] is False
    assert any(item["code"] in {"APPFORGE_MOBILE_EVIDENCE_IOS_TOOL_MISSING", "APPFORGE_MOBILE_EVIDENCE_ANDROID_TOOL_MISSING"} for item in receipt["findings"])


def test_mobile_projection_replays_receipt_and_masks_a_newer_forged_ready_value(tmp_path: Path) -> None:
    candidate, contract = _candidate(tmp_path), _contract(tmp_path)
    first = verify_mobile_evidence(tmp_path, candidate, contract, _evidence(tmp_path, contract), Path(".factory/appforge/old-mobile-evidence.json"))
    forged = dict(first)
    forged["path"] = None
    forged["reports"] = []
    forged["receipt_sha256"] = _canonical_sha({key: item for key, item in forged.items() if key not in {"receipt_sha256", "path"}})
    forged.pop("path", None)
    newer = tmp_path / ".factory/appforge/new-mobile-evidence.json"
    _write(newer, forged)
    import os
    os.utime(tmp_path / first["path"], ns=(1_000_000_000, 1_000_000_000))
    os.utime(newer, ns=(2_000_000_000, 2_000_000_000))
    projection = mobile_evidence_projection(tmp_path)
    assert projection["latest"] is None
    assert projection["marker"] == "APPFORGE_MOBILE_EVIDENCE_REVIEW_REQUIRED"


def test_mobile_projection_fails_closed_on_non_object_receipt(tmp_path: Path) -> None:
    path = tmp_path / ".factory" / "appforge" / "malformed-mobile-evidence.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[]", encoding="utf-8")

    projection = mobile_evidence_projection(tmp_path)

    assert projection["latest"] is None
    assert projection["invalid_count"] == 1
    assert projection["marker"] == "APPFORGE_MOBILE_EVIDENCE_REVIEW_REQUIRED"
