from __future__ import annotations

import hashlib
import json
from pathlib import Path

from factoryline.appforge_mobile_evidence import mobile_evidence_projection, verify_mobile_evidence
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
    return {
        "tool": tool, "source_path": source.relative_to(root).as_posix(), "source_sha256": _sha(source), "platforms": platforms,
        "checks": {key: "passed" for key in checks},
        "release_stages": {stage: "not_attempted" for stage in STAGES},
        "production_signals": signals or {},
    }


def _evidence(root: Path, contract: Path) -> Path:
    reports = [
        _report(root, "xcodebuild", ["ios"], {"build", "tests", "accessibility", "design_system_conformance"}),
        _report(root, "android_gradle", ["android"], {"build", "tests", "adaptive_layout", "accessibility", "r8_permissions", "play_metadata", "design_system_conformance"}),
        _report(root, "fastlane", ["ios"], {"snapshot", "device_frames", "layout", "contrast", "store_assets"}),
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
