from __future__ import annotations

import json
from pathlib import Path

from factoryline.appforge_eas import appforge_eas_projection, verify_eas_preflight
from factoryline.appforge_evidence_kit import CANDIDATE_SCHEMA
from factoryline.cli import main


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _candidate(root: Path) -> Path:
    return _write(root / "candidate.json", {"schema": CANDIDATE_SCHEMA, "candidate": {"bundle_identifier": "com.example.calm", "version": "1.0", "build_number": "42", "source_commit": "a" * 40}})


def _eas(root: Path, value: object | None = None) -> Path:
    return _write(root / "eas.json", value or {"build": {"production": {"distribution": "store"}}, "submit": {"production": {"ios": {"ascAppId": "1234567890"}}}})


def test_eas_preflight_is_candidate_bound_and_never_an_execution(tmp_path: Path) -> None:
    receipt = verify_eas_preflight(tmp_path, _candidate(tmp_path), _eas(tmp_path), "production", "production", out=Path(".factory/appforge/eas-preflight.json"))

    assert receipt["ok"] is True
    assert receipt["marker"] == "APPFORGE_EAS_PREFLIGHT_READY"
    assert receipt["profiles"]["asc_app_id"] == "1234567890"
    assert receipt["authority"]["credential_access"] is False
    assert receipt["authority"]["eas_build_execute"] is False
    assert appforge_eas_projection(tmp_path)["current_count"] == 1


def test_eas_preflight_fails_closed_for_missing_app_id_or_secret(tmp_path: Path) -> None:
    missing = verify_eas_preflight(tmp_path, _candidate(tmp_path), _eas(tmp_path, {"build": {"production": {}}, "submit": {"production": {"ios": {}}}}), "production", "production")
    assert missing["ok"] is False
    assert any(item["code"] == "APPFORGE_EAS_ASC_APP_ID_MISSING" for item in missing["findings"])

    with_secret = verify_eas_preflight(tmp_path, _candidate(tmp_path), _eas(tmp_path, {"token": "do-not-store", "build": {"production": {}}, "submit": {"production": {"ios": {"ascAppId": "123"}}}}), "production", "production")
    assert with_secret["ok"] is False
    assert any(item["code"] == "APPFORGE_EAS_SECRET_IN_CONFIG" for item in with_secret["findings"])


def test_eas_preflight_cli_writes_an_explicit_local_handoff(tmp_path: Path, capsys) -> None:
    _candidate(tmp_path)
    _eas(tmp_path)
    assert main([
        "revenue", "appforge-eas", "--root", str(tmp_path), "--candidate", "candidate.json", "--eas-json", "eas.json",
        "--build-profile", "production", "--submit-profile", "production", "--out", ".factory/appforge/eas-preflight.json", "--json",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "APPFORGE_EAS_PREFLIGHT_READY"
    assert result["path"] == ".factory/appforge/eas-preflight.json"
