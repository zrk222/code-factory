from __future__ import annotations

import json
from pathlib import Path

import factoryline.release_candidate as candidate


def _source(root: Path, *, version: str = "0.46.3") -> None:
    (root / "factoryline").mkdir(parents=True)
    (root / "pyproject.toml").write_text(f"[project]\nversion = \"{version}\"\n", encoding="utf-8")
    (root / "factoryline" / "__init__.py").write_text(f"__version__ = \"{version}\"\n", encoding="utf-8")


def _contract(root: Path, *, version: str = "0.46.3", commit: str = "a" * 40) -> Path:
    path = root / "contract.json"
    path.write_text(json.dumps({"schema": "factory.release-contract.v1", "feature": "release", "candidate": {"source_version": version, "source_commit": commit}}), encoding="utf-8")
    return path


def test_stale_python_artifact_is_rejected(monkeypatch, tmp_path: Path) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(candidate, "verify_release_contract", lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"})
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.2-py3-none-any.whl").write_bytes(b"old")

    result = candidate.release_candidate_preflight(tmp_path, _contract(tmp_path), [artifact_dir])

    assert result["ok"] is False
    assert any(item["code"] == "E_RELEASE_ARTIFACT_VERSION_MISMATCH" for item in result["blockers"])
    assert result["marker"] == "RELEASE_CANDIDATE_PREFLIGHT_BLOCKED"


def test_matching_artifact_and_source_binding_pass(monkeypatch, tmp_path: Path) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(candidate, "verify_release_contract", lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"})
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(b"new")

    result = candidate.release_candidate_preflight(tmp_path, _contract(tmp_path), [artifact_dir])

    assert result["ok"] is True
    assert result["marker"] == "RELEASE_CANDIDATE_PREFLIGHT_PASS"
    assert result["facts"]["artifact_versions_match"] is True
    assert result["artifacts"]["artifacts"][0]["platform"] == "python"


def test_missing_artifact_inventory_fails_closed(monkeypatch, tmp_path: Path) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(candidate, "verify_release_contract", lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"})

    result = candidate.release_candidate_preflight(tmp_path, _contract(tmp_path), [tmp_path / "empty"])

    assert result["ok"] is False
    assert any(item["code"] == "E_RELEASE_ARTIFACT_MISSING" for item in result["blockers"])


def test_source_commit_mismatch_blocks_before_candidate_pass(monkeypatch, tmp_path: Path) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "b" * 40)
    monkeypatch.setattr(candidate, "verify_release_contract", lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"})
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(b"new")

    result = candidate.release_candidate_preflight(tmp_path, _contract(tmp_path), [artifact_dir])

    assert result["ok"] is False
    assert any(item["code"] == "RELEASE_CONTRACT_SOURCE_MISMATCH" for item in result["blockers"])


def test_requested_active_metadata_is_part_of_candidate_decision(monkeypatch, tmp_path: Path) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(candidate, "verify_release_contract", lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"})
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(b"new")
    progress = tmp_path / "Progress.md"
    progress.write_text("[2026-09-06 10:00] event\n[2026-09-06 09:00] event\n", encoding="utf-8")

    result = candidate.release_candidate_preflight(tmp_path, _contract(tmp_path), [artifact_dir], [progress])

    assert result["ok"] is False
    assert result["facts"]["ledger_drift"] is True
    assert any(item["code"] == "E_METADATA_LEDGER_ORDER" for item in result["blockers"])
