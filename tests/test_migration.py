from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from factoryline.migration import (
    READINESS_CATEGORIES,
    MigrationError,
    assess_migration_readiness,
    build_repository_context,
    verify_migration_readiness,
    verify_repository_context,
)


def _manifest(root: Path, *, complete: bool = True) -> Path:
    evidence = root / "proof.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    categories = READINESS_CATEGORIES if complete else READINESS_CATEGORIES[:-1]
    payload = {
        "schema": "factory.migration.readiness-input.v1",
        "project": "legacy-modernization",
        "checks": [
            {
                "id": f"check-{category}", "category": category,
                "command": ["tool", "verify", category], "passed": True,
                "evidence": [str(evidence)],
                **({"reproducibility_runs": {"passed": 2, "total": 2}} if category == "environment" else {}),
            }
            for category in categories
        ],
    }
    path = root / "readiness-input.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_migration_readiness_separates_registration_from_executable_proof(tmp_path: Path):
    partial = assess_migration_readiness(_manifest(tmp_path, complete=False), tmp_path)
    assert partial["ready"] is False
    assert partial["lane_registration_pct"] < 100
    assert partial["executable_proof_pct"] < 100
    full = assess_migration_readiness(_manifest(tmp_path), tmp_path, force=True)
    assert full["ready"] is True
    assert full["lane_registration_pct"] == 100
    assert full["executable_proof_pct"] == 100
    assert verify_migration_readiness(Path(full["path"]))["ready"] is True
    (tmp_path / "proof.json").write_text('{"passed": false}\n', encoding="utf-8")
    assert verify_migration_readiness(Path(full["path"]))["valid"] is False


def test_autowiki_and_lore_are_bound_to_tracked_facts(tmp_path: Path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "tests@example.com"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Tests"], check=True)
    (tmp_path / "adr").mkdir()
    (tmp_path / "adr" / "0001-choice.md").write_text("# Keep migrations reversible\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "record reversible migration"], check=True, capture_output=True)
    receipt = build_repository_context(tmp_path)
    assert receipt["tracked_files"] == 2
    assert verify_repository_context(Path(receipt["path"]))["valid"] is True
    lore = tmp_path / ".factory" / "context" / "LORE.md"
    assert "Keep migrations reversible" in lore.read_text(encoding="utf-8")
    lore.write_text("tampered\n", encoding="utf-8")
    assert verify_repository_context(Path(receipt["path"]))["valid"] is False


def test_readiness_rejects_invalid_argv_and_implicit_replacement(tmp_path: Path):
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["checks"][0]["command"] = "tool verify"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(MigrationError, match="argv command") as invalid:
        assess_migration_readiness(manifest, tmp_path)
    assert invalid.value.code == "MIGRATION_READINESS_INPUT"

    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    environment = next(check for check in payload["checks"] if check["category"] == "environment")
    environment["reproducibility_runs"] = {"passed": 1, "total": 1}
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    insufficient = assess_migration_readiness(manifest, tmp_path)
    assert insufficient["ready"] is False
    assert "environment" in insufficient["unverified_categories"]

    manifest = _manifest(tmp_path)
    assess_migration_readiness(manifest, tmp_path, force=True)
    with pytest.raises(MigrationError) as replay:
        assess_migration_readiness(manifest, tmp_path)
    assert replay.value.code == "MIGRATION_ARTIFACT_EXISTS"


def test_migration_verifiers_fail_closed_on_malformed_records(tmp_path: Path):
    readiness = assess_migration_readiness(_manifest(tmp_path), tmp_path)
    readiness_path = Path(readiness["path"])
    payload = json.loads(readiness_path.read_text(encoding="utf-8"))
    payload["evidence"] = [
        None,
        {"path": "", "sha256": "bad"},
        {"path": str(tmp_path / "proof.json"), "sha256": "bad"},
    ]
    readiness_path.write_text(json.dumps(payload), encoding="utf-8")
    result = verify_migration_readiness(readiness_path)
    assert result["valid"] is False
    assert any("must be an object" in error for error in result["errors"])
    assert any("path is invalid" in error for error in result["errors"])
    assert any("sha256 is invalid" in error for error in result["errors"])

    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.email", "tests@example.com"], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Tests"], check=True)
    (repository / "app.py").write_text("print('ok')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-m", "initial"], check=True, capture_output=True)
    context = build_repository_context(repository)
    context_path = Path(context["path"])
    context_payload = json.loads(context_path.read_text(encoding="utf-8"))
    context_payload["artifacts"] = "not-a-list"
    context_path.write_text(json.dumps(context_payload), encoding="utf-8")
    context_result = verify_repository_context(context_path)
    assert context_result["valid"] is False
    assert "context artifact records must be a list" in context_result["errors"]


def test_readiness_evidence_cannot_escape_the_repository(tmp_path: Path):
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    outside = tmp_path.parent / "outside-proof.json"
    outside.write_text("{}\n", encoding="utf-8")
    payload["checks"][0]["evidence"] = [str(outside)]
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(MigrationError) as rejected:
        assess_migration_readiness(manifest, tmp_path)
    assert rejected.value.code == "MIGRATION_EVIDENCE_OUTSIDE_ROOT"
