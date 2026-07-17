from __future__ import annotations

import json
import subprocess
from pathlib import Path

from factoryline.migration import (
    READINESS_CATEGORIES,
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
