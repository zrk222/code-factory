from __future__ import annotations

import json
import shutil
from pathlib import Path

from factoryline.cli import main
from factoryline.release_integrity import release_integrity, render_release_integrity


ROOT = Path(__file__).parents[1]
WORKFLOWS = ("publish.yml", "openvsx.yml", "jetbrains-marketplace.yml", "huggingface-space.yml")
INTELLIJ_FILES = (
    "editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt",
    "editors/intellij/settings.gradle.kts",
    "editors/intellij/build.gradle.kts",
)
HUGGINGFACE_FILES = ("deploy/huggingface/README.md",)
PACKAGE_FILES = ("pyproject.toml",)


def _workflow_copy(tmp_path: Path) -> Path:
    destination = tmp_path / ".github" / "workflows"
    destination.mkdir(parents=True)
    for name in WORKFLOWS:
        shutil.copy2(ROOT / ".github" / "workflows" / name, destination / name)
    for relative in INTELLIJ_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    for relative in HUGGINGFACE_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    for relative in PACKAGE_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    return tmp_path


def test_release_integrity_reports_exact_read_only_happy_path() -> None:
    before = {name: (ROOT / ".github" / "workflows" / name).read_bytes() for name in WORKFLOWS}

    result = release_integrity(ROOT)

    assert result["schema"] == "factory.release_integrity.v1"
    assert result["marker"] == "RELEASE_INTEGRITY_READ_ONLY"
    assert result["ok"] is True
    assert [item["id"] for item in result["checks"]] == [
        "RELEASE_FAN_IN_EXACT",
        "RELEASE_VALIDATION_PARTITIONED",
        "OPENVSX_AUTHORIZATION_EARLY",
        "PYPI_TRUSTED_PUBLISHING",
        "JETBRAINS_APPROVAL_GUARD",
        "INTELLIJ_COMPATIBILITY_DECLARED",
        "HUGGINGFACE_METADATA_PREFLIGHT",
        "PYTHON_PACKAGE_DATA_EXPLICIT",
    ]
    assert all(item["passed"] for item in result["checks"])
    assert not any(result["authority"].values())
    assert {name: (ROOT / ".github" / "workflows" / name).read_bytes() for name in WORKFLOWS} == before


def test_release_integrity_rejects_missing_artifact_fan_in(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    publish = root / ".github" / "workflows" / "publish.yml"
    publish.write_text(
        publish.read_text(encoding="utf-8").replace(
            "needs: [validate_python, validate_vscode, validate_intellij]",
            "needs: validate_python",
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["marker"] == "RELEASE_INTEGRITY_FAILURE"
    assert result["failed_check_ids"] == ["RELEASE_FAN_IN_EXACT"]
    assert result["next_action"]["action"] == "repair_release_workflow"


def test_release_integrity_rejects_late_openvsx_authorization(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "openvsx.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace("needs: authorize\n", ""),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["OPENVSX_AUTHORIZATION_EARLY"]


def test_release_integrity_rejects_intellij_compatibility_configuration_regression(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    settings = root / "editors" / "intellij" / "settings.gradle.kts"
    settings.write_text(settings.read_text(encoding="utf-8").replace('version "2.4.10"', 'version "2.1.20"'), encoding="utf-8")

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["INTELLIJ_COMPATIBILITY_DECLARED"]


def test_release_integrity_rejects_missing_repair_scope_confirmation(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    actions = root / "editors" / "intellij" / "src" / "main" / "kotlin" / "app" / "factoryline" / "intellij" / "FactoryLineActions.kt"
    actions.write_text(
        actions.read_text(encoding="utf-8").replace(
            'FactoryLineExecutionConfirmation.confirm(project, "Prepare Repair Scope")',
            "true",
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["INTELLIJ_COMPATIBILITY_DECLARED"]


def test_release_integrity_rejects_huggingface_metadata_that_would_fail_remotely(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    readme = root / "deploy" / "huggingface" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
                "short_description: Build a local MVP. Catch hollow tests before review.",
            f"short_description: {'x' * 61}",
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["HUGGINGFACE_METADATA_PREFLIGHT"]


def test_release_integrity_rejects_implicit_python_package_data(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    project = root / "pyproject.toml"
    project.write_text(project.read_text(encoding="utf-8").replace("include-package-data = false\n", ""), encoding="utf-8")

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["PYTHON_PACKAGE_DATA_EXPLICIT"]


def test_release_integrity_cli_is_machine_readable(capsys) -> None:
    assert main(["release", "integrity", "--root", str(ROOT), "--json"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["next_action"]["action"] == "review_external_publish_gates"


def test_release_integrity_text_render_keeps_authority_boundary() -> None:
    text = render_release_integrity(release_integrity(ROOT))

    assert "release integrity: ready for external-gate review" in text
    assert "PASS RELEASE_FAN_IN_EXACT" in text
    assert "authority: no execution, publication, credential, or approval authority" in text
