from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.release_integrity import (
    release_integrity,
    render_release_integrity,
    review_regression_audit,
)
from factoryline.release_route_integrity import release_route_checks


ROOT = Path(__file__).parents[1]


def test_review_regression_audit_catches_devin_failure_classes(tmp_path: Path) -> None:
    for args in (
        ["init", "-q"],
        ["config", "user.name", "Audit Test"],
        ["config", "user.email", "audit@example.invalid"],
    ):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    evidence = tmp_path / "evidence" / "self-audit" / "quality-2026-09-25.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"grade":"F"}\n', encoding="utf-8")
    channels = tmp_path / "docs" / "RELEASE_CHANNELS.md"
    channels.parent.mkdir()
    channels.write_text(
        "The owner selected a specialty AI reviewer.\n", encoding="utf-8"
    )
    contributing = tmp_path / "CONTRIBUTING.md"
    contributing.write_text("A specialty AI agent reviews source.\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-qm", "baseline"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    assert review_regression_audit(tmp_path, "HEAD")["state"] == "CLEAN"
    evidence.write_text('{"grade":"A"}\n', encoding="utf-8")
    history = review_regression_audit(tmp_path, "HEAD")
    assert history["state"] == "BLOCKED"
    assert history["findings"][0]["code"] == "HISTORICAL_EVIDENCE_MUTATED"
    evidence.write_text('{"grade":"F"}\n', encoding="utf-8")
    contributing.write_text(
        "Every public release requires approval by a human other than the initiator.\n",
        encoding="utf-8",
    )
    channels.write_text(
        "PyPI and Hugging Face no longer require a second human.\n", encoding="utf-8"
    )
    conflict = review_regression_audit(tmp_path, "HEAD")
    assert conflict["state"] == "BLOCKED"
    assert conflict["findings"][0]["code"] == "RELEASE_REVIEW_POLICY_CONFLICT"
    assert review_regression_audit(tmp_path, "missing-ref")["state"] == "INCOMPLETE"
    assert (
        review_regression_audit(tmp_path, "--output=unexpected")["state"]
        == "INCOMPLETE"
    )


WORKFLOWS = (
    "publish.yml",
    "openvsx.yml",
    "vscode-marketplace.yml",
    "jetbrains-marketplace.yml",
    "intellij-plugin.yml",
    "huggingface-space.yml",
)
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
    before = {
        name: (ROOT / ".github" / "workflows" / name).read_bytes() for name in WORKFLOWS
    }

    result = release_integrity(ROOT)

    assert result["schema"] == "factory.release_integrity.v1"
    assert result["marker"] == "RELEASE_INTEGRITY_READ_ONLY"
    assert result["ok"] is True
    assert [item["id"] for item in result["checks"]] == [
        "RELEASE_FAN_IN_EXACT",
        "RELEASE_CANDIDATE_PREFLIGHT_REQUIRED",
        "RELEASE_VALIDATION_PARTITIONED",
        "OPENVSX_AUTHORIZATION_EARLY",
        "VSCODE_MARKETPLACE_AUTHORIZATION_EARLY",
        "VSCODE_MARKETPLACE_CANDIDATE_SEALED",
        "JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY",
        "JETBRAINS_JDK21_EXACT",
        "HUGGINGFACE_AUTHORIZATION_EARLY",
        "PYPI_TRUSTED_PUBLISHING",
        "JETBRAINS_APPROVAL_GUARD",
        "INTELLIJ_COMPATIBILITY_DECLARED",
        "HUGGINGFACE_METADATA_PREFLIGHT",
        "PYTHON_PACKAGE_DATA_EXPLICIT",
    ]
    assert all(item["passed"] for item in result["checks"])
    assert not any(result["authority"].values())
    assert (
        "JetBrains publication still requires JETBRAINS_MARKETPLACE_TOKEN in the protected jetbrains-marketplace environment."
        in result["external_requirements"]
    )
    assert (
        "Hugging Face Space publication still requires the configured HF_TOKEN GitHub Actions secret."
        in result["external_requirements"]
    )
    assert {
        name: (ROOT / ".github" / "workflows" / name).read_bytes() for name in WORKFLOWS
    } == before


def test_release_route_checks_expose_the_huggingface_admission_boundary() -> None:
    checks = {item["id"]: item for item in release_route_checks(ROOT)}

    assert checks["HUGGINGFACE_AUTHORIZATION_EARLY"] == {
        "id": "HUGGINGFACE_AUTHORIZATION_EARLY",
        "passed": True,
        "evidence": "Hugging Face credential admission is declared before Space candidate work",
    }


def test_release_integrity_rejects_missing_artifact_fan_in(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    publish = root / ".github" / "workflows" / "publish.yml"
    publish.write_text(
        publish.read_text(encoding="utf-8").replace(
            "needs: [guard, validate_python, validate_vscode, validate_intellij]",
            "needs: validate_python",
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["marker"] == "RELEASE_INTEGRITY_FAILURE"
    assert result["failed_check_ids"] == ["RELEASE_FAN_IN_EXACT"]
    assert result["next_action"]["action"] == "repair_release_workflow"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('[[ "$is_draft" == "true" ]]', '[[ "$is_draft" == "false" ]]'),
        (
            '[[ "$GITHUB_REF" == "refs/heads/main" ]]',
            '[[ "$GITHUB_REF" == "refs/heads/feature" ]]',
        ),
        ("--draft=false", "--draft=true"),
        ('== "$EXPECTED_COMMIT"', '!= "$EXPECTED_COMMIT"'),
        ("workflow_dispatch:", "release:\n    types: [published]"),
        (
            "ref: ${{ needs.guard.outputs.candidate_commit }}",
            "ref: ${{ github.event.release.tag_name }}",
        ),
        ('git merge-base --is-ancestor "$candidate_commit" origin/main', "true"),
        ('item["published_at"]', 'item["created_at"]'),
        ("group: publish-release-train", "group: publish-${{ inputs.release_tag }}"),
        ('git fetch --no-tags origin "refs/tags/${RELEASE_TAG}"', "true"),
        (
            "needs: [guard, validate_python, validate_vscode, validate_intellij]",
            "needs: [validate_python, validate_vscode, validate_intellij]",
        ),
    ],
)
def test_release_integrity_rejects_unsafe_or_unbound_publish_topology(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _workflow_copy(tmp_path)
    publish = root / ".github" / "workflows" / "publish.yml"
    original = publish.read_text(encoding="utf-8")
    assert old in original
    publish.write_text(original.replace(old, new, 1), encoding="utf-8")

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["RELEASE_FAN_IN_EXACT"]


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


def test_release_integrity_rejects_vscode_candidate_validation_without_authorization(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "vscode-marketplace.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "needs: authorize\n", "needs: []\n", 1
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["VSCODE_MARKETPLACE_AUTHORIZATION_EARLY"]
    assert result["next_action"]["action"] == "repair_release_workflow"


def test_release_integrity_rejects_publication_without_candidate_preflight(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    publish = root / ".github" / "workflows" / "publish.yml"
    content = publish.read_text(encoding="utf-8")
    start = content.index("      - name: Require sealed release candidate preflight")
    end = content.index("      - name: Attach distributions to GitHub release", start)
    publish.write_text(content[:start] + content[end:], encoding="utf-8")

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["RELEASE_CANDIDATE_PREFLIGHT_REQUIRED"]


def test_release_integrity_rejects_unsealed_vscode_candidate_identity(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "vscode-marketplace.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "grep -Fx 'publisher=zrk222' manifest.txt", "true"
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["VSCODE_MARKETPLACE_CANDIDATE_SEALED"]


def test_release_integrity_rejects_java17_in_any_intellij_gradle_workflow(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "intellij-plugin.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            'java-version: "21"', 'java-version: "17"', 1
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["JETBRAINS_JDK21_EXACT"]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("environment: jetbrains-marketplace", "environment: missing"),
        ('test -n "$PUBLISH_TOKEN"', "false"),
        ("needs: authorize\n", "needs: []\n"),
        (
            "needs: [authorize, validate, compatibility]",
            "needs: [validate, compatibility]",
        ),
    ],
)
def test_release_integrity_rejects_jetbrains_authorization_route_bypass(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "jetbrains-marketplace.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY"]
    assert result["next_action"]["action"] == "repair_release_workflow"


def test_release_integrity_rejects_intellij_compatibility_configuration_regression(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    settings = root / "editors" / "intellij" / "settings.gradle.kts"
    settings.write_text(
        settings.read_text(encoding="utf-8").replace(
            'version "2.4.10"', 'version "2.1.20"'
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["INTELLIJ_COMPATIBILITY_DECLARED"]


def test_release_integrity_rejects_missing_repair_scope_confirmation(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    actions = (
        root
        / "editors"
        / "intellij"
        / "src"
        / "main"
        / "kotlin"
        / "app"
        / "factoryline"
        / "intellij"
        / "FactoryLineActions.kt"
    )
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


def test_release_integrity_rejects_huggingface_metadata_that_would_fail_remotely(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    readme = root / "deploy" / "huggingface" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            "short_description: Audit code, review evidence, and resolve defects.",
            f"short_description: {'x' * 61}",
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["HUGGINGFACE_METADATA_PREFLIGHT"]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('test -n "$HF_TOKEN"', "false"),
        ("HF_TOKEN: ${{ secrets.HF_TOKEN }}", "HF_TOKEN: missing"),
    ],
)
def test_release_integrity_rejects_missing_huggingface_authorization(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "huggingface-space.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["HUGGINGFACE_AUTHORIZATION_EARLY"]
    assert result["next_action"]["action"] == "repair_release_workflow"


def test_release_integrity_rejects_late_huggingface_authorization(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "huggingface-space.yml"
    content = workflow.read_text(encoding="utf-8")
    authorizer = """      - name: Require Hugging Face token before candidate work
        shell: bash
        env:
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
        run: |
          set -euo pipefail
          test -n \"$HF_TOKEN\" || {
            echo \"HF_TOKEN is required before Hugging Face Space candidate work.\" >&2
            exit 1
          }
"""
    assert authorizer in content
    workflow.write_text(
        content.replace(authorizer, "").replace(
            "      - uses: actions/checkout@v4\n",
            "      - uses: actions/checkout@v4\n" + authorizer,
            1,
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["HUGGINGFACE_AUTHORIZATION_EARLY"]


def test_release_integrity_rejects_implicit_python_package_data(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    project = root / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace(
            "include-package-data = false\n", ""
        ),
        encoding="utf-8",
    )

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
    assert (
        "authority: no execution, publication, credential, or approval authority"
        in text
    )


@pytest.mark.parametrize(
    "ages,draft,admitted",
    [
        ([9], False, True),
        ([1], False, False),
        ([9, 10, 11, 12], False, False),
        ([0], True, True),
    ],
)
def test_publication_guard_uses_published_timestamps(tmp_path, ages, draft, admitted):
    import os
    import subprocess
    import sys
    from datetime import datetime, timedelta, timezone
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    step = next(
        item
        for item in workflow["jobs"]["guard"]["steps"]
        if item.get("name")
        == "Enforce cadence using actual GitHub publication timestamps"
    )
    script = step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    now = datetime.now(timezone.utc)
    (tmp_path / "release-train.json").write_text(
        json.dumps(
            {
                "cadence": {
                    "effective_at": (now - timedelta(days=60)).isoformat(),
                    "max_releases_30d": 4,
                    "minimum_days_between_releases": 7,
                }
            }
        )
    )
    history = [
        {
            "draft": draft,
            "created_at": "2000-01-01T00:00:00Z",
            "published_at": None if draft else (now - timedelta(days=age)).isoformat(),
        }
        for age in ages
    ]
    (tmp_path / "release-history.json").write_text(json.dumps([history]))
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**os.environ, "RUNNER_TEMP": str(tmp_path)},
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is admitted, result.stderr
