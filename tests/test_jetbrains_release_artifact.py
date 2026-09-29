from __future__ import annotations

import io
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from scripts.jetbrains_marketplace_measurement import (
    BASELINE_SCHEMA,
    MEASUREMENT_SCHEMA,
    BaselineError,
    build_measurement,
    load_baseline,
)
from scripts.jetbrains_release_artifact import (
    ArtifactError,
    create_manifest,
    verify_manifest,
)


COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parent.parent


def test_intellij_workflow_cancels_superseded_commits_on_same_ref() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "intellij-plugin.yml"
    ).read_text(encoding="utf-8")
    assert "branches: [main]" in workflow
    assert "pull_request:" in workflow
    assert "group: intellij-plugin-${{ github.ref }}" in workflow
    assert (
        "group: intellij-plugin-${{ github.event.pull_request.head.sha" not in workflow
    )
    assert "cancel-in-progress: true" in workflow


def _write_plugin_archive(
    path: Path, *, plugin_id: str = "app.factoryline", version: str = "0.7.2"
) -> None:
    plugin_jar = io.BytesIO()
    with ZipFile(plugin_jar, "w", ZIP_DEFLATED) as jar:
        jar.writestr(
            "META-INF/plugin.xml",
            f"""<idea-plugin>
                <id>{plugin_id}</id>
                <name>FactoryLine AI Proof</name>
                <version>{version}</version>
            </idea-plugin>""",
        )
    with ZipFile(path, "w", ZIP_DEFLATED) as distribution:
        distribution.writestr(
            "factoryline-intellij/lib/factoryline-intellij.jar", plugin_jar.getvalue()
        )


def test_manifest_round_trip_binds_archive_and_release_inputs(tmp_path: Path) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    manifest_path = tmp_path / "manifest.json"
    _write_plugin_archive(archive)

    manifest = create_manifest(
        archive, release_ref="jetbrains-v0.7.2", commit=COMMIT, channel="default"
    )
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    assert (
        verify_manifest(
            archive,
            manifest_path,
            release_ref="jetbrains-v0.7.2",
            commit=COMMIT,
            channel="default",
        )
        == manifest
    )
    assert manifest["plugin"] == {
        "id": "app.factoryline",
        "name": "FactoryLine AI Proof",
        "version": "0.7.2",
    }


def test_manifest_accepts_immutable_ci_retry_build_metadata(tmp_path: Path) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    _write_plugin_archive(archive, version="0.8.16")

    manifest = create_manifest(
        archive,
        release_ref="jetbrains-v0.8.16+ci.2",
        commit=COMMIT,
        channel="default",
    )

    assert manifest["plugin"]["version"] == "0.8.16"
    assert manifest["release"]["ref"] == "jetbrains-v0.8.16+ci.2"


def test_manifest_rejects_tampered_archive(tmp_path: Path) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    manifest_path = tmp_path / "manifest.json"
    _write_plugin_archive(archive)
    manifest = create_manifest(
        archive, release_ref="jetbrains-v0.7.2", commit=COMMIT, channel="default"
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    archive.write_bytes(archive.read_bytes() + b"tampered")

    with pytest.raises(ArtifactError, match="does not match"):
        verify_manifest(
            archive,
            manifest_path,
            release_ref="jetbrains-v0.7.2",
            commit=COMMIT,
            channel="default",
        )


@pytest.mark.parametrize(
    ("release_ref", "commit", "channel"),
    [
        ("main", COMMIT, "default"),
        ("v0.22.0", COMMIT, "default"),
        ("jetbrains-v0.7.2", "short", "default"),
        ("jetbrains-v0.7.2", COMMIT, "bad channel"),
    ],
)
def test_manifest_rejects_mutable_or_malformed_inputs(
    tmp_path: Path, release_ref: str, commit: str, channel: str
) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    _write_plugin_archive(archive)

    with pytest.raises(ArtifactError):
        create_manifest(
            archive, release_ref=release_ref, commit=commit, channel=channel
        )


def test_manifest_rejects_wrong_plugin_identity(tmp_path: Path) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    _write_plugin_archive(archive, plugin_id="example.untrusted")

    with pytest.raises(ArtifactError, match="Expected plugin id"):
        create_manifest(
            archive,
            release_ref="jetbrains-v0.7.2",
            commit=COMMIT,
            channel="default",
        )


def test_manifest_rejects_tag_plugin_version_mismatch(tmp_path: Path) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    _write_plugin_archive(archive, version="0.7.0")

    with pytest.raises(ArtifactError, match="does not match plugin version"):
        create_manifest(
            archive,
            release_ref="jetbrains-v0.7.2",
            commit=COMMIT,
            channel="default",
        )


# Keep IntelliJ workflow and Marketplace contract checks beside the release artifact.


def test_intellij_required_checks_are_emitted_for_every_pull_request() -> None:
    workflow = (ROOT / ".github" / "workflows" / "intellij-plugin.yml").read_text(
        encoding="utf-8"
    )

    assert "  pull_request:\n  workflow_dispatch:" in workflow
    assert "  changes:" in workflow
    assert "    needs: changes\n    runs-on: ubuntu-latest" in workflow
    assert "  test-package:\n    needs: [changes, test-package-verify]" in workflow
    assert "  compatibility:\n    needs: [changes, test-package-verify]" in workflow
    assert "Mark package verification not applicable" in workflow
    assert "Mark compatibility not applicable" in workflow
    assert (
        "defaults:\n      run:\n        working-directory: editors/intellij"
        not in workflow
    )
    assert workflow.count("working-directory: editors/intellij") == 4


def test_intellij_heavy_validation_is_scoped_without_suppressing_required_statuses() -> (
    None
):
    workflow = (ROOT / ".github" / "workflows" / "intellij-plugin.yml").read_text(
        encoding="utf-8"
    )

    assert "^(editors/intellij/|\\.github/workflows/intellij-plugin\\.yml$)" in workflow
    assert workflow.count("if: needs.changes.outputs.intellij == 'true'") >= 10
    assert "needs.changes.outputs.intellij != 'true'" in workflow
    assert "paths:" not in workflow.split("jobs:", maxsplit=1)[0]


def test_marketplace_measurement_reports_only_observed_download_movement() -> None:
    baseline = {
        "schema": BASELINE_SCHEMA,
        "recorded_at": "2026-08-04T05:00:00Z",
        "plugin_id": 33009,
        "downloads": 46,
        "listed_version": "0.7.1",
    }
    plugin = {
        "downloads": 53,
        "version": "0.8.4",
        "pricingModel": "FREE",
        "approve": False,
        "hasUnapprovedUpdate": True,
    }

    result = build_measurement(baseline, plugin)

    assert result["schema"] == MEASUREMENT_SCHEMA
    assert result["download_delta"] == 7
    assert result["download_delta_state"] == "observed"
    assert result["conversion_rate"] is None
    assert result["causal_uplift"] is None
    assert (
        result["conversion_rate_state"]
        == "unavailable_without_marketplace_impressions_or_page_views"
    )
    assert (
        result["causal_uplift_state"]
        == "unavailable_without_a_controlled_experiment_or_attribution_data"
    )


def test_marketplace_measurement_requires_a_well_formed_baseline(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "baseline.json"
    invalid.write_text(
        json.dumps({"schema": BASELINE_SCHEMA, "plugin_id": 33009, "downloads": -1})
    )

    with pytest.raises(BaselineError, match="BASELINE_DOWNLOADS_INVALID"):
        load_baseline(invalid)
