from __future__ import annotations

import io
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from scripts.jetbrains_release_artifact import ArtifactError, create_manifest, verify_manifest


COMMIT = "a" * 40


def test_intellij_workflow_deduplicates_identical_sha_triggers() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "intellij-plugin.yml").read_text(encoding="utf-8")
    assert "branches: [main]" in workflow
    assert "pull_request:" in workflow
    assert "group: intellij-plugin-${{ github.sha }}" in workflow
    assert "cancel-in-progress: true" in workflow


def _write_plugin_archive(
    path: Path, *, plugin_id: str = "app.factoryline", version: str = "0.7.1"
) -> None:
    plugin_jar = io.BytesIO()
    with ZipFile(plugin_jar, "w", ZIP_DEFLATED) as jar:
        jar.writestr(
            "META-INF/plugin.xml",
            f"""<idea-plugin>
                <id>{plugin_id}</id>
                <name>FactoryLine</name>
                <version>{version}</version>
            </idea-plugin>""",
        )
    with ZipFile(path, "w", ZIP_DEFLATED) as distribution:
        distribution.writestr("factoryline-intellij/lib/factoryline-intellij.jar", plugin_jar.getvalue())


def test_manifest_round_trip_binds_archive_and_release_inputs(tmp_path: Path) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    manifest_path = tmp_path / "manifest.json"
    _write_plugin_archive(archive)

    manifest = create_manifest(
        archive, release_ref="jetbrains-v0.7.1", commit=COMMIT, channel="default"
    )
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    assert verify_manifest(
        archive,
        manifest_path,
        release_ref="jetbrains-v0.7.1",
        commit=COMMIT,
        channel="default",
    ) == manifest
    assert manifest["plugin"] == {
        "id": "app.factoryline",
        "name": "FactoryLine",
        "version": "0.7.1",
    }


def test_manifest_rejects_tampered_archive(tmp_path: Path) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    manifest_path = tmp_path / "manifest.json"
    _write_plugin_archive(archive)
    manifest = create_manifest(
        archive, release_ref="jetbrains-v0.7.1", commit=COMMIT, channel="default"
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    archive.write_bytes(archive.read_bytes() + b"tampered")

    with pytest.raises(ArtifactError, match="does not match"):
        verify_manifest(
            archive,
            manifest_path,
            release_ref="jetbrains-v0.7.1",
            commit=COMMIT,
            channel="default",
        )


@pytest.mark.parametrize(
    ("release_ref", "commit", "channel"),
    [
        ("main", COMMIT, "default"),
        ("v0.22.0", COMMIT, "default"),
        ("jetbrains-v0.7.1", "short", "default"),
        ("jetbrains-v0.7.1", COMMIT, "bad channel"),
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
            release_ref="jetbrains-v0.7.1",
            commit=COMMIT,
            channel="default",
        )


def test_manifest_rejects_tag_plugin_version_mismatch(tmp_path: Path) -> None:
    archive = tmp_path / "factoryline-intellij.zip"
    _write_plugin_archive(archive, version="0.7.0")

    with pytest.raises(ArtifactError, match="does not match plugin version"):
        create_manifest(
            archive,
            release_ref="jetbrains-v0.7.1",
            commit=COMMIT,
            channel="default",
        )
