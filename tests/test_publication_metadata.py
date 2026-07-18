from __future__ import annotations

import json
import re
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by the Python 3.10 CI lane
    import tomli as tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _match(path: Path, pattern: str) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, f"missing expected metadata in {path.name}"
    return match.group(1)


def test_publication_versions_and_citation_are_synchronized():
    pyproject_version = _match(ROOT / "pyproject.toml", r'^version = "([^"]+)"$')
    package_version = _match(ROOT / "factoryline" / "__init__.py", r'^__version__ = "([^"]+)"$')
    citation_version = _match(ROOT / "CITATION.cff", r"^version: ([^\s]+)$")

    assert pyproject_version == package_version == citation_version
    assert _match(ROOT / "CITATION.cff", r"^date-released: (\d{4}-\d{2}-\d{2})$") == "2026-07-18"


def test_pypi_storefront_has_identity_and_canonical_links():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    identity = [{"name": "Richard Katz"}, {"email": "rkatz22@gmail.com"}]
    assert project["authors"] == identity
    assert project["maintainers"] == identity
    assert project["urls"] == {
        "Homepage": "https://github.com/zrk222/code-factory",
        "Documentation": "https://github.com/zrk222/code-factory#readme",
        "Source": "https://github.com/zrk222/code-factory",
        "Issues": "https://github.com/zrk222/code-factory/issues",
        "Changelog": "https://github.com/zrk222/code-factory/releases",
    }


def test_publish_workflow_uses_trusted_publishing_without_stored_credentials():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "  validate:" in workflow
    assert "  publish:" in workflow
    assert "needs: validate" in workflow
    assert "environment: pypi" in workflow
    assert "id-token: write" in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "actions/download-artifact@v4" in workflow
    assert "packages-dir: release-bundle/python/" in workflow
    assert "pypa/gh-action-pypi-publish@release/v1" in workflow
    assert "attestations: true" in workflow
    assert "gradle/actions/setup-gradle@v6.2.0" in workflow
    for forbidden in (
        "PYPI_TOKEN",
        "API_TOKEN",
        "user: __token__",
        "password:",
    ):
        assert forbidden not in workflow


def test_marketplace_workflow_uses_current_gradle_action_and_scoped_secret():
    workflow = (ROOT / ".github" / "workflows" / "jetbrains-marketplace.yml").read_text(encoding="utf-8")

    assert 'default: "v0.17.3"' in workflow
    assert "environment: jetbrains-marketplace" in workflow
    assert "gradle/actions/setup-gradle@v6.2.0" in workflow
    assert "gradle/actions/setup-gradle@v4" not in workflow
    assert "secrets.JETBRAINS_MARKETPLACE_TOKEN" in workflow
    assert "Test, verify, and check Marketplace package metadata" in workflow
    assert "Publish verified plugin update" in workflow


def test_ci_builds_checks_and_smokes_the_installable_package():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "package-contract:" in workflow
    assert "python -m build" in workflow
    assert "python -m twine check dist/*" in workflow
    assert "python -m pip install dist/*.whl" in workflow
    assert "actions/upload-artifact@v4" in workflow


def test_zenodo_metadata_and_visual_evidence_are_publicly_archivable():
    metadata = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))

    assert metadata["upload_type"] == "software"
    assert metadata["access_right"] == "open"
    assert metadata["creators"] == [{"name": "Katz, Richard"}]
    assert metadata["related_identifiers"][0]["identifier"] == "https://github.com/zrk222/code-factory"
    assert "Mermaid diagrams" in metadata["description"]
    assert metadata["version"] == "0.17.3"
    assert metadata["publication_date"] == "2026-07-18"
    assert "conceptual visual walkthrough" in metadata["description"]

    assets = ROOT / "docs" / "assets"
    for name in (
        "verify-policy.gif",
        "code-factory-proof-first.png",
        "factory-editor-control-room.svg",
        "prd-to-app-factory.svg",
        "product-missions.svg",
        "signal-loop.svg",
        "code-factory-quickstart-cover-v0171.png",
        "code-factory-quickstart-v0171.mp4",
    ):
        assert (assets / name).is_file(), name

    visual_assets = assets / "how-it-works"
    assert len(list(visual_assets.glob("*.png"))) == 9
    assert (visual_assets / "manifest.json").is_file()
    assert (ROOT / "docs" / "HOW_IT_WORKS_VISUAL.md").is_file()

    source_manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include docs *.md *.gif *.png *.svg *.mp4 *.json" in source_manifest

    for path in (
        ROOT / "README.md",
        ROOT / "PUBLICATION_GUIDE.md",
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "JETBRAINS_CONTROL_ROOM.md",
    ):
        assert "```mermaid" in path.read_text(encoding="utf-8"), path.name

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for entry in (
        "include .zenodo.json",
        "include CITATION.cff",
        "recursive-include docs *.md *.gif *.png *.svg",
        "*.mp4",
    ):
        assert entry in manifest

    for generated_tree in (
        "editors/vscode/node_modules",
        "editors/vscode/dist",
        "editors/intellij/.gradle",
        "editors/intellij/.intellijPlatform",
        "editors/intellij/.kotlin",
        "editors/intellij/build",
    ):
        assert f"prune {generated_tree}" in manifest
