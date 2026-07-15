from __future__ import annotations

import json
import re
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
    assert _match(ROOT / "CITATION.cff", r"^date-released: (\d{4}-\d{2}-\d{2})$") == "2026-07-15"


def test_zenodo_metadata_and_visual_evidence_are_publicly_archivable():
    metadata = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))

    assert metadata["upload_type"] == "software"
    assert metadata["access_right"] == "open"
    assert metadata["creators"] == [{"name": "Katz, Richard"}]
    assert metadata["related_identifiers"][0]["identifier"] == "https://github.com/zrk222/code-factory"
    assert "Mermaid diagrams" in metadata["description"]

    assets = ROOT / "docs" / "assets"
    for name in (
        "verify-policy.gif",
        "code-factory-proof-first.png",
        "factory-editor-control-room.svg",
        "prd-to-app-factory.svg",
    ):
        assert (assets / name).is_file(), name

    for path in (ROOT / "README.md", ROOT / "PUBLICATION_GUIDE.md", ROOT / "docs" / "JETBRAINS_CONTROL_ROOM.md"):
        assert "```mermaid" in path.read_text(encoding="utf-8"), path.name

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for entry in (
        "include .zenodo.json",
        "include CITATION.cff",
        "recursive-include docs *.md *.gif *.png *.svg",
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
