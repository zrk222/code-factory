"""Publication proof for the owner-supplied Code Factory concept artwork."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSET_ROOT = ROOT / "docs" / "assets" / "how-it-works"
PUBLIC_VISUAL_SURFACES = (
    ROOT / "README.md",
    ROOT / "LAUNCH_KIT.md",
    ROOT / "PUBLICATION_GUIDE.md",
    ROOT / "docs" / "HOW_IT_WORKS_VISUAL.md",
    ROOT / "docs" / "PRODUCT_HUNT_GALLERY.md",
)


def _png_dimensions(data: bytes) -> tuple[int, int]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    assert data[12:16] == b"IHDR"
    return struct.unpack(">II", data[16:24])


def _manifest() -> dict:
    return json.loads((ASSET_ROOT / "manifest.json").read_text(encoding="utf-8"))


def test_visual_gallery_assets_are_exact_and_unique() -> None:
    manifest = _manifest()
    entries = manifest["illustrations"]

    assert manifest["schema"] == "code-factory.visual-story.v1"
    assert manifest["label"] == "Concept illustrations"
    assert manifest["evidence_boundary"] == "Not UI screenshots or measured outcome evidence."
    assert len(entries) == 9
    assert [entry["order"] for entry in entries] == list(range(1, 10))
    assert [entry["stage"] for entry in entries] == [
        "idea intake",
        "product shaping",
        "deterministic compilation",
        "security contracts",
        "governed access",
        "proof by sabotage",
        "failure feedback",
        "signed proof chain",
        "verified release",
    ]

    digests = set()
    for entry in entries:
        path = ASSET_ROOT / entry["filename"]
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        assert digest == entry["sha256"]
        assert _png_dimensions(data) == (1122, 1402)
        assert entry["width"] == 1122
        assert entry["height"] == 1402
        assert entry["alt"].strip()
        digests.add(digest)

    assert len(digests) == 9
    assert not (ASSET_ROOT / "code-factory-in-action.png").exists()


def test_public_storefronts_label_concept_art_and_exclude_unsupported_claims() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.count("Concept illustrations") == 1
    assert readme.count("Exact shipped UI") == 1
    assert readme.count("https://raw.githubusercontent.com/zrk222/code-factory/main/docs/assets/how-it-works/") == 3
    assert "https://github.com/zrk222/code-factory/blob/main/docs/HOW_IT_WORKS_VISUAL.md" in readme

    public_copy = "\n".join(path.read_text(encoding="utf-8") for path in PUBLIC_VISUAL_SURFACES)
    for unsupported in ("2.6 hrs", "$14.37", "82%", "github.com/code-factory"):
        assert unsupported not in public_copy
    assert "concept illustrations" in public_copy.lower()
    assert "exact shipped ui" in public_copy.lower()


def test_product_hunt_gallery_is_copy_ready_and_platform_accurate() -> None:
    guide = (ROOT / "docs" / "PRODUCT_HUNT_GALLERY.md").read_text(encoding="utf-8")
    names = [entry["filename"] for entry in _manifest()["illustrations"]]
    offsets = [guide.index(name) for name in names]

    assert offsets == sorted(offsets)
    assert "at least 2 images" in guide
    assert "1270 x 760" in guide
    assert "full YouTube URL" in guide
    assert "Source images are 1122 x 1402 portrait PNGs" in guide
    assert "LISTING_NOT_FOUND" in guide


def test_zenodo_and_release_metadata_include_the_visual_walkthrough() -> None:
    metadata = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert metadata["version"] == "0.17.2"
    assert metadata["publication_date"] == "2026-07-18"
    assert "conceptual visual walkthrough" in metadata["description"]
    assert "not UI screenshots or measured outcome evidence" in metadata["description"]
    assert "docs/assets/how-it-works/*.png" in workflow
