"""Publication proof for the current, product-only Code Factory visual set."""

from __future__ import annotations

import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
CURRENT_PRODUCT_CAPTURES = (
    ASSETS / "factoryline-logo-480.png",
    ASSETS / "marketplace" / "factory-studio-mvp-1280x800.png",
    ASSETS / "marketplace" / "graph-ops-proofsearch.png",
    ASSETS / "marketplace" / "graph-ops-proofsearch-controls.png",
    ASSETS / "marketplace" / "graph-ops-evidence-frontier.png",
)
PUBLIC_VISUAL_SURFACES = (
    ROOT / "README.md",
    ROOT / "LAUNCH_KIT.md",
    ROOT / "PUBLICATION_GUIDE.md",
    ROOT / "docs" / "PRODUCT_VISUALS.md",
    ROOT / "docs" / "PRODUCT_HUNT_GALLERY.md",
    ROOT / "deploy" / "huggingface" / "index.html",
)
RETIRED_PUBLIC_VISUALS = (
    "code-factory-quickstart-v0171.mp4",
    "code-factory-quickstart-cover-v0171.png",
    "factory-studio-control-room-1080.png",
    "factory-studio-control-room.png",
    "code-factory-design.png",
    "code-factory-proof-first.png",
    "how-it-works/",
    "HOW_IT_WORKS_VISUAL.md",
)


def _png_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    assert data[12:16] == b"IHDR"
    return struct.unpack(">II", data[16:24])


def test_current_product_visuals_are_real_capture_shapes() -> None:
    assert _png_dimensions(CURRENT_PRODUCT_CAPTURES[0]) == (480, 480)
    assert _png_dimensions(CURRENT_PRODUCT_CAPTURES[1]) == (1280, 800)
    assert _png_dimensions(CURRENT_PRODUCT_CAPTURES[2]) == (1280, 800)
    assert _png_dimensions(CURRENT_PRODUCT_CAPTURES[3]) == (1280, 800)
    assert _png_dimensions(CURRENT_PRODUCT_CAPTURES[4]) == (1280, 800)

    visuals = (ROOT / "docs" / "PRODUCT_VISUALS.md").read_text(encoding="utf-8")
    for asset in (
        "factoryline-logo-480.png",
        "factory-studio-mvp-1280x800.png",
        "graph-ops-proofsearch.png",
        "graph-ops-proofsearch-controls.png",
        "graph-ops-evidence-frontier.png",
    ):
        assert asset in visuals
    assert "incomplete proof state" in visuals
    assert "not a simulated green result" in visuals


def test_public_storefronts_use_current_product_media_and_exclude_retired_visuals() -> None:
    public_copy = "\n".join(path.read_text(encoding="utf-8") for path in PUBLIC_VISUAL_SURFACES)

    assert "docs/PRODUCT_VISUALS.md" in public_copy
    assert "factory-studio-mvp-1280x800.png" in public_copy
    assert "graph-ops-proofsearch.png" in public_copy
    assert "graph-ops-proofsearch-controls.png" in public_copy
    assert "graph-ops-evidence-frontier.png" in public_copy
    assert "factoryline-logo-480.png" in public_copy
    for retired in RETIRED_PUBLIC_VISUALS:
        assert retired not in public_copy
    for unsupported in ("2.6 hrs", "$14.37", "82%", "github.com/code-factory"):
        assert unsupported not in public_copy


def test_product_hunt_gallery_is_copy_ready_and_platform_accurate() -> None:
    guide = (ROOT / "docs" / "PRODUCT_HUNT_GALLERY.md").read_text(encoding="utf-8")
    names = (
        "factoryline-logo-480.png",
        "factory-studio-mvp-1280x800.png",
        "graph-ops-proofsearch.png",
        "graph-ops-proofsearch-controls.png",
        "graph-ops-evidence-frontier.png",
    )
    offsets = [guide.index(name) for name in names]

    assert offsets == sorted(offsets)
    assert "at least two images" in guide
    assert "1270 × 760" in guide
    assert "native aspect ratio" in guide
    assert "LISTING_NOT_FOUND" in guide


def test_zenodo_and_release_metadata_only_package_current_public_visuals() -> None:
    metadata = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert metadata["version"] == "0.46.1"
    assert metadata["publication_date"] == "2026-09-02"
    assert "Graph Ops mission-control storyboard" in metadata["description"]
    assert "designed to reduce avoidable App Review rework and waiting time" in metadata["description"]
    assert "does not guarantee approval" in metadata["description"]
    assert "conceptual visual walkthrough" not in metadata["description"]
    assert "product-captures" in metadata["keywords"]
    for asset in (
        "docs/assets/factoryline-logo-480.png",
        "docs/assets/marketplace/factory-studio-mvp-1280x800.png",
        "docs/assets/marketplace/graph-ops-studio-1280x800.png",
        "docs/assets/marketplace/graph-ops-proofsearch.png",
        "docs/assets/marketplace/graph-ops-proofsearch-controls.png",
        "docs/assets/marketplace/graph-ops-evidence-frontier.png",
    ):
        assert asset in workflow
    for retired in RETIRED_PUBLIC_VISUALS:
        assert retired not in workflow
