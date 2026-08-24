# Plan: visual-listing-v0172
Spec: specs/visual-listing-v0172.md (approved)
Architect verdict: PASS

## Logical decomposition

1. Identify the current visual identity and exact Factory Studio captures.
2. Remove retired recording, blank-dashboard, and concept-art media from public
   product surfaces and future release packaging.
3. Publish a compact visual policy and Product Hunt gallery handoff.
4. Validate dimensions, public references, metadata, and release-attachment
   safety.

## Tasks

- [x] T1 | slice=docs/assets | files=docs/assets/factoryline-logo-480.png,docs/assets/marketplace/factory-studio-mvp-1280x800.png,docs/assets/marketplace/graph-ops-studio-1280x800.png | verify=`python -m pytest -q tests/test_visual_listing.py` | Retain only current identity and actual product captures.
- [x] T2 | slice=docs | files=docs/PRODUCT_VISUALS.md,docs/PRODUCT_HUNT_GALLERY.md,README.md,deploy/huggingface/index.html | verify=`python -m pytest -q tests/test_visual_listing.py tests/test_huggingface_surface.py` | Make current captures the public product story.
- [x] T3 | slice=release | files=.github/workflows/publish.yml,MANIFEST.in,.zenodo.json | verify=`python -m pytest -q tests/test_publication_metadata.py` | Keep future release packaging aligned to current media.
- [x] T4 | slice=verification | files=tests/test_visual_listing.py,specs/visual-listing-v0172.ssat.yaml,smoke/visual-listing-v0172.json | verify=`specline strict visual-listing-v0172 --root .` | Make visual retirement and current capture shapes deterministic.
