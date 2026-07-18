# Plan: visual-listing-v0172
Spec: specs/visual-listing-v0172.md (approved)
Architect verdict: PASS

## Logical decomposition (phases)

1. Bind the approved artwork and truthfulness rules in a strict spec and SSAT.
2. Add the nine immutable visual assets in three bounded batches.
3. Publish one ordered gallery manifest and platform-specific public copy.
4. Synchronize version and release metadata for GitHub, PyPI, and Zenodo.
5. Prove rendering metadata, package contents, topology, and release safety.

## Tasks (atomic - each independently shippable)

- [x] T1 | slice=specs | files=specs/visual-listing-v0172.md,specs/visual-listing-v0172.ssat.yaml | verify=`specline strict visual-listing-v0172 --root .` | Gate the visual-release contract and architecture boundary
- [x] T2 | slice=plans | files=plans/visual-listing-v0172.md | verify=`specline tasks visual-listing-v0172 --root .` | Seal atomic implementation packets
- [x] T3 | slice=docs/assets/how-it-works | files=docs/assets/how-it-works/01-idea-to-blueprint.png,docs/assets/how-it-works/02-prd-to-product-shape.png,docs/assets/how-it-works/03-ai-compiler-stack.png | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the first three owner-supplied concept illustrations byte-for-byte
- [x] T4 | slice=docs/assets/how-it-works | files=docs/assets/how-it-works/04-security-contracts.png,docs/assets/how-it-works/05-governed-access.png,docs/assets/how-it-works/06-proof-by-sabotage.png | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the middle three owner-supplied concept illustrations byte-for-byte
- [x] T5 | slice=docs/assets/how-it-works | files=docs/assets/how-it-works/07-failure-feedback.png,docs/assets/how-it-works/08-signed-proof-chain.png,docs/assets/how-it-works/09-verified-release.png | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the final three owner-supplied concept illustrations byte-for-byte
- [x] T6 | slice=docs | files=docs/assets/how-it-works/manifest.json,docs/HOW_IT_WORKS_VISUAL.md,tests/test_visual_listing.py | verify=`python -m pytest -q tests/test_visual_listing.py` | Publish the ordered gallery with deterministic asset checks
- [x] T7 | slice=README.md | files=README.md,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the three-panel GitHub and PyPI storefront preview
- [x] T8 | slice=LAUNCH_KIT.md | files=LAUNCH_KIT.md,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Separate the exact UI demo from Product Hunt concept illustrations
- [x] T9 | slice=docs | files=docs/PRODUCT_HUNT_GALLERY.md,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Record official Product Hunt gallery constraints
- [x] T10 | slice=.zenodo.json | files=.zenodo.json,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Bind the conceptual walkthrough to Zenodo version 0.17.2 metadata
- [x] T11 | slice=pyproject.toml | files=pyproject.toml,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Bump package metadata to version 0.17.2
- [x] T12 | slice=factoryline | files=factoryline/__init__.py,tests/test_factoryline.py | verify=`python -m pytest -q tests/test_factoryline.py` | Synchronize runtime version 0.17.2
- [x] T13 | slice=CITATION.cff | files=CITATION.cff,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize citation version and release date
- [x] T14 | slice=CHANGELOG.md | files=CHANGELOG.md,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Record the visual-listing release without unsupported outcome claims
- [x] T15 | slice=.github | files=.github/workflows/publish.yml,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Attach the nine-image gallery to releases and enforce publication metadata
- [x] T16 | slice=PUBLICATION_GUIDE.md | files=PUBLICATION_GUIDE.md,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the public visual-release checklist and platform boundaries
- [x] T17 | slice=MANIFEST.in | files=MANIFEST.in,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Package the SHA-256 visual manifest in the source distribution
- [x] T18 | slice=smoke | files=smoke/visual-listing-v0172.json | verify=`forge verify-tests visual-listing-v0172 specs/visual-listing-v0172.ssat.yaml --root .` | Bind the release story to a non-hollow Forge smoke receipt
- [x] T19 | slice=docs | files=docs/CAPABILITY_PACKS.md,docs/FIRST_USE.md,docs/INTELLIJ.md,docs/VSCODE.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize public documentation install pins on version 0.17.2
