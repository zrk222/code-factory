# Plan: vscode-supply-chain-v1
Spec: specs/vscode-supply-chain-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Bind and verify patched transitive dependencies.
2. Enforce the audit in PR and release workflows.
3. Synchronize and publish the 0.23.1 security patch.

## Tasks (atomic - each independently shippable)

- [x] T1 | slice=editors/vscode | files=editors/vscode/package.json,editors/vscode/package-lock.json | verify=`npm audit --json` | Pin safe transitive resolutions and regenerate the lockfile.
- [x] T2 | slice=.github/workflows | files=.github/workflows/vscode-extension.yml,.github/workflows/publish.yml | verify=`npm run audit` | Add the audit gate to VS Code CI and release packaging.
- [x] T3 | slice=tests | files=tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add deterministic lockfile and workflow assertions.
- [x] T4 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Synchronize package version 0.23.1.
- [x] T5 | slice=factoryline | files=factoryline/__init__.py | verify=`python -m pytest -q tests/test_factoryline.py` | Synchronize runtime version 0.23.1.
- [x] T6 | slice=CITATION.cff | files=CITATION.cff | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize citation version and date.
- [x] T7 | slice=.zenodo.json | files=.zenodo.json | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize archive version and date.
- [x] T8 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize the primary install surface.
- [x] T9 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Record the 0.23.1 security patch.
- [x] T10 | slice=docs | files=docs/RELEASE_NOTES_0.23.1.md,docs/RELEASE_CHANNELS.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Publish the bounded security notes and channels.
- [x] T11 | slice=deploy | files=deploy/huggingface/index.html,deploy/huggingface/README.md | verify=`python -m pytest -q tests/test_huggingface_surface.py tests/test_visual_listing.py` | Synchronize hosted public surfaces.
- [x] T12 | slice=PUBLICATION_GUIDE.md | files=PUBLICATION_GUIDE.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize publication guidance.
- [x] T13 | slice=LAUNCH_KIT.md | files=LAUNCH_KIT.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize the launch surface.
