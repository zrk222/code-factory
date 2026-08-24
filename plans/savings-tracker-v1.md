# Plan: savings-tracker-v1
Spec: specs/savings-tracker-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Seal exact paired-measurement and outcome-equivalence semantics.
2. Add atomic private receipts and publication-safe aggregation.
3. Expose CLI, Studio, VS Code, and JetBrains surfaces.
4. Prove arithmetic, privacy, authority, and mutation behavior.
5. Synchronize and publish v0.22.0 release surfaces.

## Tasks (atomic - each independently shippable)

- [x] T1 | slice=factoryline | files=factoryline/savings.py,tests/test_savings.py | verify=`python -m pytest -q tests/test_savings.py` | Implement exact paired receipts, evidence hashing, signed deltas, unknown preservation, overwrite protection, and safe aggregation.
- [x] T2 | slice=factoryline | files=factoryline/cli.py,tests/test_factoryline.py | verify=`python -m pytest -q tests/test_factoryline.py tests/test_savings.py` | Add savings record, report, and export CLI commands.
- [x] T3 | slice=factoryline | files=factoryline/studio.py,tests/test_studio.py | verify=`python -m pytest -q tests/test_studio.py tests/test_savings.py` | Add contained Studio savings endpoints and tracker panel.
- [x] T4 | slice=editors/vscode | files=editors/vscode/package.json,editors/vscode/src/extension.ts,editors/vscode/src/meter.ts,editors/vscode/src/test/receipt.test.ts | verify=`npm --prefix editors/vscode test` | Add an explicit VS Code savings report command and render exact versus unknown fields.
- [x] T5 | slice=editors/intellij | files=editors/intellij/build.gradle.kts,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineCore.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt,editors/intellij/src/main/resources/META-INF/plugin.xml | verify=`editors/intellij/gradlew.bat test` | Add an explicit JetBrains savings report action and synchronize editor metadata.
- [x] T5a | slice=editors/intellij | files=editors/intellij/src/test/kotlin/app/factoryline/intellij/FactoryLineCoreTest.kt | verify=`editors/intellij/gradlew.bat test` | Prove the JetBrains adapter emits the exact read-only savings command.
- [x] T6 | slice=tests | files=tests/test_savings.py,tests/test_studio.py,tests/test_publication_metadata.py | verify=`python -m pytest -q` | Prove negative values, unknowns, privacy exclusions, authority boundaries, and release synchronization.
- [x] T7 | slice=docs | files=docs/SAVINGS_TRACKER.md,docs/RELEASE_NOTES_0.22.0.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document paired evidence semantics and the v0.22.0 release.
- [x] T8 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the paired savings tracker to the public quick start.
- [x] T9 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Record the v0.22.0 changes.
- [x] T10 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Synchronize the package version.
- [x] T11 | slice=factoryline | files=factoryline/__init__.py | verify=`python -m pytest -q tests/test_factoryline.py` | Synchronize the runtime version.
- [x] T12 | slice=CITATION.cff | files=CITATION.cff | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize citation metadata.
- [x] T13 | slice=.zenodo.json | files=.zenodo.json | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize archive metadata.
- [x] T14 | slice=deploy | files=deploy/huggingface/README.md,deploy/huggingface/index.html,deploy/hosted/README.md | verify=`python -m pytest -q tests/test_huggingface_surface.py` | Synchronize hosted v0.22.0 surfaces.
- [x] T15 | slice=tests | files=tests/test_huggingface_surface.py | verify=`python -m pytest -q tests/test_huggingface_surface.py` | Enforce hosted version synchronization.
- [x] T16 | slice=LAUNCH_KIT.md | files=LAUNCH_KIT.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize the launch kit.
- [x] T17 | slice=docs | files=docs/VSCODE.md,docs/INTELLIJ.md,docs/RELEASE_CHANNELS.md,docs/PRODUCT_HUNT_GALLERY.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize editor and distribution documentation.
- [x] T18 | slice=adr | files=adr/savings-tracker-v1.md | verify=`forge arch-gate savings-tracker-v1 specs/savings-tracker-v1.ssat.yaml --root .` | Record the savings authority boundary.
- [x] T19 | slice=specs | files=specs/savings-tracker-v1.ssat.yaml | verify=`forge arch-gate savings-tracker-v1 specs/savings-tracker-v1.ssat.yaml --root .` | Add the executable savings architecture contract.
- [x] T20 | slice=docs | files=docs/JETBRAINS_MARKETPLACE.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Prepare the authenticated Marketplace update without claiming unverified moderation.
