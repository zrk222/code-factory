# Plan: assembly-continue-v1
Spec: specs/assembly-continue-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Seal feature discovery, state classification, and continuation result.
2. Add atomic measurement receipts and privacy-safe aggregation.
3. Add concise CLI and token-protected Studio surfaces.
4. Add deterministic and adversarial tests.
5. Synchronize public documentation, editor surfaces, and v0.21.0 release data.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/continuation.py,factoryline/assembly.py | verify=`python -m pytest -q tests/test_continuation.py` | Implement feature discovery, state-aware continuation, typed terminal results, and exact SSAT discovery.
- [ ] T2 | slice=factoryline | files=factoryline/run_metrics.py | verify=`python -m pytest -q tests/test_continuation.py` | Write atomic run receipts, preserve unknown token and cost evidence, and export aggregate-safe metrics.
- [ ] T3 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_factoryline.py tests/test_continuation.py` | Add concise continue and metrics CLI commands with distinct waiting exit status.
- [ ] T4 | slice=factoryline | files=factoryline/studio.py | verify=`python -m pytest -q tests/test_studio.py` | Add Assembly Studio mode and protected continuation endpoint without new external authority.
- [ ] T5 | slice=tests | files=tests/test_continuation.py,tests/test_studio.py,tests/test_factoryline.py,tests/test_publication_metadata.py | verify=`python -m pytest -q` | Prove continuation, receipts, Studio containment, and release synchronization.
- [ ] T6 | slice=editors/vscode | files=editors/vscode/package.json,editors/vscode/package-lock.json,editors/vscode/src/extension.ts | verify=`npm --prefix editors/vscode test` | Expose continuation in VS Code and synchronize its release version.
- [ ] T7 | slice=editors/intellij | files=editors/intellij/build.gradle.kts,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineCore.kt,editors/intellij/src/main/resources/META-INF/plugin.xml | verify=`editors/intellij/gradlew.bat test` | Expose continuation in JetBrains IDEs and synchronize its release version.
- [ ] T8 | slice=docs | files=docs/ASSEMBLY_CONTINUE.md,docs/RELEASE_NOTES_0.21.0.md,docs/CODEX_USAGE_SAMPLE.md,docs/CODEX_USAGE_SAMPLE.json | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document state-aware continuation and publish the privacy-safe usage sample.
- [ ] T9 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add continuation to the public quick start.
- [ ] T10 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Record the 0.21.0 public changes.
- [ ] T11 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Update the package version.
- [ ] T12 | slice=factoryline | files=factoryline/__init__.py | verify=`python -m pytest -q tests/test_factoryline.py` | Update the runtime version.
- [ ] T13 | slice=CITATION.cff | files=CITATION.cff | verify=`python -m pytest -q tests/test_publication_metadata.py` | Update citation metadata.
- [ ] T14 | slice=.zenodo.json | files=.zenodo.json | verify=`python -m pytest -q tests/test_publication_metadata.py` | Update archive metadata.
- [ ] T15 | slice=deploy | files=deploy/huggingface/README.md,deploy/huggingface/index.html,deploy/hosted/README.md | verify=`python -m pytest -q tests/test_huggingface_surface.py` | Synchronize hosted release surfaces.
- [ ] T16 | slice=LAUNCH_KIT.md | files=LAUNCH_KIT.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize the launch kit.
- [ ] T17 | slice=docs | files=docs/CAPABILITY_PACKS.md,docs/FIRST_USE.md,docs/ENTERPRISE_1_0.md,docs/INTELLIJ.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize install and enterprise documentation.
- [ ] T18 | slice=docs | files=docs/VSCODE.md,docs/JETBRAINS_MARKETPLACE.md,docs/RELEASE_CHANNELS.md,docs/PRODUCT_HUNT_GALLERY.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize editor and release-channel documentation.
