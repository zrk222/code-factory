# Plan: jetbrains-marketplace-growth-v1
Spec: specs/jetbrains-marketplace-growth-v1.md (approved)
Architect verdict: PASS

## Logical decomposition (phases)
1. Replace jargon-first listing metadata with outcome-led, searchable copy.
2. Add a zero-configuration first proof while retaining command confirmation.
3. Add deterministic product/listing tests and a real-screenshot publication brief.
4. Package, verify, review, then use the protected publication workflow.

## Tasks (atomic - each independently shippable)
- [x] T1 | slice=editors/intellij/src/main | files=editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineCore.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineToolWindow.kt | verify=`editors/intellij/gradlew.bat test` | Add the first-proof command, action, and primary tool-window control.
- [x] T2 | slice=editors/intellij | files=editors/intellij/src/main/resources/META-INF/plugin.xml,editors/intellij/build.gradle.kts,editors/intellij/CHANGELOG.md | verify=`editors/intellij/gradlew.bat marketplacePreflight` | Rename the listing surface, replace Marketplace copy, and set the release version.
- [x] T3 | slice=editors/intellij/src/test | files=editors/intellij/src/test/kotlin/app/factoryline/intellij/FactoryLineCoreTest.kt | verify=`editors/intellij/gradlew.bat test` | Bind the exact first-proof command.
- [x] T4 | slice=docs | files=docs/JETBRAINS_MARKETPLACE.md,docs/JETBRAINS_MARKETPLACE_SCREENSHOTS.md,docs/JETBRAINS_PRICING_BENCHMARK.json,docs/INTELLIJ.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Publish the listing guide, real-screenshot brief, bounded pricing sample, and first-use guide.
- [x] T5 | slice=tests | files=tests/test_publication_metadata.py,tests/test_jetbrains_release_artifact.py | verify=`python -m pytest -q tests/test_publication_metadata.py tests/test_jetbrains_release_artifact.py` | Bind listing identity, copy, and release metadata.
- [x] T6 | slice=.github/workflows/jetbrains-marketplace.yml | files=.github/workflows/jetbrains-marketplace.yml | verify=`python -m pytest -q tests/test_jetbrains_release_artifact.py` | Keep protected workflow examples aligned with the immutable release tag.
- [x] T7 | slice=scripts | files=scripts/jetbrains_release_artifact.py | verify=`python -m pytest -q tests/test_jetbrains_release_artifact.py` | Keep release validation guidance aligned with the immutable release tag.
- [x] T8 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Announce the Marketplace identity and bounded free-period notice.
