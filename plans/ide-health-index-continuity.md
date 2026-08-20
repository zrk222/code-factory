# Plan: IDE Health and Index Continuity

Spec: `specs/ide-health-index-continuity.md`
Architect verdict: PASS — local-only evidence, explicit writes, no automatic remediation.

1. Build a deterministic Python continuity baseline/compare contract and command.
2. Test baseline creation, stable comparison, structural drift, invalid baselines,
   output containment, and the end-to-end CLI path.
3. Add a JetBrains health recorder with bounded in-memory runtime samples.
4. Add a JetBrains continuity tab and confirmed CLI controls.
5. Update docs, package metadata, and release notes.
6. Run Python, Kotlin, package, ForgeLine, and SpecLine gates before release.

## Atomic tasks

- [x] T1 | slice=specs | files=specs/ide-health-index-continuity.md | verify=`specline validate ide-health-index-continuity` | Define authority, outputs, and failure modes.
- [x] T2 | slice=factoryline | files=factoryline/index_continuity.py,factoryline/cli.py,tests/test_index_continuity.py | verify=`python -m pytest -q tests/test_index_continuity.py` | Implement baseline and compare contracts.
- [x] T3 | slice=editors/intellij | files=editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineIdeHealth.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineIndexContinuity.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineCore.kt,tests/test_intellij_workflow.py | verify=`.\gradlew.bat test` | Implement the in-memory health recorder and continuity UI.
- [ ] T4 | slice=docs | files=docs/IDE_HEALTH.md,docs/WORKSPACE_ADVISOR.md,docs/RELEASE_NOTES_0.40.1.md,tests/test_publication_metadata.py | verify=`python -m pytest -q && .\gradlew.bat check buildPlugin marketplacePreflight` | Document, package, and validate the released feature.
