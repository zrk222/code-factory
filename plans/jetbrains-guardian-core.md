# Plan: JetBrains Guardian Core

Spec: specs/jetbrains-guardian-core.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Derive a pure, bounded Guardian assessment from existing in-memory IDE
   health samples, including explicit unavailable states and non-causal events.
2. Add a default Guardian dashboard and safe tab navigation while retaining all
   advanced proof, repair, workspace, continuity, and ledger surfaces.
3. Validate the decision logic, Kotlin tests, packaged plugin, Marketplace
   preflight, reviewer summary, compliance checklist, and release-workflow
   topology without attempting Marketplace publication.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=editors/intellij | files=<=2 | verify=`.\\gradlew.bat test -x instrumentCode --console=plain` | Derive bounded Guardian assessment and incident timeline from local samples only.
- [ ] T2 | slice=editors/intellij | files=<=3 | verify=`.\\gradlew.bat test -x instrumentCode --console=plain` | Add a first-tab Guardian dashboard with observation-only controls and tab navigation.
- [ ] T3 | slice=. | files=<=25 | verify=`.\\gradlew.bat guardianReleaseGate -x instrumentCode --console=plain`; `python -m pytest tests/test_release_integrity.py tests/test_publication_metadata.py -q` | Update version, Marketplace-facing evidence boundaries, policy checklist, reviewer summary, package gate, and release-workflow integrity without Marketplace publication.
