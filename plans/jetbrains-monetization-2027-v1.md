# Plan: jetbrains-monetization-2027-v1
Spec: specs/jetbrains-monetization-2027-v1.md (approved)
Architect verdict: PASS

## Logical decomposition

1. Lock public price and advance-notice language without activating paid mode.
2. Stage an exact paid descriptor and machine-readable January launch manifest.
3. Add fail-closed Marketplace pending/approval status checks.
4. Prove arithmetic, staging boundaries, documentation completeness, and workflow gating.

## Tasks

- [x] T1 | slice=scripts | files=scripts/jetbrains_marketplace_status.py | verify=`python -m pytest -q tests/test_jetbrains_marketplace_status.py` | Implement a fail-closed public Marketplace status checker.
- [x] T2 | slice=tests | files=tests/test_jetbrains_marketplace_status.py,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_jetbrains_marketplace_status.py tests/test_publication_metadata.py` | Bind status, price, descriptor, and documentation contracts.
- [x] T3 | slice=docs | files=docs/JETBRAINS_MONETIZATION_2027.md,docs/JETBRAINS_MONETIZATION_2027.json,docs/JETBRAINS_PRICING_BENCHMARK.json,docs/JETBRAINS_MARKETPLACE.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Publish the full monetization runbook, launch manifest, fixed price, and approval boundary.
- [x] T4 | slice=editors/intellij | files=editors/intellij/monetization/plugin-product-descriptor-2027.xml,editors/intellij/src/main/resources/META-INF/plugin.xml | verify=`editors/intellij/gradlew.bat marketplacePreflight` | Stage paid metadata while keeping active 0.7.2 free.
- [x] T5 | slice=.github/workflows/jetbrains-marketplace.yml | files=.github/workflows/jetbrains-marketplace.yml | verify=`python -m pytest -q tests/test_jetbrains_marketplace_status.py tests/test_jetbrains_release_artifact.py` | Block protected publication while an earlier listing update is pending.
- [x] T6 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Publish concise advance pricing notice and launch runbook link.
