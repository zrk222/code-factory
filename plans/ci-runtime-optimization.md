# Plan: ci-runtime-optimization
Spec: specs/ci-runtime-optimization.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Reuse the package-and-verify ZIP as the compatibility verifier input.
2. Cache safe dependency downloads for Gradle and the Python test matrix.
3. Add deterministic workflow and Gradle contract tests, then run the suite.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=ci | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py tests/test_jetbrains_release_artifact.py` | Reuse the immutable plugin ZIP and add Gradle verification input support.
- [x] T2 | slice=ci | files=<=2 | verify=`python -m pytest -q tests/test_publication_metadata.py` | Cache Python downloads and assert the workflow cache contract.
