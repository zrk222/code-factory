# Plan: release-reliability-hardening
Spec: specs/release-reliability-hardening.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Split release validation into independent artifact-producing jobs with a
   strict publish fan-in.
2. Move protected Open VSX token authorization ahead of candidate validation.
3. Add a read-only release workflow integrity inspector and CLI surface.
4. Remove release-verifier-visible deprecated IntelliJ chooser calls while
   preserving all choice defaults.
5. Upgrade the Kotlin Gradle Plugin to the Gradle-9.5-compatible line and
   reject legacy usage-value warnings.
6. Validate Hugging Face Space-card metadata before remote upload.
7. Declare Python wheel data explicitly to eliminate package-discovery ambiguity.
8. Prove happy paths, structural regressions, mutation resistance, and package
   installation without changing any publication state.

## Tasks (atomic — each independently shippable)
- [x] T1 | slice=release-workflow | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py` | Split release validation into independent Python, VS Code, and JetBrains artifact jobs with an exact publish fan-in.
- [x] T2 | slice=openvsx-preflight | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py` | Fail protected Open VSX publication before candidate work when the scoped token is absent, while retaining token-free validation mode.
- [x] T3 | slice=release-integrity | files=<=4 | verify=`python -m pytest -q tests/test_release_integrity.py` | Add the deterministic read-only workflow inspector, CLI command, and mutation-focused tests.
- [x] T4 | slice=intellij-chooser-compatibility | files=<=3 | verify=`cd editors/intellij; ./gradlew check buildPlugin verifyPlugin marketplacePreflight` | Replace deprecated IntelliJ chooser calls with the supported selector API while preserving selection defaults.
- [x] T5 | slice=intellij-gradle-compatibility | files=<=3 | verify=`cd editors/intellij; ./gradlew help --warning-mode all` | Upgrade Kotlin Gradle Plugin to the Gradle 9.5-compatible line and reject legacy usage-value warnings.
- [x] T6 | slice=huggingface-metadata-preflight | files=<=4 | verify=`python -m pytest -q tests/test_huggingface_surface.py` | Validate Hugging Face Space-card metadata before installing the client or uploading.
- [x] T7 | slice=python-package-data | files=<=4 | verify=`python -m build && python -m twine check dist/*` | Declare wheel data directly instead of relying on automatic source-directory discovery.
- [ ] T8 | slice=release-proof | files=<=4 | verify=`python -m pytest -q` | Run strict spec, architecture, smoke, package, and installed-wheel checks without publishing.
