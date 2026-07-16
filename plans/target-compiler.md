# Plan: target-compiler
Spec: specs/target-compiler.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Define target and receipt schemas plus path and overwrite invariants.
2. Compile the four target-specific starter trees.
3. Expose CLI and loopback Studio surfaces.
4. Connect VS Code and JetBrains launch actions.
5. Publish consistent diagrams, docs, tests, packages, and repository links.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/target_compiler.py | verify=`python -m pytest -q tests/test_target_compiler.py` | Implement target compiler, manifests, receipts, and four target trees.
- [ ] T2 | slice=tests | files=tests/test_target_compiler.py | verify=`python -m pytest -q tests/test_target_compiler.py` | Prove all target shapes, hash receipts, and overwrite refusal.
- [ ] T3 | slice=factoryline | files=factoryline/studio.py,factoryline/cli.py | verify=`python -m pytest -q tests/test_studio.py tests/test_factoryline.py` | Add CLI and loopback Studio with bounded request handling.
- [ ] T4 | slice=tests | files=tests/test_studio.py | verify=`python -m pytest -q tests/test_studio.py tests/test_factoryline.py` | Prove Studio path containment, body limit, and status contract.
- [ ] T5 | slice=editors/vscode | files=editors/vscode/package.json,editors/vscode/src/extension.ts,editors/vscode/src/test/receipt.test.ts | verify=`npm test` | Add trusted Studio launch through VS Code external URI handling.
- [ ] T6 | slice=editors/intellij | files=editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineCore.kt,editors/intellij/src/main/resources/META-INF/plugin.xml,editors/intellij/src/test/kotlin/app/factoryline/intellij/FactoryLineCoreTest.kt | verify=`gradlew.bat test` | Add confirmed Studio launch through JetBrains BrowserUtil.
- [ ] T7 | slice=docs | files=docs/TARGET_COMPILER.md,docs/assets/target-compiler.svg | verify=`python -m pytest -q tests/test_publication_metadata.py` | Publish the target architecture, safety boundary, and quick start.
- [ ] T8 | slice=factoryline | files=factoryline/__init__.py | verify=`python -m build` | Synchronize the package runtime version before release packaging.
- [ ] T9 | slice=tests | files=tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Prove publication metadata and target visual are synchronized.

## Release gates

- `specline validate target-compiler --root .`
- `specline strict target-compiler --root .`
- `specline verify-validators target-compiler --root .`
- `forge architect target-compiler specs/target-compiler.ssat.yaml --root . --adopt-existing`
- `forge gate architected target-compiler --root .`
- `forge verify-tests target-compiler specs/target-compiler.ssat.yaml --root .`
- `forge verify-tests-ts target-compiler --root .`
- `forge challenge target-compiler specs/target-compiler.ssat.yaml --root .`
- `forge smoke target-compiler --root .`
- `forge qa target-compiler --ssat specs/target-compiler.ssat.yaml --root . --strict`
- `python -m pytest -q`
- editor package tests
- package build, twine check, and clean-wheel smoke
