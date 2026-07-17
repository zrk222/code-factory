# Plan: product-missions
Spec: specs/product-missions.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Compile PRDs into stable Product Graphs and gap inventories.
2. Plan deterministic vertical slices with exact requirement coverage.
3. Bind one slice into a budgeted mission and verified Loop Passport.
4. Produce evidence-linked PR drafts and hash-linked outcome records.
5. Expose Meter v2, Studio, VS Code, and JetBrains control surfaces.
6. Prove mutation, drift, compatibility, packaging, and public documentation.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/product_missions.py | verify=`python -m pytest -q tests/test_product_missions.py` | Implement Product Graph, slices, mission, PR draft, and outcomes.
- [ ] T2 | slice=tests | files=tests/test_product_missions.py | verify=`python -m pytest -q tests/test_product_missions.py` | Prove deterministic IDs, complete coverage, blocking gaps, drift, budgets, and outcome chains.
- [ ] T3 | slice=factoryline | files=factoryline/cli.py,factoryline/meter.py | verify=`python -m pytest -q tests/test_product_missions.py tests/test_factoryline.py` | Add CLI contracts and honest Meter v2 fields.
- [ ] T4 | slice=factoryline | files=factoryline/studio.py | verify=`python -m pytest -q tests/test_studio.py` | Add contained Product Mission compilation to Studio.
- [ ] T5 | slice=tests | files=tests/test_studio.py | verify=`python -m pytest -q tests/test_studio.py` | Prove the contained Product Mission Studio request.
- [ ] T6 | slice=editors/vscode | files=editors/vscode/package.json,editors/vscode/src/extension.ts,editors/vscode/src/test/receipt.test.ts | verify=`npm test` | Add trusted Product Mission Studio entry point and command metadata.
- [ ] T7 | slice=editors/intellij | files=editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt,editors/intellij/src/main/resources/META-INF/plugin.xml | verify=`gradlew.bat test` | Add confirmed Product Mission Studio entry point.
- [ ] T8 | slice=docs | files=docs/PRODUCT_MISSIONS.md,docs/assets/product-missions.svg | verify=`python -m pytest -q tests/test_publication_metadata.py` | Publish workflows, boundaries, schemas, and diagrams.
- [ ] T9 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add Product Missions to the public quick start.
- [ ] T10 | slice=factoryline | files=factoryline/__init__.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Update runtime version to v0.15.0.
- [ ] T11 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m pytest -q tests/test_publication_metadata.py` | Update package version to v0.15.0.
- [ ] T12 | slice=CITATION.cff | files=CITATION.cff | verify=`python -m pytest -q tests/test_publication_metadata.py` | Update citation version to v0.15.0.

## Release gates

- `specline validate product-missions --root .`
- `specline strict product-missions --root .`
- `specline verify-validators product-missions --root .`
- `forge architect product-missions specs/product-missions.ssat.yaml --root . --adopt-existing`
- `forge gate architected product-missions --root .`
- `forge verify-tests product-missions specs/product-missions.ssat.yaml --root .`
- `forge challenge product-missions specs/product-missions.ssat.yaml --root .`
- `forge smoke product-missions --root .`
- `forge qa product-missions --ssat specs/product-missions.ssat.yaml --root . --strict`
- `python -m pytest -q`
- VS Code and JetBrains plugin tests
- build, twine check, and clean-wheel smoke
