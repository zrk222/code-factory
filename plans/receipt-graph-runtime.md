# Plan: receipt-graph-runtime
Spec: specs/receipt-graph-runtime.md (approved)
Architect verdict: PASS

## Logical decomposition (phases)

1. Seal the runtime contract and architecture boundary.
2. Implement canonical transactional state, transitions, receipts, verification, and topology export.
3. Add the optional LangGraph adapter and operator CLI.
4. Prove replay safety, role separation, tamper detection, retry bounds, persistence, and adapter parity.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=specs | files=specs/receipt-graph-runtime.md,specs/receipt-graph-runtime.ssat.yaml | verify=`specline strict receipt-graph-runtime --root .` | Add the approved spec and SSAT contract.
- [ ] T2 | slice=adr | files=adr/0013-receipt-backed-graph-runtime.md | verify=`specline validate receipt-graph-runtime --root .` | Record the orchestration-versus-authority boundary.
- [ ] T3 | slice=factoryline | files=factoryline/mission_graph.py | verify=`pytest -q tests/test_mission_graph.py -k native` | Implement the native SQLite graph, verification, and topology export.
- [ ] T4 | slice=tests | files=tests/test_mission_graph.py | verify=`pytest -q tests/test_mission_graph.py` | Prove transition, role, replay, tamper, persistence, and LangGraph parity behavior.
- [ ] T5 | slice=factoryline | files=factoryline/cli.py | verify=`pytest -q tests/test_mission_graph.py tests/test_factoryline.py` | Add the operator CLI.
- [ ] T6 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Add the optional LangGraph dependency group.
- [ ] T7 | slice=docs | files=docs/LANGGRAPH_OPS.md | verify=`pytest -q tests/test_publication_metadata.py` | Document native and LangGraph operator workflows.
- [ ] T8 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`pytest -q tests/test_publication_metadata.py` | Record the graph-runtime enhancement without changing release authority.
- [ ] T9 | slice=factoryline | files=factoryline/provider_router.py | verify=`pytest -q tests/test_provider_router.py` | Implement secret-free BYOK policy validation and deterministic multi-provider routing.
- [ ] T10 | slice=tests | files=tests/test_provider_router.py | verify=`pytest -q tests/test_provider_router.py` | Prove rails, redaction, IDE selection, cache behavior, and no-provider-call boundaries.
- [ ] T11 | slice=editors/intellij | files=editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineCore.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineToolWindow.kt,editors/intellij/src/main/resources/META-INF/plugin.xml | verify=`editors/intellij/gradlew.bat test` | Add mission graph and provider routing operations to JetBrains with explicit confirmation.
- [ ] T12 | slice=editors/intellij | files=editors/intellij/src/test/kotlin/app/factoryline/intellij/FactoryLineCoreTest.kt | verify=`editors/intellij/gradlew.bat test` | Prove JetBrains argument construction, path containment, and secret-free output handling.
