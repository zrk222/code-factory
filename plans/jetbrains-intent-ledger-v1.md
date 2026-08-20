# Plan: jetbrains-intent-ledger-v1
Spec: specs/jetbrains-intent-ledger-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Define the bounded, canonical local record and its read-only inspection state machine.
2. Expose the same inspection projection through the FactoryLine CLI and MCP.
3. Bind one selected native JetBrains Change List to capture and inspection controls, then render the result in its own Tool Window tab.
4. Upgrade package metadata to 0.8.12 and prove the CLI, plugin, package, architecture, and mutation gates.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/intent_ledger.py,tests/test_intent_ledger.py | verify=`python -m pytest -q tests/test_intent_ledger.py` | Implement hash-bound capture and read-only inspection, including no-record, scope escape, stale proof, coverage, malformed record, and deterministic repeatability cases.
- [ ] T2 | slice=factoryline | files=factoryline/cli.py,factoryline/mcp.py,tests/test_mcp.py | verify=`python -m pytest -q tests/test_intent_ledger.py tests/test_mcp.py` | Add the named-confirmation CLI capture path plus read-only CLI/MCP inspect parity without new execution authority.
- [ ] T3 | slice=editors/intellij | files=editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineCore.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineIntentLedger.kt | verify=`cd editors/intellij; .\\gradlew.bat test` | Add selected-Change-List capture and inspection actions and a dedicated visual Intent Ledger tab; preserve the configured local-only executable and confirmation boundary.
- [ ] T4 | slice=editors/intellij | files=editors/intellij/build.gradle.kts,editors/intellij/src/main/resources/META-INF/plugin.xml,editors/intellij/CHANGELOG.md | verify=`cd editors/intellij; .\\gradlew.bat marketplacePreflight` | Set 0.8.12 and concise Marketplace metadata that names the local-only behavioral-contract value and limits.
- [ ] T5 | slice=docs | files=docs/JETBRAINS_INTENT_LEDGER.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document the operator workflow, exact states, and authority boundaries.
- [ ] T6 | slice=jetbrains-intent-ledger-v1.ssat.yaml | files=jetbrains-intent-ledger-v1.ssat.yaml | verify=`forge arch-gate jetbrains-intent-ledger-v1 jetbrains-intent-ledger-v1.ssat.yaml --root .` | Seal the architecture and authority boundaries.
