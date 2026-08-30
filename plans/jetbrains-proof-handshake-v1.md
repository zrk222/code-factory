# Plan: jetbrains-proof-handshake-v1
Spec: specs/jetbrains-proof-handshake-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Seal and validate the supported artifact contracts.
2. Join path scope, intent, vendor-neutral Qodana/SonarQube SARIF, and non-hollow E2E evidence.
3. Expose read-only agent/MCP routes and supervised JetBrains controls.
4. Prove fail-closed decisions, package integrity, and Marketplace readiness.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=factoryline | files=factoryline/analysis_evidence.py,factoryline/jetbrains_handshake.py | verify=`python -m pytest -q tests/test_analysis_evidence.py tests/test_jetbrains_handshake.py` | Implement the deterministic mission and vendor-neutral analysis handshake receipt.
- [x] T2 | slice=factoryline | files=factoryline/mcp.py,factoryline/mcp_setup.py,factoryline/webmcp.py | verify=`python -m pytest -q tests/test_mcp.py tests/test_mcp_setup.py tests/test_webmcp.py` | Add Junie and Copilot MCP setup plus read-only mission/handshake tools.
- [x] T3 | slice=editors/intellij | files=editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineCore.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineRepairSandbox.kt | verify=`gradlew.bat test --tests app.factoryline.intellij.FactoryLineCoreTest` | Add supervised evidence selection, MCP setup, WebMCP/Graph Ops, and story controls.
- [x] T4 | slice=editors/intellij | files=editors/intellij/src/main/resources/META-INF/plugin.xml,editors/intellij/README.md | verify=`gradlew.bat guardianReleaseGate` | Update reviewer-facing claims and seal the 0.8.19 artifact.
