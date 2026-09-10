# Plan: junie-factoryline-taxonomy-v1
Spec: specs/junie-factoryline-taxonomy-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Create one versioned progressive taxonomy and a conservative Junie project
   pack writer with conflict-first preflight.
2. Surface taxonomy through the local MCP adapter and CLI without adding any
   execution authority.
3. Add a JetBrains tool-window route and command builders, then test Python
   behavior, package integration, and Kotlin command contracts.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=taxonomy | files=<=4 | verify=`pytest -q tests/test_junie_taxonomy.py` | Add a complete inventory-bound taxonomy and safe pack installer.
- [ ] T2 | slice=adapter | files=<=4 | verify=`pytest -q tests/test_mcp.py tests/test_mcp_setup.py` | Add read-only MCP and CLI discovery/install surfaces.
- [ ] T3 | slice=jetbrains | files=<=4 | verify=`./gradlew test` | Add a Junie taxonomy panel and explicit install command contract.
