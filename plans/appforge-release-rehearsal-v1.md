# Plan: appforge-release-rehearsal-v1

Spec: specs/appforge-release-rehearsal-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Build a sealed, credential-free Fastlane, App Store Connect CLI, Cider, Swiftlane, or Zealot release rehearsal from existing candidate and AppForge assurance evidence.
2. Surface its status through local CLI, AppForge, MCP/WebMCP, and Graph Ops.
3. Add adversarial coverage for all provider/state-boundary failures and document the Fastlane, ASC, Cider, Swiftlane, and Zealot patterns and limits.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=factoryline/appforge_release_rehearsal.py | files=<=4 | verify=`python -m pytest -q tests/test_appforge_release_rehearsal.py` | Add candidate-bound release profile verification, ordered release-state matrix, and sealed receipt with zero execution authority.
- [ ] T2 | slice=factoryline/cli.py,factoryline/appforge_design.py,factoryline/mcp.py | files=<=4 | verify=`python -m pytest -q tests/test_appforge_release_rehearsal.py tests/test_mcp.py` | Add workspace-scoped rehearsal creation and read-only status surfaces.
- [ ] T3 | slice=factoryline/webmcp.py,factoryline/graph_ops.py,factoryline/graph_ops.html | files=<=4 | verify=`python -m pytest -q tests/test_webmcp.py tests/test_graph_ops.py` | Add a seventh AppForge Mission Control lane without provider-control claims.
- [ ] T4 | slice=docs/APPFORGE_RELEASE_REHEARSAL.md,tests/test_appforge_release_rehearsal.py | files=<=4 | verify=`python -m pytest -q tests/test_appforge_release_rehearsal.py` | Document safe provider patterns and prove stage and credential boundaries.
