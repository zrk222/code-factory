# Plan: appforge-device-reality-v1

Spec: specs/appforge-device-reality-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Seal source-backed candidate, design, journey, outcome, and transport authority.
2. Verify supplied supervised artifacts deterministically and fail closed on scope/oracle weakening.
3. Surface read-only status through CLI, AppForge, MCP, WebMCP, and the existing mission-control UI.
4. Verify adversarial mutations, local interface parity, Graph Ops content, and public UI quality.

## Tasks (atomic - each independently shippable)

- [x] T1 | slice=factoryline/appforge_device_reality.py | files=<=4 | verify=`python -m pytest -q tests/test_appforge_device_reality.py` | Add sealed intent envelope and device evidence receipt validation with zero device/provider authority.
- [x] T2 | slice=factoryline/cli.py,factoryline/appforge_evidence_kit.py | files=<=4 | verify=`python -m pytest -q tests/test_appforge_device_reality.py tests/test_appforge_evidence_kit.py` | Add workspace-scoped CLI and deliberately incomplete novice evidence-kit templates.
- [x] T3 | slice=factoryline/appforge_design.py,factoryline/mcp.py,factoryline/webmcp.py | files=<=4 | verify=`python -m pytest -q tests/test_mcp.py tests/test_webmcp.py` | Project bounded status for IDE and browser agents.
- [x] T4 | slice=factoryline/graph_ops.py,factoryline/graph_ops.html,docs/APPFORGE_DEVICE_REALITY.md | files=<=4 | verify=`python -m pytest -q tests/test_graph_ops.py` | Expose the supervised Device Reality lane with its explicit claim boundary.
