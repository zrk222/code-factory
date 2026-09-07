# Plan: release-route-contracts-v1

Architect verdict: PASS

## Scope

Implement read-only static release-route checks for VS Code Marketplace
authorization and candidate sealing, plus the declared Java 21 IntelliJ
runtime. Surface route requirements in the existing release-decision Graph Ops
node without expanding its authority.

## Atomic task packets

- [x] T1 | slice=release-route-integrity | files=<=4 | verify=`python -m pytest -q tests/test_release_integrity.py` | Added isolated read-only route checks for protected VS Code authorization, sealed candidate identity, and Java 21 declarations.
- [x] T2 | slice=release-route-visibility | files=<=3 | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_release_decision.py tests/test_ide_playbook.py` | Projected declared, unobserved external route requirements into the existing zero-authority Graph Ops decision node.
- [x] T3 | slice=release-route-proof | files=<=4 | verify=`python -m pytest -q tests/test_release_integrity.py tests/test_release_decision.py tests/test_graph_ops.py tests/test_mcp.py` | Passed 78 focused tests, 8/8 scoped drift checks, package build, Twine validation, and a clean-wheel route-preflight receipt.

## Non-goals

- No provider workflow dispatch, package upload, tag, commit, or deployment.
- No credential access or environment secret validation.
- No dynamic toolchain execution as part of route inspection.
