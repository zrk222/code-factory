# Plan: jetbrains-marketplace-admission-v1

Architect verdict: PASS

## Scope

Add a fail-fast protected Marketplace authorization job and static local check.
Preserve the existing Marketplace slot guard and JDK 21 route requirements,
then expose the newly declared external condition through existing read-only
release decision surfaces.

## Atomic task packets

- [x] T1 | slice=jetbrains-marketplace-admission | files=<=4 | verify=`python -m pytest -q tests/test_release_integrity.py` | Added the protected authorization job before candidate work and its local static route check.
- [x] T2 | slice=jetbrains-marketplace-route-proof | files=<=3 | verify=`python -m pytest -q tests/test_release_integrity.py tests/test_graph_ops.py tests/test_release_decision.py` | Added four authorization-bypass mutations and verified external state remains unobserved with zero authority.
- [x] T3 | slice=jetbrains-marketplace-package-proof | files=<=4 | verify=`python -m pytest -q tests/test_release_integrity.py tests/test_release_decision.py tests/test_graph_ops.py tests/test_mcp.py` | Passed 82 focused tests, 9/9 scoped drift checks, package build, Twine validation, and a clean-wheel 12-check receipt.

## Non-goals

- No credential retrieval, provider query, release upload, tag, publication, or deployment.
- No claim of JetBrains approval, upload-slot availability, package processing, or review outcome.
