# Plan: Deep Defect Mesh v1
Spec: specs/deep-defect-mesh-v1.md (approved)
Architect verdict: PASS

## Logical decomposition
1. Seal analyzer/rule/canary authority and candidate identity.
2. Normalize bounded SARIF execution, location, fingerprint, suppression, and nested-flow facts.
3. Evaluate signed thresholds and canary survivability; correlate without causal claims.
4. Expose actionable read-only status through CLI, MCP, Mission Control, and the IDE playbook.
5. Verify positive, negative, corruption, UI-surface, package, and full-regression paths.

## Tasks
- [x] T1 | slice=specs | files=specs/deep-defect-mesh-v1.md,specs/deep-defect-mesh-v1.ssat.yaml | verify=`specline strict deep-defect-mesh-v1 --root .` | Seal the exact contract and atomic implementation plan.
- [x] T2 | slice=factoryline | files=factoryline/deep_audit_contract.py,factoryline/deep_audit_io.py | verify=`python -m pytest -q tests/test_deep_audit_contract.py` | Implement DSSE plan, source, trust, analyzer, rule, and canary validation.
- [x] T3 | slice=factoryline | files=factoryline/deep_audit_sarif.py | verify=`python -m pytest -q tests/test_deep_audit_sarif.py` | Implement strict bounded SARIF normalization including nested traces and suppressions.
- [x] T4 | slice=factoryline | files=factoryline/deep_audit.py | verify=`python -m pytest -q tests/test_deep_audit.py` | Implement decisions, clusters, action queue, receipt hashing, and status verification.
- [x] T5 | slice=factoryline | files=factoryline/cli.py,factoryline/mcp.py,factoryline/mission_control_status.py,factoryline/ide_playbook.py | verify=`python -m pytest -q tests/test_deep_audit_surfaces.py tests/test_mcp.py tests/test_ide_playbook.py` | Wire CLI, MCP, Mission Control, and IDE guidance.
- [x] T6 | slice=docs | files=docs/DEEP_DEFECT_MESH.md,docs/DEEP_DEFECT_RESEARCH.md,docs/RELEASE_NOTES_0.46.2.md | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document engines, operator flow, action output, research provenance, and claim limits.
- [x] T7 | slice=smoke | files=smoke/deep-defect-mesh-v1.json | verify=`forge verify-tests deep-defect-mesh-v1 specs/deep-defect-mesh-v1.ssat.yaml --root .` | Prove the smoke gate rejects a hollow implementation.
- [x] T8 | slice=tests | files=tests/test_deep_audit_contract.py,tests/test_deep_audit_sarif.py,tests/test_deep_audit.py,tests/test_deep_audit_surfaces.py | verify=`python -m pytest -q` | Run positive, negative, corruption, and full-regression tests.
- [x] T9 | slice=tests | files=tests/test_mcp.py,tests/test_ide_playbook.py | verify=`python -m pytest -q tests/test_mcp.py tests/test_ide_playbook.py` | Preserve existing integration inventory and routing contracts.
- [x] T10 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the claim-bounded public discovery path.
- [x] T11 | slice=factoryline | files=factoryline/deep_audit_loop.py,factoryline/graph_ops.py,factoryline/repair_loop.py | verify=`python -m pytest -q tests/test_deep_audit_loop.py tests/test_deep_audit_surfaces.py` | Connect finding lineage to graph nodes and no-progress/regression-aware repair handoffs.
- [x] T12 | slice=tests | files=tests/test_deep_audit_loop.py | verify=`python -m pytest -q tests/test_deep_audit_loop.py` | Challenge changed policy, lost analyzer coverage, new defects, stagnation, and human-only closure.
