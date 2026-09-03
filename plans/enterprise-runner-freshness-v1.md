# Plan: enterprise-runner-freshness-v1
Spec: specs/enterprise-runner-freshness-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Preserve signed identity lifecycle evidence in each immutable decision.
2. Derive and re-check packet freshness from that evidence at seal and read time.
3. Project the fresh/expired distinction through Graph Ops and MCP without a
   runner execution path.
4. Prove normal, expired, malformed, UI, and MCP paths with focused tests and
   package validation.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=factoryline | files=factoryline/enterprise_enforcement.py,factoryline/enterprise_runner_admission.py | verify=`py -3.11 -m pytest -q tests/test_enterprise_enforcement.py` | Bind immutable decision identity expiry to runner packet verification.
- [x] T2 | slice=factoryline | files=factoryline/graph_ops.py,factoryline/graph_ops.html,tests/test_enterprise_enforcement.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py tests/test_mcp.py` | Surface fresh and expired packet status in supervision tests and Graph Ops.
- [x] T3 | slice=docs | files=docs/ENTERPRISE_ENFORCEMENT.md | verify=`py -3.11 -m pytest -q tests/test_public_docstrings.py` | Document freshness and the live-revocation boundary.
