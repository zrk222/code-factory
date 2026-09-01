# Plan: oracle-firewall-v1
Spec: specs/oracle-firewall-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Capture original handoff intent, seal provenance-labelled Oracle Contracts,
   and detect fail-closed semantic weakening before a candidate can replace the
   definition of done.
2. Compile and independently validate implementation-targeted Shadow Oracle
   challenge plans, then bind autonomous admission and demotion incidents.
3. Project the complete source-to-decision lineage in FactoryLine Mission
   Control, without turning Graph Ops into an authority source.
4. Validate structural, adversarial, CLI, Graph Ops, package, and design gates.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=factoryline | files=factoryline/oracle_firewall.py,tests/test_oracle_firewall.py | verify=`py -3.11 -m pytest -q tests/test_oracle_firewall.py -k handoff_or_contract` | Capture immutable original intent handoffs, then seal and verify source-bound provenance contracts.
- [x] T2 | slice=factoryline | files=factoryline/oracle_firewall.py,tests/test_oracle_firewall.py | verify=`py -3.11 -m pytest -q tests/test_oracle_firewall.py -k drift` | Detect semantic weakening and write exact, source-justified drift reports.
- [x] T3 | slice=factoryline | files=factoryline/oracle_firewall.py,factoryline/agent_license.py,tests/test_oracle_firewall.py,tests/test_agent_license.py | verify=`py -3.11 -m pytest -q tests/test_oracle_firewall.py tests/test_agent_license.py` | Add independent implementation challenge, incident capsule, and demotion evidence.
- [x] T4 | slice=factoryline | files=factoryline/cli.py,factoryline/graph_ops.py,factoryline/graph_ops.html,tests/test_graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_oracle_firewall.py tests/test_graph_ops.py tests/test_factoryline.py` | Expose explicit CLI and read-only Mission Control proof-of-oracle path.
- [x] T5 | slice=docs | files=docs/ORACLE_FIREWALL.md,docs/GRAPH_OPS.md | verify=`py -3.11 -m pytest -q tests/test_oracle_firewall.py tests/test_graph_ops.py` | Document authority limits and Mission Control workflow.
- [x] T6 | slice=README.md | files=README.md | verify=`py -3.11 -m build; py -3.11 -m twine check dist/*` | Add the operator entrypoint and validate the distributable artifact.
- [x] T7 | slice=factoryline | files=factoryline/appforge_oracle.py,factoryline/codex_metadata.py,factoryline/mcp.py,tests/test_appforge_oracle.py | verify=`py -3.11 -m pytest -q tests/test_appforge_oracle.py tests/test_codex_metadata.py tests/test_mcp.py tests/test_webmcp.py` | Bind AppForge assurance, IDE/MCP supervision, and privacy-safe workspace provenance audit to the Oracle evidence boundary.
