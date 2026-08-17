# Plan: graph-portfolio-admission-v1
Spec: specs/graph-portfolio-admission-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Define deterministic portfolio and admission schemas with sealed-digest and
   no-side-effect boundaries.
2. Implement graph cycle analysis, structural critical path, slack,
   descendant-based sharing, and stable work ordering.
3. Implement admission preparation and re-verification over the existing Loop
   Passport and Graph Ops snapshot.
4. Project the evidence into Graph Ops and its visual UI with disabled
   consequential controls.
5. Run SpecLine, ForgeLine, focused and full Python tests, source mutation
   checks, UI audit, package build, and clean wheel smoke.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=factoryline/graph_portfolio.py | files=<=4 | verify=`python -m pytest -q tests/test_graph_portfolio.py` | Implement deterministic graph portfolio calculation.
- [ ] T2 | slice=factoryline/run_admission.py | files=<=4 | verify=`python -m pytest -q tests/test_run_admission.py` | Implement sealed admission packets and stale re-verification.
- [ ] T3 | slice=factoryline/graph_ops.py | files=<=4 | verify=`python -m pytest -q tests/test_graph_ops.py` | Project planner and admission evidence as read-only Graph Ops nodes.
- [ ] T4 | slice=factoryline/cli.py | files=<=4 | verify=`python -m pytest -q tests/test_graph_portfolio.py tests/test_run_admission.py` | Expose bounded CLI commands.
- [ ] T5 | slice=docs | files=<=4 | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document authority boundaries and user workflow.
