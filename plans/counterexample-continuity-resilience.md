# Plan: counterexample-continuity-resilience

Spec: `specs/counterexample-continuity-resilience.md`
Architect verdict: PASS

## Logical decomposition

1. Compile and verify deterministic counterexample plans.
2. Project promoted continuity metadata into path-triggered guardrails without reading memory content.
3. Compile and verify temporal-resilience schedules from sealed graph lineage.
4. Surface all three receipts in Graph Ops and document their execution limits.

## Tasks

- [ ] T1 | slice=counterexample | files=<=4 | verify=`pytest -q tests/test_counterexample.py` | Add canonical counterexample source, planner, verifier, CLI, and mutation tests.
- [ ] T2 | slice=guardrail | files=<=4 | verify=`pytest -q tests/test_guardrails.py` | Add continuity-backed, redacted guardrail mapping/evaluation and CLI tests.
- [ ] T3 | slice=resilience | files=<=4 | verify=`pytest -q tests/test_resilience.py` | Add sealed temporal-resilience planner/verifier based on graph lineage and tests.
- [ ] T4 | slice=graph-ops | files=<=4 | verify=`pytest -q tests/test_graph_ops.py` | Add read-only Graph Ops projections and user documentation for the new plans.
