# Plan: senior-engineering-integration
Spec: specs/senior-engineering-integration.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Keep the current six-lane runtime-audit and proof-reuse contracts as the
   source of truth; add narrow adapters and receipts rather than parallel policy.
2. Implement and test the attestation, benchmark, and scheduler modules.
3. Wire a single `factory senior` CLI surface and shared error/receipt helpers.
4. Integrate read-only status projections into Graph Ops only after module tests
   pass; no release or provider authority is added.
5. Run SpecLine drift/challenge, ForgeLine QA/smoke, focused tests, package
   validation, and a clean import smoke before any release decision.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=factoryline | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_independent_execution.py` | Add strict independent-attestation normalization/verification and adversarial cases.
- [x] T2 | slice=factoryline | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_benchmark_lab.py` | Add manifest-bound defect benchmark evaluation with per-category quality metrics.
- [x] T3 | slice=factoryline | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_incremental_scheduler.py` | Add dependency closure, DAG planning, safe reuse routing, and shadow comparison.
- [x] T4 | slice=factoryline/cli.py | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_senior_cli.py` | Expose provider-neutral `factory senior attest|benchmark|schedule|shadow` commands.
- [x] T5 | slice=tests/docs | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_senior_integration.py` | Add cross-module receipts, docs, and regression gates; preserve authority boundaries.
- [x] T6 | slice=factoryline | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_senior_assurance.py -k replay` | Add fresh, contract-bound process replay with exact source/dependency/policy/input binding, bounded output, cleanup, and secret-free environment.
- [x] T7 | slice=factoryline | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_senior_assurance.py -k repair` | Add executable original-vs-repair comparison with negative controls and reviewer-gated expectation changes.
- [x] T8 | slice=factoryline | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_senior_assurance.py -k reuse` | Add explicit policy/dependency/toolchain/environment evidence-reuse explanations that route unknown inputs to RUN and side effects to BLOCK.
- [x] T9 | slice=factoryline/cli.py | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_senior_cli.py` | Expose replay, repair, reuse, and failure-brief commands with bounded JSON receipts and no release authority.
- [x] T10 | slice=tests/docs/graph | files=<=4 | verify=`py -3.11 -m pytest -q tests/test_senior_assurance.py tests/test_senior_graph_ops.py` | Project the four receipts read-only, publish the evidence-linked failure briefing guidance, and preserve hash/authority checks.
