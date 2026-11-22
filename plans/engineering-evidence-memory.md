# Plan: Engineering Evidence Memory
Spec: specs/engineering-evidence-memory.md
Architect verdict: PASS

- [x] T1 | slice=factoryline | files=factoryline/continuity.py,factoryline/engineering_memory.py,factoryline/knowledge_handoff.py | verify=`python -m pytest -q tests/test_engineering_memory.py tests/test_knowledge_handoff.py` | Add evidence recall, independent withdrawal and receiver-revalidated knowledge handoffs.
- [x] T2 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_engineering_memory.py` | Add CLI recall and withdrawal paths.
- [x] T3 | slice=docs | files=docs/ENGINEERING_EVIDENCE_MEMORY.md | verify=`python -m pytest -q` | Document boundaries and run regressions; full-suite socket failure recorded below, not waived.
- [ ] T4 | slice=factoryline | files=factoryline/audit_rule_search.py,factoryline/engineering_memory.py,tests/test_audit_rule_search.py,tests/test_engineering_memory.py | verify=`py -3.11 -m pytest -q tests/test_engineering_memory.py tests/test_audit_rule_search.py tests/test_knowledge_handoff.py` | Share request-local corpus preparation, preserve exact ranking and trust boundaries, and measure 11 paired synthetic retrieval runs before recording speed claims.
- [ ] T5 | slice=docs | files=docs/ENGINEERING_EVIDENCE_MEMORY.md,docs/evidence/recall-preparation-20261122.json | verify=`py -3.11 .factory/recall-research/qa.py` | Record only source-bound local observations, research attribution, exact parity and end-to-end timing limits; no detector-accuracy or release claim.
- [ ] T6 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`py -3.11 .factory/recall-research/qa.py` | Keep release-candidate notes aligned with measured retrieval scope.

## Verification receipt
- Targeted continuity, engineering-memory and handoff tests: 39 passed.
- SpecLine strict, five requirement mutants, and new-module drift audit passed.
- ForgeLine architecture, review, stub rejection and smoke passed.
- Final full suite: 1229 passed, 3 skipped, 1 failed in an existing Studio HTTP test with Windows socket error 10053.
- Studio suite rerun: all 13 passed. Earlier full run failed a different Studio HTTP test with the same socket error.
- Full-suite stability is not established. No publication or deployment performed; authenticated transport and automatic runner integration are outside this local API/CLI scope.
