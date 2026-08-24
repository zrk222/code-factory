# Plan: evidence-frontier-v1

Spec: `specs/evidence-frontier-v1.md`
Architect verdict: PASS

## Logical decomposition

1. Build a sealed Evidence Frontier contract that consumes, but never modifies,
   an existing ProofSearch evaluation.
2. Add CLI planning and verification commands with compact machine-readable
   failure output.
3. Project verified frontiers into Unified Graph Ops and provide a visually clear
   non-executing control surface.
4. Prove ordering, tamper detection, no-progress halting, authority retention,
   Graph Ops projection, and UI accessibility with focused tests.

## Tasks

- [ ] T1 | slice=proof contract | files=<=4 | verify=`python -m pytest -q tests/test_evidence_frontier.py` | Implement and test sealed deterministic frontier planning and verification.
- [ ] T2 | slice=CLI | files=<=3 | verify=`python -m pytest -q tests/test_evidence_frontier.py` | Add `factory proofsearch frontier plan|verify` without execution authority.
- [ ] T3 | slice=Graph Ops | files=<=4 | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_evidence_frontier.py` | Render verified frontier nodes and safe controls.
- [ ] T4 | slice=public docs | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py tests/test_graph_ops.py` | Document the contract and update discoverability without unmeasured claims.
