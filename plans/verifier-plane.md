# Plan: verifier-plane

Spec: specs/verifier-plane.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Create a compact verifier-plane module that builds hash-bound sessions,
   validates separate worker/verifier receipts, and detects deterministic
   no-progress loops.
2. Add CLI commands and Graph Ops rendering so the bounded runtime state is
   inspectable without granting execution authority.
3. Add adversarial tests for self-verification, verifier-bundle drift,
   escaping evidence, stale results, budget exhaustion, and no-progress.
4. Update release-visible documentation and package/editor versions, then run
   SpecLine, ForgeLine, native tests, package checks, and release preflight.

## Tasks (atomic - each independently shippable)

- [x] T1 | slice=factoryline | files=<=4 | verify=`pytest -q tests/test_verifier_plane.py` | Implement session, receipt, and progress verification.
- [x] T2 | slice=factoryline | files=<=4 | verify=`pytest -q tests/test_verifier_plane.py tests/test_graph_ops.py` | Expose read-only CLI and graph state.
- [x] T3 | slice=docs | files=<=4 | verify=`python -m pytest -q` | Document authority and evidence boundaries.
- [x] T4 | slice=smoke | files=smoke/verifier-plane.json | verify=`forge verify-tests verifier-plane specs/verifier-plane.ssat.yaml --root .` | Bind adversarial verifier and Graph Ops coverage to a non-hollow smoke proof.
