# Plan: full-source-coverage211
Spec: specs/full-source-coverage211.md
Architect verdict: PASS

Bounded architecture review: independent ECC reviewer approved T2–T3 subject to
the pre-admission guard below. This approves implementation of the specified
profile, not full semantic closure, precision qualification, merge or release.

Each native per-source invocation receives no partial-workspace exculpatory
context. The full profile must not call the child batch report/primitive partition
as though a batch were the complete repository. The internal global-consumer
closure flag remains false, and source-role observations retain native priority.
Only an independently verified global reference/mutation closure can change that
flag. The aggregate has a distinct schema and is not passed to the legacy
Mission Control completion verifier.

## Logical decomposition (phases)
1. Consolidate the native consumer index and verify source accounting, effect preservation and cache invalidation.
2. Add a complete-inventory profile, bounded execution, dependency metadata and explicit uncertainty. Reuse native per-source analysis without admitting partial-workspace clearance.
3. Add integrity-checked resume and CLI routing. Local checkpoints are untrusted data, never authorization or signed proofs.
4. Execute coverage, errors, drift, mutation and fixed-panel retention checks. Report full-source results separately from frozen precision.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T2 | slice=factoryline | files=factoryline/deep_audit_io.py,tests/test_context_efficiency.py | verify=`python -m pytest -q tests/test_context_efficiency.py -k full_repository` | Implement complete eligible-source inventory, native observations, dependency metadata and checkpoint validation; reuse existing bounded inventory and local IO helpers and lazily invoke the native context scanner.
- [x] T3 | slice=factoryline | files=factoryline/cli_audit.py,tests/test_cli_bootstrap.py | verify=`python -m pytest -q tests/test_cli_bootstrap.py -k full_repository` | Expose distinct full-profile and resume paths while preserving legacy receipts and frozen studies.

## Remaining qualification
- Shared native-index consolidation is recorded in commit 917c156 and docs/evidence/shared-consumer-index211.json; its completed task is removed from this remaining-work list.
- T2–T3 source, CLI and checkpoint checks passed locally on the final frozen candidate: 1,332 scoped tests, 13/13 retained positive controls, and 583/583 real eligible Python files in 48.19 seconds. See docs/evidence/full-source-coverage211.json and its hash-bound workflow evidence. Completed implementation tasks are excluded from the integrated goal's remaining work.
- Cross-file closure and high actionable precision remain integrated-goal requirements; file accounting cannot satisfy them.
- Full CI, native quality and preregistered precision qualification remain incomplete.
