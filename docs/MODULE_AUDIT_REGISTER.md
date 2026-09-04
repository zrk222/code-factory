# Module audit register

This is an ongoing audit, not a certification that CF has no remaining defects.
Scope of this pass: six runtime evaluators, their shared receipt projection, and selected proof/assembly boundaries.

## Reviewed files

| Area | Source-level check in this pass | Remaining limitation |
|---|---|---|
| Stateful | Identity, action bounds, invariant/check counts, trace bounds, missing/duplicate invariants | Aggregate counters do not prove every sequence was explored |
| Tenant isolation | Cold/warm/revoked matrix, denied fields/effects, duplicate observations, declared surfaces | Observations are supplied; owner response semantics and undeclared surfaces need richer contracts |
| Recovery | Fault modes, operations, idempotency, concurrency, phases, cleanup | No event timeline proving actual concurrency; acknowledged zero-effect operations are not individually modeled |
| Consumer compatibility | Version/branch/environment, exact interactions, mismatch counts, matrix | Consumer inventory completeness and actual network execution remain external |
| Migration | Schemas, counts, invariants, catalog, readers, recovery, locks | Full representative data and real database recovery require native runs |
| Performance/memory | Equivalent workload/environment, thresholds, cooldown, loadgen saturation, leak observations | Aggregate windows cannot prove absence of long-tail or long-duration leaks |
| Runtime status | Self-hash and lane/decision/authority consistency | Unsigned local content is not authenticated; status does not rerun the audit |
| Proof reuse | Current file hash and proof key path; malformed row handling | Full hostile filesystem/race audit remains pending |
| Assembly | Initial process runner, attribution and meter parsing inspected | Output buffering and process-tree lifecycle need a dedicated bounded-runner review |
| Oracle | Contract/source verification and weakening comparison inspected | Complete constructor/verifier parity and all rule-edge cases remain pending |

## Repaired findings

- Runtime status accepted a self-hashed empty or contradictory green receipt. It now requires six distinct lane kinds and IDs, valid states, matching decision and no release authority. Nine adversarial variants reject.
- Proof-reuse verification crashed on a non-object input/output row. It now returns invalid evidence. Ten malformed input/output variants reject.
- Earlier committed passes fixed ambiguous execution joins and contradictory stateful/recovery counters; this pass retains their regression tests.

## Unverified modules and next sequence

1. Assembly process output/termination and full proof-reuse hostile-input review.
2. Oracle authority constructors, verifier parity, exceptions and challenge paths.
3. Graph/loop lineage and current-candidate propagation; memory revocation propagation.
4. Enterprise identity, tenancy, signing, revocations and hosted adapters.
5. AppForge mobile evidence/submission/release-chain paths.
6. IDE/MCP/A2A surfaces, then separate SpecLine, ForgeLine, HSF and Prestige engine implementations.

The assembly registry contains four external engine adapters; those engines are not implemented entirely in this checkout.
Do not interpret a passing existing test suite as a source audit of those engines or every CF file.

## Operating procedure

Governance: human_controlled. For each next module: inspect constructors and consumers, reproduce a gap, seal the requirement, add negative and boundary tests, repair, verify, and commit. Do not publish, change credentials or run external engines merely to complete this register.

## Verification for this pass

- Full suite started with receipt hardening: 1258 passed, 3 skipped.
- After the proof-row fix, focused proof-reuse, receipt and runtime-surface suite: 30 passed.
- Combined proof-reuse and evaluator regression group: 57 passed.
- SpecLine strict, three requirement mutants and scoped integrity drift audit passed; ForgeLine scoped review, architecture, stub rejection and smoke passed.
- The full suite was not recollected after adding the ten proof-row tests. No production engines, external engine repositories, marketplace publication or deployment were exercised.
