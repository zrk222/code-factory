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
| Assembly | CLI calls now use bounded capture, finite cleanup waits, timeout/cancellation checks and failing cleanup status | OS cleanup is best effort, not process isolation; Windows exited-parent descendants and POSIX native execution require broader validation |
| Oracle | Contract/source verification and weakening comparison inspected | Complete constructor/verifier parity and all rule-edge cases remain pending |
| Oracle rule verification follow-up | Reuses constructor rule validation; rejects missing groups, advisory-only required groups, empty/duplicate sources and missing original-intent binding | Local hashes are not independent signatures; scope, exception and challenge paths still need further adversarial review |
| AppForge capture reconciliation | Reconstructs integrity receipt from current original candidate and contract before accepting capture mappings | Checks file identity, not pixels, native execution, authenticity of declared approval or store approval |
| Enterprise Receipt v2 | Inspected DSSE payload-type/digest/signature/identity checks and policy/revocation consumption | Revocations are optional and timestamp-relative; not proof of current hosted authorization, tenant isolation or freshness |

## Repaired findings

- Runtime status accepted a self-hashed empty or contradictory green receipt. It now requires six distinct lane kinds and IDs, valid states, matching decision and no release authority. Nine adversarial variants reject.
- Proof-reuse verification crashed on a non-object input/output row. It now returns invalid evidence. Ten malformed input/output variants reject.
- Earlier committed passes fixed ambiguous execution joins and contradictory stateful/recovery counters; this pass retains their regression tests.
- Oracle verification previously accepted rehashed structural changes the constructor rejected. Six new negative cases cover removed gates, unauthorized rule provenance, empty/duplicate sources, missing original-intent binding and a missing rule group.
- AppForge capture reconciliation previously trusted a READY marker and self-hash without reconstructing requirements. Four new negative cases reject removed/duplicate requirements and changed/missing original contracts. A positive 13-file mapping remains accepted; its synthetic bytes intentionally prove only file reconciliation, not image quality.

## Open findings: release clearance withheld

- **Assembly resource/lifecycle remediation:** `_run_cli` now delegates to `assembly_process.run_cli`, limiting retained stdout and stderr to 4 MiB each, using a 300-second execution deadline and finite OS cleanup/reader waits. Overflow, cancellation, timeout, read failure and unconfirmed cleanup cannot pass. Windows inherited-pipe behavior has a regression test. Termination remains best effort: this is not a sandbox, and malicious escaped descendants are not proven absent.
- **Oracle architecture debt:** the signature, dependency and bounded Graph Ops findings in `specs/oracle-firewall-v1.ssat.yaml` are resolved. Its six-module QA remains grade C because `audit_metadata` and five Oracle Firewall functions exceed the unchanged hard complexity limit 10. These are separate remediation slices; no release gate was bypassed.
- **Complexity gate:** the Graph Ops coordinator now passes at complexity 10, down from 47. The wider Oracle contract still fails at maximum complexity 19 in `audit_metadata`, with five Oracle Firewall functions at 12 through 18. No limit was raised.
- **Spec drift tooling:** full-file SpecLine audit reports 25/48 passing units against the narrow new spec. Findings include existing values and numeric fragments in `utf-8` and `ipad_13`; this result needs precise scope/tool interpretation, not an invented claim of new behavioral drift or blanket suppression.
- **Windows test instability:** the initial full run ended with WinError 10053 in the Studio HTTP authorization test (1273 passed, 3 skipped, 1 failed). That exact test passed in isolation. A successful rerun does not establish the original failure's root cause.

The repair plan remains the ordered sequence below. This audit has not established exhaustive module coverage or absence of defects. No publication or production authorization follows from it.

## Unverified modules and next sequence

1. Assembly process output/termination and full proof-reuse hostile-input review.
2. Oracle authority constructors, verifier parity, exceptions and challenge paths.
3. Graph/loop lineage and current-candidate propagation; memory revocation propagation.
4. Enterprise identity, tenancy, signing, revocations and hosted adapters.
5. AppForge mobile evidence/submission/release-chain paths.
6. IDE/MCP/A2A surfaces, then separate SpecLine, ForgeLine, HSF and Prestige engine implementations.

The assembly registry contains four external engine adapters; those engines are not implemented entirely in this checkout.
Do not interpret a passing existing test suite as a source audit of those engines or every CF file.

## Assembly bounds verification

- Final regression: `python -m pytest -q` — **1292 passed, 3 skipped**, 182.31 seconds.
- `python -m pytest -q tests/test_assembly_process.py tests/test_assembly.py`: 17 passed, including real Windows subprocesses, both stream overflows, cancellation, deadline expiry, invalid deadlines, nonzero exit, malformed UTF-8, missing CLI, heartbeat failure and inherited pipes.
- SpecLine strict and three requirement mutants passed. Scoped drift audit: 5/5 functions passed.
- ForgeLine architecture and scoped QA passed; maximum complexity 9 against the unchanged hard limit 10. Empty-stub verification rejected the scaffold (one smoke check).
- Overall ForgeLine review remains blocked by `A_SUBPROC`. Its installed adversary implementation uses an unconditional substring check for `subprocess`; no exception was created or scanner disabled. This is a security-review flag, not evidence of shell injection. The runner uses argv, no shell and closed stdin.
- The first SSAT adoption found that ForgeLine expects only positional arguments in its signature list. The runner's keyword-only options remain implemented and tested; the SSAT positional signature was corrected. The initially missing smoke manifest was added and stub verification rerun successfully.
- No native POSIX execution, malicious process-escape proof or publication is claimed.

## Oracle projection follow-up

- Final regression: `python -m pytest -q` — **1300 passed, 3 skipped**, 189.08 seconds; `git diff --check` passed.
- The AppForge–Oracle authority projection now rejects non-object JSON and inputs over 1 MiB without aborting its snapshot. Before showing a READY receipt as current, it reconstructs that receipt from the original authority source and current sealed contract. Missing or changed sources are invalid, not current readiness.
- Extracted the authoritative-group check without removing any of its checks. Scoped ForgeLine review, architecture gate, stub rejection and smoke passed. Maximum complexity in `appforge_oracle.py` is now 10, within the unchanged limit. This is a scope-specific result, not the six-module Oracle review result.
- Targeted authority, submission-assurance and Graph Ops tests: 39 passed. New cases cover five non-object JSON values, two changed source paths and oversized input; the existing current-authority case still passes.
- SpecLine strict and two requirement mutants passed, spec hash `7b0139efdf4cf85b`; full-file drift audit passed after documenting the unchanged pre-existing text bounds and JSON indentation in the repair specification.
- Updated the original Oracle SSAT's positional signatures to match tested optional-output functions and the actual MCP `dispatch(request, root)` interface. Recorded existing local evidence-projection dependencies and the lazy license incident lookup. These edges confer no new execution authority; keyword-only arguments remain covered by behavioral tests.
- Rechecking the original SSAT no longer reports signature/dependency mismatches or a Graph Ops bounded-scope failure. Wider QA still fails only on Metadata and Oracle Firewall complexity findings; no scope or complexity limit was raised to hide them.

## Graph Ops bounded snapshot follow-up

- `graph_ops_snapshot` was reduced from a 300-line, complexity-47 coordinator to 70 lines at the existing hard complexity limit 10. Collection, fact mapping and marker decisions now live in deterministic private helpers; the public signature and receipt schema are unchanged.
- Focused regression: `python -m pytest -q tests/test_graph_ops.py` — **23 passed**. The Forge smoke manifest reruns this behavioral suite and is proven non-hollow by rejecting a stubbed implementation.
- Full regression after the refactor: `python -m pytest -q` — **1300 passed, 3 skipped** in 208.71 seconds.
- Scoped ForgeLine review: grade **A**, composite 100, coverage intent 1.0, security 100, and architecture gate passed. SpecLine strict validation passed and all 3 requirement mutations were killed.
- The original six-module Oracle QA now recognizes `graph_ops_snapshot` as passing. It remains grade C only because of the separately recorded Metadata and Oracle Firewall complexity debt.
- A full-file SpecLine drift scan remains unsuitable for this narrow refactor: it scans all 59 functions and reports pre-existing numeric and encoding literals outside the changed coordinator. That failure is retained as tooling/scope evidence, not suppressed or misreported as a passing gate.

## Operating procedure

Governance: human_controlled. For each next module: inspect constructors and consumers, reproduce a gap, seal the requirement, add negative and boundary tests, repair, verify, and commit. Do not publish, change credentials or run external engines merely to complete this register.

## Verification for the follow-up

- Final source: `python -m pytest -q` — **1279 passed, 3 skipped**, 182.53 seconds.
- `python -m pytest -q tests/test_oracle_firewall.py tests/test_appforge_submission_integrity.py` — **26 passed**.
- `specline strict oracle-audit-parity` — passed; `specline verify-validators oracle-audit-parity` — **3 requirement mutants killed**. Spec hash `a2996f81f32e136e`.
- Full-file drift and original Oracle SSAT/QA checks **failed**, as detailed above. No code/release gate was declared passed on their behalf. The first direct Forge review also encountered an invalid state transition; the subsequent explicit orchestration sequence surfaced the recorded contract/QA failures.
- `git diff --check` — passed. No deployment, native device test, external engine audit or marketplace submission performed.

## Earlier verification

- Full suite started with receipt hardening: 1258 passed, 3 skipped.
- After the proof-row fix, focused proof-reuse, receipt and runtime-surface suite: 30 passed.
- Combined proof-reuse and evaluator regression group: 57 passed.
- SpecLine strict, three requirement mutants and scoped integrity drift audit passed; ForgeLine scoped review, architecture, stub rejection and smoke passed.
- The full suite was not recollected after adding the ten proof-row tests. No production engines, external engine repositories, marketplace publication or deployment were exercised.
