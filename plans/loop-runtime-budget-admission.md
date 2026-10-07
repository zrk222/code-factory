# Plan: loop-runtime-budget-admission
Spec: specs/loop-runtime-budget-admission.md (strict PASS; authorized to proceed)
Architect verdict: REOPENED — specialty review of PR head `862f252` found two receipt-integrity gaps. Their fixes and fresh review are required before merge.

## Logical decomposition
1. Add a durable SQLite session/action ledger bound to the Loop Passport
   digest, with mutable projections and exact fixed-point usage accounting.
2. Add pre-action reservation, idempotent replay, settlement and live status
   projections while retaining post-run budget evaluation.
3. Expose the runtime operations inside the existing `factory loop` CLI group.
4. Exercise the full lifecycle and failure behavior; record hash-bound workflow
   evidence and verify quality, architecture and full regression gates.
5. Compile the deterministic HSF admission-state classifier at
   `specs/loop-runtime-budget-admission.yaml` against its seeded
   decision cases; it is an acceptance model only and never authorizes work.
6. Complete an independent specialty-agent review, resolve every finding, then
   seal the workflow evidence against the final candidate hashes.
7. Update the public preview/changelog, refresh the Meta Muse review status,
   and state whether this local CLI feature changes the hosted connector.

## Tasks (atomic)
- [x] T1 | slice=tests | files=tests/test_loop_passport.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | add failing tests for session replay/conflict, atomic check-and-reserve, exact projected usage, one unresolved action, restart persistence, settlement replay/conflict, CSPRNG ID validation/privacy, stale manifests, overrun and legacy compatibility.
- [x] T2 | slice=factoryline | files=factoryline/loop_passport.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | implement the SQLite transaction ledger, hashed caller IDs and runtime admission/settlement API; preserve the existing post-run budget receipt.
- [x] T3 | slice=tests | files=tests/test_loop_passport.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | add CLI-level tests for session start, action admission, settlement replay/conflict, status, failure exits and unchanged legacy budget command.
- [x] T4 | slice=factoryline | files=factoryline/cli_runtime_proof.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | expose runtime session commands inside the existing `factory loop` group without a new top-level command.
- [x] T5 | slice=.factory | files=.factory/workflow-audit-loop-runtime-budget-admission-contract.json | verify=`python -m factoryline.cli audit workflows --root . --contract .factory/workflow-audit-loop-runtime-budget-admission-contract.json --observations .factory/workflow-audit-loop-runtime-budget-admission-observations.json --json` | final source/test/spec/preview hashes and executable observations refreshed after two specialty AI reviewers found no remaining findings; GitHub Actions run 37416772610 passed the public seeded benchmark. This branch has no PR, so full CI was not run.
- [x] T6 | slice=docs | files=README.md, CHANGELOG.md | verify=`git diff --check` | 0.47.0 preview now states what was added and changed, runtime admission behavior, advisory-only HSF, enrolled-adapter scope, local-ledger limitations, and publication boundary.
- [x] T7 | slice=docs | files=docs/MCP_REGISTRY.md | verify=`read existing Muse portal record` | portal confirms the existing connector submission has 3/3 requirements in review; this CLI-only feature does not alter the hosted API, scopes, or data handling, so a duplicate submission would be inaccurate.
- [x] T8 | slice=factoryline+tests | files=factoryline/loop_passport.py,tests/test_loop_passport.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | reject incomplete version-1 session/action/receipt values as `INCOMPLETE`; verify aggregate receipt usage and limits against ordered ledger totals on status, admission replay and settlement replay.
- [x] T9 | slice=factoryline+tests | files=factoryline/review_audits.py,tests/test_review_audits.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_review_audits.py -q` | address user-reported weak oracles, no-op assertion helpers, aliases overwritten by assignment/pattern/exception captures, and undeclared Django/SQLAlchemy/SQLModel reads; keep the 26-snippet labels as regression inputs, not a benchmark accuracy claim.
- [ ] T10 | slice=proof | files=.factory/attribution-workflow-contract.json,.factory/attribution-workflow-observations.json | verify=`python -m factoryline.cli audit workflows --root . --contract .factory/attribution-workflow-contract.json --observations .factory/attribution-workflow-observations.json --json` | bind exact final changed-source/spec hashes and observations, then rerun architecture, candidate quality, full CI and specialty AI review on the final SHA.
- [x] T11 | slice=factoryline+tests | files=factoryline/review_audits.py,tests/test_review_audits.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_review_audits.py -q` | catch constant aliases, self-equality aliases, comparisons against a locally assigned constant, and always-true boolean assertions while retaining source-order reassignment behavior; treat the 7 new user-labeled variants as regression examples, not a precision/recall benchmark.

## Final review corrections
- The 2026-10-07 specialty review found and the T9 follow-up fixed false negatives for locally/module-rebound `pytest.raises` aliases, including source-order restoration after a later valid import; wildcard imports directly and inside branches; helper functions that rebound that alias; unused failure callbacks; and identical repeated-call comparisons. Nested helper/comprehension bindings remain scoped and do not invalidate an outer test alias. Regressions are covered in `tests/test_review_audits.py`; the current focused audit suite passes 125 tests. The prior combined audit/architecture/taxonomy run passed 177 tests before these final regression cases were added.
- The additional 7 user-labeled variants are regression inputs only. T11 adds conservative source-order constant propagation for direct test-body assignments and recognizes always-true boolean assertions without executing candidate code; assignments in branches invalidate known constants. A passing scan on these examples is not a measured precision or recall claim.
- Specialty security review caught and prevented a false positive from treating Python `and`/`or` results as booleans; evaluation now preserves operand-returning short-circuit semantics and uses a separate guaranteed-truth check. The final focused suite passes 137 tests; independent specialty review passed the exact final source/test hashes.
- Corrupt JSON, incomplete fixed-point values, missing or contradictory receipts,
  mismatched action/request/settlement hashes, and inconsistent overrun markers
  or settlement status versus actual aggregate totals all return `INCOMPLETE`
  instead of escaping as exceptions or replaying a misleading receipt.
- The obsolete generated HSF artifact that returned `ADMITTED` was removed;
  the current compiled classifier returns advisory states only. Extraction
  fallback is covered by a focused test, not claimed as a golden case.
- The prior specialty recheck covered an earlier candidate; it is superseded by
  findings at `862f252` and cannot approve later changes. T8-T10 remain open
  until tests, full CI, exact-SHA specialty review and protected status are current.

## Safety boundaries
- This module governs only adapters that call it before operations; unintegrated
  tools and provider-side billing remain outside its enforcement scope.
- No arbitrary process execution, model invocation, provider write, merge or
  release is added.
- Missing usage, database errors, changed manifests and stale sessions fail
  closed; reservation estimates are never silently refunded.
- Only one action may be unresolved per run; an unresolved action remains
  budgeted across restart and blocks admission until idempotent settlement.
