# Plan: loop-runtime-budget-admission
Spec: specs/loop-runtime-budget-admission.md (strict PASS; authorized to proceed)
Architect verdict: NEEDS REWORK (specialty AI review found two fail-closed evidence gaps; implementation fixes are in place and a fresh hash-bound review is pending)

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

## Tasks (atomic)
- [x] T1 | slice=tests | files=tests/test_loop_passport.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | add failing tests for session replay/conflict, atomic check-and-reserve, exact projected usage, one unresolved action, restart persistence, settlement replay/conflict, CSPRNG ID validation/privacy, stale manifests, overrun and legacy compatibility.
- [x] T2 | slice=factoryline | files=factoryline/loop_passport.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | implement the SQLite transaction ledger, hashed caller IDs and runtime admission/settlement API; preserve the existing post-run budget receipt.
- [x] T3 | slice=tests | files=tests/test_loop_passport.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | add CLI-level tests for session start, action admission, settlement replay/conflict, status, failure exits and unchanged legacy budget command.
- [x] T4 | slice=factoryline | files=factoryline/cli_runtime_proof.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_loop_passport.py -q` | expose runtime session commands inside the existing `factory loop` group without a new top-level command.
- [ ] T5 | slice=.factory | files=.factory/workflow-audit-loop-runtime-budget-admission-contract.json | verify=`python -m factoryline.cli audit workflows --root . --contract .factory/workflow-audit-loop-runtime-budget-admission-contract.json --observations .factory/workflow-audit-loop-runtime-budget-admission-observations.json --json` | refresh receipts only after final checks and specialty AI review; earlier evidence is stale after candidate edits and cannot be used as completion proof.

## Safety boundaries
- This module governs only adapters that call it before operations; unintegrated
  tools and provider-side billing remain outside its enforcement scope.
- No arbitrary process execution, model invocation, provider write, merge or
  release is added.
- Missing usage, database errors, changed manifests and stale sessions fail
  closed; reservation estimates are never silently refunded.
- Only one action may be unresolved per run; an unresolved action remains
  budgeted across restart and blocks admission until idempotent settlement.
