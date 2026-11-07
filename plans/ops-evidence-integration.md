# Plan: ops-evidence-integration
Spec: specs/ops-evidence-integration.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Compose pre-PR evidence using existing scheduling, replay, oracle and verification tools.
2. Bind repair rounds to previous source-bound receipts and stop repeated non-progress.
3. Package reviewed incidents as exposed regression inputs for existing replay tools.
4. Wire CLI entry points, run positive/adversarial checks, and record source-bound workflow evidence.

## Tasks (atomic)
- [x] T1 | slice=factoryline | files=factoryline/incremental_scheduler.py,tests/test_change_review.py | verify=`python -m pytest tests/test_change_review.py -q` | Compose current pre-PR evidence and reject incomplete obligations.
- [x] T2 | slice=factoryline | files=factoryline/fix_workflow.py,tests/test_continuation.py | verify=`python -m pytest tests/test_continuation.py -q` | Verify repair histories and implement round and no-progress decisions.
- [x] T3 | slice=factoryline | files=factoryline/senior_assurance.py,tests/test_senior_assurance.py | verify=`python -m pytest tests/test_senior_assurance.py -q` | Generate source-bound exposed incident regression packets.
- [x] T4 | slice=factoryline | files=factoryline/cli_deep_audit.py,factoryline/cli_evidence_chain.py,tests/test_change_review.py | verify=`python -m pytest tests/test_change_review.py -q` | Expose integrations and verify CLI outcome parity.
