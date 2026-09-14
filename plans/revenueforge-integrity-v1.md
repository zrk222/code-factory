# Plan: revenueforge-integrity-v1

Spec: `specs/revenueforge-integrity-v1.md`

Architect verdict: PASS

## Atomic tasks

- [x] T1 | slice=specs | files=specs/revenueforge-integrity-v1.md | verify=`specline strict revenueforge-integrity-v1 --root .` | Seal event, experiment, authority, privacy, and claim contracts.
- [x] T2 | slice=factoryline | files=factoryline/revenue_integrity.py | verify=`python -m pytest -q tests/test_revenue_integrity.py` | Implement idempotent billing reconciliation, experiment guardrails, integrity evaluation, and read-only projection.
- [x] T3 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_revenue_integrity_cli.py` | Expose bounded `billing-reconcile`, `experiment-plan`, and `integrity` commands.
- [x] T4 | slice=factoryline | files=factoryline/revenueforge.py | verify=`python -m pytest -q tests/test_revenueforge.py` | Project new integrity receipts without granting provider authority.
- [x] T5 | slice=tests | files=tests/test_revenue_integrity.py,tests/test_revenue_integrity_cli.py | verify=`python -m pytest -q tests/test_revenue_integrity.py tests/test_revenue_integrity_cli.py` | Challenge duplicate retries, conflicts, refunds, drift, approval separation, path safety, and receipt tampering.
- [x] T6 | slice=docs | files=docs/REVENUEFORGE.md | verify=`python -m pytest -q tests/test_revenueforge.py` | Document integrity receipts, command flow, and human authority boundaries.

## Release boundary

Provider writes, entitlement grants, price changes, experiment starts, winner
promotion, deployment, and credentials remain human-controlled.
