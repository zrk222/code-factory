# Plan: enterprise-revocation-freshness-v1
Spec: specs/enterprise-revocation-freshness-v1.md (approved)
Architect verdict: PASS

## Logical decomposition

1. Validate the signed revocation snapshot's shape and bounded freshness.
2. Add strict verification flags while preserving optional historical mode.
3. Prove missing, stale, future, malformed, revoked, and current paths.
4. Document the distinction between checked-at-receipt-time and current evidence.

## Tasks

- [x] T1 | slice=specs | files=specs/enterprise-revocation-freshness-v1.md,specs/enterprise-revocation-freshness-v1.ssat.yaml | verify=`specline strict enterprise-revocation-freshness-v1 --root .` | Seal the strict revocation freshness contract.
- [x] T2 | slice=factoryline | files=factoryline/enterprise_receipts.py | verify=`py -3.11 -m pytest -q tests/test_enterprise_receipts.py` | Validate signed revocation shape and strict freshness without network authority.
- [x] T3 | slice=factoryline | files=factoryline/cli.py | verify=`py -3.11 -m factoryline.cli enterprise verify --help` | Expose strict revocation and maximum-age controls.
- [x] T4 | slice=tests | files=tests/test_enterprise_receipts.py | verify=`py -3.11 -m pytest -q tests/test_enterprise_receipts.py` | Prove strict required/current/stale/future/malformed and optional historical behavior.
- [x] T5 | slice=docs | files=docs/ENTERPRISE_RECEIPTS.md | verify=`git diff --check` | Explain freshness status and claims boundary.
- [x] T6 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`git diff --check` | Record strict freshness without changing release authority.
- [x] T7 | slice=smoke | files=smoke/enterprise-revocation-freshness-v1.json | verify=`forge verify-tests enterprise-revocation-freshness-v1 specs/enterprise-revocation-freshness-v1.ssat.yaml --root .` | Register a non-hollow strict freshness smoke check.
- [x] T8 | slice=context | files=context/PROGRESS.md | verify=`git diff --check` | Record final gates and evidence for handoff.
