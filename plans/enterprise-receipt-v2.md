# Plan: enterprise-receipt-v2
Spec: specs/enterprise-receipt-v2.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Define canonical Receipt v2, DSSE PAE, trust root, policy bundle, and
   revocation schemas.
2. Implement offline Ed25519 signing and verification with fail-closed errors.
3. Expose CLI commands and retain the v1 Sigstore compatibility path.
4. Add mutation tests, fixtures, documentation, and CI evidence.

## Tasks (atomic - each independently shippable)
- [x] T1 | slice=factoryline | files=factoryline/enterprise_receipts.py,tests/test_enterprise_receipts.py | verify=`python -m pytest -q tests/test_enterprise_receipts.py` | Implement canonical DSSE envelopes and Receipt v2 validation
- [x] T2 | slice=factoryline | files=factoryline/enterprise_receipts.py,tests/test_enterprise_receipts.py | verify=`python -m pytest -q tests/test_enterprise_receipts.py` | Implement Ed25519 identity signing, trust roots, and offline verification
- [x] T3 | slice=factoryline | files=factoryline/enterprise_receipts.py,tests/test_enterprise_receipts.py | verify=`python -m pytest -q tests/test_enterprise_receipts.py` | Implement signed policy bundles and signed revocation lists
- [x] T4 | slice=factoryline | files=factoryline/cli.py,tests/test_enterprise_receipts.py | verify=`python -m pytest -q tests/test_enterprise_receipts.py` | Add enterprise receipt, policy, and revocation commands
- [x] T5 | slice=docs | files=docs/ENTERPRISE_RECEIPTS.md | verify=`python -m pytest -q` | Document offline verification and scope boundaries
- [x] T6 | slice=README.md | files=README.md | verify=`python -m pytest -q` | Add the enterprise foundation quickstart and scope note
- [x] T7 | slice=.github | files=.github/workflows/enterprise-receipts.yml,tests/test_enterprise_receipts.py | verify=`python -m pytest -q` | Prove offline signing, verification, mutation rejection, and no network dependency

## Local evidence

- `python -m pytest -q tests/test_enterprise_receipts.py`: 11 passed.
- `python -m pytest -q`: 73 passed.
- SSAT erosion check: 0 violations.
- `python -m build` and `twine check` passed for the 0.10.0 wheel and sdist.
- CI: [enterprise-receipts run 29190146673](https://github.com/zrk222/code-factory/actions/runs/29190146673) passed the dedicated optional-extra workflow.
- CI: [main run 29190146684](https://github.com/zrk222/code-factory/actions/runs/29190146684) passed the nine-platform matrix and five-brick ProofLab after the enterprise extra was added to the matrix.
- CI: [signed-receipts run 29190146682](https://github.com/zrk222/code-factory/actions/runs/29190146682) passed the existing OIDC signing and tamper challenge.
