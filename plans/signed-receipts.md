# Plan: signed-receipts
Spec: specs/signed-receipts.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Validate receipts and delegate signing and verification to Sigstore.
2. Expose a narrow CLI and optional dependency.
3. Prove the real GitHub OIDC path in CI and document the developer workflow.

## Tasks (atomic - each independently shippable)
- [x] T1 | slice=factoryline | files=factoryline/signed_receipts.py,tests/test_signed_receipts.py | verify=`python -m pytest -q tests/test_signed_receipts.py` | Implement receipt validation and Sigstore delegation
- [x] T2 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Add the optional Sigstore dependency
- [x] T3 | slice=factoryline | files=factoryline/cli.py,tests/test_signed_receipts.py | verify=`python -m pytest -q tests/test_signed_receipts.py` | Add `factory receipt sign` and `factory receipt verify`
- [x] T4 | slice=README.md | files=README.md | verify=`python -m pytest -q` | Add the signed-receipt quickstart
- [x] T5 | slice=.github | files=.github/workflows/signed-receipts.yml,tests/test_signed_receipts.py | verify=`python -m pytest -q` | Prove GitHub OIDC signing and verification
- [x] T6 | slice=docs | files=docs/SIGNED_RECEIPTS.md,tests/test_signed_receipts.py | verify=`python -m pytest -q` | Publish copy-paste signed-receipt guidance

## Release evidence

- Local: 62 tests passed; build and `twine check` passed; clean Python 3.11 wheel install with the Sigstore extra passed.
- CI: [signed-receipts run 29177856357](https://github.com/zrk222/code-factory/actions/runs/29177856357) verified the GitHub OIDC identity and rejected a one-byte receipt mutation.
- CI: [full run 29177856349](https://github.com/zrk222/code-factory/actions/runs/29177856349) passed the five-brick ProofLab and Python 3.10-3.12 matrix on Ubuntu, macOS, and Windows.
