# Plan: E2E Proof Gate

Spec: `specs/e2e-proof-gate.md`
Architect verdict: PASS

## Tasks

- [x] T1 | slice=factoryline | files=factoryline/e2e_proof.py | verify=`python -m pytest -q tests/test_e2e_proof.py` | Add strict manifest validation, bounded `shell=False` execution, capture hashing, and receipt compilation.
- [x] T2 | slice=tests | files=tests/test_e2e_proof.py | verify=`python -m pytest -q tests/test_e2e_proof.py` | Add passing, hollow, positive-failure, timeout, missing-artifact, malformed-command, and no-write rejection tests.
- [x] T3 | slice=factoryline | files=factoryline/cli.py | verify=`factory e2e verify --help` | Wire JSON-safe CLI output and explicit non-zero validation errors. The existing monolithic dispatcher remains an integration seam; the new E2E module is the SSAT-scoped architecture unit.
- [x] T4 | slice=docs | files=docs/E2E_PROOF_GATE.md,docs/OVERVIEW.md | verify=`specline validate e2e-proof-gate --root .` | Publish the command manifest, security boundary, and exact scope limits.
- [x] T5 | slice=README.md | files=README.md | verify=`rg -n "factory e2e verify" README.md` | Add the native E2E proof use case to the public quick-start table.
- [x] T6 | slice=smoke | files=smoke/e2e-proof-gate.json | verify=`forge smoke e2e-proof-gate --root .` | Bind passing command-pair behavior to a reverse-classical smoke receipt.

## Release gate

Run focused tests, full `pytest -q`, SpecLine validation/mutation checks,
ForgeLine architecture checks, package build, and clean wheel smoke before a
public release is proposed.
