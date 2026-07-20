# Plan: hosted-control-plane-v1
Spec: specs/hosted-control-plane-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Seal tenant lifecycle, authority, secret-reference, callback, audit, and console contracts.
2. Add PostgreSQL control storage and dynamic identity/secret boundaries.
3. Extend the hosted service and WSGI routes without granting the console mutation authority.
4. Prove hostile, concurrent, PostgreSQL, redaction, and responsive-console behavior.
5. Publish bounded deployment guidance and receipt-backed workflow evidence.

## Tasks (atomic; each independently shippable)
- [x] T1 | slice=specs | files=specs/hosted-control-plane-v1.md,specs/hosted-control-plane-v1.ssat.yaml | verify=`specline strict hosted-control-plane-v1 --root .` | Seal functional, authority, data, and non-goal contracts.
- [x] T2 | slice=plans | files=plans/hosted-control-plane-v1.md | verify=`specline tasks hosted-control-plane-v1 --root .` | Seal independently verifiable task packets.
- [x] T3 | slice=factoryline | files=factoryline/hosted_control.py | verify=`python -m pytest -q tests/test_hosted_control.py` | Implement tenant lifecycle validation, secret references, and PostgreSQL control store.
- [x] T4 | slice=factoryline | files=factoryline/hosted_api.py,factoryline/hosted_identity.py | verify=`python -m pytest -q tests/test_hosted_control.py tests/test_hosted_adapter.py` | Compose dynamic tenant identity, secret resolution, administrative routes, and callback authority.
- [x] T5 | slice=factoryline | files=factoryline/hosted_console.html | verify=`python -m pytest -q tests/test_hosted_console.py` | Build the read-only responsive operator console.
- [x] T6 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Package the operator console asset.
- [x] T7 | slice=tests | files=tests/test_hosted_control.py,tests/test_hosted_console.py,tests/test_hosted_postgres.py | verify=`python -m pytest -q tests/test_hosted_control.py tests/test_hosted_console.py tests/test_hosted_postgres.py` | Prove hostile API, replay, redaction, console, and PostgreSQL behavior.
- [x] T8 | slice=.github | files=.github/workflows/hosted-adapter.yml | verify=`python -m pytest -q tests/test_publication_metadata.py` | Run control-plane integration against PostgreSQL in CI.
- [x] T9 | slice=docs | files=docs/HOSTED_CONTROL_PLANE.md,docs/HOSTED_PR_ASSURANCE.md | verify=`python -m pytest -q tests/test_hosted_console.py` | Document onboarding, authority, and evidence limits.
- [x] T10 | slice=deploy | files=deploy/hosted/README.md | verify=`python -m pytest -q tests/test_hosted_console.py` | Document the bounded deployment path.
- [x] T11 | slice=smoke | files=smoke/hosted-control-plane-v1.json | verify=`forge smoke hosted-control-plane-v1 --root .` | Bind runtime and hostile checks to a smoke receipt.
- [x] T12 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the bounded v0.19 public entry point.
- [x] T13 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Record the v0.19 control-plane behavior and limits.
- [x] T14 | slice=.zenodo.json | files=.zenodo.json | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize archival metadata.
- [x] T15 | slice=CITATION.cff | files=CITATION.cff | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize citation metadata.
