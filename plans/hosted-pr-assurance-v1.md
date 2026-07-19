# Plan: hosted-pr-assurance-v1
Spec: specs/hosted-pr-assurance-v1.md
Architect verdict: PASS

## Logical decomposition
1. Seal hosted trust, data, and external-authority contracts.
2. Implement PostgreSQL, JWKS, GitHub App, and HTTP adapters behind interfaces.
3. Prove hostile behavior locally and real PostgreSQL behavior in CI.
4. Package and document a bounded container deployment.

## Tasks
- [x] T1 | slice=specs | files=specs/hosted-pr-assurance-v1.md,specs/hosted-pr-assurance-v1.ssat.yaml | verify=`specline strict hosted-pr-assurance-v1 --root .` | Seal hosted contract.
- [x] T2 | slice=plans | files=plans/hosted-pr-assurance-v1.md | verify=`specline tasks hosted-pr-assurance-v1 --root .` | Seal atomic packets.
- [x] T3 | slice=factoryline | files=factoryline/hosted_storage.py | verify=`python -m pytest -q tests/test_hosted_adapter.py` | Implement PostgreSQL RLS and transactional outbox store.
- [x] T4 | slice=factoryline | files=factoryline/hosted_identity.py,factoryline/hosted_github.py | verify=`python -m pytest -q tests/test_hosted_adapter.py` | Implement bounded JWKS and GitHub App clients.
- [x] T5 | slice=factoryline | files=factoryline/hosted_api.py | verify=`python -m pytest -q tests/test_hosted_adapter.py` | Implement WSGI routes and worker service.
- [x] T6 | slice=tests | files=tests/test_hosted_adapter.py,tests/test_hosted_postgres.py | verify=`python -m pytest -q tests/test_hosted_adapter.py tests/test_hosted_postgres.py` | Prove hostile and PostgreSQL paths.
- [x] T7 | slice=.github | files=.github/workflows/hosted-adapter.yml | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add PostgreSQL integration CI.
- [x] T8 | slice=deploy | files=deploy/hosted/Dockerfile,deploy/hosted/README.md | verify=`python -m build` | Package deployment reference.
- [x] T9 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Publish optional hosted dependencies.
- [x] T10 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the public hosted entry point.
- [x] T11 | slice=docs | files=docs/HOSTED_PR_ASSURANCE.md | verify=`python -m pytest -q tests/test_hosted_adapter.py` | Document deployment and limits.
- [x] T12 | slice=smoke | files=smoke/hosted-pr-assurance-v1.json | verify=`forge smoke hosted-pr-assurance-v1 --root .` | Bind hostile checks to receipt.
