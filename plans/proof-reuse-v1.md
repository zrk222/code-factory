# Plan: proof-reuse-v1
Spec: specs/proof-reuse-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Seal content-addressed key and fail-closed disposition semantics.
2. Implement private proof receipts, verification, routing, mutation challenge, and automatic paired savings.
3. Expose CLI, docs, AKU, and CI trigger deduplication.
4. Prove privacy, authority, mutation, compatibility, and packaging behavior.
5. Synchronize and publish version 0.23.0.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/proof_reuse.py,tests/test_proof_reuse.py | verify=`python -m pytest -q tests/test_proof_reuse.py` | Implement proof keys, private receipts, verification, and RUN/REUSE/SKIP/BLOCK routing.
- [ ] T2 | slice=factoryline | files=factoryline/proof_reuse.py,factoryline/savings.py,tests/test_proof_reuse.py | verify=`python -m pytest -q tests/test_proof_reuse.py tests/test_savings.py` | Add exact automatic paired savings for verified reuse and preserve unknown tokens.
- [ ] T3 | slice=factoryline | files=factoryline/proof_reuse.py,factoryline/cli.py,tests/test_proof_reuse.py | verify=`python -m pytest -q tests/test_proof_reuse.py tests/test_factoryline.py` | Add proofs record, plan, verify, and challenge CLI commands.
- [ ] T4 | slice=.github | files=.github/workflows/intellij-plugin.yml,tests/test_jetbrains_release_artifact.py | verify=`python -m pytest -q tests/test_jetbrains_release_artifact.py` | Restrict push runs to main and add SHA-keyed concurrency cancellation.
- [ ] T5 | slice=docs | files=docs/PROOF_REUSE.md,docs/RELEASE_NOTES_0.23.0.md | verify=`python -m pytest -q tests/test_proof_reuse.py tests/test_publication_metadata.py` | Document governance, CLI, exact savings, and release behavior.
- [ ] T5a | slice=adr | files=adr/proof-reuse-v1.md | verify=`forge arch-gate proof-reuse-v1 specs/proof-reuse-v1.ssat.yaml --root .` | Record the proof reuse authority boundary.
- [ ] T5b | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the public quick-start.
- [ ] T5c | slice=AKU_STANDARD.md | files=AKU_STANDARD.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the supervised proof-router AKU.
- [ ] T6 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Synchronize package version 0.23.0.
- [ ] T6a | slice=factoryline | files=factoryline/__init__.py | verify=`python -m pytest -q tests/test_factoryline.py` | Synchronize runtime version 0.23.0.
- [ ] T6b | slice=tests | files=tests/test_publication_metadata.py,tests/test_huggingface_surface.py | verify=`python -m pytest -q tests/test_publication_metadata.py tests/test_huggingface_surface.py` | Enforce public version synchronization.
- [ ] T7 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`python -m build` | Record the v0.23.0 changelog.
- [ ] T7a | slice=CITATION.cff | files=CITATION.cff | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize citation metadata.
- [ ] T7b | slice=.zenodo.json | files=.zenodo.json | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize archive metadata.
- [ ] T8 | slice=deploy | files=deploy/huggingface/README.md,deploy/huggingface/index.html,deploy/hosted/README.md | verify=`python -m pytest -q tests/test_huggingface_surface.py` | Synchronize hosted surfaces.
- [ ] T8a | slice=. | files=LAUNCH_KIT.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize the launch surface.
