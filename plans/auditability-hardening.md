# Plan: auditability-hardening
Spec: specs/auditability-hardening.md (approved)
Architect verdict: PASS

## Logical decomposition (phases)

1. Seal the auditability and scope contract.
2. Add the offline receipt mutation gate and CLI receipt.
3. Prove canonicalization properties and classified invalid inputs.
4. Raise public API docstring coverage to the enforceable contract.
5. Add adversarial Studio and migration verification tests and minimal fixes.
6. Re-run full cross-surface, package, architecture, and factory evidence gates.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=specs | files=specs/auditability-hardening.md,specs/auditability-hardening.ssat.yaml | verify=`specline strict auditability-hardening --root .` | Gate the A-grade auditability and explicit non-enterprise scope contract
- [ ] T2 | slice=plans | files=plans/auditability-hardening.md | verify=`specline tasks auditability-hardening --root .` | Seal atomic implementation packets
- [ ] T3 | slice=factoryline | files=factoryline/receipt_challenge.py | verify=`python -m pytest -q tests/test_receipt_challenge.py` | Implement the offline DSSE receipt mutation gate and canonical receipt
- [ ] T4 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_receipt_challenge.py tests/test_enterprise_receipts.py` | Expose factory verify-receipts with structured exit semantics
- [ ] T5 | slice=tests | files=tests/test_receipt_challenge.py | verify=`python -m pytest -q tests/test_receipt_challenge.py` | Prove the gate kills every declared receipt mutation
- [ ] T6 | slice=factoryline | files=factoryline/enterprise_receipts.py | verify=`python -m pytest -q tests/test_enterprise_receipts.py tests/test_canonical_properties.py` | Classify Unicode encoding failures as E_INVALID_PAYLOAD
- [ ] T7 | slice=tests | files=tests/test_canonical_properties.py | verify=`python -m pytest -q tests/test_canonical_properties.py` | Add bounded Hypothesis round-trip, order, Unicode, and invalid-input properties
- [ ] T8 | slice=factoryline | files=factoryline/app_builder.py,factoryline/assurance.py,factoryline/attribution.py,factoryline/boundary.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public construction, assurance, attribution, and boundary APIs
- [ ] T9 | slice=factoryline | files=factoryline/capability_packs.py,factoryline/challenge.py,factoryline/cli.py,factoryline/compliance.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public pack, challenge, CLI, and compliance APIs
- [ ] T10 | slice=factoryline | files=factoryline/control_plane.py,factoryline/enterprise_receipts.py,factoryline/integrations.py,factoryline/loop_passport.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public control, receipt, integration, and loop APIs with refusal semantics
- [ ] T11 | slice=factoryline | files=factoryline/meter.py,factoryline/migration.py,factoryline/operations.py,factoryline/optimizer.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public measurement, migration, operations, and optimization APIs
- [ ] T12 | slice=factoryline | files=factoryline/passport.py,factoryline/privacy.py,factoryline/proof.py,factoryline/protocol.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public passport, privacy, proof, and protocol APIs
- [ ] T13 | slice=factoryline | files=factoryline/refinement.py,factoryline/signal_loop.py,factoryline/signed_receipts.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public refinement, signal-loop, and signing APIs with fail-closed semantics
- [ ] T14 | slice=tests | files=tests/test_public_docstrings.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Enforce meaningful docstrings for every public function and method
- [ ] T15 | slice=tests | files=tests/test_studio.py | verify=`python -m pytest -q tests/test_studio.py` | Prove wrong-token, escaped-path, and replayed Studio decision POSTs fail closed
- [ ] T16 | slice=factoryline | files=factoryline/migration.py,tests/test_migration.py | verify=`python -m pytest -q tests/test_migration.py` | Return structured invalid migration/context verdicts and test hostile evidence inputs
- [ ] T17 | slice=tests | files=tests/test_signed_receipts.py | verify=`python -m pytest -q tests/test_signed_receipts.py` | Preserve the existing OIDC identity-pinned Sigstore CI path without duplication
- [ ] T18 | slice=smoke | files=smoke/auditability-hardening.json | verify=`forge smoke auditability-hardening --root .` | Bind receipt mutation, docstring, Studio, and migration proof to one smoke receipt
- [ ] T19 | slice=factoryline | files=factoryline/contract.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public receipt contract serialization APIs
- [ ] T20 | slice=factoryline | files=factoryline/overrides.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public override and CI template APIs
- [ ] T21 | slice=factoryline | files=factoryline/provenance.py | verify=`python -m pytest -q tests/test_public_docstrings.py` | Document public build provenance API and unknown-identity boundary
- [ ] T22 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m pytest -q tests/test_canonical_properties.py` | Add Hypothesis to the development test dependency set used by the standard CI matrix
