# Plan: deep-audit-attestation-v1

Spec: specs/deep-audit-attestation-v1.md
Architect verdict: PASS

- [x] T1 | slice=specs | files=specs/deep-audit-attestation-v1.md,specs/deep-audit-attestation-v1.ssat.yaml | verify=`specline strict deep-audit-attestation-v1 --root . && specline verify-validators deep-audit-attestation-v1 --root .` | Seal signer, freshness, coverage, and no-authority requirements before code.
- [x] T2 | slice=factoryline | files=factoryline/deep_audit_attestation.py | verify=`py -3.11 -m pytest -q tests/test_deep_audit_attestation.py` | Verify a signed attestation against the exact receipt and pinned trust root with bounded freshness and independent-verifier checks.
- [x] T3 | slice=factoryline | files=factoryline/deep_audit_loop.py,factoryline/cli.py | verify=`py -3.11 -m pytest -q tests/test_deep_audit_attestation.py tests/test_deep_audit_loop.py` | Add optional strict attestation requirements to repair comparison while preserving legacy non-strict compatibility.
- [x] T4 | slice=tests | files=tests/test_deep_audit_attestation.py,tests/test_deep_audit_loop.py | verify=`py -3.11 -m pytest -q tests/test_deep_audit_attestation.py tests/test_deep_audit_loop.py` | Kill signature, digest, coverage, independence, freshness, and missing-attestation mutants.
- [x] T5 | slice=docs | files=docs/DEEP_AUDIT_DECISIONS.md,docs/DEEP_AUDIT_LOOP_VERIFICATION.md,docs/OVERVIEW.md | verify=`git diff --check` | Explain signed evidence, strict comparison, and the review-only claim boundary.
- [x] T6 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`git diff --check` | Record the attestation and freshness gate in the release history.
- [x] T7 | slice=smoke | files=smoke/deep-audit-attestation-v1.json | verify=`python -m pytest -q tests/test_deep_audit_attestation.py tests/test_deep_audit_loop.py` | Register deterministic attestation markers and the no-authority boundary.
- [x] T8 | slice=context | files=context/PROGRESS.md | verify=`git diff --check` | Record the sealed plan and implementation receipts for the handoff.

## Explicit non-goals

- No analyzer execution, automatic repair, provider interaction, publication,
  deployment, merge, approval, or credential handling.


## Executable audit extension (owner-authorized)

- [x] E1 | slice=factoryline | files=factoryline/deep_audit_io.py,factoryline/deep_audit_contract.py | verify=`python -m pytest -q tests/test_deep_audit_contract.py` | Bind full inventory and pinned execution contracts.
- [ ] E2 | slice=factoryline | files=factoryline/deep_audit.py,factoryline/deep_audit_sarif.py | verify=`python -m pytest -q tests/test_deep_audit_loop.py tests/test_deep_audit_sarif.py` | Run isolated adapters and retain progress, challenges and resolution evidence.
- [ ] E3 | slice=factoryline | files=factoryline/deep_audit_attestation.py,factoryline/cli_deep_audit.py | verify=`python -m pytest -q tests/test_deep_audit_attestation.py tests/test_deep_audit_surfaces.py` | Authenticate reviewer origin and expose execution/status/cancel APIs.
- [ ] E4 | slice=plugins | files=plugins/muse-code-factory-audit/hooks/audit.mjs,docs/DEEP_AUDIT_DECISIONS.md | verify=`python -m pytest -q tests/test_langchain_plugin.py` | Integrate current run evidence while preserving missing coverage and authority boundaries.

Execution coordinator implementation and synthetic regression coverage are present.
E2-E4 remain open for real adapter integration, final specialty re-review, and
validated end-to-end evidence. Do not mark them complete from synthetic tests.
