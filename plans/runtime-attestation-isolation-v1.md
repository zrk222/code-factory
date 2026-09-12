# Plan: runtime-attestation-isolation-v1

Spec: specs/runtime-attestation-isolation-v1.md
Architect verdict: PASS

## Logical decomposition

1. Define a narrow boundary contract above the existing six lanes.
2. Capture only facts the local supervisor can observe and classify them
   honestly as supervised-only.
3. Verify signed external boundary evidence offline and join it into the
   six-lane decision without changing release authority.
4. Exercise tampering, stale/replay, shell, backend, and composite-decision
   failures through tests and a ForgeLine smoke.

## Tasks (atomic)

- [x] T1 | slice=runtime-attestation | files=2 | verify=`py -3.11 -m pytest -q tests/test_runtime_attestation.py` | Implement bounded local capture, strict validation, signed external verification, and fail-closed boundary decisions.
- [x] T2 | slice=runtime-audit | files=4 | verify=`py -3.11 -m pytest -q tests/test_runtime_audit.py tests/test_runtime_audit_contract.py tests/test_runtime_audit_runner.py` | Bind optional runtime-boundary plans, capture the local receipt, and make a weak or missing boundary block the composite decision.
- [x] T3 | slice=surfaces | files=2 | verify=`py -3.11 -m pytest -q tests/test_senior_cli.py tests/test_runtime_audit_surfaces.py` | Expose signed boundary verification through the provider-neutral senior CLI and preserve read-only Mission status.
- [x] T4 | slice=proof | files=4 | verify=`forge verify-tests runtime-attestation-isolation-v1 specs/runtime-attestation-isolation-v1.ssat.yaml --root .` | Add the smoke, docs, and release notes; prove known weak boundaries cannot pass as independent isolation.

## Non-goals

No kernel/container sandbox, eBPF/sidecar enforcement, provider action,
credential access, automatic approval, or production readiness claim.
