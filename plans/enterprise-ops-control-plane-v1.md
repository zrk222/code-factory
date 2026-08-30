# Plan: enterprise-ops-control-plane-v1
Spec: specs/enterprise-ops-control-plane-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Implement a tenant-bound local operations store, identity lifecycle, and
   content-addressed evidence export.
2. Implement bounded proof execution with an explicit Docker isolation route
   and fail-closed process-boundary fallback.
3. Implement required-check evaluation, outcome telemetry, SLA readiness, and
   golden-path status.
4. Integrate the CLI, docs, and deterministic hostile tests.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=factoryline | files=factoryline/enterprise_ops.py | verify=`python -m pytest -q tests/test_enterprise_ops.py` | Implement the local evidence workspace, identity registry, and export contract.
- [x] T2 | slice=factoryline | files=factoryline/enterprise_ops.py | verify=`python -m pytest -q tests/test_enterprise_ops.py` | Implement Docker/process proof runner policy and bounded output/timeout behavior.
- [x] T3 | slice=factoryline | files=factoryline/enterprise_ops.py | verify=`python -m pytest -q tests/test_enterprise_ops.py` | Implement SDLC required checks, outcome hash-chain telemetry, SLA readiness, and golden status.
- [x] T4 | slice=factoryline/cli.py | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_enterprise_ops.py tests/test_factoryline.py` | Expose `factory ops` commands with stable JSON output and fail-closed exit codes.
- [x] T5 | slice=tests | files=tests/test_enterprise_ops.py | verify=`python -m pytest -q tests/test_enterprise_ops.py` | Prove tenant boundaries, inactive identities, runner refusal, tamper detection, required checks, and SLA gating.
- [x] T6 | slice=docs | files=docs/ENTERPRISE_OPERATIONS.md,docs/ENTERPRISE_1_0.md,docs/COMMERCIAL_PACKAGING.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document the seven implemented local/supervised slices and their hosted-service limits.
