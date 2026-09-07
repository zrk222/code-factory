# Plan: pre-deploy-release-hardening-v1
Spec: specs/pre-deploy-release-hardening-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Seal the candidate release contract and reject mixed-version artifacts.
2. Add scoped Codex metadata/ledger and state-to-receipt integrity checks.
3. Bind Windows children to a Job Object while suspended, before resume.
4. Wire the receipt into CLI/CI and prove deliberate mutations fail closed.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=release | files=<=4 | verify=`python -m pytest -q tests/test_release_candidate.py tests/test_release_integrity.py` | Implement exact source/version/commit contract binding and stale artifact rejection; wire publish preflight before external steps.
- [ ] T2 | slice=metadata | files=<=4 | verify=`python -m pytest -q tests/test_codex_metadata.py` | Add active/archive scope, ledger order/head drift, and `.forge` state/receipt lineage findings without promoting archival claims.
- [ ] T3 | slice=runtime | files=<=4 | verify=`python -m pytest -q tests/test_assembly_process.py` | Launch suspended on Windows, assign kill-on-close Job Object, resume only after binding, and fail closed on setup/resume errors.
- [ ] T4 | slice=verification | files=<=4 | verify=`python -m compileall -q factoryline tests scripts; python -m pytest -q tests/test_release_preflight_cli.py` | Expose deterministic machine-readable preflight and record the receipt/authority boundary; no provider action.
