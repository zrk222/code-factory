# Plan: workspace-defect-policy-v1
Spec: specs/workspace-defect-policy-v1.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/primitive_observation_binding.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k workspace_policy319 -q` | Share native policy decision semantics without authorizing serialized reports.
- [ ] T2 | slice=factoryline | files=factoryline/deep_audit_io.py,tests/test_deep_audit.py | verify=`python -m pytest tests/test_deep_audit.py -k workspace_policy319 -q` | Bind selection to current native workspace generation and checkpoint configuration; preserve legacy behavior.
- [ ] T3 | slice=factoryline | files=factoryline/cli_audit.py,tests/test_cli_bootstrap.py | verify=`python -m pytest tests/test_cli_bootstrap.py -k workspace_policy319 -q` | Use the same decision in JSON, text and exit behavior; retain isolated scope rejection.

## Architecture decision
Use existing native workspace partition, inventory verification and model identity. Selection enters checkpoint configuration before reading saved rows. Decision generation stays inside the native scan; a supplied JSON decision is never consumed as authority. Reuse central decision construction from bounded admission. No new production module or dependency. Qualification includes pending/error/forgery/default/checkpoint-switch controls. Original accuracy target remains unmet until independently labeled measurement qualifies.
