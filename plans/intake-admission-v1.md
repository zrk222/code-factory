# Plan: intake-admission-v1

Spec: specs/intake-admission-v1.md
Architect verdict: PASS

- [x] T1 | slice=specs | files=specs/intake-admission-v1.md,specs/intake-admission-v1.ssat.yaml | verify=`specline strict intake-admission-v1 --root . && specline verify-validators intake-admission-v1 --root .` | Define digest-bound compatibility, strict mode, and checkpoint-fix guardrails; kill requirement deletion/inversion mutants.
- [x] T2 | slice=factoryline | files=factoryline/intake_parameters.py,factoryline/runtime_audit_contract.py,factoryline/runtime_audit.py | verify=`py -3.11 -m pytest -q tests/test_intake_admission.py tests/test_runtime_audit_contract.py` | Verify authoritative intake binding across signed runtime plans and retain the digest in runtime receipts.
- [x] T3 | slice=factoryline | files=factoryline/run_admission.py,factoryline/cli.py | verify=`py -3.11 -m pytest -q tests/test_run_admission.py` | Bind external-agent admission and permit only named, hash-bound checkpoint-fix allowances.
- [x] T4 | slice=factoryline | files=factoryline/agent_proof_bridge.py,factoryline/proof_review_workflow.py,factoryline/release_candidate.py | verify=`py -3.11 -m pytest -q tests/test_agent_proof_bridge.py tests/test_proof_review_workflow.py tests/test_release_candidate.py` | Revalidate agent handoffs, Proof Review, and release preflight against the same intake envelope.
- [x] T5 | slice=docs | files=docs/INTENT_BOUND_ADMISSION.md | verify=`git diff --check` | Document the proof chain, recovery codes, and no-authority checkpoint boundary.
- [x] T6 | slice=smoke | files=smoke/intake-admission-v1.json | verify=`python -m pytest -q tests/test_intake_admission.py tests/test_runtime_audit_contract.py tests/test_run_admission.py tests/test_proof_review_workflow.py` | Register the non-hollow strict-admission smoke gate, including checkpoint-fix boundary evidence.

## Explicit non-goals

- No automatic patch application or agent execution.
- No provider, credential, network, publication, deployment, merge, or approval action.
