# Plan: full-stack-ux-harness-v1
Spec: specs/full-stack-ux-harness-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Compile the attachment into a bounded contract and evidence verifier.
2. Make the reusable skill discoverable to agents and IDE/A2A workflows.
3. Add adversarial tests and validate package/repository integrity.

## Tasks (atomic - each independently shippable)

- [x] T1 | slice=factoryline | files=<=3 | verify=`python -m pytest -q tests/test_full_stack_ux_harness.py` | Add the manifest template, fail-closed evaluator, and CLI route.
- [x] T2 | slice=skills | files=<=4 | verify=`python C:/Users/rkatz/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/full-stack-ux-harness` | Add the repository-owned skill, concise operator guide, and IDE playbook trigger.
- [x] T3 | slice=integration | files=<=4 | verify=`python -m pytest -q tests/test_full_stack_ux_harness.py tests/test_adoption_guide.py tests/test_publication_metadata.py` | Route frontend changes through the harness and prove packaging plus existing metadata remain valid.
