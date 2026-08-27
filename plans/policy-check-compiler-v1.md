# Plan: policy-check-compiler-v1
Spec: specs/policy-check-compiler-v1.md
Architect verdict: PASS

## Logical decomposition
1. Implement canonical policy loading, rule mapping, review-needed reporting,
   and an atomic workspace-contained writer.
2. Integrate the compiler into `factory ops policy` with stable JSON and exit
   codes.
3. Add hostile tests and a non-hollow smoke manifest.
4. Document the workflow and run focused plus full regression gates.

## Tasks (atomic — each independently shippable)
- [x] T1 | slice=factoryline | files=factoryline/policy_compiler.py | verify=`python -m pytest -q tests/test_policy_compiler.py` | Compile versioned policies deterministically and fail closed on unknown or malformed rules.
- [x] T2 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_policy_compiler.py tests/test_enterprise_ops.py` | Expose the workspace-contained `factory ops policy` command.
- [x] T3 | slice=tests | files=tests/test_policy_compiler.py | verify=`python -m pytest -q tests/test_policy_compiler.py` | Prove key-order invariance, hash binding, path containment, review-needed output, and CLI read-back.
- [x] T4 | slice=docs | files=docs/ENTERPRISE_OPERATIONS.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document the deterministic compiler and its authority boundary.
