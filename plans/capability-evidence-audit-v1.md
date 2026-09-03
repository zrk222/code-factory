# Plan: capability-evidence-audit-v1
Spec: specs/capability-evidence-audit-v1.md
Architect verdict: PASS

## Tasks
- [x] T1 | slice=factoryline | files=factoryline/capability_evidence.py | verify=`python -m pytest -q tests/test_capability_evidence.py` | Implement bounded manifest, hash, and argv execution validation.
- [x] T2 | slice=tests | files=tests/test_capability_evidence.py | verify=`python -m pytest -q tests/test_capability_evidence.py` | Prove structural, execution, path, hollow-file, and nonzero-command behavior.
- [x] T3 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_capability_evidence.py` | Add the evidence-audit command with stable exit behavior.
- [x] T4 | slice=evidence | files=evidence/capability-evidence.json | verify=`python -m pytest -q tests/test_capability_evidence.py` | Bind the four public maturity classes to implementation and tests.
- [x] T5 | slice=docs | files=docs/CAPABILITY_EVIDENCE.md | verify=`python -m pytest -q tests/test_adoption_guide.py` | Explain structural binding versus executed local evidence.
- [x] T6 | slice=specs | files=specs/capability-evidence-audit-v1.ssat.yaml | verify=`forge arch-gate capability-evidence-audit-v1 specs/capability-evidence-audit-v1.ssat.yaml --root .` | Make the feature architecture executable.
- [x] T7 | slice=smoke | files=smoke/capability-evidence-audit-v1.json | verify=`forge verify-tests capability-evidence-audit-v1 specs/capability-evidence-audit-v1.ssat.yaml --root .` | Make the anti-hollow smoke executable.

## Non-goals
- No external customer validation, hosted-service certification, release approval, provider action, or claim that local tests prove independent battle-testing.
