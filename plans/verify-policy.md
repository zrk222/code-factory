# Plan: verify-policy

Spec: specs/verify-policy.md

- [x] T1 | slice=assurance | files=factoryline/assurance.py | verify=`python -m pytest -q tests/test_assurance.py` | Mutate explicit rules and nested boolean policy settings
- [x] T2 | slice=assurance | files=factoryline/assurance.py | verify=`python -m pytest -q tests/test_assurance.py` | Run baseline and mutation evaluator commands without shell execution
- [x] T3 | slice=cli | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_assurance.py` | Add receipted `factory verify-policy`
- [x] T4 | slice=docs | files=docs/VERIFY_POLICY.md,README.md | verify=`python -m pytest -q` | Document the reviewed challenge manifest and scope
