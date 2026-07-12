# Plan: compliance-plane-foundation

Spec: specs/compliance-plane.md

- [x] T1 | slice=factoryline | files=factoryline/compliance.py | verify=`python -m pytest -q tests/test_compliance.py` | Implement versioned baseline and customer control packs
- [x] T2 | slice=tests | files=tests/test_compliance.py | verify=`python -m pytest -q tests/test_compliance.py` | Prove OSCAL-shaped export, evidence mapping, and non-certifying label
- [x] T3 | slice=docs | files=docs/COMPLIANCE.md | verify=`python -m pytest -q` | Document scope and exact limitations
- [x] T4 | slice=cli | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_compliance.py` | Expose pack listing and export commands

