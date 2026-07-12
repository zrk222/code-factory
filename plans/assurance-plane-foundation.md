# Plan: assurance-plane-foundation

Spec: specs/assurance-plane.md

- [x] T1 | slice=factoryline | files=factoryline/assurance.py | verify=`python -m pytest -q tests/test_assurance.py` | Implement graph, risk DAG, constrained runner, SBOM/VEX, policy mutation, and private manifest primitives
- [x] T2 | slice=tests | files=tests/test_assurance.py | verify=`python -m pytest -q tests/test_assurance.py` | Prove cycles, dependency closure, cwd containment, mutation detection, and digest stability
- [x] T3 | slice=docs | files=docs/ASSURANCE.md | verify=`python -m pytest -q` | Document artifacts and limits without overstating sandbox strength
- [x] T4 | slice=cli | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_assurance.py` | Expose graph, SBOM, VEX, and policy mutation commands

