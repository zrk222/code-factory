# Plan: external-runtime-evidence-v1
Spec: specs/external-runtime-evidence-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Contract: implement bounded provider-neutral bundle validation, immutable receipt
   writing, TestSprite provider preservation, and deterministic receipt diffing.
2. Surface: add `factory external import|diff` CLI commands and project valid
   receipts into read-only Graph Ops facts/nodes/markers.
3. Evidence: add unit tests for valid import, tamper rejection, identity mismatch,
   deterministic diff, idempotent output, Graph Ops projection, and authority limits.
4. Documentation: document the offline adapter contract, TestSprite example,
   generic-provider guidance, and the fact that external evidence never grants
   release authority.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=factoryline | files=factoryline/external_evidence.py,tests/test_external_evidence.py | verify=`pytest -q tests/test_external_evidence.py` | Implement and test bounded bundle import and deterministic receipt diff.
- [ ] T2 | slice=factoryline | files=factoryline/cli.py | verify=`python -m factoryline.cli external --help` | Add offline `external import|diff` commands with fail-closed exit codes.
- [ ] T3 | slice=factoryline | files=factoryline/graph_ops.py,tests/test_graph_ops.py | verify=`pytest -q tests/test_graph_ops.py -k external` | Project imported external evidence as a read-only typed lane and preserve authority/recommendation boundaries.
- [ ] T4 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`python -c "from pathlib import Path; assert Path('docs/EXTERNAL_RUNTIME_EVIDENCE.md').is_file()"` | Publish the provider-neutral contract, TestSprite example, and non-authority warning.
- [ ] T5 | slice=external-runtime-evidence-v1.ssat.yaml | files=external-runtime-evidence-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('external-runtime-evidence-v1.ssat.yaml').is_file()"` | Bind the implementation surface and bounded architecture invariants.
- [ ] T6 | slice=smoke | files=smoke/external-runtime-evidence-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/external-runtime-evidence-v1.json').is_file()"` | Register a non-hollow smoke gate for the external evidence path.
