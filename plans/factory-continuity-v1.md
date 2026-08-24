# Plan: factory-continuity-v1
Spec: specs/factory-continuity-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)

1. Define the metadata-only local ledger and its fail-closed authorization,
   evidence, expiry, idempotency, and audit rules.
2. Expose explicit local CLI verbs; project redacted facts into Graph Ops.
3. Validate behavioral, visual, specification, architecture, and mutation
   boundaries without claiming a hosted memory service.

## Tasks (atomic — each independently shippable)

- [x] T1 | slice=factoryline | files=factoryline/continuity.py | verify=`python -m pytest -q tests/test_continuity.py` | Add metadata-only record, independent promotion, exact recall, expiry withholding, idempotency, and audit verification.
- [x] T2 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_continuity.py` | Add explicit local init, record, recall, promote, prove, and status commands.
- [x] T3 | slice=factoryline | files=factoryline/graph_ops.py,factoryline/graph_ops.html | verify=`python -m pytest -q tests/test_continuity.py tests/test_graph_ops.py` | Project redacted continuity nodes and a disabled Decision Replay control with no write authority.
- [x] T4 | slice=tests | files=tests/test_continuity.py | verify=`python -m pytest -q tests/test_continuity.py tests/test_graph_ops.py tests/test_studio.py` | Prove the ledger, Graph Ops redaction, CLI flow, and read-only projection boundaries.
- [x] T5 | slice=docs | files=docs/FACTORY_CONTINUITY.md,docs/GRAPH_OPS.md | verify=`python -m pytest -q tests/test_continuity.py tests/test_studio.py` | Document exact authority and service-milestone boundaries.
- [x] T6 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_continuity.py` | Surface the local Decision Replay workflow without a hosted-service claim.
- [x] T7 | slice=specs | files=specs/factory-continuity-v1.md,specs/factory-continuity-v1.ssat.yaml | verify=`specline strict factory-continuity-v1 --root .` | Seal the product and architecture contract.
- [x] T8 | slice=plans | files=plans/factory-continuity-v1.md | verify=`specline tasks factory-continuity-v1 --root .` | Seal atomic implementation packets.
