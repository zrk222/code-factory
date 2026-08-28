# Plan: journey-proof-engine-v1
Spec: specs/journey-proof-engine-v1.md (approved)
Architect verdict: PASS

## Logical decomposition (phases)
1. Seal input and receipt schemas plus canonical validation.
2. Compile reality, failure, workflow, and healing proof decisions.
3. Project verified receipts into CLI, Graph Ops, MCP, and reviewer documentation.
4. Challenge gates, run full regression/package checks, and audit drift.

## Tasks (atomic - each independently shippable)
- [ ] T1 | slice=proof contract | files=<=2 | verify=`python -m pytest -q tests/test_journey_proof.py -k reality` | Implement Journey Reality Graph schemas, comparison, receipts, and focused tests.
- [ ] T2 | slice=failure capsule | files=<=2 | verify=`python -m pytest -q tests/test_journey_proof.py -k capsule` | Implement Rich Failure Capsules with bounded adjacent steps and hash-bound artifacts.
- [ ] T3 | slice=workflow proof | files=<=2 | verify=`python -m pytest -q tests/test_journey_proof.py -k workflow` | Implement Stateful Workflow Proof with DAG, value-flow, cleanup, and idempotency gates.
- [ ] T4 | slice=healing gate | files=<=2 | verify=`python -m pytest -q tests/test_journey_proof.py -k healing` | Implement Proof-Gated Healing with human-controlled or bounded supervised-auto review mode, scope hashing, positive proof, negative mutation, and a separate FactoryLine Agent Work Audit.
- [ ] T5 | slice=CLI | files=<=3 | verify=`python -m pytest -q tests/test_cli.py tests/test_journey_proof.py` | Add CLI commands and atomic JSON and Markdown outputs.
- [ ] T6 | slice=Graph Ops and MCP | files=<=4 | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_mcp_server.py` | Add read-only Graph Ops and MCP projections.
- [ ] T7 | slice=public docs | files=<=3 | verify=`python -m pytest -q tests/test_publication_metadata.py tests/test_journey_proof.py` | Document schemas, authority boundaries, use cases, and release metadata.
- [ ] T8 | slice=release verification | files=<=4 | verify=`python -m pytest -q` | Run drift, ForgeLine, full regression, package, and clean-worktree completion gates.
