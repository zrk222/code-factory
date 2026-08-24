# Plan: code-factory-agent-contract-v2
Spec: specs/code-factory-agent-contract-v2.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Add the canonical Core-5 contract validator and CLI receipt.
2. Make the default assembly chain conditional on UI scope and include Prestige.
3. Add a deduplicated telemetry inventory over all supported receipt stores.
4. Extend provider policies with execution constraints and fail-closed routing.
5. Add regression tests, update help/docs, and prove the feature through the
   SpecLine/ForgeLine/factory release gates and preset deployment path.

## Tasks (atomic - each independently shippable)
- [x] T1 | slice=factoryline | files=<=4 | verify=`pytest -q tests/test_agent_contract.py` | Add Core-5 normalization, hashing, and CLI validation.
- [x] T2 | slice=factoryline | files=<=4 | verify=`pytest -q tests/test_assembly.py` | Insert conditional Prestige stage and preserve canonical stage ordering.
- [x] T3 | slice=factoryline | files=<=4 | verify=`pytest -q tests/test_telemetry.py` | Reconcile legacy receipts, run receipts, traces, and meter rows with quality markers.
- [x] T4 | slice=factoryline | files=<=4 | verify=`pytest -q tests/test_provider_router.py` | Enforce projected cost, latency, capability, privacy, and output-contract rails.
- [x] T5 | slice=tests+docs | files=<=4 | verify=`pytest -q` | Run full regression, package proof, and publish the evidence packet.
