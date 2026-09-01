# FactoryLine 0.8.22 — reviewer summary

- **User impact:** an externally orchestrated agent run can look complete while
  its workflow, handoffs, or resumed state drifted.
  **FactoryLine response:** Unified Graph Ops displays a verified Atomic Proof
  Adapter receipt bound to the current Oracle Contract.
  **Evidence:** `factoryline/atomic_proof_adapter.py`,
  `tests/test_atomic_proof_adapter.py`, and the `atomic-proof-panel` in
  `factoryline/graph_ops.html`.
- **Scope and source integrity:** the adapter rejects undeclared handoffs,
  capability or path scope escape, changed source bytes, topology drift, tool
  drift, and checkpoint drift.
  **Evidence:** stable `E_ATOMIC_*` failure codes and mutation-backed SpecLine
  contract `specs/atomic-proof-adapter-v1.md`.
- **IDE safety:** the JetBrains plugin remains confirmation-gated and the new
  view is read-only. It does not execute or resume the external workflow,
  change IDE settings, apply code, approve, merge, publish, deploy, or access
  credentials.
  **Evidence:** plugin description, Graph Ops authority map, MCP/WebMCP
  read-only declarations, and package tests.
- **Compatibility and approval:** compatibility, packaging, signing, and
  Marketplace submission are rechecked by the protected JDK 21 release gate.
  JetBrains moderation timing and approval remain external decisions.
