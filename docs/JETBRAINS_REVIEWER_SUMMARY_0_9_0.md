# FactoryLine 0.9.0 — JetBrains reviewer summary

| Review area | User impact | Evidence and boundary |
| --- | --- | --- |
| Agent handoff inspection | Developers can inspect a provider-neutral handoff against the original sealed intent instead of trusting a completion claim. | `factoryline.agent_proof_bridge`; typed DAG, source-precondition, before/after, checkpoint, and Oracle-binding tests. No provider call or agent execution. |
| Intent integrity | A worker cannot supply or weaken a blocking rule through the handoff envelope. | Current Oracle Contract is mandatory; stale binding rejects receipt verification. |
| Review visibility | Unified Graph Ops shows the contract, provider declaration, workflow, run, and evidence nodes. | Read-only Graph Ops projection tests; no approval, repair, merge, publication, or deployment controls added. |
| Worklog aid | A user can create a local review draft from sealed evidence. | `factory worklog draft`; explicit `review_required`, zero external connector/message authority, and stale-contract rejection tests. |
| IDE safety | The plugin exposes local evidence only. | Plugin remains local and free in this build; no credential access, remote agent action, automatic posting, or Marketplace approval claim. |

This document is evidence for reviewer triage, not a request to bypass normal
Marketplace validation or a statement about JetBrains' external review outcome.
