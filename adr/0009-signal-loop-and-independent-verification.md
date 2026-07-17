# ADR 0009: Govern signals and separate creators from verifiers

## Status

Accepted.

## Decision

Code Factory will place a deterministic Signal Loop before Product Missions and
an independent completion contract after them. Signals are local untrusted data;
the Opinion Dock is the owner-controlled cognitive anchor; machine triage is
explainable but never self-approving. Missions use a creator-verifier pattern
with an explicit context wall. Completion is a separate immutable receipt and
requires a distinct verifier, complete criterion coverage, and file-bound proof.

## Consequences

- Corrections improve the durable rule system instead of only one generated plan.
- Product Owners retain taste, prioritization, and promotion authority.
- Verifiers cannot inherit creator scratchpads or hidden reasoning.
- The factory can route abstract reasoning profiles without coupling to one model.
- Connector ingestion, agent execution, scheduling, merge, and deployment remain
  separate integrations with separate approvals.
