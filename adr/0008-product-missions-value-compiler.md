# ADR 0008: Product Missions Value Compiler

## Status

Accepted for v0.15.0.

## Decision

Code Factory will compile PRDs into deterministic Product Graphs, vertical
value slices, and hash-bound missions before an agent is selected. Runtime
agents remain adapters. Every mission is constrained by a Loop Passport and
cannot merge, publish, deploy, or send external messages.

## Rationale

The factory already proves implementation artifacts after work begins. Product
Missions closes the gap between ambiguous intent and the first reviewable PR.
It makes requirements, UX states, evidence, budgets, and outcomes traceable
without making a model the source of truth.

## Consequences

- v1 parsing and slicing are deterministic and conservative.
- Missing product detail is surfaced as a blocking gap, never invented.
- Parallel agent execution is possible later, but only across approved slices.
- Product success remains an observed outcome, separate from build success.
