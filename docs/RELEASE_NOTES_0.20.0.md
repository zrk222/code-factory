# Code Factory v0.20.0 — Governed Missions and BYOK Routing

Code Factory v0.20.0 turns Product Missions into a durable, inspectable state
machine and adds a secret-free control plane for choosing providers and models
across CLI, Studio, VS Code, and JetBrains.

## Highlights

- Transactional SQLite mission ledger with canonical, hash-linked events and
  idempotent transitions.
- Independent creator/validator identities, exact milestone coverage, bounded
  retries, and hard token/cost/time/iteration exhaustion.
- Human pause, plan revision, and fresh-context resume as first-class receipts.
- Optional LangGraph adapter with local SQLite checkpoints while Code Factory
  remains the evidence authority.
- BYOK provider policies containing only environment-variable references,
  provider/model allowlists, IDE selection, quality floors, price metadata,
  routing bias, and cache rails.
- JetBrains 0.5.0 Mission Operations with workspace-contained paths and output
  redaction.
- Governed instruction-learning packets with distinct worker, validator, and
  human promotion identities.

## Verified release evidence

- Python regression suite: 262 passed, 2 skipped.
- JetBrains test, plugin build, and Marketplace metadata preflight: passed.
- SpecLine requirement mutations: 34 of 34 killed.
- ForgeLine implementation mutants: 2 of 2 killed.
- ForgeLine QA: A, composite 96.5, security 100, maximum complexity 10.

These measurements describe the tested repository state. Provider routing is a
recommendation and policy-verification boundary; an external runtime remains
responsible for credential injection, provider calls, and spend authorization.
