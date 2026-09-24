# Historical release notes: v0.20.0 through v0.23.1

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

---

# Code Factory 0.21.0

Code Factory can now resume itself.

`factory continue [feature]` discovers the current feature state, runs the next
safe local stages, and stops at a clear human boundary instead of returning a
large report that the user must interpret. The same engine is available in the
new Factory Studio Assembly tab and in the VS Code and JetBrains integrations.

This release also makes measurement publishable without overstating results.
Each continuation creates an atomic run receipt. `factory metrics` exports only
privacy-safe aggregates, preserves unobserved token and cost fields as unknown,
and refuses to manufacture productivity savings without a measured baseline.

Highlights:

- state-aware continuation with distinct completed, waiting, and halted states;
- exact SSAT contract resolution and feature-selection safeguards;
- compact human output plus stable JSON;
- Studio, VS Code, and JetBrains entry points;
- atomic run receipts and privacy-safe public metric exports;
- synchronized Python package, hosted Space, editor bundles, citation, and
  archive metadata.

---

# Code Factory 0.22.0

Code Factory 0.22 adds a paired savings tracker for publishing exact,
auditable samples of elapsed-time, token, and cost changes.

## What shipped

- `factory savings record` writes an atomic private receipt for an exact
  baseline-versus-Factory pair.
- `factory savings report` produces an aggregate-safe public JSON report.
- Signed deltas preserve regressions, while absent counters remain unknown.
- Productivity gain remains withheld until equivalent-outcome evidence is
  explicitly asserted and hash-bound.
- Factory Studio, VS Code 0.7.0, and JetBrains 0.7.0 expose the same report.

## Evidence boundary

The tracker performs arithmetic over user-supplied observations. It does not
run the compared workflows, infer missing counters, certify causal attribution,
or establish outcome equivalence. Public exports deliberately exclude pair
identifiers, paths, evidence hashes, and per-pair measurements.

---

# Code Factory 0.23.0

Code Factory 0.23.0 adds content-addressed proof reuse for read-only validation.

- `factory proofs record|plan|verify|challenge`
- RUN, REUSE, SKIP, and BLOCK with fail-closed relevance
- SHA-256 binding for inputs, outputs, command, toolchain, and environment
- compact public-safe proof plans
- isolated mutation challenge
- exact automatic paired savings for verified reuse
- SHA-keyed IntelliJ workflow concurrency

The feature earned ForgeLine grade A with a 100/100 final feature score,
maximum complexity 9, security score 100, complete public-function test intent,
and complete public-function documentation.
That score is scoped to `factoryline/proof_reuse.py`, not the whole repository.

July contained 66 IntelliJ workflow launches for 42 unique head SHAs: 24
duplicate launches (36.4%), 216 duplicate jobs, and 1101.3 duplicate
runner-minutes measured from API timestamps. The user-supplied Actions UI job
averages imply an approximate 2567.5-minute matrix baseline, making the exact
duplicate minutes approximately 42.9% of that approximate baseline. These are
historical opportunity measurements, not realized or prospective savings.
Future savings remain unmeasured until prospective reuse receipts exist.

---

# Code Factory 0.23.1

Code Factory 0.23.1 is a supply-chain security patch for the VS Code extension
build toolchain.

## Fixed

- Resolve `brace-expansion` to 5.0.9, addressing GHSA-mh99-v99m-4gvg.
- Resolve `fast-uri` to 3.1.5, addressing GHSA-v2hh-gcrm-f6hx.
- Run `npm audit --audit-level=high` after `npm ci` and before tests in both
  VS Code continuous integration and release packaging.

## Evidence

- The reviewed lockfile reports 0 vulnerabilities on Node 22.
- VS Code compilation, tests, and dependency-free VSIX packaging pass with the
  patched graph.
- Deterministic publication tests enforce the exact resolutions and workflow
  order.

## Scope boundary

The affected packages are development-only transitive packaging dependencies.
They were not bundled into the dependency-free VSIX, and this patch adds no
extension command, permission, activation event, or runtime authority.

---

