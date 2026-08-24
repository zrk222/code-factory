# Start Here: from idea to enterprise evidence

Code Factory uses one local evidence model at every level. You can begin with
an outcome instead of a framework, then add rigor only when the work needs it.

## 0. See the difference in under two minutes

```powershell
pip install factoryline-code-factory
factory first-proof --root .
```

This runs a sealed demonstration in a disposable local sandbox. The positive
control must pass; the negative control is intentionally hollow and must be
caught as `HOLLOW_E2E_TEST`. A successful demo writes verified JSON/Markdown
evidence plus an optional, privacy-safe Proof Card under `.factory/`. It does
not inspect, modify, or upload your project source.

To share a card from another verified E2E receipt, opt in explicitly:

```powershell
factory proof-card .factory/e2e-proof/<receipt>.json --root .
```

The card contains only the bounded result and source-receipt hash. Commands,
paths, repository names, prompts, logs, and user identity are excluded.

```mermaid
flowchart LR
    I["Describe an outcome"] --> M["Instant local MVP"]
    M --> V["Run explicit proof commands"]
    V --> G["Inspect Unified Graph Ops"]
    G --> T["Product Missions and team review"]
    T --> E["Policy, assurance, and tenant controls"]
    E --> H{"Human release authority"}
```

## 1. Instant MVP — no factory vocabulary required

```powershell
factory mvp "Build an approval tracker for a small team" --root .
```

This produces one contained web starter in `./my-mvp`, explains its explicit
next proof commands, and leaves deploy, publish, credentials, connectors, and
messages unavailable. Open `factory studio --root .` for the same outcome-first
flow; **Instant MVP** is its default mode.

If you already have a PRD, clarify its current unknowns before scaffolding:

```powershell
factory prd grill .\PRD.md --root . --mode quick
```

The local answer sheet is source-bound and capped at three current questions;
it does not modify the PRD or grant build authority. See [PRD Grill](PRD_GRILL.md).

The starter is deliberately `compiled_blocked`: it is useful code and a
concrete product shape, not an unsupported claim that it is production-ready.

## 2. Professional workflow — proof without slowing down

Use the same project directory to add requirements, test coverage, proof reuse,
and a clear stateful next action:

```powershell
factory coverage --root .\my-mvp --json
factory graph ops --root .\my-mvp --json
factory graph ops --root .\my-mvp --mermaid
factory graph portfolio --root .\my-mvp --json
```

Graph Ops gives a bounded, read-only map of the facts already present. It can
recommend the next validation or evidence step but never runs it on your
behalf. Use `factory continue`, Product Missions, and content-addressed proof
reuse when the project needs more structured delivery.

For work where a passing happy-path test is not enough, add three small,
deterministic planning layers: compile the negative cases your requirements must
reject, activate only independently promoted and scope-matched memory metadata
as a redacted guardrail, and derive stateful replay risks from sealed lineage.
They remain plans, not execution authority. See [Counterexamples, Guardrails,
and Temporal Resilience](COUNTEREXAMPLE_GUARDRAIL_RESILIENCE.md).

When several proof or delivery slices exist, use `factory graph portfolio` to
see the deterministic critical path, safe proposal-only parallel waves, and
blocker chains. Teams that use an external harness can seal a short-lived Run
Admission Packet from a reviewed Loop Passport; the harness must re-verify it
before use. See [Graph Portfolio and Run Admission](GRAPH_PORTFOLIO_ADMISSION.md).

## 3. Enterprise controls — add governance, not friction

Teams can retain the exact same traceability while adding independent
verification, approval boundaries, signed capability packs, policy challenges,
tenant-scoped evidence, and supervised hosted adapters. These controls do not
turn a local MVP into an autonomous publisher: merge, publish, deploy, signing,
credentials, connectors, and external messages remain explicitly human-owned.

## What Code Factory will and will not optimize

The factory optimizes for a small, fact-derived next action, reuse of verified
read-only proof, and less reconstruction of context. It does not claim time,
token, cost, productivity, conversion, security certification, or production
readiness without a corresponding measured or hash-bound receipt.
