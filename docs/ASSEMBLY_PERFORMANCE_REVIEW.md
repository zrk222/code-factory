# Assembly efficiency: shared observations, unchanged gates

## Delivered slice

Graph Ops previously loaded four evidence projections and loaded them again
through Mission Control. It now passes the request-local Mission observations
to the graph renderers. The human and agent control planes consume the same
observations. There is no persistent cache and no bypass of gate verification.
Oracle contract rendering still verifies the contract independently.

The paired regression test executes both paths and requires identical graph
output. It measures eight versus four direct calls to the four shared readers.
This is a call-count reduction, not a claim of 50% faster overall execution.
Freshness tests insert invalid evidence between requests and require the next
request to block. Explicit empty observations do not accidentally trigger rereads.

## Diagnose before optimizing

```console
factory mission-control profile --root . --json
```

This read-only command returns five named reader spans, canonical SHA-256
fingerprints, an aggregate evidence identity and zero action authority. It omits
raw evidence bodies. Timings are separate from evidence identity and include
reader execution only, not interpreter startup or all six modules' runtimes.
Hashes are integrity identifiers, not signatures or proof of truthful inputs.
Neither profiling nor projection sharing provides an atomic filesystem snapshot.
Execution gates must verify their own current inputs.

## Six-piece assembly review scope

| Piece | Existing role | Optimization boundary |
|---|---|---|
| SpecLine | Intent, spec and task contract | Never reuse approval after a contract change. |
| ForgeLine | Ordered execution and behavioral gates | Preserve dependency order; only independent read-only work is a parallelization candidate. |
| HSF | Deterministic compilation | Reuse only through existing exact-input proof verification. |
| Prestige | Design verification when UI is in scope | Do not run irrelevant UI gates; absence of UI evidence is not design approval. |
| FactoryLine | Orchestration, graph and human/agent control | Shared request-local reads and bounded profiling delivered here. |
| AppForge | Mobile evidence when mobile work is in scope | Remains conditional, not the default center of every assembly. |

These are reviewed operating boundaries, not measured performance improvements
in the other five components. Native IDE responsiveness, large populated receipt
stores, subprocess startup, end-to-end gate duration, and concurrent filesystem
writes still require workload-specific measurement. Deep Defect Mesh, its repair
comparisons and comprehensive finding lineage remain a separate pending slice;
their design documents are not evidence of delivered implementation.

## Verification boundaries

The focused four-file test command passed 42 tests. Forge architecture, scoped
review, QA and smoke passed. The scaffold challenge failed at import, so it
proves scaffold rejection, not that every semantic mutation is detected; the
paired behavioral tests independently exercise read counts and fresh blockers.
The CLI's architecture gate labels its operator approval as human; it was
invoked by the assistant under the user's implementation request, not a
separate independent human review or release approval.

The whole-file SpecLine drift scanner reported pre-existing CLI/graph numeric
literals against this narrow spec, including the `8` in UTF-8. Its failure must
not be represented as an assembly-wide clean audit. The focused new-module
audit and regression suite are the appropriate evidence for this slice.

Final local regression receipt (2026-09-03, Windows/Python 3.11):
`python -m pytest -q` returned **1125 passed, 3 skipped in 171.22s**.
`python -m compileall -q` passed for all three changed Python modules.
`specline audit` on the Mission Control module passed all four functions.
No remote publication, native IDE benchmark, or production speed claim follows
from these local results.
