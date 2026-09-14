# Deep audit graph and repair-comparison verification

Delivered plan T11/T12 on Windows, Python 3.11. No deployment or publication.

- Full regression: `python -m pytest -q` — 1208 passed, 3 skipped, 196.12 seconds.
- Targeted graph/comparison/surface/shared-reader suite — 29 passed.
- SpecLine strict and 13 requirement-mutation checks passed; drift audit of the new comparison module passed with no warnings.
- Forge scoped review, architecture gate, scaffold rejection and runtime smoke passed for `deep-audit-loop`. The SSAT scopes the two new public comparison/projection entry points, not the entire historical CLI/graph codebase.
- Independent in-memory sabotage forced every comparison to return approval_required. All four selected policy-change, no-progress and regression tests failed. Source files were not changed by this test.
- Graph tests verify six declared lineage stages, unassessed status, 50-chain truncation, complete receipt references and rejection of a changed observed digest.
- `git diff --check` passed.

The architecture gate was invoked by the assistant under the user's scoped
implementation request, not an independent human review. The comparison reads
self-hash-valid observations; it does not authenticate their producer or establish
chronology/freshness. The result never approves, executes, signs or repairs.

Graph lineage is evidence routing, not proof of causation or verified policy
approval. The existing repair-loop adapter exposes this comparison without
closing or modifying existing repair packets. All non-improving outcomes require
review; no background loop, arbitrary retry budget or schedule was introduced.

Public release packaging, complete discovery documentation and publication tasks
remain separate from this implementation slice.

## Attestation freshness gate

The deep-audit comparison now accepts optional independent DSSE attestations.
Each attestation is checked offline against an operator-pinned trust root and the
exact self-hash receipt it accompanies. Signer identity, complete target/canary
coverage, plan/candidate/ruleset/canary bindings, timezone-aware timestamps and
the bounded age window are verified before a comparison result is returned.
`--require-attestation` requires both sides; missing, invalid, analyzer-self,
future, expired or stale evidence returns a stable `E_DEEP_ATTESTATION_*` code.
The legacy self-hash-only path remains available when no attestation is supplied.
Neither path executes analyzers, applies repairs, approves a change, or grants
release authority.
