# Candidate continuity receipt

The candidate-lineage verifier is the small, strict join between Code Factory's
three independent proof surfaces: the Oracle Firewall contract, a deep audit,
and Graph Ops lineage. Agents may assemble the manifest, but the verifier does
not trust agent-selected gates and never grants release authority.

## What it proves

`Source → approved obligation → candidate digest → deep-audit evidence → graph
lineage → review decision` refers to one workspace candidate. It checks current
Oracle source bindings, self-hash-valid deep-audit evidence, candidate-bound
graph lineage, exact evidence file digests, unique paths, and bounded inputs.

```powershell
factory graph lineage-continuity .factory/candidate-lineage.json --root . --json
```

The result is `CANDIDATE_LINEAGE_VERIFIED` only for a complete two-kind
manifest. `release_approval` is always false and all authority flags remain
false. A failure is actionable: `E_CANDIDATE_LINEAGE_ORACLE` points to stale or
wrong Oracle evidence; `E_CANDIDATE_LINEAGE_GRAPH` identifies an unbound or
different graph candidate; `E_CANDIDATE_LINEAGE_EVIDENCE` identifies a changed
or malformed receipt; and path, schema, incomplete, or authority errors identify
the corresponding boundary.

This is a continuity proof, not a correctness proof. It does not execute code,
repair a candidate, authenticate an external analyzer, approve a release,
publish, deploy, sign, contact a provider, or read credentials. A human still
reviews the evidence and makes the release decision.
