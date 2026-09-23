# Jev + BM25/BM25F rule retrieval

Code Factory now uses a two-stage, optional retrieval/classification path for
large rule inventories:

1. **BM25/BM25F retrieves locally.** `factory.search_audit_rules` defaults to
   deterministic BM25F ranking. `ranking: "bm25"` uses a single-field score;
   `ranking: "lexical"` preserves the legacy substring search. BM25F gives
   higher weight to the rule name and rejection code than to descriptive text,
   so an agent sees the most actionable conditions first.
2. **Jev may classify the bounded candidates.** The result contains a
   secret-free `jevHandoff` with candidate rule IDs and a context hash. A host
   may pass that handoff to an injected Jev transport and validate the typed
   result with `factoryline.jev_classifier.classify_retrieval`.
   `fuse_advisory_scores` can blend per-rule Jev scores with local relevance;
   CF keeps local BM25/BM25F dominant and preserves local order when Jev
   scores are missing or invalid.
3. **CF remains the authority.** Jev labels are advisory routing hints such as
   `RUN_LANE`, `TARGETED_REPAIR`, or `HUMAN_REVIEW`. Invalid, stale, low-quality,
   or unavailable Jev output fails closed to `HUMAN_REVIEW`. It cannot execute
   a lane, alter a threshold, approve a release, merge, publish, or grant
   credentials.

The default path is offline and provider-free. This preserves local operation,
keeps rule discovery explainable, and lets teams measure Jev against their own
defect corpus before enabling it. Required measurements include precision,
recall, calibration, false-negative rate, latency, and fallback rate; no
provider speed or cost claim is inferred from the adapter.

## Scope gate

Run the feature-scoped gate, which audits only the two implementation modules:

```powershell
forge qa jev-bm25-retrieval-v1 --ssat specs/jev-bm25-retrieval-v1.ssat.yaml --root . --strict
```

Do not substitute `--repo-wide` for this slice. That inventory scope includes
unrelated generated wheels and TypeScript/TSX products, so a Python-only audit
would report parser and coverage failures outside this feature.
