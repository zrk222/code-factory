# Study N435 evidence record

## Scope and result

This is one AI-only, two-reviewer study of admitted `SECURITY_HARDCODED_SECRET` findings in a bounded sample of public Python web applications. It does not measure all Code Factory rules or languages. Luna and Sol 6.1 supplied independent labels; no outside human adjudication occurred.

- Original first-blind consensus: **9 TP, 2 FP, 49 unclear** across 60 selected findings; 11 decided, precision 81.82%, Wilson 95% lower bound 52.30%. The qualification remains **false/incomplete cohort**: two technical inputs were incomplete/error, leaving the required cohort incomplete and below minimum decided count.
- Post-study same-rubric application review: **54 TP, 2 FP, 4 unclear**; 56 decided, precision 96.43%, Wilson 95% lower bound 87.88%, 54 TP repositories, max repository TP share 1/54. This re-applies the unchanged rubric to the same frozen cohort. It is **not a new blind study**, held-out cohort, or replacement for the original result. It does not erase original technical failures or qualification state.
- Original source engine: `a66d42bd67eb3d95bf08315708f2696a9df87fc5`; preregistered runtime manifest SHA-256 `6e5dc4e69e3d94986f5d5f78fd44c144e100f25449c1bd367fc6c1dd17cd873f`; preregistration SHA-256 `ded8b9ea45dc0994eb07dd61ff261b9c7390d3827b843e079bd8af31f230b7ed`. Prior outcomes were excluded before sampling; 983 metadata survivors remained; selection used frozen rank and first 60 admitted findings, distinct repositories, one per repository.
- Sampling flow: 736 probed, 327 captured, 325 complete, 1 prior-context duplicate, 408 ineligible, 2 technical failures, 247 raw findings, 60 admitted/selected.
- Maintenance commit `72ec69c6e0367fd2b18804caa62846c3efbc9c43` repaired lazy name-parent lookup. Separately, verified data recovery finalized the one failed staging rename without redownloading; the receipt is `.factory/precision435-run/recovery/fantaso-finalization.json`. Both originally failed inputs then passed the public CLI, persisted receipt, and different-process verifier; 26 targeted checks passed, and 0 other completed study inputs were rerun. The code fix and recovery are maintenance evidence, not a TP gain or score update.

## Error record

The two original false positives remain `N435-005` and `N435-014`. The post-study review leaves `N435-024`, `N435-047`, `N435-052`, and `N435-054` unclear. Findings are kept source-linked by repository, revision, path, line, and hashes in the ledger; literal credential values and source dumps are excluded.

## Claim limits

No same-cohort baseline or recall claim is available. The 90% TP/all count is a different quantity from precision over decided labels. No gate-ready or binary-release accuracy claim follows from these results. Original labels, scores, source snapshot, and technical failures are preserved.

## Evidence files

- `original-blind-score.json.gz` and `post-study-rubric-score.json.gz` are deterministic gzip containers of the original JSON bytes; decompression SHA-256 is checked against source files.
- `sampling-provenance-error-ledger.json` contains compact cohort provenance and 60 source-linked finding records, without literal secrets or source dumps.
- `artifact-sha256.json` records source and output hashes.
- Workflow QA is under `.factory/precision435-record-qa/`. The report/data checks validate record integrity only; they do not rerun source analysis or software tests.
