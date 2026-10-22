# Native Python regression matrix: zero failures

Candidate: `f03ef2c1fb6f9e55482fdf34afab6594aa9b7977`.
GitHub CI run: [39758730355](https://github.com/zrk222/code-factory/actions/runs/39758730355).

All nine matrix jobs passed. Downloaded JUnit reports contain the same 8,364
collected cases per job, with **zero failures or errors**:

| Host | Python | Passed | Skipped | Failed/error |
|---|---|---:|---:|---:|
| Ubuntu | 3.10,3.11,3.12 (each) | 8,352 | 12 | 0 |
| macOS | 3.10,3.11,3.12 (each) | 8,352 | 12 | 0 |
| Windows | 3.10,3.11,3.12 (each) | 8,348 | 16 | 0 |

Every report includes all original 24 frozen regression cases and all four
Python 3.10 fixture-parser cases, passing without skips. The companion records
exact report hashes and job identities. Platform skips remain preserved in the
original reports; they are not passes. No local passing suite was rerun.

**The native candidate-quality gate still fails.** This is test-matrix evidence,
not a full-CI-green, merge or release claim. Source-level precision prototypes
remain unadmitted. Latest fresh actionable precision stays **0 TP / 49 FP / 8 unclear
(0% on 49 decided)**; no precision improvement follows from these regression passes.
