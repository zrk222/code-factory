# Study434: post-repair development result

**96.97% decided precision (32 TP / 33 decided), with 91.43% known-TP retention (32/35).**

This reuses the exposed Study434 cohort: 76 alerts across 58 repositories, with the original two AI review passes and no relabelling or outside human adjudication. It is a development retest, not a new held-out measurement.

| Measure | Previous C1 | Current C3 |
| --- | ---: | ---: |
| Admitted TP / FP / UNCLEAR | 27 / 1 / 6 | 32 / 1 / 6 |
| Decided precision | 96.43% | 96.97% |
| Known-TP retention | 77.14% | 91.43% |

Five additional TPs were recovered: N434-001,008,021,023 and070. No previously admitted labelled TP was lost, no additional labelled FP was admitted, and all 121 previous raw ledger records remain. Three labelled TPs remain unadmitted (020,048,049); one admitted FP remains (032). UNCLEAR stays visible. The 33 decided admissions remain below the preregistered 40-alert minimum; this is not a gate-readiness claim.

Shared repairs carry finite import/provider and scalar-origin evidence through admission. Verification reuses one fresh complete source pass within eligible seals, preserves later independent passes, and removes unused configuration plumbing, duplicated identity projections and unreachable code. All nine affected production modules pass C901<=10; no module, dependency or cap was added. Historical module/coupling debt remains open.

Profile: `factory audit security --security-only --defect-policy source-role-v3 --json`, on the same captured Python sources.

The final public-CLI -> persisted-receipt -> independent-verification run completed all 58 repositories in 287.86 seconds with four persistent workers. Median repository time was 6.72 seconds (previous observed median 8.73); the slowest remained 286.80 seconds. Maximum reported worker peak was 142.60 MiB. These are observed runs with different worker reuse/concurrency, not an isolated algorithmic speedup estimate; the slowest case still needs work.

Source commits: 021e8ab8 and 23a42032. Frozen 537-file runtime manifest SHA-256: `a7e05e643b1053a57e48f5e7d286b4c26965e198ef1ca9b35b0720e55add61aa`. Commit binding compares all 537 files with 23a42032, allowing checkout newline normalization only.

[Exact development score (gzip)](study434-development-score.json.gz); decompressed SHA-256: `749f28b8990032848a6160d279e0d89ac37a6ed5fd585749db473e737f25f77e`.

The original [held-out study record](study434-held-out-results.md) remains separate. These results do not describe the existing 0.49.5 release binaries.
