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

## Current source native test matrix

Exact tested source: `ffcac7960d33fce39da63e9ebd96106521c92ae9`.
[Native CI run 39765104022](https://github.com/zrk222/code-factory/actions/runs/39765104022).
Nine existing CI JUnit artifacts were downloaded and checked; no jobs or passing
local tests were rerun to produce this receipt.

All nine Ubuntu, macOS and Windows jobs on Python 3.10–3.12 pass. Each report has
8,364 cases and zero failures/errors. Ubuntu/macOS: 8,352 passed, 12 skipped;
Windows: 8,348 passed, 16 skipped. Skips are not treated as passes.

The workflow remains failed because native candidate quality remains FAIL.
The unchanged local native audit has 90 complexity findings; architecture passes
at 429 Python files / 133 core modules, within unchanged 464/133 caps. This is
neither a full-CI-green claim nor merge qualification.

CodeQL alerts 87/88 were dismissed as source-reviewed false positives. Their
traces start at password-comparison diagnostic-return functions. The returned
payload contains fixed rule/message/severity metadata and AST coordinates, not
the target password literal or request value. Root verified four relevant Git
blob identities against the analyzed merge, and a separate ECC reviewer checked
the source. Both dismissal states were read back through the API. This applies
only to those two paths and is not a CF precision gain. Original SARIF and review
receipts remain under `.factory/precision231/`.

Latest qualified actionable precision is unchanged: Study225 **0 TP / 49 FP /
8 unclear; 0/49 = 0%**, nominal alert-level Wilson 95% **0–7.27%**. Same-family AI
reviews, incomplete semantic coverage and exposed-data limitations remain.
Neither the 35% merge bar nor 80% publication bar is met.

## Native CLI resealing repair

The first scanner seal discarded the captured source bytes. CLI and receipt
preparation then sealed the same report again; native source recomputation
rejected valid proofs because their bytes were missing. The repair retains an
immutable capture outside JSON fields and recomputes the proof on every seal.
JSON-only reports and changed source bindings still reject those observations.
An independent INCOMPLETE state is retained when proof partition derives CLEAN.

Four new copy/deepcopy/receipt/CLI regressions failed on the baseline, then all
four passed in 1.62 seconds after repair. Only those failed cases were rerun.
Separate ECC source review passed for the exact repair. Three new unsafe-shell
controls retain HIGH; a raising validator removes the transient private field.

Actual public CLI replay on the exposed `genotrance/px` repository (29/29 files)
changes **25 active security alerts to 20**, retaining all five changed sites as
source-proven primitive observations. The remaining 20 security findings and
all non-security findings are exactly unchanged, including severity. Existing
source-role policy supplies the INFO observation classification; this repair
adds no exemption or new severity policy. It preserves the original primitive
and runtime-incomplete boundary. Paired elapsed times were 14.75 and 17.985
seconds; no speedup is claimed.

This is a measured development delta, not a fresh precision percentage. The
latest fresh actionable result remains 0/49, and merge/publication bars remain
unmet. Matching-source full CI and broader true-positive retention are pending.
The account/ChoiceSet prototypes remain unadmitted. See
[`native-reseal234.json`](native-reseal234.json) for exact source and evidence hashes.

## Native quality repair235 and exact-parent CI

The nine native Python CI jobs passed on `822830e1`: each reports 8,368
cases with zero failures/errors. Ubuntu/macOS have 8,356 passed and 12 skipped;
Windows has 8,352 passed and 16 skipped. Overall CI still fails candidate-quality.

A separately ECC-reviewed, behavior-preserving nine-line helper extraction now
removes one native complexity failure: 90 to 89, with no added findings.
Architecture remains HEALTHY at 429 Python files / 133 core modules. The prior
CI matrix qualifies parent `822830e1`; matching-source CI for this extraction
remains pending. See [native-quality235.json](native-quality235.json).

The exposed Wiki replay audits 209/209 files in each lane and leaves all five
CRITICAL security alerts unchanged. It adds no precision gain. Study225 remains
0/49 decided actionable (eight unclear); the private fixture repairs remain
unadmitted. No passing local unit suite was rerun for this source-equivalent
refactor.
