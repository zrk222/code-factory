# Fresh security precision study225

## Result

Two separate AI review contexts labeled every one of the 57 emitted security
alerts. Consensus is **0 actionable TP, 49 FP, 8 unclear**: **0% actionable
precision on 49 decided alerts**, Wilson 95% **0–7.27%**. Counting unclear alerts
against success also gives 0/57. This fails the owner's 35% intermediate merge
threshold and the original 80% publication target. No merge is approved.

Primitive recognition is separate: 41 TP, 15 FP, one disagreement kept unclear.
Its 73.21% decided match rate is **not actionable precision**.

| Reviewer | Actionable TP | FP | Unclear |
| --- | ---: | ---: | ---: |
| AI A, Sol 6.1 high | 0 | 49 | 8 |
| AI B, Sol 6.1 high | 0 | 54 | 3 |
| Agreement; disagreements remain unclear | 0 | 49 | 8 |

These are independent contexts of the same model, with shared-error risk; no
human validation is claimed. Five actionable disagreements and one primitive
disagreement are preserved, without majority voting or changed labels.

## Prospective scope and coverage

The scanner was frozen before predictions. Twelve public repository commits were
pinned after a metadata-only prior-exposure screen, with no replacements after
predictions. No recorded exposure in that registry does not prove universal lack
of earlier exposure or model training data. All tracked content was hash-frozen;
the capture contains 3,958 tracked Python files and 9,883 tracked files overall.

The native full-repository profile accounts for all eligible Python sources in
460-source batches. It preserves its own directory exclusions and does not gain
cross-file semantic closure merely by processing all files. Two concurrent
workers used a 180-second budget per repository. Target code was not imported,
executed or installed; native coordinator output was limited to untracked state.

Eleven repository scans reached zero pending sources. Ten audited every eligible
source; Nautobot audited 1,260/1,262, with two deliberately invalid syntax fixture
files recorded as errors. OpenWISP failed before its first scan prefix because
its pytest collection configuration was unsupported; it was not replaced or
retried. Overall, 3,533 eligible sources were audited in the eleven reporting
repositories. **The twelve-repository coverage qualification is incomplete.**

The predetermined sample was the first 60 distinct emitted `SECURITY_*` alert
keys by a fixed SHA-256 ranking, across every rule and severity, with all alerts
used if fewer than 60. There were 57, so every emitted alert was labeled. Failed
repository outcomes remain in the coverage ledger. The score describes emitted
alerts, not undetected defects or the failed repository.

## What this establishes

This is a new fixed study with a broader source profile, not a paired improvement
or regression against the older 25% exposed development panel or 9.09% Study210.
Those earlier populations, denominators and source profiles differ. No combined
or selectively pooled score is reported.

The major actionable false-positive family is hardcoded secrets: 44 FP and four
unclear among 48 alerts. Fifteen of the overall primitive labels are also false
positives, including protocol endpoints, configuration/import selectors and enum
category values. Dangerous operations and secret-shaped binding names alone do
not establish a contextual defect. The full report preserves per-rule,
per-repository and per-reviewer counts.

The frozen study is now exposed to implementation work. Future fixes replayed
against these labels are development evidence, not a fresh held-out score.
Source-role and credential-lifecycle repairs must produce native finding changes
and retain real positives at their justified severity. Removing false positives
from this zero-TP panel cannot itself establish positive precision or recall.

## Evidence

Machine-readable result: `docs/evidence/fresh-heldout-study225.json`.

Local immutable inputs, raw outputs and labels are under `.factory/study225/`:

- `registration.json` and `registration-clarification.json`: fixed prospective
  rules, score definitions, sampling, disagreements and failure handling.
- `scanner-manifest.json` and `content-freeze.json`: scanner and source bytes.
- `preregistered-review.json`: ECC approval of the exact runner before scanning.
- `scan-cohort.json`: all twelve terminal outcomes, errors and source verification.
- `private-selection.json`: all 57 selected keys and packet hashes.
- `reviews/label-a.json` and `reviews/label-b.json`: independent original labels.
- `score.py`: hash/evidence verification, agreement rule and Wilson calculation.

Full-suite integration, historical positive retention, native quality and the
remaining PR gates are separate outstanding requirements. This study does not
claim zero failing tests, complete semantic coverage or production safety.
