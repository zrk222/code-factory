# Study249: sealed actionable-security measurement

## Result

Two separate blinded `gpt-6.1-sol` high contexts reviewed every claim in the
preregistered 60-unit sample. Both returned the same per-claim decisions.
This is AI-only review, not independent human validation or separate organizations.

| Scanner | TP | FP | Unclear | Decided actionable precision | Wilson 95% |
| --- | ---: | ---: | ---: | ---: | --- |
| Baseline `965d6294` | 33 | 10 | 0 | 76.74% (33/43) | 62.26–86.85% |
| Candidate `e4a46fcb` | 33 | 27 | 0 | **55.00% (33/60)** | **42.49–66.91%** |

Unclear-inclusive candidate rate is also 55.00%. Primitive pattern presence
is 60/60; it is not actionable precision. All 33 sampled baseline TPs are
retained. The candidate exceeds the numerical 35% and 30-decided requirements,
but the complete preregistered merge check is **NOT MET** because coverage is
incomplete. No merge approval or publication claim follows from this report.

## Paired interpretation

- The 43 unchanged exact claims are 33 TP / 10 FP on both scanners: **zero
  measured detection improvement** on that common set.
- Seventeen candidate-only sampled alerts are all false positives from ARES.
  That repository timed out on baseline and finished on candidate. These
  findings do not establish that changed rules introduced new false alarms;
  the baseline has no completed comparable output for that repository.
- The raw descriptive difference is -21.74 percentage points with different
  denominators. It is not a demonstrated rule-quality regression or gain.
- Baseline completed 13/15 repositories; candidate completed 14/15. Bitcart
  remains incomplete (247 audited of 262 Python files). Both input seals pass.
- Thirty-two of the 33 TPs are separate request-to-eval sink locations in one
  repository, FinancialFraudDataGenerator. The unit was preregistered as a
  finding/span, so they remain separate units. This concentration limits
  generalization; the simple Wilson interval does not model repository clusters.
- No target code was executed, imported or installed. No exploitation was run.

## False-positive families in this now-exposed sample

| Family | FP |
| --- | ---: |
| ARES enum/discriminator metadata and synthetic test credentials | 17 |
| Fixed request-body overrides before eval | 5 |
| Operator-selected YAML configuration with explicit FullLoader | 1 |
| Private application-produced pickle cache | 1 |
| Development-only secret selection | 1 |
| Local Docker test TLS verification setting | 1 |
| Public password-hash algorithm configuration in tests | 1 |

These labels may guide development now, but this sample cannot be presented
as a fresh held-out measurement after tuning on them. Do not clear enum or test
findings by name/path alone; prove source roles and retain real credentials.

## Exact evidence

- `score.json`: frozen scorer result, groups, unit labels and input hashes.
- `blinded-packets/manifest.json`: SHA256
  `73ad4bea6f5b04b91cc1e38f599e4c569954be9f7364074bb2b040bc5fd2ddb5`.
- `labels-a.json`: SHA256
  `1fa610199c47450e12634b126bd8806766354691c3f9267179206398f547809b`.
- `labels-b.json`: SHA256
  `eaa6d95c7aa3e4d4c96935cd03baccd19ddefd9be2ee942609b08c2bcba506f0`.
- `candidate-scanner-freeze.json`: exact raw package and canonical Git blobs,
  private candidate commit `e4a46fcb3e243409d420901ec4961f17ae4aab9c`.
- `predictions/{baseline,candidate}/summary.json`: all 15 terminal receipts per
  scanner, original failures preserved without replacement.
- `scoring-addendum.md` and `measurement-tool-freeze.json`: preregistered
  population, sampling, disagreement, denominator and scoring rules.

The exposed Wiki native regression remains separate: its source query qualifies
the fixture, but final source-binding comparison rejects the receipt and retains
the CRITICAL alert. The 52 affected checks and three new allocator controls pass;
they do not override that failed native observation or establish global readiness.
