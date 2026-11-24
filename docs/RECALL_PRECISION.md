# Recall and precision: where Code Factory stands (24 Nov 2026)

This page records every recall and precision number measured in the
23–24 Nov work, how each was measured, and how far it can be trusted.
None of these numbers is a held-out release claim. The last section says
what a claim would need.

## Detection rule

Recall uses the same rule as the 161-advisory study
(`advisory-recall-factory-20261121.json`). An advisory counts as detected
when a rule whose CWE family matches the advisory reports a line inside the
old side of a `git diff -U5` hunk, in an in-language, non-test file changed
by the fix. An alert elsewhere in a changed file ("file hit") is reported
only as a description.

## Recall

Pattern lane (opengrep, `semgrep-pattern-limited.yml`), first fix commit of
each advisory, Wilson 95% intervals:

| Set | Role | Before (ruleset `34c22d94`) | Now (PR #384) |
| --- | --- | --- | --- |
| 113 advisories, published 2026-09-01 to 2026-11-23 | Working set: frozen before any diff was read, then used to design rules | 1/107, 0.9% (0.2–5.1%) | **18/107, 16.8% (10.9–25.0%)** |
| 161-advisory study | Validation for the new rules: their fixes were not read while designing them, but the set is exposed to earlier work | 6/148, 4.1% (1.9–8.6%) | **19/148, 12.8% (8.4–19.2%)** |

Other lanes, unchanged by this work:

| Lane | Set | Score |
| --- | --- | --- |
| CodeQL, untuned stock queries | 161-advisory study, analyzed cases | 18/118, 15.3% (9.9–22.8%) |
| Factory combined (pattern plus CodeQL), 21 Nov | 161-advisory study | 20/161, 12.4% (8.2–18.4%) |
| Python `audit security`, changed files only | 113 working set, Python cases | 2/23, 8.7% (2.4–26.8%) |
| Python `audit security`, changed files only | 161-advisory study, Python cases | 1/25, 4.0% (0.7–19.5%) |

What moved recall, in order (step records in
`docs/evidence/parameter-sink-rules-20261124.json`):

| Step | Working set | 161 set | Alerts on clean repos |
| --- | --- | --- | --- |
| Archive extraction, request-to-path for Go/Java/Ruby, raw-HTML output | 1 | 6 | 0 of 19 repos |
| Shell and SQL text built from a function parameter; tar extraction without a filter | 8 | 16 | 5 |
| Parameter joined under a base directory with no containment check | 12 | 18 | 3 |
| JS/TS unescaped attribute interpolation and `innerHTML` | 16 | 20 | 7 of 9 JS repos |
| Go/JS/Python TLS trust checks | 18 | 20 | 1 |
| Merging the two `tarfile` rules to stay within the 64-rule bound | 18 | 19 | — |

The 161-set gain (6 to 19) is the better guide to generalization, because
those fixes were never read for this work. The working-set figure is tuned.

What recall still misses: about four in five advisories. Most are checks
added deep inside sanitizer, parser and certificate libraries (loofah,
rails-html-sanitizer, svg-sanitizer, forge X.509, highcharts allow-lists),
where the vulnerable line is library-internal. Pattern rules cannot see
these; the CodeQL lane with library models is the route (Codex PR #386 adds
offline Java, C# and Go workers).

## Precision

No adjudicated precision exists for the new rules. These are the
measurements that do exist:

| Measurement | Result | Strength |
| --- | --- | --- |
| New pattern rules on clean, well-maintained control repositories | 16 alerts after tuning: parameter shell/SQL 5, path join 3, JS HTML 7, TLS 1. All reviewed as real instances of the pattern, mostly in tooling or release scripts. | Single reviewer (Claude), development controls |
| Rule rejected for precision | PHP HTML string concatenation: 76 alerts on phpBB, no 161-set gain. Not shipped. | Same |
| Python SQL parameter rule on 48 full advisory repositories | 435 alerts before restricting sinks to cursor/connection receivers, 148 after. Recall unchanged. | Volume only |
| Imported `unittest.TestCase` oracle credit (PR #380) | Review-tier findings on 5 control repositories 136 to 93, none added, security tiers unchanged | Volume only |
| Earlier blind study (study225) | 0 actionable true positives in 49 decided security alerts, mostly hardcoded secrets | Two blind AI reviewers; predates the credential work in #376/#377 |

### Cross-function reach (`factoryline/parameter_reach.py`)

The reach pass follows a sink parameter to its callers until nothing
changes. On 48 full Python advisory repositories it labelled the
parameter-rule alerts as follows:

| Label | Alerts inside fixed lines (true positives) | Other alerts |
| --- | --- | --- |
| `entry_reached` | 2 | 26 |
| `public_api` | 2 | 213 |
| `unresolved` | 0 | 81 |
| `callers_constant_only` | 0 | 16 |

No true positive was demoted. The tier report now promotes `audit security`
command, shell, SQL and path findings from `NEEDS_CONTEXT` to
`SUPPORTED_DEFECT` when an entry point reaches them, with the call chain as
evidence (`source_bound_entry_reach`). On five Python control repositories
it promoted nothing, because they have no such findings.

## What a release claim needs

1. **A new frozen advisory set.** The 113 set has been used to design rules,
   so the next fresh set must be frozen before any rule changes and scored once.
2. **Adjudicated precision.** Labels from two blind reviewers and an
   adjudicator, on a fixed sample of emitted alerts from frozen repositories,
   reported with Wilson intervals per rule family.
3. **Unchanged scoring rule.** Pre-register any change to the hunk rule (for
   example, crediting an alert anywhere in the changed function) before seeing
   results.
