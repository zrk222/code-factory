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

### Cross-function reach (`factoryline/captured_operand_audit.py` (`reach`, `entry_reach_tier`))

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

## Gaps closed on 24 Nov

- **Containment checks must guard.** The archive and request-path rules for
  Python, Go, Java, JavaScript, Ruby and PHP clear a value only when a
  containment check on that same value sits in a rejecting guard (an `if` that
  raises, returns, continues or throws, or a `try` around `relative_to` whose
  `except` exits) before the value is used. A bare predicate call no longer
  counts; each language has a positive control for it. On 32 control
  repositories this adds two alerts, both in Grav's `ZipArchiver`, where entry
  names are validated in a separate pre-pass loop (a cross-function check the
  pattern rules cannot see).
- **Go archive guards** bind the checked value, so a guard on an unrelated
  value (for example a label) no longer hides an entry-name write.
- **Reach follows registered handlers and wrappers.** Functions passed to
  `add_url_rule`, `add_api_route`, `add_route`, `register_tool`, `add_tool`,
  `add_command`, `add_handler` and similar calls, `mcp.tool()(handler)`, and
  values of module-level `*_HANDLERS`/`TOOLS`/`ROUTES` dictionaries are entry
  points. `*args`/`**kwargs` forwarding wrappers propagate to their callers.

Still open: calls through dynamic imports or string dispatch (for example
GeoNode's handler loaded by module path) are not resolved, so such sinks stay
`public_api` or `unresolved`.

## Fresh and overflow advisory sets (24 Nov)

The November 24 selections were frozen from advisory metadata before their
diffs were opened. The overflow sample covers npm and PyPI. The figures
below describe the historical rule snapshots and their original scoring.

| Set | Ruleset | Hunk recall | Wilson 95% | Path traversal |
|---|---|---|---|---|
| Fresh, original 85 scored | #384 head | 10/85 (11.8%) | 6.5–20.3% | 1/33 |
| Fresh, after path tuning on these cases | historical traversal revision | 19/85 (22.4%) | 14.8–32.3% | 10/33 |
| Overflow, original 56 scored | #384 head | 4/56 (7.1%) | 2.8–17.0% | 2/26 |
| Overflow, original 56 scored | historical traversal revision | 5/56 (8.9%) | 3.9–19.3% | 3/26 |

A repository and fix identity check revised the fresh baseline to
[10/83 (12.0%)](https://github.com/zrk222/code-factory/blob/22bae917cbdfe39ca8c3e9a9fbf978b75a7ab6a1/docs/evidence/heldout-recall-results-20261124-fresh.json).
The exposed tuning result retains its original 85-case denominator.

The [overflow receipt](evidence/path-traversal-rules-20261124.json) records
four scored rows matching three previously seen fixes. The retained
historical candidate has **3/22 path hits and 5/52 overall**, across 49
distinct scored fixes. The baseline receipt has aggregate totals, so the
adjusted paired gain and retention of baseline hits remain unmeasured.
The receipt keeps the original rule hash and outcomes. The containment
correction has separate development controls and awaits benchmark scoring.

Historical controls recorded 11 additional Python alerts, five additional
JavaScript alerts, and zero firings of the Python request rule across 48
Python repositories. These are alert counts. A paired run with blinded
adjudication is needed to measure precision and the incremental effect of
cross-function reach.

## Paired development receipts (24 Nov, evening)

Baseline is the main ruleset `816bbef3`. Development sets only; the Sep–Oct
held-out set was not scored. Strict hunk recall, same definition as above.

| Candidate | Fresh /85 | Overflow /56 | 113 set /107 | 161 set /148 | Lost | Residuals per hit | Control alerts | Decision |
|---|---|---|---|---|---|---|---|---|
| baseline `816bbef3` | 10 | 4 | 18 | 19 | — | 0.75 | — | — |
| [`b986ab2`](evidence/recall-evaluation-b986ab2-dev.json) | 30 | 9 (/55) | 18 | 21 | 0 | 0.78 | +22 | ACCEPT |
| [`21299b0`](evidence/recall-evaluation-21299b0-dev.json) | 30 | 9 | 18 | 30 | 0 | 0.77 | +22 | REJECT (one control) |
| [`a79afe7`](evidence/recall-evaluation-a79afe7-dev.json) | 29 | 9 | 18 | 30 | 0 | 0.78 | +21 | ACCEPT |
| [`07ebe50`](evidence/recall-evaluation-07ebe50-dev.json) | 29 | 9 | 18 | 30 | 0 | 0.78 | +21 | ACCEPT |

`21299b0` adds Ruby and Java SQL-text rules, Go ordering/grouping sinks, and
merges two rule pairs to stay at 64 rules. It passes every development
gate. It fails one control gate. On pdf.js, both rulesets time out on the
emscripten `*_nowasm_fallback.js` files. The candidate times out once more
after a rescan, and it does so deterministically. The cause is the generic
`run(`/`shell(` wrapper sink of `javascript.parameter-shell-command`. With
those two names removed, that rule runs on one such file in 0.9 s instead
of 7.6 s. `a79afe7` drops those two names and is accepted; it gives up
one exposed hit (nocobase calls a local `run(command, env)` wrapper).
Engine for all three receipts: OpenGrep 1.15.0, binary sha256 `a10cebc3…0e33`;
`a79afe7` ruleset sha256 `2affe435…bbbe`; `07ebe50` (branch-aware Python
format checks, fs and database receiver identity) ruleset sha256 `e3e5787c…`.

Harness fixes found by these runs: the scan profile is pinned for both sides
of a run; a parse warning that quotes source text is no longer counted as an
engine timeout; and a control pair that differs only in timeouts is rescanned
once, with the first attempt kept.

## Sep–Oct held-out set, scored once (25 Nov)

The [Sep–Oct manifest](evidence/heldout-recall-manifest-20261124-sepoct.json)
(124 advisories, sha256 `d8a5f3bc…2a73`) was frozen from metadata in
`5168ec4`, before the rule changes above. It shares no advisory or fix
commit with any development set. Each ruleset scored it once, with the
same harness, profile and engine
([identities](evidence/heldout-recall-results-20261125-sepoct-identities.txt)).

| Ruleset | Strict hunk recall | Wilson 95% | Path | XSS | Command | Alerts in changed files |
|---|---|---|---|---|---|---|
| [main `816bbef3`](evidence/heldout-recall-results-20261125-sepoct-baseline-816bbef3.json) | 13/124 (10.5%); 13/110 known (11.8%) | 7.0–19.2% (known) | 2/33 | 6/32 | 3/13 | 44 |
| [candidate `07ebe50`](evidence/heldout-recall-results-20261125-sepoct-candidate-07ebe50.json) | 14/124 (11.3%); 14/110 known (12.7%) | 7.7–20.2% (known) | 3/33 | 6/32 | 3/13 | 91 |

Fourteen cases are unknown (13 change no in-language source, one fix is
unfetchable). The candidate gains one case (GHSA-8mcc-hrx5-hvxc, PyPI path)
and loses none. Changed-file alerts double for that one gain.

Most of the development gains did not carry over. On the exposed sets the
same candidate went from 51 to 86 hits; on this held-out set it gains one.
The rule changes since 24 Nov fit the exposed cases more than they
generalize. They should not be cited as a recall improvement beyond 11.3% of the
registered 124 (12.7% of the 110 with known outcomes).
This manifest is now spent: any later scoring of it is a development run.

## Q2 2026 held-out set, frozen 25 Nov (sealed)

[282 advisories](evidence/heldout-recall-manifest-20261125-q2.json) published
2026-04-01..2026-06-30, frozen from GitHub advisory-database metadata only
(candidate metadata sha256 `6b45382a…c7e7`), before any further rule change,
excluding every advisory and fix commit in `docs/evidence` and in the exposed
development manifests (556 IDs, 1,288 fix commits). Composition: npm 69,
PyPI 68, Go 61, Packagist 49, Maven 33, RubyGems 2. It is to be scored once,
by the agreed candidate, with the registered 282-case denominator.

## Recall harness (`scripts/recall_harness.mjs`)

Held-out numbers are produced by one committed tool instead of scratch scripts.

| Command | What it does |
|---|---|
| `freeze` | Selects cases from advisory metadata only. It excludes every earlier advisory ID and every earlier fix commit found under `docs/evidence`, keeps one case per fix commit and at most `--per-repo` per repository, and records a case digest. |
| `score` | Runs the production profile argv (`deploy/deep-adapters/profiles/semgrep-pattern-limited.json`) with only the binary, ruleset and I/O paths substituted. It reports strict hunk recall (primary), trace overlap (an alert whose source or dataflow step is on a changed line; diagnostic only), file recall, fix-side residuals, and outcomes split into hit, miss, engine timeout, unknown and error. Alerts in changed files are reported as a review budget. |
| `evaluate` | The gate for one candidate ruleset against a baseline: every dev manifest plus benign control repositories. It rejects lost baseline hits, new engine errors or timeouts, more fix-side residuals, control growth beyond `--max-control-increase`, and, with `--labels`, labeled false positives that return or labeled true positives that disappear. A flag on trial (for example `--taint-intrafile`) can apply to the candidate only. |
| `observe` | Adds new control alerts to a label file (`TP`, `FP`, `UNCLEAR`, or pending). Labels are keyed by rule, repository, path and snippet digest, so line shifts do not orphan them. |

A held-out manifest is scored once per ruleset; any later scoring of it is a
development run and is reported as such.

## What a release claim needs

1. **A new frozen advisory set.** The 113 set has been used to design rules,
   so the next fresh set must be frozen before any rule changes and scored once.
2. **Adjudicated precision.** Labels from two blind reviewers and an
   adjudicator, on a fixed sample of emitted alerts from frozen repositories,
   reported with Wilson intervals per rule family.
3. **Unchanged scoring rule.** Pre-register any change to the hunk rule (for
   example, crediting an alert anywhere in the changed function) before seeing
   results.
