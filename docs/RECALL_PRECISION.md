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

## Fresh held-out sets (24 Nov) and path traversal

Two sets of GitHub-reviewed advisories published Jul–Aug 2026 were frozen
from metadata before any diff was read (`docs/evidence/heldout-recall-manifest-20261124-*.json`).

| Set | Ruleset | Hunk recall | Wilson 95% | Path traversal |
|---|---|---|---|---|
| Fresh, 91 cases (85 scored) | #384 head, scored once | 10/85 (11.8%) | 6.5–20.3% | 1/33 |
| Fresh, after path tuning (now a dev set) | this change | 19/85 (22.4%) | 14.8–32.3% | 10/33 |
| Overflow, 61 cases (56 scored), never read | #384 head | 4/56 (7.1%) | 2.8–17.0% | 2/26 |
| Overflow, same cases | this change, scored once | 5/56 (8.9%) | 3.9–19.3% | 3/26 |

**Overlap correction (applied after scoring).** Four overflow cases share a
repository and fix commit with an earlier development case under a different
advisory ID (mistune `1bef343a`, PraisonAI `1620b49f` twice, mcp-atlassian
`b0417334`); all four were path misses. Without them the overflow numbers are
4/52 → 5/52 overall (Wilson 4.2–20.6%) and 2/22 → 3/22 for path traversal
(Wilson 4.7–33.3%). The Sep–Oct set below excludes earlier fix commits as well
as earlier advisory IDs.

The path rules were tuned on the 33 path cases of the fresh set and gain 9
there. On the overflow set, which they never saw, they gain 1 (litellm's
parameter join). **The number to quote for this change is the overflow one:
path traversal 3/26 (11.5%, Wilson 4.0–29.0%), overall 5/56.** The 113 and
161 sets are unchanged (18/107 and 19/148).

On the controls, the new rules add 11 parameter-join alerts across 48 full
Python repositories (about half on caller-supplied mapping keys or
parameters, the rest on internal names) and 5 JavaScript alerts across 7
control repositories (SvelteKit's dev and preview servers serving `req.url`,
and one trivial `existsSync(path.join(dir, file))` helper). The Python
request rule fires on none of the 48 repositories, before or after.

Most remaining path misses are fixes that add a check in front of a sink the
pattern lane cannot tie to untrusted input: an options field forwarded through
callbacks, a value read from an archive's own manifest, a resource URL in a
framework loader, or a missing branch of an existing check (postcss). Those
need cross-function reach, not more patterns.

## What a release claim needs

1. **A new frozen advisory set.** The 113 set has been used to design rules,
   so the next fresh set must be frozen before any rule changes and scored once.
2. **Adjudicated precision.** Labels from two blind reviewers and an
   adjudicator, on a fixed sample of emitted alerts from frozen repositories,
   reported with Wilson intervals per rule family.
3. **Unchanged scoring rule.** Pre-register any change to the hunk rule (for
   example, crediting an alert anywhere in the changed function) before seeing
   results.
