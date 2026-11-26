# Exposed-161 pattern-lane miss taxonomy (candidate b2a2800f)

This classifies the 121 exposed-161 cases that candidate rules b2a2800f (branch `claude/carry-forward-39`, commit 1673ec5d) do not hit: 116 misses, 3 coverage_incomplete and 2 unknown. It uses manifest 7036f848 (cases 5f332b15) and receipt e83f0082 (written by 25c5c78c). The held-out Q2 cohort was not read, scanned or referenced.

Machine-readable data, with per-case rationale and every bucket: `recall-exposed-161-miss-taxonomy-20261126.json`.

## Flagged anywhere in the vulnerable file

- **10** non-hits have an alert of the advisory family in a changed file on the old side, outside the hunk. This equals the receipt's file_hits minus hunk_hits (50 - 40).
- Only **4** of them are the same vulnerability flagged at its sink while the fix edits a sanitizer upstream: GHSA-4h97, GHSA-73wf, GHSA-qcpp and GHSA-vj3g. The other 6 are unrelated alerts in large files.
- 17 non-hits have an alert from any rule in a changed file.
- Source of the counts: the old side of the 158 scannable exposed packets was rescanned once, under the replay lock, with the frozen rules and the harness's own scoring exports. The rescan reproduces the receipt case for case: 40/40 hits, 50 file hits, 0 mismatches.

## Class x reason (lane totals on the right)

| class | not_pattern | interprocedural | sink_unmodeled | source_unmodeled | no_rule | no_source_change | outside_hunk | coverage_gap | total | pattern | codeql | native | none | pattern-recoverable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| injection-sql | 11 | 4 | 6 | 3 | 3 | 2 | 1 |  | 30 | 11 | 4 | 1 | 14 | 10 |
| injection-command | 7 | 4 | 1 | 6 | 2 |  | 2 | 1 | 23 | 7 | 4 | 1 | 11 | 7 |
| path-traversal | 6 | 5 | 4 | 4 |  | 1 | 1 |  | 21 | 4 | 4 | 1 | 12 | 4 |
| crypto-tls | 9 | 2 |  |  | 1 | 2 |  |  | 14 | 1 |  |  | 13 |  |
| xss | 4 | 1 | 2 |  | 2 |  |  | 2 | 11 | 1 | 1 |  | 9 | 1 |
| deserialization | 5 |  |  |  | 2 |  |  |  | 7 | 2 |  |  | 5 | 2 |
| authz-access-control | 7 |  |  |  |  |  |  |  | 7 |  |  |  | 7 |  |
| injection-code | 1 | 1 | 1 |  | 2 |  |  |  | 5 | 2 |  | 1 | 2 | 2 |
| other | 2 |  |  |  | 1 |  |  |  | 3 | 1 |  |  | 2 | 1 |
| **total** | 52 | 17 | 14 | 13 | 13 | 5 | 4 | 3 | 121 | 29 | 13 | 4 | 75 | 27 |

Reasons: not_pattern = logic, authz, configuration or deny-list completeness. interprocedural = the flow crosses functions or files. sink_unmodeled = framework/ORM dispatch or a sink shape the rules do not match. source_unmodeled = the source is not modeled. no_rule = no rule for the class or language. outside_hunk = the same vulnerability is flagged elsewhere in the file. no_source_change = no in-language source change, or unknown. coverage_gap = coverage_incomplete.

## Top 5 recoverable buckets (class x reason x lane)

| # | bucket | cases | est. hit gain | examples | rationale |
|---|---|---|---|---|---|
| 1 | injection-sql / sink_unmodeled / pattern | 4 | +3 | GHSA-vf2r-cxg9-p7rf, GHSA-85gf-wr67-f83w, GHSA-wc3v-3457-c8cm | Add DB-wrapper and builder sinks (ADOdb Execute/GetOne/GetAll, Rails finder taking a whole params hash, go-sqlbuilder Select with a Sprintf quoted %s). The SQL text is on the deleted line. GHSA-jjgq is excluded because its $db->query sink is outside the hunks. |
| 2 | injection-sql / source_unmodeled / pattern | 3 | +3 | GHSA-6gm7-j668-w6h9, GHSA-vj9x-w7ch-f46p, GHSA-g23g-mw97-65c8 | Model Symfony $request->get()/query/request bags and framework-bound Go form structs as sources; both pimcore cases concatenate the value into a hand-quoted condition fragment on the deleted line. |
| 3 | path-traversal / sink_unmodeled / pattern | 3 | +3 | GHSA-8qvf-mr4w-9x2c, GHSA-mj4x-vf5c-5xg8, GHSA-h36j-8vv3-cj52 | Widen python.parameter-path-join-without-containment operand shapes ($BASE / ($A + $P), $BASE / $P[...]), and stop treating a custom tar members= filter whose check is startswith() without os.sep as a sanitizer. |
| 4 | injection-command / outside_hunk / pattern | 2 | +2 | GHSA-73wf-9vmv-5pv9, GHSA-qcpp-8x79-hhp3 | Already flagged at the secure_popen sink; the fix edits the sanitizer above it. Needs no rule change, only a scoring decision (trace or sanitizer-span attribution), which Codex owns. The same mechanism covers GHSA-4h97 (sql) and GHSA-vj3g (path): 4 cases in total. |
| 5 | injection-command / no_rule / pattern | 2 | +2 | GHSA-2jh5-g5ch-43q5, GHSA-qrg7-hfx7-95c5 | C# ProcessStartInfo{FileName="cmd.exe", Arguments=$"/C ...{x}"} with a non-literal interpolation, and git subcommands taking a variable positional argument without a "--" end-of-options marker. Tied at 2 with five other buckets; see tie_note. |

Six class x reason x lane buckets tie at 2 recoverable cases: injection-command/outside_hunk (ranked 4: no rule work), injection-command/no_rule (ranked 5), injection-command/source_unmodeled (GHSA-6qjf %x interpolation, GHSA-mc7w process.argv), injection-sql/no_rule (GHSA-mhwp Ruby ^$ anchors, GHSA-vmw2 C# SQL text), injection-code/no_rule (GHSA-6m8w rego.Query, GHSA-8gqp Nashorn without --no-java) and deserialization/no_rule (GHSA-2pm6 misspelled allowed_classes, GHSA-2fmj case-sensitive phar:// check).

## What the pattern lane can and cannot recover

- At most **27** of the 121 non-hits look recoverable by the pattern lane (23 through rule changes, 4 through a scoring change only). That would take the candidate from 40 to at most 67 hits. This is an upper bound: no rule was written, and precision controls and the fixed-side residual limit (0.48 per hit) were not run. The top 5 buckets add up to +13 at most.
- **92/121 (76%)** cannot be recovered by any pattern rule. Of these, 13 need CodeQL interprocedural analysis, 4 need a native PHP taint tool, and **75 (62% of all non-hits)** have no automated lane: they are logic, authz, configuration or deny-list fixes, cases with no in-language change, or coverage gaps.
- not_pattern is the largest reason (52/121). 12 of the 17 TLS-family (CWE-295) misses are not_pattern: option/flag logic, peer-identity checks or authentication, not a disabled-verification call. Of the other 5, two have no in-language change, two have the trust-all inside a client library, and one has no rule (EventMachine start_tls).

## Proposals (not implemented)

- Scoring (Codex-owned, not implemented): the 4 same-vulnerability outside-hunk cases (GHSA-4h97, GHSA-73wf, GHSA-qcpp, GHSA-vj3g) have the alert at the sink while the fix edits a sanitizer or validator upstream. A pre-registered secondary metric that credits a same-file family alert on the fixed flow (or trace_hit when the SARIF carries a dataflow step in the hunk) would count them without any rule change. It must be pre-registered and reported apart from hunk_hits.
- Join (Codex-owned): the 13 codeql-lane and 4 native_sast-lane cases are where the native-to-pattern fingerprint join would add recall. Their CodeQL alerts would mostly land at the sink, outside the fix hunk, so the same scoring question applies.

## Caveats

- One reviewer, diff-level reading. Reasons and lanes are judgments; borderline calls are noted in each rationale.
- The pattern-recoverable count is an upper bound: no rule was written, and precision controls and the 10% fixed-side residual tolerance (limit 0.48 per hit) were not evaluated.
- GHSA-mrq8/GHSA-6vmq and GHSA-r8g5/GHSA-x843 share a fix commit, so each pair counts twice.
- Five non-hits are not scored misses: 3 coverage_incomplete and 2 unknown (no old-side source; no in-language source change).
