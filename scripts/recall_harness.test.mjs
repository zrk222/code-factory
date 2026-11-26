import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { hunkAdjudicationIdentity, hunkIdentity, loadAdjudicatedLosses } from './recall_losses.mjs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { parseHunks, ruleFamilies, selectCases, wilson, profileArgv, sarifFindings, scoreCase, summarize, gate, gainRetention, controlFindingDeltas,
  familiesFor, isTestPath, caseDigest, priorExposure, sha256, scoreManifest, validateRecallManifest, checkpointArtifactsIntact,
  publishPreparedCase } from './recall_harness.mjs';
import { changedFiles, coverageGaps, engineCoverage, fileCoverage, sarifPath, scannerPath, summarizeCoverage } from './recall_coverage.mjs';

const DIFF = `diff --git a/app/files.py b/app/files.py
--- a/app/files.py
+++ b/app/files.py
@@ -10,3 +10,4 @@ def read(name):
 a
-b
+b2
+b3
 c
diff --git a/tests/test_files.py b/tests/test_files.py
--- a/tests/test_files.py
+++ b/tests/test_files.py
@@ -1 +1 @@
-x
+y
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1 @@
-x
+y
`;

test('hunks keep in-language non-test files with old and new sides', () => {
  const hunks = parseHunks(DIFF, ['py']);
  assert.deepEqual(Object.keys(hunks), ['app/files.py']);
  assert.deepEqual(hunks['app/files.py'].old, [10, 11, 12]);
  assert.deepEqual(hunks['app/files.py'].new, [10, 11, 12, 13]);
  assert.ok(isTestPath('pkg/__tests__/a.ts') && isTestPath('a_test.go') && !isTestPath('src/contest.py'));
});

test('hunk content cannot overwrite paths and file headers retain spaces', () => {
  const diff = [
    'diff --git a/café file.py b/café file.py', '--- a/café file.py\t', '+++ b/café file.py\t',
    '@@ -1 +1 @@', '--- a/other.py', '+++ b/other.py', '@@ -8 +8 @@', '-a', '+b',
  ].join('\n');
  assert.deepEqual(parseHunks(diff, ['py']), { 'café file.py': {
    old: [1, 8], new: [1, 8], new_path: 'café file.py',
  } });
});

test('rule families read both inline and block CWE lists', () => {
  const rules = `rules:
  - id: python.request-path-traversal
    metadata:
      cwe: ["CWE-22"]
  - id: ruby.request-path-traversal
    metadata:
      cwe:
      - CWE-22
      - CWE-73
  - id: c.unsafe-gets
    metadata:
      cwe: ["CWE-242"]
`;
  assert.deepEqual(ruleFamilies(rules), { 'python.request-path-traversal': ['path'],
    'ruby.request-path-traversal': ['path'], 'c.unsafe-gets': [] });
  const shipped = ruleFamilies(readFileSync('deploy/deep-adapters/rules/semgrep-pattern-limited.yml', 'utf8'));
  const shippedRuleCount = Object.keys(shipped).length;
  assert.ok(shippedRuleCount > 0 && shippedRuleCount <= 64, `shipped rules must stay within the 64-rule ceiling (${shippedRuleCount})`);
  assert.deepEqual(shipped['php.archive-path-traversal'], ['path']);
});

test('selection excludes prior advisories, prior fix commits, duplicates and capped repositories', () => {
  const fix = n => String(n).repeat(40).slice(0, 40);
  const row = (ghsa, repo, f, published = '2026-09-10', cwes = ['CWE-22']) =>
    ({ ghsa, ecosystem: 'PyPI', cwes, published, repository: repo, fix: fix(f) });
  const candidates = [row('G-1', 'o/a', 1), row('G-2', 'o/a', 1), row('G-3', 'o/b', 2), row('G-4', 'o/c', 3),
    row('G-5', 'o/d', 4, '2026-08-01'), row('G-6', 'o/e', 5, '2026-09-11', ['CWE-400']),
    row('G-7', 'o/f', 6), row('G-8', 'o/f', 7), row('G-9', 'o/f', 8)];
  const prior = { ids: new Set(['G-3']), fixes: new Set([fix(3)]) };
  const { cases, dropped } = selectCases(candidates, { from: '2026-09-01', to: '2026-10-31', prior, perRepo: 2 });
  assert.deepEqual(cases.map(c => c.ghsa), ['G-1', 'G-7', 'G-8']);
  assert.deepEqual(dropped, { prior_id: 1, prior_fix: 1, window: 1, family: 1, duplicate_fix: 1, repository_cap: 1 });
  assert.equal(caseDigest(cases), caseDigest(JSON.parse(JSON.stringify(cases))));
});

test('wilson interval and family mapping', () => {
  assert.deepEqual(wilson(10, 85), [6.5, 20.3]);
  assert.equal(wilson(0, 0), null);
  assert.deepEqual(familiesFor(['CWE-22', 'CWE-73', 'CWE-200', 'CWE-79']), ['path', 'xss']);
});

test('profile argv substitutes only binary, ruleset and I/O', () => {
  const profile = { commands: [{ argv: ['/usr/bin/opengrep', 'scan', '--disable-nosem', '--config', '/opt/rules.yml',
    '--sarif-output', '{report}', '{source}'] }] };
  assert.deepEqual(profileArgv(profile, { bin: 'og', rules: 'r.yml', report: 'o.sarif', source: '.', extra: ['--taint-intrafile'] }),
    ['og', 'scan', '--disable-nosem', '--config', 'r.yml', '--sarif-output', 'o.sarif', '--taint-intrafile', '.']);
});

const loc = (uri, line) => ({ physicalLocation: { artifactLocation: { uri }, region: { startLine: line } } });
const sarif = { runs: [{ results: [
  { ruleId: 'python.request-path-traversal', locations: [loc('app/files.py', 40)],
    codeFlows: [{ threadFlows: [{ locations: [{ location: loc('app/files.py', 11) }] }] }] },
  { ruleId: 'python.request-sql-injection', locations: [loc('./app/files.py', 11)] },
] }] };

test('findings carry dataflow steps; hunk, trace and residual are scored separately', () => {
  const findings = sarifFindings(sarif);
  assert.deepEqual(findings[0], { rule: 'python.request-path-traversal', path: 'app/files.py', line: 40,
    trace: [['app/files.py', 11]] });
  const hunks = parseHunks(DIFF, ['py']);
  const rules = { 'python.request-path-traversal': ['path'], 'python.request-sql-injection': ['sql'] };
  const pathCase = scoreCase({ families: ['path'], hunks, oldFindings: findings, newFindings: [], rules });
  assert.equal(pathCase.hunk_hit, false);
  assert.equal(pathCase.trace_hit, true);
  assert.equal(pathCase.file_hit, true);
  const sqlCase = scoreCase({ families: ['sql'], hunks, oldFindings: findings,
    newFindings: [{ rule: 'python.request-sql-injection', path: 'app/files.py', line: 13 }], rules });
  assert.equal(sqlCase.hunk_hit, true);
  assert.deepEqual(sqlCase.fix_side_residual, [['python.request-sql-injection', 'app/files.py', 13]]);
  const summary = summarize([{ status: 'scored', fix: 'f1', families: ['sql'], ecosystem: 'PyPI', ...sqlCase },
    { status: 'scored', fix: 'f2', families: ['path'], ecosystem: 'PyPI', ...pathCase }, { status: 'unfetchable' }]);
  assert.equal(summary.hunk_hits, 1);
  assert.equal(summary.trace_hits, 2);
  assert.equal(summary.fix_side_residual_alerts, 1);
  assert.deepEqual(summary.by_family.path, { hits: 0, scored: 1 });

  const mixed = scoreCase({ families: ['sql', 'path'], hunks, oldFindings: [...findings,
    { rule: 'fixture.other', path: 'app/files.py', line: 11 },
    { rule: 'python.request-sql-injection', path: 'other.py', line: 1 }], newFindings: [], rules });
  const mixedSummary = summarize([{ status: 'scored', fix: 'f3', families: ['sql', 'path'], ecosystem: 'PyPI', ...mixed }]);
  assert.deepEqual(mixed.matched_hunk_families, ['sql']);
  assert.deepEqual(mixedSummary.by_family, { sql: { hits: 1, scored: 1 }, path: { hits: 0, scored: 1 } });
  assert.deepEqual(mixedSummary.review_budget, {
    alerts_in_changed_files: 3, family_alerts_in_changed_files: 2, per_scored_case: 3,
  });
});

test('gate rejects lost hits, more residuals and control growth', () => {
  const result = (rows, residual = 0) => ({ cases: rows,
    summary: { fix_side_residual_alerts: residual, hunk_hits: rows.filter(row => row.hunk_hit).length } });
  const before = result([{ ghsa: 'A', hunk_hit: true }, { ghsa: 'B', hunk_hit: false }]);
  const better = result([{ ghsa: 'A', hunk_hit: true }, { ghsa: 'B', hunk_hit: true }]);
  assert.equal(gate({ dev: [{ before, after: better }], controls: [{ before: 3, after: 3 }] }).decision, 'ACCEPT');
  const lostVerdict = gate({ dev: [{ before, after: result([{ ghsa: 'A', hunk_hit: false }, { ghsa: 'B', hunk_hit: true }]) }], controls: [] });
  assert.equal(lostVerdict.decision, 'REJECT');
  assert.match(lostVerdict.failures[0], /lost 1 dev hit/);
  assert.deepEqual(lostVerdict.lost_baseline_hits, ['A']);
  assert.equal(gate({ dev: [{ before, after: result(better.cases, 2) }], controls: [] }).decision, 'REJECT');
  // Twice the hits may carry twice the residuals, not more.
  assert.equal(gate({ dev: [{ before: result(before.cases, 1), after: result(better.cases, 2) }], controls: [] }).decision, 'ACCEPT');
  assert.equal(gate({ dev: [{ before: result(before.cases, 1), after: result(better.cases, 3) }], controls: [] }).decision, 'REJECT');
  const noisy = gate({ dev: [{ before, after: better }], controls: [{ before: 3, after: 9 }], maxControlIncrease: 5 });
  assert.deepEqual([noisy.decision, noisy.control_increase], ['REJECT', 6]);
});

test('gate rejects dropped, added and duplicate case IDs and scores reordered cases by ID', () => {
  const result = cases => ({ cases, scope: 'ecosystem', summary: { fix_side_residual_alerts: 0, hunk_hits: 1 } });
  const a = { ghsa: 'A', hunk_hit: true }, b = { ghsa: 'B', hunk_hit: false };
  const before = result([a, b]);
  const compare = after => gate({ dev: [{ before, after }], controls: [] });
  assert.equal(compare(result([b, a])).decision, 'ACCEPT');
  assert.match(compare(result([b])).failures[0], /Candidate case missing for A/);
  assert.match(compare(result([a, b, { ghsa: 'C' }])).failures[0], /Baseline case missing for C/);
  assert.match(compare(result([a, a])).failures[0], /Duplicate advisory ID/);
  assert.match(gate({ dev: [{ before: result([a, a]), after: before }], controls: [] }).failures[0], /Duplicate advisory ID/);
  assert.match(compare({ ...before, scope: 'scannable' }).failures[0], /scoring scope differs/);
  const gain = { before: result([b]), after: result([{ ...b, hunk_hit: true }]) };
  const separate = { before: result([a]), after: result([a]) };
  const independent = gate({ dev: [gain, separate], controls: [] });
  assert.equal(independent.decision, 'ACCEPT');
  assert.deepEqual(independent.gained, ['B']);
  const duplicated = gate({ dev: [gain, gain], controls: [] });
  assert.equal(duplicated.decision, 'REJECT');
  assert.match(duplicated.failures[0], /Duplicate advisory ID across paired recall cohorts: B/);
  assert.deepEqual(duplicated.gained, ['B']);
});

test('gainRetention requires the archived cohort, hit and exact source packets', () => {
  const cohort = '1'.repeat(64), ghsa = 'GHSA-xxxx-yyyy-zzzz';
  const evidence = { ghsa, revisions: { old: 'a', fixed: 'b' }, source_packets: { old: [{ path: 'sample.py', sha256: 'c' }], fixed: [] } };
  const block = { manifest_cases_sha256: cohort, cases: [{ ghsa, before: 'miss', after: 'hit' }], after_evidence: { cases: [evidence] } };
  const reference = { schema: 'factory.recall-evaluation.v1', gained: [ghsa], dev: [block] };
  const pairs = (row, digest = cohort) => [{ after: { manifest_cases_sha256: digest, cases: [row] } }];
  const hit = { ...evidence, status: 'scored', hunk_hit: true };
  assert.deepEqual(gainRetention(reference, pairs(hit)), { required: 1, retained: 1, lost: [] });
  assert.deepEqual(gainRetention(reference, pairs({ ...hit, hunk_hit: false })).lost, [ghsa]);
  assert.deepEqual(gainRetention(reference, pairs({ ...hit, source_packets: { old: [], fixed: [] } })).lost, [ghsa]);
  assert.deepEqual(gainRetention(reference, pairs(hit, '2'.repeat(64))).lost, [ghsa]);
  assert.throws(() => gainRetention({ ...reference, gained: [ghsa, ghsa] }, pairs(hit)), /checkpoint membership differs/);
});

function savedAdjudication(root) {
  const pair = { manifest_cases_sha256: '1'.repeat(64), manifest_sha256: '2'.repeat(64),
    profile_sha256: '3'.repeat(64), ruleset_sha256: '4'.repeat(64) };
  const engine = '5'.repeat(64);
  const loc = ['fixture.arithmetic', 'sample.py', 1];
  const ghsa = 'GHSA-2345-6789-cfgh';
  const second = 'GHSA-2345-6789-cfgj';
  const base = { status: 'scored', hunk_hit: true, hunk_findings: [loc], revisions: { old: 'a', fixed: 'b' },
    source_packets: { old: [{ path: 'sample.py', sha256: 'c' }], fixed: [] },
    file_coverage: { old: [{ path: 'sample.py', state: 'reported_scanned' }], fixed: [] } };
  const sources = [{ ...base, ghsa }, { ...base, ghsa: second }];
  const before = { ...pair, cases: sources, summary: { hunk_hits: 2, fix_side_residual_alerts: 0 } };
  const after = { ...before, ruleset_sha256: '6'.repeat(64), cases: sources.map(row => ({ ...row, hunk_hit: false })),
    summary: { hunk_hits: 0, fix_side_residual_alerts: 0 } };
  const score = { schema: 'factory.recall-evaluation.v1', candidate_sha256: pair.ruleset_sha256,
    engine: { executable_sha256: engine }, gained: [ghsa, second],
    dev: [{ manifest_cases_sha256: pair.manifest_cases_sha256, after_evidence: before,
      cases: sources.map(row => ({ ghsa: row.ghsa, before: 'miss', after: 'hit', hunk_findings: row.hunk_findings })) }] };
  const vote = (id, final) => ({ item: id, repository_case: `example/owned ${id}`, rule: loc[0], file: loc[1],
    line: loc[2], on_fix_hunk: true, final });
  const fp = vote(ghsa, 'FP');
  const adjudication = { schema: 'factory.adjudicated-precision.v1', candidate: 'owned (ruleset 44444444)',
    cohort: 'owned (spent), changed files', rows: [fp, fp, vote(second, 'TP')] };
  const save = (path, value) => {
    const bytes = JSON.stringify(value);
    writeFileSync(join(root, path), bytes);
    return { path, sha256: sha256(bytes) };
  };
  const plan = { schema: 'factory.recall-adjudicated-losses.v1', score: save('score.json', score),
    adjudication: save('adjudication.json', adjudication), manifest_cases_sha256: pair.manifest_cases_sha256 };
  save('loss-plan.json', plan);
  return { ghsa, second, before, after, score, plan, engine, loc, path: join(root, 'loss-plan.json') };
}

test('adjudicated loss inputs reject non-files and enforce the byte cap', () => {
  const root = mkdtempSync(join(tmpdir(), 'recall-loss-file-'));
  try {
    const { engine, path } = savedAdjudication(root);
    assert.throws(() => loadAdjudicatedLosses(root, engine), /regular file|EISDIR|EPERM/);
    assert.doesNotThrow(() => loadAdjudicatedLosses(path, engine));
    truncateSync(join(root, 'score.json'), 32_000_001);
    assert.throws(() => loadAdjudicatedLosses(path, engine), /byte limit/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('hash-bound adjudicated losses exempt only complete FP-only hunk removals', () => {
  const root = mkdtempSync(join(tmpdir(), 'recall-loss-policy-'));
  try {
    const { ghsa, second, before, after, score, plan, engine, loc, path } = savedAdjudication(root);
    const policy = loadAdjudicatedLosses(path, engine);
    assert.equal(policy.receipt.score_sha256, plan.score.sha256);
    assert.equal(policy.cases.get(ghsa).identity, hunkIdentity([loc]));
    const compare = (left, right) => gate({ dev: [{ before: left, after: right }], controls: [], lossPolicy: policy });
    const reviewed = compare(before, after);
    assert.deepEqual(reviewed.raw_lost_baseline_hits, [ghsa, second]);
    assert.deepEqual(reviewed.lost_fp_only, [ghsa]);
    assert.deepEqual(reviewed.lost_baseline_hits, [second]);
    assert.equal(reviewed.decision, 'REJECT');
    assert.deepEqual(gainRetention(score, [{ after }], policy), { required: 2, retained: 0, lost: [second], lost_fp_only: [ghsa] });
    const otherScope = { manifest_cases_sha256: '9'.repeat(64) };
    assert.deepEqual(compare({ ...before, ...otherScope }, { ...after, ...otherScope }).lost_fp_only, []);
    assert.deepEqual(compare({ ...before, engine_args: ['--other-options'] }, after).lost_fp_only, []);
    const withUnreviewed = { ...before.cases[0], hunk_findings: [loc, loc] };
    assert.deepEqual(compare({ ...before, cases: [withUnreviewed, before.cases[1]] }, after).lost_fp_only, []);
    const incomplete = { ...after.cases[0], file_coverage: { old: [], fixed: [{ path: 'sample.py', state: 'partial' }] } };
    assert.deepEqual(compare(before, { ...after, cases: [incomplete, after.cases[1]] }).lost_fp_only, []);
    assert.throws(() => loadAdjudicatedLosses(path, '0'.repeat(64)), /engine differs/);
    writeFileSync(join(root, 'adjudication.json'), '{}');
    assert.throws(() => loadAdjudicatedLosses(path, engine), /source fingerprint differs/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('line-only adjudication cannot waive two alerts on the same line', () => {
  const root = mkdtempSync(join(tmpdir(), 'recall-loss-same-line-'));
  try {
    const { ghsa, score, plan, engine, loc, path } = savedAdjudication(root);
    const row = score.dev[0].cases[0];
    row.hunk_findings = [loc, loc];
    const adjudication = JSON.parse(readFileSync(join(root, plan.adjudication.path), 'utf8'));
    adjudication.rows = [adjudication.rows[0], { ...adjudication.rows[0], item: 'second-position' }];
    const persist = () => {
      for (const [reference, value] of [[plan.score, score], [plan.adjudication, adjudication]]) {
        const bytes = JSON.stringify(value);
        writeFileSync(join(root, reference.path), bytes);
        reference.sha256 = sha256(bytes);
      }
      writeFileSync(path, JSON.stringify(plan));
      return loadAdjudicatedLosses(path, engine);
    };
    assert.equal(persist().cases.has(ghsa), false);
    row.hunk_spans = [[1, 0, 4], [6, 0, 9]];
    assert.equal(hunkAdjudicationIdentity({ ...row, hunk_spans: [[1, 0, null], [6, 0, 9]] }, true), null);
    assert.equal(persist().cases.has(ghsa), false);
    adjudication.rows.forEach((vote, index) => { vote.span = row.hunk_spans[index]; });
    assert.equal(persist().cases.has(ghsa), true);
    row.hunk_findings.push(loc);
    row.hunk_spans.push(row.hunk_spans[0]);
    assert.equal(persist().cases.has(ghsa), true);
    adjudication.rows[1].span = [6, 0, 10];
    assert.equal(persist().cases.has(ghsa), false);
    adjudication.rows[1].span = row.hunk_spans[1];
    adjudication.rows[1].source_sha256 = 'b'.repeat(64);
    assert.equal(persist().cases.has(ghsa), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('coverage gaps never count as misses and regressions fail on either revision', () => {
  const clean = { path: 'sample.py', sha256: sha256('fixture'), state: 'reported_scanned', reason: 'engine_scan_paths' };
  const base = { ghsa: 'A', status: 'scored', hunk_hit: false, fix_side_residual: [],
    families: ['path'], ecosystem: 'PyPI', file_coverage: { old: [clean], fixed: [clean] } };
  const incomplete = { ...base, file_coverage: { ...base.file_coverage,
    old: [{ ...clean, state: 'submitted', reason: 'no_engine_coverage_report' }] } };
  const summary = summarize([base, incomplete]);
  assert.equal(summary.scored, 1);
  assert.equal(summary.outcomes.miss, 1);
  assert.equal(summary.outcomes.coverage_incomplete, 1);
  assert.deepEqual(summary.hunk_hits_over_registered_cases.cases, 2);
  assert.deepEqual(summary.diagnostics[0].old_coverage_gaps, ['sample.py']);
  const result = row => ({ cases: [row], summary: summarize([row]) });
  const compare = (before, after) => gate({ dev: [{ before: result(before), after: result(after) }], controls: [] });
  assert.deepEqual(compare(base, incomplete).new_coverage_gaps, ['A']);
  assert.equal(compare(incomplete, incomplete).decision, 'ACCEPT');
  const hit = { ...base, hunk_hit: true, matched_hunk_families: ['path'] };
  const partialFixed = { ...hit, file_coverage: { ...hit.file_coverage,
    fixed: [{ ...clean, state: 'partial', reason: 'parse' }] } };
  assert.equal(result(partialFixed).summary.hunk_hits, 1);
  assert.equal(compare(hit, partialFixed).decision, 'REJECT');
  assert.equal(compare(partialFixed, partialFixed).decision, 'ACCEPT');
  const failedFixed = { ...partialFixed, file_coverage: { ...partialFixed.file_coverage,
    fixed: [{ ...clean, state: 'partial', reason: 'engine_error' }] },
  parser_probe: { fixed: { confirmed_limits: [clean.path] } } };
  assert.deepEqual(compare(partialFixed, failedFixed).new_coverage_gaps, ['A']);
  assert.deepEqual(compare(hit, failedFixed).new_coverage_gaps, ['A']);
  const probe = { path: clean.path, state: 'parse_limited', sha256: sha256('different source') };
  const probed = sha256 => ({ ...partialFixed, parser_probe: { fixed: { observations: [{ ...probe, sha256 }] } } });
  assert.deepEqual(compare(hit, probed(probe.sha256)).new_coverage_gaps, ['A']);
  assert.deepEqual(compare(hit, probed(clean.sha256)).new_coverage_gaps, []);
});

test('outcomes separate hits, misses, engine timeouts, unknowns and errors', async () => {
  const { outcomeOf, scanNotes } = await import('./recall_harness.mjs');
  assert.equal(outcomeOf({ status: 'scored', hunk_hit: true }), 'hit');
  assert.equal(outcomeOf({ status: 'scored', hunk_hit: false, scan_notes: { timeouts: 1 } }), 'timeout');
  assert.equal(outcomeOf({ status: 'scored', hunk_hit: false, scan_notes: { timeouts: 0 } }), 'miss');
  assert.equal(outcomeOf({ status: 'no_in_language_source_change' }), 'unknown');
  assert.equal(outcomeOf({ status: 'error' }), 'error');
  const notes = scanNotes({ runs: [{ invocations: [{ toolExecutionNotifications: [
    { descriptor: { id: 'Timeout' }, message: { text: 'Timeout when running rule x on a.py' }, level: 'warning' },
    { descriptor: { id: 'Syntax error' }, message: { text: 'Syntax error at line a.py:3' }, level: 'warning' }] }] }] });
  assert.deepEqual(notes, { timeouts: 1, parse_errors: 1, blocking_parse_errors: 0, other: 0 });
  assert.equal(outcomeOf({ status: 'scored', hunk_hit: true, scan_notes: { ...notes, timeouts: 0 } }), 'hit');
  // A parse warning quotes the target source; a word in that excerpt is not an engine timeout.
  const quoted = scanNotes({ runs: [{ invocations: [{ toolExecutionNotifications: [
    { descriptor: { id: 'Syntax error' }, level: 'warning',
      message: { text: 'Syntax error at line A.java:1:\n `class A { int connectionTimeout; }` was unexpected' } }] }] }] });
  assert.deepEqual(quoted, { timeouts: 0, parse_errors: 1, blocking_parse_errors: 0, other: 0 });
});

test('observation loop queues control alerts once and gates on labels', async () => {
  const { queueLabels, checkLabels, labelKey } = await import('./recall_harness.mjs');
  const alert = { rule: 'ruby.request-path-traversal', path: 'lib/installer.rb', line: 537, snippet: 'File.join bindir, name' };
  const deltas = [{ dir: '/ctl/rubygems', added: [alert], emitted: [alert] }];
  assert.throws(() => queueLabels(null, deltas, 'invalid'), /population fingerprint/);
  const queued = queueLabels(null, deltas);
  assert.equal(queued.labels.length, 1);
  assert.equal(queueLabels(queued, deltas).labels.length, 1);
  assert.equal(queued.labels[0].key, labelKey('rubygems', alert));
  const fp = { ...queued, labels: [{ ...queued.labels[0], verdict: 'FP' }] };
  assert.deepEqual(checkLabels(fp, deltas).fp_returned, [queued.labels[0].key]);
  const shifted = [{ dir: '/ctl/rubygems', emitted: [{ ...alert, line: 540 }] }];
  assert.equal(checkLabels(fp, shifted).fp_returned.length, 1);
  const tp = { ...queued, labels: [{ ...queued.labels[0], verdict: 'TP' }] };
  assert.equal(checkLabels(tp, [{ dir: '/ctl/rubygems', emitted: [] }]).tp_dropped.length, 1);
  assert.deepEqual(checkLabels(tp, deltas).labeled_precision.tp, 1);
});

test('controlFindingDeltas keeps each same-line region and rejects duplicated evidence', () => {
  const findings = columns => sarifFindings({ runs: [{ results: columns.map(startColumn => {
    const location = loc('sample.py', 3);
    Object.assign(location.physicalLocation.region, { startColumn, endLine: 3, endColumn: startColumn + 1 });
    return { ruleId: 'fixture.review', locations: [location] };
  }) }] });
  const before = findings([2, 5]), after = findings([2, 7]);
  assert.deepEqual(controlFindingDeltas(before, after), { added: [after[1]], removed: [before[1]] });
  assert.throws(() => controlFindingDeltas(before, findings([2, 2])), /Duplicate scanner span/);
});

test('precision evidence uses current emitted decisions and reports legacy span conflicts', async () => {
  const { queueLabels, checkLabels, labelKey } = await import('./recall_harness.mjs');
  const common = { rule: 'fixture.review', path: 'sample.py', line: 3, snippet: 'review marker' };
  const first = { ...common, span: [2, 0, 4] }, second = { ...common, span: [6, 0, 8] };
  const historical = { ...common, line: 7, snippet: 'previous review' };
  const delta = { dir: '/ctl/demo', added: [first, second], emitted: [first, second] };
  const label = (repo, alert, verdict) => ({ ...alert, repo, key: labelKey(repo, alert), verdict });
  const review = checkLabels({ labels: [label('demo', first, 'TP'), label('demo', historical, 'FP'),
    label('other', historical, 'TP')] }, [delta]);
  assert.deepEqual([review.emitted, review.judged, review.unreviewed_emitted], [2, 1, 1]);
  assert.deepEqual([review.labeled_precision.tp, review.labeled_precision.fp], [1, 0]);
  assert.deepEqual(review.tp_dropped, []);
  const legacy = label('demo', common, 'FP');
  const ambiguous = checkLabels({ labels: [legacy] }, [delta]);
  assert.deepEqual(ambiguous.ambiguous_labels, [legacy.key]);
  assert.equal(ambiguous.labeled_precision, null);
  assert.equal(queueLabels({ labels: [legacy] }, [delta]).labels.length, 3);
  assert.deepEqual(checkLabels({ labels: [legacy] }, [{ ...delta, emitted: [first] }]).fp_returned, [legacy.key]);
  const swapped = { ...delta, added: [second], removed: [first], emitted: [second] };
  assert.deepEqual(checkLabels({ labels: [legacy] }, [swapped]).ambiguous_labels, [legacy.key]);
  assert.equal(queueLabels({ labels: [legacy] }, [swapped]).labels.length, 2);
  assert.equal(queueLabels({ labels: [legacy] }, [{ dir: delta.dir, added: [second] }]).labels.length, 2);
  assert.notEqual(labelKey('demo', first), labelKey('demo', second));
});


const feederRow = { ghsa: 'GHSA-xxxx-yyyy-zzzz', ecosystem: 'PyPI', cwes: ['CWE-79'],
  published: '2026-09-10', repository: 'example/label-demo', fix: '1'.repeat(40) };

test('priorExposure reads nested evidence and ignores non-JSON notes', () => {
  const root = mkdtempSync(join(tmpdir(), 'recall-prior-'));
  try {
    const nested = join(root, 'archived');
    mkdirSync(nested);
    writeFileSync(join(nested, 'exposed.json'), JSON.stringify([feederRow, feederRow]));
    writeFileSync(join(root, 'note.txt'), 'GHSA-aaaa-bbbb-cccc');
    const exposure = priorExposure([root, join(root, 'missing')]);
    assert.deepEqual([...exposure.ids], [feederRow.ghsa]);
    assert.deepEqual([...exposure.fixes], [feederRow.fix]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('changedFiles and engineCoverage distinguish source loss from analysis failures', () => {
  const changes = changedFiles(Buffer.from('M\0app.py\0A\0new.py\0'));
  assert.throws(() => changedFiles(Buffer.from('M\0app.py')), /Invalid changed-file inventory/);
  assert.throws(() => engineCoverage({ paths: {} }), /Missing engine scan paths/);
  const coverage = engineCoverage({ paths: { scanned: ['./app.py'] },
    errors: [{ type: 'Syntax error', spans: [{ file: './app.py' }] }] });
  const pathError = { type: 'Timeout', path: './app.py' };
  const parseError = { type: 'Syntax error', path: './app.py' };
  for (const errors of [[pathError, parseError], [parseError, pathError]]) {
    assert.equal(engineCoverage({ paths: { scanned: ['./app.py'] }, errors }).problems.get('app.py'), 'engine_error');
  }
  const packet = { path: 'app.py', bytes: 2, sha256: sha256('ok') };
  const scan = { submitted: true, verified: true, coverage, findings: [] };
  const file_coverage = fileCoverage(changes, { packets: { old: [packet], fixed: [packet] },
    scans: { old: scan, fixed: scan }, extensions: ['py'], isTestPath });
  assert.equal(file_coverage.old[0].sha256, packet.sha256);
  assert.equal(file_coverage.old[0].state, 'partial');
  assert.deepEqual(coverageGaps(file_coverage.old), ['app.py']);
  assert.deepEqual(coverageGaps([{ path: 'only-finding.py', state: 'reported_scanned', reason: 'sarif_finding' }]),
    ['only-finding.py']);
  assert.deepEqual(summarizeCoverage([{ file_coverage }, {}]), {
    'partial:parse': 2, 'absent:added_in_fix': 1, 'excluded:no_scored_hunk': 1,
  });
});

test('scanner paths preserve native Windows punctuation and resolve SARIF aliases through the source packets', () => {
  const path = 'nested folder/naïve% name.py';
  assert.equal(scannerPath(String.raw`.\nested folder\naïve% name.py`, true), path);
  assert.equal(scannerPath(String.raw`path\with\literal-slash.py`, false), String.raw`path\with\literal-slash.py`);
  assert.equal(sarifPath(path, new Set([path])), path);
  assert.equal(sarifPath('nested%20folder/na%C3%AFve%25%20name.py', new Set([path])), path);
  assert.throws(() => sarifPath('file://nested/% raw.py', new Set()), URIError);
  assert.equal(sarifPath('nested/file%20name.py', new Set(['nested/file%20name.py'])), 'nested/file%20name.py');
  assert.throws(() => sarifPath('nested/file%20name.py', new Set(['nested/file name.py', 'nested/file%20name.py'])),
    /Ambiguous SARIF source pathname/);
  const raw = path.replaceAll('/', process.platform === 'win32' ? '\\' : '/');
  assert.equal(sarifFindings({ runs: [{ results: [{ ruleId: 'fixture.review', locations: [loc(raw, 1)] }] }] },
    new Set([path]))[0].path, path);
  const coverage = engineCoverage({ paths: { scanned: [raw], skipped: [{ path: raw, reason: 'fixture' }] },
    errors: [{ path: raw, type: 'PartialParsing' }] });
  assert.ok(coverage.scanned.has(path));
  assert.equal(coverage.skipped.get(path), 'fixture');
  assert.equal(coverage.problems.get(path), 'parse');
});

test('observe preserves labels and rejects concurrent updates and corrupt input', () => {
  const root = mkdtempSync(join(tmpdir(), 'recall-labels-'));
  try {
    const controls = join(root, 'controls.json'), labels = join(root, 'labels.json');
    const lock = labels + '.lock';
    writeFileSync(controls, JSON.stringify({ deltas: [] }));
    const run = () => spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'observe', '--controls', controls,
      '--labels', labels], { encoding: 'utf8', timeout: 20000 });
    assert.equal(run().status, 0);
    const initial = readFileSync(labels, 'utf8');
    writeFileSync(lock, '');
    const blocked = run();
    assert.notEqual(blocked.status, 0);
    assert.match(blocked.stderr, /EEXIST/);
    assert.equal(readFileSync(labels, 'utf8'), initial);
    assert.ok(existsSync(lock));
    rmSync(lock);
    writeFileSync(labels, 'invalid JSON');
    assert.notEqual(run().status, 0);
    assert.equal(readFileSync(labels, 'utf8'), 'invalid JSON');
    assert.equal(existsSync(lock), false);
    writeFileSync(labels, initial);
    assert.equal(run().status, 0);
    assert.equal(readFileSync(labels, 'utf8'), initial);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('the feeder coalesces repeated metadata and rejects an ambiguous fix', () => {
  const window = { from: '2026-09-01', to: '2026-10-01' };
  const same = selectCases([feederRow, { ...feederRow }], window);
  assert.equal(same.cases.length, 1);
  assert.deepEqual(same.dropped, { duplicate_case: 1 });
  assert.throws(() => selectCases([feederRow, { ...feederRow, fix: '2'.repeat(40) }], window),
    /Conflicting advisory metadata/);
});

test('manifest validation preserves old seals and refuses changed case bytes', () => {
  const cases = [feederRow];
  const sealed = { cases, cases_sha256: caseDigest(cases) };
  assert.equal(validateRecallManifest(sealed), sealed.cases_sha256);
  assert.equal(validateRecallManifest({ cases, schema: 'factory.heldout-advisory-manifest.v1',
    manifest_sha256: sealed.cases_sha256 }), sealed.cases_sha256);
  assert.throws(() => validateRecallManifest({ ...sealed, cases: [{ ...feederRow, fix: '2'.repeat(40) }] }),
    /case digest differs/);
  assert.throws(() => validateRecallManifest({ cases: [feederRow, feederRow] }), /Duplicate advisory ID/);
  assert.throws(() => validateRecallManifest({ cases }), /case digest differs/);
});

async function feederFixture(run, row = feederRow) {
  const root = mkdtempSync(join(tmpdir(), 'recall-feeder-'));
  try {
    const workdir = join(root, 'work'), caseKey = caseDigest([row]);
    const prepared = join(workdir, 'cases-v4', caseKey);
    const source = join(prepared, 'old', 'sample.py');
    const old = Buffer.from('print("before")\r\n'), fixed = Buffer.from('print("after")\n');
    const diff = Buffer.from([
      'diff --git a/sample.py b/sample.py', '--- a/sample.py', '+++ b/sample.py', '@@ -1 +1 @@',
      '-print("before")', '+print("after")', '',
    ].join('\n'));
    const fingerprints = bytes => [{ path: 'sample.py', bytes: bytes.length, sha256: sha256(bytes) }];
    mkdirSync(join(prepared, 'old'), { recursive: true });
    mkdirSync(join(prepared, 'new'), { recursive: true });
    writeFileSync(source, old);
    writeFileSync(join(prepared, 'new', 'sample.py'), fixed);
    const diffPath = join(prepared, 'diff.patch');
    writeFileSync(diffPath, diff);
    const inventory = Buffer.from('M\0sample.py\0');
    const inventoryPath = join(prepared, 'changes.z');
    writeFileSync(inventoryPath, inventory);
    writeFileSync(join(prepared, 'case.json'), JSON.stringify({ status: 'ready', case_sha256: caseKey,
      revisions: { old: '3'.repeat(40), fixed: row.fix }, diff_sha256: sha256(diff),
      changed_files_sha256: sha256(inventory),
      source_packets: { old: fingerprints(old), fixed: fingerprints(fixed) } }));

    const scanner = join(root, 'scanner.mjs');
    writeFileSync(scanner, [
      "import { appendFileSync, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';",
      "import { basename, dirname } from 'node:path';",
      "if (process.argv.includes('--dump-ast')) {",
      "  const mode = process.env.FIXTURE_PARSER_LIMIT;",
      "  if (mode === 'partial') { console.error('node type: ERROR'); process.exit(3); }",
      "  if (mode === 'fatal' || mode === 'wrong-file') {",
      "    const target = mode === 'fatal' ? process.argv.at(-1) : 'unrelated.py';",
      "    console.error('[00.13][ERROR]: Error: exception Parsing_error.Syntax_error (' + target + ':1:0)');",
      "    process.exit(2);",
      "  }",
      "  if (mode === 'io') { console.error('cannot open source for parsing'); process.exit(2); }",
      "  process.exit(0);",
      "}",
      "const rules = process.argv[process.argv.indexOf('--config') + 1];",
      "const report = process.argv[process.argv.indexOf('--sarif-output') + 1];",
      "const coverageArgs = process.argv.indexOf('--json-output');",
      "const files = (await import('node:fs')).readdirSync('.');",
      "const old = basename(process.cwd()) === 'old';",
      "const control = basename(process.cwd()) === 'control';",
      "const ruleText = readFileSync(rules, 'utf8');",
      "if (old && ruleText.includes('# rules-drift')) appendFileSync(rules, '# drifted during scan\\n');",
      "const driftMarker = dirname(rules) + '/group-drift';",
      "if (old && ruleText.includes('# group-drift ' + basename(dirname(process.cwd()))) && !existsSync(driftMarker)) {",
      "  writeFileSync(driftMarker, '');",
      "  appendFileSync(rules, '# drifted during scan\\n');",
      "}",
      "if (old && ruleText.includes('# manifest-drift')) appendFileSync(dirname(rules) + '/manifest.json', ' ');",
      "if (control && ruleText.includes('# control-source-drift')) appendFileSync('sample.py', '# drifted during scan\\n');",
      "if (control && ruleText.includes('# control-rules-drift')) appendFileSync(rules, '# drifted during scan\\n');",
      "if (control && ruleText.includes('# require-parallel-controls')) {",
      "  const arm = basename(report).startsWith('before') ? 'before' : 'after';",
      "  const other = dirname(rules) + '/parallel-' + (arm === 'before' ? 'after' : 'before');",
      "  if (!process.argv.includes('--jobs=1')) throw Error('Unbounded control worker arguments');",
      "  writeFileSync(dirname(rules) + '/parallel-' + arm, '');",
      "  const deadline = Date.now() + 5000;",
      "  while (!existsSync(other) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));",
      "  if (!existsSync(other)) throw Error('The second control arm did not start');",
      "}",
      "if (control && ruleText.includes('# assert-directory-excludes')) {",
      "  const exclusions = process.argv.flatMap((arg, index) => arg === '--exclude' ? [process.argv[index + 1]] : []);",
      "  if (JSON.stringify(exclusions) !== JSON.stringify(['build/', 'fixture.py/', 'test/'])) throw Error('Wrong scanner directory exclusions');",
      "}",
      "const incomplete = !old && ruleText.includes('# incomplete');",
      "const devTimeout = old && (ruleText.includes('# persistent-case-timeout') || (ruleText.includes('# retry') && basename(dirname(dirname(report))) !== 'serial'));",
      "const recoveredControl = process.argv.includes('--timeout=15') && process.argv.includes('--jobs=1');",
      "const boundedControl = process.argv.includes('--timeout=15');",
      "if (!control && boundedControl && ruleText.includes('# control-first-pass')) throw Error('Control timeout leaked to development scan');",
      "const controlTimeout = control && (ruleText.includes('# persistent-timeout') || (ruleText.includes('# control-timeout') && !recoveredControl) || (ruleText.includes('# control-first-pass') && !boundedControl));",
      "const missingCoverage = old && ruleText.includes('# missing-coverage');",
      "const disputedParse = ruleText.includes(old ? '# candidate-parse' : '# fixed-parse');",
      "const results = old && !missingCoverage && !ruleText.includes('# clean-miss') ? [{ ruleId: 'fixture.review', locations: [{ physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1 } } }] }] : [];",
      "if (results.length && ruleText.includes('# hunk-spans')) {",
      "  const span = (startColumn, endColumn) => ({ ruleId: 'fixture.review', locations: [{ physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1, startColumn, endColumn } } }] });",
      "  results.splice(0, 1, span(1, 4), span(6, 9));",
      "}",
      "if (control && ruleText.includes('# control-missing-path')) results.push({ ruleId: 'fixture.review', locations: [{ physicalLocation: { artifactLocation: { uri: 'missing.py' }, region: { startLine: 1 } } }] });",
      "if (control && ruleText.includes('# reviewed-control')) results.push({ ruleId: 'fixture.review', locations: [{ physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1, startColumn: 1 } } }] });",
      "const issues = incomplete ? [{ descriptor: { id: 'ParseError' }, level: 'error' }] : [];",
      "if (devTimeout || controlTimeout) issues.push({ descriptor: { id: 'Timeout' }, level: 'warning' });",
      "const defaultIgnored = files.filter(path => path === 'ignored.py' || (path === 'candidate-only.py' && ruleText.includes('# candidate-default-ignore')));",
      "const sizeLimit = Number(process.argv.find(arg => arg.startsWith('--max-target-bytes='))?.split('=')[1] ?? 1000000);",
      "const oversized = files.filter(path => path.startsWith('large-') && statSync(path).size > sizeLimit);",
      "const skipped = [...defaultIgnored.map(path => ({ path, reason: 'semgrepignore_patterns_match' })), ...[...(files.includes('skipped.py') ? ['skipped.py'] : []), ...oversized].map(path => ({ path, reason: 'exceeded_size_limit' }))];",
      "if (coverageArgs >= 0 && !missingCoverage) writeFileSync(process.argv[coverageArgs + 1], JSON.stringify({ paths: { scanned: files.filter(path => path !== 'unreported.py' && !skipped.some(item => item.path === path)), skipped }, errors: [...(files.includes('partial.py') ? [{ type: 'Syntax error', path: 'partial.py' }] : []), ...(disputedParse ? [{ type: 'Syntax error', path: 'sample.py' }] : [])] }));",
      "writeFileSync(report, JSON.stringify({ runs: [{ results, invocations: [{ executionSuccessful: !incomplete, toolExecutionNotifications: issues }] }] }));",
      "process.exitCode = incomplete ? 2 : 0;",
    ].join('\n'));
    const profile = join(root, 'profile.json');
    writeFileSync(profile, JSON.stringify({ engine: 'semgrep', commands: [{ argv: ['scanner', scanner, '--config', '{rules}',
      '--sarif-output', '{report}', '{source}'] }] }));
    const rowText = JSON.stringify({ cases: [row], cases_sha256: caseKey }, null, 2) + '\n';
    const manifest = join(root, 'manifest.json');
    writeFileSync(manifest, rowText);
    const baseline = join(root, 'baseline.yml'), candidate = join(root, 'candidate.yml');
    const rules = 'rules:\n  - id: fixture.review\n    metadata:\n      cwe: ["CWE-79"]\n';
    writeFileSync(baseline, rules);
    writeFileSync(candidate, rules + '# incomplete\n');
    await run({ root, workdir, source, manifest, profile, baseline, candidate, diffPath, inventoryPath, old, diff,
      opts: { workdir, profile, opengrep: process.execPath, jobs: 1 } });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test('score and evaluation carry exact bytes and fixed-side diagnostics', () => feederFixture(async fixture => {
  const { root, workdir, manifest, profile, baseline, candidate, old, diff, opts } = fixture;
  const before = await scoreManifest(manifest, baseline, opts);
  assert.equal(before.summary.hunk_hits, 1);
  assert.equal(before.manifest_sha256, sha256(readFileSync(manifest)));
  assert.equal(before.profile_sha256, sha256(readFileSync(profile)));
  assert.equal(before.ruleset_sha256, sha256(readFileSync(baseline)));
  assert.equal(before.cases[0].source_packets.old[0].sha256, sha256(old));
  assert.equal(before.cases[0].diff_sha256, sha256(diff));
  assert.equal(before.cases[0].scan_sides.old.report_sha256,
    sha256(readFileSync(join(workdir, before.scan_directory, feederRow.ghsa, 'old.sarif'))));
  assert.equal(before.cases[0].scan_sides.old.coverage_report_sha256,
    sha256(readFileSync(join(workdir, before.scan_directory, feederRow.ghsa, 'old.sarif.coverage.json'))));
  assert.equal(before.cases[0].file_coverage.fixed[0].reason, 'engine_scan_paths');

  const expectedEngine = {
    executable: basename(process.execPath), executable_sha256: sha256(readFileSync(process.execPath)), version: process.version,
  };
  const scoreOutput = join(root, 'score.json');
  const scoreArgs = ['scripts/recall_harness.mjs', 'score', '--manifest', manifest,
    '--rules', baseline, '--workdir', workdir, '--opengrep', process.execPath, '--jobs', '1'];
  const score = spawnSync(process.execPath, [...scoreArgs, '--profile', profile, '--out', scoreOutput], { encoding: 'utf8' });
  assert.equal(score.status, 0, score.stderr);
  const savedScore = JSON.parse(readFileSync(scoreOutput, 'utf8'));
  assert.deepEqual(savedScore.engine, expectedEngine);
  assert.deepEqual(savedScore.cases[0].source_packets, before.cases[0].source_packets);
  const invalidProfile = join(root, 'invalid-engine-profile.json');
  const rejectedOutput = join(root, 'rejected-score.json');
  writeFileSync(invalidProfile, JSON.stringify({ ...JSON.parse(readFileSync(profile, 'utf8')), tool_version: 'wrong-version' }));
  const rejected = spawnSync(process.execPath, [...scoreArgs, '--profile', invalidProfile, '--out', rejectedOutput], { encoding: 'utf8' });
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /engine version differs from profile/);
  assert.equal(existsSync(rejectedOutput), false);

  const output = join(root, 'evaluation.json');
  const engine = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate', '--manifest', manifest,
    '--baseline', baseline, '--candidate', candidate, '--profile', profile, '--workdir', workdir,
    '--opengrep', process.execPath, '--jobs', '1', '--out', output], { encoding: 'utf8' });
  assert.equal(engine.status, 2, engine.stderr);
  const evaluation = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(evaluation.engine, expectedEngine);
  assert.equal(evaluation.profile_sha256, sha256(readFileSync(profile)));
  assert.equal(evaluation.baseline_sha256, sha256(readFileSync(baseline)));
  assert.equal(evaluation.candidate_sha256, sha256(readFileSync(candidate)));
  const dev = evaluation.dev[0];
  const observed = dev.after_evidence.cases[0];
  assert.equal(evaluation.decision, 'REJECT');
  assert.deepEqual(evaluation.precision_evidence, { state: 'not_run', emitted: 0, adjudicated: 0, unreviewed: 0,
    population_bound: false, review_independence: 'unestablished' });
  assert.deepEqual(evaluation.new_errors, [feederRow.ghsa]);
  assert.deepEqual(evaluation.new_coverage_gaps, []);
  assert.deepEqual(dev.cases[0].matched_hunk_families, ['xss']);
  assert.equal(dev.after.scored, 0);
  assert.equal(dev.after.outcomes.error, 1);
  assert.equal(observed.status, 'incomplete');
  assert.equal(observed.scan_sides.fixed.parse_errors, 1);
  assert.equal(observed.scan_sides.fixed.exit_code, 2);
  assert.equal(observed.file_coverage.fixed[0].sha256, before.cases[0].file_coverage.fixed[0].sha256);
  assert.equal(observed.scan_sides.fixed.report_sha256,
    sha256(readFileSync(join(workdir, dev.after_evidence.scan_directory, feederRow.ghsa, 'new.sarif'))));

  const drifted = structuredClone(before);
  drifted.cases[0].source_packets.old[0].sha256 = '0'.repeat(64);
  assert.match(gate({ dev: [{ before, after: drifted }], controls: [] }).failures[0], /source byte fingerprints differ/);
}));

test('review-alerts exports pinned old-side reports with distinct spans on one line', () => feederFixture(fixture => {
  const { root, workdir, manifest, profile, baseline, old } = fixture;
  writeFileSync(baseline, readFileSync(baseline, 'utf8') + '# hunk-spans\n# candidate-parse\n');
  const saved = join(root, 'score.json');
  const output = join(root, 'review-alerts.json');
  const script = 'scripts/recall_harness.mjs';
  const scored = spawnSync(process.execPath, [script, 'score', '--manifest', manifest,
    '--rules', baseline, '--profile', profile, '--opengrep', process.execPath, '--workdir', workdir, '--out', saved], { encoding: 'utf8' });
  assert.equal(scored.status, 0, scored.stderr);
  const raw = readFileSync(saved);
  assert.equal(JSON.parse(raw).cases[0].file_coverage.old[0].state, 'partial');
  const digest = sha256(raw);
  const run = (pin = digest) => spawnSync(process.execPath, [script, 'review-alerts', '--score', saved,
    '--score-sha256', pin, '--workdir', workdir, '--out', output], { encoding: 'utf8' });
  const exported = run();
  assert.equal(exported.status, 0, exported.stderr);
  assert.deepEqual(JSON.parse(exported.stdout), { alerts: 2, scored_cases: 1, omitted_cases: 0 });
  const records = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(records.map(({ span }) => span), [[1, 0, 4], [6, 0, 9]]);
  for (const alert of records) {
    assert.equal(alert.case, feederRow.ghsa);
    assert.equal(alert.path, 'sample.py');
    assert.equal(alert.rule, 'fixture.review');
    assert.equal(alert.source_sha256, sha256(old));
    assert.equal(alert.rules_sha256, sha256(readFileSync(baseline)));
    assert.equal(alert.on_fix_hunk, true);
  }

  rmSync(output);
  assert.match(run('0'.repeat(64)).stderr, /Review score digest mismatch/);
  const report = join(workdir, JSON.parse(raw).cases[0].captures.old.sarif.path);
  writeFileSync(report, ' ', { flag: 'a' });
  assert.match(run().stderr, /Review SARIF digest differs/);
  assert.equal(existsSync(output), false);
}));

test('evaluation refuses a missing or mismatched engine and ruleset drift without writing a new receipt', () =>
  feederFixture(({ root, workdir, manifest, baseline, candidate, profile }) => {
    const output = join(root, 'unqualified.json');
    const evaluate = (opengrep, ...extra) => spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate', '--manifest', manifest,
      '--baseline', baseline, '--candidate', candidate, '--profile', profile, '--workdir', workdir,
      '--opengrep', opengrep, '--jobs', '1', '--out', output, ...extra], { encoding: 'utf8' });
    const missingLabels = evaluate(process.execPath, '--dir', root, '--labels', join(root, 'missing-labels.json'));
    assert.notEqual(missingLabels.status, 0);
    assert.match(missingLabels.stderr, /ENOENT.*missing-labels/);
    const missing = evaluate(join(root, 'unavailable-engine'));
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /engine executable could not be resolved/);
    const pinned = JSON.parse(readFileSync(profile, 'utf8'));
    pinned.version_argv = ['scanner', '--version'];
    writeFileSync(profile, JSON.stringify({ ...pinned, tool_version: 'unavailable-version' }));
    const mismatch = evaluate(process.execPath);
    assert.notEqual(mismatch.status, 0);
    assert.match(mismatch.stderr, /engine version differs from profile/);
    writeFileSync(profile, JSON.stringify({ ...pinned, tool_version: process.version }));
    writeFileSync(baseline, readFileSync(baseline, 'utf8') + '# rules-drift\n');
    const drift = evaluate(process.execPath);
    assert.notEqual(drift.status, 0);
    assert.match(drift.stderr, /Scan ruleset byte fingerprint differs/);
    assert.equal(existsSync(output), false);
  }));

test('an empty successful scanner result needs old-side coverage to count as a miss', () => feederFixture(async fixture => {
  const { root, workdir, manifest, profile, baseline, candidate, opts } = fixture;
  const before = await scoreManifest(manifest, baseline, opts);
  writeFileSync(candidate, readFileSync(baseline, 'utf8') + '# missing-coverage\n');
  const after = await scoreManifest(manifest, candidate, opts);
  assert.equal(after.cases[0].outcome, 'coverage_incomplete');
  assert.equal(after.cases[0].status, 'incomplete');
  assert.equal(after.summary.outcomes.miss, 0);
  assert.equal(after.summary.hunk_hits_over_registered_cases.cases, 1);
  const verdict = gate({ dev: [{ before, after }], controls: [] });
  assert.deepEqual(verdict.new_coverage_gaps, [feederRow.ghsa]);
  assert.deepEqual(verdict.lost_baseline_hits, [feederRow.ghsa]);
  assert.equal(verdict.decision, 'REJECT');

  const checkpoint = join(root, 'checkpoint.json');
  writeFileSync(checkpoint, JSON.stringify({ schema: 'factory.recall-evaluation.v1', gained: [feederRow.ghsa], dev: [{
    manifest_cases_sha256: before.manifest_cases_sha256, after_evidence: { cases: before.cases },
    cases: [{ ghsa: feederRow.ghsa, before: 'miss', after: 'hit' }],
  }] }));
  const output = join(root, 'checkpoint-evaluation.json');
  const evaluation = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate', '--manifest', manifest,
    '--baseline', candidate, '--candidate', candidate, '--profile', profile, '--workdir', workdir,
    '--opengrep', process.execPath, '--jobs', '1', '--out', output, '--retain-gains-from', checkpoint], { encoding: 'utf8' });
  assert.equal(evaluation.status, 2, evaluation.stderr);
  const replay = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(replay.lost_baseline_hits, []);
  assert.deepEqual(replay.gain_retention, { checkpoint_sha256: sha256(readFileSync(checkpoint)),
    required: 1, retained: 0, lost: [feederRow.ghsa] });
  assert.match(replay.failures[0], /lost 1 checkpoint hit/);
}));

test('evaluation retries both control arms once with a bounded timeout and one scanner worker', () =>
  feederFixture(({ root, workdir, manifest, profile, baseline, candidate }) => {
    const control = join(root, 'control');
    mkdirSync(control);
    writeFileSync(join(control, 'sample.py'), '# benign input\n');
    const rules = readFileSync(baseline, 'utf8');
    const output = join(root, 'paired-control.json');
    const evaluate = (...extra) => {
      const run = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate', '--manifest', manifest,
        '--baseline', baseline, '--candidate', candidate, '--profile', profile, '--workdir', workdir,
        '--opengrep', process.execPath, '--jobs', '1', '--dir', control, '--out', output, ...extra],
      { encoding: 'utf8' });
      return { status: run.status, result: JSON.parse(readFileSync(output, 'utf8')) };
    };
    writeFileSync(candidate, rules + '# control-timeout\n');
    const recovered = evaluate();
    assert.equal(recovered.status, 0);
    assert.equal(recovered.result.decision, 'ACCEPT');
    const [delta] = recovered.result.controls;
    assert.equal(delta.initial_scan_sides.after.timeouts, 1);
    assert.equal(delta.initial_scan_sides.before.timeouts, 0);
    assert.deepEqual(delta.retry_extra_args, ['--timeout=15', '--jobs=1']);
    assert.equal(delta.scan_sides.before.timeouts, 0);
    assert.equal(delta.scan_sides.after.timeouts, 0);
    assert.ok(delta.scan_sides.after.duration_ms >= 0);
    const explicit = evaluate('--extra-arg', '--timeout=5');
    assert.equal(explicit.status, 2);
    assert.deepEqual(explicit.result.controls[0].retry_extra_args, ['--jobs=1']);
    const explicitWorkers = evaluate('--extra-arg', '--jobs=3');
    assert.equal(explicitWorkers.status, 2);
    assert.deepEqual(explicitWorkers.result.controls[0].retry_extra_args, ['--timeout=15']);
    writeFileSync(join(control, 'partial.py'), '# benign parser fixture\n');
    const mixed = evaluate();
    assert.equal(mixed.status, 2);
    const [mixedDelta] = mixed.result.controls;
    assert.equal(mixedDelta.initial_scan_sides?.after.timeouts, 1);
    assert.equal(mixedDelta.scan_sides.after.timeouts, 0);
    assert.equal(mixedDelta.scan_sides.before.other, 0);
    assert.deepEqual(mixedDelta.coverage_gap_delta.shared, [{ path: 'partial.py', reason: 'parse' }]);
    writeFileSync(candidate, rules + '# incomplete\n# control-timeout\n');
    const fatal = evaluate();
    assert.equal(fatal.status, 2);
    assert.equal(fatal.result.controls[0].initial_scan_sides, undefined);
    assert.equal(fatal.result.controls[0].scan_sides.after.failed_exit, true);
    assert.equal(fatal.result.controls[0].scan_sides.after.timeouts, 1);
    writeFileSync(baseline, rules + '# persistent-timeout\n');
    writeFileSync(candidate, rules + '# persistent-timeout\n');
    const persistent = evaluate();
    assert.equal(persistent.status, 2);
    assert.equal(persistent.result.decision, 'REJECT');
    assert.equal(persistent.result.controls[0].scan_sides.before.timeouts, 1);
    assert.equal(persistent.result.controls[0].scan_sides.after.timeouts, 1);
  }));

test('an explicit first-pass timeout covers both control arms and leaves development scans unchanged', () =>
  feederFixture(({ root, workdir, manifest, profile, baseline, candidate }) => {
    const control = join(root, 'control');
    mkdirSync(control);
    writeFileSync(join(control, 'sample.py'), '# benign input\n');
    const rules = readFileSync(baseline, 'utf8') + '# control-first-pass\n';
    writeFileSync(baseline, rules);
    writeFileSync(candidate, rules);
    const output = join(root, 'bounded-control.json');
    const run = (command, args, ...extra) => spawnSync(process.execPath, [
      'scripts/recall_harness.mjs', command, ...args, '--profile', profile, '--workdir', workdir,
      '--opengrep', process.execPath, '--dir', control, '--out', output, ...extra,
    ], { encoding: 'utf8' });
    const evaluation = ['--manifest', manifest, '--baseline', baseline, '--candidate', candidate];
    const result = run('evaluate', evaluation, '--control-timeout', '15');
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(readFileSync(output, 'utf8'));
    assert.equal(receipt.control_timeout_seconds, 15);
    assert.equal(receipt.dev[0].after.hunk_hits, 1);
    assert.deepEqual(receipt.extra_args, []);
    assert.equal(receipt.controls[0].initial_scan_sides, undefined);
    for (const side of Object.values(receipt.controls[0].scan_sides)) {
      assert.equal(side.timeouts, 0);
      assert.equal(side.control_coverage.complete, true);
    }
    const standalone = run('controls', ['--rules', baseline, '--rules', candidate], '--control-timeout', '15');
    assert.equal(standalone.status, 0, standalone.stderr);
    const controlReceipt = JSON.parse(readFileSync(output, 'utf8'));
    assert.equal(controlReceipt.control_timeout_seconds, 15);
    assert.equal(controlReceipt.deltas[0].initial_scan_sides, undefined);
    writeFileSync(baseline, readFileSync(baseline, 'utf8').replace('# control-first-pass', ''));
    writeFileSync(candidate, readFileSync(baseline, 'utf8'));
    const longer = run('evaluate', evaluation, '--control-timeout', '60');
    assert.equal(longer.status, 0, longer.stderr);
    const longerReceipt = JSON.parse(readFileSync(output, 'utf8'));
    assert.equal(longerReceipt.control_timeout_seconds, 60);
    assert.deepEqual(longerReceipt.extra_args, []);
    assert.equal(longerReceipt.dev[0].after.hunk_hits, 1);
    rmSync(output);
    for (const extra of [
      ['--control-timeout', '1800'],
      ['--control-timeout', '15', '--candidate-extra-arg', '--timeout=5'],
      ['--control-timeout', '15', '--control-timeout', '5'],
    ]) {
      const invalid = run('evaluate', evaluation, ...extra);
      assert.equal(invalid.status, 1);
      assert.match(invalid.stderr, /--control-timeout/);
      assert.equal(existsSync(output), false);
    }
  }));

test('parallel control arms share a bounded worker setting and complete the same source scope', () =>
  feederFixture(({ root, workdir, profile, baseline, candidate }) => {
    const control = join(root, 'control');
    mkdirSync(control);
    writeFileSync(join(control, 'sample.py'), '# benign input\n');
    const rules = readFileSync(baseline, 'utf8') + '# require-parallel-controls\n';
    writeFileSync(baseline, rules);
    writeFileSync(candidate, rules);
    const output = join(root, 'parallel-controls.json');
    const run = (workers, ...extra) => spawnSync(process.execPath, [
      'scripts/recall_harness.mjs', 'controls', '--rules', baseline, '--rules', candidate,
      '--profile', profile, '--workdir', workdir, '--opengrep', process.execPath, '--dir', control,
      '--out', output, '--parallel-controls', workers, ...extra,
    ], { encoding: 'utf8', timeout: 20000 });
    const result = run('1');
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(readFileSync(output, 'utf8'));
    assert.equal(receipt.control_parallel_workers_per_arm, 1);
    assert.equal(receipt.deltas[0].initial_scan_sides, undefined);
    for (const side of Object.values(receipt.deltas[0].scan_sides)) {
      assert.equal(side.control_coverage.complete, true);
      assert.equal(side.control_coverage.reported, 1);
    }
    rmSync(output);
    for (const [workers, ...extra] of [
      ['1', '--candidate-extra-arg', '--jobs=1'],
      ['0'],
      [String(Number.MAX_SAFE_INTEGER)],
      ['1', '--parallel-controls', '1'],
    ]) {
      const invalid = run(workers, ...extra);
      assert.equal(invalid.status, 1);
      assert.match(invalid.stderr, /--parallel-controls/);
      assert.equal(existsSync(output), false);
    }
  }));

test('evaluation rejects overlapping manifests before resolving the scanner', () => feederFixture(fixture => {
  const { root, workdir, manifest, profile, baseline, candidate } = fixture;
  const overlap = join(root, 'another-cohort.json');
  const output = join(root, 'overlap-evaluation.json');
  writeFileSync(overlap, readFileSync(manifest));
  const result = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate',
    '--manifest', manifest, '--manifest', overlap, '--baseline', baseline, '--candidate', candidate,
    '--profile', profile, '--workdir', workdir, '--opengrep', join(root, 'missing-scanner'), '--out', output],
  { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Duplicate advisory ID across paired recall cohorts/);
  assert.equal(existsSync(output), false);
  assert.equal(readdirSync(workdir).some(path => path.startsWith('scan-')), false);
}));

test('evaluation refuses a manifest changed during the paired scan', () => feederFixture(fixture => {
  const { root, workdir, manifest, profile, baseline, candidate } = fixture;
  const output = join(root, 'drifted-evaluation.json');
  writeFileSync(candidate, readFileSync(baseline, 'utf8') + '# manifest-drift\n');
  const result = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate',
    '--manifest', manifest, '--baseline', baseline, '--candidate', candidate,
    '--profile', profile, '--workdir', workdir, '--opengrep', process.execPath, '--out', output],
  { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Evaluation manifest bytes changed during scoring/);
  assert.equal(existsSync(output), false);
}));

test('same-size source rewrites and changed diff or inventory bytes cannot yield a measured case', () => feederFixture(async fixture => {
  const { source, manifest, baseline, diffPath, inventoryPath, opts, old, diff } = fixture;
  const rewritten = Buffer.from('print("bEfore")\r\n');
  assert.equal(rewritten.length, old.length);
  assert.notDeepEqual(rewritten, old);
  writeFileSync(source, rewritten);
  const sourceDrift = await scoreManifest(manifest, baseline, opts);
  assert.equal(sourceDrift.summary.scored, 0);
  assert.match(sourceDrift.cases[0].scan_sides.old.detail, /source byte fingerprints differ/);
  assert.equal(sourceDrift.cases[0].file_coverage.old[0].state, 'not_submitted');
  writeFileSync(source, old);
  writeFileSync(diffPath, 'changed\n');
  const diffDrift = await scoreManifest(manifest, baseline, opts);
  assert.equal(diffDrift.summary.scored, 0);
  assert.match(diffDrift.cases[0].detail, /diff byte fingerprint differs/);
  writeFileSync(diffPath, diff);
  writeFileSync(inventoryPath, 'changed\n');
  const inventoryDrift = await scoreManifest(manifest, baseline, opts);
  assert.equal(inventoryDrift.summary.scored, 0);
  assert.match(inventoryDrift.cases[0].detail, /inventory fingerprint differs/);
}));

test('paired controls bind source bytes and stop when input changes or leaves the tree', () => feederFixture(fixture => {
  const { root, workdir, profile, baseline, candidate } = fixture;
  const control = join(root, 'control'), output = join(root, 'controls.json');
  mkdirSync(join(control, '.git'), { recursive: true });
  writeFileSync(join(control, '.git', 'HEAD'), 'ignored checkout metadata\n');
  const original = Buffer.from('# benign café input\r\n');
  writeFileSync(join(control, 'sample.py'), original);
  const stableRules = readFileSync(baseline, 'utf8');
  writeFileSync(candidate, stableRules);

  const controls = () => {
    const run = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'controls', '--rules', baseline,
      '--rules', candidate, '--profile', profile, '--workdir', workdir, '--opengrep', process.execPath,
      '--dir', control, '--out', output], { encoding: 'utf8', timeout: 20000 });
    assert.ok(existsSync(output), run.stderr);
    return { status: run.status, result: JSON.parse(readFileSync(output, 'utf8')).deltas[0] };
  };
  const stable = controls();
  assert.equal(stable.status, 0);
  const sourceTree = { sha256: caseDigest([{ path: 'sample.py', sha256: sha256(original) }]), entries: 1 };
  assert.deepEqual(stable.result.source_tree, sourceTree);
  assert.deepEqual(stable.result.scan_sides.after.control_coverage, {
    complete: true, expected: 1, reported: 1, gaps: [],
  });

  for (const path of ['skipped.py', 'partial.py', 'unreported.py']) {
    writeFileSync(join(control, path), '# owned coverage test');
  }
  const incomplete = controls();
  assert.equal(incomplete.status, 2);
  for (const side of ['before', 'after']) {
    assert.deepEqual(incomplete.result.scan_sides[side].control_coverage, {
      complete: false, expected: 4, reported: 1, gaps: [
        { path: 'partial.py', reason: 'parse' },
        { path: 'skipped.py', reason: 'exceeded_size_limit' },
        { path: 'unreported.py', reason: 'absent_from_engine_paths' },
      ],
    });
  }
  for (const path of ['skipped.py', 'partial.py', 'unreported.py']) rmSync(join(control, path));

  writeFileSync(baseline, stableRules + '# control-source-drift\n');
  const drift = controls();
  assert.equal(drift.status, 2);
  assert.deepEqual(drift.result.source_tree, sourceTree);
  assert.match(drift.result.scan_sides.before.source_error, /source byte fingerprints differ/);
  assert.equal(drift.result.scan_sides.after, null);
  assert.equal(drift.result.initial_scan_sides, undefined);

  writeFileSync(baseline, stableRules);
  writeFileSync(candidate, stableRules + '# control-missing-path\n');
  const missing = controls();
  assert.equal(missing.status, 2);
  assert.match(missing.result.scan_sides.after.detail, /finding path is absent/);

  writeFileSync(candidate, stableRules);
  const linkType = process.platform === 'win32' ? 'junction' : 'dir';
  mkdirSync(join(control, 'target'));
  symlinkSync(join(control, 'target'), join(control, 'inside'), linkType);
  const linked = controls();
  assert.equal(linked.status, 0);
  assert.deepEqual(linked.result.source_tree, { sha256: caseDigest([
    { path: 'inside', link_target: 'target' },
    { path: 'sample.py', sha256: sha256(readFileSync(join(control, 'sample.py'))) },
  ]), entries: 2 });

  symlinkSync(join(control, 'not-built'), join(control, 'generated'), linkType);
  const dangling = controls();
  assert.equal(dangling.status, 0, dangling.result.error);
  assert.deepEqual(dangling.result.source_tree, { sha256: caseDigest([
    { path: 'generated', link_target: 'not-built', link_state: 'dangling' },
    { path: 'inside', link_target: 'target' },
    { path: 'sample.py', sha256: sha256(readFileSync(join(control, 'sample.py'))) },
  ]), entries: 3 });

  const missingSource = join(control, 'missing.py');
  symlinkSync(join(control, 'not-built'), missingSource, linkType);
  const eligible = controls();
  assert.equal(eligible.status, 2);
  assert.match(eligible.result.error, /dangling control link occupies an eligible source path/i);
  rmSync(missingSource);

  const outside = join(root, 'outside');
  mkdirSync(outside);
  symlinkSync(outside, join(control, 'outside'), linkType);
  const escaped = controls();
  assert.equal(escaped.status, 2);
  assert.match(escaped.result.error, /link leaves the source tree/);
  rmSync(join(control, 'outside'));
  symlinkSync(join(outside, 'missing'), join(control, 'broken-external'), linkType);
  const escapedDangling = controls();
  assert.equal(escapedDangling.status, 2);
  assert.match(escapedDangling.result.error, /link leaves the source tree/);
}));

test('reviewed control gate requires a complete, source-bound population', () => feederFixture(fixture => {
  const { root, workdir, profile, manifest, baseline, candidate } = fixture;
  const control = join(root, 'control'), output = join(root, 'reviewed.json'), labels = join(root, 'labels.json');
  mkdirSync(control);
  writeFileSync(join(control, 'sample.py'), '# owned review control');
  const stableRules = readFileSync(baseline, 'utf8') + '# reviewed-control\n';
  for (const rule of [baseline, candidate]) writeFileSync(rule, stableRules);
  const invoke = (command, ...args) => spawnSync(process.execPath,
    ['scripts/recall_harness.mjs', command, ...args], { encoding: 'utf8', timeout: 20000 });
  const evaluate = (...args) => {
    const run = invoke('evaluate', '--manifest', manifest, '--baseline', baseline, '--candidate', candidate,
      '--profile', profile, '--opengrep', process.execPath, '--workdir', workdir, '--jobs', '1',
      '--dir', control, '--out', output, '--require-reviewed-controls', 'true', ...args);
    assert.equal(run.stderr, '');
    return [run.status, JSON.parse(readFileSync(output, 'utf8'))];
  };
  const [initial, pending] = evaluate();
  assert.equal(initial, 2);
  assert.equal(pending.precision_evidence.state, 'unreviewed', JSON.stringify(pending.controls[0]));
  assert.equal(pending.controls[0].added.length, 0);
  assert.equal(pending.controls[0].emitted.length, 1);
  assert.equal(pending.controls[0].emitted[0].snippet, undefined);
  assert.equal(invoke('observe', '--controls', output, '--labels', labels).status, 0);
  const sheet = JSON.parse(readFileSync(labels, 'utf8'));
  assert.equal(sheet.control_population_sha256, pending.control_population_sha256);
  assert.equal(sheet.labels.length, 1);
  sheet.labels[0].verdict = 'TP';
  writeFileSync(labels, JSON.stringify(sheet));
  const [qualified, accepted] = evaluate('--labels', labels);
  assert.equal(qualified, 0);
  assert.equal(accepted.precision_evidence.adjudicated, 1);
  assert.equal(accepted.precision_evidence.review_independence, 'unestablished');

  writeFileSync(join(control, 'sample.py'), '# revised owned review control');
  const [stale, rejected] = evaluate('--labels', labels);
  assert.equal(stale, 2);
  assert.equal(rejected.precision_evidence.population_bound, false);
  assert.equal(invoke('observe', '--controls', output, '--labels', labels).status, 0);
  const refreshed = JSON.parse(readFileSync(labels, 'utf8'));
  assert.equal(refreshed.labels.length, 1);
  assert.equal(refreshed.labels[0].verdict, null);
  assert.equal(refreshed.archived_labels[sheet.control_population_sha256][0].verdict, 'TP');
}));

test('a successful serial retry keeps the original timed-out report fingerprint', () => feederFixture(async fixture => {
  const { workdir, manifest, baseline, opts } = fixture;
  writeFileSync(baseline, readFileSync(baseline, 'utf8') + '# retry\n');
  const result = await scoreManifest(manifest, baseline, opts);
  const row = result.cases[0];
  const root = join(workdir, result.scan_directory);
  assert.equal(row.outcome, 'hit');
  assert.equal(row.retried_serially, true);
  assert.equal(row.initial_scan_sides.old.timeouts, 1);
  assert.equal(row.scan_sides.old.timeouts, 0);
  assert.equal(row.initial_scan_sides.old.report_sha256, sha256(readFileSync(join(root, feederRow.ghsa, 'old.sarif'))));
  assert.equal(row.scan_sides.old.report_sha256, sha256(readFileSync(join(root, 'serial', feederRow.ghsa, 'old.sarif'))));
  assert.notEqual(row.initial_captures.old.sarif.path, row.captures.old.sarif.path);
  assert.equal(row.initial_captures.old.source_root, row.captures.old.source_root);
  for (const capture of [row.initial_captures.old, row.captures.old, row.captures.fixed]) {
    assert.equal(existsSync(join(workdir, capture.source_root)), true);
    for (const report of [capture.sarif, capture.native_report]) {
      assert.doesNotMatch(report.path, /\\/);
      assert.equal(sha256(readFileSync(join(workdir, report.path))), report.sha256);
    }
  }
}));

test('a fixed parser probe classifies only reproduced engine limits', () => feederFixture(fixture => {
  const { root, workdir, manifest, profile, baseline, candidate } = fixture;
  writeFileSync(candidate, readFileSync(baseline, 'utf8') + '# candidate-parse\n');
  const output = join(root, 'probe-evaluation.json');
  for (const [mode, state] of [['parsed', 'parsed'], ['partial', 'parse_limited'],
    ['fatal', 'syntax_error'], ['io', 'unresolved'], ['wrong-file', 'unresolved']]) {
    const reproduced = state === 'parse_limited';
    const run = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate', '--baseline', baseline,
      '--candidate', candidate, '--manifest', manifest, '--profile', profile, '--workdir', workdir,
      '--opengrep', process.execPath, '--out', output, '--probe-coverage', 'true'],
    { encoding: 'utf8', timeout: 20000, env: { ...process.env, FIXTURE_PARSER_LIMIT: mode } });
    assert.ok(existsSync(output), run.stderr);
    const verdict = JSON.parse(readFileSync(output, 'utf8'));
    assert.equal(verdict.decision, reproduced ? 'ACCEPT' : 'REJECT');
    assert.deepEqual(verdict.new_coverage_gaps, reproduced ? [] : [feederRow.ghsa]);
    const evidence = verdict.dev[0].after_evidence.cases[0];
    assert.deepEqual(evidence.parser_probe.old.confirmed_limits, reproduced ? ['sample.py'] : []);
    assert.equal(evidence.file_coverage.old[0].state, 'partial');
    const observation = evidence.parser_probe.old.observations[0];
    assert.equal(observation.state, state, mode);
    assert.equal(observation.sha256, evidence.source_packets.old[0].sha256);
  }
}));

test('evaluate preserves a raw lost hit with two pinned all-FP spans on the same line', () => feederFixture(async fixture => {
  const { root, workdir, manifest, profile, baseline, candidate, opts } = fixture;
  writeFileSync(baseline, readFileSync(baseline, 'utf8') + '# hunk-spans\n');
  writeFileSync(candidate, readFileSync(baseline, 'utf8') + '# clean-miss\n');
  const before = await scoreManifest(manifest, baseline, opts);
  const prior = before.cases[0], expected = prior.ghsa;
  assert.deepEqual(prior.hunk_spans, [[1, 0, 4], [6, 0, 9]]);
  const score = { schema: 'factory.recall-evaluation.v1', candidate_sha256: before.ruleset_sha256,
    engine: { executable_sha256: sha256(readFileSync(process.execPath)) }, gained: [expected],
    dev: [{ manifest_cases_sha256: before.manifest_cases_sha256, after_evidence: before,
      cases: [{ ghsa: expected, before: 'miss', after: 'hit',
        hunk_findings: prior.hunk_findings, hunk_spans: prior.hunk_spans }] }] };
  const adjudication = { schema: 'factory.adjudicated-precision.v1', cohort: 'owned (spent)',
    candidate: `owned (ruleset ${before.ruleset_sha256.slice(0, 8)})`,
    rows: prior.hunk_findings.map(([rule, file, line], index) => ({ item: `owned-${index}`,
      repository_case: `example/label-demo ${expected}`, rule, file, line, on_fix_hunk: true, final: 'FP',
      span: prior.hunk_spans[index], source_sha256: prior.source_packets.old[0].sha256 })) };
  const save = (name, value) => {
    const bytes = JSON.stringify(value);
    writeFileSync(join(root, name), bytes);
    return { path: name, sha256: sha256(bytes) };
  };
  const scoreRef = save('score.json', score);
  const plan = save('loss-plan.json', { schema: 'factory.recall-adjudicated-losses.v1', score: scoreRef,
    adjudication: save('adjudication.json', adjudication), manifest_cases_sha256: before.manifest_cases_sha256 });
  const output = join(root, 'adjudicated-evaluation.json');
  const run = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate', '--baseline', baseline,
    '--candidate', candidate, '--manifest', manifest, '--profile', profile, '--workdir', workdir,
    '--opengrep', process.execPath, '--out', output, '--adjudicated-losses', join(root, plan.path),
    '--retain-gains-from', join(root, scoreRef.path)], { encoding: 'utf8', timeout: 20000 });
  assert.equal(run.status, 0, run.stderr);
  const report = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(report.raw_lost_baseline_hits, [expected]);
  assert.deepEqual(report.lost_fp_only, [expected]);
  assert.deepEqual(report.lost_baseline_hits, []);
  assert.deepEqual(report.dev[0].cases[0].baseline_hunk_findings, prior.hunk_findings);
  assert.deepEqual(report.dev[0].cases[0].baseline_hunk_spans, prior.hunk_spans);
  assert.deepEqual(report.gain_retention.lost_fp_only, [expected]);
  assert.equal(report.gain_retention.retained, 0);
  const retentionRules = join(root, 'retention.yml');
  writeFileSync(retentionRules, readFileSync(baseline, 'utf8') + '# distinct checkpoint rules\n');
  const retentionScore = await scoreManifest(manifest, retentionRules, opts);
  assert.notEqual(retentionScore.ruleset_sha256, before.ruleset_sha256);
  assert.deepEqual(retentionScore.cases[0].hunk_spans, prior.hunk_spans);
  const checkpoint = save('retention-score.json', {
    ...score, candidate_sha256: retentionScore.ruleset_sha256,
    dev: [{ ...score.dev[0], after_evidence: retentionScore }],
  });
  const gainAdjudication = { ...adjudication, candidate: `owned (ruleset ${retentionScore.ruleset_sha256.slice(0, 8)})` };
  const gainPlan = name => save(`gain-plan-${name}.json`, {
    schema: 'factory.recall-adjudicated-losses.v1', score: checkpoint,
    adjudication: save(`gain-adjudication-${name}.json`, gainAdjudication),
    manifest_cases_sha256: retentionScore.manifest_cases_sha256,
  });
  const args = ['scripts/recall_harness.mjs', 'evaluate', '--baseline', baseline,
    '--candidate', candidate, '--manifest', manifest, '--profile', profile, '--workdir', workdir,
    '--opengrep', process.execPath, '--out', output, '--adjudicated-losses', join(root, plan.path),
    '--retain-gains-from', join(root, checkpoint.path)];
  const evaluate = (selected) => spawnSync(process.execPath,
    [...args, '--gain-adjudicated-losses', join(root, selected.path)], { encoding: 'utf8', timeout: 20000 });

  const mismatch = evaluate(plan);
  assert.notEqual(mismatch.status, 0);
  assert.match(mismatch.stderr, /exact retention checkpoint/);
  const independent = evaluate(gainPlan('exact'));
  assert.equal(independent.status, 0, independent.stderr);
  const separate = JSON.parse(readFileSync(output, 'utf8'));
  assert.equal(separate.max_control_increase, 0);
  assert.deepEqual(separate.lost_fp_only, [expected]);
  assert.deepEqual(separate.gain_retention.lost_fp_only, [expected]);
  assert.equal(separate.adjudicated_loss_basis.score_sha256, scoreRef.sha256);
  assert.equal(separate.gain_retention.adjudicated_loss_basis.score_sha256, checkpoint.sha256);
  assert.equal(separate.gain_retention.adjudicated_loss_basis.exact_spans_and_source, true);
  gainAdjudication.rows = adjudication.rows.map(({ source_sha256, ...row }) => row);
  const unbound = evaluate(gainPlan('unpinned'));
  assert.equal(unbound.status, 2, unbound.stderr);
  const blocked = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(blocked.lost_fp_only, [expected]);
  assert.deepEqual(blocked.gain_retention.lost, [expected]);
  const invalidLimit = spawnSync(process.execPath, [...args, '--max-control-increase', 'NaN'],
    { encoding: 'utf8', timeout: 20000 });
  assert.notEqual(invalidLimit.status, 0);
  assert.match(invalidLimit.stderr, /one safe integer/);
}, { ...feederRow, ghsa: 'GHSA-2345-6789-cfgh' }));

test('declared control directories are excluded and unrelated missing paths remain coverage gaps', () => feederFixture(fixture => {
  const { root, workdir, profile, baseline } = fixture;
  const control = join(root, 'control'), output = join(root, 'controls.json');
  const run = () => spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'controls', '--rules', baseline,
    '--rules', baseline, '--profile', profile, '--workdir', workdir, '--opengrep', process.execPath,
    '--dir', control, '--out', output, '--control-exclude', 'test', '--control-exclude', 'build',
    '--control-exclude', 'fixture.py'],
  { encoding: 'utf8', timeout: 20000 });
  writeFileSync(baseline, readFileSync(baseline, 'utf8') + '# assert-directory-excludes\n');
  for (const dir of ['build', 'test']) {
    mkdirSync(join(control, dir), { recursive: true });
    writeFileSync(join(control, dir, 'sample.py'), '# owned excluded control');
  }
  writeFileSync(join(control, 'sample.py'), '# owned in-scope control');
  writeFileSync(join(control, 'fixture.py'), '# a file of the same name is still eligible');
  const success = run();
  assert.equal(success.status, 0, success.stderr);
  const receipt = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(receipt.control_excluded_directories, ['build', 'fixture.py', 'test']);
  for (const side of Object.values(receipt.deltas[0].scan_sides)) {
    assert.equal(side.control_coverage.expected, 2);
    assert.deepEqual(side.control_coverage.excluded.map(item => item.path), ['build/sample.py', 'test/sample.py']);
  }
  writeFileSync(join(control, 'unreported.py'), '# missing coverage outside exclusions');
  assert.equal(run().status, 2);
  const failed = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(failed.deltas[0].scan_sides.after.control_coverage.gaps, [
    { path: 'unreported.py', reason: 'absent_from_engine_paths' },
  ]);
}));

test('paired controls record only shared scanner ignores and keep candidate skips visible', () => feederFixture(fixture => {
  const { root, workdir, profile, baseline, candidate } = fixture;
  const control = join(root, 'control'), output = join(root, 'control-scope.json');
  mkdirSync(control);
  for (const file of ['sample.py', 'ignored.py', 'candidate-only.py', 'helper_spec.rb', 'arithmetic_test.go']) {
    writeFileSync(join(control, file), '# owned control fixture\n');
  }
  writeFileSync(candidate, readFileSync(baseline, 'utf8') + '# candidate-default-ignore\n');
  const run = rules => spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'controls', '--rules', baseline,
    '--rules', rules, '--profile', profile, '--workdir', workdir, '--opengrep', process.execPath,
    '--dir', control, '--out', output], { encoding: 'utf8', timeout: 20000 });
  const stable = run(baseline);
  assert.equal(stable.status, 0, stable.stderr);
  const { deltas: [original] } = JSON.parse(readFileSync(output, 'utf8'));
  const exclusions = [
    { path: 'arithmetic_test.go', reason: 'test_path' },
    { path: 'helper_spec.rb', reason: 'test_path' },
    { path: 'ignored.py', reason: 'shared_semgrepignore_patterns_match' },
  ];
  for (const side of Object.values(original.scan_sides)) {
    assert.deepEqual(side.control_coverage, { complete: true, expected: 2, reported: 2, gaps: [], excluded: exclusions });
  }
  assert.match(original.control_scope_sha256, /^[0-9a-f]{64}$/);
  assert.equal(run(candidate).status, 2);
  const { deltas: [rejected] } = JSON.parse(readFileSync(output, 'utf8'));
  assert.equal(rejected.control_scope_sha256, original.control_scope_sha256);
  assert.deepEqual(rejected.scan_sides.before.control_coverage.gaps, []);
  assert.deepEqual(rejected.scan_sides.after.control_coverage.gaps, [
    { path: 'candidate-only.py', reason: 'semgrepignore_patterns_match' },
  ]);
  assert.deepEqual(rejected.scan_sides.after.control_coverage.excluded, exclusions);
  assert.deepEqual(rejected.coverage_gap_delta, { state: 'COMPARED', shared: [], baseline_only: [],
    candidate_only: [{ path: 'candidate-only.py', reason: 'semgrepignore_patterns_match' }] });

  writeFileSync(join(control, 'partial.py'), '# owned parser control\n');
  assert.equal(run(baseline).status, 2);
  const { deltas: [shared] } = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(shared.coverage_gap_delta, { state: 'COMPARED',
    shared: [{ path: 'partial.py', reason: 'parse' }], baseline_only: [], candidate_only: [] });

  writeFileSync(baseline, readFileSync(baseline, 'utf8') + '# persistent-timeout\n');
  assert.equal(run(baseline).status, 2);
  const { deltas: [timeout] } = JSON.parse(readFileSync(output, 'utf8'));
  assert.equal(timeout.scan_sides.before.timeouts, 1);
  assert.equal(timeout.scan_sides.after.timeouts, 1);
  for (const side of Object.values(timeout.scan_sides)) {
    assert.deepEqual(side.control_coverage.excluded, exclusions);
    assert.deepEqual(side.control_coverage.gaps, [{ path: 'partial.py', reason: 'parse' }]);
  }
}));

test('controls scan bounded larger files on both arms and preserve explicit size limits', () => feederFixture(fixture => {
  const { root, workdir, profile, baseline } = fixture;
  const control = join(root, 'control'), output = join(root, 'sizes.json');
  mkdirSync(control);
  writeFileSync(join(control, 'sample.py'), 'VALUE = 1\n');
  writeFileSync(join(control, 'large-table.py'), Buffer.alloc(1_428_813, 32));
  const run = (...extra) => {
    const result = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'controls',
      '--rules', baseline, '--rules', baseline, '--profile', profile, '--workdir', workdir,
      '--opengrep', process.execPath, '--dir', control, '--out', output, ...extra],
    { encoding: 'utf8', timeout: 30000 });
    return { status: result.status, delta: JSON.parse(readFileSync(output, 'utf8')).deltas[0] };
  };
  const recovered = run();
  assert.equal(recovered.status, 0);
  assert.equal(recovered.delta.max_target_bytes, 1_428_813);
  for (const side of Object.values(recovered.delta.scan_sides)) {
    assert.deepEqual(side.control_coverage, { complete: true, expected: 2, reported: 2, gaps: [] });
  }
  const explicit = run('--extra-arg', '--max-target-bytes=1000000');
  assert.equal(explicit.status, 2);
  assert.equal(explicit.delta.max_target_bytes, undefined);
  writeFileSync(join(control, 'large-over-budget.py'), Buffer.alloc(2_097_153, 32));
  const beyond = run();
  assert.equal(beyond.status, 2);
  for (const side of Object.values(beyond.delta.scan_sides)) {
    assert.deepEqual(side.control_coverage.gaps, [{ path: 'large-over-budget.py', reason: 'exceeded_size_limit' }]);
  }
}));

test('control checkpoints resume only while the final and retry reports still match', () => feederFixture(fixture => {
  const { root, workdir, profile, baseline, candidate } = fixture;
  const control = join(root, 'control'), output = join(root, 'controls.json');
  const checkpoint = join(root, 'control-checkpoints');
  mkdirSync(control);
  writeFileSync(join(control, 'sample.py'), 'VALUE = 1\n');
  writeFileSync(candidate, readFileSync(baseline, 'utf8') + '# control-timeout\n');
  const run = () => {
    const result = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'controls',
      '--rules', baseline, '--rules', candidate, '--profile', profile, '--workdir', workdir,
      '--opengrep', process.execPath, '--dir', control, '--out', output, '--checkpoint-dir', checkpoint],
    { encoding: 'utf8', timeout: 30000 });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(readFileSync(output, 'utf8')).deltas[0];
  };
  const fresh = run();
  assert.equal(fresh.initial_scan_sides.after.timeouts, 1);
  assert.equal(run().resumed_from_checkpoint, true);
  const reports = readdirSync(workdir, { recursive: true });
  const coverage = reports.find(path => path.endsWith('after-retry.sarif.coverage.json'));
  assert.ok(coverage);
  writeFileSync(join(workdir, coverage), '{}');
  const rescanned = run();
  assert.equal(rescanned.resumed_from_checkpoint, undefined);
  assert.equal(rescanned.control_scope_sha256, fresh.control_scope_sha256);
  const firstReport = rescanned.initial_scan_sides.after.reports.sarif.path;
  rmSync(join(workdir, firstReport));
  assert.equal(run().resumed_from_checkpoint, undefined);
  assert.equal(run().resumed_from_checkpoint, true);
}));

test('standalone controls bind the scanner and reject rules changed during scanning', () => feederFixture(fixture => {
  const { root, workdir, profile, baseline, candidate, manifest } = fixture;
  const control = join(root, 'control'), output = join(root, 'controls.json');
  const checkpoint = join(root, 'control-checkpoints');
  mkdirSync(control);
  writeFileSync(join(control, 'sample.py'), 'VALUE = 1\n');
  writeFileSync(profile, JSON.stringify(JSON.parse(readFileSync(profile, 'utf8')), null, 2) + '\n');
  const run = () => spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'controls', '--rules', baseline,
    '--rules', candidate, '--profile', profile, '--workdir', workdir, '--opengrep', process.execPath,
    '--dir', control, '--out', output, '--checkpoint-dir', checkpoint], { encoding: 'utf8', timeout: 30000 });

  const original = readFileSync(baseline);
  const drifting = Buffer.concat([original, Buffer.from('# control-rules-drift\n')]);
  writeFileSync(candidate, drifting);
  const drift = run();
  assert.notEqual(drift.status, 0, 'changed rules were accepted');
  assert.match(drift.stderr, /ruleset byte fingerprint differs/);
  assert.equal(existsSync(output), false);
  assert.equal(existsSync(checkpoint) ? readdirSync(checkpoint).length : 0, 0);

  writeFileSync(candidate, drifting);
  const evaluationOutput = join(root, 'evaluation.json');
  const evaluation = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate', '--manifest', manifest,
    '--baseline', baseline, '--candidate', candidate, '--profile', profile, '--workdir', workdir,
    '--opengrep', process.execPath, '--jobs', '1', '--dir', control, '--out', evaluationOutput],
  { encoding: 'utf8', timeout: 30000 });
  assert.notEqual(evaluation.status, 0);
  assert.match(evaluation.stderr, /ruleset byte fingerprint differs/);
  assert.equal(existsSync(evaluationOutput), false);

  writeFileSync(candidate, original);
  const stable = run();
  assert.equal(stable.status, 0, stable.stderr);
  const receipt = JSON.parse(readFileSync(output, 'utf8'));
  assert.equal(receipt.engine.version, process.version);
  assert.equal(receipt.engine.executable_sha256, sha256(readFileSync(process.execPath)));
  assert.equal(receipt.profile_sha256, sha256(readFileSync(profile)));
  assert.equal(receipt.before_sha256, sha256(readFileSync(baseline)));
  assert.equal(receipt.after_sha256, sha256(original));

  rmSync(output);
  writeFileSync(profile, JSON.stringify({ ...JSON.parse(readFileSync(profile, 'utf8')), tool_version: 'wrong-version' }));
  const mismatchedVersion = run();
  assert.notEqual(mismatchedVersion.status, 0);
  assert.match(mismatchedVersion.stderr, /engine version differs from profile/);
  assert.equal(existsSync(output), false);
}));


test('case publication retries transient Windows locks and preserves a competing receipt', async t => {
  const root = mkdtempSync(join(tmpdir(), 'recall-publish-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const stage = join(root, 'staged'), destination = join(root, 'committed');
  mkdirSync(stage);
  writeFileSync(join(stage, 'case.json'), 'staged');
  const failed = code => Object.assign(new Error(code), { code });
  let attempts = 0;
  const rename = (source, target) => {
    if (++attempts === 1) throw failed('EPERM');
    renameSync(source, target);
  };
  await publishPreparedCase(stage, destination, { rename, platform: 'win32' });
  assert.equal(attempts, 2);
  assert.equal(readFileSync(join(destination, 'case.json'), 'utf8'), 'staged');

  let competitors = 0;
  await publishPreparedCase(stage, destination, { platform: 'win32', rename: () => {
    competitors++;
    throw failed('EEXIST');
  } });
  assert.equal(competitors, 1);
  assert.equal(readFileSync(join(destination, 'case.json'), 'utf8'), 'staged');

  for (const [platform, code] of [['linux', 'EPERM'], ['win32', 'EXDEV']]) {
    let errors = 0;
    await assert.rejects(publishPreparedCase(stage, join(root, 'missing'), { platform, rename: () => {
      errors++;
      throw failed(code);
    } }), { code });
    assert.equal(errors, 1);
  }

  let locks = 0;
  await assert.rejects(publishPreparedCase(stage, join(root, 'missing'), { platform: 'win32', rename: () => {
    locks++;
    throw failed('EACCES');
  } }), { code: 'EACCES' });
  assert.equal(locks, 4);
});

test('local Git source bytes survive preparation, scanning, and the reported packet inventory', () =>
  feederFixture(async ({ root, workdir, manifest, baseline, profile }) => {
    const scanWorkdir = process.platform === 'win32'
      ? join(root, 'w'.repeat(Math.max(1, 170 - root.length - 1))) : workdir;
    const repository = join(root, 'local-repo');
    mkdirSync(repository);
    const git = (...args) => execFileSync('git', ['-C', repository, ...args], { encoding: 'utf8' }).trim();
    const commit = message => git('-c', 'user.name=Factory Test', '-c', 'user.email=test@example.invalid',
      '-c', 'commit.gpgsign=false', 'commit', '-qm', message);
    git('init', '-q');
    git('config', 'core.autocrlf', 'false');
    const beforeBytes = Buffer.from('print("before")\r\n');
    const afterBytes = Buffer.from('print("after")\n');
    const longBefore = Buffer.from('# café\r\n'.repeat(40000));
    const longAfter = Buffer.concat([longBefore, Buffer.from('# updated\n')]);
    const source = join(repository, 'sample.py');
    writeFileSync(source, beforeBytes);
    writeFileSync(join(repository, 'long file.py'), longBefore);
    writeFileSync(join(repository, 'empty after.py'), 'before\n');
    for (const file of ['retired.py', 'clean file.py', 'View.vue', 'skipped.py', 'partial.py', 'unreported.py']) {
      writeFileSync(join(repository, file), 'before\n');
    }
    git('add', '.');
    commit('old label');
    const parent = git('rev-parse', 'HEAD');
    writeFileSync(source, afterBytes);
    writeFileSync(join(repository, 'long file.py'), longAfter);
    writeFileSync(join(repository, 'empty after.py'), '');
    for (const file of ['new.py', 'clean file.py', 'View.vue', 'skipped.py', 'partial.py', 'unreported.py']) {
      writeFileSync(join(repository, file), 'after\n');
    }
    git('rm', 'retired.py');
    git('add', '.');
    commit('new label');
    const fix = git('rev-parse', 'HEAD');
    const current = { ...feederRow, fix };
    writeFileSync(manifest, JSON.stringify({ cases: [current], cases_sha256: caseDigest([current]) }));
    const out = join(root, 'score.json');
    const override = 'url.' + pathToFileURL(repository).href + '.insteadOf';
    const result = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'score', '--manifest', manifest,
      '--rules', baseline, '--profile', profile, '--workdir', scanWorkdir, '--opengrep', process.execPath,
      '--jobs', '1', '--out', out], { encoding: 'utf8', timeout: 20000, env: { ...process.env,
        GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: override,
        GIT_CONFIG_VALUE_0: 'https://github.com/example/label-demo.git', GIT_ALLOW_PROTOCOL: 'file' } });
    assert.equal(result.status, 0, result.stderr);
    const scored = JSON.parse(readFileSync(out, 'utf8'));
    const captured = scored.cases[0];
    const directory = join(scanWorkdir, 'cases-v4', caseDigest([current]));
    assert.equal(captured.status, 'scored', captured.detail);
    assert.equal(scored.summary.scored, 1);
    assert.equal(scored.summary.hunk_hits, 1);
    assert.deepEqual(captured.revisions, { old: parent, fixed: fix });
    if (process.platform === 'win32') assert.equal(captured.scan_sides.old.windows_source_alias, true);
    assert.deepEqual(readFileSync(join(directory, 'old', 'sample.py')), beforeBytes);
    assert.deepEqual(readFileSync(join(directory, 'new', 'sample.py')), afterBytes);
    assert.deepEqual(readFileSync(join(directory, 'old', 'long file.py')), longBefore);
    assert.deepEqual(readFileSync(join(directory, 'new', 'long file.py')), longAfter);
    assert.equal(readFileSync(join(directory, 'new', 'empty after.py')).length, 0);
    const coverage = (side, path) => captured.file_coverage[side].find(row => row.path === path);
    assert.equal(coverage('old', 'sample.py').sha256, sha256(beforeBytes));
    assert.equal(coverage('fixed', 'sample.py').sha256, sha256(afterBytes));
    assert.equal(coverage('fixed', 'long file.py').sha256, sha256(longAfter));
    assert.equal(coverage('fixed', 'empty after.py').sha256, sha256(''));
    assert.equal(captured.diff_sha256, sha256(readFileSync(join(directory, 'diff.patch'))));
    assert.equal(captured.changed_files_sha256, sha256(readFileSync(join(directory, 'changes.z'))));
    assert.equal(coverage('old', 'new.py').reason, 'added_in_fix');
    assert.equal(coverage('fixed', 'retired.py').reason, 'deleted_in_fix');
    assert.equal(coverage('old', 'View.vue').reason, 'outside_ecosystem_language');
    assert.equal(coverage('old', 'clean file.py').reason, 'engine_scan_paths');
    assert.equal(coverage('old', 'skipped.py').reason, 'exceeded_size_limit');
    assert.equal(coverage('old', 'partial.py').state, 'partial');
    assert.equal(coverage('old', 'unreported.py').state, 'unreported');
  }));

test('parse warnings stay diagnostics; timeouts and failed scans make a case incomplete', async () => {
  const { outcomeOf } = await import('./recall_harness.mjs');
  const side = notes => ({ status: 'scored', hunk_hit: true, scan_sides: { old: notes, fixed: { timeouts: 0 } } });
  assert.equal(outcomeOf(side({ timeouts: 0, parse_errors: 2, other: 0 })), 'hit');
  assert.equal(outcomeOf(side({ timeouts: 1, parse_errors: 0, other: 0 })), 'timeout');
  assert.equal(outcomeOf(side({ timeouts: 0, parse_errors: 0, other: 1 })), 'error');
  assert.equal(outcomeOf(side({ timeouts: 0, failed_exit: true })), 'error');
});

test('scannable scope widens file types; the primary scope stays the ecosystem language', async () => {
  const { scopeExtensions, SCANNABLE_EXTENSIONS } = await import('./recall_harness.mjs');
  assert.deepEqual(scopeExtensions('PyPI'), ['py']);
  assert.equal(scopeExtensions('PyPI', 'scannable'), SCANNABLE_EXTENSIONS);
  assert.ok(SCANNABLE_EXTENSIONS.includes('ts') && SCANNABLE_EXTENSIONS.includes('rs') && !SCANNABLE_EXTENSIONS.includes('svelte'));
});

test('a control incomplete on both rulesets is rejected even with matching counts', async () => {
  const { gate } = await import('./recall_harness.mjs');
  const result = rows => ({ cases: rows, summary: { fix_side_residual_alerts: 0, hunk_hits: 0 } });
  const pair = { before: result([]), after: result([]) };
  assert.equal(gate({ dev: [pair], controls: [{ dir: 'control', before: 4, after: 4, incomplete_on_both: 'timeout' }] }).decision, 'REJECT');
  assert.equal(gate({ dev: [pair], controls: [{ dir: 'pdf.js', error: 'Control scan incomplete' }] }).decision, 'REJECT');
});

test('a resumed score reuses only exactly matching completed cases', () => feederFixture(async fixture => {
  const { root, manifest, baseline, opts } = fixture;
  const checkpointDir = join(root, 'checkpoints');
  const resumable = { ...opts, 'checkpoint-dir': checkpointDir };
  const fresh = await scoreManifest(manifest, baseline, resumable);
  assert.deepEqual(fresh.resumed_cases, []);
  assert.equal(readdirSync(checkpointDir).length, 1);
  // A second run after an interruption reuses the completed case and reports the same outcome.
  const resumed = await scoreManifest(manifest, baseline, resumable);
  assert.deepEqual(resumed.resumed_cases, [feederRow.ghsa]);
  assert.deepEqual(resumed.summary, fresh.summary);
  assert.deepEqual(resumed.cases.map(row => [row.ghsa, row.outcome, row.hunk_hit]),
    fresh.cases.map(row => [row.ghsa, row.outcome, row.hunk_hit]));
  // Any change to the ruleset bytes misses the checkpoint.
  const revised = join(root, 'revised.yml');
  writeFileSync(revised, readFileSync(baseline, 'utf8') + '# clean-miss\n');
  const changed = await scoreManifest(manifest, revised, resumable);
  assert.deepEqual(changed.resumed_cases, []);
  assert.equal(changed.summary.hunk_hits, 0);
  const timeouts = join(root, 'retry.yml');
  writeFileSync(timeouts, readFileSync(baseline, 'utf8') + '# retry\n');
  const before = readdirSync(checkpointDir).length;
  const retrySettings = { ...resumable, jobs: 1 };
  const recovered = await scoreManifest(manifest, timeouts, retrySettings);
  const [recoveredCase] = recovered.cases;
  assert.equal(recoveredCase.retried_serially, true);
  assert.equal(recoveredCase.outcome, 'hit');
  assert.equal(recoveredCase.initial_scan_sides.old.timeouts, 1);
  assert.equal(readdirSync(checkpointDir).length, before + 1);
  const resumedRetry = await scoreManifest(manifest, timeouts, retrySettings);
  assert.deepEqual(resumedRetry.resumed_cases, [feederRow.ghsa]);
  assert.deepEqual(resumedRetry.cases, recovered.cases);
  assert.deepEqual(readdirSync(join(fixture.workdir, resumedRetry.scan_directory)), []);
  const initialReport = join(fixture.workdir, recoveredCase.initial_captures.old.native_report.path);
  writeFileSync(initialReport, '{}');
  assert.equal(checkpointArtifactsIntact(fixture.workdir, recoveredCase), false);
  const reacquired = await scoreManifest(manifest, timeouts, retrySettings);
  assert.deepEqual(reacquired.resumed_cases, []);
  assert.notEqual(reacquired.cases[0].initial_captures.old.native_report.path,
    recoveredCase.initial_captures.old.native_report.path);
  writeFileSync(timeouts, readFileSync(baseline, 'utf8') + '# persistent-case-timeout\n');
  const persistent = await scoreManifest(manifest, timeouts, retrySettings);
  assert.equal(persistent.cases[0].outcome, 'timeout');
  assert.equal(readdirSync(checkpointDir).length, before + 1);
}));

test('checkpoint records are bound to their full input fingerprint', async () => {
  const { checkpointKey, readCheckpoint, writeCheckpoint } = await import('./recall_harness.mjs');
  const root = mkdtempSync(join(tmpdir(), 'cf-checkpoint-'));
  try {
    const inputs = { case_sha256: 'a', ruleset_sha256: 'b' };
    writeCheckpoint(root, inputs, { outcome: 'hit' });
    assert.deepEqual(readCheckpoint(root, inputs), { outcome: 'hit' });
    assert.equal(readCheckpoint(root, { ...inputs, ruleset_sha256: 'c' }), null);
    const recordPath = join(root, `${checkpointKey(inputs)}.json`);
    const record = JSON.parse(readFileSync(recordPath, 'utf8'));
    record.result.outcome = 'miss';
    writeFileSync(recordPath, JSON.stringify(record));
    assert.equal(readCheckpoint(root, inputs), null);
    // A record whose stored inputs do not match its name is ignored.
    writeFileSync(recordPath, JSON.stringify({ ...record, inputs: { other: 1 } }));
    assert.equal(readCheckpoint(root, inputs), null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('scored cases reach the checkpoint directory only under the verified executable pin', () => feederFixture(async fixture => {
  const { root, workdir, manifest, baseline, profile, opts } = fixture;
  const checkpoints = join(root, 'case-engine-checkpoints');
  const settings = { ...opts, 'checkpoint-dir': checkpoints };
  const rulesBytes = readFileSync(baseline), profileBytes = readFileSync(profile);
  const stale = '1'.repeat(64);
  const engine = { path: process.execPath, receipt: { executable: basename(process.execPath),
    executable_sha256: stale, version: process.version } };
  const context = { profile: JSON.parse(profileBytes), profileSha256: sha256(profileBytes),
    bin: engine.path, engine, rules: baseline, rulesSha256: sha256(rulesBytes),
    ruleMap: ruleFamilies(rulesBytes.toString('utf8')), extra: [], workdir, scope: 'ecosystem' };
  await assert.rejects(scoreManifest(manifest, baseline, settings, context), /engine executable bytes changed during case scoring/);
  assert.equal(existsSync(checkpoints), false);

  const actual = sha256(readFileSync(engine.path));
  const verified = { ...context, engine: { ...engine, receipt: { ...engine.receipt, executable_sha256: actual } } };
  const fresh = await scoreManifest(manifest, baseline, settings, verified);
  assert.equal(fresh.cases[0].status, 'scored');
  const records = readdirSync(checkpoints);
  assert.equal(records.length, 1);
  assert.equal(JSON.parse(readFileSync(join(checkpoints, records[0]), 'utf8')).inputs.engine_sha256, actual);
  const warm = await scoreManifest(manifest, baseline, settings, verified);
  assert.deepEqual(warm.resumed_cases, [fresh.cases[0].ghsa]);
  await assert.rejects(scoreManifest(manifest, baseline, settings, { ...verified, engine: { ...verified.engine, path: profile } }),
    /engine executable bytes changed during case scoring/);
  assert.deepEqual(readdirSync(checkpoints), records);
}));

test('an interrupted scoring group preserves only earlier verified checkpoints', () => feederFixture(async fixture => {
  const { root, workdir, manifest, baseline, opts } = fixture;
  const checkpoints = join(root, 'group-checkpoints');
  const casesRoot = join(workdir, 'cases-v4');
  const original = join(casesRoot, caseDigest([feederRow]));
  const record = JSON.parse(readFileSync(join(original, 'case.json'), 'utf8'));
  const cases = Array.from({ length: 18 }, (_, index) => ({ ...feederRow, ghsa: `GHSA-test-bulk-${String(index).padStart(4, '0')}` }));
  for (const row of cases) {
    const key = caseDigest([row]);
    const folder = join(casesRoot, key);
    cpSync(original, folder, { recursive: true });
    writeFileSync(join(folder, 'case.json'), JSON.stringify({ ...record, case_sha256: key }));
  }
  writeFileSync(manifest, JSON.stringify({ cases, cases_sha256: caseDigest(cases) }));
  const rules = readFileSync(baseline, 'utf8') + `# group-drift ${caseDigest([cases.at(-1)])}\n`;
  writeFileSync(baseline, rules);
  const settings = { ...opts, jobs: 1, 'checkpoint-dir': checkpoints };
  await assert.rejects(scoreManifest(manifest, baseline, settings), /Scan ruleset byte fingerprint differs/);
  assert.equal(existsSync(join(root, 'group-drift')), true);
  assert.equal(readdirSync(checkpoints).length, 16);

  writeFileSync(baseline, rules);
  const resumed = await scoreManifest(manifest, baseline, settings);
  assert.deepEqual(resumed.resumed_cases, cases.slice(0, 16).map(row => row.ghsa));
  assert.equal(resumed.cases.filter(row => row.outcome === 'hit').length, cases.length);
  assert.equal(readdirSync(checkpoints).length, cases.length);
}));

test('incomplete cases and rows with missing artifacts are rescanned, never resumed', () => feederFixture(async fixture => {
  const { root, workdir, manifest, baseline, candidate, opts } = fixture;
  const checkpointDir = join(root, 'checkpoints');
  const resumable = { ...opts, 'checkpoint-dir': checkpointDir };
  // The candidate fixture is incomplete (parse error), so it is never checkpointed.
  const incomplete = await scoreManifest(manifest, candidate, resumable);
  assert.equal(incomplete.cases[0].status, 'incomplete');
  assert.equal(existsSync(checkpointDir) ? readdirSync(checkpointDir).length : 0, 0);
  const again = await scoreManifest(manifest, candidate, resumable);
  assert.deepEqual(again.resumed_cases, []);
  // A strict hit remains reportable even when one revision has a coverage gap.
  for (const [side, marker] of [['old', '# candidate-parse'], ['fixed', '# fixed-parse']]) {
    writeFileSync(candidate, readFileSync(baseline, 'utf8') + marker + '\n');
    const partial = await scoreManifest(manifest, candidate, resumable);
    assert.equal(partial.cases[0].outcome, 'hit');
    assert.equal(partial.cases[0].file_coverage[side][0].state, 'partial');
    assert.equal(existsSync(checkpointDir) ? readdirSync(checkpointDir).length : 0, 0, side);
    const partialReplay = await scoreManifest(manifest, candidate, resumable);
    assert.deepEqual(partialReplay.resumed_cases, []);
  }
  // A completed case resumes only while the SARIF it cites is intact.
  const fresh = await scoreManifest(manifest, baseline, resumable);
  assert.equal(readdirSync(checkpointDir).length, 1);
  assert.equal(checkpointArtifactsIntact(workdir, fresh.cases[0]), true);
  const sarif = join(workdir, fresh.cases[0].captures.old.sarif.path);
  writeFileSync(sarif, '{}');
  assert.equal(checkpointArtifactsIntact(workdir, fresh.cases[0]), false);
  const rescanned = await scoreManifest(manifest, baseline, resumable);
  assert.deepEqual(rescanned.resumed_cases, []);
  assert.deepEqual(rescanned.summary, fresh.summary);
  const { checkpointable, scorerSha256 } = await import('./recall_harness.mjs');
  assert.equal(checkpointable({ status: 'unfetchable', outcome: 'unknown' }), false);
  assert.equal(checkpointable({ status: 'incomplete', outcome: 'coverage_incomplete' }), false);
  assert.equal(checkpointable({ status: 'scored', outcome: 'miss' }), false);
  assert.equal(checkpointable(fresh.cases[0]), true);
  assert.match(scorerSha256(), /^[a-f0-9]{64}$/);
}));
