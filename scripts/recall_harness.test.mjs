import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { parseHunks, ruleFamilies, selectCases, wilson, profileArgv, sarifFindings, scoreCase, summarize, gate, gainRetention, controlFindingDeltas,
  familiesFor, isTestPath, caseDigest, priorExposure, sha256, scoreManifest, validateRecallManifest } from './recall_harness.mjs';
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
  assert.equal(Object.keys(shipped).length, 64);
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

test('coverage gaps never count as misses and regressions fail on either revision', () => {
  const clean = { path: 'sample.py', state: 'reported_scanned', reason: 'engine_scan_paths' };
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

async function feederFixture(run) {
  const root = mkdtempSync(join(tmpdir(), 'recall-feeder-'));
  try {
    const workdir = join(root, 'work'), caseKey = caseDigest([feederRow]);
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
      revisions: { old: '3'.repeat(40), fixed: feederRow.fix }, diff_sha256: sha256(diff),
      changed_files_sha256: sha256(inventory),
      source_packets: { old: fingerprints(old), fixed: fingerprints(fixed) } }));

    const scanner = join(root, 'scanner.mjs');
    writeFileSync(scanner, [
      "import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';",
      "import { basename, dirname } from 'node:path';",
      "const rules = process.argv[process.argv.indexOf('--config') + 1];",
      "const report = process.argv[process.argv.indexOf('--sarif-output') + 1];",
      "const coverageArgs = process.argv.indexOf('--json-output');",
      "const files = (await import('node:fs')).readdirSync('.');",
      "const old = basename(process.cwd()) === 'old';",
      "const control = basename(process.cwd()) === 'control';",
      "const ruleText = readFileSync(rules, 'utf8');",
      "if (old && ruleText.includes('# rules-drift')) appendFileSync(rules, '# drifted during scan\\n');",
      "if (control && ruleText.includes('# control-source-drift')) appendFileSync('sample.py', '# drifted during scan\\n');",
      "const incomplete = !old && ruleText.includes('# incomplete');",
      "const devTimeout = old && ruleText.includes('# retry') && basename(dirname(dirname(report))) !== 'serial';",
      "const controlTimeout = control && (ruleText.includes('# persistent-timeout') || (ruleText.includes('# control-timeout') && !process.argv.includes('--timeout=15')));",
      "const missingCoverage = old && ruleText.includes('# missing-coverage');",
      "const results = old && !missingCoverage ? [{ ruleId: 'fixture.review', locations: [{ physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1 } } }] }] : [];",
      "if (control && ruleText.includes('# control-missing-path')) results.push({ ruleId: 'fixture.review', locations: [{ physicalLocation: { artifactLocation: { uri: 'missing.py' }, region: { startLine: 1 } } }] });",
      "const issues = incomplete ? [{ descriptor: { id: 'ParseError' }, level: 'error' }] : [];",
      "if (devTimeout || controlTimeout) issues.push({ descriptor: { id: 'Timeout' }, level: 'warning' });",
      "if (coverageArgs >= 0 && !missingCoverage) writeFileSync(process.argv[coverageArgs + 1], JSON.stringify({ paths: { scanned: files.filter(path => path !== 'skipped.py' && path !== 'unreported.py'), skipped: files.includes('skipped.py') ? [{ path: 'skipped.py', reason: 'exceeded_size_limit' }] : [] }, errors: files.includes('partial.py') ? [{ type: 'Syntax error', path: 'partial.py' }] : [] }));",
      "writeFileSync(report, JSON.stringify({ runs: [{ results, invocations: [{ executionSuccessful: !incomplete, toolExecutionNotifications: issues }] }] }));",
      "process.exitCode = incomplete ? 2 : 0;",
    ].join('\n'));
    const profile = join(root, 'profile.json');
    writeFileSync(profile, JSON.stringify({ engine: 'semgrep', commands: [{ argv: ['scanner', scanner, '--config', '{rules}',
      '--sarif-output', '{report}', '{source}'] }] }));
    const rowText = JSON.stringify({ cases: [feederRow], cases_sha256: caseKey }, null, 2) + '\n';
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

  const output = join(root, 'evaluation.json');
  const engine = spawnSync(process.execPath, ['scripts/recall_harness.mjs', 'evaluate', '--manifest', manifest,
    '--baseline', baseline, '--candidate', candidate, '--profile', profile, '--workdir', workdir,
    '--opengrep', process.execPath, '--jobs', '1', '--out', output], { encoding: 'utf8' });
  assert.equal(engine.status, 2, engine.stderr);
  const evaluation = JSON.parse(readFileSync(output, 'utf8'));
  assert.deepEqual(evaluation.engine, {
    executable: basename(process.execPath), executable_sha256: sha256(readFileSync(process.execPath)), version: process.version,
  });
  assert.equal(evaluation.profile_sha256, sha256(readFileSync(profile)));
  assert.equal(evaluation.baseline_sha256, sha256(readFileSync(baseline)));
  assert.equal(evaluation.candidate_sha256, sha256(readFileSync(candidate)));
  const dev = evaluation.dev[0];
  const observed = dev.after_evidence.cases[0];
  assert.equal(evaluation.decision, 'REJECT');
  assert.deepEqual(evaluation.precision_evidence, { state: 'not_run', emitted: 0, adjudicated: 0, unreviewed: 0 });
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
    assert.match(drift.stderr, /Evaluation ruleset bytes changed during scoring/);
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

test('evaluation retries both control arms once with a bounded timeout and records both attempts', () =>
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
    assert.deepEqual(delta.retry_extra_args, ['--timeout=15']);
    assert.equal(delta.scan_sides.before.timeouts, 0);
    assert.equal(delta.scan_sides.after.timeouts, 0);
    assert.ok(delta.scan_sides.after.duration_ms >= 0);
    const explicit = evaluate('--extra-arg', '--timeout=5');
    assert.equal(explicit.status, 2);
    assert.deepEqual(explicit.result.controls[0].retry_extra_args, []);
    writeFileSync(baseline, rules + '# persistent-timeout\n');
    writeFileSync(candidate, rules + '# persistent-timeout\n');
    const persistent = evaluate();
    assert.equal(persistent.status, 2);
    assert.equal(persistent.result.decision, 'REJECT');
    assert.equal(persistent.result.controls[0].scan_sides.before.timeouts, 1);
    assert.equal(persistent.result.controls[0].scan_sides.after.timeouts, 1);
  }));

test('changed prepared source, diff and inventory bytes cannot yield a measured case', () => feederFixture(async fixture => {
  const { source, manifest, baseline, diffPath, inventoryPath, opts, old, diff } = fixture;
  writeFileSync(source, Buffer.from('print("before")\n'));
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

  const outside = join(root, 'outside');
  mkdirSync(outside);
  symlinkSync(outside, join(control, 'outside'), linkType);
  const escaped = controls();
  assert.equal(escaped.status, 2);
  assert.match(escaped.result.error, /link leaves the source tree/);
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
}));


test('local Git source bytes survive preparation, scanning, and the reported packet inventory', () =>
  feederFixture(async ({ root, workdir, manifest, baseline, profile }) => {
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
      '--rules', baseline, '--profile', profile, '--workdir', workdir, '--opengrep', process.execPath,
      '--jobs', '1', '--out', out], { encoding: 'utf8', timeout: 20000, env: { ...process.env,
        GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: override,
        GIT_CONFIG_VALUE_0: 'https://github.com/example/label-demo.git', GIT_ALLOW_PROTOCOL: 'file' } });
    assert.equal(result.status, 0, result.stderr);
    const scored = JSON.parse(readFileSync(out, 'utf8'));
    const captured = scored.cases[0];
    const directory = join(workdir, 'cases-v4', caseDigest([current]));
    assert.equal(captured.status, 'scored', captured.detail);
    assert.equal(scored.summary.scored, 1);
    assert.equal(scored.summary.hunk_hits, 1);
    assert.deepEqual(captured.revisions, { old: parent, fixed: fix });
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
