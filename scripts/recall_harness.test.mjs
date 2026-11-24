import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseHunks, ruleFamilies, selectCases, wilson, profileArgv, sarifFindings, scoreCase, summarize, gate,
  familiesFor, isTestPath, caseDigest } from './recall_harness.mjs';

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
});

test('gate rejects lost hits, more residuals and control growth', () => {
  const result = (rows, residual = 0) => ({ cases: rows, summary: { fix_side_residual_alerts: residual } });
  const before = result([{ ghsa: 'A', hunk_hit: true }, { ghsa: 'B', hunk_hit: false }]);
  const better = result([{ ghsa: 'A', hunk_hit: true }, { ghsa: 'B', hunk_hit: true }]);
  assert.equal(gate({ dev: [{ before, after: better }], controls: [{ before: 3, after: 3 }] }).decision, 'ACCEPT');
  const lostVerdict = gate({ dev: [{ before, after: result([{ ghsa: 'A', hunk_hit: false }, { ghsa: 'B', hunk_hit: true }]) }], controls: [] });
  assert.equal(lostVerdict.decision, 'REJECT');
  assert.match(lostVerdict.failures[0], /lost 1 dev hit/);
  assert.deepEqual(lostVerdict.lost_baseline_hits, ['A']);
  assert.equal(gate({ dev: [{ before, after: result(better.cases, 2) }], controls: [] }).decision, 'REJECT');
  const noisy = gate({ dev: [{ before, after: better }], controls: [{ before: 3, after: 9 }], maxControlIncrease: 5 });
  assert.deepEqual([noisy.decision, noisy.control_increase], ['REJECT', 6]);
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
  assert.deepEqual(notes, { timeouts: 1, parse_errors: 1, other: 0 });
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
