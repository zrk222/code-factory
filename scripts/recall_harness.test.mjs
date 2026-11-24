import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { parseHunks, ruleFamilies, selectCases, wilson, profileArgv, sarifFindings, scoreCase, summarize, gate,
  familiesFor, isTestPath, caseDigest, sha256, scoreManifest, validateRecallManifest } from './recall_harness.mjs';

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


const feederRow = { ghsa: 'GHSA-xxxx-yyyy-zzzz', ecosystem: 'PyPI', cwes: ['CWE-79'],
  published: '2026-09-10', repository: 'example/label-demo', fix: '1'.repeat(40) };

test('the feeder coalesces repeated metadata and rejects an ambiguous fix', () => {
  const window = { from: '2026-09-01', to: '2026-10-01' };
  const same = selectCases([feederRow, { ...feederRow }], window);
  assert.equal(same.cases.length, 1);
  assert.deepEqual(same.dropped, { duplicate_case: 1 });
  assert.throws(() => selectCases([feederRow, { ...feederRow, fix: '2'.repeat(40) }], window),
    /Conflicting advisory metadata/);
});

test('manifest validation preserves old seals and refuses changed case bytes', () => {
  for (const day of ['20261123', '20261124-overflow']) {
    const value = JSON.parse(readFileSync('docs/evidence/heldout-recall-manifest-' + day + '.json', 'utf8'));
    assert.equal(validateRecallManifest(value), value.cases_sha256 ?? value.manifest_sha256);
  }
  const cases = [feederRow];
  const sealed = { cases, cases_sha256: caseDigest(cases) };
  assert.equal(validateRecallManifest(sealed), sealed.cases_sha256);
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
      "import { readFileSync, writeFileSync } from 'node:fs';",
      "import { basename, dirname } from 'node:path';",
      "const rules = process.argv[process.argv.indexOf('--config') + 1];",
      "const report = process.argv[process.argv.indexOf('--sarif-output') + 1];",
      "const coverageArgs = process.argv.indexOf('--json-output');",
      "const files = (await import('node:fs')).readdirSync('.');",
      "const old = basename(process.cwd()) === 'old';",
      "const ruleText = readFileSync(rules, 'utf8');",
      "const incomplete = !old && ruleText.includes('# incomplete');",
      "const timeout = old && ruleText.includes('# retry') && basename(dirname(dirname(report))) !== 'serial';",
      "const results = old ? [{ ruleId: 'fixture.review', locations: [{ physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1 } } }] }] : [];",
      "const issues = incomplete ? [{ descriptor: { id: 'ParseError' }, level: 'error' }] : [];",
      "if (timeout) issues.push({ descriptor: { id: 'Timeout' }, level: 'warning' });",
      "if (coverageArgs >= 0) writeFileSync(process.argv[coverageArgs + 1], JSON.stringify({ paths: { scanned: files.filter(path => path !== 'skipped.py' && path !== 'unreported.py'), skipped: files.includes('skipped.py') ? [{ path: 'skipped.py', reason: 'exceeded_size_limit' }] : [] }, errors: files.includes('partial.py') ? [{ type: 'Syntax error', path: 'partial.py' }] : [] }));",
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
  const dev = evaluation.dev[0];
  const observed = dev.after_evidence.cases[0];
  assert.equal(evaluation.decision, 'REJECT');
  assert.deepEqual(evaluation.new_errors, [feederRow.ghsa]);
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
    const source = join(repository, 'sample.py');
    writeFileSync(source, beforeBytes);
    for (const file of ['retired.py', 'clean file.py', 'View.vue', 'skipped.py', 'partial.py', 'unreported.py']) {
      writeFileSync(join(repository, file), 'before\n');
    }
    git('add', '.');
    commit('old label');
    const parent = git('rev-parse', 'HEAD');
    writeFileSync(source, afterBytes);
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
    const coverage = (side, path) => captured.file_coverage[side].find(row => row.path === path);
    assert.equal(coverage('old', 'sample.py').sha256, sha256(beforeBytes));
    assert.equal(coverage('fixed', 'sample.py').sha256, sha256(afterBytes));
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
