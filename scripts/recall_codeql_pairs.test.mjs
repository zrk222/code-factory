import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { caseDigest, sha256, sortKeys } from './recall_harness.mjs';
import { scoreCodeqlPairs } from './recall_codeql_pairs.mjs';

function stagedPair(t) {
  const root = mkdtempSync(join(tmpdir(), 'cf-codeql-pair-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (path, bytes) => {
    writeFileSync(join(root, path), bytes);
    return { path, sha256: sha256(bytes) };
  };
  const json = (path, value) => write(path, JSON.stringify(value));
  const row = { ghsa: 'GHSA-2222-3333-4444', repository: 'example/project', ecosystem: 'PyPI',
    fix: 'b'.repeat(40), cwes: ['CWE-89'] };
  const manifest = json('manifest.json', { cases: [row], cases_sha256: caseDigest([row]) });
  const diff = write('diff.patch', 'diff --git a/sample.py b/sample.py\n--- a/sample.py\n+++ b/sample.py\n@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 2\n');
  const changes = write('changes.z', 'M\0sample.py\0');
  const source = { old: 'VALUE = 1\n', fixed: 'VALUE = 2\n' };
  const revisions = { old: 'a'.repeat(40), fixed: row.fix };
  const source_packets = Object.fromEntries(Object.entries(source).map(([side, bytes]) => [
    side, [{ path: 'sample.py', bytes: bytes.length, sha256: sha256(bytes) }],
  ]));
  const binding = { ghsa: row.ghsa, revisions, source_packets, diff_sha256: diff.sha256, changed_files_sha256: changes.sha256 };
  const prepared = json('case.json', { ...binding, status: 'ready', case_sha256: caseDigest([row]) });
  const reference = json('reference.json', { schema: 'factory.recall-exposed-run-readback.v1',
    manifest_sha256: manifest.sha256, manifest_cases_sha256: caseDigest([row]),
    candidate: { registered: 1, hunk_hits: 0 }, cases: [{ advisory: row.ghsa, after: 'miss',
      input_sha256: sha256(JSON.stringify(sortKeys(binding))) }] });
  const id = 'test/fixture.scope.detail';
  const query = write('query.ql', '/**\n * @id ' + id + '\n * @tags external/cwe/cwe-089\n */\n');
  const zip = spawnSync(process.env.CF_RECALL_PYTHON ?? 'python', ['-I', '-c',
    'import json, sys, zipfile\nfor side, text in json.load(sys.stdin).items():\n with zipfile.ZipFile(side + ".zip", "w") as archive: archive.writestr("src/sample.py", text)'],
  { cwd: root, input: JSON.stringify(source), encoding: 'utf8', windowsHide: true });
  assert.equal(zip.status, 0, zip.stderr ?? zip.error?.message);
  const capture = (side, invocations = [{ executionSuccessful: true }], located = true) => {
    const results = side === 'old' ? [{ ruleId: id, locations: located ? [
      { physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1 } } },
    ] : [] }] : [];
    const sarif = json(side + '.sarif', { version: '2.1.0', runs: [{ tool: { driver: { name: 'CodeQL',
      semanticVersion: '2.27.1', rules: [{ id, properties: { tags: ['external/cwe/cwe-089'] } }] } }, results, invocations }] });
    const observation = json(side + '.json', { case: row.ghsa, side, query: id, revision: revisions[side],
      query_sha256: query.sha256, native_sha256: sarif.sha256, reported_alerts: results.length });
    const path = side + '.zip';
    return { sarif, observation, archive: { path, sha256: sha256(readFileSync(join(root, path))) }, archive_prefix: 'src' };
  };
  const value = { schema: 'factory.recall-codeql-pairs.v1', engine_version: '2.27.1', manifest, reference,
    cases: [{ advisory: row.ghsa, prepared, query, query_id: id, old: capture('old'), fixed: capture('fixed') }] };
  return { root, row, value, capture, json, write, run: input => scoreCodeqlPairs(join(root, json('bundle.json', input).path)) };
}

test('paired CodeQL scoring requires both revisions and verifies actual source archive bytes', t => {
  const { value, capture, run } = stagedPair(t);
  const receipt = run(value);
  assert.equal(receipt.scope, 'supplemental');
  assert.equal(receipt.reference_hunk_hits, 0);
  assert.equal(receipt.scored_pairs, 1);
  assert.equal(receipt.strict_hits_on_reference_misses, 1);
  assert.equal(receipt.deleted_line_hits, 1);
  assert.equal(receipt.fixed_hunk_residuals, 0);
  assert.deepEqual(receipt.cases[0].hunk_matches, [['test/fixture.scope.detail', 'sample.py', 1]]);
  const pair = value.cases[0];
  const withPair = changed => ({ ...value, cases: [{ ...pair, ...changed }] });
  assert.throws(() => run(withPair({ old: pair.fixed })), /Native case or revision differs/);
  assert.throws(() => run(withPair({ old: { ...pair.old, archive: pair.fixed.archive } })), /Source archive packet bytes differ/);
  assert.throws(() => run(withPair({ old: { ...pair.old, archive_prefix: 'other' } })), /Source archive entry is missing/);
  assert.throws(() => run({ ...value, cases: [pair, pair] }), /Duplicate CodeQL advisory pair/);
  assert.throws(() => run({ ...value, manifest: { ...value.manifest, path: '../manifest.json' } }), /leaves the work directory/);
  assert.throws(() => run(withPair({ old: capture('old', []) })), /Unqualified CodeQL report/);
  assert.throws(() => run(withPair({ old: capture('old', [{ executionSuccessful: true,
    toolExecutionNotifications: [{ level: 'error' }] }]) })), /Unqualified CodeQL report/);
  assert.throws(() => run(withPair({ old: capture('old', undefined, false) })), /Native alert location is missing/);
});

test('registered CodeQL plans reconcile the exact query set and keep absent cases visible', t => {
  const { root, row, value, json, write, run } = stagedPair(t);
  const pair = value.cases[0];
  const unobserved = { ...row, ghsa: 'GHSA-3333-4444-5555', cwes: ['CWE-295'] };
  const unsupported = { ...row, ghsa: 'GHSA-4444-5555-6666', ecosystem: 'npm' };
  const cases = [row, unobserved, unsupported];
  const manifest = json('registry.json', { cases, cases_sha256: caseDigest(cases) });
  const previous = JSON.parse(readFileSync(join(root, value.reference.path), 'utf8'));
  const reference = json('registered-reference.json', { ...previous, candidate: { registered: 3, hunk_hits: 0 },
    manifest_sha256: manifest.sha256, manifest_cases_sha256: caseDigest(cases),
    cases: [...previous.cases, ...[unobserved, unsupported].map(r => ({ advisory: r.ghsa, after: 'miss' }))] });
  const extra = { id: 'test/other-family',
    source: write('extra.ql', '/**\n * @id test/other-family\n * @tags external/cwe/cwe-079\n */\n') };
  const queries = [{ id: pair.query_id, source: pair.query }, extra];
  const plan = json('plan.json', { schema: 'factory.recall-codeql-plan.v1', engine_version: value.engine_version,
    manifest_sha256: manifest.sha256, reference_sha256: reference.sha256, policies: [{ ecosystem: 'PyPI', queries }],
    advisory_schedule: [row.ghsa, unobserved.ghsa] });
  const queries_sha256 = caseDigest(queries.map(({ id, source }) => ({ id, sha256: source.sha256 })));
  const capture = (side, complete = true) => {
    const raw = JSON.parse(readFileSync(join(root, pair[side].sarif.path), 'utf8'));
    const run = raw.runs[0];
    if (complete) {
      run.tool.driver.rules.push({ id: extra.id, properties: { tags: ['external/cwe/cwe-079'] } });
      if (side === 'fixed') run.results = [{ ruleId: extra.id, locations: [
        { physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1 } } },
      ] }];
    }
    const sarif = json('plan-' + side + '.sarif', raw);
    const prior = JSON.parse(readFileSync(join(root, pair[side].observation.path), 'utf8'));
    const observation = json('plan-' + side + '.json', { ...prior, plan_sha256: plan.sha256,
      queries_sha256, native_sha256: sarif.sha256, reported_alerts: run.results.length });
    return { ...pair[side], sarif, observation };
  };
  const bundle = { ...value, schema: 'factory.recall-codeql-pairs.v2', manifest, reference, plan,
    cases: [{ ...pair, old: capture('old'), fixed: capture('fixed') }] };
  const scored = run(bundle);
  assert.equal(scored.scope, 'registered-codeql-plan');
  assert.equal(scored.planned_cases, 2);
  assert.deepEqual(scored.unobserved_advisories, [unobserved.ghsa]);
  assert.deepEqual(scored.unsupported_advisories, [unsupported.ghsa]);
  assert.deepEqual(scored.uncovered_advisory_families, [{ advisory: unobserved.ghsa, families: ['tls'] }]);
  assert.equal(scored.strict_hunk_hits, 1);
  assert.equal(scored.fixed_hunk_residuals, 0);
  assert.equal(scored.cases[0].native_alerts.fixed, 1);
  const frozenPlan = JSON.parse(readFileSync(join(root, plan.path), 'utf8'));
  const truncated = json('truncated.json', { ...frozenPlan, advisory_schedule: [row.ghsa] });
  assert.throws(() => run({ ...bundle, plan: truncated }), /schedule omits or adds registered cases/);
  assert.throws(() => run({ ...bundle, cases: [{ ...bundle.cases[0], fixed: capture('fixed', false) }] }),
    /CodeQL query inventory or alert count differs/);
});
