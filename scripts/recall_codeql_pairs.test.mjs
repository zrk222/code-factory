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
  return { value, capture, run: input => scoreCodeqlPairs(join(root, json('bundle.json', input).path)) };
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
