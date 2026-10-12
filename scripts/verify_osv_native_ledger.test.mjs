import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  markCasePassed,
  reportIdentity,
  validateCompleteLedger,
  validateExtractorRuns,
  validateExpectedFailure,
  writeRequirement,
} from './verify_osv_native_ledger.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');

function fixture({ failedExtractor = false, badDecision = false } = {}) {
  const catalog = 'a'.repeat(64);
  const query = {
    name: 'native-clean-fixture',
    version: '0.0.0',
    ecosystem: 'PyPI',
    state: 'EXECUTED',
    evaluated_advisories: 1,
    evaluated_sha256: catalog,
    matched_advisories: [],
  };
  const decision = {
    catalog_sha256: catalog,
    ecosystem: query.ecosystem,
    evaluated_advisories: query.evaluated_advisories,
    matched_advisories: query.matched_advisories,
    name: query.name,
    version: query.version,
  };
  query.decision_sha256 = badDecision ? '0'.repeat(64) : sha(JSON.stringify(decision));
  return {
    factory_lookup_execution: {
      schema: 'factory.osv-lookup-execution.v1',
      upstream_commit: 'a14aa98ab8408547083d4411091c5fbaf5b47d8e',
      database_sha256: '36ef7d92e174230b8c7c26b952562be23837472c2239b6752de64d5d683a800e',
      catalog_advisories: 1,
      catalog_sha256: catalog,
      queries: [query],
      extractor_runs: [{
        plugins: ['requirements'],
        statuses: [{ name: 'requirements', state: failedExtractor ? 'FAILED' : 'SUCCEEDED' }],
      }],
    },
  };
}

test('successful native ledger verifies decision and marks the operator case PASS', () => {
  const report = fixture();
  validateCompleteLedger(report, 'native-clean-fixture', '0.0.0', { vulnerable: false });
  const item = markCasePassed({ state: 'FAIL' }, report);
  assert.equal(item.state, 'PASS');
  assert.match(item.report_identity, /native-clean-fixture/);
});

test('successful scan cannot hide an unsuccessful extractor', () => {
  const report = fixture({ failedExtractor: true });
  assert.throws(() => validateCompleteLedger(report, 'native-clean-fixture', '0.0.0', { vulnerable: false }));
});

test('validateExtractorRuns accepts matching native statuses and rejects incomplete or mismatched rows', () => {
  const ledger = fixture().factory_lookup_execution;
  assert.doesNotThrow(() => validateExtractorRuns(ledger));
  assert.throws(() => validateExtractorRuns({ extractor_runs: [{
    plugins: ['requirements', 'lockfile'],
    statuses: [{ name: 'requirements', state: 'SUCCEEDED' }],
  }] }), /incomplete/);
  assert.throws(() => validateExtractorRuns({ extractor_runs: [{
    plugins: ['lockfile', 'requirements'],
    statuses: [
      { name: 'lockfile', state: 'SUCCEEDED' },
      { name: 'other', state: 'SUCCEEDED' },
    ],
  }] }), /did not succeed/);
});

test('reportIdentity normalizes query order and retains only ledger-backed report IDs', () => {
  const report = fixture();
  const ledger = report.factory_lookup_execution;
  ledger.queries = [
    { name: 'zeta', version: '2.0', ecosystem: 'PyPI', matched_advisories: ['GHSA-Z'] },
    { name: 'alpha', version: '1.0', ecosystem: 'PyPI', matched_advisories: ['GHSA-A'] },
  ];
  report.results = [{ packages: [{ vulnerabilities: [{ id: 'GHSA-Z' }, { id: 'UNBOUND' }] }] },
    { packages: [{ vulnerabilities: [{ id: 'GHSA-A' }] }] }];
  const expected = JSON.stringify({
    queries: [
      { name: 'alpha', version: '1.0', ecosystem: 'PyPI', matched_advisories: ['GHSA-A'] },
      { name: 'zeta', version: '2.0', ecosystem: 'PyPI', matched_advisories: ['GHSA-Z'] },
    ],
    reported_advisories: ['GHSA-A', 'GHSA-Z'],
  });
  assert.equal(reportIdentity(report), expected);
});

test('writeRequirement creates distinct read-only fixture directories for separate cases', () => {
  const root = mkdtempSync(join(tmpdir(), 'osv-requirement-test-'));
  try {
    const first = writeRequirement(root, 'requests==2.19.1\n');
    const second = writeRequirement(root, 'urllib3==1.25.0\n');
    const firstPath = join(first, 'requirements.txt');
    const secondPath = join(second, 'requirements.txt');
    assert.notEqual(first, second);
    assert.equal(readFileSync(firstPath, 'utf8'), 'requests==2.19.1\n');
    assert.equal(readFileSync(secondPath, 'utf8'), 'urllib3==1.25.0\n');
    assert.equal(statSync(firstPath).mode & 0o222, 0);
    assert.equal(statSync(secondPath).mode & 0o222, 0);
    if (process.platform !== 'win32') {
      assert.equal(statSync(first).mode & 0o111, 0o111);
      assert.equal(statSync(second).mode & 0o111, 0o111);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('decision digest is recomputed from canonical evidence', () => {
  const report = fixture({ badDecision: true });
  assert.throws(() => validateCompleteLedger(report, 'native-clean-fixture', '0.0.0', { vulnerable: false }));
});

test('missing database case requires its native database diagnostic', () => {
  assert.equal(validateExpectedFailure('missing_database', 2, null,
    'open /opt/factory/osv-db/osv-scanner/PyPI/all.zip: no such file or directory'), null);
  assert.equal(validateExpectedFailure('missing_database', 2, null,
    'could not load db for PyPI ecosystem: unable to fetch OSV database: no offline version of the OSV database is available\n'
    + 'cannot execute native OSV query: unable to fetch OSV database: no offline version of the OSV database is available'), null);
  assert.throws(() => validateExpectedFailure('missing_database', 2, null, 'permission denied'));
  assert.throws(() => validateExpectedFailure('missing_database', 2, null, 'database operation failed'));
  assert.throws(() => validateExpectedFailure('missing_database', 1, null, 'vulnerability found'));
});

test('malformed database case requires a zip or native database diagnostic', () => {
  assert.equal(validateExpectedFailure('malformed_database', 2, null, 'zip: not a valid zip file'), null);
  assert.throws(() => validateExpectedFailure('malformed_database', 2, null, 'zip operation failed'));
  assert.throws(() => validateExpectedFailure('malformed_database', 2, null, 'container stopped'));
});

test('extractor failure requires explicit native extractor evidence', () => {
  assert.equal(validateExpectedFailure('extractor_failure', 2, null,
    'extractor requirements failed: invalid syntax'), null);
  assert.throws(() => validateExpectedFailure('extractor_failure', 2, null, 'failed to extract package'));
  assert.throws(() => validateExpectedFailure('extractor_failure', 2, null, 'docker runtime error'));
  assert.throws(() => validateExpectedFailure('extractor_failure', 0, null, 'extractor requirements failed'));
});
