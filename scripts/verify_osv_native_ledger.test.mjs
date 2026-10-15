import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  markCasePassed,
  readReport,
  reportIdentity,
  validateCompleteLedger,
  validateExtractorInventory,
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
      database_sha256: '013a03eb8d5a67818901fe0632728a5f1011621d6b956f14b25e5f71a7b82c5c',
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
  validateCompleteLedger(report, 'native-clean-fixture', '0.0.0', {
    vulnerable: false, expectedPlugins: ['requirements'],
  });
  const item = markCasePassed({ state: 'FAIL' }, report);
  assert.equal(item.state, 'PASS');
  assert.match(item.report_identity, /native-clean-fixture/);
});

test('readReport parses a bounded regular report through its opened descriptor', () => {
  const root = mkdtempSync(join(tmpdir(), 'osv-report-test-'));
  try {
    const ledgerReport = fixture();
    const bytes = Buffer.from(JSON.stringify(ledgerReport));
    writeFileSync(join(root, 'report.json'), bytes, { flag: 'wx' });
    const result = readReport(root);
    assert.deepEqual(result.report, ledgerReport);
    assert.deepEqual(result.bytes, bytes);
    assert.equal(readReport(join(root, 'missing')), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('readReport rejects a directory report path', () => {
  const root = mkdtempSync(join(tmpdir(), 'osv-report-path-test-'));
  try {
    const directory = join(root, 'report.json');
    mkdirSync(directory);
    assert.throws(() => readReport(root), /regular file/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('readReport rejects a symlink report path', { skip: process.platform === 'win32' }, () => {
  const root = mkdtempSync(join(tmpdir(), 'osv-report-symlink-test-'));
  try {
    const target = join(root, 'target.json');
    const symlinkDir = join(root, 'symlink-case');
    writeFileSync(target, JSON.stringify(fixture()), { flag: 'wx' });
    mkdirSync(symlinkDir);
    symlinkSync(target, join(symlinkDir, 'report.json'), 'file');
    assert.throws(() => readReport(symlinkDir), /ELOOP|symbolic|regular file/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('successful scan cannot hide an unsuccessful extractor', () => {
  const report = fixture({ failedExtractor: true });
  assert.throws(() => validateCompleteLedger(report, 'native-clean-fixture', '0.0.0', {
    vulnerable: false, expectedPlugins: ['requirements'],
  }));
});

test('validateExtractorRuns accepts matching native statuses and rejects incomplete or mismatched rows', () => {
  const ledger = fixture().factory_lookup_execution;
  assert.doesNotThrow(() => validateExtractorRuns(ledger, ['requirements']));
  assert.throws(() => validateExtractorRuns(ledger, ['lockfile', 'requirements']), /did not succeed/);
  assert.throws(() => validateExtractorRuns({ extractor_runs: [{
    plugins: ['requirements', 'lockfile'],
    statuses: [{ name: 'requirements', state: 'SUCCEEDED' }],
  }] }, ['lockfile', 'requirements']), /incomplete/);
  assert.throws(() => validateExtractorRuns({ extractor_runs: [{
    plugins: ['lockfile', 'requirements'],
    statuses: [
      { name: 'lockfile', state: 'SUCCEEDED' },
      { name: 'other', state: 'SUCCEEDED' },
    ],
  }] }, ['lockfile', 'requirements']), /did not succeed/);
});

test('validateExtractorInventory binds names to the pinned source, profile, and generator', () => {
  const inventory = {
    schema: 'factory.osv-extractor-inventory.v1',
    upstream_commit: 'a14aa98ab8408547083d4411091c5fbaf5b47d8e',
    profile_sha256: 'b'.repeat(64),
    generator_sha256: 'c'.repeat(64),
    presets: ['lockfile', 'sbom', 'directory'],
    capabilities: { direct_fs: true, running_system: true, network: 'offline', os: 'linux' },
    plugins: ['alpha', 'requirements'],
  };
  assert.deepEqual(validateExtractorInventory(inventory, 'b'.repeat(64), 'c'.repeat(64)), inventory.plugins);
  assert.throws(() => validateExtractorInventory(inventory, 'd'.repeat(64), 'c'.repeat(64)), /not bound/);
  assert.throws(() => validateExtractorInventory(inventory, 'b'.repeat(64), 'd'.repeat(64)), /not bound/);
  assert.throws(() => validateExtractorInventory({ ...inventory, plugins: ['requirements', 'alpha'] }, 'b'.repeat(64), 'c'.repeat(64)), /invalid plugin/);
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
    const lockfile = writeRequirement(root, '{ malformed json\n', 'package-lock.json');
    assert.equal(readFileSync(join(lockfile, 'package-lock.json'), 'utf8'), '{ malformed json\n');
    assert.throws(() => writeRequirement(root, 'bad', '../requirements.txt'), /Unsupported native fixture filename/);
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
  assert.throws(() => validateCompleteLedger(report, 'native-clean-fixture', '0.0.0', {
    vulnerable: false, expectedPlugins: ['requirements'],
  }));
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
  assert.equal(validateExpectedFailure('extractor_failure', 2, null,
    'extractor javascript/packagelockjson failed: invalid JSON'), null);
  assert.throws(() => validateExpectedFailure('extractor_failure', 2, null, 'failed to extract package'));
  assert.throws(() => validateExpectedFailure('extractor_failure', 2, null, 'docker runtime error'));
  assert.throws(() => validateExpectedFailure('extractor_failure', 0, null, 'extractor requirements failed'));
});
