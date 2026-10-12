import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  markCasePassed,
  validateCompleteLedger,
  validateExpectedFailure,
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

test('decision digest is recomputed from canonical evidence', () => {
  const report = fixture({ badDecision: true });
  assert.throws(() => validateCompleteLedger(report, 'native-clean-fixture', '0.0.0', { vulnerable: false }));
});

test('missing database case requires its native database diagnostic', () => {
  assert.equal(validateExpectedFailure('missing_database', 2, null,
    'open /opt/factory/osv-db/osv-scanner/PyPI/all.zip: no such file or directory'), null);
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
