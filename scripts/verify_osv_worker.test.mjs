import test from 'node:test';
import assert from 'node:assert/strict';
import { validateOSVControl } from './verify_osv_worker.mjs';

const bundle = (hits = 1) => ({ artifacts: {
  'report.json': { factory_lookup_execution: { schema: 'factory.osv-lookup-execution.v1', queries: [{}] },
    results: [{ packages: [{ vulnerabilities: Array.from({ length: hits }, () => ({ id: 'GHSA-29vq-49wr-vm6x' })) }] }] },
  'coverage.json': { version_probe: { exit_code: 0 }, native_invocations: [{ execution: { exit_code: 1 } }],
    errors: ['NATIVE_CHALLENGES_REQUIRED'] },
} });
test('native OSV control accepts measured target and fixed controls without claiming admission', () => {
  assert.equal(validateOSVControl(bundle(), 1).target_findings, 1);
  assert.equal(validateOSVControl(bundle(0), 0).target_findings, 0);
  assert.deepEqual(validateOSVControl(bundle(), 1).remaining_errors, ['NATIVE_CHALLENGES_REQUIRED']);
});
test('native OSV control rejects a report without a native lookup ledger', () => {
  const value = bundle(); delete value.artifacts['report.json'].factory_lookup_execution;
  assert.throws(() => validateOSVControl(value, 1), /lookup ledger/);
});
test('native OSV control rejects missing or failed native and version executions', () => {
  for (const field of ['native_invocations', 'version_probe']) {
    const value = bundle(); delete value.artifacts['coverage.json'][field];
    assert.throws(() => validateOSVControl(value, 1), /execution failed/);
  }
  const failed = bundle(); failed.artifacts['coverage.json'].native_invocations[0].execution.exit_code = 2;
  assert.throws(() => validateOSVControl(failed, 1), /execution failed/);
});
test('native OSV control rejects a silent positive miss and a negative false finding', () => {
  assert.throws(() => validateOSVControl(bundle(0), 1), /Expected 1/);
  assert.throws(() => validateOSVControl(bundle(), 0), /Expected 0/);
});
