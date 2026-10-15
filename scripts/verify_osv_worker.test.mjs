import test from 'node:test';
import assert from 'node:assert/strict';
import { validateOSVControl, createOSVContract } from './verify_osv_worker.mjs';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

test('native OSV contract binds the primary database artifact to the shipped profile and image', () => {
  const profile = JSON.parse(readFileSync(new URL('../deploy/deep-adapters/profiles/osv.json', import.meta.url)));
  const image = `sha256:${'a'.repeat(64)}`;
  const value = createOSVContract(profile, 'root-config-fixed', [], image);
  assert.equal(value.lane.image, image);
  assert.equal(value.lane.native_policy.database_path, '/opt/factory/osv-db/osv-scanner/PyPI/all.zip');
  assert.equal(value.lane.native_policy.database_sha256, profile.ruleset_sha256);
  assert.equal(value.lane.native_policy.baseline_config_sha256, createHash('sha256').update('\n').digest('hex'));
  assert.deepEqual(value.obligations, []); // Three seeded controls do not constitute signed challenge admission.
  assert.throws(() => createOSVContract({ ...profile, ruleset_sha256: 'unknown' }, 'fixed', [], image), /binding/);
  assert.throws(() => createOSVContract(profile, 'fixed', [], 'mutable-tag'), /binding/);
});

const bundle = (hits = 1) => ({ artifacts: {
  'report.json': { factory_lookup_execution: { schema: 'factory.osv-lookup-execution.v1', queries: [{}] },
    results: [{ source: { path: 'requirements.txt' }, packages: [{ package: { ecosystem: 'PyPI', name: 'werkzeug', version: '0.1' },
      vulnerabilities: Array.from({ length: hits }, () => ({ id: 'GHSA-29vq-49wr-vm6x' })) }] }] },
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

test('native OSV control counts one affected package for reciprocal advisory aliases and preserves raw count', () => {
  const value = bundle(0);
  value.artifacts['report.json'].results[0].packages[0].vulnerabilities = [
    { id: 'PYSEC-2026-2320', aliases: ['CVE-2026-27199', 'GHSA-29vq-49wr-vm6x'] },
    { id: 'GHSA-29vq-49wr-vm6x', aliases: ['CVE-2026-27199', 'PYSEC-2026-2320'] },
  ];
  const result = validateOSVControl(value, 1);
  assert.equal(result.target_findings, 1);
  assert.equal(result.target_advisory_records, 2);
  value.artifacts['report.json'].results.push(structuredClone(value.artifacts['report.json'].results[0]));
  assert.throws(() => validateOSVControl(value, 1), /Expected 1/);
});
