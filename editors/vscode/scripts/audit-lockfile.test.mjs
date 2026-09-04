import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyBinary, requireSuccessfulScan, checksums } from './audit-lockfile.mjs';

test('scanner is pinned for Windows, Linux and macOS', () => {
  assert.equal(Object.keys(checksums).length, 6);
  for (const [, hash] of Object.values(checksums)) assert.match(hash, /^[a-f0-9]{64}$/);
});
test('modified scanner cannot execute', () => {
  const bytes = Buffer.from('scanner');
  verifyBinary(bytes, createHash('sha256').update(bytes).digest('hex'));
  assert.throws(() => verifyBinary(bytes, '0'.repeat(64)), /checksum mismatch/);
});
test('findings, empty results, network failure, timeout and signals fail closed', () => {
  requireSuccessfulScan({ status: 0 });
  for (const result of [{}, { status: 1 }, { status: 2 }, { status: null },
    { status: 0, error: new Error('network') }, { status: null, error: new Error('ETIMEDOUT') },
    { status: 0, signal: 'SIGTERM' }]) {
    assert.throws(() => requireSuccessfulScan(result), /audit blocked/);
  }
});
