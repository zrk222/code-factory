import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { downloadFeed, evaluate, parseManifest, targets, trackerUrl } from './verify_worker_cves.mjs';

const pkg = { binary: 'libfoo', version: '99', source: 'foo', source_version: '1:2.0-1' };
const feed = release => ({ foo: { 'CVE-example': { releases: { sid: release } } } });
const check = (data, compare = () => true, packages = [pkg]) => evaluate(data, packages, compare, ['CVE-example'])[0];
test('baseline remains exactly fifteen original unique CVE IDs', () => {
  assert.equal(targets.length, 15);
  assert.equal(new Set(targets).size, 15);
  assert(targets.every(id => /^CVE-\d{4}-\d+$/.test(id)));
});
test('compare uses source version, including epoch, not binary version', () => {
  const result = check(feed({ status: 'resolved', fixed_version: '1:2.0-1' }), (installed, fixed) => {
    assert.equal(installed, pkg.source_version);
    assert.equal(fixed, '1:2.0-1');
    return true;
  });
  assert.equal(result.state, 'RESOLVED');
});
test('unfixed version and open advisory block', () => {
  assert.equal(check(feed({ status: 'resolved', fixed_version: '3' }), () => false).state, 'BLOCKED');
  assert.equal(check(feed({ status: 'open', fixed_version: '0' })).state, 'BLOCKED');
});
test('unknown, absent, malformed and missing source records fail closed', () => {
  for (const data of [{}, { foo: { 'CVE-example': {} } }, feed({ status: 'resolved' }), feed({ status: 'resolved', fixed_version: 0 }), feed({ status: 'undetermined' })]) {
    assert.equal(check(data).state, 'BLOCKED');
  }
});
test('all installed binary variants of a source must be resolved', () => {
  assert.equal(check(feed({ status: 'resolved', fixed_version: '3' }), value => value === pkg.source_version,
    [pkg, { ...pkg, binary: 'libfoo-extra', source_version: '1' }]).state, 'BLOCKED');
});
test('Debian fixed_version zero means not affected without comparison', () => {
  assert.equal(check(feed({ status: 'resolved', fixed_version: '0' }), () => { throw Error('unexpected comparison'); }).state, 'RESOLVED');
});
test('manifest rejects empty or incomplete source metadata', () => {
  assert.deepEqual(parseManifest('libfoo\t99\tfoo\t1:2.0-1\n'), [pkg]);
  for (const text of ['', 'libfoo\t99\t\t', 'libfoo\t99']) assert.throws(() => parseManifest(text));
});
test('official HTTPS feed preserves raw SHA256 and rejects errors, redirects and oversize data', async () => {
  const raw = Buffer.from('{"foo":{}}');
  const result = await downloadFeed(async (url, options) => {
    assert.equal(url, trackerUrl);
    assert.equal(new URL(url).protocol, 'https:');
    assert.equal(options.redirect, 'error');
    assert(options.signal instanceof AbortSignal);
    return new Response(raw);
  });
  assert.equal(result.sha256, createHash('sha256').update(raw).digest('hex'));
  await assert.rejects(downloadFeed(async () => new Response(raw), 1), /byte limit/);
  await assert.rejects(downloadFeed(async () => new Response('', { status: 503 })), /HTTP 503/);
  await assert.rejects(downloadFeed(async () => new Response('[]')), /Invalid tracker/);
  await assert.rejects(downloadFeed(async () => new Response('{')), SyntaxError);
});
