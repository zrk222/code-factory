import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { downloadFeed, evaluate, matchesVersion, parseManifest, targets, trackerUrl } from './verify_worker_cves.mjs';

test('worker workflow path filters cover every Docker build input without framework scope', () => {
  const workflow = readFileSync('.github/workflows/worker-verification.yml', 'utf8').replace(/\r\n/g, '\n');
  const dockerfile = readFileSync('deploy/deep-adapters/Dockerfile', 'utf8').replace(/\r\n/g, '\n');
  const dockerSourceFiles = [...new Set([...dockerfile.matchAll(/^COPY\s+(.+)$/gm)]
    .flatMap(match => match[1].trim().split(/\s+/).slice(0, -1))
    .filter(path => path.startsWith('factoryline/')))];
  assert.deepEqual(dockerSourceFiles.sort(), [
    'factoryline/__init__.py',
    'factoryline/deep_audit_io.py',
    'factoryline/runtime_audit_common.py',
    'factoryline/runtime_audit_process.py',
  ].sort());

  const triggers = [...workflow.matchAll(/^  (pull_request|push):\n([\s\S]*?)(?=^  [a-z_]+:|^permissions:)/gm)];
  assert.deepEqual(triggers.map(match => match[1]).sort(), ['pull_request', 'push']);
  for (const trigger of triggers) {
    const paths = [...trigger[2].matchAll(/^      - (.+)$/gm)].map(match => match[1]);
    assert(paths.includes('deploy/deep-adapters/**'));
    assert(paths.includes('.dockerignore'));
    assert(paths.includes('scripts/verify_worker_cves*.mjs'));
    assert(paths.includes('scripts/verify_semgrep_surface.mjs'));
    assert(paths.includes('scripts/verify_codeql_cross_file.mjs'));
    assert(paths.includes('.github/workflows/worker-verification.yml'));
    for (const path of dockerSourceFiles) assert(paths.includes(path), `missing Docker COPY input ${path}`);
    assert.deepEqual(paths.filter(path => path.startsWith('factoryline/')).sort(), dockerSourceFiles.slice().sort());
    assert.equal(paths.includes('factoryline/**'), false);
    assert.equal(paths.some(path => path.startsWith('factoryline/') && path.endsWith('/judge_framework.json')), false);
  }
  assert.match(workflow, /^  workflow_dispatch:\s*$/m);
});

test('tool versions require exact tokens, not a substring or prerelease', () => {
  assert(matchesVersion('Version: v2.27.1\n', '2.27.1'));
  assert(matchesVersion('{"version":"2.27.1"}', '2.27.1'));
  for (const value of ['2.27.10', '12.27.1', '2.27.1-rc1', '2.27.1+local']) {
    assert.equal(matchesVersion(value, '2.27.1'), false);
  }
});

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
