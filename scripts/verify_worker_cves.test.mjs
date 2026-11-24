import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { downloadFeed, evaluate, matchesVersion, parseManifest, targets, trackerUrl } from './verify_worker_cves.mjs';
import { assertStructuralParity, verifyStructuralBundle } from './verify_codeql_structural.mjs';

test('compiled fixture parity ignores known timing fields and detects native evidence drift', () => {
  const expected = [{ path: 'Example.java', sha256: 'source-hash' }];
  const pins = { profile_sha256: 'profile-hash', ruleset_sha256: 'ruleset-hash',
    mode: 'interprocedural-full', tool_version: '2.27.1' };
  const bundle = {
    candidate_sha256: 'candidate',
    artifacts: {
      'native.json': {
        version: '2.1.0',
        properties: { factory_native_raw_sha256: 'first-digest' },
        runs: [{
          tool: { driver: { name: 'CodeQL' } },
          invocations: [{ executionSuccessful: true, toolExecutionNotifications: [{
            descriptor: { id: 'cli/file-coverage-baseline' }, timeUtc: 'first',
            properties: { attributes: { durationMilliseconds: 20 } },
          }] }],
          properties: { metricResults: [{ ruleId: 'count', value: 2 }, { ruleId: 'types', value: 1 }] },
          results: [{ ruleId: 'fixture-control', locations: [{ physicalLocation: { region: { startLine: 2 } } }] }],
        }],
      },
      'coverage.json': {
        ...pins,
        complete: false,
        errors: ['NATIVE_SOURCE_ACCOUNTING_REQUIRED', 'NATIVE_CHALLENGES_REQUIRED'],
        source_accounting: { state: 'COMPLETE', checks: { 'Example.java': { state: 'EXTRACTED', sha256: 'source-hash' } } },
        codeql_source_execution: {
          rows: { 'Example.java': { parse_errors: 0, syntax_nodes: 1 } },
          archived_sources: { 'Example.java': 'source-hash' },
        },
      },
      'challenges.json': { observations: [] },
    },
  };
  const first = verifyStructuralBundle(bundle, 'candidate', expected, pins);
  const repeat = structuredClone(first);
  repeat.sarif.properties.factory_native_raw_sha256 = 'repeat-digest';
  const notification = repeat.sarif.runs[0].invocations[0].toolExecutionNotifications[0];
  notification.timeUtc = 'second';
  notification.properties.attributes.durationMilliseconds = 12;
  repeat.sarif.runs[0].properties.metricResults.reverse();
  repeat.sarif.runs[0].properties.metricResults[0] = { value: 1, ruleId: 'types' };
  assertStructuralParity(first, repeat);
  notification.descriptor.id = 'unexpected-diagnostic';
  assert.throws(() => assertStructuralParity(first, repeat), /changed on repeat \(report\)/);
  notification.descriptor.id = 'cli/file-coverage-baseline';
  repeat.sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine = 3;
  assert.throws(() => assertStructuralParity(first, repeat), /Native report or source coverage changed/);
  repeat.sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine = 2;
  repeat.coverage.codeql_source_execution.rows['Example.java'].parse_errors = 1;
  assert.throws(() => assertStructuralParity(first, repeat), /Native report or source coverage changed/);
  for (const change of [
    coverage => { delete coverage.codeql_source_execution; },
    coverage => { coverage.codeql_source_execution.rows['Example.java'].syntax_nodes = 0; },
    coverage => { coverage.codeql_source_execution.rows['Example.java'].parse_errors = 1; },
    coverage => { coverage.codeql_source_execution.archived_sources['Example.java'] = 'other-bytes'; },
    coverage => { coverage.profile_sha256 = 'other-profile'; },
    coverage => { coverage.ruleset_sha256 = 'other-rules'; },
  ]) {
    const changed = structuredClone(bundle);
    change(changed.artifacts['coverage.json']);
    assert.throws(() => verifyStructuralBundle(changed, 'candidate', expected, pins), /exact native file coverage/);
  }
  const invalid = structuredClone(bundle);
  invalid.artifacts['native.json'].runs = [{}];
  assert.throws(() => verifyStructuralBundle(invalid, 'candidate', expected, pins), /exact native file coverage/);
  invalid.artifacts['native.json'] = bundle.artifacts['native.json'];
  invalid.artifacts['coverage.json'].errors.push('ADAPTER_ERROR');
  assert.throws(() => verifyStructuralBundle(invalid, 'candidate', expected, pins), /exact native file coverage/);
  bundle.artifacts['coverage.json'].source_accounting.checks['Example.java'].sha256 = 'other-bytes';
  assert.throws(() => verifyStructuralBundle(bundle, 'candidate', expected, pins), /exact native file coverage/);
});

test('worker workflow path filters cover every Docker build input without framework scope', () => {
  const workflow = readFileSync('.github/workflows/worker-verification.yml', 'utf8').replace(/\r\n/g, '\n');
  const dockerfile = readFileSync('deploy/deep-adapters/Dockerfile', 'utf8').replace(/\r\n/g, '\n');
  const copySources = [...dockerfile.matchAll(/^COPY\s+(.+)$/gm)]
    .flatMap(match => match[1].trim().split(/\s+/).slice(0, -1));
  const bindSources = [...dockerfile.matchAll(/^RUN\s+.*?--mount=type=bind,source=([^,\s]+)/gm)]
    .map(match => match[1]);
  const dockerSourceFiles = [...new Set([...copySources, ...bindSources]
    .filter(path => path.startsWith('factoryline/')))];
  assert.deepEqual(dockerSourceFiles.sort(), [
    'factoryline/__init__.py',
    'factoryline/assembly_process.py',
    'factoryline/audit_taxonomy.py',
    'factoryline/data/junie_pack.json',
    'factoryline/deep_audit.py',
    'factoryline/deep_audit_attestation.py',
    'factoryline/deep_audit_io.py',
    'factoryline/deep_audit_contract.py',
    'factoryline/deep_audit_loop.py',
    'factoryline/deep_audit_sarif.py',
    'factoryline/enterprise_receipts.py',
    'factoryline/repository_checkpoint_audit.py',
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
    assert(paths.includes('scripts/verify_codeql_structural.mjs'));
    assert(paths.includes('.github/workflows/worker-verification.yml'));
    for (const path of dockerSourceFiles) assert(paths.includes(path), `missing Docker build input ${path}`);
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
