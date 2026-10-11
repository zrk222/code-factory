import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { selectWorkerTargets, sdkTargets } from './select_worker_targets.mjs';

const base = 'a'.repeat(40);
const head = 'b'.repeat(40);
const event = fields => fields;
const paths = (...items) => Buffer.from(`${items.join('\0')}\0`);
const prEvent = (baseSha = base, headSha = head) => ({ pull_request: { base: { sha: baseSha }, head: { sha: headSha } } });
const pushEvent = (before = base, after = head) => ({ before, after });
function gitFor({ checkout = head, diffPaths = paths('README.md'), ancestors = new Set([base, head]), dirty = false } = {}) {
  return (_file, args) => {
    if (args[0] === 'rev-parse') return Buffer.from(`${checkout}\n`);
    if (args[0] === 'diff-index') {
      if (dirty) throw new Error('tracked checkout is dirty');
      return Buffer.alloc(0);
    }
    if (args[0] === 'merge-base') {
      if (!ancestors.has(args[2])) throw new Error('not an ancestor');
      return Buffer.alloc(0);
    }
    if (args[0] === 'diff') {
      assert.deepEqual(args.slice(-3), [base, checkout, '--']);
      return diffPaths;
    }
    throw new Error(`unexpected git command: ${args.join(' ')}`);
  };
}

test('Semgrep rule, profile, control and verifier changes skip SDK matrix', () => {
  const input = prEvent();
  const result = selectWorkerTargets('pull_request', input, gitFor({ diffPaths: paths(
    'deploy/deep-adapters/rules/semgrep-pattern-limited.yml',
    'deploy/deep-adapters/profiles/semgrep-pattern-limited.json',
    'deploy/deep-adapters/rules/tests/python-controls.txt',
    'deploy/deep-adapters/rules/tests/javascript-controls.js',
    'scripts/verify_semgrep_surface.mjs',
  ) }));
  assert.equal(result.sdk, 'false');
  assert.equal(result.reason, 'semgrep-only');
  assert.deepEqual(JSON.parse(result.matrix), sdkTargets);
});

test('mixed and common or unknown paths retain every SDK target', () => {
  const input = pushEvent();
  for (const changed of [
    ['deploy/deep-adapters/rules/semgrep-pattern-limited.yml', 'factoryline/runtime_audit_common.py'],
    ['README.md'],
    ['deploy/deep-adapters/Dockerfile'],
  ]) {
    assert.equal(selectWorkerTargets('push', input, gitFor({ diffPaths: paths(...changed) })).sdk, 'true');
  }
});

test('malicious or malformed revisions never reach git', () => {
  let calls = 0;
  const git = () => { calls++; return paths('deploy/deep-adapters/rules/semgrep-pattern-limited.yml'); };
  const result = selectWorkerTargets('push', pushEvent(`${base}; touch BAD`, head), git);
  assert.equal(result.sdk, 'true');
  assert.equal(result.reason, 'unresolvable-revisions');
  assert.equal(calls, 0);
});

test('empty and malformed diff output retain full matrix', () => {
  const input = pushEvent();
  assert.equal(selectWorkerTargets('push', input, gitFor({ diffPaths: Buffer.alloc(0) })).sdk, 'true');
  assert.equal(selectWorkerTargets('push', input, gitFor({ diffPaths: Buffer.from('deploy/deep-adapters/rules/semgrep-pattern-limited.yml') })).sdk, 'true');
});

test('manual and unknown events retain full matrix', () => {
  assert.equal(selectWorkerTargets('workflow_dispatch', {}).sdk, 'true');
  assert.equal(selectWorkerTargets('schedule', {}).sdk, 'true');
});

test('Git failure retains full matrix', () => {
  const input = pushEvent();
  const result = selectWorkerTargets('push', input, () => { throw new Error('git unavailable'); });
  assert.equal(result.sdk, 'true');
  assert.equal(result.reason, 'git-diff-failed');
});

test('PR paths are selected from the checked-out merge candidate', () => {
  const input = prEvent();
  assert.equal(selectWorkerTargets('pull_request', input, gitFor({ diffPaths: paths('README.md') })).sdk, 'true');
  assert.equal(selectWorkerTargets('pull_request', input, gitFor({ diffPaths: paths('deploy/deep-adapters/rules/semgrep-pattern-limited.yml') })).sdk, 'false');
});

test('push checkout mismatch and PR non-ancestor fail closed', () => {
  assert.equal(selectWorkerTargets('push', pushEvent(), gitFor({ checkout: 'c'.repeat(40) })).sdk, 'true');
  assert.equal(selectWorkerTargets('pull_request', prEvent(), gitFor({ ancestors: new Set([base]) })).sdk, 'true');
});

test('dirty tracked checkout fails closed', () => {
  assert.equal(selectWorkerTargets('push', pushEvent(), gitFor({ dirty: true })).sdk, 'true');
});

test('malformed git revision and ancestry outputs fail closed', () => {
  const malformedRevision = (_file, args) => args[0] === 'rev-parse' ? Buffer.from(`${head}\nextra\n`) : Buffer.alloc(0);
  const malformedAncestry = (_file, args) => args[0] === 'rev-parse' ? Buffer.from(`${head}\n`) : Buffer.from('unexpected');
  assert.equal(selectWorkerTargets('push', pushEvent(), malformedRevision).sdk, 'true');
  assert.equal(selectWorkerTargets('pull_request', prEvent(), malformedAncestry).sdk, 'true');
});

test('CLI reads GitHub event name separately and writes GitHub outputs', () => {
  const directory = mkdtempSync(join(tmpdir(), 'worker-target-selector-'));
  const output = join(directory, 'github-output.txt');
  const script = fileURLToPath(new URL('./select_worker_targets.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script], {
    encoding: 'utf8',
    env: { ...process.env, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_EVENT_JSON: JSON.stringify({ inputs: {} }), GITHUB_OUTPUT: output },
  });
  try {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
    const lines = readFileSync(output, 'utf8').trim().split('\n');
    assert.equal(lines[0], 'sdk=true');
    assert.equal(lines[1], `matrix=${JSON.stringify(sdkTargets)}`);
    assert.equal(lines[2], 'reason=manual-or-unknown-event');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
