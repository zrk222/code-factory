import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { corpusDigest, summarize } from './scan_benchmark.mjs';

test('corpus digest binds names and bytes of Python files only', t => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-bench-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'pkg'));
  writeFileSync(join(dir, 'pkg', 'a.py'), 'x = 1\ny = 2\n');
  writeFileSync(join(dir, 'notes.txt'), 'ignored\n');
  const first = corpusDigest(dir);
  assert.equal(first.python_files, 1);
  assert.equal(first.lines, 2);
  writeFileSync(join(dir, 'pkg', 'a.py'), 'x = 1\ny = 3\n');
  assert.notEqual(corpusDigest(dir).corpus_sha256, first.corpus_sha256);
});

test('summary requires identical output and reports the spread', () => {
  const corpus = { corpus_sha256: 'c', python_files: 1, lines: 100 };
  const stable = summarize(corpus, 0, [{ seconds: 10, digest: 'a' }, { seconds: 10.5, digest: 'a' }, { seconds: 10.2, digest: 'a' }], {});
  assert.equal(stable.median_seconds, 10.2);
  assert.equal(stable.stable_output, true);
  assert.equal(stable.stable_timing, true);
  const drift = summarize(corpus, 0, [{ seconds: 10, digest: 'a' }, { seconds: 12, digest: 'b' }], {});
  assert.equal(drift.stable_output, false);
  assert.equal(drift.stable_timing, false);
});

test('failed scans cannot publish a timing receipt', t => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-bench-fail-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'factoryline'));
  writeFileSync(join(dir, 'factoryline', '__init__.py'), '');
  writeFileSync(join(dir, 'factoryline', 'cli.py'), 'def main():\n    return 7\n');
  const out = join(dir, 'timing.json');
  const cli = fileURLToPath(new URL('./scan_benchmark.mjs', import.meta.url));
  const run = spawnSync(process.execPath, [cli, dir, out, '--runs', '1'], { cwd: dir, encoding: 'utf8' });
  assert.ifError(run.error);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /scan failed with exit 7/);
  assert.equal(existsSync(out), false);
});
