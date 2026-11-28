import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
