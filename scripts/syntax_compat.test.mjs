import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { rewrite, stage } from './syntax_compat.mjs';

test('rewrites a conditional with a leading-dot number and keeps every offset', () => {
  const text = 'var n=t.label==="u"?.12:0,s=1;\nvar k=a?.b;';
  const result = rewrite(text, '.js');
  assert.equal(result.text, 'var n=t.label==="u"? 12:0,s=1;\nvar k=a?.b;');
  assert.equal(result.text.length, text.length);
  assert.deepEqual(result.edits.map(edit => [edit.line, edit.column, edit.from]), [[1, 20, '?.']]);
});

test('leaves optional chaining and non-script files alone', () => {
  assert.deepEqual(rewrite('a?.b?.[0]?.(1)', '.ts').edits, []);
  assert.deepEqual(rewrite('$a ?.5 : 0;', '.php').edits, []);
});

test('stages a byte-identical tree except recorded edits, without following symlinks', () => {
  const root = mkdtempSync(join(tmpdir(), 'compat-src-'));
  const out = mkdtempSync(join(tmpdir(), 'compat-out-'));
  mkdirSync(join(root, 'js'));
  writeFileSync(join(root, 'js', 'bundle.js'), 'x=c?.5:0;\n');
  writeFileSync(join(root, 'README.md'), 'c?.5\n');
  symlinkSync('/etc', join(root, 'escape'));
  const files = stage(root, out);
  assert.equal(readFileSync(join(out, 'js', 'bundle.js'), 'utf8'), 'x=c? 5:0;\n');
  assert.equal(readFileSync(join(out, 'README.md'), 'utf8'), 'c?.5\n');
  assert.equal(files.length, 1);
  assert.equal(files[0].path, join('js', 'bundle.js'));
  assert.throws(() => readFileSync(join(out, 'escape', 'hostname')));
});
