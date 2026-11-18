'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { glob } = require('tinyglobby');

test('VSCE enumeration preserves files, dotfiles and ignored dependencies', async () => {
  const cwd = await fs.mkdtemp(join(tmpdir(), 'factory-package-files-'));
  try {
    await fs.mkdir(join(cwd, 'dist'));
    await fs.mkdir(join(cwd, 'node_modules'));
    await Promise.all(['package.json', '.hidden', 'dist/extension.js', 'node_modules/ignored.js']
      .map(name => fs.writeFile(join(cwd, name), 'fixture')));
    const options = { cwd, onlyFiles: true, dot: true, ignore: ['node_modules/**'] };
    assert.deepEqual((await glob('**', options)).sort(),
      ['.hidden', 'dist/extension.js', 'package.json']);
    assert.ok(!(await glob('**', { ...options, dot: false })).includes('.hidden'));
    assert.ok((await glob('**', { ...options, onlyFiles: false })).includes('dist'));
    assert.deepEqual((await glob('**', { ...options, ignore: ['DIST/**', 'NODE_MODULES/**'],
      caseSensitiveMatch: false })).sort(), ['.hidden', 'package.json']);
  } finally {
    await fs.rm(cwd, { recursive: true, force: true });
  }
});

test('VSCE enumeration uses its supplied filesystem without traversing directory links', async () => {
  const cwd = await fs.mkdtemp(join(tmpdir(), 'factory-package-links-'));
  const target = await fs.mkdtemp(join(tmpdir(), 'factory-package-target-'));
  try {
    await fs.writeFile(join(target, 'outside.js'), 'fixture');
    await fs.symlink(target, join(cwd, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    const nodefs = require('node:fs');
    let reads = 0;
    const asFile = entry => entry.isSymbolicLink() ? Object.create(entry, {
      isFile: { value: () => true }, isDirectory: { value: () => false },
      isSymbolicLink: { value: () => false },
    }) : entry;
    const custom = {
      readdir: (path, options, callback) => {
        reads++;
        nodefs.readdir(path, options, (err, entries) =>
          callback(err, err ? entries : entries.map(asFile)));
      },
      readdirSync: (path, options) => nodefs.readdirSync(path, options).map(asFile),
    };
    const files = await glob('**', { cwd, onlyFiles: true, followSymbolicLinks: false,
      fs: custom, dot: true });
    assert.ok(reads > 0);
    assert.deepEqual(files, ['linked']);
  } finally {
    await fs.rm(cwd, { recursive: true, force: true });
    await fs.rm(target, { recursive: true, force: true });
  }
});

test('unreviewed options and patterns fail closed', async () => {
  await assert.rejects(glob('**', { unsupported: true }), /Unsupported VSCE enumeration option/);
  await assert.rejects(glob('arbitrary'), /Unsupported VSCE enumeration pattern/);
});
