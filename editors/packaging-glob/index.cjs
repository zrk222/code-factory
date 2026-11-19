'use strict';

const { glob } = require('glob');
const fs = require('node:fs');

const supported = new Set([
  'cwd', 'onlyFiles', 'followSymbolicLinks', 'fs', 'caseSensitiveMatch', 'dot', 'ignore',
]);

exports.glob = async (patterns, options = {}) => {
  if (patterns !== '**') throw new Error('Unsupported VSCE enumeration pattern');
  for (const key of Object.keys(options)) {
    if (!supported.has(key)) throw new Error('Unsupported VSCE enumeration option: ' + key);
  }
  return glob(patterns, {
    cwd: options.cwd,
    nodir: options.onlyFiles !== false,
    follow: options.followSymbolicLinks !== false,
    fs: options.fs ? { ...fs, ...options.fs } : undefined,
    nocase: options.caseSensitiveMatch === false,
    dot: options.dot === true,
    ignore: options.ignore,
    posix: true,
  });
};
