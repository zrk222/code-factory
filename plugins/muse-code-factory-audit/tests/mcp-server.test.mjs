import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const server = fileURLToPath(new URL('../mcp/server.mjs', import.meta.url));

test('MCP method dispatch rejects prototype property names as unknown methods', () => {
  const requests = ['constructor', '__proto__', 'toString'].map((method, index) =>
    JSON.stringify({ jsonrpc: '2.0', id: index + 1, method }),
  );
  const child = spawnSync(process.execPath, [server], {
    input: `${requests.join('\n')}\n`,
    encoding: 'utf8',
    timeout: 5_000,
  });

  assert.equal(child.status, 0, child.stderr);
  const responses = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
  assert.deepEqual(
    responses.map((response) => response.error?.code),
    [-32601, -32601, -32601],
  );
  assert.deepEqual(
    responses.map((response) => response.id),
    [1, 2, 3],
  );
});

test('receipt MAC creation is stable for the local key and rejects corrupt key bytes', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'muse-receipt-mac-'));
  try {
    mkdirSync(path.join(directory, 'cf-build-audit'), { recursive: true });
    const script = `import { receiptMac } from ${JSON.stringify(new URL('../hooks/audit.mjs', import.meta.url).href)};\nconst a=receiptMac('payload',true); const b=receiptMac('payload'); if(a!==b || !/^[a-f0-9]{64}$/.test(a)) process.exit(2);`;
    const run = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      encoding: 'utf8', timeout: 5_000, env: { ...process.env, MUSE_PLUGIN_DATA_DIR: directory },
    });
    assert.equal(run.status, 0, run.stderr);
    const keyPath = path.join(directory, 'cf-build-audit', 'receipt-key.bin');
    assert.equal(readFileSync(keyPath).length, 32);
    writeFileSync(keyPath, Buffer.alloc(31));
    const corrupt = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      encoding: 'utf8', timeout: 5_000, env: { ...process.env, MUSE_PLUGIN_DATA_DIR: directory },
    });
    assert.notEqual(corrupt.status, 0);
    assert.match(corrupt.stderr, /Invalid local audit key/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('runHook honors explicit event matching and ignores unrelated hook events', () => {
  const audit = fileURLToPath(new URL('../hooks/audit.mjs', import.meta.url));
  const directory = mkdtempSync(path.join(os.tmpdir(), 'muse-run-hook-'));
  try {
    const launcher = `import { runHook } from ${JSON.stringify(new URL('../hooks/audit.mjs', import.meta.url).href)}; runHook('PostToolUse');`;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', launcher], {
      input: JSON.stringify({ hook_event_name: 'Stop', cwd: directory }), encoding: 'utf8', timeout: 5_000,
      env: { ...process.env, MUSE_PLUGIN_DATA_DIR: path.join(directory, 'state') },
    });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, '');
    assert.ok(readFileSync(audit, 'utf8').includes('runHook(expectedEvent)'));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
