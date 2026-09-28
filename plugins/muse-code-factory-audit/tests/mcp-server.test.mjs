import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
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
