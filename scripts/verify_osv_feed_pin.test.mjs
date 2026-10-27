import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const sha256 = '95b325be6311d4d9ee90adf4207e73194e92480c2a72a71bbc3ac39fc74e0be5';
const generation = '1792839797362039';

test('OSV PyPI feed pin binds the immutable GCS generation and checksum everywhere', () => {
  const dockerfile = readFileSync('deploy/deep-adapters/Dockerfile', 'utf8');
  const profile = JSON.parse(readFileSync('deploy/deep-adapters/profiles/osv.json', 'utf8'));
  const readme = readFileSync('deploy/deep-adapters/README.md', 'utf8');
  const dockerAdd = dockerfile.match(/^ADD --checksum=sha256:([a-f0-9]{64}) "([^"]+)" \/tmp\/osv-pypi-all\.zip$/m);

  assert.ok(dockerAdd, 'Dockerfile must pin the remote PyPI archive with ADD --checksum');
  assert.equal(dockerAdd[1], sha256);
  const source = new URL(dockerAdd[2]);
  assert.equal(source.origin, 'https://storage.googleapis.com');
  assert.equal(source.pathname, '/storage/v1/b/osv-vulnerabilities/o/PyPI%2Fall.zip');
  assert.equal(source.searchParams.get('alt'), 'media');
  assert.equal(source.searchParams.get('generation'), generation);
  assert.equal(profile.ruleset_sha256, sha256);
  assert.match(readme, new RegExp(`GCS generation ${generation}\\b`));
});
