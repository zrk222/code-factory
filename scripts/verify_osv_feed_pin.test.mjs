import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const sha256 = '185c442aaa1441952582615f5543fad026b6ec13df4b03ed0d18ac3389001abc';
const generation = '1793594892933509';

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
