import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const sha256 = 'a9d670370380fde52d5395debb2e2412639920be5ce9d6aac5349df50d45e9a5';
const generation = '1794393188720263';

test('OSV PyPI feed pin binds the retained archive and checksum everywhere', () => {
  const dockerfile = readFileSync('deploy/deep-adapters/Dockerfile', 'utf8');
  const profile = JSON.parse(readFileSync('deploy/deep-adapters/profiles/osv.json', 'utf8'));
  const readme = readFileSync('deploy/deep-adapters/README.md', 'utf8');
  const dockerAdd = dockerfile.match(/^ADD --checksum=sha256:([a-f0-9]{64}) "([^"]+)" \/tmp\/osv-pypi-all\.zip$/m);

  assert.ok(dockerAdd, 'Dockerfile must pin the remote PyPI archive with ADD --checksum');
  assert.equal(dockerAdd[1], sha256);
  const source = new URL(dockerAdd[2]);
  assert.equal(source.href,
    `https://github.com/zrk222/code-factory/releases/download/v0.49.6/osv-pypi-${generation}-${sha256}.zip`);
  assert.equal(profile.ruleset_sha256, sha256);
  assert.match(readme, new RegExp(`GCS generation ${generation}\\b`));
});
