import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const pack = 'local/clickhouse-query-model';
const packVersion = '0.0.1';
const query = '/opt/codeql/codeql/qlpacks/codeql/python-queries/1.8.11/Security/CWE-089/SqlInjection.ql';
const queryHash = 'e8324e568041a22d5d3a4ea21ef52ef791d67a699352273edda350caeca84964';
const modelFiles = ['qlpack.yml', 'models/clickhouse-query.model.yml'];
const fixtureFiles = ['routes', 'statements'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function snapshot(workspace) {
  const files = {};
  mkdirSync(join(workspace, 'model', 'models'), { recursive: true });
  mkdirSync(join(workspace, 'fixture'));
  for (const path of modelFiles) {
    const bytes = readFileSync(join(root, path));
    writeFileSync(join(workspace, 'model', path), bytes);
    files[`/model/${path}`] = sha256(bytes);
  }
  for (const name of fixtureFiles) {
    const bytes = readFileSync(join(root, 'controls', `${name}.fixture`));
    writeFileSync(join(workspace, 'fixture', `${name}.py`), bytes);
    files[`/fixture/${name}.py`] = sha256(bytes);
  }
  return files;
}

function command() {
  const codeql = '/opt/codeql/codeql/codeql';
  const analyze = `${codeql} database analyze /out/db ${query} --threads=2 --ram=2200 --format=sarif-latest`;
  return [
    'export HOME=/out',
    `${codeql} version --format=json > /out/version.json`,
    `sha256sum ${query} /model/qlpack.yml /model/models/clickhouse-query.model.yml /fixture/routes.py /fixture/statements.py > /out/inputs.sha256`,
    `${codeql} database create /out/db --language=python --build-mode=none --source-root=/fixture --threads=2 --ram=2200`,
    `${analyze} --output=/out/baseline.sarif`,
    `${analyze} --output=/out/model.sarif --additional-packs=/model --model-packs=${pack}@${packVersion} --rerun`,
  ].join('\n');
}

function step(location) {
  const physical = location.physicalLocation;
  return `${physical.artifactLocation.uri}:${physical.region.startLine}`;
}

function flow(result) {
  assert.equal(result.ruleId, 'py/sql-injection');
  const sink = step(result.locations[0]);
  const ordered = result.codeFlows.flatMap(path => path.threadFlows)
    .map(thread => thread.locations.map(item => step(item.location)));
  const expected = { 'statements.py:5': 'routes.py:6', 'statements.py:8': 'routes.py:9' };
  assert.ok(expected[sink], `Unexpected finding: ${sink}`);
  assert.ok(ordered.some(path => path.includes(expected[sink]) && path.at(-1) === sink),
    `Missing cross-file path to ${sink}`);
  return { source: expected[sink], sink };
}

function readResults(path) {
  const bytes = readFileSync(path);
  const { runs } = JSON.parse(bytes);
  assert.equal(runs.length, 1);
  assert.ok(runs[0].invocations?.some(invocation => invocation.executionSuccessful));
  return { run: runs[0], sha256: sha256(bytes) };
}

function verifyModelIdentity(baseline, modeled) {
  const extensions = new Map(modeled.tool.extensions.map(item => [item.name, item]));
  assert.ok(!baseline.tool.extensions?.some(item => item.name === pack));
  assert.equal(extensions.get('codeql/python-queries').semanticVersion.split('+')[0], '1.8.11');
  assert.equal(extensions.get('codeql/python-all').semanticVersion.split('+')[0], '7.2.6');
  const extension = extensions.get(pack);
  assert.ok(extension?.properties?.isCodeQLModelPack);
  assert.equal(extension.semanticVersion, packVersion);
  assert.deepEqual(extension.taxa.map(taxon => taxon.id).sort(),
    ['models/clickhouse-query.model.yml/0/0', 'models/clickhouse-query.model.yml/0/1']);
}

export function verifyClickHouseModel({ image, output, docker, workspace }) {
  const out = join(workspace, 'out');
  assert.match(image, /^sha256:[a-f0-9]{64}$/, 'Immutable image ID required');
  const inputs = snapshot(workspace);
  mkdirSync(out);
  const argv = ['run', '--rm', '--pull=never', '--network=none', '--read-only',
    '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=256',
    '--memory=3500m', '--cpus=2', '--tmpfs', '/tmp:rw,nosuid,nodev,size=1024m,mode=1777',
    '--mount', `type=bind,source=${join(workspace, 'model')},target=/model,readonly`,
    '--mount', `type=bind,source=${join(workspace, 'fixture')},target=/fixture,readonly`,
    '--mount', `type=bind,source=${out},target=/out`, '--entrypoint', '/bin/sh', image, '-ec', command()];
  docker(argv, 480000);
  const hashes = readFileSync(join(out, 'inputs.sha256'), 'utf8').trim().split('\n')
    .map(line => line.trim().split(/\s+/).reverse());
  assert.deepEqual(Object.fromEntries(hashes), { [query]: queryHash, ...inputs });
  assert.equal(JSON.parse(readFileSync(join(out, 'version.json'), 'utf8')).version, '2.27.1');
  const baseline = readResults(join(out, 'baseline.sarif'));
  const modeled = readResults(join(out, 'model.sarif'));
  assert.deepEqual(baseline.run.results, []);
  verifyModelIdentity(baseline.run, modeled.run);
  const flows = modeled.run.results.map(flow).sort((a, b) => a.sink.localeCompare(b.sink));
  assert.deepEqual(flows.map(item => item.sink), ['statements.py:5', 'statements.py:8']);
  for (const report of ['baseline', 'model']) {
    writeFileSync(`${output}.${report}.sarif`, readFileSync(join(out, `${report}.sarif`)));
  }
  return { image_id: image, inputs_sha256: inputs, query_sha256: queryHash,
    claim_boundary: 'Isolated static analysis and synthetic controls only.',
    image_argv_sha256: sha256(JSON.stringify(argv)), model: { name: pack, version: packVersion },
    flows, baseline_findings: 0, parameter_bound_control: { sink: 'statements.py:11', findings: 0 },
    baseline_sha256: baseline.sha256, modeled_sha256: modeled.sha256 };
}
