import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const pack = 'local/clickhouse-query-model';
const packVersion = '0.0.1';
const query = '/opt/codeql/codeql/qlpacks/codeql/python-queries/1.8.11/Security/CWE-089/SqlInjection.ql';
const queryHash = 'e8324e568041a22d5d3a4ea21ef52ef791d67a699352273edda350caeca84964';
const modelFiles = ['qlpack.yml', 'models/clickhouse-query.model.yml'];
const fixtureFiles = ['routes', 'statements'];
const reportFiles = ['inputs.sha256', 'version.json', 'baseline.sarif', 'model.sarif'];
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
  // Exact read-only mounts remain readable even when the host uses a private umask.
  for (const dir of ['model', 'model/models', 'fixture']) chmodSync(join(workspace, dir), 0o755);
  for (const path of Object.keys(files)) chmodSync(join(workspace, path.slice(1)), 0o644);
  return files;
}

function command() {
  const codeql = '/opt/codeql/codeql/codeql';
  const analyze = `${codeql} database analyze /out/db ${query} --threads=2 --ram=2200 --format=sarif-latest`;
  return [
    'export HOME=/out',
    `${codeql} version --format=json > /out/version.json`,
    `sha256sum ${query} /model/qlpack.yml /model/models/clickhouse-query.model.yml /fixture/routes.py /fixture/statements.py > /out/inputs.sha256`,
    `${codeql} database create /out/db --language=python --build-mode=none --source-root=/fixture --threads=2 --ram=2200 >&2`,
    `${analyze} --output=/out/baseline.sarif >&2`,
    `${analyze} --output=/out/model.sarif --additional-packs=/model --model-packs=${pack}@${packVersion} --rerun >&2`,
    `/usr/local/bin/python -I -c 'import base64,json,sys; from pathlib import Path; print(json.dumps({name:base64.b64encode((Path("/out")/name).read_bytes()).decode("ascii") for name in sys.argv[1:]}))' ${reportFiles.join(' ')}`,
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

function readResults(bytes) {
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
  assert.match(image, /^sha256:[a-f0-9]{64}$/, 'Immutable image ID required');
  const inputs = snapshot(workspace);
  const argv = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--user=1000:1000',
    '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=256',
    '--memory=3500m', '--cpus=2', '--tmpfs', '/tmp:rw,nosuid,nodev,size=1024m,mode=1777',
    '--mount', `type=bind,source=${join(workspace, 'model')},target=/model,readonly`,
    '--mount', `type=bind,source=${join(workspace, 'fixture')},target=/fixture,readonly`,
    '--tmpfs', '/out:rw,nosuid,nodev,noexec,size=768m,mode=0700,uid=1000,gid=1000',
    '--entrypoint', '/bin/sh', image, '-ec', command()];
  const received = JSON.parse(docker(argv, 480000));
  assert.deepEqual(Object.keys(received).sort(), [...reportFiles].sort());
  const reports = Object.fromEntries(reportFiles.map(name => {
    const bytes = Buffer.from(received[name], 'base64');
    assert.equal(bytes.toString('base64'), received[name], `Invalid output encoding: ${name}`);
    return [name, bytes];
  }));
  const hashes = reports['inputs.sha256'].toString('utf8').trim().split('\n')
    .map(line => line.trim().split(/\s+/).reverse());
  assert.deepEqual(Object.fromEntries(hashes), { [query]: queryHash, ...inputs });
  assert.equal(JSON.parse(reports['version.json']).version, '2.27.1');
  const baseline = readResults(reports['baseline.sarif']);
  const modeled = readResults(reports['model.sarif']);
  assert.deepEqual(baseline.run.results, []);
  verifyModelIdentity(baseline.run, modeled.run);
  const flows = modeled.run.results.map(flow).sort((a, b) => a.sink.localeCompare(b.sink));
  assert.deepEqual(flows.map(item => item.sink), ['statements.py:5', 'statements.py:8']);
  for (const report of ['baseline', 'model']) {
    writeFileSync(`${output}.${report}.sarif`, reports[`${report}.sarif`]);
  }
  return { image_id: image, inputs_sha256: inputs, query_sha256: queryHash,
    claim_boundary: 'Isolated static analysis and synthetic controls only.',
    image_argv_sha256: sha256(JSON.stringify(argv)), model: { name: pack, version: packVersion },
    flows, baseline_findings: 0, parameter_bound_control: { sink: 'statements.py:11', findings: 0 },
    baseline_sha256: baseline.sha256, modeled_sha256: modeled.sha256 };
}
