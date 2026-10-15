import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { docker } from './verify_worker_cves.mjs';

const target = 'GHSA-29vq-49wr-vm6x';
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const digest = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(canonical(value))).digest('hex');

export function createOSVContract(profile, name, entries, image) {
  if (!/^[a-f0-9]{64}$/.test(profile.ruleset_sha256) || !/^sha256:[a-f0-9]{64}$/.test(image))
    throw new Error('Missing immutable OSV database or image binding');
  return { schema: 'factory.deep-adapter-input.v1', run_id: `osv-native-${name}`,
    manifest_sha256: digest(entries), inventory: { candidate_sha256: digest(entries), files: entries },
    lane: { engine: 'osv', mode: profile.mode, tool_version: profile.tool_version, image,
      ruleset_sha256: profile.ruleset_sha256, timeout_seconds: 90, memory_mib: 512,
      report: 'report.json', coverage: 'coverage.json', challenge_report: 'challenges.json', languages: ['text'], rule_ids: [],
      native_policy: { database_path: '/opt/factory/osv-db/osv-scanner/PyPI/all.zip',
        database_sha256: profile.ruleset_sha256, baseline_config_sha256: digest('\n'), advisory_aliases: {} } },
    obligations: [] };
}

export function validateOSVControl(bundle, expectedHits) {
  const report = bundle?.artifacts?.['report.json'];
  const coverage = bundle?.artifacts?.['coverage.json'];
  const ledger = report?.factory_lookup_execution;
  if (ledger?.schema !== 'factory.osv-lookup-execution.v1' || !Array.isArray(ledger.queries) || !ledger.queries.length)
    throw new Error('Missing native OSV lookup ledger');
  if (coverage?.version_probe?.exit_code !== 0 || !coverage.native_invocations?.length
      || coverage.native_invocations.some(row => ![0, 1].includes(row.execution?.exit_code)))
    throw new Error('Native OSV execution failed or is missing');
  const hits = (report.results ?? []).flatMap(row => row.packages ?? [])
    .flatMap(pkg => pkg.vulnerabilities ?? []).filter(v => [v.id, ...(v.aliases ?? [])].includes(target));
  if (hits.length !== expectedHits) throw new Error(`Expected ${expectedHits} target findings, got ${hits.length}`);
  return { target_findings: hits.length, native_queries: ledger.queries.length,
    bundle_sha256: digest(bundle), remaining_errors: coverage.errors ?? [] };
}

export function verifyOSVWorker(image, output) {
  const result = { schema: 'factory.osv-native-worker-controls.v1', state: 'BLOCKED', controls: [],
    candidate_commit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    claim_boundary: 'Three seeded native controls; not independent accuracy, complete challenge admission or release authority.' };
  const directory = mkdtempSync(join(tmpdir(), 'factory-osv-native-'));
  const profile = JSON.parse(readFileSync(new URL('../deploy/deep-adapters/profiles/osv.json', import.meta.url), 'utf8'));
  try {
    result.image_id = docker(['image', 'inspect', image, '--format', '{{.Id}}']).stdout.trim();
    if (!/^sha256:[a-f0-9]{64}$/.test(result.image_id)) throw new Error('Invalid immutable image ID');
    const cases = [
      ['root-config-vulnerable', { 'requirements.txt': 'Werkzeug==0.1\n',
        'osv-scanner.toml': `[[IgnoredVulns]]\nid = "${target}"\nreason = "synthetic suppression control"\n` }, 1],
      ['nested-config-vulnerable', { 'nested/requirements.txt': 'Werkzeug==0.1\n',
        'nested/osv-scanner.toml': '[[PackageOverrides]]\nname = "werkzeug"\necosystem = "PyPI"\nignore = true\n' }, 1],
      ['root-config-fixed', { 'requirements.txt': 'Werkzeug==3.1.6\n' }, 0],
    ];
    for (const [name, files, expectedHits] of cases) {
      const source = join(directory, name); mkdirSync(source);
      const entries = Object.entries(files).sort().map(([path, body]) => {
        mkdirSync(dirname(join(source, path)), { recursive: true }); writeFileSync(join(source, path), body);
        return { path, bytes: Buffer.byteLength(body), sha256: digest(body), language: 'text' };
      });
      const contract = createOSVContract(profile, name, entries, result.image_id);
      const contractPath = join(directory, `${name}.json`); writeFileSync(contractPath, JSON.stringify(contract));
      const container = `factory-osv-control-${randomUUID()}`;
      let execution;
      try {
        execution = docker(['run', '--rm', '--pull=never', '--name', container, '--network=none', '--read-only',
          '--user=1000:1000', '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=64',
          '--memory=512m', '--memory-swap=512m', '--cpus=1', '--log-driver=none',
          '--mount', `type=bind,source=${source},target=/src,readonly`,
          '--mount', `type=bind,source=${contractPath},target=/factory-contract.json,readonly`,
          '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,mode=1777',
          '--tmpfs', '/out:rw,nosuid,nodev,noexec,size=32m,mode=1777',
          result.image_id, 'osv', '--mode', profile.mode]);
      } finally {
        docker(['rm', '-f', container], [0, 1]);
        if (docker(['container', 'ls', '-aq', '--filter', `name=^/${container}$`]).stdout.trim())
          throw new Error('Native control container cleanup incomplete');
      }
      const bundle = JSON.parse(execution.stdout);
      mkdirSync(dirname(output), { recursive: true });
      writeFileSync(`${output}.${name}.bundle.json`, `${JSON.stringify(bundle)}\n`);
      const checked = validateOSVControl(bundle, expectedHits);
      result.controls.push({ name, state: 'PASS', sources: entries, ...checked });
    }
    result.state = 'PASS';
  } catch (error) { result.error = error.message; }
  finally {
    if (dirname(resolve(directory)) !== resolve(tmpdir())) throw new Error('Unsafe temporary cleanup path');
    rmSync(directory, { recursive: true, force: true });
    mkdirSync(dirname(output), { recursive: true }); writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`);
  }
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [image, output] = process.argv.slice(2);
  if (!image || !output) throw new Error('Usage: node scripts/verify_osv_worker.mjs IMAGE OUTPUT');
  const result = verifyOSVWorker(image, output);
  console.log(JSON.stringify({ state: result.state, image_id: result.image_id, error: result.error }));
  process.exitCode = result.state === 'PASS' ? 0 : 1;
}
