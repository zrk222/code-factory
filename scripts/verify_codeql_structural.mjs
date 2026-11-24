import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { arch, platform, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { docker } from './verify_worker_cves.mjs';

const [image, output, target] = process.argv.slice(2);
const language = {
  'codeql-java-worker': 'java',
  'codeql-csharp-worker': 'csharp',
  'codeql-go-worker': 'go',
}[target];
if (!image || !output || !language) throw new Error('Specify image, output, and a compiled CodeQL target');
const fixtures = {
  java: { 'Example.java': 'public class Example { int sum(int x, int y) { return x + y; } }\n' },
  csharp: { 'Example.cs': 'public class Example { public int Sum(int x, int y) => x + y; }\n' },
  go: {
    'nested/go.mod': 'module example.test/native\n\ngo 1.24.0\n',
    'nested/compute.go': 'package native\n\nfunc Add(x, y int) int { return x + y }\n',
    'nested/compute_test.go': 'package native\n\nimport "testing"\n\nfunc TestCompileOnly(*testing.T) { panic("not an execution test") }\n',
  },
}[language];
const hash = value => createHash('sha256').update(value).digest('hex');
const profilePath = `deploy/deep-adapters/profiles/codeql-${language}-full.json`;
const profileRaw = readFileSync(profilePath);
const profile = JSON.parse(profileRaw);
const workspace = mkdtempSync(join(tmpdir(), 'cf-codeql-structural-'));
const receipt = {
  schema: 'factory.codeql-structural-controls.v1',
  state: 'BLOCKED',
  scope: 'Benign offline source accounting fixture. No recall, signed family qualification, or release claim.',
  target, image, observed_at: new Date().toISOString(),
  candidate_commit: process.env.GITHUB_SHA ?? null,
  host: { platform: platform(), architecture: arch() },
  profile_sha256: hash(profileRaw),
  recipe_sha256: hash(readFileSync('deploy/deep-adapters/Dockerfile')),
};
try {
  mkdirSync(dirname(resolve(output)), { recursive: true });
  const id = docker(['image', 'inspect', image, '--format', '{{.Id}}']).stdout.trim();
  if (!/^sha256:[a-f0-9]{64}$/.test(id)) throw new Error('Immutable image ID required');
  receipt.image_id = id;
  receipt.host.docker = JSON.parse(docker(['version', '--format', '{{json .Server}}']).stdout);
  const isolation = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--user=1000:1000',
    '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=128', '--memory=3g', '--cpus=2',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=1024m,mode=1777', '--tmpfs', '/out:rw,nosuid,nodev,noexec,size=64m,mode=1777'];
  const installed = docker([...isolation, '--entrypoint', '/bin/cat', id, '/opt/factory/adapter-profile.json']).stdout;
  if (hash(installed) !== receipt.profile_sha256) throw new Error('Image profile differs from candidate');
  const source = join(workspace, 'source');
  const files = Object.entries(fixtures).map(([path, content]) => {
    mkdirSync(dirname(join(source, path)), { recursive: true });
    writeFileSync(join(source, path), content);
    return { path, sha256: hash(content), language: path.endsWith('go.mod') ? 'dependency' : language };
  });
  const candidate = hash(JSON.stringify(files));
  const lane = { id: 'codeql-structural-control', family: 'static', languages: [language],
    timeout_seconds: 900, memory_mib: 3072, report: 'native.json',
    coverage: 'coverage.json', challenge_report: 'challenges.json' };
  for (const key of ['engine', 'mode', 'tool_version', 'ruleset_sha256']) lane[key] = profile[key];
  const contract = { schema: 'factory.deep-adapter-input.v1', run_id: 'codeql-structural-control',
    manifest_sha256: hash(JSON.stringify({ profile: receipt.profile_sha256, candidate })),
    inventory: { candidate_sha256: candidate, files }, lane, obligations: [] };
  const contractPath = join(workspace, 'contract.json');
  writeFileSync(contractPath, JSON.stringify(contract));
  const started = Date.now();
  const { stdout, stderr, status } = docker([...isolation,
    '--mount', `type=bind,source=${source},target=/src,readonly`,
    '--mount', `type=bind,source=${contractPath},target=/factory-contract.json,readonly`,
    id, profile.engine, '--mode', profile.mode], [0, 1, 2], 960000);
  writeFileSync(`${output}.bundle.json`, stdout);
  writeFileSync(`${output}.stderr.txt`, stderr);
  receipt.execution = { status, elapsed_ms: Date.now() - started, stdout_sha256: hash(stdout), stderr_sha256: hash(stderr) };
  if (status !== 0) throw new Error('Worker failed the native control');
  const bundle = JSON.parse(stdout);
  const coverage = bundle.artifacts?.['coverage.json']?.source_accounting;
  const expected = files.filter(file => file.language === language);
  if (bundle.candidate_sha256 !== candidate || !bundle.artifacts?.['native.json']?.runs?.length
      || coverage?.state !== 'COMPLETE' || Object.keys(coverage.checks ?? {}).length !== expected.length
      || expected.some(file => coverage.checks[file.path]?.state !== 'EXTRACTED'
        || coverage.checks[file.path]?.sha256 !== file.sha256)) {
    throw new Error('Expected exact native file coverage and a source-bound report');
  }
  receipt.source_bindings = files;
  receipt.candidate_sha256 = candidate;
  receipt.state = 'PASS';
} catch (error) {
  receipt.error = error.message;
} finally {
  rmSync(workspace, { recursive: true, force: true });
  mkdirSync(dirname(resolve(output)), { recursive: true });
  writeFileSync(output, `${JSON.stringify(receipt, null, 2)}\n`);
}
console.log(JSON.stringify({ state: receipt.state, image_id: receipt.image_id, error: receipt.error }));
process.exitCode = receipt.state === 'PASS' ? 0 : 1;
