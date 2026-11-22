import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';

const [image, output = '.factory/codeql-cross-file-verification.json'] = process.argv.slice(2);
const variant = process.argv[4] ?? 'javascript';
if (!['javascript', 'actions', 'python', 'ruby'].includes(variant)) throw new Error('Unknown CodeQL control variant');
if (!image) throw new Error('Usage: node scripts/verify_codeql_cross_file.mjs IMAGE OUTPUT');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const profilePath = `deploy/deep-adapters/profiles/codeql-${variant}-full.json`;
const profile = JSON.parse(readFileSync(profilePath, 'utf8'));
const fixtureRoot = 'deploy/deep-adapters/rules/tests/codeql-cross-file';
const receipt = { schema: 'factory.codeql-cross-file-controls.v1', state: 'BLOCKED',
  observed_at: new Date().toISOString(), image, source: {}, controls: [], executions: [],
  variant, claim_boundary: 'Native cross-module or workflow-injection positive and safe controls; no universal accuracy or release approval.' };
const temp = mkdtempSync(join(tmpdir(), 'cf-codeql-cross-file-'));
function docker(args, timeout = 30000) {
  const proc = spawnSync('docker', args, { encoding: 'utf8', timeout, maxBuffer: 16 * 1024 * 1024 });
  const path = `${output}.execution-${receipt.executions.length}.json`;
  const evidence = JSON.stringify({ schema: 'factory.codeql-control-execution.v1',
    exit_status: proc.status ?? null, signal: proc.signal ?? null,
    timed_out: proc.error?.code === 'ETIMEDOUT',
    error: proc.error ? { name: proc.error.name, code: proc.error.code ?? null, message: proc.error.message } : null,
    stdout: proc.stdout ?? '', stderr: proc.stderr ?? '' });
  mkdirSync(dirname(resolve(output)), { recursive: true });
  writeFileSync(path, `${evidence}\n`);
  receipt.executions.push({ path: basename(path), sha256: hash(Buffer.from(`${evidence}\n`)) });
  if (proc.error || proc.status !== 0) throw new Error(`Docker execution failed: ${proc.error?.code ?? proc.status}`);
  return proc.stdout;
}
try {
  receipt.source[profilePath] = hash(readFileSync(profilePath));
  const targets = {
    actions: { 'workflow-controls.txt': '.github/workflows/control.yml' },
    python: { 'python-route.fixture': 'route.py', 'python-service.fixture': 'service.py' },
    ruby: { 'ruby-application.fixture': 'app/controllers/application_controller.rb', 'ruby-controller.fixture': 'app/controllers/reports_controller.rb', 'ruby-exporter.fixture': 'lib/exporter.rb' },
    javascript: { 'route.js': 'route.js', 'service.fixture': 'service.js' },
  }[variant];
  const fixtures = Object.keys(targets);
  const vulnerableCall = ['child_process.', 'exec', '(alias)'].join('');
  for (const name of fixtures) receipt.source[`${fixtureRoot}/${name}`] = hash(readFileSync(`${fixtureRoot}/${name}`));
  const id = docker(['image', 'inspect', image, '--format', '{{.Id}}']).trim();
  if (!/^sha256:[a-f0-9]{64}$/.test(id)) throw new Error('Immutable image ID required');
  receipt.image_id = id;
  const isolation = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--user=1000:1000',
    '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=256', '--memory=3g', '--cpus=2',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=1024m,mode=1777', '--tmpfs', '/out:rw,nosuid,nodev,noexec,size=64m,mode=1777'];
  const installed = JSON.parse(docker([...isolation, '--entrypoint', '/bin/cat', id, '/opt/factory/adapter-profile.json']));
  if (JSON.stringify(installed) !== JSON.stringify(profile)) throw new Error('Image profile differs from candidate');
  for (const positive of [true, false]) {
    const workspace = join(temp, positive ? 'vulnerable' : 'safe');
    const source = join(workspace, 'source');
    mkdirSync(source, { recursive: true });
    const files = [];
    for (const name of fixtures) {
      let content = readFileSync(`${fixtureRoot}/${name}`, 'utf8');
      if (variant === 'python' && name === 'python-service.fixture') {
        const unsafe = `connection.execute("SELECT name FROM users WHERE name = '" + name + "'")`;
        if (content.split(unsafe).length !== 2) throw new Error('Expected exactly one Python SQL control replacement');
        if (!positive) content = content.replace(unsafe, 'connection.execute("SELECT name FROM users WHERE name = ?", (name,))');
      }
      if (!positive && name === 'service.fixture') {
        const safeCall = ["child_process.", "execFile('/usr/bin/printf', ['%s', alias])"].join('');
        content = content.replace(vulnerableCall, safeCall);
      }
      if (!positive && variant === 'actions') {
        content = content.replace('        run: echo "${{ github.event.pull_request.title }}"',
          '        env:\n          PR_TITLE: ${{ github.event.pull_request.title }}\n        run: printf "%s\\n" "$PR_TITLE"');
      }
      if (name === 'ruby-exporter.fixture') {
        const unsafe = 'system("report-tool --format #{format}")';
        if (content.split(unsafe).length !== 2) throw new Error('Expected exactly one Ruby command control replacement');
        if (!positive) content = content.replace(unsafe, 'system("report-tool", "--format", format)');
      }
      const target = targets[name];
      mkdirSync(dirname(join(source, target)), { recursive: true });
      writeFileSync(join(source, target), content);
      files.push({ path: target, sha256: hash(Buffer.from(content)), language: variant === 'actions' ? 'configuration' : variant });
    }
    const candidate = hash(Buffer.from(JSON.stringify(files)));
    const lane = { id: 'codeql-cross-file-control', family: 'static', languages: variant === 'actions' ? ['configuration'] : variant === 'javascript' ? ['javascript', 'typescript'] : [variant],
      timeout_seconds: 900, memory_mib: 3072, report: 'native.json', coverage: 'coverage.json', challenge_report: 'challenges.json' };
    for (const key of ['engine', 'mode', 'tool_version', 'ruleset_sha256']) lane[key] = profile[key];
    const contract = { schema: 'factory.deep-adapter-input.v1', run_id: 'codeql-cross-file-control', manifest_sha256: 'b'.repeat(64),
      inventory: { candidate_sha256: candidate, files }, lane, obligations: [] };
    const contractPath = join(workspace, 'contract.json');
    writeFileSync(contractPath, JSON.stringify(contract));
    const started = Date.now();
    const raw = docker([...isolation, '--mount', `type=bind,source=${source},target=/src,readonly`,
      '--mount', `type=bind,source=${contractPath},target=/factory-contract.json,readonly`,
      id, profile.engine, '--mode', profile.mode], 960000);
    writeFileSync(`${output}.${positive ? 'vulnerable' : 'safe'}.bundle.json`, raw);
    const bundle = JSON.parse(raw);
    const artifact = bundle.artifacts?.['native.json'];
    if (bundle.candidate_sha256 !== candidate || !artifact?.runs?.length) throw new Error('Candidate binding or native report missing');
    const findings = artifact.runs.flatMap(run => run.results ?? []);
    const commands = findings.filter(result => variant === 'actions'
      ? result.ruleId?.startsWith('actions/code-injection/') : result.ruleId === {
        python: 'py/sql-injection', ruby: 'rb/command-line-injection', javascript: 'js/command-line-injection',
      }[variant]);
    const flows = commands.flatMap(result => (result.codeFlows ?? []).flatMap(flow => flow.threadFlows ?? []));
    const orderedFlows = flows.map(flow => (flow.locations ?? []).map(step => step.location?.physicalLocation?.artifactLocation?.uri));
    const paths = new Set(orderedFlows.flat());
    const crossFileFlow = orderedFlows.some(flow => {
      const [from, to] = variant === 'ruby' ? ['app/controllers/reports_controller.rb', 'lib/exporter.rb']
        : variant === 'python' ? ['route.py', 'service.py'] : ['route.js', 'service.js'];
      const sourceIndex = flow.indexOf(from);
      return sourceIndex >= 0 && flow.slice(sourceIndex + 1).includes(to);
    });
    const record = { positive, state: 'BLOCKED', candidate_sha256: candidate, source_bindings: files,
      findings: findings.length, target_rule_findings: commands.length,
      ...(variant === 'python' ? {} : { command_injection_findings: commands.length }),
      flow_paths: [...paths].filter(Boolean).sort(),
      ordered_flow_paths: orderedFlows, cross_file_flow_observed: crossFileFlow,
      artifact_sha256: hash(Buffer.from(JSON.stringify(artifact))), elapsed_ms: Date.now() - started };
    receipt.controls.push(record);
    const workflowLocation = commands.some(result => (result.locations ?? []).some(location => {
      const physical = location.physicalLocation;
      return physical?.artifactLocation?.uri === '.github/workflows/control.yml'
        && physical.region?.startLine === 10;
    }));
    record.workflow_injection_location_observed = workflowLocation;
    record.flow_evidence = orderedFlows.length ? 'OBSERVED' : 'NOT_EMITTED';
    const evidenceObserved = variant === 'actions' ? workflowLocation : crossFileFlow;
    if (positive && (!commands.length || !evidenceObserved)) throw new Error('Required native finding location or ordered cross-file trace missing');
    if (!positive && findings.length) throw new Error('Safe control produced findings');
    record.state = 'PASS';
    console.log(JSON.stringify({ positive, state: record.state, findings: record.findings, flow_paths: record.flow_paths }));
  }
  receipt.state = 'PASS';
} catch (error) {
  receipt.error = error.message;
} finally {
  rmSync(temp, { recursive: true, force: true });
  mkdirSync(dirname(resolve(output)), { recursive: true });
  writeFileSync(output, `${JSON.stringify(receipt, null, 2)}\n`);
}
console.log(JSON.stringify({ state: receipt.state, image_id: receipt.image_id, error: receipt.error }));
process.exitCode = receipt.state === 'PASS' ? 0 : 1;
