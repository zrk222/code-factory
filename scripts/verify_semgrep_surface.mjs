import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, copyFileSync, readFileSync, writeFileSync, mkdirSync, chmodSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join, dirname } from 'node:path';

const [image, output = '.factory/semgrep-surface-verification.json'] = process.argv.slice(2);
if (!image) throw new Error('Usage: node scripts/verify_semgrep_surface.mjs IMAGE OUTPUT');
const root = process.cwd();
const profile = JSON.parse(readFileSync('deploy/deep-adapters/profiles/semgrep-pattern-limited.json', 'utf8'));
const rulesPath = 'deploy/deep-adapters/rules/semgrep-pattern-limited.yml';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const receipt = { schema: 'factory.semgrep-surface-controls.v1', state: 'BLOCKED',
  observed_at: new Date().toISOString(), image, source: {},
  claim_boundary: 'Native controls for ten declared rules in Python, JavaScript and TypeScript; no general detection-accuracy or interprocedural-coverage claim.' };
const temp = mkdtempSync(join(tmpdir(), 'cf-semgrep-surface-'));
function docker(args) {
  const run = spawnSync('docker', args, { encoding: 'utf8', timeout: 120000, maxBuffer: 16 * 1024 * 1024 });
  if (run.error || run.status !== 0) throw new Error(`Docker control failed: ${run.error?.message ?? run.stderr}`);
  return run.stdout;
}
try {
  for (const path of [rulesPath, 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json',
    'deploy/deep-adapters/rules/tests/python-controls.txt', 'deploy/deep-adapters/rules/tests/javascript-controls.js']) {
    receipt.source[path] = hash(readFileSync(path));
  }
  if (receipt.source[rulesPath] !== profile.ruleset_sha256) throw new Error('Ruleset hash differs from profile');
  const id = docker(['image', 'inspect', image, '--format', '{{.Id}}']).trim();
  if (!/^sha256:[a-f0-9]{64}$/.test(id)) throw new Error('Invalid immutable image ID');
  receipt.image_id = id;
  const base = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
    '--security-opt=no-new-privileges=true', '--pids-limit=128', '--memory=2g', '--cpus=2',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777', '-e', 'HOME=/tmp', '-e', 'SEMGREP_SETTINGS_FILE=/tmp/settings.yml'];
  const bundled = JSON.parse(docker([...base, '--entrypoint', '/bin/cat', id, '/opt/factory/adapter-profile.json']));
  if (JSON.stringify(bundled) !== JSON.stringify(profile)) throw new Error('Image profile differs from candidate');
  const bundledRules = docker([...base, '--entrypoint', '/bin/cat', id, '/opt/factory/rules/semgrep-pattern-limited.yml']);
  if (hash(Buffer.from(bundledRules)) !== profile.ruleset_sha256) throw new Error('Image rules differ from candidate');
  copyFileSync(rulesPath, join(temp, 'semgrep-pattern-limited.yml'));
  copyFileSync('deploy/deep-adapters/rules/tests/python-controls.txt', join(temp, 'semgrep-pattern-limited.py'));
  for (const extension of ['js', 'ts']) copyFileSync('deploy/deep-adapters/rules/tests/javascript-controls.js', join(temp, `semgrep-pattern-limited.${extension}`));
  // mkdtempSync defaults to 0700. The hardened image runs Semgrep as a
  // non-root user, so make only these synthetic, read-only test inputs
  // traversable before mounting the directory with Docker's readonly option.
  chmodSync(temp, 0o755);
  for (const name of readdirSync(temp)) chmodSync(join(temp, name), 0o644);
  const controls = docker([...base, '--mount', `type=bind,source=${temp},target=/cases,readonly`,
    '--entrypoint', '/usr/bin/semgrep', id, '--test', '--json', '--metrics=off', '--disable-version-check', '--disable-nosem', '/cases']);
  receipt.controls = JSON.parse(controls);
  const tested = Object.values(receipt.controls.results ?? {}).flatMap(result => Object.entries(result.checks ?? {}));
  if (tested.length !== 10 || tested.some(([, check]) => check.passed !== true || check.errors?.length)) {
    throw new Error('Incomplete or failing rule controls');
  }
  if (receipt.controls.config_missing_tests?.length || receipt.controls.config_with_errors?.length) {
    throw new Error('Missing or invalid rule controls');
  }
  receipt.controls_sha256 = hash(Buffer.from(controls));
  // Exercise suppression only after annotation testing: Semgrep's test runner
  // interprets nosemgrep comments differently from production scan output.
  const annotated = [];
  for (const extension of ['py', 'js', 'ts']) {
    const fixture = join(temp, `semgrep-pattern-limited.${extension}`);
    const content = readFileSync(fixture, 'utf8');
    const vulnerableCall = ['child_process.', 'exec', '(alias);'].join('');
    const suppressed = extension === 'py'
      ? content.replace('os.system(alias)', 'os.system(alias)  # nosemgrep: python.request-command-injection')
      : content.replace(vulnerableCall, vulnerableCall + ' // nosemgrep: javascript.request-command-injection');
    if (suppressed === content) throw new Error('Missing suppression control');
    const lines = suppressed.split(/\r?\n/);
    const line = lines.findIndex(value => value.includes('nosemgrep:')) + 1;
    annotated.push(`opt.factory.rules.${extension === 'py' ? 'python' : 'javascript'}.request-command-injection|semgrep-pattern-limited.${extension}|${line}`);
    writeFileSync(fixture, suppressed);
  }
  const argv = profile.commands[0].argv.slice(1);
  const reportIndex = argv.indexOf('--sarif-output');
  if (reportIndex < 0 || argv[reportIndex + 1] !== '{report}') throw new Error('Unexpected SARIF profile');
  argv.splice(reportIndex, 2, '--sarif');
  const native = docker([...base, '--mount', `type=bind,source=${temp},target=/cases,readonly`,
    '--entrypoint', profile.commands[0].argv[0], id, ...argv.map(value => value === '{source}' ? '/cases' : value)]);
  const sarif = JSON.parse(native);
  mkdirSync(dirname(resolve(root, output)), { recursive: true });
  writeFileSync(`${output}.sarif`, native);
  const findings = (sarif.runs ?? []).flatMap(run => run.results ?? []);
  if (findings.length !== 21) throw new Error(`Native profile expected 21 control findings, observed ${findings.length}`);
  const active = results => results.filter(result => !(result.suppressions ?? []).some(suppression => suppression.status !== 'rejected'));
  const keys = results => results.map(result => {
    const locations = result.locations ?? [];
    if (locations.length !== 1) throw new Error('Control finding requires exactly one primary location');
    const location = locations[0].physicalLocation;
    const uri = location?.artifactLocation?.uri ?? '';
    return `${result.ruleId}|${uri.split('/').at(-1)}|${location?.region?.startLine}`;
  }).sort();
  // Semgrep retains inSource metadata even with --disable-nosem. The worker
  // consumes all results from this profile; only the enabled scan excludes it.
  const disabledKeys = keys(findings);
  if (new Set(disabledKeys).size !== 21 || annotated.some(key => !disabledKeys.includes(key))) {
    throw new Error('Disabled suppression omitted or duplicated an exact control finding');
  }
  if (!argv.includes('--disable-nosem')) throw new Error('Production profile must disable inline suppression');
  const enabled = docker([...base, '--mount', `type=bind,source=${temp},target=/cases,readonly`,
    '--entrypoint', profile.commands[0].argv[0], id,
    ...argv.filter(value => value !== '--disable-nosem').map(value => value === '{source}' ? '/cases' : value)]);
  writeFileSync(`${output}.suppression-enabled.sarif`, enabled);
  const enabledFindings = (JSON.parse(enabled).runs ?? []).flatMap(run => run.results ?? []);
  const enabledKeys = keys(active(enabledFindings));
  const expectedKeys = disabledKeys.filter(key => !annotated.includes(key));
  if (JSON.stringify(enabledKeys) !== JSON.stringify(expectedKeys)) {
    throw new Error('Enabled suppression did not remove exactly the three annotated findings');
  }
  receipt.native_findings = findings.length;
  receipt.inline_suppression_control = 'PASS';
  receipt.suppression_control = { annotated_findings: annotated.sort(), disabled_report_findings: disabledKeys.length,
    enabled_unsuppressed_findings: enabledKeys.length, enabled_sarif_sha256: hash(Buffer.from(enabled)) };
  receipt.native_rule_ids = [...new Set(findings.map(result => result.ruleId))].sort();
  receipt.native_sarif_sha256 = hash(Buffer.from(native));
  receipt.native_dataflow_findings = findings.filter(result => result.codeFlows?.length).length;
  receipt.dataflow_trace_state = receipt.native_dataflow_findings > 0 ? 'OBSERVED' : 'NOT_MEASURED';
  if (receipt.native_rule_ids.length !== 10) throw new Error('Native profile omitted rules');
  receipt.state = 'PASS';
} catch (error) {
  receipt.error = error.message;
} finally {
  // Only the exact temporary directory created by this process is removed.
  rmSync(temp, { recursive: true, force: true });
  mkdirSync(dirname(resolve(root, output)), { recursive: true });
  writeFileSync(output, `${JSON.stringify(receipt, null, 2)}\n`);
}
console.log(JSON.stringify({ state: receipt.state, image_id: receipt.image_id, error: receipt.error }));
process.exitCode = receipt.state === 'PASS' ? 0 : 1;
