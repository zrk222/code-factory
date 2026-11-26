import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { selectWorkerTargets, sdkTargets } from './select_worker_targets.mjs';

const base = 'a'.repeat(40);
const head = 'b'.repeat(40);
const event = fields => fields;
const paths = (...items) => Buffer.from(`${items.join('\0')}\0`);
const prEvent = (baseSha = base, headSha = head) => ({ pull_request: { base: { sha: baseSha }, head: { sha: headSha } } });
const pushEvent = (before = base, after = head) => ({ before, after });
function gitFor({ checkout = head, diffPaths = paths('README.md'), ancestors = new Set([base, head]), dirty = false } = {}) {
  return (_file, args) => {
    if (args[0] === 'rev-parse') return Buffer.from(`${checkout}\n`);
    if (args[0] === 'diff-index') {
      if (dirty) throw new Error('tracked checkout is dirty');
      return Buffer.alloc(0);
    }
    if (args[0] === 'merge-base') {
      if (!ancestors.has(args[2])) throw new Error('not an ancestor');
      return Buffer.alloc(0);
    }
    if (args[0] === 'diff') {
      assert.deepEqual(args.slice(-3), [base, checkout, '--']);
      return diffPaths;
    }
    throw new Error(`unexpected git command: ${args.join(' ')}`);
  };
}

test('Semgrep rule, profile, control and verifier changes skip SDK matrix', () => {
  const input = prEvent();
  const result = selectWorkerTargets('pull_request', input, gitFor({ diffPaths: paths(
    'deploy/deep-adapters/rules/semgrep-pattern-limited.yml',
    'deploy/deep-adapters/profiles/semgrep-pattern-limited.json',
    'deploy/deep-adapters/rules/tests/python-controls.txt',
    'deploy/deep-adapters/rules/tests/javascript-controls.js',
    'scripts/verify_semgrep_surface.mjs',
  ) }));
  assert.equal(result.sdk, 'false');
  assert.equal(result.reason, 'semgrep-only');
  assert.deepEqual(JSON.parse(result.matrix), sdkTargets);
});

test('mixed and common or unknown paths retain every SDK target', () => {
  const input = pushEvent();
  for (const changed of [
    ['deploy/deep-adapters/rules/semgrep-pattern-limited.yml', 'factoryline/runtime_audit_common.py'],
    ['README.md'],
    ['deploy/deep-adapters/Dockerfile'],
    ['deploy/deep-adapters/rules/tests/codeql-cross-file/python-route.fixture'],
  ]) {
    assert.equal(selectWorkerTargets('push', input, gitFor({ diffPaths: paths(...changed) })).sdk, 'true');
  }
});

test('malicious or malformed revisions never reach git', () => {
  let calls = 0;
  const git = () => { calls++; return paths('deploy/deep-adapters/rules/semgrep-pattern-limited.yml'); };
  const result = selectWorkerTargets('push', pushEvent(`${base}; touch BAD`, head), git);
  assert.equal(result.sdk, 'true');
  assert.equal(result.reason, 'unresolvable-revisions');
  assert.equal(calls, 0);
});

test('empty and malformed diff output retain full matrix', () => {
  const input = pushEvent();
  assert.equal(selectWorkerTargets('push', input, gitFor({ diffPaths: Buffer.alloc(0) })).sdk, 'true');
  assert.equal(selectWorkerTargets('push', input, gitFor({ diffPaths: Buffer.from('deploy/deep-adapters/rules/semgrep-pattern-limited.yml') })).sdk, 'true');
});

test('manual and unknown events retain full matrix', () => {
  assert.equal(selectWorkerTargets('workflow_dispatch', {}).sdk, 'true');
  assert.equal(selectWorkerTargets('schedule', {}).sdk, 'true');
});

test('Git failure retains full matrix', () => {
  const input = pushEvent();
  const result = selectWorkerTargets('push', input, () => { throw new Error('git unavailable'); });
  assert.equal(result.sdk, 'true');
  assert.equal(result.reason, 'git-diff-failed');
});

test('PR paths are selected from the checked-out merge candidate', () => {
  const input = prEvent();
  assert.equal(selectWorkerTargets('pull_request', input, gitFor({ diffPaths: paths('README.md') })).sdk, 'true');
  assert.equal(selectWorkerTargets('pull_request', input, gitFor({ diffPaths: paths('deploy/deep-adapters/rules/semgrep-pattern-limited.yml') })).sdk, 'false');
});

test('push checkout mismatch and PR non-ancestor fail closed', () => {
  assert.equal(selectWorkerTargets('push', pushEvent(), gitFor({ checkout: 'c'.repeat(40) })).sdk, 'true');
  assert.equal(selectWorkerTargets('pull_request', prEvent(), gitFor({ ancestors: new Set([base]) })).sdk, 'true');
});

test('dirty tracked checkout fails closed', () => {
  assert.equal(selectWorkerTargets('push', pushEvent(), gitFor({ dirty: true })).sdk, 'true');
});

test('malformed git revision and ancestry outputs fail closed', () => {
  const malformedRevision = (_file, args) => args[0] === 'rev-parse' ? Buffer.from(`${head}\nextra\n`) : Buffer.alloc(0);
  const malformedAncestry = (_file, args) => args[0] === 'rev-parse' ? Buffer.from(`${head}\n`) : Buffer.from('unexpected');
  assert.equal(selectWorkerTargets('push', pushEvent(), malformedRevision).sdk, 'true');
  assert.equal(selectWorkerTargets('pull_request', prEvent(), malformedAncestry).sdk, 'true');
});

test('CLI reads GitHub event name separately and writes GitHub outputs', () => {
  const directory = mkdtempSync(join(tmpdir(), 'worker-target-selector-'));
  const output = join(directory, 'github-output.txt');
  const script = fileURLToPath(new URL('./select_worker_targets.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script], {
    encoding: 'utf8',
    env: { ...process.env, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_EVENT_JSON: JSON.stringify({ inputs: {} }), GITHUB_OUTPUT: output },
  });
  try {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
    const lines = readFileSync(output, 'utf8').trim().split('\n');
    assert.equal(lines[0], 'sdk=true');
    assert.equal(lines[1], `matrix=${JSON.stringify(sdkTargets)}`);
    assert.equal(lines[2], 'reason=manual-or-unknown-event');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function trustedWorkflowProgram() {
  const workflow = readFileSync(new URL('../.github/workflows/worker-verification.yml', import.meta.url), 'utf8');
  const program = workflow.match(/node --input-type=module <<'NODE'\r?\n([\s\S]*?)          NODE/)[1];
  assert.ok(!workflow.slice(workflow.indexOf('  plan-worker-targets:'), workflow.indexOf('  selector-controls:')).includes('node --test'));
  const sdkJob = workflow.split('  sdk-workers:')[1].split(/\r?\n  [\w-]+:/)[0];
  assert.match(sdkJob, /^    needs: \[plan-worker-targets, selector-controls\]\r?$/m);
  assert.match(sdkJob, /^    if: needs\.plan-worker-targets\.outputs\.sdk == 'true'\r?$/m);
  assert.doesNotMatch(sdkJob, /node --test/);
  const controls = workflow.split('  selector-controls:')[1].split(/\r?\n  [\w-]+:/)[0];
  const suites = controls.match(/node --test(?:\s+scripts\/[\w.-]+\.test\.mjs)+/g);
  assert.equal(suites?.length, 1);
  const paths = suites[0].split(/\s+/).slice(2);
  for (const name of ['select_worker_targets', 'verify_worker_cves', 'verify_osv_worker', 'semgrep_mutation_controls',
    'recall_harness', 'recall_codeql_pairs']) assert.ok(paths.includes(`scripts/${name}.test.mjs`));
  return program.replace(/^          /gm, '');
}

for (const target of ['osv-worker', 'semgrep-worker', 'codeql-python-worker', 'unknown-target', { target: 'codeql-python-worker' }]) {
test(`manual ${target} selection cannot narrow a PR or push matrix`, () => {
  for (const name of ['workflow_dispatch', 'pull_request', 'push']) {
    const directory = mkdtempSync(join(tmpdir(), 'factory-manual-osv-'));
    const output = join(directory, 'output.txt');
    try {
      const result = spawnSync(process.execPath, ['--input-type=module', '-e', trustedWorkflowProgram()], {
        cwd: directory, encoding: 'utf8', env: { ...process.env, RUNNER_TEMP: directory, GITHUB_OUTPUT: output,
          GITHUB_EVENT_NAME: name, GITHUB_EVENT_JSON: JSON.stringify({ inputs: { target } }) },
      });
      assert.equal(result.status, 0, result.stderr);
      const expected = name === 'workflow_dispatch' && ['osv-worker', 'codeql-python-worker'].includes(target) ? [target] : sdkTargets;
      assert.ok(readFileSync(output, 'utf8').includes(`matrix=${JSON.stringify(expected)}\n`));
      const sdk = name === 'workflow_dispatch' && target === 'semgrep-worker' ? 'false' : 'true';
      assert.ok(readFileSync(output, 'utf8').includes(`sdk=${sdk}\n`));
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});
}

for (const variant of ['python', 'ruby']) {
for (const scenario of ['pass', 'missing-finding', 'reverse-flow', 'wrong-rule', 'safe-finding', 'wrong-candidate', 'profile-mismatch', 'missing-mutation', 'duplicate-mutation', 'malformed-json', 'nonzero-exit', 'timeout', 'missing-report']) {
  test(`${variant} cross-file verifier wiring with MOCKED Docker: ${scenario}`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'factory-python-codeql-wiring-'));
    const output = join(directory, 'receipt.json');
    const program = fileURLToPath(new URL('./verify_codeql_cross_file.mjs', import.meta.url));
    // Exercise the actual CLI program without an environment-enabled production
    // bypass. These synthetic bundles are unit controls, NOT native CodeQL proof.
    const bootstrap = `
      import assert from 'node:assert/strict';
      import cp from 'node:child_process';
      import fs from 'node:fs';
      import {syncBuiltinESMExports} from 'node:module';
      import {pathToFileURL} from 'node:url';
      const [program, output, scenario, variant] = process.argv.slice(1);
      const ruby = variant === 'ruby';
      const fixture = ruby ? 'ruby-exporter.fixture' : 'python-service.fixture';
      const filenames = ruby ? ['app/controllers/application_controller.rb','app/controllers/reports_controller.rb','lib/exporter.rb'] : ['route.py','service.py'];
      const rule = ruby ? 'rb/command-line-injection' : 'py/sql-injection';
      const read = fs.readFileSync;
      fs.readFileSync = (path, ...options) => {
        const value = read(path, ...options);
        if (!String(path).endsWith(fixture)) return value;
        let text = value.toString();
        if (scenario === 'missing-mutation') text = text.replace(ruby ? 'system(' : 'connection.execute', 'missing(');
        if (scenario === 'duplicate-mutation') text += text;
        return Buffer.isBuffer(value) ? Buffer.from(text) : text;
      };
      cp.spawnSync = (file, args) => {
        assert.equal(file, 'docker');
        const result = value => ({status:0,stdout:JSON.stringify(value),stderr:''});
        if (args[0] === 'image') return {status:0,stdout:'sha256:'+'a'.repeat(64),stderr:''};
        assert.ok(args.includes('--pull=never') && args.includes('--network=none') && args.includes('--read-only'));
        if (args.includes('/bin/cat')) {
          const profile = JSON.parse(read('deploy/deep-adapters/profiles/codeql-'+variant+'-full.json'));
          if (scenario === 'profile-mismatch') profile.mode = 'wrong';
          return result(profile);
        }
        const mount = target => args.find(x => x.startsWith('type=bind,source=') && x.endsWith(',target='+target+',readonly'))
          .slice('type=bind,source='.length).split(',target=')[0];
        const contract = JSON.parse(read(mount('/factory-contract.json')));
        assert.deepEqual(contract.lane.languages, [variant]);
        assert.deepEqual(contract.inventory.files.map(x=>x.path), filenames);
        const source = read(mount('/src')+'/'+filenames.at(-1),'utf8');
        const positive = source.includes(ruby ? '#{format}' : '+ name +');
        if (!positive) assert.ok(source.includes(ruby ? 'system("report-tool", "--format", format)' : 'WHERE name = ?", (name,)'));
        if (scenario === 'nonzero-exit') return {status:2,stdout:'partial native output',stderr:'native failure diagnostics'};
        if (scenario === 'timeout') return {status:null,signal:'SIGTERM',stdout:'partial timeout output',stderr:'timeout diagnostics',error:Object.assign(new Error('native timeout'),{code:'ETIMEDOUT'})};
        if (scenario === 'malformed-json') return {status:0,stdout:'NOT_JSON preserved native output',stderr:''};
        const report = (positive || scenario === 'safe-finding') && scenario !== 'missing-finding';
        const paths = ruby ? filenames.slice(1) : filenames.slice();
        if (scenario === 'reverse-flow') paths.reverse();
        const results = report ? [{ruleId:scenario === 'wrong-rule' ? 'unrelated' : rule,
          codeFlows:[{threadFlows:[{locations:paths.map(uri=>({location:{physicalLocation:{artifactLocation:{uri}}}}))}]}]}] : [];
        return result({candidate_sha256:scenario === 'wrong-candidate' ? '0'.repeat(64) : contract.inventory.candidate_sha256,
          artifacts:scenario === 'missing-report' ? {} : {'native.json':{runs:[{results}]}}});
      };
      syncBuiltinESMExports();
      process.argv = [process.execPath, program, 'factory-codeql:test', output, variant];
      await import(pathToFileURL(program).href);
    `;
    try {
      const result = spawnSync(process.execPath, ['--input-type=module', '-e', bootstrap, program, output, scenario, variant], {encoding:'utf8'});
      assert.equal(result.status, scenario === 'pass' ? 0 : 1, result.stderr);
      const receipt = JSON.parse(readFileSync(output, 'utf8'));
      assert.equal(receipt.state, scenario === 'pass' ? 'PASS' : 'BLOCKED');
      if (scenario === 'pass') {
        assert.equal(receipt.variant, variant);
        assert.equal(receipt.controls.length, 2);
        assert.equal(receipt.controls[0].target_rule_findings, 1);
        assert.equal(receipt.controls[0].cross_file_flow_observed, true);
        assert.equal(receipt.controls[1].findings, 0);
        if (variant === 'python') assert.ok(!('command_injection_findings' in receipt.controls[0]));
        else assert.equal(receipt.controls[0].command_injection_findings, 1);
      } else assert.ok(receipt.error);
      const executions = receipt.executions.map(row => JSON.parse(readFileSync(join(directory,row.path),'utf8')));
      assert.ok(executions.length >= 2);
      if (scenario === 'nonzero-exit') {
        assert.equal(executions.at(-1).exit_status, 2);
        assert.equal(executions.at(-1).stdout, 'partial native output');
        assert.equal(executions.at(-1).stderr, 'native failure diagnostics');
      }
      if (scenario === 'timeout') {
        assert.equal(executions.at(-1).exit_status, null);
        assert.equal(executions.at(-1).signal, 'SIGTERM');
        assert.equal(executions.at(-1).timed_out, true);
        assert.equal(executions.at(-1).error.code, 'ETIMEDOUT');
        assert.equal(executions.at(-1).stdout, 'partial timeout output');
      }
      if (scenario === 'malformed-json') assert.equal(readFileSync(`${output}.vulnerable.bundle.json`,'utf8'), 'NOT_JSON preserved native output');
      if (scenario === 'wrong-candidate' || scenario === 'missing-report') assert.ok(readFileSync(`${output}.vulnerable.bundle.json`,'utf8').includes('candidate_sha256'));
    } finally { rmSync(directory, {recursive:true,force:true}); }
  });
}
}

for (const scenario of ['candidate sabotage', 'missing baseline', 'manual']) {
  test(`trusted workflow selector: ${scenario} runs all SDK workers`, () => {
    const root = mkdtempSync(join(tmpdir(), 'factory-trusted-selector-'));
    const git = (...args) => {
      const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      return result.stdout.trim();
    };
    try {
      git('init'); git('config', 'user.name', 'Control'); git('config', 'user.email', 'control@example.invalid');
      mkdirSync(join(root, 'scripts'));
      writeFileSync(join(root, 'README.md'), 'baseline');
      if (scenario === 'candidate sabotage') writeFileSync(join(root, 'scripts/select_worker_targets.mjs'), readFileSync(new URL('./select_worker_targets.mjs', import.meta.url)));
      git('add', '.'); git('commit', '-m', 'baseline');
      const baseline = git('rev-parse', 'HEAD');
      writeFileSync(join(root, 'scripts/select_worker_targets.mjs'), 'console.log(JSON.stringify({sdk:"false",matrix:"[]",reason:"forged"}));');
      git('add', '.'); git('commit', '-m', 'candidate');
      const candidate = git('rev-parse', 'HEAD');
      const output = join(root, 'output.txt');
      const result = spawnSync(process.execPath, ['--input-type=module', '-e', trustedWorkflowProgram()], {
        cwd: root, encoding: 'utf8', env: { ...process.env, RUNNER_TEMP: root, GITHUB_OUTPUT: output,
          GITHUB_EVENT_NAME: scenario === 'manual' ? 'workflow_dispatch' : 'push', GITHUB_EVENT_JSON: JSON.stringify({before: baseline, after: candidate}) },
      });
      assert.equal(result.status, 0, result.stderr);
      const lines = readFileSync(output, 'utf8');
      assert.ok(lines.includes('sdk=true\n'));
      assert.ok(lines.includes(`matrix=${JSON.stringify(sdkTargets)}\n`));
      assert.ok(!lines.includes('forged'));
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}
