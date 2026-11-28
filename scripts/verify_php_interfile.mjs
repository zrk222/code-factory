import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { docker } from './verify_worker_cves.mjs';

const [image, output] = process.argv.slice(2);
if (!image || !output) throw new Error('Usage: verify_php_interfile.mjs IMAGE RECEIPT');
const hash = value => createHash('sha256').update(value).digest('hex');
const root = mkdtempSync(join(tmpdir(), 'cf-php-interfile-'));
const profileBytes = readFileSync('deploy/deep-adapters/profiles/semgrep-php-interfile.json');
const profile = JSON.parse(profileBytes);
const receipt = {
  schema: 'factory.php-interfile-verification.v1', state: 'BLOCKED',
  candidate_commit: process.env.GITHUB_SHA ?? null, profile_sha256: hash(profileBytes),
  scope: 'Unsigned PHP worker fixture with pinned rule accounting and separate benign cross-file flow controls and paired parser evidence.',
};
try {
  const id = docker(['image', 'inspect', image, '--format', '{{.Id}}']).stdout.trim();
  assert.match(id, /^sha256:[a-f0-9]{64}$/);
  receipt.image_id = id;
  const isolation = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--user=1000:1000',
    '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=64', '--memory=768m',
    '--cpus=1', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,mode=1777',
    '--tmpfs', '/out:rw,nosuid,nodev,noexec,size=32m,mode=1777'];
  const fromImage = path => docker([...isolation, '--entrypoint', '/bin/cat', id, path]).stdout;
  assert.equal(hash(fromImage('/opt/factory/adapter-profile.json')), receipt.profile_sha256);
  const rules = fromImage('/opt/factory/rules/semgrep-pattern-limited.yml');
  assert.equal(hash(rules), profile.ruleset_sha256);
  const ruleIds = JSON.parse(rules).rules.map(rule => rule.id).sort();
  assert.equal(ruleIds.length, 5);
  const source = join(root, 'source'), safe = join(root, 'safe'), mixed = join(root, 'mixed');
  const fixture = {
    'helper.php': '<?php\nfunction store_fixture_output($value) { return record_test_marker($value); }\n',
    'main.php': "<?php\nrequire_once __DIR__ . '/helper.php';\nstore_fixture_output(marker_from_fixture());\n",
  };
  const safeFixture = { ...fixture, 'main.php': fixture['main.php'].replace('marker_from_fixture()', "'fixed'") };
  for (const dir of [source, safe, mixed]) {
    mkdirSync(dir);
    for (const [name, text] of Object.entries(dir === safe ? safeFixture : fixture)) {
      writeFileSync(join(dir, name), text);
    }
  }
  const template = '<p>{{ $message }}</p>\n';
  writeFileSync(join(mixed, 'view.blade.php'), template);
  const inventory = sources => Object.entries(sources).map(([path, text]) => ({
    path, language: 'php', sha256: hash(text),
  }));
  const files = inventory(fixture), safeFiles = inventory(safeFixture);
  const lane = { id: 'php-control', family: 'static', languages: ['php'], timeout_seconds: 90,
    memory_mib: 768, native_artifact_roles: ['rule_inventory', 'sarif_report'], rule_ids: ruleIds,
    report: 'native.json', coverage: 'coverage.json', challenge_report: 'challenges.json' };
  for (const key of ['engine', 'mode', 'tool_version', 'ruleset_sha256']) lane[key] = profile[key];
  const contract = join(root, 'contract.json');
  const mount = (from, to) => ['--mount', `type=bind,source=${from},target=${to},readonly`];
  const runAdapter = (dir, inventory) => {
    writeFileSync(contract, JSON.stringify({ schema: 'factory.deep-adapter-input.v1', run_id: 'php-control',
      manifest_sha256: hash(JSON.stringify(lane)),
      inventory: { candidate_sha256: hash(JSON.stringify(inventory)), files: inventory }, lane, obligations: [] }));
    return docker([...isolation, ...mount(dir, '/src'), ...mount(contract, '/factory-contract.json'),
      id, 'semgrep', '--mode', profile.mode], [0, 1, 2], 100000);
  };
  const adapter = runAdapter(source, files);
  writeFileSync(`${output}.adapter.json`, adapter.stdout);
  writeFileSync(`${output}.adapter.stderr`, adapter.stderr);
  assert.equal(adapter.status, 0, 'Native adapter command failed');
  const bundle = JSON.parse(adapter.stdout);
  assert.equal(bundle.candidate_sha256, hash(JSON.stringify(files)));
  const coverage = bundle.artifacts['coverage.json'];
  assert.equal(coverage.complete, false, 'Unsigned fixture lacks admission challenges');
  const observations = coverage.semgrep_rule_execution.observations;
  assert.deepEqual(observations.map(row => row.rule_id), ruleIds);
  for (const observation of observations) {
    assert.deepEqual(observation.native_report.paths.scanned.map(path => path.replace(/^\/src\//, '')).sort(),
      ['helper.php', 'main.php'], 'Each pinned rule must scan both PHP sources');
  }
  receipt.adapter_sha256 = hash(adapter.stdout);
  receipt.source_bindings = files;
  const unsupported = runAdapter(mixed, [...files, { path: 'view.blade.php', language: 'php', sha256: hash(template) }]);
  assert.equal(unsupported.status, 0, 'A Blade template should preserve ordinary PHP evidence');
  writeFileSync(`${output}.mixed.adapter.json`, unsupported.stdout);
  const mixedCoverage = JSON.parse(unsupported.stdout).artifacts['coverage.json'];
  const accounting = mixedCoverage.source_accounting;
  assert.equal(mixedCoverage.complete, false);
  assert.ok(mixedCoverage.errors.includes('NATIVE_SOURCE_ACCOUNTING_REQUIRED'));
  assert.equal(accounting.state, 'INCOMPLETE');
  assert.deepEqual(accounting.measured_paths, ['helper.php', 'main.php']);
  assert.deepEqual(accounting.missing_paths, ['view.blade.php']);
  receipt.blade_scope = { state: accounting.state, missing_paths: accounting.missing_paths,
    retained_php_paths: accounting.measured_paths, sha256: hash(unsupported.stdout) };

  const marker = join(root, 'marker.json');
  writeFileSync(marker, JSON.stringify({ rules: [{ id: 'benign-cross-file-marker', languages: ['php'],
    mode: 'taint', message: 'Marker passed into fixture recorder', severity: 'INFO',
    options: { taint_interfile: true }, 'pattern-sources': [{ pattern: 'marker_from_fixture()' }],
    'pattern-sinks': [{ pattern: 'record_test_marker(...)' }],
  }] }));
  const fixed = profile.commands[0].argv.slice(2, profile.commands[0].argv.indexOf('--config'));
  receipt.marker_rule_sha256 = hash(readFileSync(marker));
  receipt.parser = { tool_version: profile.tool_version, argv: [
    '/usr/bin/opengrep', 'scan', '--dump-ast', '--json', '--lang', 'php',
  ] };
  const dumpAst = (dir, path) => docker([...isolation, ...mount(dir, '/src'), '--entrypoint',
    receipt.parser.argv[0], id, ...receipt.parser.argv.slice(1), `/src/${path}`], [0, 3], 30000);
  const parseProof = result => {
    assert.equal(result.status, 0, 'PHP parser rejected source');
    const statements = JSON.parse(result.stdout).Pr;
    assert.ok(Array.isArray(statements) && statements.length > 0, 'Expected a nonempty PHP fixture AST');
    return { exit_code: result.status, ast_sha256: hash(result.stdout), top_level_nodes: statements.length };
  };
  // Parse-only evidence is reusable within this pinned image for identical bytes at the same path.
  const parsed = new Map();
  const extraction = (dir, expected) => expected.map(({ path, sha256 }) => {
    assert.equal(hash(readFileSync(join(dir, path))), sha256, 'Source changed during verification');
    const key = JSON.stringify([path, sha256]);
    if (!parsed.has(key)) parsed.set(key, parseProof(dumpAst(dir, path)));
    return { path, sha256, ...parsed.get(key) };
  });
  receipt.controls = {};
  for (const [name, dir, flags] of [
    ['interfile', source, fixed], ['disabled', source, fixed.filter(flag => flag !== '--enable-interfile')],
    ['safe', safe, fixed],
  ]) {
    const raw = docker([...isolation, ...mount(dir, '/src'), ...mount(marker, '/proof/marker.json'),
      '--entrypoint', '/usr/bin/opengrep', id, 'scan', ...flags, '--strict', '--quiet',
      '--no-rewrite-rule-ids', '--config', '/proof/marker.json', '--json', '/src']).stdout;
    writeFileSync(`${output}.${name}.json`, raw);
    const native = JSON.parse(raw);
    assert.equal(native.version, profile.tool_version);
    assert.deepEqual(native.errors, []);
    assert.deepEqual(native.skipped_rules, []);
    assert.deepEqual([...native.paths.scanned].sort(), files.map(file => `/src/${file.path}`).sort());
    assert.equal(native.results.length, name === 'interfile' ? 1 : 0);
    if (name === 'interfile') {
      assert.match(native.results[0].path, /(?:^|\/)helper\.php$/);
      const origin = native.results[0].extra.dataflow_trace.find(step => step.kind === 'source');
      assert.match(origin.location.path, /(?:^|\/)main\.php$/);
    }
    const control = { findings: native.results.length, sha256: hash(raw) };
    if (name !== 'disabled') {
      assert.deepEqual(native.interfile_languages_used, ['PHP']);
      control.extraction = extraction(dir, dir === safe ? safeFiles : files);
    }
    receipt.controls[name] = control;
  }

  // The parser can emit a partial AST for malformed PHP. Its exit code is decisive.
  const malformed = join(root, 'malformed');
  mkdirSync(malformed);
  const damaged = '<?php\nfunction other( { return 8; }\n';
  writeFileSync(join(malformed, 'broken.php'), damaged);
  const rejected = dumpAst(malformed, 'broken.php');
  assert.equal(rejected.status, 3, 'Expected the pinned parser to reject malformed PHP');
  assert.throws(() => parseProof(rejected), /PHP parser rejected source/);
  receipt.malformed_control = { path: 'broken.php', sha256: hash(damaged), exit_code: rejected.status,
    stdout_sha256: hash(rejected.stdout), stderr_sha256: hash(rejected.stderr) };
  receipt.state = 'PASS';
} catch (error) {
  receipt.error = error.message;
} finally {
  rmSync(root, { recursive: true, force: true });
  writeFileSync(output, JSON.stringify(receipt, null, 2) + '\n');
}
console.log(JSON.stringify({ state: receipt.state, image_id: receipt.image_id, error: receipt.error }));
process.exitCode = receipt.state === 'PASS' ? 0 : 1;
