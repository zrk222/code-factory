import test from 'node:test';
import assert from 'node:assert/strict';
import { findingKeys, mutationReports, verifyRuleMutation, verifySourceSinkFlows, verifyFlowControlMatrix, verifyFindingCountMatrix,
  verifyNativeControlFindings,
  fixedReviewedFindingCounts, javascriptControlManifest, verifyJavascriptControlMatrix,
  tsxQualificationSuffix, appendExtensionControls, typescriptExtensionEndpoints } from './semgrep_mutation_controls.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const finding = (ruleId, line = 1) => ({ ruleId, locations: [{ physicalLocation: {
  artifactLocation: { uri: '/cases/control.py' }, region: { startLine: line },
} }] });
const report = results => ({ version: '2.1.0', runs: [{ results,
  invocations: [{ executionSuccessful: true }] }] });
const baseline = report([finding('target'), finding('other', 2)]);

test('disabled detector removes target and preserves unrelated findings', () => {
  assert.deepEqual(verifyRuleMutation(baseline, report([finding('other', 2)]), 'target'), {
    state: 'PASS', disabled_rule_id: 'target', removed_findings: 1, retained_findings: 1,
    target_finding_keys: ['target|/cases/control.py|1'],
  });
});

test('mutationReports restores exact report bytes and rejects missing, reordered or invalid evidence', () => {
  const first = Buffer.from(JSON.stringify(report([finding('other', 2)])) + '\r\n');
  const second = Buffer.from(JSON.stringify(report([finding('target')])) + '\n');
  const line = (rule, raw) => JSON.stringify([rule, gzipSync(raw).toString('base64')]);
  const rows = [line('target', first), line('other', second)];
  const rules = ['target', 'other'];
  const unpack = archive => [...mutationReports(archive + '\n', rules)];
  const reports = unpack(rows.join('\n'));
  assert.deepEqual(reports, [{ ruleId: 'target', raw: first }, { ruleId: 'other', raw: second }]);
  for (const { ruleId, raw } of reports) assert.equal(verifyRuleMutation(baseline, JSON.parse(raw), ruleId).state, 'PASS');
  assert.throws(() => unpack(rows[0]), /Incomplete native mutation batch/);
  assert.throws(() => unpack([...rows].reverse().join('\n')), /batch rule identity differs/);
  assert.throws(() => unpack([rows[0], JSON.stringify(['other', 'bad'])].join('\n')));
});

for (const [name, mutated] of [
  ['target still active', baseline],
  ['other detector suppressed', report([])],
  ['unrelated finding changed', report([finding('other', 3)])],
  ['additional finding', report([finding('other', 2), finding('new', 4)])],
  ['duplicate finding', report([finding('other', 2), finding('other', 2)])],
]) test(name, () => assert.throws(() => verifyRuleMutation(baseline, mutated, 'target')));

test('missing positive detector control is rejected', () => {
  assert.throws(() => verifyRuleMutation(baseline, baseline, 'unknown'));
});
test('failed or missing native execution is rejected', () => {
  for (const invocations of [[], [{ executionSuccessful: false }],
    [{ executionSuccessful: true, toolExecutionNotifications: [{ level: 'error' }] }]]) {
    const raw = report([]); raw.runs[0].invocations = invocations;
    assert.throws(() => findingKeys(raw));
  }
});
test('malformed native finding identity is rejected', () => {
  assert.throws(() => findingKeys(report([{ ruleId: 'target', locations: [] }])));
  assert.throws(() => findingKeys(report([finding('target|other')])));
  const ambiguous = finding('target');
  ambiguous.locations[0].physicalLocation.artifactLocation.uri = '/cases/control|other.py';
  assert.throws(() => findingKeys(report([ambiguous])));
});

function atSpan(rule, start, end) {
  const result = finding(rule, 5);
  const location = result.locations[0].physicalLocation;
  location.artifactLocation.uri = '/src/control.py';
  Object.assign(location.region, { startColumn: start, endColumn: end });
  return result;
}

test('verifyNativeControlFindings requires precisely the registered overlaps', () => {
  const outer = atSpan('target', 10, 30), inner = atSpan('target', 15, 22);
  const manifest = [{ rule: 'target', path: 'control.py', line: 5, spans: [[10, 30], [15, 22]] }];
  assert.deepEqual(verifyNativeControlFindings(report([outer, inner]), manifest), {
    logical_keys: ['target|control.py|5'], raw_findings: 2,
  });
  for (const invalid of [[inner], [outer, inner, atSpan('target', 16, 23)],
    [outer, atSpan('target', 15, 23)], [outer, outer]]) {
    assert.throws(() => verifyNativeControlFindings(report(invalid), manifest), /native finding|Native finding spans/);
  }
  assert.throws(() => verifyNativeControlFindings(report([outer, inner]), [{ ...manifest[0], spans: undefined }]));
});

test('rule mutation preserves every unrelated span on the same line', () => {
  const outer = atSpan('other', 10, 30), inner = atSpan('other', 15, 22);
  const before = report([finding('target'), outer, inner]);
  assert.equal(verifyRuleMutation(before, report([inner, outer]), 'target').retained_findings, 2);
  assert.throws(() => verifyRuleMutation(before, report([outer, atSpan('other', 15, 23)]), 'target'));
  assert.throws(() => findingKeys(report([outer, outer])), /Duplicate native findings/);
});

const flowManifest = [{ rule: 'target', path: 'control.go', source_line: 2, line: 5 }];
const sourceHashes = { 'control.go': 'a'.repeat(64) };
function flowReport() {
  const result = finding('target', 5);
  result.locations[0].physicalLocation.artifactLocation.uri = '/src/control.go';
  result.codeFlows = [{ threadFlows: [{ locations: [2, 3, 5].map(line => ({ location: {
    physicalLocation: { artifactLocation: { uri: '/src/control.go' }, region: { startLine: line } },
  } })) }] }];
  return report([result]);
}
test('native ordered source alias sink trace is bound to fixture source hash', () => {
  const verified = verifySourceSinkFlows(flowReport(), flowManifest, sourceHashes);
  assert.deepEqual(verified[0].flows[0].map(step => step.line), [2, 3, 5]);
  assert.ok(verified[0].flows[0].every(step => step.source_sha256 === sourceHashes['control.go']));
});
for (const [name, mutate] of [
  ['missing trace', value => { delete value.runs[0].results[0].codeFlows; }],
  ['wrong source', value => { value.runs[0].results[0].codeFlows[0].threadFlows[0].locations[0].location.physicalLocation.region.startLine = 1; }],
  ['reversed endpoints', value => { value.runs[0].results[0].codeFlows[0].threadFlows[0].locations.reverse(); }],
  ['foreign language trace', value => { value.runs[0].results[0].codeFlows[0].threadFlows[0].locations[0].location.physicalLocation.artifactLocation.uri = '/src/control.java'; }],
  ['duplicate sink', value => { value.runs[0].results.push(structuredClone(value.runs[0].results[0])); }],
]) test(name + ' rejects source-to-sink control', () => {
  const value = flowReport(); mutate(value);
  assert.throws(() => verifySourceSinkFlows(value, flowManifest, sourceHashes));
});

test('registered matrix cannot lose alias, safe or provider controls with its expectations', () => {
  const rules = ['go', 'java', 'csharp', 'ruby'].flatMap(language =>
    ['command', 'sql'].map(family => `opt.factory.rules.${language}.request-${family}-injection`));
  const safe = Object.fromEntries(rules.map(rule => [rule, 3]));
  const all = Object.keys(fixedReviewedFindingCounts);
  const manifest = Object.entries(fixedReviewedFindingCounts).flatMap(([rule, count]) =>
    Array.from({ length: count }, (_, index) => ({ rule,
      ...((rules.includes(rule) && index < ({ 'opt.factory.rules.go.request-command-injection': 5,
        'opt.factory.rules.java.request-sql-injection': 7, 'opt.factory.rules.go.request-sql-injection': 4,
        'opt.factory.rules.ruby.request-sql-injection': 4 }[rule] ?? 3)) ? { source_line: index + 2 } : {}),
    })));
  assert.doesNotThrow(() => verifyFlowControlMatrix(manifest, safe, all));
  assert.doesNotThrow(() => verifyFindingCountMatrix(manifest, all));
  assert.throws(() => verifyFlowControlMatrix(manifest.slice(1), safe, all));
  assert.throws(() => verifyFlowControlMatrix(manifest, { ...safe, [rules[0]]: 2 }, all));
  assert.throws(() => verifyFlowControlMatrix([{ rule: all[8] }, ...manifest.slice(1)], safe, all));
  const pythonPath = 'opt.factory.rules.python.request-path-traversal';
  const phpPath = 'opt.factory.rules.php.request-path-traversal';
  const omitIndex = manifest.findIndex(item => item.rule === pythonPath);
  const balancedReplacement = manifest.filter((_, index) => index !== omitIndex);
  balancedReplacement.push({ ...manifest[omitIndex], rule: phpPath });
  assert.equal(balancedReplacement.length, 402);
  assert.equal(new Set(balancedReplacement.map(item => item.rule)).size, 64);
  assert.throws(() => verifyFlowControlMatrix(balancedReplacement, safe, all));
  assert.throws(() => verifyFindingCountMatrix(balancedReplacement, all));
});

test('fixed TSX qualification rejects omitted, substituted and wrong-language controls', () => {
  const manifest = javascriptControlManifest();
  assert.doesNotThrow(() => verifyJavascriptControlMatrix(manifest));
  assert.equal(manifest.filter(item => item.path.endsWith('.js')).length, 12);
  assert.equal(manifest.filter(item => item.path === 'semgrep-pattern-limited.ts').length, 32);
  assert.deepEqual(manifest.filter(item => item.path.startsWith('typescript-shell-')).map(({ path, line }) =>
    [path, line]), [['typescript-shell-wrapper.ts', 7], ['typescript-shell-binding.ts', 5],
    ['typescript-shell-sanitizer.ts', 6], ['typescript-shell-sanitizer.ts', 11]]);
  assert.equal(manifest.filter(item => item.path.endsWith('.ts')).length, 65);
  assert.deepEqual(manifest.filter(item => item.path === 'typescript-sql-identifier.ts').map(item => item.line),
    [42, 47, 49, 55, 60, 71, 81, 88]);
  assert.equal(manifest.find(item => item.path === 'typescript-html-escaped-local.ts').line, 10);
  assert.equal(manifest.filter(item => item.path.endsWith('.tsx')).length, 17);
  assert.deepEqual(manifest.filter(item => item.path === 'semgrep-pattern-limited.tsx').slice(-2).map(item =>
    [item.source_line, item.line]), [[199, 202], [203, 205]]);
  assert.deepEqual(manifest.filter(item => item.path.endsWith('.js')).slice(-5).map(item =>
    [item.source_line, item.line]), [[106, 106], [110, 112], [116, 118], [160, 164], [172, 175]]);
  assert.throws(() => verifyJavascriptControlMatrix(manifest.filter(item => !item.path.endsWith('.tsx'))));
  assert.throws(() => verifyJavascriptControlMatrix(manifest.map(item => ({ ...item,
    path: item.path.replace('.tsx', '.ts') }))));
  assert.throws(() => verifyJavascriptControlMatrix(manifest.map(item => ({ ...item, source_line: item.source_line + 1 }))));
});

test('reviewed TSX endpoints bind actual JSX, Unicode, imported aliases and rebound controls', () => {
  const source = readFileSync(new URL('../deploy/deep-adapters/rules/tests/javascript-controls.js', import.meta.url), 'utf8') + tsxQualificationSuffix;
  const lines = source.split(/\r?\n/);
  const manifest = javascriptControlManifest();
  const rendererSources = new Map([[160, /tokens\[index\]\.children/], [172, /items\[index\]\.content/]]);
  for (const expected of manifest.filter(item => item.path === 'semgrep-pattern-limited.tsx')) {
    assert.match(lines[expected.source_line - 1], rendererSources.get(expected.source_line) ?? /req\.(query|params|body)/);
    assert.match(lines[expected.line - 2], /ruleid: javascript\.request-/);
  }
  assert.match(source, /return <section title="é漢字">\{value\}<\/section>/);
  assert.match(lines[201], /processAlias\.exec\(alias\)/);
  assert.match(lines[204], /fileAlias\.readFileSync\(path\)/);
  assert.match(source, /safe = "echo fixed"/);
  assert.match(source, /function shadowed\(processAlias, req\)/);
  const reportSource = readFileSync(new URL('../deploy/deep-adapters/rules/tests/report-cli-markup-tsx.txt', import.meta.url), 'utf8');
  const reportLines = reportSource.split(/\r?\n/);
  for (const expected of manifest.filter(item => item.path === 'report-cli-markup.tsx')) {
    assert.equal(reportLines[expected.line - 2].trim(), `// ruleid: ${expected.rule.replace('opt.factory.rules.', '')}`);
  }
});

test('rule-family controls append as one parseable source per language at fixed lines', () => {
  const files = new Map([
    ['/t/semgrep-pattern-limited.ts', readFileSync(new URL('../deploy/deep-adapters/rules/tests/javascript-controls.js', import.meta.url), 'utf8')],
    ['/t/semgrep-pattern-limited.go', 'package controls\nimport "crypto/tls"\nfunc controls() {}\n'],
    ['/t/semgrep-pattern-limited.java', 'class Controls {}\n'],
    ['/t/semgrep-pattern-limited.cs', 'class Controls {}\n'],
    ['/t/semgrep-pattern-limited.php', '<?php\n$x = 1;\n'],
    ['/t/semgrep-pattern-limited.py', 'import os\n'],
    ['/t/semgrep-pattern-limited.rb', '# controls\n'],
  ]);
  const root = fileURLToPath(new URL('../deploy/deep-adapters/rules/tests', import.meta.url));
  appendExtensionControls('/t', root, path => files.get(path) ?? readFileSync(path, 'utf8'), (path, content) => files.set(path, content));
  const go = files.get('/t/semgrep-pattern-limited.go');
  assert.equal(go.match(/^package /gm).length, 1);
  assert.ok(go.indexOf('import "archive/zip"') < go.indexOf('func controls'));
  assert.equal(files.get('/t/semgrep-pattern-limited.php').match(/<\?php/g).length, 1);
  assert.ok(!/^package /m.test(files.get('/t/semgrep-pattern-limited.java')));
  assert.match(files.get('/t/semgrep-pattern-limited.cs'), /class LibrarySqlControls/);
  const ts = files.get('/t/semgrep-pattern-limited.ts').split(/\r?\n/);
  for (const [rule, line] of typescriptExtensionEndpoints) {
    assert.ok(ts[line - 2].includes(`ruleid: javascript.${rule}`), `${rule} at ${line}`);
  }
  for (const name of ['shell-wrapper', 'shell-binding', 'shell-helper', 'html-escaped-local', 'sql-identifier']) {
    const separate = readFileSync(`${root}/tsx-${name}-controls.txt`, 'utf8');
    assert.equal(files.get(`/t/typescript-${name}.ts`), separate);
    assert.equal(ts.join('\n').includes(separate), false);
  }
});

