import test from 'node:test';
import assert from 'node:assert/strict';
import { findingKeys, verifyRuleMutation, verifySourceSinkFlows, verifyFlowControlMatrix, verifyFindingCountMatrix,
  fixedReviewedFindingCounts, javascriptControlManifest, verifyJavascriptControlMatrix,
  tsxQualificationSuffix } from './semgrep_mutation_controls.mjs';
import { readFileSync } from 'node:fs';

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
      ...((rules.includes(rule) && index < 3) ? { source_line: index + 2 } : {}),
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
  assert.equal(balancedReplacement.length, 131);
  assert.equal(new Set(balancedReplacement.map(item => item.rule)).size, 30);
  assert.throws(() => verifyFlowControlMatrix(balancedReplacement, safe, all));
  assert.throws(() => verifyFindingCountMatrix(balancedReplacement, all));
});

test('fixed TSX qualification rejects omitted, substituted and wrong-language controls', () => {
  const manifest = javascriptControlManifest();
  assert.doesNotThrow(() => verifyJavascriptControlMatrix(manifest));
  assert.equal(manifest.filter(item => item.path.endsWith('.js')).length, 10);
  assert.equal(manifest.filter(item => item.path.endsWith('.ts')).length, 10);
  assert.equal(manifest.filter(item => item.path.endsWith('.tsx')).length, 12);
  assert.deepEqual(manifest.filter(item => item.path.endsWith('.tsx')).slice(-2).map(item =>
    [item.source_line, item.line]), [[159, 162], [163, 165]]);
  assert.deepEqual(manifest.filter(item => item.path.endsWith('.js')).slice(-3).map(item =>
    [item.source_line, item.line]), [[106, 106], [110, 112], [116, 118]]);
  assert.throws(() => verifyJavascriptControlMatrix(manifest.filter(item => !item.path.endsWith('.tsx'))));
  assert.throws(() => verifyJavascriptControlMatrix(manifest.map(item => ({ ...item,
    path: item.path.replace('.tsx', '.ts') }))));
  assert.throws(() => verifyJavascriptControlMatrix(manifest.map(item => ({ ...item, source_line: item.source_line + 1 }))));
});

test('reviewed TSX endpoints bind actual JSX, Unicode, imported aliases and rebound controls', () => {
  const source = readFileSync(new URL('../deploy/deep-adapters/rules/tests/javascript-controls.js', import.meta.url), 'utf8') + tsxQualificationSuffix;
  const lines = source.split(/\r?\n/);
  for (const expected of javascriptControlManifest().filter(item => item.path.endsWith('.tsx'))) {
    assert.match(lines[expected.source_line - 1], /req\.(query|params|body)/);
    assert.match(lines[expected.line - 2], /ruleid: javascript\.request-/);
  }
  assert.match(source, /return <section title="é漢字">\{value\}<\/section>/);
  assert.match(lines[161], /processAlias\.exec\(alias\)/);
  assert.match(lines[164], /fileAlias\.readFileSync\(path\)/);
  assert.match(source, /safe = "echo fixed"/);
  assert.match(source, /function shadowed\(processAlias, req\)/);
});
