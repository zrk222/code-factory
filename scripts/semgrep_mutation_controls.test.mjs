import test from 'node:test';
import assert from 'node:assert/strict';
import { findingKeys, verifyRuleMutation, verifySourceSinkFlows, verifyFlowControlMatrix } from './semgrep_mutation_controls.mjs';

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
  const manifest = rules.flatMap(rule => [{ rule, source_line: 2 }, { rule, source_line: 4 }]);
  const safe = Object.fromEntries(rules.map(rule => [rule, 3]));
  const all = [...rules, ...Array.from({ length: 22 }, (_, i) => `other-${i}`)];
  while (manifest.length < 97) manifest.push({ rule: all[8] });
  assert.doesNotThrow(() => verifyFlowControlMatrix(manifest, safe, all));
  assert.throws(() => verifyFlowControlMatrix(manifest.slice(1), safe, all));
  assert.throws(() => verifyFlowControlMatrix(manifest, { ...safe, [rules[0]]: 2 }, all));
  assert.throws(() => verifyFlowControlMatrix([{ rule: all[8] }, ...manifest.slice(1)], safe, all));
});
