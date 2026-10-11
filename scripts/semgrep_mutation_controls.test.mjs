import test from 'node:test';
import assert from 'node:assert/strict';
import { findingKeys, verifyRuleMutation } from './semgrep_mutation_controls.mjs';

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
