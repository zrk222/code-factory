export function findingKeys(report) {
  if (!report || report.version !== '2.1.0' || !Array.isArray(report.runs) || report.runs.length !== 1) {
    throw new Error('Invalid native SARIF report');
  }
  const run = report.runs[0];
  if (!Array.isArray(run.results) || !Array.isArray(run.invocations) ||
      run.invocations.length !== 1 || run.invocations[0].executionSuccessful !== true ||
      (run.invocations[0].toolExecutionNotifications ?? []).some(item => item.level === 'error')) {
    throw new Error('Native detector execution is incomplete');
  }
  const keys = run.results.map(result => {
    const location = result.locations?.[0]?.physicalLocation;
    const uri = location?.artifactLocation?.uri;
    const line = location?.region?.startLine;
    if (typeof result.ruleId !== 'string' || !result.ruleId || result.ruleId.includes('|') ||
        result.locations?.length !== 1 || typeof uri !== 'string' || !uri || uri.includes('|') ||
        !Number.isInteger(line) || line < 1) throw new Error('Invalid native finding identity');
    return `${result.ruleId}|${uri}|${line}`;
  }).sort();
  if (new Set(keys).size !== keys.length) throw new Error('Duplicate native findings');
  return keys;
}

export function verifyRuleMutation(baseline, mutated, ruleId) {
  if (typeof ruleId !== 'string' || !ruleId || ruleId.includes('|')) {
    throw new Error('Invalid disabled rule ID');
  }
  const before = findingKeys(baseline);
  const after = findingKeys(mutated);
  const target = before.filter(key => key.startsWith(`${ruleId}|`));
  if (!target.length) throw new Error('Disabled detector has no positive control');
  const expected = before.filter(key => !key.startsWith(`${ruleId}|`));
  if (JSON.stringify(expected) !== JSON.stringify(after)) {
    throw new Error('Mutation did not remove exactly the target detector findings');
  }
  return { state: 'PASS', disabled_rule_id: ruleId, removed_findings: target.length,
    retained_findings: after.length, target_finding_keys: target };
}
