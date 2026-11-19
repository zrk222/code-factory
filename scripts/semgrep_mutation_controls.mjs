import { readFileSync } from 'node:fs';

export function findingKeys(report) {
  const run = validatedRun(report);
  const keys = run.results.map(findingKey).sort();
  requireUniqueFindings(keys);
  return keys;
}

function validatedRun(report) {
  if (!report || report.version !== '2.1.0' || !Array.isArray(report.runs) || report.runs.length !== 1) {
    throw new Error('Invalid native SARIF report');
  }
  const run = report.runs[0];
  if (!Array.isArray(run.results)) throw new Error('Native detector execution is incomplete');
  validateInvocation(run.invocations);
  return run;
}

function validateInvocation(invocations) {
  if (!Array.isArray(invocations) || invocations.length !== 1 ||
      invocations[0].executionSuccessful !== true ||
      (invocations[0].toolExecutionNotifications ?? []).some(item => item.level === 'error')) {
    throw new Error('Native detector execution is incomplete');
  }
}

function findingKey(result) {
  const location = result.locations?.[0]?.physicalLocation;
  const uri = location?.artifactLocation?.uri;
  const line = location?.region?.startLine;
  if (typeof result.ruleId !== 'string' || !result.ruleId || result.ruleId.includes('|') ||
      result.locations?.length !== 1 || typeof uri !== 'string' || !uri || uri.includes('|') ||
      !Number.isInteger(line) || line < 1) throw new Error('Invalid native finding identity');
  return `${result.ruleId}|${uri}|${line}`;
}

function requireUniqueFindings(keys) {
  if (new Set(keys).size !== keys.length) throw new Error('Duplicate native findings');
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

// Verify native trace endpoints against reviewed synthetic fixture expectations.
// This validates transport evidence; it does not infer a flow from source text.
export function verifySourceSinkFlows(report, manifest, sourceHashes) {
  const run = validatedRun(report);
  const required = manifest.filter(item => item.source_line !== undefined);
  if (!required.length) throw new Error('Missing source-to-sink fixture expectations');
  return required.map(expected => verifyExpectedFlow(run, expected, sourceHashes));
}

function verifyExpectedFlow(run, expected, sourceHashes) {
  const matches = run.results.filter(result => matchesExpectedFinding(result, expected));
  if (matches.length !== 1) throw new Error('Missing or duplicate traced finding');
  const flows = (matches[0].codeFlows ?? []).flatMap(flow => flow.threadFlows ?? []);
  const paths = flows.map(thread => (thread.locations ?? []).map(step => boundFlowStep(step, sourceHashes)));
  if (!paths.some(steps => matchesEndpoints(steps, expected))) {
    throw new Error('Native source/sink endpoints differ');
  }
  return { rule: expected.rule, path: expected.path, source_line: expected.source_line,
    sink_line: expected.line, flows: paths };
}

function matchesExpectedFinding(result, expected) {
  const place = result.locations?.[0]?.physicalLocation;
  return result.ruleId === expected.rule && sourcePath(place?.artifactLocation?.uri) === expected.path &&
    place.region?.startLine === expected.line;
}

function boundFlowStep(step, sourceHashes) {
  const place = step.location?.physicalLocation;
  const path = sourcePath(place?.artifactLocation?.uri);
  const line = place?.region?.startLine;
  if (!Object.hasOwn(sourceHashes, path) || !/^[a-f0-9]{64}$/.test(sourceHashes[path]) ||
      !Number.isInteger(line) || line < 1 || step.index !== undefined) {
    throw new Error('Unbound native flow step');
  }
  return { path, source_sha256: sourceHashes[path], line };
}

function matchesEndpoints(steps, expected) {
  return steps.length >= 2 && steps[0].path === expected.path &&
    steps[0].line === expected.source_line && steps.at(-1).path === expected.path &&
    steps.at(-1).line === expected.line;
}

// Fixed reviewed line identities; never generated from candidate annotations.
export const javascriptControlEndpoints = [
  ['command', 4, 9], ['sql', 23, 26], ['html', 36, 38],
  ['path', 55, 59], ['path', 63, 66], ['path', 70, 73], ['path', 99, 101],
];
export const tsxQualificationSuffix = readFileSync(
  new URL('../deploy/deep-adapters/rules/tests/tsx-controls.txt', import.meta.url), 'utf8');

export function javascriptControlManifest() {
  const family = javascriptControlEndpoints.map(([family, source_line, line]) => ({
    rule: `opt.factory.rules.javascript.request-${family === 'path' ? 'path-traversal' : family + '-injection'}`,
    source_line, line,
  }));
  return ['js', 'ts', 'tsx'].flatMap(extension => {
    const path = `semgrep-pattern-limited.${extension}`;
    const additional = extension === 'tsx' ? [
      { rule: 'opt.factory.rules.javascript.request-command-injection', source_line: 106, line: 109 },
      { rule: 'opt.factory.rules.javascript.request-path-traversal', source_line: 110, line: 112 },
    ] : [];
    return [...family, ...additional].map(item => ({ ...item, path }));
  });
}

export function verifyJavascriptControlMatrix(manifest) {
  const identity = item => `${item.rule}|${item.path}|${item.source_line}|${item.line}`;
  const observed = manifest.filter(item => /\.(?:js|ts|tsx)$/.test(item.path ?? '')).map(identity).sort();
  if (JSON.stringify(observed) !== JSON.stringify(javascriptControlManifest().map(identity).sort())) {
    throw new Error('JavaScript/TypeScript/TSX fixed source/finding matrix differs');
  }
}

export function verifyFlowControlMatrix(manifest, safeCounts, ruleIds) {
  if (manifest.length !== 106 || ruleIds.length !== 30 || new Set(ruleIds).size !== 30) {
    throw new Error('Registered rule/finding control matrix differs');
  }
  for (const language of ['go', 'java', 'csharp', 'ruby']) {
    for (const family of ['command', 'sql']) {
      const rule = `opt.factory.rules.${language}.request-${family}-injection`;
      if (!ruleIds.includes(rule) || manifest.filter(item => item.rule === rule &&
          Number.isInteger(item.source_line)).length !== 2 || safeCounts[rule] !== 3) {
        throw new Error('Missing direct, alias, safe or provider-mismatch flow control');
      }
    }
  }
}

function sourcePath(uri) {
  if (typeof uri !== 'string') return undefined;
  return uri.replace(/^(?:file:\/\/)?\/src\//, '');
}
