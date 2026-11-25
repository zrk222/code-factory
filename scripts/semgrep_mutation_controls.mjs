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
  ['html', 106, 106], ['html', 110, 112], ['html', 116, 118],
];
export const fixedReviewedFindingCounts = Object.freeze({
  'opt.factory.rules.c.unsafe-gets': 2,
  'opt.factory.rules.csharp.disabled-certificate-verification': 1,
  'opt.factory.rules.csharp.request-command-injection': 3,
  'opt.factory.rules.csharp.request-sql-injection': 3,
  'opt.factory.rules.go.archive-path-traversal': 4,
  'opt.factory.rules.go.disabled-tls-verification': 1,
  'opt.factory.rules.go.parameter-path-join-without-containment': 1,
  'opt.factory.rules.go.parameter-shell-command': 1,
  'opt.factory.rules.go.parameter-sql-text': 3,
  'opt.factory.rules.go.request-command-injection': 3,
  'opt.factory.rules.go.request-html-injection': 2,
  'opt.factory.rules.go.request-path-traversal': 1,
  'opt.factory.rules.go.request-sql-injection': 4,
  'opt.factory.rules.go.tls-client-cert-requested-not-verified': 1,
  'opt.factory.rules.go.tls-peer-not-verified': 2,
  'opt.factory.rules.java.archive-path-traversal': 3,
  'opt.factory.rules.java.disabled-hostname-verification': 4,
  'opt.factory.rules.java.parameter-sql-text': 5,
  'opt.factory.rules.java.request-command-injection': 3,
  'opt.factory.rules.java.request-html-injection': 1,
  'opt.factory.rules.java.request-path-traversal': 1,
  'opt.factory.rules.java.request-sql-injection': 3,
  'opt.factory.rules.javascript.archive-path-traversal': 3,
  'opt.factory.rules.javascript.dom-innerhtml-from-variable': 1,
  'opt.factory.rules.javascript.html-template-unescaped-interpolation': 2,
  'opt.factory.rules.javascript.parameter-path-join-without-containment': 2,
  'opt.factory.rules.javascript.parameter-shell-command': 4,
  'opt.factory.rules.javascript.parameter-sql-text': 2,
  'opt.factory.rules.javascript.request-command-injection': 4,
  'opt.factory.rules.javascript.request-html-injection': 12,
  'opt.factory.rules.javascript.request-path-traversal': 18,
  'opt.factory.rules.javascript.request-sql-injection': 3,
  'opt.factory.rules.javascript.tls-reject-unauthorized-disabled': 1,
  'opt.factory.rules.php.archive-path-traversal': 3,
  'opt.factory.rules.php.parameter-shell-command': 1,
  'opt.factory.rules.php.parameter-sql-text': 3,
  'opt.factory.rules.php.request-command-injection': 13,
  'opt.factory.rules.php.request-file-inclusion': 2,
  'opt.factory.rules.php.request-html-injection': 1,
  'opt.factory.rules.php.request-path-traversal': 12,
  'opt.factory.rules.php.request-sql-injection': 15,
  'opt.factory.rules.php.request-unsafe-deserialization': 4,
  'opt.factory.rules.python.archive-path-traversal': 4,
  'opt.factory.rules.python.disabled-tls-verification': 4,
  'opt.factory.rules.python.parameter-path-join-without-containment': 4,
  'opt.factory.rules.python.parameter-shell-command': 7,
  'opt.factory.rules.python.parameter-sql-text': 2,
  'opt.factory.rules.python.request-command-injection': 2,
  'opt.factory.rules.python.request-html-injection': 1,
  'opt.factory.rules.python.request-path-traversal': 28,
  'opt.factory.rules.python.request-sql-injection': 1,
  'opt.factory.rules.python.tarfile-extractall-without-filter': 5,
  'opt.factory.rules.python.unsafe-deserialization': 2,
  'opt.factory.rules.python.unsafe-deserialization-unscoped': 5,
  'opt.factory.rules.ruby.archive-path-traversal': 2,
  'opt.factory.rules.ruby.disabled-tls-verification': 2,
  'opt.factory.rules.ruby.parameter-shell-command': 1,
  'opt.factory.rules.ruby.parameter-sql-text': 4,
  'opt.factory.rules.ruby.request-command-injection': 3,
  'opt.factory.rules.ruby.request-html-injection': 1,
  'opt.factory.rules.ruby.request-path-traversal': 4,
  'opt.factory.rules.ruby.request-sql-injection': 4,
  'opt.factory.rules.rust.reqwest-disabled-tls-verification': 1,
  'opt.factory.rules.swift.trust-exceptions': 3,
});
// Fixed reviewed sink lines of the rule-family controls appended to the .ts
// fixture (see extensionControlFiles); search-mode rules carry no source line.
export const typescriptExtensionEndpoints = Object.freeze([
  ['archive-path-traversal', 165], ['archive-path-traversal', 185], ['archive-path-traversal', 194],
  ['parameter-shell-command', 207], ['parameter-shell-command', 217],
  ['parameter-sql-text', 233], ['parameter-path-join-without-containment', 247],
  ['html-template-unescaped-interpolation', 261], ['html-template-unescaped-interpolation', 271],
  ['dom-innerhtml-from-variable', 281], ['tls-reject-unauthorized-disabled', 290],
  ['request-path-traversal', 305], ['request-path-traversal', 312], ['request-path-traversal', 314],
  ['parameter-path-join-without-containment', 328], ['parameter-sql-text', 343],
  ['parameter-shell-command', 358], ['parameter-shell-command', 360],
  ['request-path-traversal', 379], ['request-path-traversal', 381],
]);
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
      { rule: 'opt.factory.rules.javascript.request-command-injection', source_line: 159, line: 162 },
      { rule: 'opt.factory.rules.javascript.request-path-traversal', source_line: 163, line: 165 },
    ] : extension === 'ts' ? typescriptExtensionEndpoints.map(([rule, line]) => ({
      rule: `opt.factory.rules.javascript.${rule}`, line,
    })) : [];
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

// Reviewed totals: 64 rules (the deep-audit ruleset bound) and 248 annotated findings.
const REVIEWED_RULES = 64;
const REVIEWED_FINDINGS = 248;

export function verifyFindingCountMatrix(manifest, ruleIds) {
  const expectedRuleIds = Object.keys(fixedReviewedFindingCounts).sort();
  const observedRuleIds = [...ruleIds].sort();
  if (manifest.length !== REVIEWED_FINDINGS || ruleIds.length !== REVIEWED_RULES || new Set(ruleIds).size !== REVIEWED_RULES ||
      JSON.stringify(observedRuleIds) !== JSON.stringify(expectedRuleIds) ||
      Object.values(fixedReviewedFindingCounts).reduce((sum, count) => sum + count, 0) !== REVIEWED_FINDINGS) {
    throw new Error('Registered rule/finding control matrix differs');
  }
  const observedCounts = new Map(ruleIds.map(rule => [rule, 0]));
  for (const item of manifest) {
    if (!observedCounts.has(item.rule)) throw new Error('Unexpected native fixture rule');
    observedCounts.set(item.rule, observedCounts.get(item.rule) + 1);
  }
  if (ruleIds.some(rule => observedCounts.get(rule) !== fixedReviewedFindingCounts[rule])) {
    throw new Error('Reviewed per-rule positive finding counts differ');
  }
}

export function verifyFlowControlMatrix(manifest, safeCounts, ruleIds) {
  verifyFindingCountMatrix(manifest, ruleIds);
  for (const language of ['go', 'java', 'csharp', 'ruby']) {
    for (const family of ['command', 'sql']) {
      const rule = `opt.factory.rules.${language}.request-${family}-injection`;
      const required = family === 'sql' && ['go', 'ruby'].includes(language) ? 4 : 3;
      if (!ruleIds.includes(rule) || manifest.filter(item => item.rule === rule &&
          Number.isInteger(item.source_line)).length !== required || !(safeCounts[rule] >= 3)) {
        throw new Error('Missing direct, alias, framework, safe or provider-mismatch flow control');
      }
    }
  }
}

function sourcePath(uri) {
  if (typeof uri !== 'string') return undefined;
  return uri.replace(/^(?:file:\/\/)?\/src\//, '');
}

// Rule-family controls kept in their own reviewed files and appended to the
// native fixture of the same language. Package clauses, imports and PHP open
// tags are hoisted so each composite stays one parseable source file.
export const extensionControlFiles = Object.freeze([
  ['py', 'python-archive-output-controls.txt'], ['py', 'python-parameter-sink-controls.txt'],
  ['py', 'python-path-join-controls.txt'], ['py', 'python-tls-trust-controls.txt'],
  ['py', 'python-path-request-controls.txt'], ['py', 'python-shell-wrapper-controls.txt'],
  ['py', 'python-model-loader-controls.txt'],
  ['go', 'go-archive-output-controls.txt'], ['go', 'go-parameter-sink-controls.txt'],
  ['go', 'go-path-join-controls.txt'], ['go', 'go-tls-trust-controls.txt'],
  ['java', 'java-archive-output-controls.txt'], ['java', 'java-sql-text-controls.txt'],
  ['ts', 'javascript-archive-output-controls.txt'], ['ts', 'tsx-parameter-sink-controls.txt'],
  ['ts', 'tsx-path-join-controls.txt'], ['ts', 'tsx-html-output-controls.txt'],
  ['ts', 'javascript-tls-trust-controls.txt'], ['ts', 'tsx-path-request-controls.txt'],
  ['ts', 'tsx-sql-text-controls.txt'], ['ts', 'tsx-shell-text-controls.txt'],
  ['ts', 'tsx-fs-identity-controls.txt'],
  ['rb', 'ruby-archive-output-controls.txt'], ['rb', 'ruby-parameter-sink-controls.txt'],
  ['rb', 'ruby-path-param-controls.txt'], ['rb', 'ruby-sql-text-controls.txt'],
  ['php', 'php-archive-output-controls.php'], ['php', 'php-parameter-sink-controls.php'],
  ['php', 'php-path-upload-controls.php'],
]);

function splitHeader(extension, content) {
  const lines = content.split(/\r?\n/);
  const header = [], body = [];
  let inImportBlock = false;
  for (const line of lines) {
    if (extension === 'go') {
      if (/^package\s/.test(line)) continue;
      if (/^import\s*\($/.test(line)) { inImportBlock = true; continue; }
      if (inImportBlock) { if (line.trim() === ')') inImportBlock = false; else if (line.trim()) header.push(`import ${line.trim()}`); continue; }
      if (/^import\s/.test(line)) { header.push(line); continue; }
    } else if (extension === 'java') {
      if (/^package\s/.test(line)) continue;
      if (/^import\s/.test(line)) { header.push(line); continue; }
    } else if (extension === 'php' && line.trim() === '<?php') {
      continue;
    }
    body.push(line);
  }
  return [header, body.join('\n')];
}

export function appendExtensionControls(temp, controlsDir, read, write) {
  for (const [extension, name] of extensionControlFiles) {
    const path = `${temp}/semgrep-pattern-limited.${extension}`;
    const [header, body] = splitHeader(extension, read(`${controlsDir}/${name}`));
    let current = read(path);
    if (header.length) {
      if (extension === 'go') current = current.replace(/^(package [^\n]*\n)/, `$1${header.join('\n')}\n`);
      else current = `${header.join('\n')}\n${current}`;
    }
    write(path, `${current.replace(/\n*$/, '\n')}\n${body}\n`);
  }
}
