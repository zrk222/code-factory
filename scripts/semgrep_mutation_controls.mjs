import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';

export function* mutationReports(archive, ruleIds) {
  const lines = archive.trimEnd().split('\n');
  if (lines.length !== ruleIds.length) throw new Error('Incomplete native mutation batch');
  for (const [index, line] of lines.entries()) {
    const entry = JSON.parse(line);
    if (!Array.isArray(entry) || entry.length !== 2 || entry[0] !== ruleIds[index] || typeof entry[1] !== 'string') {
      throw new Error('Native mutation batch rule identity differs');
    }
    const [ruleId, encoded] = entry;
    const raw = gunzipSync(Buffer.from(encoded, 'base64'), { maxOutputLength: 16 * 1024 * 1024 });
    yield { ruleId, raw };
  }
}

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

function findingIdentity(result) {
  const location = result.locations?.[0]?.physicalLocation;
  const uri = location?.artifactLocation?.uri;
  const region = location?.region;
  const line = region?.startLine;
  if (typeof result.ruleId !== 'string' || !result.ruleId || result.ruleId.includes('|') ||
      result.locations?.length !== 1 || typeof uri !== 'string' || !uri || uri.includes('|') ||
      !Number.isInteger(line) || line < 1) throw new Error('Invalid native finding identity');
  return { rule: result.ruleId, uri, line, span: findingSpan(region) };
}

function findingSpan({ startLine, startColumn, endLine = startLine, endColumn }) {
  if (startColumn === undefined && endColumn === undefined && endLine === startLine) return null;
  const coordinates = [startColumn, endLine, endColumn];
  if (!coordinates.every(value => Number.isInteger(value) && value > 0) || endLine < startLine ||
      (endLine === startLine && endColumn < startColumn)) throw new Error('Invalid native finding span');
  return coordinates;
}

function findingKey(result) {
  const { rule, uri, line, span } = findingIdentity(result);
  return [rule, uri, line, ...(span ?? [])].join('|');
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

const controlKey = ({ rule, path, line }) => `${rule}|${path}|${line}`;

export function verifyNativeControlFindings(report, manifest) {
  const run = validatedRun(report);
  const expected = new Map(manifest.map(item => [controlKey(item), { item, observed: [] }]));
  if (expected.size !== manifest.length) throw new Error('Duplicate reviewed control location');
  for (const result of run.results) {
    const { rule, uri, line, span } = findingIdentity(result);
    const key = controlKey({ rule, path: sourcePath(uri), line });
    if (!expected.has(key)) throw new Error(`Unexpected native finding at ${key}`);
    expected.get(key).observed.push(span?.join(':') ?? '');
  }
  for (const [key, { item, observed }] of expected) {
    const reviewed = item.spans?.map(([start, end]) => [start, item.line, end].join(':')).sort();
    if (!observed.length || new Set(observed).size !== observed.length) {
      throw new Error(`Missing or duplicate native finding at ${key}`);
    }
    if (reviewed ? JSON.stringify(observed.sort()) !== JSON.stringify(reviewed) : observed.length !== 1) {
      throw new Error(`Native finding spans differ at ${key}`);
    }
  }
  return { logical_keys: [...expected.keys()].sort(), raw_findings: run.results.length };
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
  ['html', 160, 164], ['html', 172, 175],
];
export const fixedReviewedFindingCounts = Object.freeze({
  'opt.factory.rules.c.unsafe-gets': 2,
  'opt.factory.rules.csharp.disabled-certificate-verification': 1,
  'opt.factory.rules.csharp.request-command-injection': 7,
  'opt.factory.rules.csharp.request-sql-injection': 10,
  'opt.factory.rules.go.archive-path-traversal': 4,
  'opt.factory.rules.go.disabled-tls-verification': 2,
  'opt.factory.rules.go.parameter-path-join-without-containment': 1,
  'opt.factory.rules.go.parameter-shell-command': 4,
  'opt.factory.rules.go.parameter-sql-text': 10,
  'opt.factory.rules.go.request-command-injection': 5,
  'opt.factory.rules.go.request-html-injection': 6,
  'opt.factory.rules.go.request-path-traversal': 1,
  'opt.factory.rules.go.request-sql-injection': 6,
  'opt.factory.rules.go.tls-client-cert-requested-not-verified': 1,
  'opt.factory.rules.go.tls-peer-not-verified': 2,
  'opt.factory.rules.java.archive-path-traversal': 3,
  'opt.factory.rules.java.disabled-hostname-verification': 5,
  'opt.factory.rules.java.parameter-sql-text': 7,
  'opt.factory.rules.java.request-command-injection': 4,
  'opt.factory.rules.java.request-html-injection': 1,
  'opt.factory.rules.java.request-path-traversal': 1,
  'opt.factory.rules.java.request-sql-injection': 7,
  'opt.factory.rules.javascript.archive-path-traversal': 3,
  'opt.factory.rules.javascript.dom-innerhtml-from-variable': 5,
  'opt.factory.rules.javascript.html-template-unescaped-interpolation': 6,
  'opt.factory.rules.javascript.parameter-path-join-without-containment': 3,
  'opt.factory.rules.javascript.parameter-shell-command': 9,
  'opt.factory.rules.javascript.parameter-sql-text': 11,
  'opt.factory.rules.javascript.request-command-injection': 5,
  'opt.factory.rules.javascript.request-html-injection': 18,
  'opt.factory.rules.javascript.request-path-traversal': 30,
  'opt.factory.rules.javascript.request-sql-injection': 3,
  'opt.factory.rules.javascript.tls-reject-unauthorized-disabled': 1,
  'opt.factory.rules.php.archive-path-traversal': 3,
  'opt.factory.rules.php.parameter-shell-command': 1,
  'opt.factory.rules.php.parameter-sql-text': 14,
  'opt.factory.rules.php.request-command-injection': 13,
  'opt.factory.rules.php.request-file-inclusion': 2,
  'opt.factory.rules.php.request-html-injection': 4,
  'opt.factory.rules.php.request-path-traversal': 12,
  'opt.factory.rules.php.request-sql-injection': 19,
  'opt.factory.rules.php.request-unsafe-deserialization': 5,
  'opt.factory.rules.python.archive-path-traversal': 4,
  'opt.factory.rules.python.disabled-tls-verification': 6,
  'opt.factory.rules.python.parameter-path-join-without-containment': 23,
  'opt.factory.rules.python.parameter-shell-command': 8,
  'opt.factory.rules.python.parameter-sql-text': 3,
  'opt.factory.rules.python.request-command-injection': 2,
  'opt.factory.rules.python.request-html-injection': 1,
  'opt.factory.rules.python.request-path-traversal': 29,
  'opt.factory.rules.python.request-sql-injection': 1,
  'opt.factory.rules.python.tarfile-extractall-without-filter': 7,
  'opt.factory.rules.python.unsafe-deserialization': 2,
  'opt.factory.rules.python.unsafe-deserialization-unscoped': 9,
  'opt.factory.rules.ruby.archive-path-traversal': 2,
  'opt.factory.rules.ruby.disabled-tls-verification': 6,
  'opt.factory.rules.ruby.parameter-shell-command': 7,
  'opt.factory.rules.ruby.parameter-sql-text': 8,
  'opt.factory.rules.ruby.request-command-injection': 3,
  'opt.factory.rules.ruby.request-html-injection': 1,
  'opt.factory.rules.ruby.request-path-traversal': 5,
  'opt.factory.rules.ruby.request-sql-injection': 7,
  'opt.factory.rules.rust.reqwest-disabled-tls-verification': 6,
  'opt.factory.rules.swift.trust-exceptions': 3,
});
// Fixed reviewed sink lines of the rule-family controls appended to the .ts
// fixture (see extensionControlFiles); search-mode rules carry no source line.
export const typescriptExtensionEndpoints = Object.freeze([
  ['archive-path-traversal', 205], ['archive-path-traversal', 225], ['archive-path-traversal', 234],
  // The direct sink and interpolation are separate native spans on these lines.
  ['parameter-shell-command', 247], ['parameter-shell-command', 257],
  ['parameter-sql-text', 273], ['parameter-path-join-without-containment', 287],
  ['html-template-unescaped-interpolation', 301], ['html-template-unescaped-interpolation', 311],
  ['dom-innerhtml-from-variable', 321], ['tls-reject-unauthorized-disabled', 330],
  ['request-path-traversal', 345], ['request-path-traversal', 352],
  ['parameter-path-join-without-containment', 368], ['parameter-sql-text', 383],
  ['parameter-shell-command', 398], ['parameter-shell-command', 400],
  ['request-path-traversal', 419], ['request-path-traversal', 421],
  ['parameter-path-join-without-containment', 443],
]);
export const tsxQualificationSuffix = readFileSync(
  new URL('../deploy/deep-adapters/rules/tests/tsx-controls.txt', import.meta.url), 'utf8');

export function javascriptControlManifest() {
  const family = javascriptControlEndpoints.map(([family, source_line, line]) => ({
    rule: `opt.factory.rules.javascript.request-${family === 'path' ? 'path-traversal' : family + '-injection'}`,
    source_line, line,
  }));
  const combined = ['js', 'ts', 'tsx'].flatMap(extension => {
    const path = `semgrep-pattern-limited.${extension}`;
    const additional = extension === 'tsx' ? [
      { rule: 'opt.factory.rules.javascript.request-command-injection', source_line: 199, line: 202 },
      { rule: 'opt.factory.rules.javascript.request-path-traversal', source_line: 203, line: 205 },
    ] : extension === 'ts' ? typescriptExtensionEndpoints.map(([rule, line, spans]) => ({
      rule: `opt.factory.rules.javascript.${rule}`, line, ...(spans ? { spans } : {}),
    })) : [];
    return [...family, ...additional].map(item => ({ ...item, path }));
  });
  const rule = 'opt.factory.rules.javascript.parameter-shell-command';
  return [...combined,
    { rule, path: 'typescript-shell-wrapper.ts', line: 7 },
    { rule, path: 'typescript-shell-binding.ts', line: 5 },
    { rule: 'opt.factory.rules.javascript.html-template-unescaped-interpolation',
      path: 'typescript-html-escaped-local.ts', line: 10 },
    { rule: 'opt.factory.rules.javascript.html-template-unescaped-interpolation',
      path: 'typescript-html-escaped-local.ts', line: 15 },
    { rule: 'opt.factory.rules.javascript.parameter-sql-text',
      path: 'typescript-html-escaped-local.ts', line: 35 },
    { rule: 'opt.factory.rules.javascript.dom-innerhtml-from-variable',
      path: 'typescript-html-escaped-local.ts', line: 51 },
    { rule: 'opt.factory.rules.javascript.dom-innerhtml-from-variable',
      path: 'typescript-html-escaped-local.ts', line: 85 },
    { rule: 'opt.factory.rules.javascript.parameter-shell-command',
      path: 'typescript-html-escaped-local.ts', line: 56 },
    // Values stay reported; quoted identifiers, placeholder lists and aliased quoting helpers do not.
    ...[42, 47, 49, 55, 60, 71, 81, 88].map(line => ({ rule: 'opt.factory.rules.javascript.parameter-sql-text',
      path: 'typescript-sql-identifier.ts', line })),
    // Joined request paths before a fail-closed containment check, prefix-only and
    // non-exiting checks, raw concatenations, and reads that precede the check.
    ...[21, 39, 44, 48, 50, 58, 63, 67, 72, 81, 90].map(line => ({ rule: 'opt.factory.rules.javascript.request-path-traversal',
      path: 'typescript-path-guard.ts', line })),
    ...[[98, 100], [107, 109]].map(([source_line, line]) => ({
      rule: 'opt.factory.rules.javascript.request-path-traversal', path: 'typescript-path-guard.ts', source_line, line,
    })),
    // Values inside inline event-handler attributes.
    ...[4, 9].map(line => ({ rule: 'opt.factory.rules.javascript.html-template-unescaped-interpolation',
      path: 'typescript-html-event-handler.ts', line })),
    // A transparent helper and the raw parameter both retain dataflow.
    ...[6, 11].map(line => ({ rule, path: 'typescript-shell-sanitizer.ts', line })),
    { rule: 'opt.factory.rules.javascript.request-command-injection', path: 'report-cli-markup.tsx', line: 4 },
    { rule: 'opt.factory.rules.javascript.dom-innerhtml-from-variable', path: 'report-cli-markup.tsx', line: 11 },
    { rule: 'opt.factory.rules.javascript.dom-innerhtml-from-variable', path: 'report-cli-markup.tsx', line: 24 },
  ];
}

export function verifyJavascriptControlMatrix(manifest) {
  const identity = item => `${item.rule}|${item.path}|${item.source_line}|${item.line}|${JSON.stringify(item.spans ?? [])}`;
  const observed = manifest.filter(item => /\.(?:js|ts|tsx)$/.test(item.path ?? '')).map(identity).sort();
  if (JSON.stringify(observed) !== JSON.stringify(javascriptControlManifest().map(identity).sort())) {
    throw new Error('JavaScript/TypeScript/TSX fixed source/finding matrix differs');
  }
}

// Reviewed totals bind the enabled rule set and exact annotated finding count.
const REVIEWED_RULES = 64;
const REVIEWED_FINDINGS = 400;

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
      const required = language === 'go' && family === 'command' ? 5
        : language === 'java' && family === 'sql' ? 7
          : family === 'sql' && ['go', 'ruby'].includes(language) ? 4 : 3;
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
  ['cs', 'csharp-sql-library-controls.txt'], ['cs', 'csharp-command-controls.txt'],
  ['ts', 'javascript-archive-output-controls.txt'], ['ts', 'tsx-parameter-sink-controls.txt'],
  ['ts', 'tsx-path-join-controls.txt'], ['ts', 'tsx-html-output-controls.txt'],
  ['ts', 'javascript-tls-trust-controls.txt'], ['ts', 'tsx-path-request-controls.txt'],
  ['ts', 'tsx-sql-text-controls.txt'], ['ts', 'tsx-shell-text-controls.txt'],
  ['ts', 'tsx-fs-identity-controls.txt'], ['ts', 'tsx-sql-tagged-controls.txt'],
  ['ts', 'tsx-path-template-controls.txt'],
  // Independent programs must not share module-level imports.
  ['ts', 'tsx-shell-wrapper-controls.txt', 'typescript-shell-wrapper.ts'],
  ['ts', 'tsx-shell-binding-controls.txt', 'typescript-shell-binding.ts'],
  ['ts', 'tsx-shell-helper-controls.txt', 'typescript-shell-helper.ts'],
  ['ts', 'tsx-html-escaped-local-controls.txt', 'typescript-html-escaped-local.ts'],
  ['ts', 'tsx-sql-identifier-controls.txt', 'typescript-sql-identifier.ts'],
  ['ts', 'tsx-path-guard-controls.txt', 'typescript-path-guard.ts'],
  ['ts', 'tsx-html-event-handler-controls.txt', 'typescript-html-event-handler.ts'],
  ['ts', 'tsx-shell-sanitizer-controls.txt', 'typescript-shell-sanitizer.ts'],
  ['rb', 'ruby-archive-output-controls.txt'], ['rb', 'ruby-parameter-sink-controls.txt'],
  ['rb', 'ruby-path-param-controls.txt'], ['rb', 'ruby-sql-text-controls.txt'],
  ['cs', 'csharp-sql-builder-controls.txt', 'csharp-sql-builder.cs'],
  ['rs', 'rust-boring-hostname-controls.txt', 'rust-boring-hostname.rs'],
  ['rb', 'report-command-path-ruby.txt', 'report-command-path.rb'],
  ['go', 'report-command-trust-go.txt', 'report-command-trust.go'],
  ['php', 'report-query-php.php', 'report-query.php'],
  ['py', 'report-path-python.txt', 'report-path.py'],
  ['cs', 'report-command-csharp.txt', 'report-command.cs'],
  ['java', 'report-trust-java.txt', 'report-trust.java'],
  ['tsx', 'report-cli-markup-tsx.txt', 'report-cli-markup.tsx'],
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
  for (const [extension, name, standalone] of extensionControlFiles) {
    const content = read(`${controlsDir}/${name}`);
    if (standalone) {
      write(`${temp}/${standalone}`, content);
      continue;
    }
    const path = `${temp}/semgrep-pattern-limited.${extension}`;
    const [header, body] = splitHeader(extension, content);
    let current = read(path);
    if (header.length) {
      if (extension === 'go') current = current.replace(/^(package [^\n]*\n)/, `$1${header.join('\n')}\n`);
      else current = `${header.join('\n')}\n${current}`;
    }
    write(path, `${current.replace(/\n*$/, '\n')}\n${body}\n`);
  }
}
