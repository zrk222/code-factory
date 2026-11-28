import { spawnSync } from 'node:child_process';
import { extname, isAbsolute, posix, relative, resolve } from 'node:path';

export const PARSER_LANGUAGE = Object.freeze({ c: 'c', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp', cs: 'csharp',
  go: 'go', java: 'java', js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  php: 'php', py: 'python', pyi: 'python', rb: 'ruby', rs: 'rust', swift: 'swift',
  ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript' });

// Git's NUL-delimited inventory includes files that the strict hunk filter drops.
export function changedFiles(raw) {
  const fields = new TextDecoder('utf-8', { fatal: true }).decode(raw).split('\0');
  if (fields.pop() !== '' || fields.length % 2) throw new Error('Invalid changed-file inventory');
  const changes = [];
  for (let index = 0; index < fields.length; index += 2) {
    const [status, path] = fields.slice(index, index + 2);
    if (!/^[ADMT]$/.test(status) || !path) throw new Error('Invalid changed-file entry');
    changes.push({ path, status });
  }
  return changes;
}

export function scannerPath(path, windows = process.platform === 'win32') {
  if (typeof path !== 'string') return null;
  return (windows ? path.replaceAll('\\', '/') : path).replace(/^\.\//, '');
}

export function sarifPath(uri, packetPaths) {
  const explicitFileUri = uri.startsWith('file://');
  const value = uri.replace(/^file:\/\//, '');
  const literal = scannerPath(value);
  let decoded;
  try {
    decoded = scannerPath(decodeURIComponent(value));
  } catch (error) {
    if (explicitFileUri || (packetPaths && !packetPaths.has(literal))) throw error;
    return literal;
  }
  // OpenGrep sometimes emits a pathname literally rather than encoding it as a URI.
  if (explicitFileUri || !packetPaths?.has(literal)) return decoded;
  if (decoded !== literal && packetPaths.has(decoded)) throw new Error('Ambiguous SARIF source pathname');
  return literal;
}

function engineSkippedPaths(entries) {
  const skipped = new Map();
  for (const entry of entries) {
    const path = scannerPath(entry.path);
    if (!path) continue;
    const reason = skipped.has(path) && skipped.get(path) !== entry.reason ? null : entry.reason;
    skipped.set(path, reason);
  }
  return skipped;
}

export function engineCoverage(report) {
  if (!Array.isArray(report?.paths?.scanned)) throw new Error('Missing engine scan paths');
  const scanned = new Set(report.paths.scanned.map(path => scannerPath(path)).filter(Boolean));
  const skipped = engineSkippedPaths(report.paths.skipped ?? []);
  const problems = new Map();
  const priority = { parse: 1, engine_error: 2, engine_timeout: 3 };
  let timeouts = 0;
  for (const error of report.errors ?? []) {
    const path = scannerPath(error.path ?? error.spans?.[0]?.file);
    const type = String(error.type);
    const reason = /timeout|timed out/i.test(type) ? 'engine_timeout'
      : /pars|syntax/i.test(type) ? 'parse' : 'engine_error';
    if (reason === 'engine_timeout') timeouts++;
    if (path && priority[reason] > (priority[problems.get(path)] ?? 0)) {
      problems.set(path, reason);
    }
  }
  return { scanned, skipped, problems, timeouts };
}

// Read only rule identity, attribution, and scope from the YAML document.
const ruleMetadataProgram = String.raw`
import json, sys
try:
    import yaml
except ImportError:
    sys.exit(3)

def value(node, kind, tag):
    if not isinstance(node, kind) or node.tag != "tag:yaml.org,2002:" + tag:
        raise ValueError("Unsupported rule scope")
    return node.value

def mapping(node):
    pairs = value(node, yaml.MappingNode, "map")
    fields = {value(key, yaml.ScalarNode, "str"): val for key, val in pairs}
    if len(fields) != len(pairs):
        raise ValueError("Duplicate YAML scope field")
    return fields

def strings(node):
    return [value(item, yaml.ScalarNode, "str") for item in value(node, yaml.SequenceNode, "seq")]

doc = mapping(yaml.compose(sys.stdin.buffer, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)))
records, seen = [], set()
for item in value(doc["rules"], yaml.SequenceNode, "seq"):
    rule = mapping(item)
    name = value(rule["id"], yaml.ScalarNode, "str")
    if not name or name in seen:
        raise ValueError("Invalid or duplicate rule id")
    seen.add(name)
    paths = mapping(rule["paths"]) if "paths" in rule else {}
    meta = mapping(rule["metadata"]) if "metadata" in rule else {}
    cwe = meta.get("cwe")
    if cwe is None:
        cwes = []
    elif isinstance(cwe, yaml.ScalarNode):
        cwes = [value(cwe, yaml.ScalarNode, "str")]
    else:
        cwes = strings(cwe)
    mode = value(meta["mode"], yaml.ScalarNode, "str") if "mode" in meta else None
    records.append(dict(id=name, cwes=cwes,
        languages=strings(rule["languages"]) if "languages" in rule else [],
        excludes=strings(paths["exclude"]) if "exclude" in paths else []))
    if mode:
        records[-1]["mode"] = mode
print(json.dumps(records))
`;

export function readRuleMetadata(rules) {
  const python = process.env.CF_RECALL_PYTHON;
  const read = (command, options = []) => spawnSync(command, [...options, '-I', '-c', ruleMetadataProgram], {
    input: rules, encoding: 'utf8', windowsHide: true, timeout: 7000, maxBuffer: 2 * 1024 * 1024,
  });
  let parsed = read(python ?? 'python');
  if (!python && process.platform === 'win32' && (parsed.status === 3 || parsed.error?.code === 'ENOENT')) {
    parsed = read('py', ['-3']);
  }
  if (parsed.status !== 0) return null;
  try {
    const rules = JSON.parse(parsed.stdout);
    return Array.isArray(rules) ? rules : null;
  } catch { return null; }
}

export function compileScannerPathPolicy(rules) {
  const scopes = typeof rules === 'string' || Buffer.isBuffer(rules) ? readRuleMetadata(rules) : rules;
  if (!scopes || scopes.some(({ languages }) => !languages.length)) return () => false;
  const byLanguage = Map.groupBy(scopes.flatMap(({ languages, excludes: patterns }) => {
    const excludes = patterns.filter(glob => /^\*\*\/[\w.*\/-]+$/.test(glob));
    return languages.map(language => ({ language, excludes }));
  }), rule => rule.language);
  const known = new Set(Object.values(PARSER_LANGUAGE));
  if ([...byLanguage.keys()].some(language => !known.has(language))) return () => false;
  return (path) => {
    const extension = extname(path).slice(1).toLowerCase();
    const language = PARSER_LANGUAGE[extension];
    if (!language) return false;
    // Some native parsers accept additional files, so these extensions need both policies.
    const named = extension === 'js' || extension === 'jsx' ? ['javascript', 'typescript']
      : language === 'typescript' ? ['typescript', 'javascript'] : [language];
    const applicable = named.flatMap(name => byLanguage.get(name) ?? []);
    return Boolean(applicable.length) && applicable.every(rule => rule.excludes.some(glob => posix.matchesGlob(path, glob)));
  };
}

export function scannerPathPolicy(profile, rules) {
  if (profile.engine !== 'semgrep' || !['1.15.0', '2.1.0'].includes(profile.tool_version)) return null;
  const usesTargetInventory = profile.tool_version === '2.1.0';
  const proof = usesTargetInventory ? 'opengrep-2.1.0-target-inventory-v1' : 'opengrep-1.15.0-coverage-report-v1';
  return { proof, ruleExcludes: compileScannerPathPolicy(rules), usesTargetInventory };
}

export function engineTargetIgnores(stdout, source) {
  const selected = new Set(), ignored = new Set();
  for (const line of stdout.split(/\r?\n/).filter(Boolean)) {
    const row = line.match(/^(selected) (.+)$/) ?? line.match(/^(ignored) (.+) \[([a-z0-9_-]+)\]$/);
    if (!row) return null;
    const name = scannerPath(relative(source, resolve(source, row[2])));
    if (!name || name === '..' || name.startsWith('../') || isAbsolute(name)) return null;
    if (row[1] === 'selected') selected.add(name);
    else if (row[3] === 'semgrepignore_patterns_match') ignored.add(name);
  }
  return path => !selected.has(path) && [...ignored].some(name => path === name || path.startsWith(name + '/'));
}

function packetCoverage(source, scan, findings, path) {
  if (!scan.submitted) return { ...source, state: 'not_submitted', reason: 'input_verification_failed' };
  if (!scan.verified) return { ...source, state: 'submitted', reason: 'scan_evidence_unverified' };
  const engine = scan.coverage;
  const issue = engine?.problems.get(path);
  const matched = findings.has(path);
  if (issue) return { ...source, state: 'partial', reason: issue };
  if (!matched && !engine?.scanned.has(path) && engine?.policyExclusions?.has(path)) {
    return { ...source, state: 'excluded', reason: 'scanner_path_policy', policy: engine.policyExclusions.get(path) };
  }
  if (engine?.skipped.has(path)) return { ...source, state: 'skipped', reason: engine.skipped.get(path) ?? 'engine_reported_skip' };
  if (engine?.scanned.has(path)) return { ...source, state: 'reported_scanned', reason: 'engine_scan_paths' };
  if (matched) return { ...source, state: 'reported_scanned', reason: 'sarif_finding' };
  if (engine) return { ...source, state: 'unreported', reason: 'absent_from_engine_paths' };
  return { ...source, state: 'submitted', reason: 'no_engine_coverage_report' };
}

function revisionCoverage(changes, options) {
  const { side, packets, scan, extensions, isTestPath } = options;
  const byPath = new Map(packets.map(({ path, bytes, sha256 }) => [path, { bytes, sha256 }]));
  const findings = new Set(scan.findings.map(row => row.path));
  return changes.map(({ path, status }) => {
    const source = byPath.get(path);
    if (source) return { path, submitted: scan.submitted, ...packetCoverage(source, scan, findings, path) };
    if (status === (side === 'old' ? 'A' : 'D')) return { path, submitted: false, state: 'absent',
      reason: side === 'old' ? 'added_in_fix' : 'deleted_in_fix' };
    const eligible = extensions.some(ext => path.endsWith(`.${ext}`));
    const reason = isTestPath(path) ? 'test_path' : eligible ? 'no_scored_hunk' : 'outside_ecosystem_language';
    return { path, submitted: false, state: 'excluded', reason };
  });
}

export function fileCoverage(changes, { packets, scans, extensions, isTestPath }) {
  return Object.fromEntries(['old', 'fixed'].map(side => [side, revisionCoverage(changes, {
    side, packets: packets[side], scan: scans[side], extensions, isTestPath,
  })]));
}

export function coverageGapEntries(files = []) {
  return files.filter(file => !['absent', 'excluded'].includes(file.state)
    && (file.state !== 'reported_scanned' || file.reason === 'sarif_finding'));
}

export function coverageGaps(files) {
  return coverageGapEntries(files).map(file => file.path);
}

// Callers may provide old coverage when they independently replay the path-policy evidence.
export function completeFixedCoverage(files, packets, oldFiles = []) {
  if (!Array.isArray(files) || !Array.isArray(packets)
    || files.some(file => typeof file?.path !== 'string') || coverageGaps(files).length) return false;
  const byPath = new Map(files.map(file => [file.path, file]));
  const oldByPath = new Map(oldFiles.map(file => [file?.path, file]));
  return byPath.size === files.length && oldByPath.size === oldFiles.length && packets.every(packet => {
    const file = byPath.get(packet?.path);
    if (file?.submitted !== true || file.sha256 !== packet.sha256 || file.bytes !== packet.bytes) return false;
    if (file.state === 'reported_scanned') return true;
    const old = oldByPath.get(file.path);
    return file.state === 'excluded' && file.reason === 'scanner_path_policy'
      && ['engine_target_ignore', 'rule_path_exclusions'].includes(file.policy)
      && old?.submitted === true && old.state === 'excluded' && old.reason === file.reason && old.policy === file.policy;
  });
}

export function summarizeCoverage(rows) {
  const counts = {};
  for (const row of rows) {
    for (const files of Object.values(row.file_coverage ?? {})) {
      for (const { state, reason } of files) {
        const key = `${state}:${reason}`;
        counts[key] = (counts[key] ?? 0) + 1;
      }
    }
  }
  return counts;
}
