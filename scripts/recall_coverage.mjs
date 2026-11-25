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

export function engineCoverage(report) {
  if (!Array.isArray(report?.paths?.scanned)) throw new Error('Missing engine scan paths');
  const scanned = new Set(report.paths.scanned.map(path => scannerPath(path)).filter(Boolean));
  const skipped = new Map((report.paths.skipped ?? []).map(entry => [scannerPath(entry.path), entry.reason]));
  const problems = new Map();
  for (const error of report.errors ?? []) {
    const path = scannerPath(error.path ?? error.spans?.[0]?.file);
    if (path) problems.set(path, /pars|syntax/i.test(String(error.type)) ? 'parse' : 'engine_error');
  }
  return { scanned, skipped, problems };
}

function packetCoverage(source, scan, findings, path) {
  if (!scan.submitted) return { ...source, state: 'not_submitted', reason: 'input_verification_failed' };
  if (!scan.verified) return { ...source, state: 'submitted', reason: 'scan_evidence_unverified' };
  const engine = scan.coverage;
  const issue = engine?.problems.get(path);
  const matched = findings.has(path);
  if (issue) return { ...source, state: 'partial', reason: issue };
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

export function coverageGaps(files = []) {
  return files.filter(file => !['absent', 'excluded'].includes(file.state)
    && (file.state !== 'reported_scanned' || file.reason === 'sarif_finding')).map(file => file.path);
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
