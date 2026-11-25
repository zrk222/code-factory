#!/usr/bin/env node
// Recall/precision harness for the pattern lane, so held-out numbers are
// reproducible and overlap-safe instead of living in scratch scripts.
//
//   freeze   --candidates rows.json --from YYYY-MM-DD --to YYYY-MM-DD --out manifest.json
//            [--exclude-dir docs/evidence] [--per-repo 3] [--per-ecosystem N]
//   score    --manifest manifest.json --rules ruleset.yml --out results.json
//            [--opengrep BIN] [--profile profile.json] [--workdir DIR] [--jobs 6] [--extra-arg ARG]...
//   controls --rules old.yml --rules new.yml --dir DIR [--dir DIR]... --out deltas.json
//   evaluate --baseline base.yml --candidate new.yml --manifest dev.json [--manifest ...] [--dir CONTROL]...
//            [--max-control-increase N] [--extra-arg ARG]... [--candidate-extra-arg ARG]... --out verdict.json
//            [--probe-coverage true] [--control-exclude DIRECTORY]...
//            [--adjudicated-losses plan.json] [--checkpoint-dir DIR]
//            [--labels labels.json] [--require-reviewed-controls true]
//   observe  --controls deltas.json --labels labels.json   (queue emitted control alerts for review)
//   compare  before.json after.json
//
// Scoring runs the production profile argv (deploy/deep-adapters/profiles),
// with the binary, ruleset and report/source paths substituted, plus an
// OpenGrep coverage report for diagnostics. The scoring rule is fixed: a
// CWE-family-matching alert on an old-side line of a `git diff -U5` hunk in
// an in-language, non-test changed file at the fix parent. Alerts still on
// new-side hunk lines at the fix commit are reported as fix-side residuals,
// a precision proxy.
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { accessSync, closeSync, constants, createReadStream, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readlinkSync, realpathSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, delimiter, dirname, extname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { changedFiles, coverageGaps, engineCoverage, fileCoverage, sarifPath, summarizeCoverage } from './recall_coverage.mjs';
import { hunkAdjudicationIdentity, loadAdjudicatedLosses } from './recall_losses.mjs';

export const FAMILIES = Object.freeze({
  'CWE-78': 'cmd', 'CWE-88': 'cmd', 'CWE-77': 'cmd', 'CWE-89': 'sql',
  'CWE-22': 'path', 'CWE-23': 'path', 'CWE-36': 'path', 'CWE-73': 'path', 'CWE-99': 'path',
  'CWE-79': 'xss', 'CWE-116': 'xss', 'CWE-80': 'xss', 'CWE-502': 'deser',
  'CWE-295': 'tls', 'CWE-297': 'tls', 'CWE-98': 'incl', 'CWE-94': 'code',
});
export const LANGUAGES = Object.freeze({
  PyPI: ['py'], npm: ['js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'mts', 'cts'], Packagist: ['php'],
  Go: ['go'], Maven: ['java'], RubyGems: ['rb'],
});

// Secondary, pre-registered scope: every file type the production semgrep lane
// receives (deep_audit_io.SEMGREP_SOURCE_LANGUAGES), whatever the advisory's
// ecosystem. The primary score keeps the ecosystem-language scope.
export const SCANNABLE_EXTENSIONS = Object.freeze(['py', 'pyi', 'js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'mts', 'cts',
  'php', 'go', 'rs', 'java', 'c', 'h', 'cpp', 'cc', 'cxx', 'hpp', 'cs', 'rb', 'swift']);
export const scopeExtensions = (ecosystem, scope = 'ecosystem') =>
  scope === 'scannable' ? SCANNABLE_EXTENSIONS : LANGUAGES[ecosystem];

const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs|testdata|fixtures?)(\/|$)|_test\.|\.test\.|\.spec\.|Tests?\.(java|cs)$/;

export function isTestPath(path) {
  return TEST_PATH.test(path);
}
export function familiesFor(cwes) {
  return [...new Set(cwes.map(cwe => FAMILIES[cwe]).filter(Boolean))].sort();
}
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const caseDigest = cases => sha256(JSON.stringify(cases.map(sortKeys)));

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sortKeys(value[key])]));
  }
  return value;
}

export function wilson(successes, trials, z = 1.96) {
  if (!trials) return null;
  const p = successes / trials;
  const denominator = 1 + z * z / trials;
  const centre = p + z * z / (2 * trials);
  const spread = z * Math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials));
  return [(centre - spread) / denominator, (centre + spread) / denominator].map(x => Math.round(x * 1000) / 10);
}

function appendHunk(files, match, oldPath, newPath, keep) {
  const [oldStart, oldCount, newStart, newCount] = [match[1], match[2] ?? '1', match[3], match[4] ?? '1'].map(Number);
  if (keep(oldPath)) {
    const entry = files[oldPath] ??= { old: [], new: [], new_path: newPath };
    for (let i = oldStart; i < oldStart + Math.max(oldCount, 1); i++) entry.old.push(i);
  }
  if (keep(newPath) && keep(oldPath ?? newPath)) {
    const entry = files[oldPath ?? newPath] ??= { old: [], new: [], new_path: newPath };
    for (let i = newStart; i < newStart + Math.max(newCount, 1); i++) entry.new.push(i);
  }
}

function diffPath(header, prefix) {
  const raw = header.slice(4).replace(/\t$/, '');
  const path = raw.startsWith('"') ? JSON.parse(raw) : raw;
  return path.startsWith(prefix) ? path.slice(prefix.length) : null;
}

// Old- and new-side line sets of every in-language, non-test file in a -U5 diff.
export function parseHunks(diff, extensions) {
  const files = {};
  let oldPath = null, newPath = null;
  let inHunks = false;
  const keep = path => path && extensions.some(ext => path.endsWith(`.${ext}`)) && !isTestPath(path);
  for (const line of diff.split('\n')) {
    if (line.startsWith('diff --git ')) { oldPath = newPath = null; inHunks = false; continue; }
    if (!inHunks && line.startsWith('--- ')) { oldPath = diffPath(line, 'a/'); continue; }
    if (!inHunks && line.startsWith('+++ ')) { newPath = diffPath(line, 'b/'); continue; }
    const match = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (!match) continue;
    inHunks = true;
    appendHunk(files, match, oldPath, newPath, keep);
  }
  return files;
}

// Rule id -> scored families, read from the ruleset without a YAML dependency.
export function ruleFamilies(rulesText) {
  const out = {};
  for (const block of rulesText.split(/\n  - id: /).slice(1)) {
    const id = block.split('\n', 1)[0].trim();
    const inline = block.match(/\n\s+cwe:\s*\[([^\]]*)\]/);
    const listed = block.match(/\n(\s+)cwe:\s*\n((?:\1\s*- .*\n?)+)/);
    const cwes = inline ? inline[1].split(',') : listed ? listed[2].split('\n') : [];
    out[id] = familiesFor(cwes.map(item => item.replace(/[-\s"']/g, '').replace(/^CWE/, 'CWE-')).filter(Boolean));
  }
  return out;
}

// Earlier advisory IDs and earlier repository@fix pairs from every manifest
// and result file under the evidence directories.
export function priorExposure(paths) {
  const ids = new Set(), fixes = new Set();
  const visit = path => {
    for (const name of readdirSync(path, { withFileTypes: true })) {
      const full = join(path, name.name);
      if (name.isDirectory()) visit(full);
      else if (name.name.endsWith('.json')) {
        const text = readFileSync(full, 'utf8');
        for (const id of text.matchAll(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/g)) ids.add(id[0]);
        for (const fix of text.matchAll(/\b[0-9a-f]{40}\b/g)) fixes.add(fix[0]);
      }
    }
  };
  for (const path of paths) if (existsSync(path)) visit(path);
  return { ids, fixes };
}

function caseExclusion(row, from, to, prior) {
  if (!Object.hasOwn(LANGUAGES, row.ecosystem)) return 'ecosystem';
  if (!(row.published >= from && row.published <= to)) return 'window';
  if (!/^[0-9a-f]{40}$/.test(row.fix ?? '') || !/^[\w.-]+\/[\w.-]+$/.test(row.repository ?? '')) return 'fix_commit';
  if (!Array.isArray(row.cwes) || !familiesFor(row.cwes).length) return 'family';
  if (prior.ids.has(row.ghsa)) return 'prior_id';
  if (prior.fixes.has(row.fix)) return 'prior_fix';
  return null;
}

function distinctCandidates(candidates, { from, to, prior }, drop) {
  const eligible = new Map();
  for (const row of candidates) {
    const reason = caseExclusion(row, from, to, prior);
    if (reason) { drop(reason); continue; }
    const candidate = { ghsa: row.ghsa, ecosystem: row.ecosystem, cwes: [...row.cwes].sort(), published: row.published,
      repository: row.repository, fix: row.fix };
    const previous = eligible.get(candidate.ghsa);
    if (!previous) eligible.set(candidate.ghsa, candidate);
    else if (caseDigest([previous]) === caseDigest([candidate])) drop('duplicate_case');
    else throw new Error('Conflicting advisory metadata for ' + candidate.ghsa);
  }
  return [...eligible.values()].sort((a, b) => b.published.localeCompare(a.published) || a.ghsa.localeCompare(b.ghsa));
}

// Deterministic, overlap-safe selection from advisory metadata only.
export function selectCases(candidates, options) {
  const { from, to, prior = { ids: new Set(), fixes: new Set() }, perRepo = 3, perEcosystem = Infinity } = options;
  const dropped = {};
  const drop = reason => { dropped[reason] = (dropped[reason] ?? 0) + 1; };
  const ordered = distinctCandidates(candidates, { from, to, prior }, drop);
  const seenFix = new Set(), repoCount = {}, ecoCount = {}, cases = [];
  for (const row of ordered) {
    if (seenFix.has(row.fix)) { drop('duplicate_fix'); continue; }
    if ((repoCount[row.repository] ?? 0) >= perRepo) { drop('repository_cap'); continue; }
    if ((ecoCount[row.ecosystem] ?? 0) >= perEcosystem) { drop('ecosystem_cap'); continue; }
    seenFix.add(row.fix);
    repoCount[row.repository] = (repoCount[row.repository] ?? 0) + 1;
    ecoCount[row.ecosystem] = (ecoCount[row.ecosystem] ?? 0) + 1;
    cases.push(row);
  }
  return { cases, dropped };
}

const advisoryId = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;

function validManifestRow(row) {
  return row && typeof row.ghsa === 'string' && advisoryId.test(row.ghsa)
    && Object.hasOwn(LANGUAGES, row.ecosystem) && Array.isArray(row.cwes)
    && row.cwes.every(cwe => typeof cwe === 'string') && familiesFor(row.cwes).length > 0
    && typeof row.repository === 'string' && /^[\w.-]+\/[\w.-]+$/.test(row.repository)
    && !row.repository.split('/').some(part => part === '.' || part === '..')
    && typeof row.fix === 'string' && /^[0-9a-f]{40}$/.test(row.fix);
}

export function validateRecallManifest(manifest) {
  if (!Array.isArray(manifest?.cases) || !manifest.cases.length || !manifest.cases.every(validManifestRow)) {
    throw new Error('Invalid recall case metadata');
  }
  if (new Set(manifest.cases.map(row => row.ghsa)).size !== manifest.cases.length) {
    throw new Error('Duplicate advisory ID in recall manifest');
  }
  const observed = caseDigest(manifest.cases);
  const expected = manifest.cases_sha256 ?? (manifest.schema === 'factory.heldout-advisory-manifest.v1'
    ? manifest.manifest_sha256 : undefined);
  if (observed !== expected) throw new Error('Recall manifest case digest differs');
  return observed;
}

// The production argv with only binary, ruleset and I/O substituted.
export function profileArgv(profile, { bin, rules, report, source, extra = [] }) {
  const argv = profile.commands[0].argv.map(arg => arg === '{report}' ? report : arg === '{source}' ? source : arg);
  argv[0] = bin;
  const config = argv.indexOf('--config');
  if (config < 0) throw new Error('profile has no --config');
  argv[config + 1] = rules;
  argv.splice(argv.length - 1, 0, ...extra);
  return argv;
}

function regionSpan({ startLine, startColumn, endLine, endColumn }) {
  const lineOffset = (endLine ?? startLine) - startLine;
  if (startColumn === undefined && lineOffset === 0 && endColumn === undefined) return null;
  return [startColumn ?? null, lineOffset, endColumn ?? null];
}

export function sarifFindings(sarif, packetPaths) {
  const out = [];
  const clean = loc => sarifPath(loc.artifactLocation.uri, packetPaths);
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const location = result.locations?.[0]?.physicalLocation;
      if (!location) continue;
      const trace = (result.codeFlows ?? []).flatMap(flow => flow.threadFlows ?? [])
        .flatMap(thread => thread.locations ?? []).map(step => step.location?.physicalLocation)
        .filter(step => step?.artifactLocation && step.region).map(step => [clean(step), step.region.startLine]);
      const span = regionSpan(location.region);
      out.push({ rule: result.ruleId.split('.').slice(-2).join('.'), path: clean(location),
        line: location.region.startLine, ...(span ? { span } : {}), trace });
    }
  }
  return out;
}

// Hunk/file hit and fix-side residuals for one case.
export function scoreCase({ families, hunks, oldFindings, newFindings, rules }) {
  const wanted = new Set(families);
  const relevant = finding => (rules[finding.rule] ?? []).some(family => wanted.has(family));
  const changedFindings = oldFindings.filter(f => Object.hasOwn(hunks, f.path));
  const oldHits = changedFindings.filter(relevant);
  const hunkHits = oldHits.filter(f => hunks[f.path]?.old.includes(f.line));
  const matchedFamilies = [...new Set(hunkHits.flatMap(f => rules[f.rule].filter(family => wanted.has(family))))].sort();
  // Secondary, pre-registered: the alert's source or any dataflow step is on a changed line.
  const traceHits = oldHits.filter(f => [[f.path, f.line], ...(f.trace ?? [])]
    .some(([path, line]) => hunks[path]?.old.includes(line)));
  const residual = newFindings.filter(relevant).filter(f => Object.values(hunks)
    .some(entry => entry.new_path === f.path && entry.new.includes(f.line)));
  const hunkSpans = hunkHits.map(f => f.span ?? null);
  return { hunk_hit: hunkHits.length > 0, trace_hit: traceHits.length > 0, file_hit: oldHits.length > 0,
    hunk_findings: hunkHits.map(f => [f.rule, f.path, f.line]),
    ...(hunkSpans.some(Boolean) ? { hunk_spans: hunkSpans } : {}), matched_hunk_families: matchedFamilies,
    alerts_in_changed_files: changedFindings.length, family_alerts_in_changed_files: oldHits.length,
    fix_side_residual: residual.map(f => [f.rule, f.path, f.line]) };
}

function scanIssue(notes) {
  if (notes?.timeouts > 0) return 'timeout';
  if (notes?.blocking_parse_errors > 0 || notes?.other > 0 || notes?.failed_exit) return 'error';
  return null;
}

export function outcomeOf(row) {
  if (row.status === 'error') return 'error';
  const sides = row.scan_sides ?? { old: row.scan_notes };
  const issues = Object.values(sides).map(scanIssue);
  if (issues.includes('timeout')) return 'timeout';
  if (issues.includes('error')) return 'error';
  if (!row.hunk_hit && coverageGaps(row.file_coverage?.old).length) return 'coverage_incomplete';
  if (row.status !== 'scored') return 'unknown';
  return row.hunk_hit ? 'hit' : 'miss';
}

export function summarize(rows) {
  const outcomes = rows.map(outcomeOf);
  const scored = rows.filter((_, index) => ['hit', 'miss'].includes(outcomes[index]));
  const tally = (key, hit) => {
    const out = {};
    for (const row of scored) {
      for (const value of [].concat(row[key])) {
        const entry = out[value] ??= { hits: 0, scored: 0 };
        entry.scored++; entry.hits += hit(row, value) ? 1 : 0;
      }
    }
    return out;
  };
  const hits = scored.filter(row => row.hunk_hit).length;
  const fileHits = scored.filter(row => row.file_hit).length;
  const alerts = rows.reduce((n, row) => n + (row.alerts_in_changed_files ?? 0), 0);
  const scoredAlerts = scored.reduce((n, row) => n + (row.alerts_in_changed_files ?? 0), 0);
  return {
    cases: rows.length, scored: scored.length, file_coverage: summarizeCoverage(rows),
    status: rows.reduce((acc, row) => ({ ...acc, [row.status]: (acc[row.status] ?? 0) + 1 }), {}),
    hunk_hits: hits, hunk_recall_wilson95: wilson(hits, scored.length),
    hunk_hits_over_registered_cases: { hits, cases: rows.length, wilson95: wilson(hits, rows.length) },
    trace_hits: scored.filter(row => row.trace_hit).length,
    trace_recall_wilson95: wilson(scored.filter(row => row.trace_hit).length, scored.length),
    file_hits: fileHits, file_recall_wilson95: wilson(fileHits, scored.length),
    distinct_fixes_hit: new Set(scored.filter(row => row.hunk_hit).map(row => row.fix)).size,
    outcomes: outcomes.reduce((acc, outcome) => { acc[outcome]++; return acc; },
      { hit: 0, miss: 0, timeout: 0, unknown: 0, error: 0, coverage_incomplete: 0 }),
    diagnostics: rows.flatMap((row, index) => ['hit', 'miss'].includes(outcomes[index]) ? [] : [{
      ghsa: row.ghsa, status: row.status, outcome: outcomes[index],
      scan_sides: row.scan_sides ?? { old: row.scan_notes }, detail: row.detail,
      old_coverage_gaps: coverageGaps(row.file_coverage?.old),
    }]),
    // Review budget: every alert in a changed file is something a reviewer reads.
    review_budget: { alerts_in_changed_files: alerts,
      family_alerts_in_changed_files: rows.reduce((n, row) => n + (row.family_alerts_in_changed_files ?? 0), 0),
      per_scored_case: scored.length ? Math.round(10 * scoredAlerts / scored.length) / 10 : 0 },
    fix_side_residual_alerts: scored.reduce((n, row) => n + row.fix_side_residual.length, 0),
    by_family: tally('families', (row, family) => row.matched_hunk_families?.includes(family)),
    by_ecosystem: tally('ecosystem', row => row.hunk_hit),
  };
}

// Async child processes so --jobs really runs cases side by side.
function runProcess(command, args, { cwd, env, timeout = 1800000, bytes = false, discardStdout = false } = {}) {
  return new Promise(done => {
    const child = spawn(command, args, { cwd, env: { ...process.env, ...env },
      ...(discardStdout ? { stdio: ['ignore', 'ignore', 'pipe'] } : {}) });
    const out = [], err = [];
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeout);
    child.stdout?.on('data', chunk => out.push(chunk));
    child.stderr.on('data', chunk => err.push(chunk));
    child.on('error', error => { clearTimeout(timer); done({ status: -1, stdout: '', stderr: String(error) }); });
    child.on('close', status => { clearTimeout(timer);
      const stdout = Buffer.concat(out);
      done({ status, timedOut, stdout: bytes ? stdout : stdout.toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
  });
}

const git = (dir, ...args) => runProcess('git', ['-C', dir, ...args], { timeout: 900000 });

const gitBytes = (dir, ...args) => runProcess('git', ['-C', dir, ...args], { timeout: 900000, bytes: true });
const byPath = (a, b) => a.path < b.path ? -1 : a.path === b.path ? 0 : 1;
const utf8 = raw => new TextDecoder('utf-8', { fatal: true }).decode(raw);
const packet = (path, raw) => ({ path, bytes: raw.length, sha256: sha256(raw) });

async function nextBlobChunk(reader, path) {
  const chunk = await reader.next();
  if (chunk.done) throw new Error('Truncated prepared source: ' + path);
  return chunk.value;
}

async function readBatchBlob(stream, path) {
  let end = stream.pending.indexOf(10);
  while (end < 0 && stream.pending.length <= 128) {
    stream.pending = Buffer.concat([stream.pending, await nextBlobChunk(stream.reader, path)]);
    end = stream.pending.indexOf(10);
  }
  const header = end >= 0 && end <= 128 && stream.pending.toString('ascii', 0, end).match(/^blob (0|[1-9]\d*)$/);
  if (!header) throw new Error('Prepared source could not be read: ' + path);
  stream.pending = stream.pending.subarray(end + 1);
  const raw = Buffer.allocUnsafe(Number(header[1]));
  for (let offset = 0; offset < raw.length;) {
    if (!stream.pending.length) stream.pending = await nextBlobChunk(stream.reader, path);
    const bytes = Math.min(raw.length - offset, stream.pending.length);
    stream.pending.copy(raw, offset, 0, bytes);
    stream.pending = stream.pending.subarray(bytes);
    offset += bytes;
  }
  if (!stream.pending.length) stream.pending = await nextBlobChunk(stream.reader, path);
  if (stream.pending[0] !== 10) throw new Error('Invalid prepared source framing: ' + path);
  stream.pending = stream.pending.subarray(1);
  return raw;
}

async function materialize(repo, revision, paths, target) {
  if (!paths.length) return [];
  // NUL-delimited requests preserve arbitrary Git paths. Read one blob at a time.
  const child = spawn('git', ['-C', repo, 'cat-file', '--batch=%(objecttype) %(objectsize)', '-z'],
    { stdio: ['pipe', 'pipe', 'ignore'] });
  const status = new Promise(done => {
    child.once('error', () => done(-1));
    child.once('close', done);
  });
  const timer = setTimeout(() => child.kill('SIGKILL'), 900000);
  child.stdin.on('error', () => {}); // Child failure is checked via the stream and exit code.
  child.stdin.end(paths.map(path => revision + ':' + path + '\0').join(''));
  const stream = { reader: child.stdout[Symbol.asyncIterator](), pending: Buffer.alloc(0) };
  const packets = [];
  try {
    for (const path of paths) {
      const raw = await readBatchBlob(stream, path);
      const location = join(target, path);
      mkdirSync(dirname(location), { recursive: true });
      writeFileSync(location, raw);
      packets.push(packet(path, raw));
    }
    if (stream.pending.length || !(await stream.reader.next()).done || await status !== 0) {
      throw new Error('Unexpected Git response while preparing source blobs');
    }
    return packets.sort(byPath);
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await status;
  }
}

function verifyPreparedBytes(root, expected) {
  const files = [];
  const visit = (directory, prefix) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const location = join(directory, entry.name), relative = prefix + entry.name;
      if (entry.isDirectory()) visit(location, relative + '/');
      else if (entry.isFile()) files.push(packet(relative, readFileSync(location)));
      else throw new Error('Unexpected input in prepared source: ' + relative);
    }
  };
  visit(root, '');
  if (caseDigest(files.sort(byPath)) !== caseDigest(expected)) {
    throw new Error('Prepared source byte fingerprints differ');
  }
}

function readCoverage(path, notes) {
  try {
    const raw = readFileSync(path);
    notes.coverage_report_sha256 = sha256(raw);
    notes.coverage_report_bytes = raw.length;
    return engineCoverage(JSON.parse(utf8(raw)));
  } catch (error) {
    notes.coverage_report_issue = error.code === 'ENOENT' ? 'missing' : 'invalid';
    return null;
  }
}

function coverageReportPath(profile, report, collectCoverage) {
  if (collectCoverage && profile.engine === 'semgrep' && profile.commands[0].argv.includes('--sarif-output')) {
    return report + '.coverage.json';
  }
  return null;
}

// Scan with the source as cwd so SARIF URIs are relative to it.
export async function scan(context, source, report = `${source}.sarif`, collectCoverage = false) {
  rmSync(report, { force: true });
  mkdirSync(dirname(report), { recursive: true });
  const coveragePath = coverageReportPath(context.profile, report, collectCoverage);
  if (coveragePath) rmSync(coveragePath, { force: true });
  const extra = coveragePath ? [...context.extra, '--json-output', coveragePath, '--verbose'] : context.extra;
  const argv = profileArgv(context.profile, { bin: context.bin, rules: context.rules, report, source: '.', extra });
  const started = performance.now();
  const run = await runProcess(argv[0], argv.slice(1), { cwd: source,
    env: { HOME: process.env.HOME ?? '/tmp', PYTHONIOENCODING: 'utf-8', LANG: 'C.UTF-8' } });
  const execution = { failed_exit: ![0, 1].includes(run.status), exit_code: run.status,
    timeouts: Number(Boolean(run.timedOut)), duration_ms: Math.round(performance.now() - started) };
  const coverage = coveragePath && readCoverage(coveragePath, execution);
  if (!existsSync(report)) {
    throw Object.assign(new Error('Scan produced no SARIF report'), {
      diagnostics: execution,
    });
  }
  const reportBytes = readFileSync(report);
  const diagnostics = { ...execution, report_sha256: sha256(reportBytes), report_bytes: reportBytes.length };
  try {
    const sarif = JSON.parse(utf8(reportBytes));
    if (!Array.isArray(sarif?.runs) || !sarif.runs.length) throw new Error('Scan produced no SARIF run');
    const findings = sarifFindings(sarif, context.packetPaths);
    findings.notes = { ...diagnostics, ...scanNotes(sarif) };
    findings.coverage = coverage;
    findings.notes.timeouts = Math.max(execution.timeouts, findings.notes.timeouts);
    return findings;
  } catch (error) {
    throw Object.assign(error, { diagnostics });
  }
}

// Engine timeouts and parse failures, so a miss caused by the engine is not
// counted as a detector miss.
function notificationKind(note) {
  const descriptor = note.descriptor?.id ?? '';
  // Parse messages can quote arbitrary source text after the diagnostic header.
  const message = (note.message?.text ?? '').split(/\n|`/)[0];
  if (/syntax|pars/i.test(descriptor)) return 'parse';
  if (/timeout|timed out/i.test(`${descriptor} ${message}`)) return 'timeout';
  return /syntax|pars/i.test(message) ? 'parse' : 'other';
}

export function scanNotes(sarif) {
  const notes = { timeouts: 0, parse_errors: 0, blocking_parse_errors: 0, other: 0 };
  for (const run of sarif.runs ?? []) {
    for (const invocation of run.invocations ?? []) {
      if (invocation.executionSuccessful === false) notes.other++;
      for (const note of invocation.toolExecutionNotifications ?? []) {
        const kind = notificationKind(note);
        if (kind === 'timeout') notes.timeouts++;
        else if (kind === 'parse') {
          notes.parse_errors++;
          if (note.level !== 'warning' && note.level !== 'note') notes.blocking_parse_errors++;
        }
        else if (note.level === 'error') notes.other++;
      }
    }
  }
  return notes;
}

function readPreparedInventory(directory, digest) {
  const raw = readFileSync(join(directory, 'changes.z'));
  if (sha256(raw) !== digest) throw new Error('Prepared changed-file inventory fingerprint differs');
  return changedFiles(raw);
}

// Fetch once per case and keep the old/new trees, so several rulesets can be
// scored against the same materialized fixes.
function bindPreparedCase(directory, record, key, row, scope) {
  if (record.case_sha256 !== key) throw new Error('Prepared case fingerprint differs');
  if (record.status !== 'ready') return record;
  if (record.revisions?.fixed !== row.fix || !/^[0-9a-f]{40}$/.test(record.revisions?.old ?? '')) {
    throw new Error('Prepared source revisions differ');
  }
  const patch = readFileSync(join(directory, 'diff.patch'));
  if (sha256(patch) !== record.diff_sha256) throw new Error('Prepared diff byte fingerprint differs');
  return { ...record, changes: readPreparedInventory(directory, record.changed_files_sha256),
    hunks: parseHunks(patch.toString('utf8'), scopeExtensions(row.ecosystem, scope)),
    old: record.source_packets.old.length ? join(directory, 'old') : null,
    new: record.source_packets.fixed.length ? join(directory, 'new') : null };
}

async function prepareChanges(repo, dir, parent, fix, extensions) {
  const inventory = await gitBytes(repo, 'diff', '--name-status', '--no-renames', '-z', parent, fix, '--');
  if (inventory.status !== 0) throw new Error('Prepared changed-file inventory could not be read');
  const changes = changedFiles(inventory.stdout);
  const additions = new Set(changes.filter(row => row.status === 'A').map(row => row.path));
  const diff = await gitBytes(repo, '-c', 'core.quotePath=false', 'diff', '-U5', parent, fix, '--',
    ...extensions.map(ext => '*.' + ext));
  if (diff.status !== 0) throw new Error('Prepared case diff could not be read');
  const hunks = parseHunks(diff.stdout.toString('utf8'), extensions);
  const old = await materialize(repo, parent, Object.keys(hunks).filter(path => !additions.has(path)), join(dir, 'old'));
  const fixedPaths = [...new Set(Object.values(hunks).map(entry => entry.new_path).filter(Boolean))];
  const fixed = await materialize(repo, fix, fixedPaths, join(dir, 'new'));
  writeFileSync(join(dir, 'changes.z'), inventory.stdout);
  writeFileSync(join(dir, 'diff.patch'), diff.stdout);
  return { status: 'ready', revisions: { old: parent, fixed: fix },
    changed_files_sha256: sha256(inventory.stdout), diff_sha256: sha256(diff.stdout), source_packets: { old, fixed } };
}

async function buildPreparedCase(dir, row, scope) {
  const repo = join(dir, 'repo');
  mkdirSync(repo, { recursive: true });
  await git(repo, 'init', '-q');
  await git(repo, 'remote', 'add', 'origin', `https://github.com/${row.repository}.git`);
  if ((await git(repo, 'fetch', '-q', '--filter=blob:none', '--depth=2', 'origin', row.fix)).status !== 0) return { status: 'unfetchable' };
  const fix = (await git(repo, 'rev-parse', 'FETCH_HEAD')).stdout.trim();
  if (fix !== row.fix) throw new Error('Fetched case revision differs from the manifest');
  const parent = (await git(repo, 'rev-parse', `${fix}^`)).stdout.trim();
  if (!parent) return { status: 'no_parent' };
  return prepareChanges(repo, dir, parent, fix, scopeExtensions(row.ecosystem, scope));
}

export async function publishPreparedCase(staging, directory, { rename = renameSync, platform = process.platform } = {}) {
  const record = join(directory, 'case.json');
  for (const wait of [25, 75, 150, null]) {
    try {
      rename(staging, directory);
      return;
    } catch (error) {
      if (existsSync(record)) return;
      if (wait === null || platform !== 'win32' || !['EACCES', 'EBUSY', 'EPERM'].includes(error.code)) throw error;
    }
    await delay(wait);
  }
}

async function prepareCase(workdir, row, scope = 'ecosystem') {
  const key = caseDigest([row]);
  const cache = join(workdir, scope === 'scannable' ? 'cases-v4-scannable' : 'cases-v4'), directory = join(cache, key);
  const record = join(directory, 'case.json');
  const read = () => bindPreparedCase(directory, JSON.parse(readFileSync(record, 'utf8')), key, row, scope);
  if (existsSync(record)) return read();

  mkdirSync(cache, { recursive: true });
  const staging = mkdtempSync(join(cache, key + '-'));
  try {
    const data = await buildPreparedCase(staging, row, scope);
    if (data.status === 'unfetchable') return data;
    rmSync(join(staging, 'repo'), { recursive: true, force: true });
    writeFileSync(join(staging, 'case.json'), JSON.stringify({ ...data, case_sha256: key }));
    await publishPreparedCase(staging, directory);
    return read();
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

class RecallInputDrift extends Error {}

function verifyRulesBytes(context) {
  if (sha256(readFileSync(context.rules)) !== context.rulesSha256) {
    throw new RecallInputDrift('Scan ruleset byte fingerprint differs');
  }
}

function reportReferences(context, report, diagnostics) {
  const local = path => relative(context.workdir, path).split(sep).join('/');
  const coverage = coverageReportPath(context.profile, report, true);
  return { sarif: diagnostics.report_sha256 ? { path: local(report), sha256: diagnostics.report_sha256 } : null,
    native_report: coverage && diagnostics.coverage_report_sha256
      ? { path: local(coverage), sha256: diagnostics.coverage_report_sha256 } : null };
}

function captureReference(context, source, report, diagnostics) {
  return { source_root: relative(context.workdir, source).split(sep).join('/'), ...reportReferences(context, report, diagnostics) };
}

async function observeSide(context, source, report, expected) {
  if (!source) return { findings: [], diagnostics: null, submitted: false };
  let diagnostics;
  let submitted = false;
  try {
    verifyPreparedBytes(source, expected);
    verifyRulesBytes(context);
    submitted = true;
    const packetPaths = new Set(expected.map(row => row.path));
    const findings = await scan({ ...context, packetPaths }, source, report, true);
    diagnostics = findings.notes;
    verifyRulesBytes(context);
    verifyPreparedBytes(source, expected);
    const capture = captureReference(context, source, report, diagnostics);
    return { findings, diagnostics, coverage: findings.coverage, capture, submitted, verified: true };
  } catch (error) {
    if (error instanceof RecallInputDrift) throw error;
    return { findings: [], submitted, diagnostics: { ...(diagnostics ?? error.diagnostics),
      other: 1, detail: String(error.message).slice(-300) } };
  }
}

async function scoreOne(context, row) {
  const prepared = await prepareCase(context.workdir, row, context.scope);
  if (prepared.status !== 'ready') return { status: prepared.status };
  const reports = join(context.scanRoot, row.ghsa);
  const { old: oldPackets, fixed: fixedPackets } = prepared.source_packets;
  const old = await observeSide(context, prepared.old, join(reports, 'old.sarif'), oldPackets);
  const fixed = await observeSide(context, prepared.new, join(reports, 'new.sarif'), fixedPackets);
  const families = familiesFor(row.cwes);
  const result = scoreCase({ families, hunks: prepared.hunks, oldFindings: old.findings,
    newFindings: fixed.findings, rules: context.ruleMap });
  const coverage = fileCoverage(prepared.changes, { packets: prepared.source_packets,
    scans: { old, fixed }, extensions: scopeExtensions(row.ecosystem, context.scope), isTestPath });
  const status = oldPackets.length ? 'scored' : fixedPackets.length ? 'no_old_side_source' : 'no_in_language_source_change';
  const rowResult = { status, families, changed_files: Object.keys(prepared.hunks).sort(),
    revisions: prepared.revisions, source_packets: prepared.source_packets, diff_sha256: prepared.diff_sha256,
    changed_files_sha256: prepared.changed_files_sha256, file_coverage: coverage,
    scan_notes: old.diagnostics, scan_sides: { old: old.diagnostics, fixed: fixed.diagnostics },
    captures: { old: old.capture ?? null, fixed: fixed.capture ?? null }, ...result };
  const outcome = outcomeOf(rowResult);
  return { ...rowResult, status: ['error', 'timeout', 'coverage_incomplete'].includes(outcome) ? 'incomplete' : status, outcome };
}

async function pool(items, jobs, worker) {
  if (!Number.isSafeInteger(jobs) || jobs < 1) throw new Error('Recall jobs must be a positive integer');
  const out = new Array(items.length);
  let next = 0;
  let failure;
  await Promise.all(Array.from({ length: Math.min(jobs, items.length) }, async () => {
    try {
      while (!failure && next < items.length) {
        const index = next++;
        out[index] = await worker(items[index]);
      }
    } catch (error) { failure ??= { error }; }
  }));
  if (failure) throw failure.error;
  return out;
}

function options(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) { out._.push(argv[i]); continue; }
    const key = argv[i].slice(2);
    const value = argv[++i];
    out[key] = key in out ? [].concat(out[key], value) : value;
  }
  return out;
}

function freeze(opts) {
  const candidateBytes = readFileSync(opts.candidates);
  const candidates = JSON.parse(utf8(candidateBytes));
  const prior = priorExposure([].concat(opts['exclude-dir'] ?? 'docs/evidence'));
  const { cases, dropped } = selectCases(candidates, { from: opts.from, to: opts.to, prior,
    perRepo: Number(opts['per-repo'] ?? 3), perEcosystem: Number(opts['per-ecosystem'] ?? Infinity) });
  const manifest = { schema: 'factory.recall-heldout.v1', frozen_from: 'advisory metadata only; no fix diff read',
    candidate_metadata_sha256: sha256(candidateBytes),
    window: [opts.from, opts.to], exclusions: { prior_ids: prior.ids.size, prior_fix_commits: prior.fixes.size },
    dropped, counts: cases.reduce((acc, row) => ({ ...acc, [row.ecosystem]: (acc[row.ecosystem] ?? 0) + 1 }), {}),
    cases_sha256: caseDigest(cases), scoring_rule: 'hunk rule: CWE-family alert on an old-side -U5 hunk line, in-language non-test file, fix parent',
    cases };
  validateRecallManifest(manifest);
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 1)}\n`);
  console.log(`froze ${cases.length} cases (${manifest.cases_sha256})`, dropped);
}

function scoringContext(opts, rulesPath) {
  const rulesBytes = readFileSync(rulesPath);
  // evaluate() reads the profile once so a working-tree edit during a long
  // paired run cannot give the two sides different profiles.
  const profileBytes = opts.profileBytes ?? readFileSync(opts.profile ?? 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json');
  return { profile: JSON.parse(utf8(profileBytes)), profileSha256: sha256(profileBytes),
    bin: opts.opengrep ?? process.env.OPENGREP ?? 'opengrep', rules: resolve(rulesPath),
    rulesSha256: sha256(rulesBytes), ruleMap: ruleFamilies(utf8(rulesBytes)),
    extra: [].concat(opts['extra-arg'] ?? []), workdir: resolve(opts.workdir ?? '.factory/recall-work'),
    scope: opts.scope === 'scannable' ? 'scannable' : 'ecosystem' };
}

// Restartable qualification: a completed scored case (or control pair) is
// kept under the exact fingerprint of everything that decides its outcome,
// and reused only when every input matches. Timeouts and errors are never
// kept, so a resumed run rescans them.
export function checkpointKey(inputs) {
  return sha256(Buffer.from(JSON.stringify(inputs)));
}

export function readCheckpoint(root, inputs) {
  if (!root) return null;
  const path = join(root, `${checkpointKey(inputs)}.json`);
  if (!existsSync(path)) return null;
  try {
    const saved = JSON.parse(readFileSync(path, 'utf8'));
    return JSON.stringify(saved.inputs) === JSON.stringify(inputs)
      && saved.result_sha256 === sha256(JSON.stringify(saved.result)) ? saved.result : null;
  } catch { return null; }
}

export function writeCheckpoint(root, inputs, result) {
  if (!root) return;
  mkdirSync(root, { recursive: true });
  const path = join(root, `${checkpointKey(inputs)}.json`);
  const staging = `${path}.${process.pid}.tmp`;
  writeFileSync(staging, JSON.stringify({ inputs, result, result_sha256: sha256(JSON.stringify(result)) }));
  renameSync(staging, path);
}

// Only a finished, fully covered outcome is kept: scored hits and misses, and
// cases whose fix changes no in-language source. Incomplete coverage,
// unfetchable or parentless cases, timeouts and errors are always rescanned.
const CHECKPOINT_STATUSES = new Set(['scored', 'no_old_side_source', 'no_in_language_source_change']);
export const checkpointable = row => CHECKPOINT_STATUSES.has(row.status)
  && (row.status === 'scored' ? ['hit', 'miss'].includes(row.outcome) : row.outcome === 'unknown');

// The scorer's own code is part of every checkpoint key.
let scorerFingerprint;
export function scorerSha256() {
  scorerFingerprint ??= caseDigest(['recall_harness.mjs', 'recall_coverage.mjs', 'recall_losses.mjs'].map(name =>
    packet(name, readFileSync(new URL(`./${name}`, import.meta.url)))));
  return scorerFingerprint;
}

// A saved row is reusable only while the captures and source packets it cites
// are still present in this work directory with the same bytes.
export function checkpointArtifactsIntact(workdir, row) {
  try {
    for (const side of ['old', 'fixed']) {
      const capture = row.captures?.[side];
      const packets = row.source_packets?.[side] ?? [];
      if (!capture) { if (packets.length) return false; continue; }
      for (const artifact of [capture.sarif, capture.native_report].filter(Boolean)) {
        if (sha256(readFileSync(resolve(workdir, artifact.path))) !== artifact.sha256) return false;
      }
      verifyPreparedBytes(resolve(workdir, capture.source_root), packets);
    }
    return true;
  } catch { return false; }
}

function readScoringManifest(path) {
  const bytes = readFileSync(path);
  const manifest = JSON.parse(utf8(bytes));
  return { path, cases: manifest.cases, casesSha256: validateRecallManifest(manifest), sha256: sha256(bytes) };
}

export async function scoreManifest(manifestPath, rulesPath, opts = {}, context = null) {
  return scorePreparedManifest(readScoringManifest(manifestPath), opts, context ?? scoringContext(opts, rulesPath));
}

async function scorePreparedManifest(manifest, opts, context) {
  const checkpoints = opts['checkpoint-dir'] ? resolve(opts['checkpoint-dir']) : null;
  const engine = context.engine ?? (checkpoints ? await bindRecallEngine(context.profile, context.bin) : null);
  if (engine) context.bin = engine.path;
  const verifyPins = async operation => {
    if (engine) await verifyBoundEngine(engine, operation);
    verifyRulesBytes(context);
  };
  await verifyPins('case scoring');
  mkdirSync(context.workdir, { recursive: true });
  context.scanRoot = mkdtempSync(join(context.workdir, 'scan-'));
  const one = async (row, scanContext = context) => {
    try { return { ...row, ...(await scoreOne(scanContext, row)) }; }
    catch (error) {
      if (error instanceof RecallInputDrift) throw error;
      return { ...row, status: 'error', detail: String(error.message).slice(-300) };
    }
  };
  const resumed = [];
  const checkpointed = async (row, staged) => {
    const inputs = { schema: 'factory.recall-case-checkpoint.v2', scorer_sha256: scorerSha256(),
      manifest_cases_sha256: manifest.casesSha256, case_sha256: caseDigest([row]), ruleset_sha256: context.rulesSha256,
      profile_sha256: context.profileSha256, engine_sha256: engine.receipt.executable_sha256,
      engine_args: context.extra, scope: context.scope };
    const saved = readCheckpoint(checkpoints, inputs);
    if (saved && checkpointable(saved) && checkpointArtifactsIntact(context.workdir, saved)) {
      resumed.push(row.ghsa);
      return saved;
    }
    const result = await one(row);
    if (checkpointable(result)) staged.push({ inputs, result });
    return result;
  };
  const jobs = Number(opts.jobs ?? 6);
  const rows = [];
  if (checkpoints) {
    // Publish only after the group still matches the inputs used in its keys.
    const groupSize = Math.max(16, jobs);
    for (let start = 0; start < manifest.cases.length; start += groupSize) {
      const staged = [];
      const group = manifest.cases.slice(start, start + groupSize);
      rows.push(...await pool(group, jobs, row => checkpointed(row, staged)));
      await verifyPins('case checkpoint');
      for (const { inputs, result } of staged) writeCheckpoint(checkpoints, inputs, result);
    }
  } else {
    rows.push(...await pool(manifest.cases, jobs, row => one(row)));
  }
  // Engine timeouts depend on machine load; repeat those cases one at a time
  // so a timeout is only recorded when it happens on an otherwise idle engine.
  let retried = false;
  for (let index = 0; index < rows.length; index++) {
    if (rows[index].outcome !== 'timeout') continue;
    retried = true;
    const initial = rows[index];
    const serial = { ...context, scanRoot: join(context.scanRoot, 'serial') };
    rows[index] = { ...(await one(manifest.cases[index], serial)), retried_serially: true,
      initial_scan_sides: initial.scan_sides, initial_captures: initial.captures };
  }
  if (!checkpoints || retried) await verifyPins('case scoring');
  return { schema: 'factory.recall-result.v1', manifest: manifest.path, manifest_cases_sha256: manifest.casesSha256,
    manifest_sha256: manifest.sha256, ruleset_sha256: context.rulesSha256, profile_sha256: context.profileSha256,
    scope: context.scope, engine_args: context.extra,
    scan_directory: basename(context.scanRoot),
    ...(checkpoints ? { resumed_cases: resumed.sort() } : {}),
    argv: profileArgv(context.profile, { bin: context.bin, rules: '{rules}', report: '{report}', source: '{source}', extra: context.extra }),
    summary: summarize(rows), cases: rows };
}

async function score(opts) {
  const context = scoringContext(opts, opts.rules);
  const engine = await bindRecallEngine(context.profile, context.bin);
  context.engine = engine;
  const out = await scoreManifest(opts.manifest, opts.rules, opts, context);
  await verifyBoundEngine(engine, 'scoring');
  writeFileSync(opts.out, `${JSON.stringify({ ...out, engine: engine.receipt }, null, 1)}\n`);
  console.log(JSON.stringify(out.summary, null, 1));
}

// Accept/reject gates for one candidate ruleset against a baseline.
function measuredOutcome(row) {
  return row.status ? outcomeOf(row) : row.hunk_hit ? 'hit' : 'miss';
}

function caseInputFingerprint(row) {
  return caseDigest([row.revisions ?? null, row.diff_sha256 ?? null, row.source_packets ?? null,
    row.changed_files_sha256 ?? null]);
}

function sameAdjudicationScope(result, evidence) {
  return ['manifest_sha256', 'manifest_cases_sha256', 'profile_sha256']
    .every(name => result[name] === evidence[name]);
}

function completeCandidateMiss(row) {
  return row.status === 'scored' && measuredOutcome(row) === 'miss'
    && Array.isArray(row.file_coverage?.old) && Array.isArray(row.file_coverage?.fixed)
    && !coverageGaps(row.file_coverage.fixed).length;
}

function adjudicatedFpMiss(policy, before, old, after, row) {
  const known = policy?.cases.get(old.ghsa);
  if (!known || !completeCandidateMiss(row)) return false;
  const evidence = policy.receipt;
  if (before.ruleset_sha256 !== evidence.ruleset_sha256) return false;
  if (JSON.stringify(before.engine_args ?? []) !== JSON.stringify(evidence.engine_args)) return false;
  if (!sameAdjudicationScope(before, evidence) || !sameAdjudicationScope(after, evidence)) return false;
  const input = caseInputFingerprint(known.source);
  return caseInputFingerprint(old) === input && caseInputFingerprint(row) === input
    && hunkAdjudicationIdentity(old, known.spanBound) === known.identity;
}

function recordLostHit(changes, pair, old, row) {
  const target = adjudicatedFpMiss(changes.lossPolicy, pair.before, old, pair.after, row)
    ? changes.lostFpOnly : changes.lost;
  target.push(row.ghsa);
  changes.rawLost.push(row.ghsa);
}

function hasNewCoverageGaps(old, row) {
  return Object.entries(old.file_coverage ?? {}).some(([side, files]) => {
    const previous = new Set(coverageGaps(files));
    const confirmedLimits = new Set(row.parser_probe?.[side]?.confirmed_limits);
    return coverageGaps(row.file_coverage?.[side]).some(path => !previous.has(path) && !confirmedLimits.has(path));
  });
}

const PARSER_LANGUAGE = { c: 'c', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp', cs: 'csharp',
  go: 'go', java: 'java', js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  php: 'php', py: 'python', pyi: 'python', rb: 'ruby', rs: 'rust', swift: 'swift',
  ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript' };

function newParsePaths(before, after, side) {
  const known = new Set(coverageGaps(before.file_coverage?.[side]));
  return (after.file_coverage?.[side] ?? []).filter(file => file.state === 'partial' && file.reason === 'parse' && !known.has(file.path))
    .map(file => file.path);
}

async function probeCoverage(dev, opts) {
  const workdir = resolve(opts.workdir ?? '.factory/recall-work');
  const profile = JSON.parse(utf8(opts.profileBytes));
  if (profile.engine !== 'semgrep') throw new Error('Fixed parser probe requires an OpenGrep profile');
  const prefix = [profile.commands[0].argv[1], '--dump-ast', '--json', '--disable-version-check'];
  for (const { before, after } of dev) {
    const baseline = indexCases(before.cases);
    await pool(after.cases, Number(opts.jobs ?? 6), async row => {
      const old = baseline.get(row.ghsa);
      if (!old || caseInputFingerprint(old) !== caseInputFingerprint(row)) return;
      for (const side of ['old', 'fixed']) {
        const paths = newParsePaths(old, row, side);
        if (!paths.length || !row.captures?.[side]) continue;
        const source = resolve(workdir, row.captures[side].source_root);
        const packets = row.source_packets[side];
        const packetsByPath = new Map(packets.map(packet => [packet.path, packet]));
        verifyPreparedBytes(source, packets);
        const observations = [];
        for (const path of paths) {
          const language = PARSER_LANGUAGE[extname(path).slice(1).toLowerCase()];
          const packet = packetsByPath.get(path);
          if (!language || !packet) continue;
          const run = await runProcess(opts.opengrep, [...prefix, '--lang', language, join(source, path)],
            { cwd: source, timeout: 60000, discardStdout: true });
          const partial = run.status === 3 && /node type: ERROR|(?:syntax|parse) error|PartialParsing/i.test(run.stderr);
          observations.push({ path, language, sha256: packet.sha256,
            exit_code: run.status, timed_out: run.timedOut, diagnostic_sha256: sha256(run.stderr),
            state: run.timedOut ? 'unresolved' : partial ? 'parse_limited' : run.status === 0 ? 'parsed' : 'unresolved' });
        }
        verifyPreparedBytes(source, packets);
        row.parser_probe ??= {};
        row.parser_probe[side] = { disputed_paths: paths, observations,
          confirmed_limits: observations.filter(item => item.state === 'parse_limited').map(item => item.path) };
      }
    });
  }
  return { method: 'opengrep_dump_ast_v1', profile_sha256: sha256(opts.profileBytes), options: prefix.slice(1) };
}

const duplicateAdvisory = ghsa => 'Duplicate advisory ID across paired recall cohorts: ' + ghsa;

function measureCaseChange(old, row, pair, changes) {
  const { gained, newErrors, newCoverageGaps, failures, seenAdvisories } = changes;
  if (seenAdvisories.has(row.ghsa)) {
    failures.push(duplicateAdvisory(row.ghsa));
    return;
  }
  seenAdvisories.add(row.ghsa);
  if (caseInputFingerprint(old) !== caseInputFingerprint(row)) {
    failures.push('Baseline and candidate source byte fingerprints differ for ' + row.ghsa);
    return;
  }
  const previous = measuredOutcome(old), current = measuredOutcome(row);
  if (previous === 'hit' && current !== 'hit') recordLostHit(changes, pair, old, row);
  if (previous === 'miss' && current === 'hit') gained.push(row.ghsa);
  const failure = ['error', 'timeout'];
  if (failure.includes(current) && !failure.includes(previous)) newErrors.push(row.ghsa);
  if (hasNewCoverageGaps(old, row)) newCoverageGaps.push(row.ghsa);
}

const indexCases = rows => new Map(rows.map(row => [row.ghsa, row]));

function measureDevPair({ before, after }, changes) {
  if (before.manifest_sha256 !== after.manifest_sha256 || before.profile_sha256 !== after.profile_sha256
      || before.scope !== after.scope) {
    changes.failures.push('Baseline and candidate manifest, profile or scoring scope differs');
    return;
  }
  const baseline = indexCases(before.cases), candidate = indexCases(after.cases);
  if (baseline.size !== before.cases.length || candidate.size !== after.cases.length) {
    changes.failures.push('Duplicate advisory ID in paired recall cases');
    return;
  }
  for (const [ghsa, old] of baseline) {
    const row = candidate.get(ghsa);
    if (!row) changes.failures.push('Candidate case missing for ' + ghsa);
    else measureCaseChange(old, row, { before, after }, changes);
  }
  for (const ghsa of candidate.keys()) {
    if (!baseline.has(ghsa)) changes.failures.push('Baseline case missing for ' + ghsa);
  }
}

export function gate({ dev, controls, maxControlIncrease = 0, residualTolerance = 0.1, lossPolicy = null }) {
  const lost = [], gained = [], newErrors = [], newCoverageGaps = [], failures = [], lostFpOnly = [], rawLost = [];
  const changes = { lost, gained, newErrors, newCoverageGaps, failures, lossPolicy, lostFpOnly, rawLost, seenAdvisories: new Set() };
  for (const pair of dev) measureDevPair(pair, changes);
  const residualBefore = dev.reduce((n, pair) => n + pair.before.summary.fix_side_residual_alerts, 0);
  const residualAfter = dev.reduce((n, pair) => n + pair.after.summary.fix_side_residual_alerts, 0);
  const controlIncrease = controls.reduce((n, delta) => n + (delta.after ?? 0) - (delta.before ?? 0), 0);
  if (newErrors.length) failures.push(`new engine errors/timeouts: ${newErrors.join(', ')}`);
  if (lost.length) failures.push(`lost ${lost.length} dev hit(s): ${lost.join(', ')}`);
  if (newCoverageGaps.length) failures.push(`new engine coverage gaps: ${newCoverageGaps.join(', ')}`);
  // Residuals are judged per strict hit: a rule that finds more fixes also sees
  // more fixed code it cannot prove safe. The rate may not rise by more than
  // residualTolerance (default 10%).
  const hitsBefore = dev.reduce((n, pair) => n + pair.before.summary.hunk_hits, 0);
  const hitsAfter = dev.reduce((n, pair) => n + pair.after.summary.hunk_hits, 0);
  const rateBefore = residualBefore / Math.max(hitsBefore, 1), rateAfter = residualAfter / Math.max(hitsAfter, 1);
  if (rateAfter > rateBefore * (1 + residualTolerance)) {
    failures.push(`fix-side residuals per hit ${rateBefore.toFixed(2)} -> ${rateAfter.toFixed(2)} (${residualBefore} -> ${residualAfter})`);
  }
  if (controlIncrease > maxControlIncrease) failures.push(`control alerts +${controlIncrease} > ${maxControlIncrease}`);
  if (controls.some(delta => delta.error || delta.incomplete_on_both)) failures.push('a control scan failed');
  return { decision: failures.length ? 'REJECT' : 'ACCEPT', failures, gained, lost_baseline_hits: lost, new_errors: newErrors,
    ...(lossPolicy ? { lost_fp_only: lostFpOnly, raw_lost_baseline_hits: rawLost,
      adjudicated_loss_basis: lossPolicy.receipt } : {}),
    new_coverage_gaps: newCoverageGaps,
    residual: [residualBefore, residualAfter], residual_per_hit: [rateBefore, rateAfter].map(x => Math.round(x * 100) / 100),
    control_increase: controlIncrease };
}

function evaluationEvidence(result) {
  return { manifest_sha256: result.manifest_sha256, cases_sha256: result.manifest_cases_sha256,
    profile_sha256: result.profile_sha256, ruleset_sha256: result.ruleset_sha256, scan_directory: result.scan_directory,
    cases: result.cases.map(({ ghsa, revisions, source_packets, diff_sha256, changed_files_sha256, file_coverage,
      scan_sides, initial_scan_sides, captures, initial_captures, parser_probe, retried_serially, outcome, status }) =>
      ({ ghsa, revisions, source_packets, diff_sha256, changed_files_sha256,
        file_coverage, scan_sides, initial_scan_sides, captures, initial_captures, parser_probe, retried_serially, outcome, status })) };
}

function pairedCaseEvidence({ before, after }) {
  const baseline = indexCases(before.cases);
  return after.cases.map(row => {
    const previous = baseline.get(row.ghsa);
    return { ghsa: row.ghsa, fix: row.fix, before: previous?.outcome ?? previous?.status ?? null,
      after: row.outcome ?? row.status, hunk_findings: row.hunk_findings ?? [],
      ...(row.hunk_spans ? { hunk_spans: row.hunk_spans } : {}),
      matched_hunk_families: row.matched_hunk_families ?? [], fix_side_residual: row.fix_side_residual ?? [],
      retried_serially: Boolean(row.retried_serially) };
  });
}

function executablePath(command) {
  const directories = /[\\/]/.test(command) ? [''] : (process.env.PATH ?? '/usr/bin:/bin').split(delimiter);
  const suffixes = process.platform === 'win32' && !extname(command) ? ['.exe', '.com', ''] : [''];
  for (const directory of directories) {
    for (const suffix of suffixes) {
      try {
        const path = realpathSync(resolve(directory, command + suffix));
        accessSync(path, constants.X_OK);
        if (statSync(path).isFile()) return path;
      } catch (error) {
        if (!['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'].includes(error.code)) throw error;
      }
    }
  }
  throw new Error('Recall engine executable could not be resolved');
}

async function fileFingerprint(path) {
  const digest = createHash('sha256');
  for await (const bytes of createReadStream(path)) digest.update(bytes);
  return digest.digest('hex');
}

async function bindRecallEngine(profile, command) {
  const path = executablePath(command);
  const executable_sha256 = await fileFingerprint(path);
  const args = profile.version_argv?.slice(1) ?? ['--version'];
  const probe = await runProcess(path, args, { timeout: 30000 });
  const version = probe.stdout.trim();
  if (probe.status !== 0 || !/^[^\r\n]{1,128}$/.test(version)) throw new Error('Recall engine version probe failed');
  if (profile.tool_version && version !== profile.tool_version) throw new Error('Recall engine version differs from profile');
  return { path, receipt: { executable: basename(path), executable_sha256, version } };
}

async function verifyBoundEngine(engine, operation) {
  if (await fileFingerprint(engine.path) !== engine.receipt.executable_sha256) {
    throw new RecallInputDrift(`Recall engine executable bytes changed during ${operation}`);
  }
}

function evaluationRules(opts) {
  return { baseline_sha256: sha256(readFileSync(opts.baseline)), candidate_sha256: sha256(readFileSync(opts.candidate)) };
}

function verifyEvaluationRules(opts, expected) {
  const actual = evaluationRules(opts);
  if (actual.baseline_sha256 !== expected.baseline_sha256 || actual.candidate_sha256 !== expected.candidate_sha256) {
    throw new RecallInputDrift('Evaluation ruleset bytes changed during scoring');
  }
}

function recordedGainsIn(block, required, engineArgs) {
  const cohort = block.manifest_cases_sha256;
  if (!/^[a-f0-9]{64}$/.test(cohort)) throw new Error('Invalid recall gain checkpoint manifest');
  const evidence = indexCases(block.after_evidence.cases);
  return block.cases.filter(row => required.has(row.ghsa) && row.before === 'miss' && row.after === 'hit')
    .map(row => {
      const source = evidence.get(row.ghsa);
      if (!source?.revisions || !source.source_packets) throw new Error('Recall gain checkpoint is missing case input evidence');
      return [row.ghsa, { cohort, input: caseInputFingerprint(source),
        prior: { ...source, hunk_findings: row.hunk_findings, hunk_spans: row.hunk_spans },
        scope: { manifest_cases_sha256: cohort, manifest_sha256: block.after_evidence.manifest_sha256,
          profile_sha256: block.after_evidence.profile_sha256, ruleset_sha256: block.after_evidence.ruleset_sha256,
          engine_args: engineArgs } }];
    });
}

function recordedGains(reference) {
  if (reference?.schema !== 'factory.recall-evaluation.v1' || !Array.isArray(reference.gained)
      || !reference.gained.length || !Array.isArray(reference.dev)) throw new Error('Invalid recall gain checkpoint');
  const required = new Set(reference.gained);
  const engineArgs = [].concat(reference.extra_args ?? [], reference.candidate_extra_args ?? []);
  const entries = reference.dev.flatMap(block => recordedGainsIn(block, required, engineArgs));
  const records = new Map(entries);
  if (records.size !== entries.length || records.size !== reference.gained.length) {
    throw new Error('Recall gain checkpoint membership differs');
  }
  return records;
}

export function gainRetention(reference, pairs, lossPolicy = null) {
  const required = recordedGains(reference);
  const candidate = new Map(pairs.map(({ after }) => [after.manifest_cases_sha256, { after, cases: indexCases(after.cases) }]));
  if (candidate.size !== pairs.length) throw new Error('Duplicate manifest in recall gain replay');
  const lost = [], fpOnly = [];
  for (const [id, { cohort, input, prior, scope }] of required) {
    const entry = candidate.get(cohort), row = entry?.cases.get(id);
    if (row && measuredOutcome(row) === 'hit' && caseInputFingerprint(row) === input) continue;
    if (row && adjudicatedFpMiss(lossPolicy, scope, prior, entry.after, row)) fpOnly.push(id);
    else lost.push(id);
  }
  return { required: required.size, retained: required.size - lost.length - fpOnly.length, lost: lost.sort(),
    ...(lossPolicy ? { lost_fp_only: fpOnly.sort() } : {}) };
}

function applyGainRetention(verdict, bytes, pairs, lossPolicy) {
  const compatible = lossPolicy?.receipt.score_sha256 === sha256(bytes) ? lossPolicy : null;
  const retention = gainRetention(JSON.parse(utf8(bytes)), pairs, compatible);
  verdict.gain_retention = { checkpoint_sha256: sha256(bytes), ...retention };
  if (retention.lost.length) verdict.failures.push(`lost ${retention.lost.length} checkpoint hit(s): ${retention.lost.join(', ')}`);
}

function suppliedLabels(opts) {
  if (!opts.labels) return null;
  if (!opts.dir) throw new Error('Control directories are required when reviewing labels');
  const labels = JSON.parse(utf8(readFileSync(opts.labels)));
  if (!Array.isArray(labels?.labels)) throw new Error('Invalid control label sheet');
  return labels;
}

function precisionState(controls, review) {
  if (!controls.length) return 'not_run';
  if (controls.some(delta => delta.error || delta.incomplete_on_both)) return 'incomplete';
  if (!review.emitted) return 'no_alerts';
  if (!review.judged) return 'unreviewed';
  return review.unreviewed_emitted || review.ambiguous_labels.length ? 'partially_reviewed' : 'reviewed';
}

function precisionEvidence(verdict, labels, controls, population, requireReviewed) {
  const review = checkLabels(labels, controls);
  const state = precisionState(controls, review);
  const populationBound = labels?.control_population_sha256 === population;
  if (requireReviewed && (state !== 'reviewed' || !populationBound)) {
    verdict.failures.push('complete source-bound control review required (' + state + ')');
  }
  if (labels) {
    verdict.labels = review;
    if (review.fp_returned.length) verdict.failures.push(`labeled false positives emitted again: ${review.fp_returned.length}`);
    if (review.tp_dropped.length) verdict.failures.push(`labeled true positives no longer emitted: ${review.tp_dropped.length}`);
    if (review.ambiguous_labels.length) verdict.failures.push(`ambiguous control label matches: ${review.ambiguous_labels.length}`);
  }
  return { state, emitted: review.emitted, adjudicated: review.judged,
    unreviewed: review.unreviewed_emitted, population_bound: populationBound,
    review_independence: 'unestablished' };
}

function reviewPopulation(context, deltas) {
  return caseDigest([{ ...context, controls: deltas.map(delta => ({
    dir: delta.dir, source_tree: delta.source_tree ?? null, coverage: [
      delta.scan_sides?.before?.control_coverage ?? null, delta.scan_sides?.after?.control_coverage ?? null,
    ], emitted: (delta.emitted ?? []).map(alert => labelKey(repoName(delta.dir), alert)).sort(),
  })) }]);
}

function readEvaluationManifests(paths) {
  const seen = new Set();
  return [].concat(paths).map(path => {
    const manifest = readScoringManifest(path);
    for (const { ghsa } of manifest.cases) {
      if (seen.has(ghsa)) throw new Error(duplicateAdvisory(ghsa));
      seen.add(ghsa);
    }
    return manifest;
  });
}

function verifyEvaluationManifests(manifests) {
  for (const { path, sha256: expected } of manifests) {
    if (sha256(readFileSync(path)) !== expected) throw new Error('Evaluation manifest bytes changed during scoring');
  }
}

async function evaluate(input) {
  const opts = { ...input, profileBytes: input.profileBytes
    ?? readFileSync(input.profile ?? 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json') };
  const checkpoint = opts['retain-gains-from'] ? readFileSync(opts['retain-gains-from']) : null;
  const excludedDirs = controlExcludedDirectories(opts);
  const labels = suppliedLabels(opts);
  const reviewOption = opts['require-reviewed-controls'];
  if (reviewOption !== undefined && reviewOption !== 'true') {
    throw new Error('--require-reviewed-controls accepts true');
  }
  const manifests = readEvaluationManifests(opts.manifest);
  const engine = await bindRecallEngine(JSON.parse(utf8(opts.profileBytes)),
    opts.opengrep ?? process.env.OPENGREP ?? 'opengrep');
  const lossPolicy = opts['adjudicated-losses']
    ? loadAdjudicatedLosses(opts['adjudicated-losses'], engine.receipt.executable_sha256) : null;
  opts.opengrep = engine.path;
  const rules = evaluationRules(opts);
  // A flag under test (for example --taint-intrafile) applies to the candidate only.
  const candidateOpts = { ...opts, 'extra-arg': [].concat(opts['extra-arg'] ?? [], opts['candidate-extra-arg'] ?? []) };
  if (opts['probe-coverage'] !== undefined && !['true', 'false'].includes(opts['probe-coverage'])) {
    throw new Error('--probe-coverage requires true or false');
  }
  const scoreArm = (manifest, path, settings, expectedRules) => {
    const context = scoringContext(settings, path);
    if (context.rulesSha256 !== expectedRules) throw new RecallInputDrift('Evaluation ruleset bytes changed during scoring');
    return scorePreparedManifest(manifest, settings, { ...context, engine });
  };
  const dev = [];
  for (const manifest of manifests) {
    const before = await scoreArm(manifest, opts.baseline, opts, rules.baseline_sha256);
    const after = await scoreArm(manifest, opts.candidate, candidateOpts, rules.candidate_sha256);
    dev.push({ manifest: manifest.path, before, after });
  }
  const controlDeltas = opts.dir ? await controlDeltas_({ ...opts, rules: [opts.baseline, opts.candidate], ruleFingerprints: rules }, engine) : [];
  const parserProbe = opts['probe-coverage'] === 'true' ? await probeCoverage(dev, opts) : null;
  await verifyBoundEngine(engine, 'evaluation');
  verifyEvaluationManifests(manifests);
  verifyEvaluationRules(opts, rules);
  const verdict = gate({ dev, controls: controlDeltas, maxControlIncrease: Number(opts['max-control-increase'] ?? 0), lossPolicy });
  if (checkpoint) applyGainRetention(verdict, checkpoint, dev, lossPolicy);
  const settings = { ...rules, engine: engine.receipt, profile_sha256: sha256(opts.profileBytes),
    extra_args: [].concat(opts['extra-arg'] ?? []), candidate_extra_args: [].concat(opts['candidate-extra-arg'] ?? []),
    ...(excludedDirs.length ? { control_excluded_directories: excludedDirs } : {}) };
  const population = reviewPopulation(settings, controlDeltas);
  const requireReviewed = reviewOption === 'true';
  verdict.precision_evidence = precisionEvidence(verdict, labels, controlDeltas, population, requireReviewed);
  verdict.decision = verdict.failures.length ? 'REJECT' : 'ACCEPT';
  const out = { schema: 'factory.recall-evaluation.v1', ...settings, ...verdict,
    parser_probe: parserProbe,
    decision_scope: requireReviewed ? 'reviewed_development_controls' : 'development',
    control_population_sha256: population,
    dev: dev.map(pair => ({ manifest: pair.manifest, manifest_cases_sha256: pair.after.manifest_cases_sha256,
      before: pair.before.summary, after: pair.after.summary,
      before_evidence: evaluationEvidence(pair.before), after_evidence: evaluationEvidence(pair.after),
      cases: pairedCaseEvidence(pair) })),
    controls: controlDeltas.map(({ emitted, ...delta }) => emitted ? {
      ...delta, emitted: emitted.map(({ snippet, ...finding }) => ({ ...finding, snippet_sha256: sha256(snippet ?? '') })),
    } : delta) };
  writeFileSync(opts.out, `${JSON.stringify(out, null, 1)}\n`);
  console.log(out.decision, out.failures, `gained ${out.gained.length}`, `controls +${out.control_increase}`);
  if (out.decision === 'REJECT') process.exitCode = 2;
}

const CONTROL_TIMEOUT_RETRY_SECONDS = 15;
const OPENGREP_DEFAULT_TARGET_BYTES = 1_000_000;
const CONTROL_SOURCE_MAX_BYTES = 2 * 1024 * 1024;
const CONTROL_HASH_BATCH_SIZE = 16;

function controlTargetBytes(directory, source, base, candidate) {
  if (base.profile.engine !== 'semgrep') return null;
  const argv = [...base.profile.commands[0].argv, ...base.extra, ...candidate.extra];
  if (argv.some(arg => /^--max-target-bytes(?:=|$)/.test(arg))) return null;
  // Match the existing source-evidence envelope for bounded local files.
  const largest = source.eligible.reduce((limit, path) => {
    const bytes = statSync(join(directory, path)).size;
    return bytes <= CONTROL_SOURCE_MAX_BYTES && bytes > limit ? bytes : limit;
  }, OPENGREP_DEFAULT_TARGET_BYTES);
  return largest > OPENGREP_DEFAULT_TARGET_BYTES ? largest : null;
}

function controlRetryArgs(profile, baselineArgs, candidateArgs) {
  const hasTimeoutOverride = [...profile.commands[0].argv, ...baselineArgs, ...candidateArgs]
    .some(arg => /^--(?:timeout(?:=|$)|dynamic-timeout|allow-rule-timeout-control)/.test(arg));
  return profile.engine === 'semgrep' && !hasTimeoutOverride ? [`--timeout=${CONTROL_TIMEOUT_RETRY_SECONDS}`] : [];
}

function insideControl(root, path) {
  const local = relative(root, path);
  return !isAbsolute(local) && local !== '..' && !local.startsWith(`..${sep}`);
}

function controlSourceExtension(path) {
  return SCANNABLE_EXTENSIONS.includes(extname(path).slice(1).toLowerCase());
}

function controlLinkTarget(root, target) {
  const parts = relative(root, target).split(sep);
  if (!insideControl(root, target) || parts.includes('.git')) {
    throw new Error('Control source link leaves the source tree');
  }
  return parts.join('/');
}

function controlLink(root, location, eligible) {
  const link = readlinkSync(location);
  const target = isAbsolute(link) ? link : `${dirname(location)}${sep}${link}`;
  controlLinkTarget(root, resolve(target));
  try {
    return { link_target: controlLinkTarget(root, realpathSync.native(location)) };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    if (eligible) throw new Error('Dangling control link occupies an eligible source path');
    // Only record a missing final component with a resolvable in-tree parent.
    const parent = realpathSync.native(dirname(target));
    controlLinkTarget(root, parent);
    const missing = join(parent, basename(target));
    if (lstatSync(missing, { throwIfNoEntry: false })) throw error;
    return { link_target: controlLinkTarget(root, missing), link_state: 'dangling' };
  }
}

async function controlSource(root, excludedDirs) {
  const files = [];
  const pending = [];
  const hashBatch = async () => {
    files.push(...await Promise.all(pending.splice(0).map(async ({ path, location }) => ({
      path, sha256: await fileFingerprint(location),
    }))));
  };
  const exclusionReason = path => {
    if (path.split('/').slice(0, -1).some(part => excludedDirs.includes(part))) return 'declared_control_exclusion';
    if (isTestPath(path) || path.endsWith('_spec.rb')) return 'test_path';
    return null;
  };
  const visit = async (directory, prefix) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === '.git') continue;
      const location = join(directory, entry.name), path = prefix + entry.name;
      if (entry.isDirectory()) {
        await visit(location, path + '/');
      } else if (entry.isFile()) {
        pending.push({ path, location });
        if (pending.length === CONTROL_HASH_BATCH_SIZE) await hashBatch();
      } else if (entry.isSymbolicLink()) {
        files.push({ path, ...controlLink(root, location, controlSourceExtension(path) && !exclusionReason(path)) });
      } else {
        throw new Error('Unsupported entry in control source tree');
      }
    }
  };
  await visit(root, '');
  if (pending.length) await hashBatch();
  const supported = files.filter(file => file.sha256 && controlSourceExtension(file.path));
  const excluded = new Map(supported.map(({ path }) => [path, exclusionReason(path)])
    .filter(([, reason]) => reason));
  return { paths: new Set(files.map(file => file.path)), hashes: new Map(files.map(file => [file.path, file.sha256])),
    eligible: supported.map(file => file.path).filter(path => !excluded.has(path)).sort(), excluded, excludedDirs,
    evidence: { sha256: caseDigest(files.sort(byPath)), entries: files.length } };
}

function controlScanCoverage(eligible, engine) {
  const gaps = [];
  for (const path of eligible) {
    const reason = !engine ? 'missing_engine_coverage' : engine.problems.get(path)
      ?? (engine.skipped.has(path) ? engine.skipped.get(path) ?? 'engine_reported_skip' : null)
      ?? (engine.scanned.has(path) ? null : 'absent_from_engine_paths');
    if (reason) gaps.push({ path, reason });
  }
  return { complete: eligible.length > 0 && !gaps.length,
    expected: eligible.length, reported: eligible.length - gaps.length, gaps };
}

async function controlObservation(context, directory, report, source) {
  let notes, coverage, findings = [];
  try {
    if (context.rulesSha256) verifyRulesBytes(context);
    findings = await scan({ ...context, packetPaths: source.paths }, directory, report, true);
    notes = findings.notes;
    coverage = findings.coverage;
    if (context.rulesSha256) verifyRulesBytes(context);
    if (findings.some(finding => !source.paths.has(finding.path))) {
      throw new Error('Control finding path is absent from the source tree');
    }
    if (findings.some(finding => source.excluded.get(finding.path) === 'declared_control_exclusion')) {
      throw new Error('Scanner emitted findings outside the declared control scope');
    }
    const eligibleFindings = findings.filter(finding => !source.excluded.has(finding.path));
    if (eligibleFindings.length !== findings.length) notes.excluded_test_findings = findings.length - eligibleFindings.length;
    findings = eligibleFindings;
  } catch (error) {
    if (error instanceof RecallInputDrift) throw error;
    findings = [];
    notes = { ...(notes ?? error.diagnostics), other: 1, detail: String(error.message).slice(-300) };
  }
  notes.reports = reportReferences(context, report, notes);
  try {
    if ((await controlSource(directory, source.excludedDirs)).evidence.sha256 !== source.evidence.sha256) {
      throw new Error('Control source byte fingerprints differ');
    }
  } catch (error) {
    return { findings: [], notes: { ...notes, other: 1, source_error: String(error.message).slice(-300) }, sourceInvalid: true };
  }
  return { findings, notes, coverage };
}

function pairedControlScope(source, sides) {
  const exclusions = new Map(source.excluded);
  if (sides.every(side => side.coverage && !side.sourceInvalid && !scanIssue(side.notes))) {
    const reported = new Set(sides.flatMap(side => side.findings.map(finding => finding.path)));
    for (const path of source.eligible) {
      const agreed = sides.every(({ coverage }) => coverage.skipped.get(path) === 'semgrepignore_patterns_match'
        && !coverage.scanned.has(path) && !coverage.problems.has(path));
      if (agreed && !reported.has(path)) exclusions.set(path, 'shared_semgrepignore_patterns_match');
    }
  }
  const eligible = source.eligible.filter(path => !exclusions.has(path));
  const excluded = [...exclusions].map(([path, reason]) => ({ path, reason })).sort(byPath);
  return { eligible, excluded, sha256: caseDigest([{ source_sha256: source.evidence.sha256, eligible, excluded }]) };
}

function recordControlCoverage(side, scope) {
  if (!side.notes) return;
  const coverage = controlScanCoverage(scope.eligible, side.coverage);
  if (scope.excluded.length) coverage.excluded = scope.excluded;
  side.notes.control_coverage = coverage;
  if (!coverage.complete && !scanIssue(side.notes)) {
    side.notes.other = 1;
    side.notes.detail = 'Control scan must cover every eligible source file';
  }
}

async function controlPair({ base, candidate, directory, reports, source, workdir }, suffix, retryArgs = []) {
  const old = await controlObservation({ ...base, workdir, extra: [...base.extra, ...retryArgs] }, directory, `${reports}/before${suffix}.sarif`, source);
  const now = old.sourceInvalid ? { findings: [], notes: null }
    : await controlObservation({ ...candidate, workdir, extra: [...candidate.extra, ...retryArgs] }, directory, `${reports}/after${suffix}.sarif`, source);
  const scope = pairedControlScope(source, [old, now]);
  for (const side of [old, now]) recordControlCoverage(side, scope);
  const scan_sides = { before: old.notes, after: now.notes };
  const issues = [old, now].map(side => side.sourceInvalid ? 'error' : scanIssue(side.notes));
  return { old: old.findings, now: now.findings, scan_sides, issues, control_scope_sha256: scope.sha256 };
}

function controlFindingIndex(findings) {
  const bySpan = new Map(findings.map(finding => [
    JSON.stringify([finding.rule, finding.path, finding.line, finding.span ?? null]), finding,
  ]));
  if (bySpan.size !== findings.length) throw new Error('Duplicate scanner span in precision controls');
  return bySpan;
}

export function controlFindingDeltas(before, after) {
  const old = controlFindingIndex(before), now = controlFindingIndex(after);
  const onlyIn = (left, right) => [...left.entries()].filter(([key]) => !right.has(key)).map(([, finding]) => finding);
  return { added: onlyIn(now, old), removed: onlyIn(old, now) };
}

function controlExcludedDirectories(opts) {
  const excludedDirs = [...new Set([].concat(opts['control-exclude'] ?? []))].sort();
  if (excludedDirs.some(path => typeof path !== 'string' || !/^[\w-][\w.-]*$/.test(path))) {
    throw new Error('--control-exclude requires a single directory name');
  }
  return excludedDirs;
}

async function retainedReportMatches(root, reference, expected, required) {
  if (!expected) return !required && !reference;
  if (reference?.sha256 !== expected || typeof reference.path !== 'string' || isAbsolute(reference.path)) return false;
  const path = resolve(root, reference.path);
  if (!insideControl(root, path)) return false;
  const canonical = realpathSync(path);
  return insideControl(root, canonical) && statSync(canonical).isFile() && await fileFingerprint(canonical) === expected;
}

async function controlReportsIntact(root, notes, required) {
  if (!notes) return !required;
  if (required && !notes.control_coverage?.complete) return false;
  const matches = await Promise.all([
    retainedReportMatches(root, notes.reports?.sarif, notes.report_sha256, required),
    retainedReportMatches(root, notes.reports?.native_report, notes.coverage_report_sha256, required),
  ]);
  return matches.every(Boolean);
}

async function controlCheckpointIntact(root, delta) {
  if (delta.error) return false;
  try {
    const matches = await Promise.all(['before', 'after'].flatMap(side => [
      controlReportsIntact(root, delta.scan_sides?.[side], true),
      controlReportsIntact(root, delta.initial_scan_sides?.[side], false),
    ]));
    return matches.every(Boolean);
  } catch { return false; }
}

async function controlDeltas_(opts, engine) {
  const [before, after] = [].concat(opts.rules);
  const excludedDirs = controlExcludedDirectories(opts);
  const exclusionArgs = excludedDirs.flatMap(path => ['--exclude', `${path}/**`, '--exclude', `**/${path}/**`]);
  const rules = opts.ruleFingerprints;
  const base = { profile: JSON.parse(utf8(opts.profileBytes)),
    bin: engine.path, extra: [].concat(opts['extra-arg'] ?? [], exclusionArgs),
    rules: resolve(before), rulesSha256: rules.baseline_sha256 };
  const candidate = { ...base, extra: [...base.extra, ...[].concat(opts['candidate-extra-arg'] ?? [])],
    rules: resolve(after), rulesSha256: rules.candidate_sha256 };
  const checkpointProfile = sha256(Buffer.from(JSON.stringify(base.profile)));
  const deltas = [];
  const workdir = resolve(opts.workdir ?? '.factory/recall-work');
  let scanRoot;
  for (const dir of [].concat(opts.dir)) {
    try {
      const directory = realpathSync(resolve(dir));
      if (insideControl(directory, workdir)) throw new Error('Control scan reports must be outside the source tree');
      mkdirSync(workdir, { recursive: true });
      const reportsRoot = realpathSync(workdir);
      if (insideControl(directory, reportsRoot)) throw new Error('Control scan reports must be outside the source tree');
      const source = await controlSource(directory, excludedDirs);
      const maxTargetBytes = controlTargetBytes(directory, source, base, candidate);
      const targetArgs = maxTargetBytes ? [`--max-target-bytes=${maxTargetBytes}`] : [];
      const effectiveBase = { ...base, extra: [...base.extra, ...targetArgs] };
      const effectiveCandidate = { ...candidate, extra: [...candidate.extra, ...targetArgs] };
      const checkpointInputs = opts['checkpoint-dir'] ? { schema: 'factory.recall-control-checkpoint.v3',
        scorer_sha256: scorerSha256(), dir,
        source_tree: source.evidence, excluded: excludedDirs, ...rules,
        profile_sha256: checkpointProfile,
        engine_sha256: engine.receipt.executable_sha256, extra: effectiveBase.extra,
        candidate_extra: effectiveCandidate.extra } : null;
      const savedDelta = checkpointInputs && readCheckpoint(resolve(opts['checkpoint-dir']), checkpointInputs);
      if (savedDelta && await controlCheckpointIntact(reportsRoot, savedDelta)) {
        deltas.push({ ...savedDelta, resumed_from_checkpoint: true });
        continue;
      }
      scanRoot ??= mkdtempSync(join(reportsRoot, 'controls-'));
      const context = { base: effectiveBase, candidate: effectiveCandidate, directory, source,
        workdir: reportsRoot, reports: join(scanRoot, sha256(directory).slice(0, 16)) };
      let attempt = await controlPair(context, '');
      const sizing = maxTargetBytes ? { max_target_bytes: maxTargetBytes } : {};
      let recovery = sizing;
      if (attempt.issues.includes('timeout') && !attempt.issues.includes('error')) {
        const extra = controlRetryArgs(base.profile, base.extra, candidate.extra);
        recovery = { ...sizing, initial_scan_sides: attempt.scan_sides, retry_extra_args: extra };
        attempt = await controlPair(context, '-retry', extra);
      }
      const { old, now, scan_sides, issues, control_scope_sha256 } = attempt;
      if (issues.some(Boolean)) {
        deltas.push({ dir, error: 'Control scan incomplete', source_tree: source.evidence, scan_sides, control_scope_sha256, ...recovery });
        continue;
      }
      const { added, removed } = controlFindingDeltas(old, now);
      const lines = controlSnippets(directory, [...old, ...now], source.hashes);
      const snip = f => withSnippet(lines, f);
      const delta = { dir, before: old.length, after: now.length, source_tree: source.evidence, scan_sides, control_scope_sha256, ...recovery,
        added: added.map(snip), removed: removed.map(snip),
        emitted: now.map(snip) };
      if (checkpointInputs) {
        await verifyBoundEngine(engine, 'control checkpoint');
        verifyEvaluationRules({ baseline: base.rules, candidate: candidate.rules }, rules);
        writeCheckpoint(resolve(opts['checkpoint-dir']), checkpointInputs, delta);
      }
      deltas.push(delta);
    } catch (error) {
      if (error instanceof RecallInputDrift) throw error;
      deltas.push({ dir, error: String(error.message).slice(-300) });
    }
  }
  return deltas;
}

// Observation loop: control alerts become a label queue; labels gate later changes.
function controlSnippets(root, findings, hashes) {
  const snippets = new Map();
  for (const { path, line } of findings) {
    if (!snippets.has(path)) snippets.set(path, new Map());
    snippets.get(path).set(line, '');
  }
  for (const [path, lines] of snippets) {
    const bytes = readFileSync(join(root, path));
    if (sha256(bytes) !== hashes.get(path)) throw new Error('Control finding source bytes differ');
    const source = bytes.toString('utf8').split('\n');
    for (const line of lines.keys()) lines.set(line, (source[line - 1] ?? '').trim().slice(0, 200));
  }
  return snippets;
}

function withSnippet(snippets, finding) {
  const { rule, path, line, span } = finding;
  return { rule, path, line, ...(span ? { span } : {}), snippet: snippets.get(path).get(line) };
}

const legacyLabelKey = (repo, alert) => `${alert.rule}|${repo}|${alert.path}|${(alert.snippet_sha256 ?? sha256(alert.snippet ?? '')).slice(0, 16)}`;
export function labelKey(repo, alert) {
  const legacy = legacyLabelKey(repo, alert);
  return alert.span ? `${legacy}|${alert.line}:${alert.span.join(':')}` : legacy;
}
const repoName = dir => basename(resolve(dir.replaceAll('\\', '/')));

function keyCounts(values) {
  const counts = new Map();
  for (const key of values) counts.set(key, (counts.get(key) ?? 0) + 1);
  return counts;
}

function alertKeys(repo, alerts) {
  return (alerts ?? []).map(alert => ({ key: labelKey(repo, alert), legacy: legacyLabelKey(repo, alert) }));
}

function legacyAlternatives(entries) {
  return keyCounts(new Map(entries.map(item => [item.key, item.legacy])).values());
}

function queueControlDelta(labels, delta) {
  const repo = repoName(delta.dir);
  const legacyCount = delta.emitted ? legacyAlternatives(alertKeys(repo, [...delta.emitted, ...(delta.removed ?? [])])) : new Map();
  for (const alert of delta.emitted ?? delta.added ?? []) {
    const key = labelKey(repo, alert), legacy = legacyLabelKey(repo, alert);
    if (labels.has(legacy) && legacyCount.get(legacy) === 1) continue;
    if (!labels.has(key)) labels.set(key, { key, repo, ...alert, verdict: null, note: '' });
  }
}

function validateControlPopulation(binding) {
  if (binding != null && (typeof binding !== 'string' || !/^[a-f0-9]{64}$/.test(binding))) {
    throw new Error('Invalid control population fingerprint');
  }
}

export function queueLabels(existing, deltas, population) {
  validateControlPopulation(population);
  validateControlPopulation(existing?.control_population_sha256);
  const changed = population && existing && existing.control_population_sha256 !== population;
  const archived = { ...existing?.archived_labels };
  if (changed && existing.labels?.length) {
    archived[existing.control_population_sha256 ?? 'unbound'] = existing.labels;
  }
  const labels = new Map((changed ? [] : existing?.labels ?? []).map(label => [label.key, label]));
  for (const delta of deltas) queueControlDelta(labels, delta);
  return { schema: 'factory.recall-labels.v1', ...(population ? { control_population_sha256: population } : {}),
    ...(Object.keys(archived).length ? { archived_labels: archived } : {}),
    labels: [...labels.values()].sort((a, b) => a.key.localeCompare(b.key)) };
}

function controlLabelEvidence(deltas) {
  const completed = deltas.filter(delta => !delta.error && !delta.incomplete_on_both);
  const repos = new Set(completed.map(delta => repoName(delta.dir)));
  const emitted = completed.flatMap(delta => alertKeys(repoName(delta.dir), delta.emitted));
  const removed = completed.flatMap(delta => alertKeys(repoName(delta.dir), delta.removed));
  return { repos, emitted, exact: keyCounts(emitted.map(item => item.key)),
    legacy: keyCounts(emitted.map(item => item.legacy)), alternatives: legacyAlternatives([...emitted, ...removed]) };
}

function reviewedCount(label, evidence) {
  if (label.span) return evidence.exact.get(label.key) ?? 0;
  const count = evidence.legacy.get(label.key) ?? 0;
  return count ? Math.max(count, evidence.alternatives.get(label.key)) : 0;
}

function reviewedControlMatches(rows, evidence) {
  const matches = new Map(), ambiguous = [], fpReturned = [], tpDropped = [];
  for (const label of rows) {
    if (!evidence.repos.has(label.repo ?? label.key.split('|')[1])) continue;
    const count = reviewedCount(label, evidence);
    if (count > 1) {
      ambiguous.push(label.key);
      continue;
    }
    if (count === 1) matches.set(label.key, label.verdict);
    if (count === 1 && label.verdict === 'FP') fpReturned.push(label.key);
    if (count === 0 && label.verdict === 'TP') tpDropped.push(label.key);
  }
  return { matches, ambiguous, fpReturned, tpDropped };
}

export function checkLabels(labels, deltas) {
  const sheet = labels?.labels ?? [];
  const reviewed = sheet.filter(label => label.verdict === 'TP' || label.verdict === 'FP');
  const evidence = controlLabelEvidence(deltas);
  const { matches, ambiguous, fpReturned, tpDropped } = reviewedControlMatches(reviewed, evidence);
  const decisions = evidence.emitted.map(item => matches.get(item.key) ?? matches.get(item.legacy));
  const tp = decisions.filter(verdict => verdict === 'TP').length;
  const fp = decisions.filter(verdict => verdict === 'FP').length;
  const judged = tp + fp;
  return { judged, emitted: decisions.length, unreviewed_emitted: decisions.length - judged,
    labeled_precision: judged ? { tp, fp, wilson95: wilson(tp, judged) } : null,
    fp_returned: fpReturned, tp_dropped: tpDropped, ambiguous_labels: ambiguous,
    pending: sheet.filter(label => !label.verdict).length, unclear: sheet.filter(label => label.verdict === 'UNCLEAR').length };
}

function readOptionalLabels(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return null;
  }
}

function updateLabels(path, deltas, population) {
  const destination = resolve(path);
  const lock = destination + '.lock';
  const descriptor = openSync(lock, 'wx', 0o600);
  try {
    const queued = queueLabels(readOptionalLabels(destination), deltas, population);
    const staging = mkdtempSync(join(dirname(destination), '.recall-labels-'));
    try {
      const staged = join(staging, 'labels.json');
      writeFileSync(staged, `${JSON.stringify(queued, null, 1)}\n`, { mode: 0o600 });
      renameSync(staged, destination);
    } finally {
      rmSync(staging, { recursive: true, force: true });
    }
    return queued;
  } finally {
    closeSync(descriptor);
    rmSync(lock, { force: true });
  }
}

async function observe(opts) {
  const deltas = JSON.parse(readFileSync(opts.controls, 'utf8'));
  const queued = updateLabels(opts.labels, deltas.deltas ?? deltas.controls ?? [], deltas.control_population_sha256);
  console.log(`${queued.labels.length} labels, ${queued.labels.filter(label => !label.verdict).length} pending`);
}

async function controls(opts) {
  const [before, after] = [].concat(opts.rules);
  const profileBytes = readFileSync(opts.profile ?? 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json');
  const settings = { ...opts, baseline: before, candidate: after, profileBytes };
  const rules = evaluationRules(settings);
  const engine = await bindRecallEngine(JSON.parse(utf8(profileBytes)), opts.opengrep ?? process.env.OPENGREP ?? 'opengrep');
  const deltas = await controlDeltas_({ ...settings, ruleFingerprints: rules }, engine);
  await verifyBoundEngine(engine, 'control scoring');
  verifyEvaluationRules(settings, rules);
  writeFileSync(opts.out, `${JSON.stringify({ schema: 'factory.recall-controls.v1', before_sha256: rules.baseline_sha256,
    after_sha256: rules.candidate_sha256, profile_sha256: sha256(profileBytes), engine: engine.receipt,
    control_excluded_directories: controlExcludedDirectories(opts), deltas }, null, 1)}\n`);
  for (const delta of deltas) console.log(delta.dir, delta.before, '->', delta.after, delta.error ?? '');
  if (deltas.some(delta => delta.error)) process.exitCode = 2;
}

function compare([before, after]) {
  const [a, b] = [before, after].map(path => JSON.parse(readFileSync(path, 'utf8')));
  if (a.manifest_sha256 !== b.manifest_sha256) throw new Error('Compared manifest byte fingerprints differ');
  const index = new Map(a.cases.map(row => [row.ghsa, row]));
  for (const row of b.cases) {
    const old = index.get(row.ghsa);
    if (old && (measuredOutcome(old) === 'hit') !== (measuredOutcome(row) === 'hit')) {
      console.log(`${measuredOutcome(row) === 'hit' ? 'GAINED' : 'LOST  '} ${row.ghsa} ${row.repository} ${row.families}`);
    }
  }
  console.log(`hunk ${a.summary.hunk_hits}/${a.summary.scored} -> ${b.summary.hunk_hits}/${b.summary.scored}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const [command, ...rest] = process.argv.slice(2);
  const opts = options(rest);
  if (command === 'freeze') freeze(opts);
  else if (command === 'score') await score(opts);
  else if (command === 'controls') await controls(opts);
  else if (command === 'evaluate') await evaluate(opts);
  else if (command === 'observe') await observe(opts);
  else if (command === 'compare') compare(opts._);
  else { console.error('usage: recall_harness.mjs freeze|score|evaluate|controls|observe|compare ...'); process.exit(2); }
}
