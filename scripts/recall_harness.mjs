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
//            [--labels labels.json]
//   observe  --controls deltas.json --labels labels.json   (queue new control alerts for TP/FP labels)
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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { changedFiles, engineCoverage, fileCoverage, summarizeCoverage } from './recall_coverage.mjs';

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

export const isTestPath = path => TEST_PATH.test(path);
export const familiesFor = cwes => [...new Set(cwes.map(cwe => FAMILIES[cwe]).filter(Boolean))].sort();
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

export function sarifFindings(sarif) {
  const out = [];
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const location = result.locations?.[0]?.physicalLocation;
      if (!location) continue;
      const clean = loc => decodeURIComponent(loc.artifactLocation.uri.replace(/^file:\/\//, '')).replace(/^\.\//, '');
      const trace = (result.codeFlows ?? []).flatMap(flow => flow.threadFlows ?? [])
        .flatMap(thread => thread.locations ?? []).map(step => step.location?.physicalLocation)
        .filter(step => step?.artifactLocation && step.region).map(step => [clean(step), step.region.startLine]);
      out.push({ rule: result.ruleId.split('.').slice(-2).join('.'), path: clean(location),
        line: location.region.startLine, trace });
    }
  }
  return out;
}

// Hunk/file hit and fix-side residuals for one case.
export function scoreCase({ families, hunks, oldFindings, newFindings, rules }) {
  const wanted = new Set(families);
  const relevant = finding => (rules[finding.rule] ?? []).some(family => wanted.has(family));
  const oldHits = oldFindings.filter(relevant);
  const hunkHits = oldHits.filter(f => hunks[f.path]?.old.includes(f.line));
  // Secondary, pre-registered: the alert's source or any dataflow step is on a changed line.
  const traceHits = oldHits.filter(f => [[f.path, f.line], ...(f.trace ?? [])]
    .some(([path, line]) => hunks[path]?.old.includes(line)));
  const residual = newFindings.filter(relevant).filter(f => Object.values(hunks)
    .some(entry => entry.new_path === f.path && entry.new.includes(f.line)));
  return { hunk_hit: hunkHits.length > 0, trace_hit: traceHits.length > 0, file_hit: oldHits.length > 0,
    hunk_findings: hunkHits.map(f => [f.rule, f.path, f.line]), alerts_in_changed_files: oldHits.length,
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
  if (row.status !== 'scored') return 'unknown';
  return row.hunk_hit ? 'hit' : 'miss';
}

export function summarize(rows) {
  const outcomes = rows.map(outcomeOf);
  const scored = rows.filter((_, index) => ['hit', 'miss'].includes(outcomes[index]));
  const tally = key => {
    const out = {};
    for (const row of scored) {
      for (const value of [].concat(row[key])) {
        const entry = out[value] ??= { hits: 0, scored: 0 };
        entry.scored++; entry.hits += row.hunk_hit ? 1 : 0;
      }
    }
    return out;
  };
  const hits = scored.filter(row => row.hunk_hit).length;
  const fileHits = scored.filter(row => row.file_hit).length;
  return {
    cases: rows.length, scored: scored.length, file_coverage: summarizeCoverage(rows),
    status: rows.reduce((acc, row) => ({ ...acc, [row.status]: (acc[row.status] ?? 0) + 1 }), {}),
    hunk_hits: hits, hunk_recall_wilson95: wilson(hits, scored.length),
    trace_hits: scored.filter(row => row.trace_hit).length,
    trace_recall_wilson95: wilson(scored.filter(row => row.trace_hit).length, scored.length),
    file_hits: fileHits, file_recall_wilson95: wilson(fileHits, scored.length),
    distinct_fixes_hit: new Set(scored.filter(row => row.hunk_hit).map(row => row.fix)).size,
    outcomes: outcomes.reduce((acc, outcome) => { acc[outcome]++; return acc; },
      { hit: 0, miss: 0, timeout: 0, unknown: 0, error: 0 }),
    diagnostics: rows.flatMap((row, index) => ['hit', 'miss'].includes(outcomes[index]) ? [] : [{
      ghsa: row.ghsa, status: row.status, outcome: outcomes[index],
      scan_sides: row.scan_sides ?? { old: row.scan_notes }, detail: row.detail,
    }]),
    // Review budget: every alert in a changed file is something a reviewer reads.
    review_budget: { alerts_in_changed_files: scored.reduce((n, row) => n + row.alerts_in_changed_files, 0),
      per_scored_case: scored.length ? Math.round(10 * scored.reduce((n, row) => n + row.alerts_in_changed_files, 0) / scored.length) / 10 : 0 },
    fix_side_residual_alerts: scored.reduce((n, row) => n + row.fix_side_residual.length, 0),
    by_family: tally('families'), by_ecosystem: tally('ecosystem'),
  };
}

// Async child processes so --jobs really runs cases side by side.
function runProcess(command, args, { cwd, env, timeout = 1800000, bytes = false } = {}) {
  return new Promise(done => {
    const child = spawn(command, args, { cwd, env: { ...process.env, ...env } });
    const out = [], err = [];
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeout);
    child.stdout.on('data', chunk => out.push(chunk));
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

async function materialize(repo, revision, paths, target) {
  const packets = [];
  for (const path of paths) {
    const shown = await gitBytes(repo, 'show', revision + ':' + path);
    if (shown.status !== 0) throw new Error('Prepared source could not be read: ' + path);
    mkdirSync(dirname(join(target, path)), { recursive: true });
    writeFileSync(join(target, path), shown.stdout);
    packets.push(packet(path, shown.stdout));
  }
  return packets.sort(byPath);
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
  const run = await runProcess(argv[0], argv.slice(1), { cwd: source,
    env: { HOME: process.env.HOME ?? '/tmp', PYTHONIOENCODING: 'utf-8', LANG: 'C.UTF-8' } });
  const execution = { failed_exit: ![0, 1].includes(run.status), exit_code: run.status,
    timeouts: Number(Boolean(run.timedOut)) };
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
    const findings = sarifFindings(sarif);
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
export function scanNotes(sarif) {
  const notes = { timeouts: 0, parse_errors: 0, blocking_parse_errors: 0, other: 0 };
  for (const run of sarif.runs ?? []) {
    for (const invocation of run.invocations ?? []) {
      if (invocation.executionSuccessful === false) notes.other++;
      for (const note of invocation.toolExecutionNotifications ?? []) {
        const id = `${note.descriptor?.id ?? ''} ${note.message?.text ?? ''}`;
        if (/timeout|timed out/i.test(id)) notes.timeouts++;
        else if (/syntax|pars/i.test(id)) {
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
    try { renameSync(staging, directory); }
    catch (error) { if (!existsSync(record)) throw error; }
    return read();
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

function verifyRulesBytes(context) {
  if (sha256(readFileSync(context.rules)) !== context.rulesSha256) {
    throw new Error('Scan ruleset byte fingerprint differs');
  }
}

async function observeSide(context, source, report, expected) {
  if (!source) return { findings: [], diagnostics: null, submitted: false };
  let diagnostics;
  let submitted = false;
  try {
    verifyPreparedBytes(source, expected);
    verifyRulesBytes(context);
    submitted = true;
    const findings = await scan(context, source, report, true);
    diagnostics = findings.notes;
    verifyRulesBytes(context);
    verifyPreparedBytes(source, expected);
    return { findings, diagnostics, coverage: findings.coverage, submitted, verified: true };
  } catch (error) {
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
    scan_notes: old.diagnostics, scan_sides: { old: old.diagnostics, fixed: fixed.diagnostics }, ...result };
  const outcome = outcomeOf(rowResult);
  return { ...rowResult, status: ['error', 'timeout'].includes(outcome) ? 'incomplete' : status, outcome };
}

async function pool(items, jobs, worker) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(jobs, items.length) }, async () => {
    while (next < items.length) { const index = next++; out[index] = await worker(items[index]); }
  }));
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

export async function scoreManifest(manifestPath, rulesPath, opts = {}) {
  const manifestBytes = readFileSync(manifestPath);
  const manifest = JSON.parse(utf8(manifestBytes));
  const manifestDigest = validateRecallManifest(manifest);
  const context = scoringContext(opts, rulesPath);
  mkdirSync(context.workdir, { recursive: true });
  context.scanRoot = mkdtempSync(join(context.workdir, 'scan-'));
  const one = async (row, scanContext = context) => {
    try { return { ...row, ...(await scoreOne(scanContext, row)) }; }
    catch (error) { return { ...row, status: 'error', detail: String(error.message).slice(-300) }; }
  };
  const rows = await pool(manifest.cases, Number(opts.jobs ?? 6), one);
  // Engine timeouts depend on machine load; repeat those cases one at a time
  // so a timeout is only recorded when it happens on an otherwise idle engine.
  for (let index = 0; index < rows.length; index++) {
    if (rows[index].outcome !== 'timeout') continue;
    const initial = rows[index];
    const serial = { ...context, scanRoot: join(context.scanRoot, 'serial') };
    rows[index] = { ...(await one(manifest.cases[index], serial)), retried_serially: true,
      initial_scan_sides: initial.scan_sides };
  }
  return { schema: 'factory.recall-result.v1', manifest: manifestPath, manifest_cases_sha256: manifestDigest,
    manifest_sha256: sha256(manifestBytes), ruleset_sha256: context.rulesSha256, profile_sha256: context.profileSha256,
    scope: context.scope,
    scan_directory: basename(context.scanRoot),
    argv: profileArgv(context.profile, { bin: context.bin, rules: '{rules}', report: '{report}', source: '{source}', extra: context.extra }),
    summary: summarize(rows), cases: rows };
}

async function score(opts) {
  const out = await scoreManifest(opts.manifest, opts.rules, opts);
  writeFileSync(opts.out, `${JSON.stringify(out, null, 1)}\n`);
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

function measureCaseChange(old, row, { lost, gained, newErrors, failures }) {
  if (caseInputFingerprint(old) !== caseInputFingerprint(row)) {
    failures.push('Baseline and candidate source byte fingerprints differ for ' + row.ghsa);
    return;
  }
  const previous = measuredOutcome(old), current = measuredOutcome(row);
  if (previous === 'hit' && current !== 'hit') lost.push(row.ghsa);
  if (previous === 'miss' && current === 'hit') gained.push(row.ghsa);
  const failure = ['error', 'timeout'];
  if (failure.includes(current) && !failure.includes(previous)) newErrors.push(row.ghsa);
}

function measureDevPair({ before, after }, changes) {
  if (before.manifest_sha256 !== after.manifest_sha256 || before.profile_sha256 !== after.profile_sha256) {
    changes.failures.push('Baseline and candidate manifest or profile byte fingerprints differ');
    return;
  }
  const baseline = new Map(before.cases.map(row => [row.ghsa, row]));
  for (const row of after.cases) {
    const old = baseline.get(row.ghsa);
    if (!old) changes.failures.push('Baseline case missing for ' + row.ghsa);
    else measureCaseChange(old, row, changes);
  }
}

export function gate({ dev, controls, maxControlIncrease = 0, residualTolerance = 0.1 }) {
  const lost = [], gained = [], newErrors = [], failures = [];
  for (const pair of dev) measureDevPair(pair, { lost, gained, newErrors, failures });
  const residualBefore = dev.reduce((n, pair) => n + pair.before.summary.fix_side_residual_alerts, 0);
  const residualAfter = dev.reduce((n, pair) => n + pair.after.summary.fix_side_residual_alerts, 0);
  const controlIncrease = controls.reduce((n, delta) => n + (delta.after ?? 0) - (delta.before ?? 0), 0);
  if (newErrors.length) failures.push(`new engine errors/timeouts: ${newErrors.join(', ')}`);
  if (lost.length) failures.push(`lost ${lost.length} dev hit(s): ${lost.join(', ')}`);
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
  if (controls.some(delta => delta.error)) failures.push('a control scan failed');
  return { decision: failures.length ? 'REJECT' : 'ACCEPT', failures, gained, lost_baseline_hits: lost, new_errors: newErrors,
    residual: [residualBefore, residualAfter], residual_per_hit: [rateBefore, rateAfter].map(x => Math.round(x * 100) / 100),
    control_increase: controlIncrease };
}

function evaluationEvidence(result) {
  return { manifest_sha256: result.manifest_sha256, cases_sha256: result.manifest_cases_sha256,
    profile_sha256: result.profile_sha256, ruleset_sha256: result.ruleset_sha256, scan_directory: result.scan_directory,
    cases: result.cases.map(({ ghsa, revisions, source_packets, diff_sha256, changed_files_sha256, file_coverage,
      scan_sides, initial_scan_sides, retried_serially, outcome, status }) =>
      ({ ghsa, revisions, source_packets, diff_sha256, changed_files_sha256,
        file_coverage, scan_sides, initial_scan_sides, retried_serially, outcome, status })) };
}

async function evaluate(input) {
  const opts = { ...input, profileBytes: input.profileBytes
    ?? readFileSync(input.profile ?? 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json') };
  const manifests = [].concat(opts.manifest);
  // A flag under test (for example --taint-intrafile) applies to the candidate only.
  const candidateOpts = { ...opts, 'extra-arg': [].concat(opts['extra-arg'] ?? [], opts['candidate-extra-arg'] ?? []) };
  const dev = [];
  for (const manifest of manifests) {
    dev.push({ manifest, before: await scoreManifest(manifest, opts.baseline, opts),
      after: await scoreManifest(manifest, opts.candidate, candidateOpts) });
  }
  const controlDeltas = opts.dir ? await controlDeltas_({ ...opts, rules: [opts.baseline, opts.candidate] }) : [];
  const verdict = gate({ dev, controls: controlDeltas, maxControlIncrease: Number(opts['max-control-increase'] ?? 0) });
  if (opts.labels && existsSync(opts.labels)) {
    verdict.labels = checkLabels(JSON.parse(readFileSync(opts.labels, 'utf8')), controlDeltas);
    if (verdict.labels.fp_returned.length) verdict.failures.push(`labeled false positives emitted again: ${verdict.labels.fp_returned.length}`);
    if (verdict.labels.tp_dropped.length) verdict.failures.push(`labeled true positives no longer emitted: ${verdict.labels.tp_dropped.length}`);
    verdict.decision = verdict.failures.length ? 'REJECT' : 'ACCEPT';
  }
  const out = { schema: 'factory.recall-evaluation.v1', baseline_sha256: sha256(readFileSync(opts.baseline)),
    candidate_sha256: sha256(readFileSync(opts.candidate)), extra_args: [].concat(opts['extra-arg'] ?? []),
    candidate_extra_args: [].concat(opts['candidate-extra-arg'] ?? []), ...verdict,
    dev: dev.map(pair => ({ manifest: pair.manifest, manifest_cases_sha256: pair.after.manifest_cases_sha256,
      before: pair.before.summary, after: pair.after.summary,
      before_evidence: evaluationEvidence(pair.before), after_evidence: evaluationEvidence(pair.after),
      cases: pair.after.cases.map((row, index) => ({ ghsa: row.ghsa, fix: row.fix,
        before: pair.before.cases[index].outcome ?? pair.before.cases[index].status, after: row.outcome ?? row.status,
        hunk_findings: row.hunk_findings ?? [], fix_side_residual: row.fix_side_residual ?? [],
        retried_serially: Boolean(row.retried_serially) })) })),
    controls: controlDeltas.map(({ dir, before, after, added, removed, error, scan_sides, incomplete_on_both }) =>
      ({ dir, before, after, added, removed, error, scan_sides, incomplete_on_both })) };
  writeFileSync(opts.out, `${JSON.stringify(out, null, 1)}\n`);
  console.log(out.decision, out.failures, `gained ${out.gained.length}`, `controls +${out.control_increase}`);
  if (out.decision === 'REJECT') process.exitCode = 2;
}

async function controlDeltas_(opts) {
  const [before, after] = [].concat(opts.rules);
  const base = { profile: JSON.parse(utf8(opts.profileBytes ?? readFileSync(opts.profile ?? 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json'))),
    bin: opts.opengrep ?? process.env.OPENGREP ?? 'opengrep', extra: [].concat(opts['extra-arg'] ?? []) };
  const key = f => `${f.rule}|${f.path}|${f.line}`;
  const deltas = [];
  const workdir = resolve(opts.workdir ?? '.factory/recall-work');
  mkdirSync(workdir, { recursive: true });
  const scanRoot = mkdtempSync(join(workdir, 'controls-'));
  for (const dir of [].concat(opts.dir)) {
    try {
      const reports = join(scanRoot, sha256(resolve(dir)).slice(0, 16));
      const old = await scan({ ...base, rules: resolve(before) }, resolve(dir), `${reports}/before.sarif`);
      const now = await scan({ ...base, extra: [...base.extra, ...[].concat(opts['candidate-extra-arg'] ?? [])], rules: resolve(after) },
        resolve(dir), `${reports}/after.sarif`);
      const scan_sides = { before: old.notes, after: now.notes };
      // An engine limit the baseline hits too (same issue class, no more
      // timeouts for the candidate) is not a candidate regression; record it
      // with the delta instead of failing the control.
      const issues = Object.values(scan_sides).map(scanIssue);
      const sameIncomplete = Boolean(issues[0]) && issues[0] === issues[1]
        && (scan_sides.after.timeouts ?? 0) <= (scan_sides.before.timeouts ?? 0);
      if (issues.some(Boolean) && !sameIncomplete) {
        deltas.push({ dir, error: 'Control scan incomplete', scan_sides });
        continue;
      }
      const oldKeys = new Set(old.map(key)), newKeys = new Set(now.map(key));
      const snip = f => withSnippet(resolve(dir), f);
      deltas.push({ dir, before: old.length, after: now.length, scan_sides, ...(sameIncomplete ? { incomplete_on_both: issues[0] } : {}),
        added: now.filter(f => !oldKeys.has(key(f))).map(snip), removed: old.filter(f => !newKeys.has(key(f))).map(snip),
        emitted: now.map(snip) });
    } catch (error) { deltas.push({ dir, error: String(error.message).slice(-300) }); }
  }
  return deltas;
}

// Observation loop: control alerts become a label queue; labels gate later changes.
function withSnippet(root, finding) {
  let text = '';
  try { text = readFileSync(join(root, finding.path), 'utf8').split('\n')[finding.line - 1] ?? ''; } catch { /* moved */ }
  return { rule: finding.rule, path: finding.path, line: finding.line, snippet: text.trim().slice(0, 200) };
}

export const labelKey = (repo, alert) => `${alert.rule}|${repo}|${alert.path}|${sha256(alert.snippet ?? '').slice(0, 16)}`;
const repoName = dir => basename(resolve(dir.replaceAll('\\', '/')));

export function queueLabels(existing, deltas) {
  const labels = new Map((existing?.labels ?? []).map(label => [label.key, label]));
  for (const delta of deltas) {
    for (const alert of delta.added ?? []) {
      const key = labelKey(repoName(delta.dir), alert);
      if (!labels.has(key)) labels.set(key, { key, repo: repoName(delta.dir), ...alert, verdict: null, note: '' });
    }
  }
  return { schema: 'factory.recall-labels.v1', labels: [...labels.values()].sort((a, b) => a.key.localeCompare(b.key)) };
}

export function checkLabels(labels, deltas) {
  const emitted = new Set(deltas.flatMap(delta => (delta.emitted ?? []).map(alert => labelKey(repoName(delta.dir), alert))));
  const judged = (labels?.labels ?? []).filter(label => label.verdict === 'TP' || label.verdict === 'FP');
  const fpReturned = judged.filter(label => label.verdict === 'FP' && emitted.has(label.key)).map(label => label.key);
  const tpDropped = judged.filter(label => label.verdict === 'TP' && !emitted.has(label.key)).map(label => label.key);
  const tp = judged.filter(label => label.verdict === 'TP').length;
  return { judged: judged.length, labeled_precision: judged.length ? { tp, fp: judged.length - tp, wilson95: wilson(tp, judged.length) } : null,
    fp_returned: fpReturned, tp_dropped: tpDropped, pending: (labels?.labels ?? []).filter(label => !label.verdict).length,
    // UNCLEAR is an explicit label, kept out of the precision denominator.
    unclear: (labels?.labels ?? []).filter(label => label.verdict === 'UNCLEAR').length };
}

async function observe(opts) {
  const deltas = JSON.parse(readFileSync(opts.controls, 'utf8'));
  const existing = existsSync(opts.labels) ? JSON.parse(readFileSync(opts.labels, 'utf8')) : null;
  const queued = queueLabels(existing, deltas.deltas ?? deltas.controls ?? []);
  writeFileSync(opts.labels, `${JSON.stringify(queued, null, 1)}\n`);
  console.log(`${queued.labels.length} labels, ${queued.labels.filter(label => !label.verdict).length} pending`);
}

async function controls(opts) {
  const [before, after] = [].concat(opts.rules);
  const deltas = await controlDeltas_(opts);
  writeFileSync(opts.out, `${JSON.stringify({ schema: 'factory.recall-controls.v1', before_sha256: sha256(readFileSync(before)),
    after_sha256: sha256(readFileSync(after)), deltas }, null, 1)}\n`);
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
