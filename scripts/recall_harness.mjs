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
// with only the binary, ruleset and report/source paths substituted, so
// timeouts and flags match what ships. The scoring rule is fixed: a
// CWE-family-matching alert on an old-side line of a `git diff -U5` hunk in
// an in-language, non-test changed file at the fix parent. Alerts still on
// new-side hunk lines at the fix commit are reported as fix-side residuals,
// a precision proxy.
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

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

// Old- and new-side line sets of every in-language, non-test file in a -U5 diff.
export function parseHunks(diff, extensions) {
  const files = {};
  let oldPath = null, newPath = null;
  const keep = path => path && extensions.some(ext => path.endsWith(`.${ext}`)) && !isTestPath(path);
  for (const line of diff.split('\n')) {
    if (line.startsWith('--- ')) { oldPath = line.startsWith('--- a/') ? line.slice(6) : null; continue; }
    if (line.startsWith('+++ ')) { newPath = line.startsWith('+++ b/') ? line.slice(6) : null; continue; }
    const match = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (!match) continue;
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
  return files;
}

// Rule id -> scored families, read from the ruleset without a YAML dependency.
export function ruleFamilies(rulesText) {
  const out = {};
  for (const block of rulesText.split(/\n  - id: /).slice(1)) {
    const id = block.split('\n', 1)[0].trim();
    const inline = /\n\s+cwe:\s*\[([^\]]*)\]/.exec(block);
    const listed = /\n(\s+)cwe:\s*\n((?:\1\s*- .*\n?)+)/.exec(block);
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

// Deterministic, overlap-safe selection from advisory metadata only.
export function selectCases(candidates, options) {
  const { from, to, prior = { ids: new Set(), fixes: new Set() }, perRepo = 3, perEcosystem = Infinity } = options;
  const dropped = {};
  const drop = reason => { dropped[reason] = (dropped[reason] ?? 0) + 1; };
  const eligible = [];
  for (const row of candidates) {
    if (!LANGUAGES[row.ecosystem]) { drop('ecosystem'); continue; }
    if (!(row.published >= from && row.published <= to)) { drop('window'); continue; }
    if (!/^[0-9a-f]{40}$/.test(row.fix ?? '') || !/^[\w.-]+\/[\w.-]+$/.test(row.repository ?? '')) { drop('fix_commit'); continue; }
    if (!familiesFor(row.cwes ?? []).length) { drop('family'); continue; }
    if (prior.ids.has(row.ghsa)) { drop('prior_id'); continue; }
    if (prior.fixes.has(row.fix)) { drop('prior_fix'); continue; }
    eligible.push({ ghsa: row.ghsa, ecosystem: row.ecosystem, cwes: [...row.cwes].sort(), published: row.published,
      repository: row.repository, fix: row.fix });
  }
  eligible.sort((a, b) => b.published.localeCompare(a.published) || a.ghsa.localeCompare(b.ghsa));
  const seenFix = new Set(), repoCount = {}, ecoCount = {}, cases = [];
  for (const row of eligible) {
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

// hit / miss / timeout (a miss where the engine timed out) / unknown (no
// scorable source change, unfetchable, no parent) / error.
export function outcomeOf(row) {
  if (row.status === 'error') return 'error';
  if (row.status !== 'scored') return 'unknown';
  if (row.hunk_hit) return 'hit';
  return row.scan_notes?.timeouts ? 'timeout' : 'miss';
}

export function summarize(rows) {
  const scored = rows.filter(row => row.status === 'scored');
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
    cases: rows.length, scored: scored.length,
    status: rows.reduce((acc, row) => ({ ...acc, [row.status]: (acc[row.status] ?? 0) + 1 }), {}),
    hunk_hits: hits, hunk_recall_wilson95: wilson(hits, scored.length),
    trace_hits: scored.filter(row => row.trace_hit).length,
    trace_recall_wilson95: wilson(scored.filter(row => row.trace_hit).length, scored.length),
    file_hits: fileHits, file_recall_wilson95: wilson(fileHits, scored.length),
    distinct_fixes_hit: new Set(scored.filter(row => row.hunk_hit).map(row => row.fix)).size,
    outcomes: rows.reduce((acc, row) => { const o = row.outcome ?? outcomeOf(row); return { ...acc, [o]: (acc[o] ?? 0) + 1 }; },
      { hit: 0, miss: 0, timeout: 0, unknown: 0, error: 0 }),
    // Review budget: every alert in a changed file is something a reviewer reads.
    review_budget: { alerts_in_changed_files: scored.reduce((n, row) => n + row.alerts_in_changed_files, 0),
      per_scored_case: scored.length ? Math.round(10 * scored.reduce((n, row) => n + row.alerts_in_changed_files, 0) / scored.length) / 10 : 0 },
    fix_side_residual_alerts: scored.reduce((n, row) => n + row.fix_side_residual.length, 0),
    by_family: tally('families'), by_ecosystem: tally('ecosystem'),
  };
}

// Async child processes so --jobs really runs cases side by side.
function exec(command, args, { cwd, env, timeout = 1800000 } = {}) {
  return new Promise(done => {
    const child = spawn(command, args, { cwd, env: { ...process.env, ...env } });
    const out = [], err = [];
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.stdout.on('data', chunk => out.push(chunk));
    child.stderr.on('data', chunk => err.push(chunk));
    child.on('error', error => { clearTimeout(timer); done({ status: -1, stdout: '', stderr: String(error) }); });
    child.on('close', status => { clearTimeout(timer);
      done({ status, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }); });
  });
}

const git = (dir, ...args) => exec('git', ['-C', dir, ...args], { timeout: 900000 });

async function materialize(repo, revision, paths, target) {
  for (const path of paths) {
    const shown = await git(repo, 'show', `${revision}:${path}`);
    if (shown.status !== 0) continue;
    mkdirSync(dirname(join(target, path)), { recursive: true });
    writeFileSync(join(target, path), shown.stdout);
  }
}

// Scan with the source as cwd so SARIF URIs are relative to it.
export async function scan(context, source, report = `${source}.sarif`, { reuse = false } = {}) {
  // A cached report is reused only if the engine reported no timeout in it;
  // timeouts depend on machine load, so those scans are always repeated.
  if (reuse && existsSync(report)) {
    const cached = JSON.parse(readFileSync(report, 'utf8'));
    if (!scanNotes(cached).timeouts) {
      const findings = sarifFindings(cached);
      findings.notes = scanNotes(cached);
      return findings;
    }
  }
  rmSync(report, { force: true });
  mkdirSync(dirname(report), { recursive: true });
  const argv = profileArgv(context.profile, { bin: context.bin, rules: context.rules, report, source: '.', extra: context.extra });
  const run = await exec(argv[0], argv.slice(1), { cwd: source,
    env: { HOME: process.env.HOME ?? '/tmp', PYTHONIOENCODING: 'utf-8', LANG: 'C.UTF-8' } });
  if (!existsSync(report)) throw new Error(`scan failed (${run.status}): ${run.stderr.slice(-300)}`);
  const sarif = JSON.parse(readFileSync(report, 'utf8'));
  const findings = sarifFindings(sarif);
  findings.notes = scanNotes(sarif);
  return findings;
}

// Engine timeouts and parse failures, so a miss caused by the engine is not
// counted as a detector miss.
export function scanNotes(sarif) {
  const notes = { timeouts: 0, parse_errors: 0, other: 0 };
  for (const run of sarif.runs ?? []) {
    for (const invocation of run.invocations ?? []) {
      for (const note of invocation.toolExecutionNotifications ?? []) {
        const id = `${note.descriptor?.id ?? ''} ${note.message?.text ?? ''}`;
        if (/timeout|timed out/i.test(id)) notes.timeouts++;
        else if (/syntax|pars/i.test(id)) notes.parse_errors++;
        else if (note.level === 'error') notes.other++;
      }
    }
  }
  return notes;
}

// Fetch once per case and keep the old/new trees, so several rulesets can be
// scored against the same materialized fixes.
async function prepareCase(workdir, row) {
  const dir = join(workdir, 'cases', row.ghsa);
  const record = join(dir, 'case.json');
  if (existsSync(record)) return JSON.parse(readFileSync(record, 'utf8'));
  rmSync(dir, { recursive: true, force: true });
  const repo = join(dir, 'repo');
  mkdirSync(repo, { recursive: true });
  const done = value => { writeFileSync(record, JSON.stringify(value)); rmSync(repo, { recursive: true, force: true }); return value; };
  await git(repo, 'init', '-q');
  await git(repo, 'remote', 'add', 'origin', `https://github.com/${row.repository}.git`);
  if ((await git(repo, 'fetch', '-q', '--filter=blob:none', '--depth=2', 'origin', row.fix)).status !== 0) return { status: 'unfetchable' };
  const fix = (await git(repo, 'rev-parse', 'FETCH_HEAD')).stdout.trim();
  const parent = (await git(repo, 'rev-parse', `${fix}^`)).stdout.trim();
  if (!parent) return done({ status: 'no_parent' });
  const extensions = LANGUAGES[row.ecosystem];
  const diff = (await git(repo, 'diff', '-U5', parent, fix, '--', ...extensions.map(ext => `*.${ext}`))).stdout;
  const hunks = parseHunks(diff, extensions);
  if (!Object.keys(hunks).length) return done({ status: 'no_in_language_source_change' });
  await materialize(repo, parent, Object.keys(hunks), join(dir, 'old'));
  await materialize(repo, fix, Object.values(hunks).map(entry => entry.new_path).filter(Boolean), join(dir, 'new'));
  if (!existsSync(join(dir, 'old'))) return done({ status: 'no_in_language_source_change' });
  return done({ status: 'ready', hunks, old: join(dir, 'old'), new: existsSync(join(dir, 'new')) ? join(dir, 'new') : null });
}

async function scoreOne(context, row) {
  const prepared = await prepareCase(context.workdir, row);
  if (prepared.status !== 'ready') return { status: prepared.status };
  const reports = join(context.workdir, 'scans', sha256(context.rulesText + context.extra.join(' ')).slice(0, 16), row.ghsa);
  const oldFindings = await scan(context, prepared.old, `${reports}/old.sarif`, { reuse: true });
  const newFindings = prepared.new ? await scan(context, prepared.new, `${reports}/new.sarif`, { reuse: true }) : [];
  const result = scoreCase({ families: familiesFor(row.cwes), hunks: prepared.hunks, oldFindings, newFindings, rules: context.ruleMap });
  return { status: 'scored', families: familiesFor(row.cwes), changed_files: Object.keys(prepared.hunks).sort(),
    scan_notes: oldFindings.notes, ...result, outcome: outcomeOf({ status: 'scored', scan_notes: oldFindings.notes, ...result }) };
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
  const candidates = JSON.parse(readFileSync(opts.candidates, 'utf8'));
  const prior = priorExposure([].concat(opts['exclude-dir'] ?? 'docs/evidence'));
  const { cases, dropped } = selectCases(candidates, { from: opts.from, to: opts.to, prior,
    perRepo: Number(opts['per-repo'] ?? 3), perEcosystem: Number(opts['per-ecosystem'] ?? Infinity) });
  const manifest = { schema: 'factory.recall-heldout.v1', frozen_from: 'advisory metadata only; no fix diff read',
    window: [opts.from, opts.to], exclusions: { prior_ids: prior.ids.size, prior_fix_commits: prior.fixes.size },
    dropped, counts: cases.reduce((acc, row) => ({ ...acc, [row.ecosystem]: (acc[row.ecosystem] ?? 0) + 1 }), {}),
    cases_sha256: caseDigest(cases), scoring_rule: 'hunk rule: CWE-family alert on an old-side -U5 hunk line, in-language non-test file, fix parent',
    cases };
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 1)}\n`);
  console.log(`froze ${cases.length} cases (${manifest.cases_sha256})`, dropped);
}

function scoringContext(opts, rulesPath) {
  const rulesText = readFileSync(rulesPath, 'utf8');
  return { profile: JSON.parse(readFileSync(opts.profile ?? 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json', 'utf8')),
    bin: opts.opengrep ?? process.env.OPENGREP ?? 'opengrep', rules: resolve(rulesPath), rulesText, ruleMap: ruleFamilies(rulesText),
    extra: [].concat(opts['extra-arg'] ?? []), workdir: resolve(opts.workdir ?? '.factory/recall-work') };
}

export async function scoreManifest(manifestPath, rulesPath, opts = {}) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const context = scoringContext(opts, rulesPath);
  mkdirSync(context.workdir, { recursive: true });
  const rows = await pool(manifest.cases, Number(opts.jobs ?? 6), async row => {
    try { return { ...row, ...(await scoreOne(context, row)) }; }
    catch (error) { return { ...row, status: 'error', detail: String(error.message).slice(-300) }; }
  });
  return { schema: 'factory.recall-result.v1', manifest: manifestPath, manifest_cases_sha256: manifest.cases_sha256,
    ruleset_sha256: sha256(context.rulesText),
    argv: profileArgv(context.profile, { bin: context.bin, rules: '{rules}', report: '{report}', source: '{source}', extra: context.extra }),
    summary: summarize(rows), cases: rows };
}

async function score(opts) {
  const out = await scoreManifest(opts.manifest, opts.rules, opts);
  writeFileSync(opts.out, `${JSON.stringify(out, null, 1)}\n`);
  console.log(JSON.stringify(out.summary, null, 1));
}

// Accept/reject gates for one candidate ruleset against a baseline.
export function gate({ dev, controls, maxControlIncrease = 0 }) {
  const lost = [], gained = [];
  for (const { before, after } of dev) {
    const index = new Map(before.cases.map(row => [row.ghsa, row]));
    for (const row of after.cases) {
      const old = index.get(row.ghsa);
      if (!old) continue;
      if (old.hunk_hit && !row.hunk_hit) lost.push(row.ghsa);
      if (!old.hunk_hit && row.hunk_hit) gained.push(row.ghsa);
    }
  }
  const residualBefore = dev.reduce((n, pair) => n + pair.before.summary.fix_side_residual_alerts, 0);
  const residualAfter = dev.reduce((n, pair) => n + pair.after.summary.fix_side_residual_alerts, 0);
  const controlIncrease = controls.reduce((n, delta) => n + (delta.after ?? 0) - (delta.before ?? 0), 0);
  const newErrors = dev.flatMap(({ before, after }) => {
    const index = new Map(before.cases.map(row => [row.ghsa, row]));
    return after.cases.filter(row => ['error', 'timeout'].includes(row.outcome ?? outcomeOf(row))
      && !['error', 'timeout'].includes((index.get(row.ghsa) ?? {}).outcome ?? outcomeOf(index.get(row.ghsa) ?? {}))).map(row => row.ghsa);
  });
  const failures = [];
  if (newErrors.length) failures.push(`new engine errors/timeouts: ${newErrors.join(', ')}`);
  if (lost.length) failures.push(`lost ${lost.length} dev hit(s): ${lost.join(', ')}`);
  if (residualAfter > residualBefore) failures.push(`fix-side residuals ${residualBefore} -> ${residualAfter}`);
  if (controlIncrease > maxControlIncrease) failures.push(`control alerts +${controlIncrease} > ${maxControlIncrease}`);
  if (controls.some(delta => delta.error)) failures.push('a control scan failed');
  return { decision: failures.length ? 'REJECT' : 'ACCEPT', failures, gained, lost_baseline_hits: lost, new_errors: newErrors,
    residual: [residualBefore, residualAfter], control_increase: controlIncrease };
}

async function evaluate(opts) {
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
    dev: dev.map(pair => ({ manifest: pair.manifest, before: pair.before.summary, after: pair.after.summary })),
    controls: controlDeltas.map(({ dir, before, after, added, removed, error }) => ({ dir, before, after, added, removed, error })) };
  writeFileSync(opts.out, `${JSON.stringify(out, null, 1)}\n`);
  console.log(out.decision, out.failures, `gained ${out.gained.length}`, `controls +${out.control_increase}`);
}

async function controlDeltas_(opts) {
  const [before, after] = [].concat(opts.rules);
  const base = { profile: JSON.parse(readFileSync(opts.profile ?? 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json', 'utf8')),
    bin: opts.opengrep ?? process.env.OPENGREP ?? 'opengrep', extra: [].concat(opts['extra-arg'] ?? []) };
  const key = f => `${f.rule}|${f.path}|${f.line}`;
  const deltas = [];
  for (const dir of [].concat(opts.dir)) {
    try {
      const reports = join(resolve(opts.workdir ?? '.factory/recall-work'), 'controls', sha256(resolve(dir)).slice(0, 16));
      const old = await scan({ ...base, rules: resolve(before) }, resolve(dir), `${reports}/before.sarif`);
      const now = await scan({ ...base, extra: [...base.extra, ...[].concat(opts['candidate-extra-arg'] ?? [])], rules: resolve(after) },
        resolve(dir), `${reports}/after.sarif`);
      const oldKeys = new Set(old.map(key)), newKeys = new Set(now.map(key));
      const snip = f => withSnippet(resolve(dir), f);
      deltas.push({ dir, before: old.length, after: now.length,
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
const repoName = dir => resolve(dir).split('/').filter(Boolean).at(-1);

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
}

function compare([before, after]) {
  const [a, b] = [before, after].map(path => JSON.parse(readFileSync(path, 'utf8')));
  const index = new Map(a.cases.map(row => [row.ghsa, row]));
  for (const row of b.cases) {
    const old = index.get(row.ghsa);
    if (old && Boolean(old.hunk_hit) !== Boolean(row.hunk_hit)) {
      console.log(`${row.hunk_hit ? 'GAINED' : 'LOST  '} ${row.ghsa} ${row.repository} ${row.families}`);
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
