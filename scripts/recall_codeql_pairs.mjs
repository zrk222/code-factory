#!/usr/bin/env node
// Supplementary scoring of paired native SARIF against a registered reference.
// A v1 bundle pins the query for each targeted case. A v2 bundle pins a
// separate plan that assigns one query inventory to each supported ecosystem.
// Each old/fixed capture pins observation JSON, SARIF and the CodeQL source ZIP.
// Artifact paths are relative to the bundle, and archive prefixes identify source roots.
import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { caseDigest, familiesFor, outcomeOf, parseHunks, reviewCapturePath, sarifFindings, scopeExtensions,
  scoreCase, sha256, validateRecallManifest } from './recall_harness.mjs';
import { completeFixedCoverage, sarifPath } from './recall_coverage.mjs';
import { inputFingerprint } from './verify_registered_recall.mjs';

const FORMAT = 'factory.recall-codeql-pairs.v1';
const PLAN_BUNDLE = 'factory.recall-codeql-pairs.v2';
const digest = /^[0-9a-f]{64}$/;
const revision = /^[0-9a-f]{40}$/;
const relativeEntry = path => typeof path === 'string' && !path.includes('\\')
  && path.split('/').every(part => part && part !== '.' && part !== '..');
const json = bytes => JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, ''));
const familiesFromTags = tags => familiesFor(tags.flatMap(tag => {
  const match = tag.match(/^external\/cwe\/cwe-(\d+)$/);
  return match ? ['CWE-' + Number(match[1])] : [];
}));

function requireProof(condition, message) {
  if (!condition) throw new Error(message);
}

function boundPath(root, pin) {
  requireProof(digest.test(pin?.sha256), 'Artifact SHA-256 is required');
  return reviewCapturePath(root, pin.path);
}

function artifact(root, pin) {
  const bytes = readFileSync(boundPath(root, pin));
  requireProof(sha256(bytes) === pin.sha256, 'Artifact fingerprint differs for ' + pin.path);
  return bytes;
}

function queryBinding(root, id, pin) {
  const header = artifact(root, pin).toString('utf8').split('*/', 1)[0];
  requireProof(typeof id === 'string' && id.length > 0 && header.match(/^\s*\*\s+@id\s+(\S+)/m)?.[1] === id,
    'Query source ID differs for ' + id);
  return { id, sha256: pin.sha256, families: familiesFromTags(header.match(/external\/cwe\/cwe-\d+/g) ?? []) };
}

function registeredPolicies(root, bundle, manifest) {
  const plan = json(artifact(root, bundle.plan));
  requireProof(plan.schema === 'factory.recall-codeql-plan.v1' && plan.manifest_sha256 === bundle.manifest.sha256
    && plan.reference_sha256 === bundle.reference.sha256 && plan.engine_version === bundle.engine_version
    && Array.isArray(plan.policies) && plan.policies.length > 0, 'CodeQL plan differs from the registered inputs');
  const ecosystems = new Set(manifest.cases.map(row => row.ecosystem));
  const policies = new Map();
  for (const entry of plan.policies) {
    requireProof(ecosystems.has(entry.ecosystem) && !policies.has(entry.ecosystem)
      && Array.isArray(entry.queries) && entry.queries.length > 0, 'Invalid CodeQL ecosystem policy');
    const queries = entry.queries.map(query => queryBinding(root, query.id, query.source));
    requireProof(new Set(queries.map(q => q.id)).size === queries.length
      && queries.every(q => q.families.length), 'Duplicate or unclassified query in ecosystem policy');
    policies.set(entry.ecosystem, { queries, families: new Set(queries.flatMap(query => query.families)),
      planSha256: bundle.plan.sha256,
      queriesSha256: caseDigest(queries.map(({ id, sha256 }) => ({ id, sha256 }))) });
  }
  const planned = manifest.cases.filter(row => policies.has(row.ecosystem)).map(row => row.ghsa);
  requireProof(Array.isArray(plan.advisory_schedule), 'CodeQL plan schedule is missing');
  const scheduled = new Set(plan.advisory_schedule);
  requireProof(plan.advisory_schedule.length === planned.length && scheduled.size === planned.length
    && planned.every(id => scheduled.has(id)), 'CodeQL plan schedule omits or adds registered cases');
  return policies;
}

// Check the actual archive bytes and exact entry names, lengths and hashes.
const archiveVerifier = String.raw`
import hashlib, json, sys, zipfile
from collections import Counter
def digest_of(content):
    digest = hashlib.sha256()
    for chunk in iter(lambda: content.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()

for item in json.load(sys.stdin):
    with open(item["archive"], "rb") as content:
        if digest_of(content) != item["sha256"]:
            raise ValueError("Source archive hash differs for " + item["side"])
        content.seek(0)
        with zipfile.ZipFile(content) as archive:
            entries = Counter(entry.filename for entry in archive.infolist())
            for packet in item["packets"]:
                name = item["prefix"] + "/" + packet["path"] if item["prefix"] else packet["path"]
                if entries[name] != 1:
                    raise ValueError("Source archive entry is missing or ambiguous for " + item["side"] + ": " + packet["path"])
                entry = archive.getinfo(name)
                with archive.open(entry) as data:
                    if entry.file_size != packet["bytes"] or digest_of(data) != packet["sha256"]:
                        raise ValueError("Source archive packet bytes differ for " + item["side"] + ": " + packet["path"])
`;

function nativeUriPath(uri) {
  const encoded = /^file:\/\/(?=\/)/i.test(uri);
  const path = encoded ? decodeURIComponent(uri.slice(7)) : uri;
  if (!/^\/?[a-z]:[\\/]/i.test(path)) return path;
  const canonical = path.replace(/^\/?([a-z]):/i, (_, drive) => `/${drive.toUpperCase()}:`);
  return encoded ? canonical : canonical.replaceAll('\\', '/');
}

function nativeSourcePath(location, run, packetPaths, roots) {
  const uri = location?.uri;
  requireProof(typeof uri === 'string' && uri.length > 0, 'Native artifact URI is missing');
  const path = nativeUriPath(uri);
  requireProof(!/^[a-z][a-z\d+.-]*:/i.test(path), 'Untrusted native source URI');
  if (location.uriBaseId !== undefined) {
    const base = run.originalUriBaseIds?.[location.uriBaseId];
    const implicitRoot = location.uriBaseId === '%SRCROOT%' && base === undefined;
    const trustedRoot = typeof base?.uri === 'string' && base.uriBaseId === undefined
      && roots.includes(nativeUriPath(base.uri).replace(/\/$/, ''));
    requireProof(implicitRoot || trustedRoot, 'Untrusted native source base');
  }
  const root = roots.find(candidate => path.startsWith(candidate + '/'));
  requireProof(root || !path.startsWith('/'), 'Untrusted native source root');
  const relative = root ? path.slice(root.length + 1) : path;
  const resolved = /^file:\/\//i.test(uri) ? relative : sarifPath(relative, packetPaths);
  requireProof(relativeEntry(resolved) && !resolved.includes('\0'), 'Invalid native source path');
  return resolved;
}

function nativeArtifactPath(location, run, packetPaths, roots) {
  if (location?.index === undefined) return nativeSourcePath(location, run, packetPaths, roots);
  const index = location.index;
  requireProof(Number.isSafeInteger(index) && index >= 0 && index < (run.artifacts?.length ?? 0),
    'Native artifact index is absent');
  const indexed = nativeSourcePath(run.artifacts[index]?.location, run, packetPaths, roots);
  requireProof(location.uri === undefined || nativeSourcePath(location, run, packetPaths, roots) === indexed,
    'Native inline and indexed artifacts disagree');
  return indexed;
}

function nativeCapture(root, capture, side, input, engineVersion, policy) {
  const observed = json(artifact(root, capture?.observation));
  requireProof(observed.case === input.ghsa && observed.side === side && observed.revision === input.revisions[side],
    'Native case or revision differs for ' + side);
  const exactQuery = policy.queries[0];
  const analysisMatches = policy.planSha256
    ? observed.plan_sha256 === policy.planSha256 && observed.queries_sha256 === policy.queriesSha256
    : observed.query === exactQuery.id && observed.query_sha256 === exactQuery.sha256;
  requireProof(analysisMatches && observed.native_sha256 === capture.sarif.sha256,
    'Native query or report binding differs for ' + side);
  requireProof(capture.archive_prefix === '' || relativeEntry(capture.archive_prefix), 'Invalid archive prefix for ' + side);
  const packets = input.source_packets[side];
  requireProof(Array.isArray(packets) && packets.every(p => relativeEntry(p.path)
    && Number.isSafeInteger(p.bytes) && p.bytes >= 0 && digest.test(p.sha256))
    && new Set(packets.map(p => p.path)).size === packets.length, 'Invalid source packet list for ' + side);

  const report = json(artifact(root, capture.sarif));
  const run = report.runs?.[0];
  const driver = run?.tool?.driver;
  requireProof(report.version === '2.1.0' && report.runs?.length === 1
    && driver?.name === 'CodeQL' && (driver.semanticVersion ?? driver.version) === engineVersion
    && Array.isArray(run.results) && Array.isArray(run.invocations) && run.invocations.length > 0
    && run.invocations.every(call => call.executionSuccessful === true
      && !call.toolExecutionNotifications?.some(note => note.level === 'error')), 'Unqualified CodeQL report for ' + side);
  const descriptors = new Map((driver.rules ?? []).map(rule => [rule.id, rule]));
  requireProof(descriptors.size === policy.queries.length && descriptors.size === driver.rules?.length
    && run.results.every(result => descriptors.has(result.ruleId)) && run.results.length === observed.reported_alerts,
    'CodeQL query inventory or alert count differs for ' + side);
  for (const query of policy.queries) {
    requireProof(descriptors.has(query.id), 'CodeQL query ID differs for ' + side);
    const tags = descriptors.get(query.id).properties?.tags ?? [];
    requireProof(JSON.stringify(query.families) === JSON.stringify(familiesFromTags(tags)),
      'CodeQL family metadata differs for ' + side);
  }
  const packetPaths = new Set(packets.map(p => p.path));
  const roots = ['/src'];
  if (capture.archive_prefix) {
    // CodeQL encodes Windows drive roots as entries such as D_/work/src.
    const archiveRoot = '/' + capture.archive_prefix.replace(/^([a-z])_\//i, (_, drive) => drive.toUpperCase() + ':/');
    roots.unshift(archiveRoot);
  }
  const findings = sarifFindings(report, packetPaths, id => id,
    (location, run) => nativeArtifactPath(location, run, packetPaths, roots));
  requireProof(findings.length === run.results.length
    && findings.every(finding => finding.path && Number.isSafeInteger(finding.line) && finding.line > 0),
    'Native alert location is missing for ' + side);
  return { findings,
    archive: { archive: boundPath(root, capture.archive), sha256: capture.archive.sha256,
      prefix: capture.archive_prefix, packets, side: input.ghsa + '/' + side } };
}

function nativeDisposition(native, pattern, outcome) {
  if (!native.hunk_hit) return 'native_miss';
  if (outcome === 'hit') return 'overlap';
  if (outcome !== 'miss') return 'pattern_unresolved';
  if (native.fixed_hunk_residuals || pattern.fix_side_residual.length) return 'fixed_side_residual';
  return completeFixedCoverage(pattern.file_coverage?.fixed, pattern.source_packets?.fixed)
    ? 'eligible' : 'fixed_coverage_unresolved';
}

function joinPatternScore(pin, manifestSha, casesSha, cases, referenceCases, observations) {
  requireProof(typeof pin.path === 'string' && digest.test(pin.sha256), 'Pattern score path and SHA-256 are required');
  const bytes = readFileSync(pin.path);
  requireProof(sha256(bytes) === pin.sha256, 'Pattern score digest mismatch');
  const score = json(bytes);
  requireProof(score.schema === 'factory.recall-result.v1' && score.scope === 'ecosystem'
    && score.manifest_sha256 === manifestSha && score.manifest_cases_sha256 === casesSha
    && digest.test(score.ruleset_sha256) && digest.test(score.profile_sha256) && digest.test(score.engine?.executable_sha256)
    && Array.isArray(score.cases) && score.cases.length === cases.size && score.summary?.cases === cases.size,
  'Pattern score is for another registered cohort or lacks scanner pins');

  const pattern = new Map();
  const outcomes = new Map();
  for (const row of score.cases) {
    const registered = cases.get(row.ghsa);
    requireProof(registered && !pattern.has(row.ghsa), 'Missing or duplicate registered pattern case');
    const metadata = Object.fromEntries(Object.keys(registered).map(key => [key, row[key]]));
    requireProof(caseDigest([metadata]) === caseDigest([registered])
      && inputFingerprint(row) === referenceCases.get(row.ghsa).input_sha256,
    'Pattern case input differs from registered evidence for ' + row.ghsa);
    const outcome = outcomeOf(row);
    requireProof(row.outcome === outcome && Array.isArray(row.fix_side_residual)
      && (outcome !== 'hit' || row.hunk_findings?.length > 0), 'Pattern outcome evidence differs for ' + row.ghsa);
    pattern.set(row.ghsa, row);
    outcomes.set(row.ghsa, outcome);
  }
  const hunkHits = [...outcomes.values()].filter(outcome => outcome === 'hit').length;
  requireProof(score.summary.hunk_hits === hunkHits, 'Pattern hit count differs');
  const dispositions = observations.map(native => {
    const row = pattern.get(native.advisory), outcome = outcomes.get(native.advisory);
    return { advisory: native.advisory, input_sha256: native.input_sha256, pattern_outcome: outcome,
      disposition: nativeDisposition(native, row, outcome) };
  });
  const additions = dispositions.filter(row => row.disposition === 'eligible').length;
  return { scope: 'supplemental paired comparison', pattern_score_sha256: pin.sha256, pattern_hunk_hits: hunkHits,
    verified_pattern_cases: pattern.size, verified_native_pairs: dispositions.length,
    eligible_native_additions: additions, combined_hunk_hits: hunkHits + additions, cases: dispositions };
}

function readPairRegistry(root, bundle) {
  const manifest = json(artifact(root, bundle.manifest));
  const manifestDigest = validateRecallManifest(manifest);
  const reference = json(artifact(root, bundle.reference));
  requireProof(reference.schema === 'factory.recall-exposed-run-readback.v1'
    && reference.manifest_sha256 === bundle.manifest.sha256 && reference.manifest_cases_sha256 === manifestDigest
    && reference.cases?.length === manifest.cases.length, 'Reference is for another registered cohort');

  const cases = new Map(manifest.cases.map(row => [row.ghsa, row]));
  const referenceCases = new Map(reference.cases.map(row => [row.advisory, row]));
  requireProof(referenceCases.size === cases.size && [...cases.keys()].every(id => referenceCases.has(id))
    && reference.candidate?.registered === cases.size
    && reference.candidate.hunk_hits === reference.cases.filter(row => row.after === 'hit').length,
    'Reference case inventory or hit count differs');
  return { manifest, manifestDigest, reference, cases, referenceCases };
}

function scorePreparedPair(row, { root, cases, referenceCases, policies, engineVersion, archives }) {
  const registered = cases.get(row.advisory);
  const before = referenceCases.get(row.advisory);
  requireProof(registered && before, 'CodeQL advisory is absent from the registered cohort');
  const prepared = json(artifact(root, row.prepared));
  requireProof(prepared.status === 'ready' && prepared.case_sha256 === caseDigest([registered])
    && prepared.revisions?.fixed === registered.fix && revision.test(prepared.revisions.old),
    'Prepared case revision or registry differs for ' + row.advisory);
  const input = { ghsa: row.advisory, revisions: prepared.revisions, source_packets: prepared.source_packets,
    diff_sha256: prepared.diff_sha256, changed_files_sha256: prepared.changed_files_sha256 };
  requireProof(inputFingerprint(input) === before.input_sha256,
    'Prepared case bytes differ from the reference for ' + row.advisory);

  const families = familiesFor(registered.cwes);
  const policy = policies ? policies.get(registered.ecosystem) : { queries: [queryBinding(root, row.query_id, row.query)] };
  requireProof(policy, 'No registered CodeQL ecosystem policy for ' + row.advisory);
  if (!policies) {
    requireProof(policy.queries[0].families.some(family => families.includes(family)),
      'CodeQL query family differs for ' + row.advisory);
  }
  const old = nativeCapture(root, row.old, 'old', input, engineVersion, policy);
  const fixed = nativeCapture(root, row.fixed, 'fixed', input, engineVersion, policy);
  archives.push(old.archive, fixed.archive);

  const preparedDir = dirname(row.prepared.path);
  const patch = artifact(root, { path: join(preparedDir, 'diff.patch'), sha256: input.diff_sha256 });
  artifact(root, { path: join(preparedDir, 'changes.z'), sha256: input.changed_files_sha256 });
  const editedLines = {};
  const hunks = parseHunks(patch.toString('utf8'), scopeExtensions(registered.ecosystem), editedLines);
  const score = scoreCase({ families, hunks, editedLines, oldFindings: old.findings, newFindings: fixed.findings,
    rules: Object.fromEntries(policy.queries.map(query => [query.id, query.families])) });
  return { advisory: row.advisory, reference: before.after, input_sha256: before.input_sha256,
    ...(policies ? { queries_sha256: policy.queriesSha256 } : { query_id: row.query_id }), hunk_hit: score.hunk_hit,
    trace_hit: score.trace_hit, matched_hunk_families: score.matched_hunk_families,
    hunk_matches: score.hunk_findings, fixed_hunk_matches: score.fix_side_residual,
    deleted_line_hit: score.edited_lines.deleted_line_hit, fixed_hunk_residuals: score.fix_side_residual.length,
    native_alerts: { old: old.findings.length, fixed: fixed.findings.length },
    packets: { old: old.archive.packets.length, fixed: fixed.archive.packets.length } };
}

function verifySourceArchives(archives) {
  const verified = spawnSync(process.env.CF_RECALL_PYTHON ?? 'python', ['-I', '-c', archiveVerifier],
    { input: JSON.stringify(archives), encoding: 'utf8', windowsHide: true });
  if (verified.error) throw verified.error;
  requireProof(verified.status === 0, 'Source archive verification failed: ' + verified.stderr.trim());
}

function scheduledCoverage(plan, policies, manifest, observations) {
  const cohortCoverage = {};
  if (policies) {
    const observed = new Set(observations.map(row => row.advisory));
    const eligible = manifest.cases.filter(row => policies.has(row.ecosystem));
    cohortCoverage.plan_sha256 = plan.sha256;
    cohortCoverage.planned_cases = eligible.length;
    cohortCoverage.unobserved_advisories = eligible.filter(row => !observed.has(row.ghsa)).map(row => row.ghsa);
    cohortCoverage.unsupported_advisories = manifest.cases.filter(row => !policies.has(row.ecosystem)).map(row => row.ghsa);
    cohortCoverage.uncovered_advisory_families = eligible.flatMap(row => {
      const unsupported = familiesFor(row.cwes).filter(family => !policies.get(row.ecosystem).families.has(family));
      return unsupported.length ? [{ advisory: row.ghsa, families: unsupported }] : [];
    });
  }
  return cohortCoverage;
}

export function scoreCodeqlPairs(bundlePath, patternPin = null) {
  const bytes = readFileSync(bundlePath);
  const root = realpathSync(dirname(bundlePath));
  const bundle = json(bytes);
  requireProof([FORMAT, PLAN_BUNDLE].includes(bundle.schema) && typeof bundle.engine_version === 'string'
    && Array.isArray(bundle.cases) && bundle.cases.length > 0, 'Invalid paired CodeQL bundle');
  const { manifest, manifestDigest, reference, cases, referenceCases } = readPairRegistry(root, bundle);
  requireProof(new Set(bundle.cases.map(row => row.advisory)).size === bundle.cases.length,
    'Duplicate CodeQL advisory pair');
  const policies = bundle.schema === PLAN_BUNDLE ? registeredPolicies(root, bundle, manifest) : null;

  const archives = [];
  const observations = bundle.cases.map(row => scorePreparedPair(row, { root, cases, referenceCases,
    policies, engineVersion: bundle.engine_version, archives }));
  verifySourceArchives(archives);
  const cohortCoverage = scheduledCoverage(bundle.plan, policies, manifest, observations);
  const patternJoin = patternPin && joinPatternScore(patternPin, bundle.manifest.sha256, manifestDigest, cases, referenceCases, observations);
  return { schema: 'factory.recall-codeql-pair-score.v1', scope: policies ? 'registered-codeql-plan' : 'supplemental',
    input_sha256: sha256(bytes), ...cohortCoverage, ...(patternJoin ? { pattern_join: patternJoin } : {}),
    reference_sha256: bundle.reference.sha256, registered_cases: cases.size, reference_hunk_hits: reference.candidate.hunk_hits,
    scored_pairs: observations.length, strict_hunk_hits: observations.filter(row => row.hunk_hit).length,
    strict_hits_on_reference_misses: observations.filter(row => row.reference === 'miss' && row.hunk_hit).length,
    deleted_line_hits: observations.filter(row => row.deleted_line_hit).length,
    fixed_hunk_residuals: observations.reduce((sum, row) => sum + row.fixed_hunk_residuals, 0), cases: observations };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [bundle, out, ...extra] = process.argv.slice(2);
    const [flag, path, hashFlag, sha256] = extra;
    requireProof(bundle && out && (!extra.length || (extra.length === 4 && flag === '--pattern-score'
      && hashFlag === '--pattern-score-sha256')),
    'Usage: node scripts/recall_codeql_pairs.mjs BUNDLE OUTPUT [--pattern-score FILE --pattern-score-sha256 HEX]');
    const receipt = scoreCodeqlPairs(bundle, extra.length ? { path, sha256 } : null);
    writeFileSync(out, JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx' });
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
