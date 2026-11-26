#!/usr/bin/env node
// Supplementary scoring of paired native SARIF against a registered reference.
// The bundle pins the cohort, reference, and each prepared case and query.
// Each old/fixed capture pins observation JSON, SARIF and the CodeQL source ZIP.
// Artifact paths are relative to the bundle, and archive prefixes identify source roots.
import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { caseDigest, familiesFor, parseHunks, reviewCapturePath, sarifFindings, scopeExtensions,
  scoreCase, sha256, sortKeys, validateRecallManifest } from './recall_harness.mjs';

const FORMAT = 'factory.recall-codeql-pairs.v1';
const digest = /^[0-9a-f]{64}$/;
const revision = /^[0-9a-f]{40}$/;
const relativeEntry = path => typeof path === 'string' && !path.includes('\\')
  && path.split('/').every(part => part && part !== '.' && part !== '..');
const json = bytes => JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, ''));
const familiesFromTags = tags => familiesFor(tags.flatMap(tag => {
  const match = /^external\/cwe\/cwe-(\d+)$/.exec(tag);
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

function nativeCapture(root, capture, side, input, engineVersion, query) {
  const observed = json(artifact(root, capture?.observation));
  requireProof(observed.case === input.ghsa && observed.side === side && observed.revision === input.revisions[side],
    'Native case or revision differs for ' + side);
  requireProof(observed.query === query.id && observed.query_sha256 === query.sha256
    && observed.native_sha256 === capture.sarif.sha256, 'Native query or report binding differs for ' + side);
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
  const descriptors = driver.rules?.filter(rule => rule.id === query.id);
  requireProof(descriptors?.length === 1 && run.results.every(result => result.ruleId === query.id)
    && run.results.length === observed.reported_alerts, 'CodeQL query or alert count differs for ' + side);
  requireProof(JSON.stringify(query.families) === JSON.stringify(familiesFromTags(descriptors[0].properties?.tags ?? [])),
    'CodeQL family metadata differs for ' + side);
  const findings = sarifFindings(report, new Set(packets.map(p => p.path))).map(finding => ({ ...finding, rule: query.id }));
  requireProof(findings.length === run.results.length
    && findings.every(finding => finding.path && Number.isSafeInteger(finding.line) && finding.line > 0),
    'Native alert location is missing for ' + side);
  return { findings,
    archive: { archive: boundPath(root, capture.archive), sha256: capture.archive.sha256,
      prefix: capture.archive_prefix, packets, side: input.ghsa + '/' + side } };
}

export function scoreCodeqlPairs(bundlePath) {
  const bytes = readFileSync(bundlePath);
  const root = realpathSync(dirname(bundlePath));
  const bundle = json(bytes);
  requireProof(bundle.schema === FORMAT && typeof bundle.engine_version === 'string'
    && Array.isArray(bundle.cases) && bundle.cases.length > 0, 'Invalid paired CodeQL bundle');
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
  requireProof(new Set(bundle.cases.map(row => row.advisory)).size === bundle.cases.length,
    'Duplicate CodeQL advisory pair');

  const archives = [];
  const observations = bundle.cases.map(row => {
    const registered = cases.get(row.advisory);
    const before = referenceCases.get(row.advisory);
    requireProof(registered && before, 'CodeQL advisory is absent from the registered cohort');
    const prepared = json(artifact(root, row.prepared));
    requireProof(prepared.status === 'ready' && prepared.case_sha256 === caseDigest([registered])
      && prepared.revisions?.fixed === registered.fix && revision.test(prepared.revisions.old),
      'Prepared case revision or registry differs for ' + row.advisory);
    const input = { ghsa: row.advisory, revisions: prepared.revisions, source_packets: prepared.source_packets,
      diff_sha256: prepared.diff_sha256, changed_files_sha256: prepared.changed_files_sha256 };
    requireProof(sha256(JSON.stringify(sortKeys(input))) === before.input_sha256,
      'Prepared case bytes differ from the reference for ' + row.advisory);

    const queryHeader = artifact(root, row.query).toString('utf8').split('*/', 1)[0];
    const id = /^\s*\*\s+@id\s+(\S+)/m.exec(queryHeader)?.[1];
    requireProof(id && id === row.query_id,
      'Query source ID differs for ' + row.advisory);
    const query = { id, sha256: row.query.sha256,
      families: familiesFromTags(queryHeader.match(/external\/cwe\/cwe-\d+/g) ?? []) };
    const old = nativeCapture(root, row.old, 'old', input, bundle.engine_version, query);
    const fixed = nativeCapture(root, row.fixed, 'fixed', input, bundle.engine_version, query);
    const families = familiesFor(registered.cwes);
    requireProof(query.families.some(family => families.includes(family)), 'CodeQL query family differs for ' + row.advisory);
    archives.push(old.archive, fixed.archive);

    const preparedDir = dirname(row.prepared.path);
    const patch = artifact(root, { path: join(preparedDir, 'diff.patch'), sha256: input.diff_sha256 });
    artifact(root, { path: join(preparedDir, 'changes.z'), sha256: input.changed_files_sha256 });
    const editedLines = {};
    const hunks = parseHunks(patch.toString('utf8'), scopeExtensions(registered.ecosystem), editedLines);
    const score = scoreCase({ families, hunks, editedLines, oldFindings: old.findings, newFindings: fixed.findings,
      rules: { [query.id]: query.families } });
    return { advisory: row.advisory, reference: before.after, query_id: row.query_id, hunk_hit: score.hunk_hit,
      trace_hit: score.trace_hit, matched_hunk_families: score.matched_hunk_families,
      hunk_matches: score.hunk_findings, fixed_hunk_matches: score.fix_side_residual,
      deleted_line_hit: score.edited_lines.deleted_line_hit, fixed_hunk_residuals: score.fix_side_residual.length,
      native_alerts: { old: old.findings.length, fixed: fixed.findings.length },
      packets: { old: old.archive.packets.length, fixed: fixed.archive.packets.length } };
  });
  const verified = spawnSync(process.env.CF_RECALL_PYTHON ?? 'python', ['-I', '-c', archiveVerifier],
    { input: JSON.stringify(archives), encoding: 'utf8', windowsHide: true });
  if (verified.error) throw verified.error;
  requireProof(verified.status === 0, 'Source archive verification failed: ' + verified.stderr.trim());
  return { schema: 'factory.recall-codeql-pair-score.v1', scope: 'supplemental', input_sha256: sha256(bytes),
    reference_sha256: bundle.reference.sha256, registered_cases: cases.size, reference_hunk_hits: reference.candidate.hunk_hits,
    scored_pairs: observations.length, strict_hunk_hits: observations.filter(row => row.hunk_hit).length,
    strict_hits_on_reference_misses: observations.filter(row => row.reference === 'miss' && row.hunk_hit).length,
    deleted_line_hits: observations.filter(row => row.deleted_line_hit).length,
    fixed_hunk_residuals: observations.reduce((sum, row) => sum + row.fixed_hunk_residuals, 0), cases: observations };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [bundle, out, ...extra] = process.argv.slice(2);
    requireProof(bundle && out && !extra.length, 'Usage: node scripts/recall_codeql_pairs.mjs BUNDLE OUTPUT');
    writeFileSync(out, JSON.stringify(scoreCodeqlPairs(bundle), null, 2) + '\n', { flag: 'wx' });
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
