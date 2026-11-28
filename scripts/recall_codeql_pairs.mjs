#!/usr/bin/env node
// Supplementary scoring of paired native SARIF against a registered reference.
// A v1 bundle pins the query for each targeted case. A v2 bundle pins a
// separate plan that assigns one query inventory to each supported ecosystem.
// Each old/fixed capture pins observation JSON, SARIF and the CodeQL source ZIP.
// A v2 row may reuse a verified capture from another advisory in the same plan.
// A cohort bundle joins pinned, advisory-disjoint pair bundles from one registry.
// Artifact paths are relative to the bundle, and archive prefixes identify source roots.
import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { anchoredTraceMatches, caseDigest, sarifTraceThreads, lineCoordinatesOnly, familiesFor, outcomeOf, parseHunks, reviewCapturePath, sarifFindings, scopeExtensions,
  scoreCase, sha256, validateRecallManifest } from './recall_harness.mjs';
import { changedFiles, completeFixedCoverage as completePatternCoverage, sarifPath } from './recall_coverage.mjs';
import { inputFingerprint } from './verify_registered_recall.mjs';

const FORMAT = 'factory.recall-codeql-pairs.v1';
const PLAN_BUNDLE = 'factory.recall-codeql-pairs.v2';
const COHORT_BUNDLE = 'factory.recall-codeql-cohort.v1';
const ARM_COHORT = 'factory.recall-codeql-cohort.v2';
const extractionDiagnostics = new Map([
  ['Go', 'go/diagnostics/successfully-extracted-files'],
  ['Maven', 'java/diagnostics/successfully-extracted-files'],
  ['NuGet', 'cs/diagnostics/successfully-extracted-files'],
  ['npm', 'factory/js/diagnostics/parsed-source-files'],
  ['PyPI', 'py/diagnostics/successfully-extracted-files'],
  ['RubyGems', 'rb/diagnostics/successfully-extracted-files'],
  ['crates.io', 'rust/diagnostics/successfully-extracted-files'],
]);
const digest = /^[0-9a-f]{64}$/;
const revision = /^[0-9a-f]{40}$/;
const extractionErrors = new Set(['cs/diagnostics/extraction-errors', 'rust/diagnostics/extraction-errors']);
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

function readPinnedArtifact(path, pin) {
  const bytes = readFileSync(path);
  requireProof(sha256(bytes) === pin.sha256, 'Artifact fingerprint differs for ' + pin.path);
  return bytes;
}

function artifact(root, pin) {
  return readPinnedArtifact(boundPath(root, pin), pin);
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

def verify_group(items):
    bindings = {}
    for item in items:
        with open(item["archive"], "rb") as content:
            if digest_of(content) != item["sha256"]:
                raise ValueError("Source archive hash differs for " + item["side"])
            content.seek(0)
            with zipfile.ZipFile(content) as archive:
                entries = Counter(entry.filename for entry in archive.infolist())
                verified = {}
                for packet in item["packets"]:
                    name = item["prefix"] + "/" + packet["path"] if item["prefix"] else packet["path"]
                    if entries[name] != 1:
                        raise ValueError("Source archive entry is missing or ambiguous for " + item["side"] + ": " + packet["path"])
                    entry = archive.getinfo(name)
                    with archive.open(entry) as data:
                        if entry.file_size != packet["bytes"] or digest_of(data) != packet["sha256"]:
                            raise ValueError("Source archive packet bytes differ for " + item["side"] + ": " + packet["path"])
                    verified[packet["path"]] = {"state": "packet_verified", "sha256": packet["sha256"]}
                side_bindings = []
                for path in item["references"]:
                    name = item["prefix"] + "/" + path if item["prefix"] else path
                    if path in verified:
                        binding = verified[path]
                    elif entries[name] == 1 and not archive.getinfo(name).is_dir():
                        with archive.open(name) as data:
                            binding = {"state": "archive_verified", "sha256": digest_of(data)}
                    else:
                        binding = {"state": "ambiguous" if entries[name] > 1 else "missing"}
                    side_bindings.append({"path": path, **binding})
                bindings[item["side"]] = side_bindings
    return bindings

print(json.dumps([verify_group(items) for items in json.load(sys.stdin)], separators=(",", ":")))
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

function captureFingerprints(capture, revision, policy, packets, findings, flows) {
  const locations = findings.map(({ rule, path, line, span, trace }) =>
    ({ rule, path, line, span: span ?? null, trace: trace ?? [] }));
  const steps = flows.flat(3);
  return { revision, query_sha256: policy.queriesSha256 ?? policy.queries[0].sha256,
    packet_list_sha256: caseDigest(packets), observation_sha256: capture.observation.sha256,
    sarif_sha256: capture.sarif.sha256, archive_sha256: capture.archive.sha256,
    location_trace_sha256: caseDigest(locations), flow_trace_sha256: caseDigest(flows),
    trace_steps: steps.length, nonphysical_trace_steps: steps.filter(step => step.state === 'nonphysical').length,
    invalid_trace_steps: steps.filter(step => step.state === 'invalid_line').length,
    traced_findings: locations.filter(row => row.trace.length).length };
}

function nativeExtractionCoverage(invocations, packetPaths, resolvePath, extractionId) {
  const extracted = new Set();
  const parseFailed = new Set();
  let unlocatedErrors = 0;
  for (const invocation of invocations) {
    for (const note of invocation.toolExecutionNotifications ?? []) {
      const id = note.descriptor?.id ?? '';
      // Rust can report extracted syntax even when semantic analysis failed.
      const extractionError = extractionErrors.has(id)
        || (extractionId === extractionDiagnostics.get('crates.io') && id === 'rust/diagnostics/extraction-warnings');
      const paths = id === extractionId ? extracted
        : extractionError || /(?:parse|syntax)[_-]?(?:error|failure)/i.test(id) ? parseFailed : null;
      if (!paths) continue;
      let located = false, unresolved = false;
      for (const entry of note.locations ?? []) {
        const location = entry.physicalLocation?.artifactLocation;
        if (!location) { unresolved = true; continue; }
        // A whole-repo extraction can also report files outside the bound packets.
        let path;
        try { path = resolvePath(location); } catch { unresolved = true; continue; }
        located = true;
        if (packetPaths.has(path)) paths.add(path);
      }
      if (paths === parseFailed && (!located || unresolved)) unlocatedErrors++;
    }
  }
  const expected = [...packetPaths].sort();
  const missing = expected.filter(path => !extracted.has(path));
  return { expected, extracted: [...extracted].sort(), parse_failed: [...parseFailed].sort(),
    ...(unlocatedErrors ? { unlocated_extraction_errors: unlocatedErrors } : {}),
    missing, complete: !missing.length && !parseFailed.size && !unlocatedErrors };
}

function nativeCapture(root, capture, side, input, engineVersion, policy, extractionId) {
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
  requireProof(!run.invocations.some(call => call.toolExecutionNotifications?.some(note =>
    note.descriptor?.id === 'java/autobuilder/buildless/classpath-from-tool-failed')),
    'Unqualified CodeQL Java classpath for ' + side);
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
  const resolvePath = location => nativeArtifactPath(location, run, packetPaths, roots);
  const coverage = nativeExtractionCoverage(run.invocations, packetPaths, resolvePath, extractionId);
  const findings = sarifFindings(report, packetPaths, id => id, resolvePath);
  requireProof(findings.length === run.results.length
    && findings.every(finding => finding.path && Number.isSafeInteger(finding.line) && finding.line > 0),
    'Native alert location is missing for ' + side);
  const flows = run.results.map(result => sarifTraceThreads(result, resolvePath, true));
  const locationsUnresolved = run.results.map(({ locations }) => locations.length !== 1
    || !lineCoordinatesOnly(locations[0].physicalLocation?.region));
  const references = [...new Set([...findings.map(row => row.path),
    ...flows.flat(3).map(step => step.path).filter(Boolean)])].sort();
  return { findings, flows, locationsUnresolved, coverage,
    fingerprints: { ...captureFingerprints(capture, input.revisions[side], policy, packets, findings, flows),
      extraction_coverage_sha256: caseDigest([coverage]) },
    archive: { archive: boundPath(root, capture.archive), sha256: capture.archive.sha256,
      prefix: capture.archive_prefix, packets, references, side: input.ghsa + '/' + side } };
}

const pendingFamilyAlerts = Symbol('pendingFamilyAlerts');

function collectFamilyAlerts(old, fixed, families, rules, changes) {
  const wanted = new Set(families);
  const selected = new Set(Object.keys(rules).filter(rule => rules[rule].some(family => wanted.has(family))));
  if (!selected.size) {
    const empty = { total: 0, outside: [], unresolved: 0 };
    return { matching_query_count: 0, old: empty, fixed: empty };
  }
  const oldPaths = new Set(changes.filter(change => change.status !== 'A').map(change => change.path));
  const fixedPaths = new Set(changes.filter(change => change.status !== 'D').map(change => change.path));
  const side = (capture, changed) => {
    const outside = [];
    let total = 0, unresolved = 0;
    for (const [index, row] of capture.findings.entries()) {
      if (!selected.has(row.rule)) continue;
      total++;
      const locationsUnresolved = capture.locationsUnresolved[index];
      if (locationsUnresolved) unresolved++;
      if (!changed(row.path)) outside.push({ row, flows: capture.flows[index], locationsUnresolved });
    }
    return { total, outside, unresolved };
  };
  return { matching_query_count: selected.size, old: side(old, path => oldPaths.has(path)),
    fixed: side(fixed, path => fixedPaths.has(path)) };
}

function fingerprintAlert({ row, flows, locationsUnresolved }, bindings) {
  const hash = bindings.get(row.path)?.sha256;
  if (!hash || locationsUnresolved) return null;
  const trace = flows.map(flow => flow.map(thread => thread.map(step => step.state === 'nonphysical'
    ? null : [step.path, step.line, bindings.get(step.path)?.sha256, (step.state ?? step.mixed_coordinates) ?? null, step.span ?? null])));
  if (trace.flat(2).some(step => !step || !step[2] || step[3])) return null;
  return JSON.stringify([row.rule, row.path, row.line, row.span ?? null, hash, trace]);
}

function summarizeFamilyAlerts(input, sources) {
  const keys = (rows, bindings) => {
    const counts = new Map();
    for (const alert of rows) {
      const key = fingerprintAlert(alert, bindings);
      if (key) counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return counts;
  };
  const old = keys(input.old.outside, sources.old);
  const fixed = keys(input.fixed.outside, sources.fixed);
  const retained = [...old].reduce((sum, [key, count]) => sum + Math.min(count, fixed.get(key) ?? 0), 0);
  const side = ({ total, outside, unresolved }, counts) => ({
    total, changed_file: total - outside.length, outside_changed_files: outside.length, unresolved_locations: unresolved,
    byte_verified_outside: [...counts.values()].reduce((sum, count) => sum + count, 0),
  });
  return { matching_query_count: input.matching_query_count,
    unresolved_locations: input.old.unresolved + input.fixed.unresolved,
    old: side(input.old, old), fixed: side(input.fixed, fixed), retained_outside: retained };
}

function nativeSearchFollowUp(arms) {
  const evidence = arms.map(arm => arm.native_family_alerts).filter(row => row?.matching_query_count);
  if (evidence.some(row => row.old.changed_file || row.fixed.changed_file)) return 'review_bound_path';
  const review = evidence.some(row => Math.max(row.old.outside_changed_files, row.fixed.outside_changed_files) > row.retained_outside);
  if (review) return 'review_nonlocal_family_alerts';
  return evidence.length ? 'enhance_native_family_model' : 'completed_native_search';
}

function unmatchedNativeDisposition(native, extractionComplete) {
  if (!extractionComplete) return 'native_extraction_unresolved';
  return native.fixed_hunk_residuals ? 'fixed_side_residual' : 'native_miss';
}

function nativeDisposition(native, pattern, outcome, extractionComplete, coverageGap) {
  if (!native.hunk_hit) return unmatchedNativeDisposition(native, extractionComplete);
  if (outcome === 'hit') return 'overlap';
  if (outcome !== 'miss') return 'pattern_unresolved';
  if (native.fixed_hunk_residuals || pattern.fix_side_residual.length) return 'fixed_side_residual';
  if (native.native_family_alerts?.unresolved_locations) return 'native_alert_locations_unresolved';
  if (Object.values(native.fingerprints).some(side => side.trace_source_states.missing
    || side.trace_source_states.ambiguous || side.invalid_trace_steps)) return 'native_trace_source_unresolved';
  if (coverageGap) return coverageGap;
  return extractionComplete ? 'eligible' : 'native_extraction_unresolved';
}

function patternCaptureState(row, side) {
  const packets = row.source_packets?.[side];
  const capture = row.captures?.[side], notes = row.scan_sides?.[side];
  if (!Array.isArray(packets)) return 'missing_inventory';
  if (!packets.length && !capture && !notes) return 'no_in_scope_source';
  if (!capture?.sarif || !capture?.native_report || !notes) return 'missing_capture';
  const sameReport = (report, hash) => relativeEntry(report.path) && digest.test(hash) && report.sha256 === hash;
  const complete = relativeEntry(capture.source_root) && notes.failed_exit === false
    && [0, 1].includes(notes.exit_code) && notes.timeouts === 0 && notes.other === 0
    && notes.blocking_parse_errors === 0 && sameReport(capture.sarif, notes.report_sha256)
    && sameReport(capture.native_report, notes.coverage_report_sha256);
  return packets.length && complete ? 'report_pinned' : 'unverified_capture';
}

function patternCoverageGap(pattern, captureStates) {
  for (const side of ['old', 'fixed']) {
    if (captureStates[side] === 'no_in_scope_source') continue;
    if (captureStates[side] !== 'report_pinned'
      || !completePatternCoverage(pattern.file_coverage?.[side], pattern.source_packets?.[side])) {
      return side + '_coverage_unresolved';
    }
  }
  return null;
}

function joinedDisposition(selected, native, evidence) {
  if (selected.disposition !== 'eligible') return selected.disposition;
  if (native.fixed_hunk_residuals) return 'fixed_side_residual';
  if (evidence.some(({ arm }) => arm.native_family_alerts?.fixed.unresolved_locations)) {
    return 'native_alert_locations_unresolved';
  }
  return 'eligible';
}

function searchedFileHit(row, outcome) {
  return ['hit', 'miss'].includes(outcome) && row.file_hit;
}

function verifiedPatternOutcome(row) {
  const outcome = outcomeOf(row);
  requireProof(row.outcome === outcome && Array.isArray(row.fix_side_residual)
    && typeof row.file_hit === 'boolean', 'Pattern outcome evidence differs for ' + row.ghsa);
  requireProof(outcome !== 'hit' || (row.hunk_findings?.length > 0 && row.file_hit),
    'Pattern hunk evidence differs for ' + row.ghsa);
  return outcome;
}

function pendingEvidence(pattern, outcomes, coverageGaps, referenceCases, dispositions, observations, plans) {
  const native = new Map(dispositions.map(row => [row.advisory, row]));
  const anchored = new Set(observations.filter(row => row.anchored_trace_matches?.length).map(row => row.advisory));
  return [...pattern].flatMap(([advisory, row]) => {
    const outcome = outcomes.get(advisory), result = native.get(advisory);
    if (outcome === 'hit' || result?.disposition === 'eligible') return [];
    const registered = plans.filter(plan => !plan.unsupported_advisories.includes(advisory));
    const families = familiesFor(row.cwes);
    const compatible = registered.filter(plan => !plan.uncovered_advisory_families.some(
      gap => gap.advisory === advisory && families.every(family => gap.families.includes(family))));
    const arms = result?.arm_dispositions.filter(arm => arm.families.some(family => families.includes(family))) ?? [];
    const attempted = new Set(arms.map(arm => arm.plan_sha256));
    const readyPlans = [...new Set(compatible.map(plan => plan.plan_sha256))]
      .filter(plan => !attempted.has(plan)).sort();
    let next;
    if (outcome !== 'miss' || coverageGaps.get(advisory)) {
      next = 'resolve_pattern_coverage';
    }
    else if (result?.disposition === 'fixed_side_residual') next = 'review_fixed_side_path';
    else if (result?.disposition === 'native_alert_locations_unresolved') next = 'review_native_alert_locations';
    else if (arms.some(arm => !arm.extraction_complete)) next = 'resolve_native_extraction';
    else if (result?.pattern_file_hit || result?.native_file_hit || result?.native_hunk_hit || anchored.has(advisory)) {
      next = 'review_bound_path';
    } else if (readyPlans.length) next = 'capture_registered_pair';
    else if (arms.length) next = nativeSearchFollowUp(arms);
    else next = registered.length ? 'native_family_unmapped' : 'no_registered_native_plan';
    return [{ advisory, input_sha256: referenceCases.get(advisory).input_sha256,
      pattern_outcome: outcome, next, plan_sha256s: next === 'capture_registered_pair' ? readyPlans : [] }];
  });
}

const contextualSource = /\.(?:blade\.php|erb|html?|jinja2?|j2|svelte|twig|vue|xml|ya?ml|toml|sql|properties|sh)$/i;

function sourceRoute(file, packet, nativePaths, extensions, findings, capturePinned) {
  if (packet) {
    const parsed = capturePinned && file?.sha256 === packet.sha256 && file.bytes === packet.bytes
      && file.submitted === true && file.state === 'reported_scanned' && file.reason === 'engine_scan_paths';
    return { ...packet, state: parsed ? 'pattern_parsed' : nativePaths.has(packet.path) ? 'native_parsed' : 'parser_recheck',
      pattern_reason: file?.reason ?? 'missing_parser_receipt', hunk_findings: findings.get(packet.path) ?? 0 };
  }
  if (file?.reason !== 'outside_ecosystem_language') return null;
  if (extensions.some(ext => file.path.endsWith('.' + ext))) return { path: file.path, state: 'cross_language' };
  return contextualSource.test(file.path) ? { path: file.path, state: 'context_required' } : null;
}

function sourceRouting(row, arms, captureStates) {
  const extensions = scopeExtensions(row.ecosystem, 'scannable');
  return Object.fromEntries(['old', 'fixed'].map(side => {
    const coverage = row.file_coverage?.[side] ?? [];
    const byPath = new Map();
    for (const file of coverage) byPath.set(file.path, byPath.has(file.path) ? null : file);
    const packets = new Map((row.source_packets?.[side] ?? []).map(packet => [packet.path, packet]));
    const paths = [...new Set([...byPath.keys(), ...packets.keys()])].sort();
    const nativePaths = new Set();
    const sourceDigest = caseDigest([...packets.values()]);
    for (const arm of arms) {
      if (arm.fingerprints[side].packet_list_sha256 !== sourceDigest) continue;
      const parsed = arm.native_coverage[side];
      if (parsed.unlocated_extraction_errors) continue;
      const failed = new Set(parsed.parse_failed);
      for (const path of parsed.extracted) if (!failed.has(path)) nativePaths.add(path);
    }
    const findings = new Map();
    for (const [, path] of (side === 'old' ? row.hunk_findings : row.fix_side_residual) ?? []) {
      findings.set(path, (findings.get(path) ?? 0) + 1);
    }
    const routes = paths.map(path => sourceRoute(byPath.get(path), packets.get(path), nativePaths, extensions, findings,
      captureStates[side] === 'report_pinned')).filter(Boolean);
    return [side, { inventory_sha256: caseDigest(coverage), inventoried_paths: paths.length, routes }];
  }));
}

function caseEvidence(pattern, outcomes, coverageGaps, captureStates, referenceCases, observations, followUp, proofPins) {
  const nativeByCase = new Map(observations.map(row => [row.advisory, row]));
  const pendingByCase = new Map(followUp.map(row => [row.advisory, row]));
  return [...pattern].map(([advisory, row]) => {
    const native = nativeByCase.get(advisory);
    const arms = native?.arms ?? (native ? [native] : []);
    const pending = pendingByCase.get(advisory);
    const fixedResiduals = native?.fixed_hunk_residuals ?? null;
    const historical = outcomes.get(advisory) === 'hit';
    const coverageGap = coverageGaps.get(advisory);
    const fixedReview = row.fix_side_residual.length || fixedResiduals ? 'review_fixed_side_path' : null;
    const pattern_captures = captureStates.get(advisory);
    const source_routing = sourceRouting(row, arms, pattern_captures);
    const source_follow_up = Object.entries(source_routing).flatMap(([side, { routes }]) => routes
      .filter(route => !['pattern_parsed', 'native_parsed'].includes(route.state))
      .map(({ path, state }) => ({ side, path, state })));
    const next = pending?.next ?? (coverageGap ? 'resolve_pattern_coverage' : fixedReview)
      ?? (source_follow_up.length ? 'resolve_source_routes' : null);
    const pins = {
      advisory, input_sha256: referenceCases.get(advisory).input_sha256, ...proofPins,
      diff_sha256: row.diff_sha256, changed_files_sha256: row.changed_files_sha256,
      pattern_artifacts: row.captures ?? null,
      native_bundles: arms.map(arm => arm.native_bundle_sha256),
    };
    const layers = [
        { stage: 'sink_collection', pattern_alerts_in_changed_files: row.captures?.old ? row.alerts_in_changed_files ?? null : null,
          native_alerts: native ? arms.reduce((sum, arm) => sum + arm.native_alerts.old, 0) : null },
        { stage: 'parser_coverage', pattern: coverageGap ?? outcomes.get(advisory), pattern_captures, source_routing,
          native_captures: arms.length, complete_native_captures: arms.filter(arm =>
            arm.native_coverage.old.complete && arm.native_coverage.fixed.complete).length },
        { stage: 'source_to_sink', same_family_pattern_alerts: row.captures?.old ? row.family_alerts_in_changed_files ?? null : null,
          archive_bound_trace_anchors: native ? (native.anchored_trace_matches?.length ?? 0) : null,
          bound_native_traces: arms.filter(arm => arm.anchored_trace_matches?.length).map(arm =>
            ({ bundle_sha256: arm.native_bundle_sha256, trace_sha256: caseDigest(arm.anchored_trace_matches) })) },
        { stage: 'fixed_side', pattern_hunk_residuals: row.captures?.fixed || row.fix_side_residual.length ? row.fix_side_residual.length : null,
          native_hunk_residuals: fixedResiduals },
        { stage: 'verdict', state: next ? 'unresolved' : historical ? 'registered_hunk_hit' : 'verified_native_addition',
          historical_hunk_hit: historical, next, next_plan_sha256s: pending?.plan_sha256s ?? [], source_follow_up },
    ];
    let prior = caseDigest([pins]);
    const evidence = { ...pins, layers: layers.map(layer => {
      const packet = { ...layer, input_sha256: prior };
      prior = caseDigest([packet]);
      return { ...packet, output_sha256: prior };
    }) };
    return { ...evidence, evidence_sha256: caseDigest([evidence]) };
  });
}

function registerUnresolvedCases(caseEvidence, outcomes) {
  return caseEvidence.flatMap(({ advisory, input_sha256, evidence_sha256, layers }) => {
    const verdict = layers.at(-1);
    if (!verdict.next) return [];
    return [{ advisory, input_sha256, evidence_sha256, pattern_outcome: outcomes.get(advisory),
      next: verdict.next, plan_sha256s: verdict.next_plan_sha256s, source_follow_up: verdict.source_follow_up }];
  });
}

function joinPatternScore(pin, manifestSha, casesSha, cases, referenceCases, observations, plans, cohortPins) {
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
  const outcomes = new Map(), coverageGaps = new Map(), captureStates = new Map();
  for (const row of score.cases) {
    const registered = cases.get(row.ghsa);
    requireProof(registered && !pattern.has(row.ghsa), 'Missing or duplicate registered pattern case');
    const metadata = Object.fromEntries(Object.keys(registered).map(key => [key, row[key]]));
    requireProof(caseDigest([metadata]) === caseDigest([registered])
      && inputFingerprint(row) === referenceCases.get(row.ghsa).input_sha256,
    'Pattern case input differs from registered evidence for ' + row.ghsa);
    const outcome = verifiedPatternOutcome(row);
    pattern.set(row.ghsa, row);
    outcomes.set(row.ghsa, outcome);
    const capture = { old: patternCaptureState(row, 'old'), fixed: patternCaptureState(row, 'fixed') };
    captureStates.set(row.ghsa, capture);
    coverageGaps.set(row.ghsa, patternCoverageGap(row, capture));
  }
  const hunkHits = [...outcomes.values()].filter(outcome => outcome === 'hit').length;
  const fileHits = [...pattern].filter(([id, row]) => searchedFileHit(row, outcomes.get(id))).length;
  requireProof(score.summary.hunk_hits === hunkHits && score.summary.file_hits === fileHits,
    'Pattern hit count differs');
  const dispositions = observations.map(native => {
    const row = pattern.get(native.advisory), outcome = outcomes.get(native.advisory);
    const evidence = (native.arms ?? [native]).map(arm => {
      const extraction_complete = arm.native_coverage.old.complete && arm.native_coverage.fixed.complete;
      return { arm, extraction_complete, disposition: nativeDisposition(arm, row, outcome, extraction_complete, coverageGaps.get(native.advisory)) };
    });
    const selected = evidence.find(item => item.disposition === 'eligible')
      ?? evidence.find(item => item.arm.hunk_hit)
      ?? evidence.find(item => item.disposition === 'fixed_side_residual') ?? evidence[0];
    const disposition = joinedDisposition(selected, native, evidence);
    return { advisory: native.advisory, input_sha256: native.input_sha256, pattern_outcome: outcome,
      pattern_file_hit: searchedFileHit(row, outcome), native_hunk_hit: native.hunk_hit, native_file_hit: native.file_hit,
      native_extraction_complete: selected.extraction_complete, disposition,
      arm_dispositions: evidence.map(({ arm, extraction_complete, disposition }) =>
        ({ ...arm.detector_arm, native_bundle_sha256: arm.native_bundle_sha256,
          native_family_alerts: arm.native_family_alerts, extraction_complete, disposition })) };
  });
  const additions = dispositions.filter(row => row.disposition === 'eligible').length;
  const newHunkHits = dispositions.filter(row => row.native_hunk_hit && row.pattern_outcome !== 'hit').length;
  const newFileHits = dispositions.filter(row => row.native_file_hit && !row.pattern_file_hit).length;
  const registeredEvidence = caseEvidence(pattern, outcomes, coverageGaps, captureStates, referenceCases, observations,
    pendingEvidence(pattern, outcomes, coverageGaps, referenceCases, dispositions, observations, plans ?? []),
    { ...cohortPins, pattern_score_sha256: pin.sha256, pattern_rules_sha256: score.ruleset_sha256,
      pattern_profile_sha256: score.profile_sha256, pattern_executable_sha256: score.engine.executable_sha256 });
  return { scope: 'supplemental paired comparison', pattern_score_sha256: pin.sha256,
    pattern_hunk_hits: hunkHits, pattern_file_hits: fileHits,
    verified_pattern_cases: pattern.size, verified_native_pairs: dispositions.length,
    native_extraction_complete_pairs: dispositions.filter(row => row.native_extraction_complete).length,
    observed_union_hunk_hits: hunkHits + newHunkHits, observed_union_file_hits: fileHits + newFileHits,
    eligible_native_additions: additions, combined_hunk_hits: hunkHits + additions, cases: dispositions,
    follow_up: registerUnresolvedCases(registeredEvidence, outcomes), case_evidence: registeredEvidence };
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

function verifiedPairInput(row, { root, cases, referenceCases }) {
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
  const preparedDir = dirname(row.prepared.path);
  const patch = artifact(root, { path: join(preparedDir, 'diff.patch'), sha256: input.diff_sha256 });
  const changes = changedFiles(artifact(root, { path: join(preparedDir, 'changes.z'), sha256: input.changed_files_sha256 }));
  return { registered, before, input, patch, changes };
}

function scorePreparedPair(row, context) {
  const { root, policies, engineVersion, archives } = context;
  const { registered, before, input, patch, changes } = verifiedPairInput(row, context);
  const families = familiesFor(registered.cwes);
  const policy = policies ? policies.get(registered.ecosystem) : { queries: [queryBinding(root, row.query_id, row.query)] };
  requireProof(policy, 'No registered CodeQL ecosystem policy for ' + row.advisory);
  if (!policies) {
    requireProof(policy.queries[0].families.some(family => families.includes(family)),
      'CodeQL query family differs for ' + row.advisory);
  }
  const extractionId = extractionDiagnostics.get(registered.ecosystem);
  const old = nativeCapture(root, row.old, 'old', input, engineVersion, policy, extractionId);
  const fixed = nativeCapture(root, row.fixed, 'fixed', input, engineVersion, policy, extractionId);
  archives.push(old.archive, fixed.archive);

  const editedLines = {};
  const hunks = parseHunks(patch.toString('utf8'), scopeExtensions(registered.ecosystem), editedLines);
  const rules = Object.fromEntries(policy.queries.map(query => [query.id, query.families]));
  const score = scoreCase({ families, hunks, editedLines, oldFindings: old.findings, newFindings: fixed.findings, rules });
  const anchored = anchoredTraceMatches({ oldFindings: old.findings, newFindings: fixed.findings,
    flows: old.flows, hunks, families, rules });
  return { advisory: row.advisory, reference: before.after, input_sha256: before.input_sha256,
    ...(policies ? { queries_sha256: policy.queriesSha256 } : { query_id: row.query_id }),
    detector_arm: { engine: 'codeql', ecosystem: registered.ecosystem,
      ...(policy.planSha256 ? { plan_sha256: policy.planSha256 } : {}),
      source_extensions: scopeExtensions(registered.ecosystem),
      query_ids: policy.queries.map(query => query.id).sort(),
      families: [...new Set(policy.queries.flatMap(query => query.families))].sort() },
    hunk_hit: score.hunk_hit,
    file_hit: score.file_hit,
    trace_hit: score.trace_hit, matched_hunk_families: score.matched_hunk_families,
    hunk_matches: score.hunk_findings, fixed_hunk_matches: score.fix_side_residual,
    ...(score.hunk_spans ? { hunk_spans: score.hunk_spans } : {}),
    ...(score.fix_side_residual_spans ? { fix_side_residual_spans: score.fix_side_residual_spans } : {}),
    ...(anchored.length ? { anchored_trace_matches: anchored } : {}),
    cross_file_trace_matches: anchored.filter(match => !Object.hasOwn(hunks, match.sink.path))
      .map(match => ({ ...match, sink: { path: match.sink.path, line: match.sink.line } })),
    deleted_line_hit: score.edited_lines.deleted_line_hit, fixed_hunk_residuals: score.fix_side_residual.length,
    [pendingFamilyAlerts]: collectFamilyAlerts(old, fixed, families, rules, changes),
    native_alerts: { old: old.findings.length, fixed: fixed.findings.length },
    native_coverage: { old: old.coverage, fixed: fixed.coverage },
    fingerprints: { old: old.fingerprints, fixed: fixed.fingerprints },
    packets: { old: old.archive.packets.length, fixed: fixed.archive.packets.length } };
}

function reuseCapture(row, captured, context) {
  const source = captured.get(row.capture_reused_from);
  requireProof(context.policies && source && !Object.hasOwn(row, 'old') && !Object.hasOwn(row, 'fixed'),
    'Capture reuse requires a directly captured pair in the same registered plan');
  const { registered, before, input } = verifiedPairInput(row, context);
  const original = context.cases.get(source.advisory);
  requireProof(registered.repository === original.repository && registered.ecosystem === original.ecosystem
    && caseDigest(familiesFor(registered.cwes)) === caseDigest(familiesFor(original.cwes)),
  'Capture reuse repository, ecosystem or scored families differ for ' + row.advisory);
  requireProof(inputFingerprint({ ...input, ghsa: source.advisory }) === source.input_sha256,
    'Capture reuse source inputs differ for ' + row.advisory);
  return { ...source, advisory: row.advisory, reference: before.after, input_sha256: before.input_sha256,
    capture_reused_from: source.advisory };
}

function verifySourceArchives(groups) {
  const verified = spawnSync(process.env.CF_RECALL_PYTHON ?? 'python', ['-I', '-c', archiveVerifier],
    { input: JSON.stringify(groups), encoding: 'utf8', windowsHide: true, maxBuffer: 32 * 1024 * 1024 });
  // Retain the per-bundle limit when a combined response exceeds it.
  if (verified.error?.code === 'ENOBUFS' && groups.length > 1) {
    return groups.flatMap(group => verifySourceArchives([group]));
  }
  if (verified.error) throw verified.error;
  requireProof(verified.status === 0, 'Source archive verification failed: ' + verified.stderr.trim());
  return json(Buffer.from(verified.stdout, 'utf8'));
}

function bindTraceSources(observations, bindings) {
  for (const row of observations) {
    const sourcesBySide = {};
    for (const side of ['old', 'fixed']) {
      const sources = bindings[row.advisory + '/' + side];
      requireProof(Array.isArray(sources), 'Missing trace-source verification for ' + row.advisory + '/' + side);
      sourcesBySide[side] = new Map(sources.map(source => [source.path, source]));
      const states = {};
      for (const source of sources) states[source.state] = (states[source.state] ?? 0) + 1;
      Object.assign(row.fingerprints[side], { trace_sources_sha256: caseDigest(sources), trace_source_states: states });
    }
    row.native_family_alerts = summarizeFamilyAlerts(row[pendingFamilyAlerts], sourcesBySide);
    delete row[pendingFamilyAlerts];
    const verifiedTrace = match => sourcesBySide.old.get(match.anchor.path)?.state === 'packet_verified'
      && match.source_paths.every(path => ['packet_verified', 'archive_verified'].includes(sourcesBySide.old.get(path)?.state));
    const anchors = row.anchored_trace_matches?.filter(verifiedTrace);
    if (anchors?.length) row.anchored_trace_matches = anchors;
    else delete row.anchored_trace_matches;
    row.cross_file_trace_matches = row.cross_file_trace_matches.filter(verifiedTrace);
  }
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

function preparePairBundle(root, bundle) {
  requireProof([FORMAT, PLAN_BUNDLE].includes(bundle.schema) && typeof bundle.engine_version === 'string'
    && Array.isArray(bundle.cases) && bundle.cases.length > 0, 'Invalid paired CodeQL bundle');
  const registry = readPairRegistry(root, bundle);
  const { manifest, cases, referenceCases } = registry;
  requireProof(new Set(bundle.cases.map(row => row.advisory)).size === bundle.cases.length,
    'Duplicate CodeQL advisory pair');
  const policies = bundle.schema === PLAN_BUNDLE ? registeredPolicies(root, bundle, manifest) : null;

  const archives = [];
  const context = { root, cases, referenceCases, policies, engineVersion: bundle.engine_version, archives };
  const captured = new Map(bundle.cases.filter(row => !Object.hasOwn(row, 'capture_reused_from'))
    .map(row => [row.advisory, scorePreparedPair(row, context)]));
  return { archives, complete(bindings) {
    bindTraceSources(captured.values(), bindings);
    const observations = bundle.cases.map(row => captured.get(row.advisory) ?? reuseCapture(row, captured, context));
    return { registry, observations, scope: policies ? 'registered-codeql-plan' : 'supplemental',
      coverage: scheduledCoverage(bundle.plan, policies, manifest, observations) };
  } };
}

function verifyPairBundles(lanes) {
  const prepared = lanes.map(({ root, input }) => preparePairBundle(root, input));
  const bindings = verifySourceArchives(prepared.map(lane => lane.archives));
  requireProof(Array.isArray(bindings) && bindings.length === prepared.length, 'Missing archive verification group');
  return prepared.map((lane, index) => lane.complete(bindings[index]));
}

function summarizeVerifiedPairs(bundle, registry, observations, patternPin, plans, cohortPins) {
  const { manifestDigest, reference, cases, referenceCases } = registry;
  const patternJoin = patternPin && joinPatternScore(
    patternPin, bundle.manifest.sha256, manifestDigest, cases, referenceCases, observations, plans, cohortPins);
  const reused = observations.filter(row => (row.arms ?? [row])
    .every(arm => Object.hasOwn(arm, 'capture_reused_from'))).length;
  return { ...(patternJoin ? { pattern_join: patternJoin } : {}),
    reference_sha256: bundle.reference.sha256, registered_cases: cases.size, reference_hunk_hits: reference.candidate.hunk_hits,
    scored_pairs: observations.length, captured_pairs: observations.length - reused, reused_capture_pairs: reused,
    strict_hunk_hits: observations.filter(row => row.hunk_hit).length,
    changed_file_hits: observations.filter(row => row.file_hit).length,
    cross_file_trace_hits: observations.filter(row => row.cross_file_trace_matches.length > 0).length,
    strict_hits_on_reference_misses: observations.filter(row => row.reference === 'miss' && row.hunk_hit).length,
    deleted_line_hits: observations.filter(row => row.deleted_line_hit).length,
    fixed_hunk_residuals: observations.reduce((sum, row) => sum + row.fixed_hunk_residuals, 0), cases: observations };
}

function mergeVerifiedArms(observations) {
  return [...Map.groupBy(observations, row => row.advisory)].map(([advisory, arms]) => {
    const { input_sha256, reference } = arms[0];
    const queries = arms.flatMap(arm => arm.detector_arm.query_ids);
    requireProof(arms.every(arm => arm.input_sha256 === input_sha256 && arm.reference === reference)
      && queries.length === new Set(queries).size, 'Detector arms have different cases or overlapping query IDs');
    const hit = field => arms.some(arm => arm[field]);
    const anchors = arms.flatMap(arm => arm.anchored_trace_matches ?? []);
    return { advisory, input_sha256, reference, arms, hunk_hit: hit('hunk_hit'),
      ...(anchors.length ? { anchored_trace_matches: anchors } : {}),
      file_hit: hit('file_hit'), trace_hit: hit('trace_hit'), deleted_line_hit: hit('deleted_line_hit'),
      matched_hunk_families: [...new Set(arms.flatMap(arm => arm.matched_hunk_families))].sort(),
      cross_file_trace_matches: arms.flatMap(arm => arm.cross_file_trace_matches),
      fixed_hunk_residuals: arms.reduce((sum, arm) => sum + arm.fixed_hunk_residuals, 0) };
  });
}

function scoreCohortBundle(root, bytes, bundle, patternPin) {
  requireProof(Array.isArray(bundle.bundles) && bundle.bundles.length > 0
    && new Set(bundle.bundles.map(pin => pin?.sha256)).size === bundle.bundles.length, 'Missing or duplicate cohort bundle pins');
  const lanes = bundle.bundles.map(pin => {
    const path = boundPath(root, pin);
    return { pin, input: json(readPinnedArtifact(path, pin)), root: dirname(path) };
  });
  const first = lanes[0].input;
  requireProof(lanes.every(({ input }) => input.manifest?.sha256 === first.manifest?.sha256
    && input.reference?.sha256 === first.reference?.sha256 && input.engine_version === first.engine_version),
  'Cohort bundles use different registry, reference or engine pins');

  const verified = verifyPairBundles(lanes);
  const captures = verified.flatMap(({ observations }, index) =>
    observations.map(row => ({ ...row, native_bundle_sha256: lanes[index].pin.sha256 })));
  const grouped = bundle.schema === ARM_COHORT;
  const observations = grouped ? mergeVerifiedArms(captures) : captures;
  const covered = new Set(observations.map(row => row.advisory));
  requireProof(covered.size === observations.length, 'Duplicate CodeQL advisory across cohort bundles');
  const { registry } = verified[0];
  const cohortSha = sha256(bytes);
  return { schema: grouped ? 'factory.recall-codeql-cohort-score.v2' : 'factory.recall-codeql-cohort-score.v1',
    scope: 'verified paired native cohort', ...(grouped ? { scored_arm_pairs: captures.length } : {}),
    input_sha256: cohortSha, manifest_sha256: first.manifest.sha256, engine_version: first.engine_version,
    bundles: verified.map((lane, index) => ({ ...lanes[index].pin, scope: lane.scope,
      scored_pairs: lane.observations.length, ...lane.coverage })),
    unscored_advisories: [...registry.cases.keys()].filter(id => !covered.has(id)),
    ...summarizeVerifiedPairs(first, registry, observations, patternPin, grouped
      ? verified.map(lane => lane.coverage).filter(coverage => coverage.plan_sha256) : undefined,
    { cohort_sha256: cohortSha, manifest_sha256: first.manifest.sha256, reference_sha256: first.reference.sha256 }) };
}

export function scoreCodeqlPairs(bundlePath, patternPin = null) {
  const bytes = readFileSync(bundlePath);
  const root = realpathSync(dirname(bundlePath));
  const bundle = json(bytes);
  if ([COHORT_BUNDLE, ARM_COHORT].includes(bundle.schema)) return scoreCohortBundle(root, bytes, bundle, patternPin);
  const [{ registry, observations, scope, coverage }] = verifyPairBundles([{ root, input: bundle }]);
  const inputSha = sha256(bytes);
  for (const row of observations) row.native_bundle_sha256 = inputSha;
  return { schema: 'factory.recall-codeql-pair-score.v1', scope, input_sha256: inputSha, ...coverage,
    ...summarizeVerifiedPairs(bundle, registry, observations, patternPin, coverage.plan_sha256 ? [coverage] : [],
      { cohort_sha256: inputSha, manifest_sha256: bundle.manifest.sha256, reference_sha256: bundle.reference.sha256 }) };
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
