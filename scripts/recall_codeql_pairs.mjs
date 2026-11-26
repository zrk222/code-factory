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
import { caseDigest, familiesFor, outcomeOf, parseHunks, reviewCapturePath, sarifFindings, scopeExtensions,
  scoreCase, sha256, validateRecallManifest } from './recall_harness.mjs';
import { completeFixedCoverage, sarifPath } from './recall_coverage.mjs';
import { inputFingerprint } from './verify_registered_recall.mjs';

const FORMAT = 'factory.recall-codeql-pairs.v1';
const PLAN_BUNDLE = 'factory.recall-codeql-pairs.v2';
const COHORT_BUNDLE = 'factory.recall-codeql-cohort.v1';
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

bindings = {}
for item in json.load(sys.stdin):
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
print(json.dumps(bindings, separators=(",", ":")))
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

function traceFlows(results, resolvePath) {
  return results.map(result => (result.codeFlows ?? []).map(flow =>
    (flow.threadFlows ?? []).map(thread => (thread.locations ?? []).map(step => {
      const location = step.location?.physicalLocation;
      if (!location?.artifactLocation) return { state: 'nonphysical' };
      const path = resolvePath(location.artifactLocation);
      const line = location.region?.startLine;
      return Number.isSafeInteger(line) && line > 0 ? { path, line } : { path, state: 'invalid_line' };
    }))));
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
  const findings = sarifFindings(report, packetPaths, id => id, resolvePath);
  requireProof(findings.length === run.results.length
    && findings.every(finding => finding.path && Number.isSafeInteger(finding.line) && finding.line > 0),
    'Native alert location is missing for ' + side);
  const flows = traceFlows(run.results, resolvePath);
  const references = [...new Set([...findings.map(row => row.path),
    ...flows.flat(3).map(step => step.path).filter(Boolean)])].sort();
  return { findings, flows, fingerprints: captureFingerprints(capture, input.revisions[side], policy, packets, findings, flows),
    archive: { archive: boundPath(root, capture.archive), sha256: capture.archive.sha256,
      prefix: capture.archive_prefix, packets, references, side: input.ghsa + '/' + side } };
}

function nativeDisposition(native, pattern, outcome) {
  if (!native.hunk_hit) return 'native_miss';
  if (outcome === 'hit') return 'overlap';
  if (outcome !== 'miss') return 'pattern_unresolved';
  if (native.fixed_hunk_residuals || pattern.fix_side_residual.length) return 'fixed_side_residual';
  if (Object.values(native.fingerprints).some(side => side.trace_source_states.missing
    || side.trace_source_states.ambiguous || side.invalid_trace_steps)) return 'native_trace_source_unresolved';
  return completeFixedCoverage(pattern.file_coverage?.fixed, pattern.source_packets?.fixed)
    ? 'eligible' : 'fixed_coverage_unresolved';
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
    const outcome = verifiedPatternOutcome(row);
    pattern.set(row.ghsa, row);
    outcomes.set(row.ghsa, outcome);
  }
  const hunkHits = [...outcomes.values()].filter(outcome => outcome === 'hit').length;
  const fileHits = [...pattern].filter(([id, row]) => searchedFileHit(row, outcomes.get(id))).length;
  requireProof(score.summary.hunk_hits === hunkHits && score.summary.file_hits === fileHits,
    'Pattern hit count differs');
  const dispositions = observations.map(native => {
    const row = pattern.get(native.advisory), outcome = outcomes.get(native.advisory);
    return { advisory: native.advisory, input_sha256: native.input_sha256, pattern_outcome: outcome,
      pattern_file_hit: searchedFileHit(row, outcome), native_hunk_hit: native.hunk_hit, native_file_hit: native.file_hit,
      disposition: nativeDisposition(native, row, outcome) };
  });
  const additions = dispositions.filter(row => row.disposition === 'eligible').length;
  const newHunkHits = dispositions.filter(row => row.native_hunk_hit && row.pattern_outcome !== 'hit').length;
  const newFileHits = dispositions.filter(row => row.native_file_hit && !row.pattern_file_hit).length;
  return { scope: 'supplemental paired comparison', pattern_score_sha256: pin.sha256,
    pattern_hunk_hits: hunkHits, pattern_file_hits: fileHits,
    verified_pattern_cases: pattern.size, verified_native_pairs: dispositions.length,
    observed_union_hunk_hits: hunkHits + newHunkHits, observed_union_file_hits: fileHits + newFileHits,
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

function crossFileTraceMatches(old, fixed, hunks, families, rules) {
  const sinkKey = ({ rule, path }) => JSON.stringify([rule, path]);
  const fixedSinks = new Set(fixed.findings.map(sinkKey));
  const matches = [];
  for (const [index, finding] of old.findings.entries()) {
    const { rule, path, line } = finding;
    if (Object.hasOwn(hunks, path) || !rules[rule]?.some(family => families.includes(family))) continue;
    for (const thread of old.flows[index].flat()) {
      const steps = thread.filter(step => step.state !== 'nonphysical');
      const sink = steps.at(-1);
      if (sink?.path !== path || sink.line !== line || steps.some(step => step.state)) continue;
      const anchor = steps.slice(0, -1).find(step => Object.hasOwn(hunks, step.path)
        && hunks[step.path].old.includes(step.line));
      if (anchor) {
        matches.push({ rule, sink: { path, line }, anchor,
          source_paths: [...new Set(steps.map(step => step.path))].sort(),
          fixed_sink_residual: fixedSinks.has(sinkKey(finding)) });
      }
    }
  }
  return matches;
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
  artifact(root, { path: join(preparedDir, 'changes.z'), sha256: input.changed_files_sha256 });
  return { registered, before, input, patch };
}

function scorePreparedPair(row, context) {
  const { root, policies, engineVersion, archives } = context;
  const { registered, before, input, patch } = verifiedPairInput(row, context);
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

  const editedLines = {};
  const hunks = parseHunks(patch.toString('utf8'), scopeExtensions(registered.ecosystem), editedLines);
  const rules = Object.fromEntries(policy.queries.map(query => [query.id, query.families]));
  const score = scoreCase({ families, hunks, editedLines, oldFindings: old.findings, newFindings: fixed.findings, rules });
  return { advisory: row.advisory, reference: before.after, input_sha256: before.input_sha256,
    ...(policies ? { queries_sha256: policy.queriesSha256 } : { query_id: row.query_id }), hunk_hit: score.hunk_hit,
    file_hit: score.file_hit,
    trace_hit: score.trace_hit, matched_hunk_families: score.matched_hunk_families,
    hunk_matches: score.hunk_findings, fixed_hunk_matches: score.fix_side_residual,
    cross_file_trace_matches: crossFileTraceMatches(old, fixed, hunks, families, rules),
    deleted_line_hit: score.edited_lines.deleted_line_hit, fixed_hunk_residuals: score.fix_side_residual.length,
    native_alerts: { old: old.findings.length, fixed: fixed.findings.length },
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

function verifySourceArchives(archives) {
  const verified = spawnSync(process.env.CF_RECALL_PYTHON ?? 'python', ['-I', '-c', archiveVerifier],
    { input: JSON.stringify(archives), encoding: 'utf8', windowsHide: true, maxBuffer: 32 * 1024 * 1024 });
  if (verified.error) throw verified.error;
  requireProof(verified.status === 0, 'Source archive verification failed: ' + verified.stderr.trim());
  return json(Buffer.from(verified.stdout, 'utf8'));
}

function bindTraceSources(observations, bindings) {
  for (const row of observations) {
    for (const side of ['old', 'fixed']) {
      const sources = bindings[row.advisory + '/' + side];
      requireProof(Array.isArray(sources), 'Missing trace-source verification for ' + row.advisory + '/' + side);
      const states = {};
      for (const source of sources) states[source.state] = (states[source.state] ?? 0) + 1;
      Object.assign(row.fingerprints[side], { trace_sources_sha256: caseDigest(sources), trace_source_states: states });
    }
    const oldSources = new Map(bindings[row.advisory + '/old'].map(source => [source.path, source.state]));
    row.cross_file_trace_matches = row.cross_file_trace_matches.filter(match =>
      oldSources.get(match.anchor.path) === 'packet_verified' && match.source_paths.every(path =>
        ['packet_verified', 'archive_verified'].includes(oldSources.get(path))));
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

function verifyPairBundle(root, bundle) {
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
  bindTraceSources(captured.values(), verifySourceArchives(archives));
  const observations = bundle.cases.map(row => captured.get(row.advisory) ?? reuseCapture(row, captured, context));
  return { registry, observations, scope: policies ? 'registered-codeql-plan' : 'supplemental',
    coverage: scheduledCoverage(bundle.plan, policies, manifest, observations) };
}

function summarizeVerifiedPairs(bundle, registry, observations, patternPin) {
  const { manifestDigest, reference, cases, referenceCases } = registry;
  const patternJoin = patternPin && joinPatternScore(patternPin, bundle.manifest.sha256, manifestDigest, cases, referenceCases, observations);
  const reused = observations.filter(row => Object.hasOwn(row, 'capture_reused_from')).length;
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

  const verified = lanes.map(lane => verifyPairBundle(lane.root, lane.input));
  const observations = verified.flatMap(({ observations }, index) =>
    observations.map(row => ({ ...row, native_bundle_sha256: lanes[index].pin.sha256 })));
  const covered = new Set(observations.map(row => row.advisory));
  requireProof(covered.size === observations.length, 'Duplicate CodeQL advisory across cohort bundles');
  const { registry } = verified[0];
  return { schema: 'factory.recall-codeql-cohort-score.v1', scope: 'verified paired native cohort',
    input_sha256: sha256(bytes), manifest_sha256: first.manifest.sha256, engine_version: first.engine_version,
    bundles: verified.map((lane, index) => ({ ...lanes[index].pin, scope: lane.scope,
      scored_pairs: lane.observations.length, ...lane.coverage })),
    unscored_advisories: [...registry.cases.keys()].filter(id => !covered.has(id)),
    ...summarizeVerifiedPairs(first, registry, observations, patternPin) };
}

export function scoreCodeqlPairs(bundlePath, patternPin = null) {
  const bytes = readFileSync(bundlePath);
  const root = realpathSync(dirname(bundlePath));
  const bundle = json(bytes);
  if (bundle.schema === COHORT_BUNDLE) return scoreCohortBundle(root, bytes, bundle, patternPin);
  const { registry, observations, scope, coverage } = verifyPairBundle(root, bundle);
  return { schema: 'factory.recall-codeql-pair-score.v1', scope, input_sha256: sha256(bytes), ...coverage,
    ...summarizeVerifiedPairs(bundle, registry, observations, patternPin) };
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
