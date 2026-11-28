#!/usr/bin/env node

import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { completeFixedCoverage, readRuleMetadata, scannerPathPolicy } from './recall_coverage.mjs';
import { caseDigest, checkpointArtifactsIntact, outcomeOf, replayCaseScore, ruleFamilies, sha256, sortKeys, validateRecallManifest } from './recall_harness.mjs';

const referenceSha256 = '0e77620476c68c5de799c7b95e357667ad3bd48a9f16fd1c2cdfc6e575b8dcaf';
const protectedSha256 = '6d0de3bbebeebb3999516807bbb6e3699137bcda88dbc5e3470bbd38fe541e0c';
const engineSha256 = 'fae553cdfd1badcb30a480ec5c47e3e14355744167bff4303dc45ab436253e7a';
const engineVersion = '2.1.0';
const pathPolicyProof = 'opengrep-2.1.0-target-inventory-v1';
const engineArgs = ['--timeout=15', '--jobs=1'];
const scoringPins = {
  manifest_sha256: 'bb7a28c66c7062256851933a1e746c1fb33327021e53294d3a2e6e10d04deb60',
  manifest_cases_sha256: '5f332b159a68e4236215843095a669afe2d150757eaee4c18ece33005f0b0013',
  profile_sha256: '8ec08b713a3bd64cd272cda054faab0fe206be45d79258d74b1099f1ab326dd6',
};
const receiptSchema = 'factory.registered-recall-retention.v1';
const registeredCases = 161;
const referenceHits = 39;
const advisoryId = /^GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}$/;
const hexDigest = /^[a-f0-9]{64}$/;
const scored = outcome => outcome === 'hit' || outcome === 'miss';
const outcomes = () => ({ hit: 0, miss: 0, timeout: 0, unknown: 0, error: 0, coverage_incomplete: 0 });

function matchingMetadata(report, engineDigest) {
  return Object.entries(scoringPins).every(([key, digest]) => report?.[key] === digest)
    && report?.engine?.version === engineVersion && engineDigest === engineSha256
    && JSON.stringify(report.engine_args) === JSON.stringify(engineArgs);
}

function validReference(reference) {
  return reference?.schema === 'factory.recall-exposed-run-readback.v1'
    && matchingMetadata(reference, reference.engine?.sha256)
    && reference.candidate?.registered === registeredCases && reference.candidate?.hunk_hits === referenceHits
    && Array.isArray(reference.cases) && reference.cases.length === registeredCases
    && reference.cases.every(row => advisoryId.test(row?.advisory ?? '') && hexDigest.test(row.input_sha256 ?? '')
      && typeof row.ecosystem === 'string' && Object.hasOwn(outcomes(), row.after))
    && new Set(reference.cases.map(row => row.advisory)).size === registeredCases
    && reference.cases.filter(row => row.after === 'hit').length === referenceHits
    && Number.isSafeInteger(reference.fix_side_residual_alerts?.[1]) && reference.fix_side_residual_alerts[1] >= 0;
}

function candidateOutcome(row) {
  const outcome = outcomeOf(row);
  if (row.outcome !== outcome || typeof row.hunk_hit !== 'boolean' || !Array.isArray(row.hunk_findings)
    || row.hunk_hit !== (row.hunk_findings.length > 0) || !Array.isArray(row.fix_side_residual)) return null;
  return outcome;
}

export function inputFingerprint({ ghsa, revisions, source_packets, diff_sha256, changed_files_sha256 }) {
  // The published receipt hashes the advisory and its source bindings as one object.
  return sha256(JSON.stringify(sortKeys({ ghsa, revisions, source_packets, diff_sha256, changed_files_sha256 })));
}

function readCandidateCases(cases, failures) {
  const rows = new Map();
  for (const row of cases) {
    const id = row?.ghsa;
    if (typeof id !== 'string' || !advisoryId.test(id)) {
      failures.push({ code: 'INVALID_CANDIDATE_ADVISORY' });
      continue;
    }
    if (rows.has(id)) failures.push({ code: 'DUPLICATE_CANDIDATE_ADVISORY', advisory_ids: [id] });
    else rows.set(id, row);
  }
  return rows;
}

function compareCases(reference, candidate, summary, failures, protectedHitIds, pairedPathPolicy, recallRules) {
  const remainingProtected = new Set(protectedHitIds);
  const expected = new Set(reference.map(row => row.advisory));
  const rows = readCandidateCases(candidate, failures);
  const missing = [], unexpected = [], bindings = [], invalid = [], fixedGaps = [];
  const lost = [], gained = [], unresolved = [], incompleteCoverage = [];
  for (const id of rows.keys()) if (!expected.has(id)) unexpected.push(id);
  for (const row of reference) {
    const id = row.advisory;
    const current = rows.get(id);
    if (!current) { missing.push(id); continue; }
    if (row.ecosystem !== current.ecosystem || row.input_sha256 !== inputFingerprint(current)
      || current.fix !== current.revisions?.fixed) {
      bindings.push(id);
      continue;
    }
    summary.verified_bindings++;
    const outcome = candidateOutcome(current);
    if (outcome === null) { invalid.push(id); continue; }
    summary.candidate_outcomes[outcome]++;
    if (outcome === 'hit') remainingProtected.delete(id);
    if (scored(outcome)) {
      // Recall-mode rules only ever emit leads; their fixed-side residuals are reported, not gated.
      const recallMode = current.fix_side_residual.filter(([rule]) => recallRules.some(id => rule === id || rule.endsWith('.' + id))).length;
      summary.candidate_fixed_side_residual_alerts += current.fix_side_residual.length - recallMode;
      summary.candidate_recall_mode_residual_alerts += recallMode;
      const oldCoverage = current.file_coverage?.old;
      const oldFiles = pairedPathPolicy && Array.isArray(oldCoverage) ? oldCoverage : [];
      if (!completeFixedCoverage(current.file_coverage?.fixed, current.source_packets?.fixed, oldFiles)) fixedGaps.push(id);
    }
    if (row.after === 'hit' && outcome !== 'hit') lost.push(id);
    if (row.after === 'hit' && outcome === 'hit') summary.retained_hunk_hits++;
    if (row.after !== 'hit' && outcome === 'hit') gained.push(id);
    if (protectedHitIds.length && outcome === 'coverage_incomplete') incompleteCoverage.push(id);
    else if (outcome === 'timeout' || outcome === 'error' || (!scored(outcome) && outcome !== row.after)) unresolved.push(id);
  }
  const issueIds = {
    MISSING_CANDIDATE_ADVISORY: missing, UNEXPECTED_CANDIDATE_ADVISORY: unexpected,
    CASE_INPUT_MISMATCH: bindings, INVALID_CANDIDATE_OUTCOME: invalid,
    CANDIDATE_COVERAGE_INCOMPLETE: incompleteCoverage, FIXED_SIDE_COVERAGE_INCOMPLETE: fixedGaps,
    LOST_REFERENCE_HIT: lost, LOST_PROTECTED_HIT: [...remainingProtected], NEW_UNRESOLVED_CASE: unresolved,
  };
  for (const [code, ids] of Object.entries(issueIds)) {
    if (ids.length) failures.push({ code, advisory_ids: ids.sort() });
  }
  return { lost, gained: gained.sort(), new_unresolved: unresolved,
    ...(protectedHitIds.length ? { lost_protected: [...remainingProtected].sort() } : {}) };
}

function candidateValidationFailures(candidate, candidateRulesSha256, cases) {
  const failures = [];
  if (candidate?.schema !== 'factory.recall-result.v1' || candidate.scope !== 'ecosystem'
    || !matchingMetadata(candidate, candidate.engine?.executable_sha256)) {
    failures.push({ code: 'CANDIDATE_METADATA_MISMATCH' });
  }
  if (!hexDigest.test(candidateRulesSha256) || candidate?.ruleset_sha256 !== candidateRulesSha256) {
    failures.push({ code: 'CANDIDATE_RULES_MISMATCH' });
  }
  if (!Array.isArray(candidate?.resumed_cases) || candidate.resumed_cases.length !== 0) {
    failures.push({ code: 'CANDIDATE_NOT_FRESH' });
  }
  if (cases.length !== registeredCases) failures.push({ code: 'CANDIDATE_CASE_COUNT_MISMATCH' });
  return failures;
}

function reportedSummaryMatches(reported, summary) {
  return reported?.cases === registeredCases && reported?.hunk_hits === summary.candidate_hunk_hits
    && reported?.scored === summary.candidate_outcomes.hit + summary.candidate_outcomes.miss
    && reported?.fix_side_residual_alerts === summary.candidate_fixed_side_residual_alerts + summary.candidate_recall_mode_residual_alerts
    && caseDigest([reported?.outcomes ?? null]) === caseDigest([summary.candidate_outcomes]);
}

// CLI callers authenticate the immutable reference bytes before using this comparison.
export function verifyRegisteredRecall(reference, candidate, candidateRulesSha256, protectedHitIds = [], recallRules = []) {
  if (!validReference(reference)) return { decision: 'REJECT', failures: [{ code: 'REFERENCE_METADATA_MISMATCH' }] };
  const cases = Array.isArray(candidate?.cases) ? candidate.cases : [];
  const failures = candidateValidationFailures(candidate, candidateRulesSha256, cases);
  const summary = {
    registered_cases: registeredCases, verified_bindings: 0, reference_hunk_hits: referenceHits,
    retained_hunk_hits: 0, candidate_outcomes: outcomes(),
    reference_fixed_side_residual_alerts: reference.fix_side_residual_alerts[1],
    candidate_fixed_side_residual_alerts: 0, candidate_recall_mode_residual_alerts: 0,
  };
  const pairedPathPolicy = protectedHitIds.length > 0 && candidate?.scanner_path_policy === pathPolicyProof;
  const changes = compareCases(reference.cases, cases, summary, failures, protectedHitIds, pairedPathPolicy, recallRules);
  if (protectedHitIds.length) {
    summary.protected_hunk_hits = protectedHitIds.length;
    summary.retained_protected_hunk_hits = protectedHitIds.length - changes.lost_protected.length;
    if (!pairedPathPolicy) {
      failures.push({ code: 'CANDIDATE_PATH_POLICY_MISMATCH' });
    }
  }
  summary.candidate_hunk_hits = summary.candidate_outcomes.hit;
  if (!reportedSummaryMatches(candidate?.summary, summary)) {
    failures.push({ code: 'CANDIDATE_SUMMARY_MISMATCH' });
  }
  if (summary.candidate_fixed_side_residual_alerts > summary.reference_fixed_side_residual_alerts) {
    failures.push({ code: 'FIXED_SIDE_RESIDUALS_INCREASED' });
  }
  return { decision: failures.length ? 'REJECT' : 'ACCEPT', summary, ...changes, failures };
}

export function replayRegisteredCaptures(candidate, captureRoot, manifest, rulesText) {
  const root = realpathSync(captureRoot);
  const inputs = new Map(manifest.cases.map(row => [row.ghsa, row]));
  const rules = ruleFamilies(rulesText);
  const pathPolicy = candidate.scanner_path_policy === undefined ? null
    : scannerPathPolicy({ engine: 'semgrep', tool_version: candidate.engine?.version }, rulesText);
  if (pathPolicy?.proof !== candidate.scanner_path_policy) throw new Error('Replay scanner path policy differs from the engine');
  const cases = Array.isArray(candidate?.cases) ? candidate.cases : [];
  const invalid = [], unreproduced = [];
  const sarifCache = new Map();
  let verified_capture_cases = 0;
  for (const row of cases) {
    const retained = {};
    if (!checkpointArtifactsIntact(root, row, retained)) {
      invalid.push(row.ghsa);
      continue;
    }
    if (row.source_packets?.old?.length || row.source_packets?.fixed?.length) verified_capture_cases++;
    try {
      // Every capture has already been re-read and hashed. Resolve source paths per side.
      const replay = replayCaseScore(root, inputs.get(row.ghsa), row, retained, rules, candidate.scope, pathPolicy, sarifCache);
      if (caseDigest([replay]) !== caseDigest([Object.fromEntries(Object.keys(replay).map(key => [key, row[key]]))])) {
        throw new Error('Case score differs from replay');
      }
    } catch { unreproduced.push(row.ghsa); }
  }
  return { verified_capture_cases, replayed_case_scores: cases.length - invalid.length - unreproduced.length,
    invalid: invalid.sort(), unreproduced: unreproduced.sort() };
}

function evidenceFrom(paths, captureRoot) {
  const evidence = { schema: receiptSchema };
  try {
    const [referenceBytes, candidateBytes, rulesBytes] = paths.map(path => readFileSync(path));
    evidence.reference_sha256 = sha256(referenceBytes);
    evidence.candidate_score_sha256 = sha256(candidateBytes);
    evidence.candidate_rules_sha256 = sha256(rulesBytes);
    if (evidence.reference_sha256 !== referenceSha256) {
      return { ...evidence, decision: 'REJECT', failures: [{ code: 'REFERENCE_BYTES_MISMATCH' }] };
    }
    const protectedBytes = readFileSync(new URL('../docs/evidence/recall-protected-exposed-161-63.json', import.meta.url));
    evidence.protected_hits_sha256 = sha256(protectedBytes);
    if (evidence.protected_hits_sha256 !== protectedSha256) {
      return { ...evidence, decision: 'REJECT', failures: [{ code: 'PROTECTED_HIT_SET_BYTES_MISMATCH' }] };
    }
    const protectedHits = JSON.parse(protectedBytes).required_hit_ids;
    const candidate = JSON.parse(candidateBytes);
    const recallRules = (readRuleMetadata(rulesBytes) ?? []).filter(rule => rule.mode === 'recall').map(rule => rule.id);
    const result = verifyRegisteredRecall(JSON.parse(referenceBytes), candidate, evidence.candidate_rules_sha256, protectedHits, recallRules);
    const manifestBytes = readFileSync(new URL('../docs/evidence/recall-registered-exposed-161-manifest.json', import.meta.url));
    const manifest = JSON.parse(manifestBytes);
    if (sha256(manifestBytes) !== scoringPins.manifest_sha256
      || validateRecallManifest(manifest) !== scoringPins.manifest_cases_sha256) {
      return { ...evidence, decision: 'REJECT', failures: [{ code: 'MANIFEST_BYTES_MISMATCH' }] };
    }
    const { verified_capture_cases, replayed_case_scores, invalid, unreproduced } =
      replayRegisteredCaptures(candidate, captureRoot, manifest, rulesBytes.toString('utf8'));
    if (invalid.length) result.failures.push({ code: 'CASE_CAPTURE_INTEGRITY_FAILED', advisory_ids: invalid });
    if (unreproduced.length) result.failures.push({ code: 'CASE_SCORE_REPLAY_FAILED', advisory_ids: unreproduced });
    return { ...evidence, ...result, decision: result.failures.length ? 'REJECT' : 'ACCEPT',
      verified_capture_cases, replayed_case_scores };
  } catch {
    return { ...evidence, decision: 'REJECT', failures: [{ code: 'UNREADABLE_OR_INVALID_EVIDENCE' }] };
  }
}

function normalizedPath(path) {
  try { return realpathSync(path); }
  catch { return resolve(path); }
}

function main(args) {
  const [reference, candidate, rules, receipt, captureRoot] = args;
  const sources = [reference, candidate, rules];
  if (args.length !== 5 || sources.some(path => normalizedPath(path) === normalizedPath(receipt))) {
    console.error('Usage: verify_registered_recall.mjs REFERENCE_JSON CANDIDATE_SCORE_JSON CANDIDATE_RULES_YML RECEIPT_JSON CAPTURES_DIR');
    return 2;
  }
  const evidence = evidenceFrom(sources, captureRoot);
  try { writeFileSync(receipt, `${JSON.stringify(evidence, null, 2)}\n`); }
  catch { console.error('Unable to write the registered recall receipt.'); return 2; }
  console.log(`${evidence.decision} registered recall retention`);
  return evidence.decision === 'ACCEPT' ? 0 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
