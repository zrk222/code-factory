import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { sha256, sortKeys } from './recall_harness.mjs';
import { inputFingerprint, verifyRegisteredRecall } from './verify_registered_recall.mjs';

const rulesHash = 'a'.repeat(64);
const pins = {
  manifest_sha256: 'bb7a28c66c7062256851933a1e746c1fb33327021e53294d3a2e6e10d04deb60',
  manifest_cases_sha256: '5f332b159a68e4236215843095a669afe2d150757eaee4c18ece33005f0b0013',
  profile_sha256: '8ec08b713a3bd64cd272cda054faab0fe206be45d79258d74b1099f1ab326dd6',
  engine_args: ['--timeout=15', '--jobs=1'],
};
const engineSha256 = 'fae553cdfd1badcb30a480ec5c47e3e14355744167bff4303dc45ab436253e7a';
const alphabet = '23456789cfghjmpqrvwx';
const findings = [['fixture', 'fixture.js', 1]];
const fixedPacket = { path: 'fixture.js', bytes: 9, sha256: '2'.repeat(64) };
const fixedCoverage = { ...fixedPacket, submitted: true, state: 'reported_scanned', reason: 'engine_scan_paths' };

function fixture() {
  const cases = Array.from({ length: 161 }, (_, index) => {
    const hunkHit = index < 39;
    return {
      ghsa: `GHSA-2222-2222-22${alphabet[Math.floor(index / alphabet.length)]}${alphabet[index % alphabet.length]}`,
      ecosystem: 'npm', fix: 'f'.repeat(40), revisions: { old: 'e'.repeat(40), fixed: 'f'.repeat(40) },
      diff_sha256: 'd'.repeat(64), source_packets: { old: [], fixed: [fixedPacket] }, changed_files_sha256: 'c'.repeat(64),
      status: index === 160 ? 'no_old_side_source' : 'scored',
      outcome: index === 160 ? 'unknown' : hunkHit ? 'hit' : 'miss',
      hunk_hit: hunkHit, hunk_findings: hunkHit ? findings : [], fix_side_residual: [], file_coverage: { old: [], fixed: [{ ...fixedCoverage }] },
    };
  });
  const reference = {
    ...pins, schema: 'factory.recall-exposed-run-readback.v1', engine: { version: '2.1.0', sha256: engineSha256 },
    candidate: { registered: 161, hunk_hits: 39 }, fix_side_residual_alerts: [0, 0],
    cases: cases.map(({ ghsa, ecosystem, outcome, revisions, diff_sha256, source_packets, changed_files_sha256 }) => ({
      advisory: ghsa, ecosystem, after: outcome,
      input_sha256: sha256(JSON.stringify(sortKeys({ ghsa, revisions, diff_sha256, source_packets, changed_files_sha256 }))),
    })),
  };
  const candidate = {
    ...pins, schema: 'factory.recall-result.v1', scope: 'ecosystem',
    engine: { version: '2.1.0', executable_sha256: engineSha256 }, ruleset_sha256: rulesHash, resumed_cases: [], cases,
    summary: { cases: 161, hunk_hits: 39, scored: 160, fix_side_residual_alerts: 0,
      outcomes: { hit: 39, miss: 121, timeout: 0, unknown: 1, error: 0, coverage_incomplete: 0 } },
  };
  return { reference, candidate };
}

test('inputFingerprint binds the exact source packets to the registered digest', () => {
  const { reference, candidate } = fixture();
  const [row] = candidate.cases;
  assert.equal(inputFingerprint(row), reference.cases[0].input_sha256);
  assert.notEqual(inputFingerprint({ ...row, source_packets: { old: [], fixed: [] } }),
    reference.cases[0].input_sha256);
});

test('retains all reference hits with every input fingerprint verified', () => {
  const { reference, candidate } = fixture();
  const result = verifyRegisteredRecall(reference, candidate, rulesHash);
  assert.equal(result.decision, 'ACCEPT');
  assert.equal(result.summary.verified_bindings, 161);
  assert.equal(result.summary.retained_hunk_hits, 39);
  assert.deepEqual(result.lost, []);
});

test('protects the exact gained hits even when a replacement preserves the total', () => {
  const { reference, candidate } = fixture();
  for (const row of candidate.cases.slice(39, 63)) {
    Object.assign(row, { outcome: 'hit', hunk_hit: true, hunk_findings: findings });
  }
  const protectedHits = candidate.cases.slice(0, 63).map(row => row.ghsa);
  Object.assign(candidate.summary, { hunk_hits: 63 });
  Object.assign(candidate.summary.outcomes, { hit: 63, miss: 97 });
  candidate.scanner_path_policy = 'opengrep-2.1.0-target-inventory-v1';
  assert.equal(verifyRegisteredRecall(reference, candidate, rulesHash, protectedHits).decision, 'ACCEPT');
  const lost = candidate.cases[62];
  Object.assign(lost, { outcome: 'miss', hunk_hit: false, hunk_findings: [] });
  Object.assign(candidate.cases[63], { outcome: 'hit', hunk_hit: true, hunk_findings: findings });
  const result = verifyRegisteredRecall(reference, candidate, rulesHash, protectedHits);
  assert.equal(result.decision, 'REJECT');
  assert.equal(result.summary.candidate_hunk_hits, 63);
  assert.equal(result.summary.retained_protected_hunk_hits, 62);
  assert.deepEqual(result.lost_protected, [lost.ghsa]);
  assert.deepEqual(result.failures, [{ code: 'LOST_PROTECTED_HIT', advisory_ids: [lost.ghsa] }]);
  delete candidate.scanner_path_policy;
  assert(verifyRegisteredRecall(reference, candidate, rulesHash, protectedHits).failures.some(
    failure => failure.code === 'CANDIDATE_PATH_POLICY_MISMATCH'));
});

test('rejects spoofed input metadata and recomputes the score summary', () => {
  const { reference, candidate } = fixture();
  candidate.engine.executable_sha256 = 'f'.repeat(64);
  candidate.summary.hunk_hits = 80;
  candidate.resumed_cases = [candidate.cases[0].ghsa];
  const result = verifyRegisteredRecall(reference, candidate, 'b'.repeat(64));
  assert.equal(result.decision, 'REJECT');
  assert.deepEqual(result.failures.map(issue => issue.code), [
    'CANDIDATE_METADATA_MISMATCH', 'CANDIDATE_RULES_MISMATCH', 'CANDIDATE_NOT_FRESH', 'CANDIDATE_SUMMARY_MISMATCH',
  ]);
});

test('rejects a duplicate replacing one advisory and rejects fingerprint drift', () => {
  const { reference, candidate } = fixture();
  const missing = candidate.cases.at(-1).ghsa;
  candidate.cases.at(-2).diff_sha256 = 'f'.repeat(64);
  candidate.cases.splice(-1, 1, { ...candidate.cases[0] });
  const result = verifyRegisteredRecall(reference, candidate, rulesHash);
  assert.equal(result.decision, 'REJECT');
  assert.deepEqual(result.failures.slice(0, 3), [
    { code: 'DUPLICATE_CANDIDATE_ADVISORY', advisory_ids: [candidate.cases[0].ghsa] },
    { code: 'MISSING_CANDIDATE_ADVISORY', advisory_ids: [missing] },
    { code: 'CASE_INPUT_MISMATCH', advisory_ids: [candidate.cases.at(-2).ghsa] },
  ]);
  assert.equal(result.summary.verified_bindings, 159);
});

test('rejects an offsetting gain despite an unchanged total', () => {
  const { reference, candidate } = fixture();
  Object.assign(candidate.cases[0], { outcome: 'miss', hunk_hit: false, hunk_findings: [] });
  Object.assign(candidate.cases[39], { outcome: 'hit', hunk_hit: true, hunk_findings: findings });
  const result = verifyRegisteredRecall(reference, candidate, rulesHash);
  assert.equal(result.decision, 'REJECT');
  assert.equal(result.summary.candidate_hunk_hits, 39);
  assert.deepEqual(result.lost, [candidate.cases[0].ghsa]);
  assert.deepEqual(result.gained, [candidate.cases[39].ghsa]);
});

test('counts a recovered unresolved case as a gain', () => {
  const { reference, candidate } = fixture();
  const recovered = candidate.cases.at(-1);
  Object.assign(recovered, { status: 'scored', outcome: 'hit', hunk_hit: true, hunk_findings: findings });
  candidate.summary.scored++;
  candidate.summary.hunk_hits++;
  candidate.summary.outcomes.unknown--;
  candidate.summary.outcomes.hit++;
  const result = verifyRegisteredRecall(reference, candidate, rulesHash);
  assert.equal(result.decision, 'ACCEPT');
  assert.equal(result.summary.candidate_hunk_hits, 40);
  assert.deepEqual(result.gained, [recovered.ghsa]);
});

test('rejects scored cases with missing or incomplete fixed-side coverage', () => {
  const { reference, candidate } = fixture();
  delete candidate.cases[0].file_coverage.fixed;
  candidate.cases[1].file_coverage.fixed = [
    { path: 'fixture.js', state: 'unreported', reason: 'absent_from_engine_paths' },
  ];
  candidate.cases[2].file_coverage.fixed = [];
  candidate.cases[3].file_coverage.fixed[0].bytes++;
  const result = verifyRegisteredRecall(reference, candidate, rulesHash);
  assert.equal(result.decision, 'REJECT');
  assert.equal(result.summary.retained_hunk_hits, 39);
  assert.deepEqual(result.failures, [{ code: 'FIXED_SIDE_COVERAGE_INCOMPLETE',
    advisory_ids: candidate.cases.slice(0, 4).map(row => row.ghsa) }]);
});

test('requires matching old and fixed evidence for registered scanner path exclusions', () => {
  const { reference, candidate } = fixture();
  candidate.scanner_path_policy = 'opengrep-2.1.0-target-inventory-v1';
  const excluded = { ...fixedCoverage, state: 'excluded', reason: 'scanner_path_policy', policy: 'engine_target_ignore' };
  const [matched, oneSided, differentPolicy, changedBytes, unknownPolicy, duplicate] = candidate.cases;
  matched.file_coverage = { old: [excluded], fixed: [excluded] };
  const protectedHits = [matched.ghsa];
  assert.equal(verifyRegisteredRecall(reference, candidate, rulesHash, protectedHits).decision, 'ACCEPT');
  oneSided.file_coverage = { old: [fixedCoverage], fixed: [excluded] };
  differentPolicy.file_coverage = { old: [{ ...excluded, policy: 'rule_path_exclusions' }], fixed: [excluded] };
  changedBytes.file_coverage = { old: [excluded], fixed: [{ ...excluded, bytes: 10 }] };
  const unsupported = { ...excluded, policy: 'file_size_limit' };
  unknownPolicy.file_coverage = { old: [unsupported], fixed: [unsupported] };
  duplicate.file_coverage = { old: [excluded, excluded], fixed: [excluded] };
  const result = verifyRegisteredRecall(reference, candidate, rulesHash, protectedHits);
  assert.deepEqual(result.failures, [{ code: 'FIXED_SIDE_COVERAGE_INCOMPLETE',
    advisory_ids: candidate.cases.slice(1, 6).map(row => row.ghsa) }]);
});

test('rejects retained historical coverage gaps even when all protected hits remain', () => {
  const { reference, candidate } = fixture();
  candidate.scanner_path_policy = 'opengrep-2.1.0-target-inventory-v1';
  const index = 100;
  const row = candidate.cases[index];
  reference.cases[index].after = 'coverage_incomplete';
  row.outcome = 'coverage_incomplete';
  row.file_coverage.old = [{ path: 'fixture.js', submitted: true, state: 'unreported' }];
  candidate.summary.scored--;
  candidate.summary.outcomes.miss--;
  candidate.summary.outcomes.coverage_incomplete++;
  const protectedHits = candidate.cases.slice(0, 39).map(item => item.ghsa);
  const result = verifyRegisteredRecall(reference, candidate, rulesHash, protectedHits);
  assert.equal(result.summary.retained_protected_hunk_hits, 39);
  assert.equal(result.decision, 'REJECT');
  assert.deepEqual(result.failures, [{ code: 'CANDIDATE_COVERAGE_INCOMPLETE', advisory_ids: [row.ghsa] }]);
});

test('rejects unresolved cases and extra fixed-side residuals', () => {
  const { reference, candidate } = fixture();
  Object.assign(candidate.cases[39], { status: 'no_old_side_source', outcome: 'unknown' });
  candidate.cases[0].fix_side_residual = findings;
  candidate.summary.outcomes.miss--;
  candidate.summary.outcomes.unknown++;
  candidate.summary.scored--;
  candidate.summary.fix_side_residual_alerts = 1;
  const result = verifyRegisteredRecall(reference, candidate, rulesHash);
  assert.equal(result.decision, 'REJECT');
  assert.deepEqual(result.failures, [
    { code: 'NEW_UNRESOLVED_CASE', advisory_ids: [candidate.cases[39].ghsa] },
    { code: 'FIXED_SIDE_RESIDUALS_INCREASED' },
  ]);
});

test('CLI writes a rejected receipt when the reference bytes are unauthenticated', t => {
  const dir = mkdtempSync(join(tmpdir(), 'registered-recall-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { reference, candidate } = fixture();
  const paths = ['reference.json', 'candidate.json', 'rules.yml', 'receipt.json'].map(name => join(dir, name));
  writeFileSync(paths[0], JSON.stringify(reference));
  writeFileSync(paths[1], JSON.stringify(candidate));
  writeFileSync(paths[2], 'fixture');
  const script = fileURLToPath(new URL('./verify_registered_recall.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, ...paths, dir]);
  const receipt = JSON.parse(readFileSync(paths[3]));
  assert.equal(result.status, 2);
  assert.equal(receipt.decision, 'REJECT');
  assert.deepEqual(receipt.failures, [{ code: 'REFERENCE_BYTES_MISMATCH' }]);
});
