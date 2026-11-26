import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';

// The loss plan pins two local JSON files as {path, sha256} under score and
// adjudication. manifest_cases_sha256 selects the reviewed spent cohort.
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const isPin = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const MAX_BYTES = 32_000_000;

function readJson(path) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile()) throw new Error('Adjudicated loss input must be a regular file');
    if (opened.size > MAX_BYTES) throw new Error('Adjudicated loss input exceeds the byte limit');
    const buffer = Buffer.alloc(opened.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const count = readSync(fd, buffer, offset, buffer.length - offset, null);
      if (!count) break;
      offset += count;
    }
    const finished = fstatSync(fd);
    if (offset !== opened.size || finished.size !== opened.size
        || finished.mtimeMs !== opened.mtimeMs || finished.ctimeMs !== opened.ctimeMs) {
      throw new Error('Adjudicated loss input changed while being read');
    }
    const bytes = buffer.subarray(0, offset);
    return { data: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), sha256: digest(bytes) };
  } finally {
    closeSync(fd);
  }
}

function readPinned(directory, reference) {
  const { path, sha256 } = reference;
  if (!isPin(sha256) || typeof path !== 'string' || isAbsolute(path) || path.split(/[\\/]/).includes('..')) {
    throw new Error('Adjudicated loss sources require a relative path and SHA-256');
  }
  const input = readJson(resolve(directory, path));
  if (input.sha256 !== sha256) throw new Error('Adjudicated loss source fingerprint differs');
  return input;
}

function validSpan(span) {
  if (!Array.isArray(span) || span.length !== 3) return false;
  const [start, offset, end] = span;
  return Number.isSafeInteger(offset) && offset >= 0
    && [start, end].every(column => column === null || (Number.isSafeInteger(column) && column > 0))
    && (offset > 0 || start !== null || end !== null)
    && (offset !== 0 || (end ?? Infinity) >= (start ?? 0));
}

function reviewedFinding(row) {
  const cases = row.repository_case.match(/GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}/g);
  const fields = [row.item, row.rule, row.file];
  if (cases?.length !== 1 || fields.some(value => typeof value !== 'string' || !value)
      || !Number.isSafeInteger(row.line) || row.line < 1 || !['FP', 'TP', 'UNCLEAR'].includes(row.final)) {
    throw new Error('Invalid hunk adjudication identity or verdict');
  }
  if (row.span != null && !validSpan(row.span)) throw new Error('Invalid hunk adjudication span');
  if (row.source_sha256 != null && !isPin(row.source_sha256)) throw new Error('Invalid hunk adjudication source SHA-256');
  const location = [row.rule, row.file, row.line];
  if (row.span != null) location.push(row.span);
  return { ghsa: cases[0], location, verdict: row.final, sourceSha256: row.source_sha256 ?? null };
}

function reviewedHunks(rows) {
  const unique = new Map();
  for (const row of rows) {
    if (row.on_fix_hunk !== true) continue;
    const finding = reviewedFinding(row), previous = unique.get(row.item);
    if (previous && JSON.stringify(previous) !== JSON.stringify(finding)) throw new Error('Conflicting adjudicated item');
    unique.set(row.item, finding);
  }
  const grouped = new Map();
  for (const finding of unique.values()) {
    if (!grouped.has(finding.ghsa)) grouped.set(finding.ghsa, []);
    grouped.get(finding.ghsa).push(finding);
  }
  return grouped;
}

export function hunkIdentity(findings, spanBound = null) {
  const locations = findings.map(finding => JSON.stringify(finding));
  if (spanBound === null) return JSON.stringify(locations.sort());
  const distinct = [...new Set(locations)];
  // Line-only votes cannot distinguish multiple alerts. Exact repeats are one alert.
  return !spanBound && distinct.length !== locations.length ? null : JSON.stringify(distinct.sort());
}

export function hunkAdjudicationIdentity(row, spanBound) {
  const findings = row.hunk_findings ?? [];
  if (!findings.length) return null;
  if (!spanBound) return hunkIdentity(findings, false);
  const spans = row.hunk_spans;
  if (!Array.isArray(spans) || spans.length !== findings.length) return null;
  if (!spans.every(span => validSpan(span) && span[0] !== null && span[2] !== null)) return null;
  return hunkIdentity(findings.map((finding, index) => [...finding, spans[index]]), true);
}

function boundCohort(score, adjudication, cohort) {
  if (score.schema !== 'factory.recall-evaluation.v1' || adjudication.schema !== 'factory.adjudicated-precision.v1') {
    throw new Error('Unsupported adjudicated loss source schema');
  }
  const rulePrefix = String(adjudication.candidate).match(/\(ruleset ([a-f0-9]{8,64})\)$/)?.[1];
  if (!rulePrefix || !isPin(score.candidate_sha256) || !score.candidate_sha256.startsWith(rulePrefix)) {
    throw new Error('Adjudication candidate differs from the saved ruleset');
  }
  if (!isPin(cohort) || !adjudication.cohort.includes('(spent)')) throw new Error('Adjudication needs a registered spent cohort');
  const blocks = score.dev.filter(item => item.manifest_cases_sha256 === cohort);
  if (blocks.length !== 1 || blocks[0].after_evidence.ruleset_sha256 !== score.candidate_sha256) {
    throw new Error('Adjudication cohort is absent or ambiguous in saved evidence');
  }
  return blocks[0];
}

function matchReviewedHunks(row, source, votes, requireBoundSpans) {
  const spanBound = votes[0].location.length === 4;
  if (!votes.every(vote => vote.verdict === 'FP' && (vote.location.length === 4) === spanBound)) return null;
  if (requireBoundSpans && (!spanBound || votes.some(vote => !vote.sourceSha256))) return null;
  const sourcePins = new Map((source.source_packets.old ?? []).map(packet => [packet.path, packet.sha256]));
  if (votes.some(vote => vote.sourceSha256 && vote.sourceSha256 !== sourcePins.get(vote.location[1]))) return null;
  const identity = hunkAdjudicationIdentity(row, spanBound);
  return identity && identity === hunkIdentity(votes.map(vote => vote.location), spanBound)
    ? { source, identity, spanBound } : null;
}

function fpOnlyCases(block, labels, requireBoundSpans) {
  const evidence = new Map(block.after_evidence.cases.map(row => [row.ghsa, row]));
  if (evidence.size !== block.after_evidence.cases.length || new Set(block.cases.map(row => row.ghsa)).size !== block.cases.length) {
    throw new Error('Duplicate case in saved adjudication cohort');
  }
  const result = new Map();
  for (const row of block.cases) {
    const votes = labels.get(row.ghsa), source = evidence.get(row.ghsa);
    if (row.after !== 'hit' || !votes?.length || !source?.revisions || !source.source_packets) continue;
    const match = matchReviewedHunks(row, source, votes, requireBoundSpans);
    if (match) result.set(row.ghsa, match);
  }
  return result;
}

export function loadAdjudicatedLosses(planPath, engineSha, { requireBoundSpans = false } = {}) {
  const plan = readJson(planPath).data;
  if (plan.schema !== 'factory.recall-adjudicated-losses.v1') throw new Error('Unexpected adjudicated loss plan');
  const directory = dirname(resolve(planPath));
  const { data: score, sha256: scoreSha } = readPinned(directory, plan.score);
  const { data: adjudication, sha256: adjudicationSha } = readPinned(directory, plan.adjudication);
  if (!isPin(engineSha) || score.engine.executable_sha256 !== engineSha) {
    throw new Error('Adjudicated loss engine differs from the current execution');
  }
  const block = boundCohort(score, adjudication, plan.manifest_cases_sha256);
  const evidence = block.after_evidence;
  if (!isPin(evidence.manifest_sha256) || !isPin(evidence.profile_sha256)) throw new Error('Missing bound adjudication context');
  return {
    cases: fpOnlyCases(block, reviewedHunks(adjudication.rows), requireBoundSpans),
    receipt: { score_sha256: scoreSha, adjudication_sha256: adjudicationSha, engine_sha256: engineSha,
      review_independence: 'UNESTABLISHED',
      ...(requireBoundSpans ? { exact_spans_and_source: true } : {}),
      engine_args: [].concat(score.extra_args ?? [], score.candidate_extra_args ?? []),
      ruleset_sha256: score.candidate_sha256, manifest_sha256: evidence.manifest_sha256,
      manifest_cases_sha256: plan.manifest_cases_sha256, profile_sha256: evidence.profile_sha256 },
  };
}
