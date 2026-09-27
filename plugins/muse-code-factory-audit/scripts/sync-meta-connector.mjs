#!/usr/bin/env node
// Export only a current HMAC-sealed Muse audit summary to the Meta REST API.
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gitState, receiptMac } from '../hooks/audit.mjs';

const MAX_RECEIPT_BYTES = 8 * 1024 * 1024;
const STATUS = { passed: 'PASS', findings: 'FAIL', failed: 'FAIL',
  incomplete: 'INCOMPLETE', unavailable: 'INCOMPLETE', reported: 'INCOMPLETE',
  skipped: 'NOT_RUN', not_routed: 'NOT_RUN' };
const LANES = { codeFactory: 'code_factory', forgeLine: 'forgeline',
  appForge: 'appforge', saasForge: 'saasforge', deepPenetration: 'full_depth' };

function safeText(value, max) {
  return Array.from(String(value ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' '))
    .slice(0, max).map((char) => char.length === 1 && /[\uD800-\uDFFF]/.test(char) ? '\uFFFD' : char)
    .join('').trim();
}

function readCurrentReceipt(workspace) {
  const root = realpathSync(workspace);
  const current = gitState(root);
  if (!current) throw new Error('Git snapshot cannot be verified.');
  const dir = path.join(process.env.MUSE_PLUGIN_DATA_DIR || os.tmpdir(), 'cf-build-audit', 'receipts');
  const file = path.join(dir, `${createHash('sha256').update(root).digest('hex')}.json`);
  if (statSync(file).size > MAX_RECEIPT_BYTES) throw new Error('Audit receipt exceeds size limit.');
  const receipt = JSON.parse(readFileSync(file, 'utf8'));
  const { sha256, hmacSha256, ...body } = receipt;
  const payload = JSON.stringify(body);
  const actual = createHash('sha256').update(payload).digest('hex');
  const mac = receiptMac(payload);
  if (typeof sha256 !== 'string' || sha256 !== actual ||
      typeof hmacSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(hmacSha256) ||
      !timingSafeEqual(Buffer.from(hmacSha256, 'hex'), Buffer.from(mac, 'hex')) ||
      receipt.schemaVersion !== 'muse.cf-build-review.v2' || receipt.workspace !== root ||
      receipt.head !== current.head || receipt.worktreeSha256 !== current.worktreeSha256 ||
      receipt.policySha256 !== current.policySha256 ||
      !Number.isFinite(Date.parse(receipt.expiresAt)) || Date.parse(receipt.expiresAt) <= Date.now()) {
    throw new Error('Audit receipt is stale, tampered, expired, or for another worktree.');
  }
  return receipt;
}

function laneFor(value) {
  const label = String(value || '').toLowerCase();
  if (/forgeline/.test(label)) return 'forgeline';
  if (/appforge/.test(label)) return 'appforge';
  if (/saasforge/.test(label)) return 'saasforge';
  if (/full.depth|penetration/.test(label)) return 'full_depth';
  return 'code_factory';
}

export function snapshotFromReceipt(receipt, repository) {
  if (!/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(repository) ||
      repository.split('/').some((part) => part.startsWith('.') || part.includes('..'))) {
    throw new Error('Repository must be an owner/name slug.');
  }
  const outcomes = Object.fromEntries(Object.entries(LANES).map(([key, lane]) =>
    [lane, STATUS[receipt.outcomes?.[key]] || 'INCOMPLETE']));
  const rows = Array.isArray(receipt.findings?.rows) ? receipt.findings.rows : [];
  const total = Number.isSafeInteger(receipt.findings?.total) ? receipt.findings.total : rows.length;
  const findings = rows.slice(0, 500).map((row) => {
    const severity = String(row?.severity || '').toLowerCase();
    const safeSeverity = ['critical', 'high', 'medium', 'low', 'info'].includes(severity) ? severity : 'info';
    const candidatePath = safeText(row?.path || 'unknown', 300).replaceAll('\\', '/');
    const safePath = candidatePath.startsWith('/') || /^[A-Za-z]:/.test(candidatePath) ||
      candidatePath.includes('://') || candidatePath.split('/').includes('..') ? 'unknown' : candidatePath;
    return { path: safePath || 'unknown', line: Number.isInteger(row?.line) && row.line > 0 ? row.line : 0,
      severity: safeSeverity, title: safeText(row?.code || 'finding', 160) || 'finding',
      resolution: safeText(row?.action || 'Inspect the finding at its source and rerun the lane.', 500) || 'Inspect and rerun.',
      lane: laneFor(row?.lane) };
  });
  const coverage = [
    'Source: current local Muse audit receipt; local HMAC and Git snapshot verified, not independent attestation.',
    'Code Factory pattern and guard-path coverage needs .factory/review-audits.json; its security check analyzes Python ASTs only.',
    'ForgeLine repo-wide inventory does not prove feature SSAT QA or release admission.',
    'Full-depth penetration remains incomplete unless separately executed and attested.',
  ];
  if (receipt.policySha256 === null) {
    coverage.push('Project .factory/review-audits.json is absent; pattern and guard-path checks are unavailable.');
    if (outcomes.code_factory === 'PASS') outcomes.code_factory = 'INCOMPLETE';
  }
  if (total > findings.length) {
    coverage.push(`Only ${findings.length} of ${total} finding rows are exported. Inspect the local scanner output.`);
    for (const lane of Object.keys(outcomes)) {
      if (outcomes[lane] === 'PASS') outcomes[lane] = 'INCOMPLETE';
    }
  }
  return { schema: 'factory.meta.audit.v1', repository, commit_sha: receipt.head,
    policy_sha256: receipt.policySha256, created_at: receipt.createdAt,
    outcomes, findings, coverage };
}

async function main() {
  const [workspace, repository, endpoint] = process.argv.slice(2);
  if (!workspace || !repository || !endpoint) {
    throw new Error('Usage: node sync-meta-connector.mjs <workspace> <owner/repo> <--dry-run|https://host/v1/audits>');
  }
  const snapshot = snapshotFromReceipt(readCurrentReceipt(workspace), repository);
  if (endpoint === '--dry-run') {
    process.stdout.write(`${JSON.stringify(snapshot)}\n`);
    return;
  }
  const url = new URL(endpoint);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
      !url.pathname.endsWith('/v1/audits')) throw new Error('Endpoint must be credential-free HTTPS /v1/audits.');
  const token = process.env.FACTORY_META_ACCESS_TOKEN;
  if (!token || token.length > 8192) throw new Error('FACTORY_META_ACCESS_TOKEN is required.');
  const response = await fetch(url, { method: 'POST', redirect: 'error',
    signal: AbortSignal.timeout(10_000), headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(snapshot) });
  if (response.status !== 201) throw new Error(`Meta connector upload failed (HTTP ${response.status}).`);
  const result = await response.json();
  if (!result.id || !result.snapshot_sha256) throw new Error('Meta connector response is incomplete.');
  process.stdout.write(`${JSON.stringify({ id: result.id, snapshot_sha256: result.snapshot_sha256, status: 'uploaded' })}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
