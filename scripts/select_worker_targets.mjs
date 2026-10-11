import { appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const sdkTargets = Object.freeze([
  'codeql-python-worker', 'codeql-javascript-worker', 'codeql-actions-worker',
  'osv-worker', 'syft-worker', 'gitleaks-worker', 'trivy-worker', 'runtime-worker', 'fuzz-worker',
]);

const hash = /^[a-f0-9]{40}$/i;
const semgrepPaths = new Set([
  'deploy/deep-adapters/rules/semgrep-pattern-limited.yml',
  'deploy/deep-adapters/profiles/semgrep-pattern-limited.json',
  'deploy/deep-adapters/rules/tests/python-controls.txt',
  'deploy/deep-adapters/rules/tests/javascript-controls.js',
  'scripts/verify_semgrep_surface.mjs',
]);

function sha(value) {
  return typeof value === 'string' && hash.test(value) ? value : null;
}

function gitOutput(git, args) {
  const output = git('git', args, { encoding: 'buffer', stdio: ['ignore', 'pipe', 'pipe'] });
  return Buffer.isBuffer(output) ? output : Buffer.from(output);
}

function revisionOutput(git, args) {
  const output = gitOutput(git, args).toString('ascii');
  const match = /^([a-f0-9]{40})\n?$/.exec(output);
  return match ? match[1] : null;
}

function requireEmptyOutput(git, args) {
  if (gitOutput(git, args).length !== 0) throw new Error(`Unexpected output from git ${args[0]}`);
}

export function selectWorkerTargets(name, event, git = execFileSync) {
  const full = { sdk: 'true', matrix: JSON.stringify(sdkTargets), reason: 'fail-closed-full-matrix' };
  try {
    let base;
    let eventHead;
    if (name === 'pull_request') {
      base = sha(event.pull_request?.base?.sha);
      eventHead = sha(event.pull_request?.head?.sha);
    } else if (name === 'push') {
      base = sha(event.before);
      eventHead = sha(event.after);
    } else {
      return { ...full, reason: 'manual-or-unknown-event' };
    }
    if (!base || !eventHead) return { ...full, reason: 'unresolvable-revisions' };

    const checkout = revisionOutput(git, ['rev-parse', '--verify', 'HEAD']);
    if (!checkout) return { ...full, reason: 'unresolvable-checkout' };
    requireEmptyOutput(git, ['diff-index', '--quiet', 'HEAD', '--']);

    if (name === 'push') {
      if (checkout !== eventHead) return { ...full, reason: 'checkout-mismatch' };
    } else {
      requireEmptyOutput(git, ['merge-base', '--is-ancestor', base, checkout]);
      requireEmptyOutput(git, ['merge-base', '--is-ancestor', eventHead, checkout]);
    }

    const output = gitOutput(git, ['diff', '--name-only', '-z', base, checkout, '--']);
    const raw = output;
    if (!raw.length || raw[raw.length - 1] !== 0) return { ...full, reason: 'empty-or-malformed-diff' };
    const paths = raw.subarray(0, -1).toString('utf8').split('\0');
    if (!paths.length || paths.some(path => !path || path.includes('\ufffd'))) return { ...full, reason: 'malformed-path-list' };
    if (paths.every(path => semgrepPaths.has(path))) {
      return { sdk: 'false', matrix: JSON.stringify(sdkTargets), reason: 'semgrep-only' };
    }
    return { ...full, reason: 'common-or-unknown-path' };
  } catch {
    return { ...full, reason: 'git-diff-failed' };
  }
}

function main() {
  let event;
  try {
    event = JSON.parse(process.env.GITHUB_EVENT_JSON ?? 'null');
  } catch {
    event = null;
  }
  const result = selectWorkerTargets(process.env.GITHUB_EVENT_NAME, event);
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `sdk=${result.sdk}\nmatrix=${result.matrix}\nreason=${result.reason}\n`);
  } else {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
