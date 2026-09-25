// Bounded, read-only build audits for Muse Code's native plugin hooks.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const MAX_OUTPUT = 2_000;
const MAX_SPEC_FILES = 12;
const MAX_SPEC_BYTES = 524_288;
const STATE_TTL_MS = 7 * 24 * 60 * 60 * 1_000;
const STATE_DIR = path.join(
  process.env.MUSE_PLUGIN_DATA_DIR || os.tmpdir(),
  'cf-build-audit',
);
const BUILD_PATTERNS = [
  /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build(?:[:_-][\w.-]+)?\b/i,
  /\b(?:vite|webpack|rollup|esbuild|next|nuxt|astro|parcel)\s+build\b/i,
  /\b(?:tsc|vue-tsc)\b/i,
  /\b(?:cargo|go)\s+build\b/i,
  /\b(?:dotnet|msbuild)\b[^\r\n]*\bbuild\b/i,
  /\b(?:mvn|mvnw)\b[^\r\n]*\b(?:compile|package|install|verify)\b/i,
  /\b(?:gradle|gradlew)\b[^\r\n]*\b(?:assemble|build|compile\w*)\b/i,
  /\b(?:make|nmake)\b[^\r\n]*\b(?:all|build|compile|package)\b/i,
  /\bpython(?:3(?:\.\d+)?)?\s+-m\s+build\b/i,
];
const APPFORGE_TERMS =
  /\b(?:ios|ipados|android|swiftui|uikit|app store|play store|storekit|testflight|react native|flutter|native mobile app|mobile app)\b/gi;
const SAAS_TERMS =
  /\b(?:saas|oauth2?|oidc|identity provider|subscriptions?|entitlements?|billing|multi[- ]tenant|tenant|role[- ]based access|rbac|stripe|revocation)\b/gi;
const SAAS_DIRECT_TERMS =
  /\b(?:saas|oauth2?|oidc|identity provider|multi[- ]tenant|tenant|role[- ]based access|rbac|stripe|revocation)\b/gi;
const SPEC_PATH = /(?:^|[\\/])(?:prd|prds|spec|specs|requirements?|product-brief)(?:[\\/._-]|$)|(?:^|[\\/])(?:prd|specification|requirements?)(?:[._-][^\\/]*)?\.md$/i;
const SPEC_HEADING = /^#{1,3}\s+.{0,100}\b(?:product requirements?|software requirements?|technical specification|product specification|acceptance criteria|ssat)\b/im;

function emit(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function readEvent() {
  try {
    return JSON.parse(readFileSync(0, 'utf8'));
  } catch {
    return {};
  }
}

function collectText(value, depth = 0) {
  if (depth > 4 || value == null) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map((item) => collectText(item, depth + 1)).join(' ');
  if (typeof value !== 'object') return '';
  return ['command', 'cmd', 'script', 'input', 'text', 'arguments']
    .map((key) => collectText(value[key], depth + 1))
    .filter(Boolean)
    .join(' ');
}

function isBuildCommand(command) {
  return BUILD_PATTERNS.some((pattern) => pattern.test(command));
}

function runRtk(args, cwd, input) {
  const result = spawnSync('rtk', ['proxy', ...args], {
    cwd,
    encoding: 'utf8',
    input,
    windowsHide: true,
    timeout: 60_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  return {
    exitCode: result.status,
    timedOut: result.error?.code === 'ETIMEDOUT',
    errorCode: result.error?.code || null,
    error: result.error?.message || null,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
  };
}

function parseJson(stdout) {
  if (!stdout) return undefined;
  try {
    return JSON.parse(stdout);
  } catch {
    const lines = stdout.split(/\r?\n/).reverse();
    for (const line of lines) {
      try {
        return JSON.parse(line);
      } catch {
        // RTK and CLI wrappers can add status lines around JSON output.
      }
    }
    return undefined;
  }
}

function clipped(value) {
  return String(value || '').replace(/\s+/g, ' ').slice(0, MAX_OUTPUT);
}

function compactCli(result, label, scope = '') {
  const detail = result.stderr || result.stdout;
  if (result.timedOut) {
    return `${label}: timed out${scope}${detail ? `; detail=${clipped(detail)}` : ''}`;
  }
  if (result.error) {
    const state = result.errorCode === 'ENOENT' ? 'unavailable; executable not found' : 'failed to start';
    return `${label}: ${state}${scope}; detail=${clipped(detail || result.error)}`;
  }
  const data = parseJson(result.stdout);
  if (result.exitCode !== 0 && !data) {
    return `${label}: failed (exit_code=${result.exitCode})${scope}${detail ? `; detail=${clipped(detail)}` : ''}`;
  }
  if (!data) {
    return `${label}: completed (exit 0)${scope}${result.stdout ? `; output=${clipped(result.stdout)}` : ''}`;
  }
  const state = data.state || data.status || data.verdict || data.decision || data.grade || data.marker || 'completed';
  const scanned = typeof data.files_scanned === 'number' ? `; files_scanned=${data.files_scanned}` : '';
  const projectionCounts = [
    typeof data.current_count === 'number' ? `current_count=${data.current_count}` : '',
    typeof data.invalid_count === 'number' ? `invalid_count=${data.invalid_count}` : '',
  ].filter(Boolean);
  const counts = projectionCounts.length ? `; ${projectionCounts.join(', ')}` : '';
  const passed = typeof data.passed === 'boolean' ? `; passed=${data.passed}` : '';
  const findings = Array.isArray(data.findings)
    ? `; findings=${data.findings.slice(0, 5).map((item) => typeof item === 'string' ? item : item.code || item.name || JSON.stringify(item)).join(' | ')}`
    : '';
  const exit = result.exitCode === 0 ? '' : `; exit_code=${result.exitCode}`;
  return `${label}: ${result.exitCode === 0 ? state : `failed (state=${state})`}${scope}${exit}${scanned}${counts}${passed}${findings}`;
}

function compactForge(result) {
  const data = parseJson(result.stdout);
  if (result.timedOut) {
    return `ForgeLine repo-wide QA: timed out; scope=inventory-only${result.stderr || result.stdout ? `; detail=${clipped(result.stderr || result.stdout)}` : ''}`;
  }
  if (result.error) {
    const state = result.errorCode === 'ENOENT' ? 'unavailable; executable not found' : 'failed to start';
    return `ForgeLine repo-wide QA: ${state}; scope=inventory-only; detail=${clipped(result.stderr || result.stdout || result.error)}`;
  }
  if (result.exitCode !== 0 && !data) {
    return `ForgeLine repo-wide QA: failed (exit_code=${result.exitCode}); scope=inventory-only${result.stderr || result.stdout ? `; detail=${clipped(result.stderr || result.stdout)}` : ''}`;
  }
  if (data) {
    return `ForgeLine repo-wide QA: grade=${data.grade ?? 'unknown'}, passed=${Boolean(data.passed)}, scope=inventory-only`;
  }
  return `ForgeLine repo-wide QA: completed (exit 0), scope=inventory-only${result.stdout ? `; output=${clipped(result.stdout)}` : ''}`;
}

function projectRoot(cwd) {
  let current = path.resolve(cwd);
  while (true) {
    if (existsSync(path.join(current, '.git'))) return current;
    const parent = path.dirname(current);
    if (parent === current) return path.resolve(cwd);
    current = parent;
  }
}

function runGit(root, args) {
  const result = spawnSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 5_000,
    maxBuffer: 512 * 1024,
  });
  return result.status === 0 ? (result.stdout || '').split(/\r?\n/).filter(Boolean) : [];
}

function specBaseRef(root, gitRunner = runGit) {
  const symbolic = gitRunner(root, ['symbolic-ref', 'refs/remotes/origin/HEAD'])[0] || '';
  const candidates = [symbolic, 'origin/main', 'origin/master', 'main', 'master'];
  return candidates.find((ref) => /^[\w./-]+$/.test(ref) && gitRunner(root, ['rev-parse', '--verify', '--quiet', ref]).length > 0);
}

function changedMarkdownPaths(root, gitRunner = runGit) {
  const paths = new Set();
  const base = specBaseRef(root, gitRunner);
  if (base) {
    for (const item of gitRunner(root, ['diff', '--name-only', '--diff-filter=ACMRT', `${base}...HEAD`])) paths.add(item);
  }
  for (const item of gitRunner(root, ['diff', '--name-only', '--diff-filter=ACMRT', 'HEAD', '--'])) paths.add(item);
  for (const item of gitRunner(root, ['ls-files', '--others', '--exclude-standard'])) paths.add(item);
  return [...paths]
    .filter((item) => /\.(?:md|markdown)$/i.test(item) && !item.startsWith('..') && !path.isAbsolute(item))
    .sort()
    .slice(0, 80);
}

function readPrdAndSpecSources(root, gitRunner = runGit) {
  const sources = [];
  let totalBytes = 0;
  let rootRealPath;
  try {
    rootRealPath = realpathSync(root);
  } catch {
    return sources;
  }
  for (const relative of changedMarkdownPaths(root, gitRunner)) {
    if (sources.length >= MAX_SPEC_FILES || totalBytes >= MAX_SPEC_BYTES) break;
    const absolute = path.resolve(root, relative);
    let content;
    try {
      const actualPath = realpathSync(absolute);
      const relativeToRoot = path.relative(rootRealPath, actualPath);
      if (!relativeToRoot || relativeToRoot === '..' || relativeToRoot.startsWith(`..${path.sep}`) || path.isAbsolute(relativeToRoot)) continue;
      const info = statSync(absolute);
      if (!info.isFile() || info.size > MAX_SPEC_BYTES - totalBytes) continue;
      content = readFileSync(absolute, 'utf8');
      totalBytes += Buffer.byteLength(content, 'utf8');
    } catch {
      continue;
    }
    if (!SPEC_PATH.test(relative) && !SPEC_HEADING.test(content.slice(0, 8_192))) continue;
    sources.push({ path: relative.replaceAll('\\', '/'), content });
  }
  return sources;
}

function uniqueTerms(pattern, sources) {
  const matches = new Set();
  for (const source of sources) {
    for (const term of source.content.matchAll(pattern)) matches.add(term[0].toLowerCase());
  }
  return [...matches].sort().slice(0, 16);
}

function stateFile(event, root) {
  const key = `${event.session_id || 'unknown'}|${event.turn_id || 'unknown'}|${root}`;
  return path.join(STATE_DIR, `${createHash('sha256').update(key).digest('hex')}.jsonl`);
}

function removeStaleState() {
  try {
    const cutoff = Date.now() - STATE_TTL_MS;
    for (const name of readdirSync(STATE_DIR).slice(0, 500)) {
      const target = path.join(STATE_DIR, name);
      try {
        if (statSync(target).mtimeMs < cutoff) rmSync(target, { force: true });
      } catch {
        // A concurrently completed session may already have removed the file.
      }
    }
  } catch {
    // The directory is created when an audit summary is first written.
  }
}

export function buildAudit(event, dependencies = {}) {
  const input = event.tool_input ?? {};
  if (!isBuildCommand(collectText(input))) return;

  const runCli = dependencies.runRtk || runRtk;
  const gitRunner = dependencies.runGit || runGit;
  const emitOutput = dependencies.emit || emit;
  const root = projectRoot(event.cwd || process.cwd());
  const reports = [];
  const policyPath = path.join(root, '.factory', 'review-audits.json');
  if (existsSync(policyPath)) {
    reports.push(compactCli(
      runCli(['factory', 'audit', 'all', '--root', root, '--json'], root),
      'Code Factory patterns/guard-paths',
      '; configured project policy',
    ));
  } else {
    reports.push('Code Factory patterns/guard-paths: skipped; no .factory/review-audits.json policy exists, so no generic rules were invented.');
  }

  reports.push(compactCli(
    runCli(['factory', 'audit', 'security', '--root', root, '--json'], root),
    'Code Factory Python AST security scan',
    '; scope=Python AST only, not other languages, runtime behavior, or whole-program security analysis',
  ));
  reports.push(compactForge(runCli(['forge', 'qa', '--repo-wide', '--root', root], root)));

  const sources = readPrdAndSpecSources(root, gitRunner);
  const appforgeTerms = uniqueTerms(APPFORGE_TERMS, sources);
  const saasTerms = uniqueTerms(SAAS_TERMS, sources);
  const directSaasTerms = uniqueTerms(SAAS_DIRECT_TERMS, sources);
  reports.push(sources.length
    ? `Changed PRD/spec Markdown: ${sources.map((item) => item.path).join(', ')}`
    : 'Changed PRD/spec Markdown: none found against the repository base or current working tree; AppForge/SaaS scope was not inferred.');
  if (appforgeTerms.length) {
    reports.push(compactCli(
      runCli(['factory', 'revenue', 'appforge-status', '--root', root, '--json'], root),
      `AppForge (PRD/spec scope: ${appforgeTerms.join(', ')})`,
      '; local read-only design and evidence status',
    ));
  } else if (sources.length) {
    reports.push('AppForge: not routed; no native/mobile/App Store scope terms were found in the changed PRD/spec documents.');
  }
  if (directSaasTerms.length || saasTerms.length >= 2) {
    reports.push(compactCli(
      runCli(['factory', 'saas', 'status', '--root', root, '--json'], root),
      `SaaSForge scope via Code Factory saas_proof (PRD/spec scope: ${saasTerms.join(', ')})`,
      '; provider-neutral local read-only status; this Code Factory version does not contain a separate SaaSForge engine',
    ));
  } else if (sources.length) {
    reports.push('SaaSForge: not routed; no SaaS/identity/billing scope terms were found in the changed PRD/spec documents.');
  }

  const summary = [
    'Automatic Muse Code post-build review (read-only):',
    `Workspace: ${root}`,
    event.hook_event_name === 'PostToolUseFailure'
      ? 'The build tool reported failure; audits describe the current workspace and do not imply that build succeeded.'
      : null,
    ...reports,
    'Code Factory pattern/guard-path coverage requires this project\'s .factory/review-audits.json. Its security check analyzes Python ASTs only.',
    'ForgeLine --repo-wide is inventory-only, not feature SSAT QA or the feature release gate.',
    'PRD/spec discovery reads changed Markdown only and is bounded to 80 changed Markdown paths, 12 matching files, and 524288 combined bytes; larger changes may be truncated.',
    'Final build summary must use both labels: "Code Factory: <result>" and "ForgeLine: <result>". Include any routed AppForge/SaaS status and never present a skipped or failed check as a pass.',
  ].filter(Boolean).join('\n');

  let finalSummary = summary;
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    appendFileSync(stateFile(event, root), `${JSON.stringify({ summary, at: new Date().toISOString() })}\n`, 'utf8');
    removeStaleState();
  } catch (error) {
    finalSummary += `\nAudit summary enforcement state could not be saved: ${error.message}`;
  }
  emitOutput({
    hookSpecificOutput: {
      hookEventName: event.hook_event_name,
      additionalContext: finalSummary,
    },
  });
  return { root, summary: finalSummary };
}

function stopCheck(event) {
  const root = projectRoot(event.cwd || process.cwd());
  const file = stateFile(event, root);
  if (!existsSync(file)) return;
  const entries = readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).flatMap((line) => {
    try { return [JSON.parse(line)]; } catch { return []; }
  });
  if (!entries.length) return;

  const lastMessage = String(event.last_assistant_message || '');
  if (!/Code Factory\s*:\s*\S+/i.test(lastMessage) || !/ForgeLine\s*:\s*\S+/i.test(lastMessage)) {
    const summaries = entries.map((item) => item.summary).filter((item) => typeof item === 'string').join('\n\n');
    emit({
      decision: 'block',
      reason: `A build ran in this turn. Include both required result labels in the final build summary: "Code Factory: <result>" and "ForgeLine: <result>". Report pass, fail, skipped, or unavailable accurately.\n\n${summaries}`,
    });
    return;
  }
  rmSync(file, { force: true });
}

export function runHook(expectedEvent) {
  const event = readEvent();
  if (event.hook_event_name !== expectedEvent) return;
  if (expectedEvent === 'PostToolUse' || expectedEvent === 'PostToolUseFailure') buildAudit(event);
  else if (expectedEvent === 'Stop') stopCheck(event);
}
