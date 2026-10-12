import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const image = process.argv[2];
const outputRoot = resolve('osv-native-operator');
const timeoutMs = 120_000;
const outputLimit = 2_000_000;
const expectedSource = 'a14aa98ab8408547083d4411091c5fbaf5b47d8e';
const expectedDatabase = '36ef7d92e174230b8c7c26b952562be23837472c2239b6752de64d5d683a800e';
const sourcePaths = [
  'deploy/deep-adapters/Dockerfile',
  'deploy/deep-adapters/bin/osv-offline',
  'deploy/deep-adapters/osv-lookup-ledger.patch',
  'deploy/deep-adapters/profiles/osv.json',
  'scripts/verify_osv_native_ledger.mjs',
  'scripts/verify_osv_native_ledger.test.mjs',
  '.github/workflows/osv-native-operator.yml',
];
const argvTemplate = [
  '/opt/factory/bin/osv-offline', 'scan', 'source', '-r', '/src/input',
  '--config', '/opt/factory/rules/osv-scanner.toml', '--offline',
  '--offline-vulnerabilities', '--allow-no-lockfiles', '--all-packages',
  '--format', 'json', '--output', '/out/report.json',
];

const started = new Date().toISOString();
const receipt = {
  schema: 'factory.osv-native-operator-receipt.v1',
  state: 'INCOMPLETE',
  generated_utc: started,
  source_commit: process.env.GITHUB_SHA ?? null,
  workflow_run_id: process.env.GITHUB_RUN_ID ?? null,
  worker_image_id: image,
  docker_version: null,
  build_argv: ['docker', 'build', '--platform', 'linux/amd64', '--progress=plain', '--target', 'osv-worker', '-f', 'deploy/deep-adapters/Dockerfile', '-t', 'factory-osv-native-operator:candidate', '.'],
  image_id_argv: ['docker', 'image', 'inspect', 'factory-osv-native-operator:candidate', '--format', '{{.Id}}'],
  upstream_commit: expectedSource,
  expected_database_sha256: expectedDatabase,
  observed_database_sha256: null,
  source_sha256: {},
  environment: {
    network: 'none',
    container_user: '1000:1000 (image default)',
    scanner_environment: { HOME: '/tmp', OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: '/opt/factory/osv-db' },
  },
  cases: {},
  commands: [],
  failure: null,
};

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function run(command, args, { cwd = process.cwd(), timeout = timeoutMs, env = {} } = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd,
      env: { PATH: process.env.PATH, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let overflow = false;
    let timedOut = false;
    const append = (current, chunk) => {
      if (current.length + chunk.length > outputLimit) {
        overflow = true;
        child.kill('SIGKILL');
        return current;
      }
      return Buffer.concat([current, chunk]);
    };
    child.stdout.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeout);
    child.on('error', (error) => {
      clearTimeout(timer);
      rejectRun(error);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolveRun({ code, signal, timed_out: timedOut, output_limit_exceeded: overflow, stdout, stderr });
    });
  });
}

function saveProcess(caseDir, name, result, argv) {
  const stdoutPath = join(caseDir, `${name}.stdout.log`);
  const stderrPath = join(caseDir, `${name}.stderr.log`);
  writeFileSync(stdoutPath, result.stdout);
  writeFileSync(stderrPath, result.stderr);
  const command = { argv: ['docker', ...argv], exit_code: result.code, signal: result.signal,
    timed_out: result.timed_out, output_limit_exceeded: result.output_limit_exceeded,
    stdout_sha256: sha256(result.stdout), stderr_sha256: sha256(result.stderr),
    stdout_bytes: result.stdout.length, stderr_bytes: result.stderr.length };
  receipt.commands.push(command);
  return command;
}

function readReport(caseDir, processResult) {
  const reportPath = join(caseDir, 'report.json');
  let stat;
  try {
    stat = lstatSync(reportPath);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 10_000_000) {
    throw new Error('Native report is not a bounded regular file');
  }
  const bytes = readFileSync(reportPath);
  const report = JSON.parse(bytes.toString('utf8'));
  if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('Native report root is invalid');
  if (!report.factory_lookup_execution || report.factory_lookup_execution.schema !== 'factory.osv-lookup-execution.v1') {
    throw new Error('Native report lacks the embedded execution ledger');
  }
  return { report, bytes, path: reportPath };
}

function collectIds(value, into = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectIds(item, into);
  } else if (value && typeof value === 'object') {
    if (typeof value.id === 'string') into.push(value.id);
    for (const child of Object.values(value)) collectIds(child, into);
  }
  return into;
}

export function validateExtractorRuns(ledger) {
  if (!Array.isArray(ledger.extractor_runs) || ledger.extractor_runs.length === 0) {
    throw new Error('Native extractor execution inventory is missing');
  }
  for (const run of ledger.extractor_runs) validateExtractorRun(run);
}

function validateExtractorRun(run) {
  if (!Array.isArray(run.plugins) || run.plugins.length === 0
      || !Array.isArray(run.statuses) || run.statuses.length !== run.plugins.length) {
    throw new Error('Native extractor run is incomplete');
  }
  if (!isSortedUnique(run.plugins) || !isSortedUnique(run.statuses.map((row) => row.name))) {
    throw new Error('A native OSV extractor did not succeed');
  }
  const states = new Map(run.statuses.map((row) => [row.name, row.state]));
  if (run.plugins.some((name) => states.get(name) !== 'SUCCEEDED')) {
    throw new Error('A native OSV extractor did not succeed');
  }
}

function isSortedUnique(values) {
  return values.every((value, index) => typeof value === 'string'
    && (index === 0 || values[index - 1] < value));
}

export function reportIdentity(report) {
  const ledger = report.factory_lookup_execution;
  const matched = new Set(ledger.queries.flatMap((query) => query.matched_advisories));
  const reported = [...new Set(collectIds(report).filter((id) => matched.has(id)))].sort();
  const queries = ledger.queries.map((query) => ({
    name: query.name, version: query.version, ecosystem: query.ecosystem,
    matched_advisories: [...query.matched_advisories].sort(),
  })).sort((left, right) => `${left.ecosystem}/${left.name}/${left.version}`
    .localeCompare(`${right.ecosystem}/${right.name}/${right.version}`));
  return JSON.stringify({ queries, reported_advisories: reported });
}

export function validateCompleteLedger(report, packageName, packageVersion, { vulnerable }) {
  const ledger = report.factory_lookup_execution;
  validateLedgerBinding(ledger);
  validateExtractorRuns(ledger);
  const query = onlyPackageQuery(ledger);
  validatePackageQuery(ledger, query, packageName, packageVersion);
  validateDecisionDigest(ledger, query);
  validateVulnerabilityState(report, query, packageName, vulnerable);
  return ledger;
}

function validateLedgerBinding(ledger) {
  if (ledger.upstream_commit !== expectedSource || ledger.database_sha256 !== expectedDatabase
      || !Number.isSafeInteger(ledger.catalog_advisories) || ledger.catalog_advisories < 1
      || !/^[a-f0-9]{64}$/.test(ledger.catalog_sha256 ?? '')) {
    throw new Error('Ledger is not bound to the pinned OSV source and database');
  }
}

function onlyPackageQuery(ledger) {
  if (!Array.isArray(ledger.queries) || ledger.queries.length !== 1) {
    throw new Error('Expected exactly one native package query');
  }
  return ledger.queries[0];
}

function validatePackageQuery(ledger, query, packageName, packageVersion) {
  if (query.name !== packageName || query.version !== packageVersion
      || query.ecosystem !== 'PyPI' || query.state !== 'EXECUTED'
      || !Number.isSafeInteger(query.evaluated_advisories)
      || query.evaluated_advisories !== ledger.catalog_advisories
      || query.evaluated_sha256 !== ledger.catalog_sha256
      || !Array.isArray(query.matched_advisories)
      || query.matched_advisories.some((id) => typeof id !== 'string')) {
    throw new Error('Native query is missing, incomplete, or bound to another package');
  }
  const matched = query.matched_advisories;
  if (new Set(matched).size !== matched.length || JSON.stringify(matched) !== JSON.stringify([...matched].sort())) {
    throw new Error('Native matched advisory IDs are not unique and sorted');
  }
}

function validateDecisionDigest(ledger, query) {
  const matched = query.matched_advisories;
  const decision = {
    catalog_sha256: ledger.catalog_sha256,
    ecosystem: query.ecosystem,
    evaluated_advisories: query.evaluated_advisories,
    matched_advisories: matched,
    name: query.name,
    version: query.version,
  };
  if (sha256(Buffer.from(JSON.stringify(decision), 'utf8')) !== query.decision_sha256) {
    throw new Error('Native decision digest does not match its canonical inputs');
  }
}

function validateVulnerabilityState(report, query, packageName, vulnerable) {
  if (vulnerable !== (query.matched_advisories.length > 0)) {
    throw new Error(`Unexpected native match state for ${packageName}`);
  }
  if (vulnerable) {
    const reportIds = new Set(collectIds(report));
    if (!query.matched_advisories.some((id) => reportIds.has(id))) {
      throw new Error('Native matched advisory is absent from the retained OSV report');
    }
  }
}

async function dockerRun(name, sourceDir, caseDir, extraArgs = []) {
  if (existsSync(caseDir)) throw new Error(`Refusing stale operator output: ${name}`);
  mkdirSync(caseDir, { recursive: true });
  chmodSync(caseDir, 0o777);
  const runId = (process.env.GITHUB_RUN_ID ?? 'manual').replace(/[^a-zA-Z0-9_.-]/g, '_');
  const containerName = `osv-op-${runId}-${name}`;
  const args = [
    'run', '--rm', '--name', containerName, '--network', 'none', '--mount', `type=bind,source=${sourceDir},target=/src/input,readonly`,
    '--mount', `type=bind,source=${caseDir},target=/out`, '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=1777',
    '--env', 'HOME=/tmp', ...extraArgs, '--entrypoint', '/bin/sh', image,
    '-c', 'set +e; /opt/factory/bin/osv-offline "$@"; status=$?; chmod 0644 /out/report.json 2>/dev/null || :; exit "$status"',
    'osv-operator', ...argvTemplate.slice(1),
  ];
  const result = await run('docker', args, { timeout: 180_000 });
  const command = saveProcess(caseDir, name, result, args);
  if (result.timed_out || result.output_limit_exceeded) {
    const cleanup = await run('docker', ['rm', '-f', containerName], { timeout: 15_000 });
    if (cleanup.code !== 0) throw new Error(`${name} exceeded budget and container cleanup failed`);
    throw new Error(`${name} exceeded its process budget`);
  }
  return { result, command, parsed: readReport(caseDir, result) };
}

export function writeRequirement(root, text) {
  const source = mkdtempSync(join(root, 'source-'));
  writeFileSync(join(source, 'requirements.txt'), text, { mode: 0o444 });
  return source;
}

async function runCase(root, key, requirement, { packageName, vulnerable, extraArgs = [] }) {
  const source = writeRequirement(root, requirement);
  const fixtureSha256 = sha256(readFileSync(join(source, 'requirements.txt')));
  const caseDir = join(outputRoot, key);
  const executed = await dockerRun(key, source, caseDir, extraArgs);
  if (executed.result.code !== 0 && executed.result.code !== 1) {
    throw new Error(`${key} did not exit with an accepted native scan status`);
  }
  const reportInfo = executed.parsed;
  const item = { state: 'FAIL', argv: argvTemplate, exit_code: executed.result.code,
    fixture_sha256: fixtureSha256,
    stdout_sha256: executed.command.stdout_sha256, stderr_sha256: executed.command.stderr_sha256,
    report_sha256: reportInfo ? sha256(reportInfo.bytes) : null };
  if (!reportInfo) throw new Error(`${key} did not produce a complete native report`);
  item.native_ledger = validateCompleteLedger(reportInfo.report, packageName,
    requirement.trim().split('==')[1], { vulnerable });
  markCasePassed(item, reportInfo.report);
  item.report_path = `${key}/report.json`;
  receipt.cases[key] = item;
  return item;
}

export function validateExpectedFailure(key, code, report, diagnostic) {
  const failedLedger = report?.factory_lookup_execution;
  const failedStatuses = hasFailedExtractorStatus(failedLedger);
  const pattern = expectedFailurePattern(key);
  validateFailureEvidence(key, code, report, diagnostic, failedStatuses, pattern);
  return failedLedger?.extractor_runs ?? null;
}

function hasFailedExtractorStatus(ledger) {
  return (ledger?.extractor_runs ?? []).some((run) =>
    (run.statuses ?? []).some((status) => status.state !== 'SUCCEEDED'));
}

function expectedFailurePattern(key) {
  const patterns = {
    missing_database: /(?:open|stat) .*\/all\.zip: no such file or directory|cannot find .*all\.zip/i,
    malformed_database: /zip: not a valid zip file|not valid OSV JSON|OSV database contains no advisories/i,
    extractor_failure: /extractor [a-z0-9._-]+ failed:/i,
  };
  if (!Object.hasOwn(patterns, key)) throw new Error(`${key} lacks cause-specific native failure evidence`);
  return patterns[key];
}

function validateFailureEvidence(key, code, report, diagnostic, failedStatuses, pattern) {
  const databaseFailure = key !== 'extractor_failure';
  if (code === 0 || (databaseFailure && (code === 1 || report !== null))
      || (!databaseFailure && code === 1 && !failedStatuses)
      || (!databaseFailure && report !== null && !failedStatuses)
      || !pattern.test(diagnostic)) {
    throw new Error(`${key} lacks cause-specific native failure evidence`);
  }
  if (report && !failedStatuses) throw new Error(`${key} report contains no failed native extractor`);
  if (!report && (code === 1 || diagnostic.length === 0)) {
    throw new Error(`${key} did not return a distinct native failure status`);
  }
}

export function markCasePassed(item, report) {
  item.state = 'PASS';
  item.report_identity = reportIdentity(report);
  return item;
}

async function expectedFailure(root, key, requirement, extraArgs) {
  const source = writeRequirement(root, requirement);
  const fixtureSha256 = sha256(readFileSync(join(source, 'requirements.txt')));
  const caseDir = join(outputRoot, key);
  const executed = await dockerRun(key, source, caseDir, extraArgs);
  const item = { state: 'FAIL', argv: argvTemplate, exit_code: executed.result.code,
    fixture_sha256: fixtureSha256,
    stdout_sha256: executed.command.stdout_sha256, stderr_sha256: executed.command.stderr_sha256,
    report_sha256: executed.parsed ? sha256(executed.parsed.bytes) : null };
  const diagnostic = Buffer.concat([executed.result.stdout, executed.result.stderr]).toString('utf8');
  item.failure_evidence = validateExpectedFailure(key, executed.result.code, executed.parsed?.report ?? null, diagnostic);
  item.native_error_excerpt = diagnostic.slice(0, 1200);
  item.state = 'PASS';
  receipt.cases[key] = item;
  return item;
}

function writeReceipt() {
  const path = join(outputRoot, 'osv-native-operator-receipt.json');
  writeFileSync(path, `${JSON.stringify(receipt, null, 2)}\n`);
}

async function main() {
  let temporary;
  try {
    if (!/^sha256:[a-f0-9]{64}$/.test(image ?? '')) {
      throw new Error('Pass the immutable Docker image ID (sha256:...)');
    }
    mkdirSync(outputRoot, { recursive: true });
    for (const path of sourcePaths) receipt.source_sha256[path] = sha256(readFileSync(path));
    if (!/^[a-f0-9]{40}$/.test(receipt.source_commit ?? '')) throw new Error('Missing exact workflow source commit');
    const caseRoot = mkdtempSync(join(tmpdir(), 'osv-native-controls-'));
    temporary = caseRoot;
    chmodSync(caseRoot, 0o755);
    const dockerVersion = await run('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 15_000 });
    receipt.commands.push({ argv: ['docker', 'version', '--format', '{{.Server.Version}}'], exit_code: dockerVersion.code,
      stdout_sha256: sha256(dockerVersion.stdout), stderr_sha256: sha256(dockerVersion.stderr) });
    if (dockerVersion.code !== 0 || dockerVersion.timed_out || dockerVersion.output_limit_exceeded) {
      throw new Error('Docker server version could not be verified');
    }
    receipt.docker_version = dockerVersion.stdout.toString('utf8').trim();
    const inspect = await run('docker', ['image', 'inspect', image, '--format', '{{json .}}'], { timeout: 15_000 });
    receipt.commands.push({ argv: ['docker', 'image', 'inspect', image, '--format', '{{json .}}'], exit_code: inspect.code,
      stdout_sha256: sha256(inspect.stdout), stderr_sha256: sha256(inspect.stderr) });
    if (inspect.code !== 0) throw new Error('Immutable worker image is unavailable');
    const details = JSON.parse(inspect.stdout.toString('utf8'));
    if (details.Id !== image || details.Config?.Labels?.['io.code-factory.osv-source'] !== expectedSource
        || details.Config?.Labels?.['io.code-factory.osv-ledger'] !== 'factory.osv-lookup-execution.v1') {
      throw new Error('Worker image identity labels do not match the reviewed source');
    }
    const version = await run('docker', ['run', '--rm', '--network', 'none', '--entrypoint', '/usr/local/bin/osv-scanner', image, '--version'], { timeout: 30_000 });
    receipt.commands.push({ argv: ['docker', 'run', '--rm', '--network', 'none', '--entrypoint', '/usr/local/bin/osv-scanner', image, '--version'],
      exit_code: version.code, stdout_sha256: sha256(version.stdout), stderr_sha256: sha256(version.stderr) });
    if (version.code !== 0 || !version.stdout.toString('utf8').includes('2.2.0')) throw new Error('Native scanner version mismatch');
    receipt.native_version_output = version.stdout.toString('utf8').trim();

    const dbDir = join(caseRoot, 'pinned-db');
    mkdirSync(dbDir, { recursive: true });
    const extract = await run('docker', ['create', image], { timeout: 15_000 });
    receipt.commands.push({ argv: ['docker', 'create', image], exit_code: extract.code,
      stdout_sha256: sha256(extract.stdout), stderr_sha256: sha256(extract.stderr) });
    if (extract.code !== 0) throw new Error('Could not create a DB extraction container');
    const containerId = extract.stdout.toString('utf8').trim();
    try {
      const cp = await run('docker', ['cp', `${containerId}:/opt/factory/osv-db/osv-scanner/PyPI/all.zip`, join(dbDir, 'all.zip')], { timeout: 60_000 });
      receipt.commands.push({ argv: ['docker', 'cp', `${containerId}:/opt/factory/osv-db/osv-scanner/PyPI/all.zip`, join(dbDir, 'all.zip')],
        exit_code: cp.code, stdout_sha256: sha256(cp.stdout), stderr_sha256: sha256(cp.stderr) });
      if (cp.code !== 0) throw new Error('Could not retain the pinned database for hash verification');
    } finally {
      const removed = await run('docker', ['rm', '-f', containerId], { timeout: 15_000 });
      receipt.commands.push({ argv: ['docker', 'rm', '-f', containerId], exit_code: removed.code,
        stdout_sha256: sha256(removed.stdout), stderr_sha256: sha256(removed.stderr) });
    }
    receipt.observed_database_sha256 = sha256(readFileSync(join(dbDir, 'all.zip')));
    if (receipt.observed_database_sha256 !== expectedDatabase) throw new Error('Pinned database bytes failed their hash check');

    const positive = await runCase(caseRoot, 'positive', 'requests==2.19.1\n', {
      packageName: 'requests', vulnerable: true,
    });
    const replay = await runCase(caseRoot, 'fresh_native_replay', 'requests==2.19.1\n', {
      packageName: 'requests', vulnerable: true,
    });
    if (JSON.stringify(positive.native_ledger) !== JSON.stringify(replay.native_ledger)
        || positive.report_identity !== replay.report_identity) throw new Error('Fresh native replay differs from primary evidence');
    receipt.cases.fresh_native_replay.raw_report_sha256_matches_primary =
      positive.report_sha256 === replay.report_sha256;
    receipt.cases.fresh_native_replay.primary_report_sha256 = positive.report_sha256;
    const zero = await runCase(caseRoot, 'zero_match', 'factory-native-clean-package-7fbb19==0.0.0\n', {
      packageName: 'factory-native-clean-package-7fbb19', vulnerable: false,
    });
    const malformed = join(caseRoot, 'malformed-db');
    mkdirSync(malformed, { recursive: true });
    writeFileSync(join(malformed, 'all.zip'), 'not a zip database\n', { mode: 0o444 });
    const dbArgs = (path) => ['--mount', `type=bind,source=${path},target=/opt/factory/osv-db/osv-scanner/PyPI,readonly`];
    const emptyDbArgs = ['--tmpfs', '/opt/factory/osv-db/osv-scanner/PyPI:rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0755'];
    await expectedFailure(caseRoot, 'missing_database', 'requests==2.19.1\n', emptyDbArgs);
    await expectedFailure(caseRoot, 'malformed_database', 'requests==2.19.1\n', dbArgs(malformed));
    await expectedFailure(caseRoot, 'extractor_failure', 'this is not a valid requirement !!!\n', []);
    if (Object.keys(receipt.cases).length !== 6 || Object.values(receipt.cases).some((item) => item.state !== 'PASS')) {
      throw new Error('One or more native operator controls remain incomplete');
    }
    receipt.state = 'PASS_SCOPED_NATIVE_OPERATOR';
  } catch (error) {
    receipt.failure = String(error?.stack ?? error).slice(0, 4000);
    throw error;
  } finally {
    receipt.finished_utc = new Date().toISOString();
    if (temporary) {
      try {
        rmSync(temporary, { recursive: true, force: true });
      } catch (error) {
        receipt.state = 'INCOMPLETE';
        receipt.failure = `Temporary input cleanup failed: ${String(error).slice(0, 1000)}`;
      }
    }
    writeReceipt();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(`OSV native operator controls incomplete: ${error.message}`);
    process.exitCode = 1;
  });
}
