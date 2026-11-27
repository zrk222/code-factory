import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { arch, platform, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { docker } from './verify_worker_cves.mjs';

function hasExactSourceAccounting(accounting, expected) {
  return expected.length > 0 && accounting?.state === 'COMPLETE'
    && Object.keys(accounting.checks ?? {}).length === expected.length
    && expected.every(file => accounting.checks[file.path]?.state === 'EXTRACTED'
      && accounting.checks[file.path]?.sha256 === file.sha256);
}

function hasBoundNativeSources(execution, expected) {
  return expected.every(({ path, sha256 }) => {
    const row = execution?.rows?.[path];
    const nodes = row?.syntax_nodes;
    return Number.isInteger(nodes) && nodes > 0 && nodes <= 0x7fffffff
      && row.parse_errors === 0 && execution.archived_sources?.[path] === sha256;
  });
}

function isSuccessfulCodeQLReport(sarif) {
  return sarif?.version === '2.1.0'
    && Array.isArray(sarif.runs) && sarif.runs.length > 0
    && sarif.runs.every(run => run?.tool?.driver?.name === 'CodeQL'
      && Array.isArray(run.invocations) && run.invocations.length > 0
      && run.invocations.every(invocation => invocation?.executionSuccessful === true));
}

export function verifyStructuralBundle(bundle, candidate, expected, pins) {
  const coverage = bundle.artifacts?.['coverage.json'];
  const sarif = bundle.artifacts?.['native.json'];
  // This unsigned fixture has no signed obligations or independent challenges.
  const fixtureOnly = ['NATIVE_SOURCE_ACCOUNTING_REQUIRED', 'NATIVE_CHALLENGES_REQUIRED'];
  if (bundle.candidate_sha256 !== candidate || !isSuccessfulCodeQLReport(sarif)
      || !Array.isArray(coverage?.errors) || coverage.errors.some(error => !fixtureOnly.includes(error))
      || !hasExactSourceAccounting(coverage.source_accounting, expected)
      || !hasBoundNativeSources(coverage.codeql_source_execution, expected)
      || !Object.entries(pins).every(([key, value]) => coverage[key] === value)) {
    throw new Error('Expected exact native file coverage and a source-bound report');
  }
  return { sarif, coverage, challenges: bundle.artifacts['challenges.json'] };
}

const stableJson = value => JSON.stringify(value, (_, item) =>
  item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);

function compareRecords(a, b) {
  const left = stableJson(a), right = stableJson(b);
  return left < right ? -1 : left > right ? 1 : 0;
}

function hasArtifactIndex(value, field) {
  return value !== null && typeof value === 'object' && (
    Object.hasOwn(value, 'parentIndex')
    // These indexes refer to tool descriptors, not the artifact array.
    || (Object.hasOwn(value, 'index') && field !== 'descriptor' && field !== 'rule')
    || Object.entries(value).some(([key, child]) => hasArtifactIndex(child, key))
  );
}

function normalizeArtifactOrder({ artifacts, ...run }) {
  // Only URI declarations whose indexes describe their own positions can move.
  if (!Array.isArray(artifacts) || !artifacts.every((row, index) =>
    row?.location?.index === index && typeof row.location.uri === 'string'
    && Object.keys(row).length === 1
    && Object.keys(row.location).every(key => ['index', 'uri', 'uriBaseId'].includes(key)))) return;
  if (hasArtifactIndex(run)) return;

  artifacts.sort((a, b) => compareRecords(
    [a.location.uriBaseId ?? null, a.location.uri],
    [b.location.uriBaseId ?? null, b.location.uri]));
  artifacts.forEach((row, index) => { row.location.index = index; });
}

export function assertStructuralParity(first, repeat) {
  const semantics = ({ sarif, coverage, challenges }) => {
    const report = structuredClone(sarif);
    // The raw digest includes CodeQL telemetry timestamps. Keep it in the stored bundle.
    delete report.properties?.factory_native_raw_sha256;
    for (const run of report.runs) {
      normalizeArtifactOrder(run);
      for (const invocation of run.invocations ?? []) {
        for (const notification of invocation.toolExecutionNotifications ?? []) {
          delete notification.timeUtc;
          if (['cli/file-coverage-baseline', 'cli/platform'].includes(notification.descriptor?.id)) {
            delete notification.properties?.attributes?.durationMilliseconds;
          }
        }
        const notifications = invocation.toolExecutionNotifications ?? [];
        // File-level diagnostics can arrive in any order within the same group.
        for (const id of ['go/diagnostics/successfully-extracted-files', 'go/baseline/expected-extracted-files']) {
          const fileRows = notifications.filter(row => row.descriptor?.id === id).sort(compareRecords).values();
          for (const [index, row] of notifications.entries()) {
            if (row.descriptor?.id === id) notifications[index] = fileRows.next().value;
          }
        }
      }
      // CodeQL exports these counters as an unordered list.
      run.properties?.metricResults?.sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
    }
    // Wrapper executions and archive/stream hashes are retained in the raw bundle.
    // These fields describe the analysis result and the exact inputs it covered.
    const {
      schema, complete, errors, fallback, mode, obligations, codeql_query_execution,
      profile_sha256, ruleset_sha256, source_accounting, sources, tool_version,
    } = coverage;
    return {
      report, challenges, schema, complete, errors, fallback, mode, obligations,
      queries: codeql_query_execution?.rules?.map(({ rule_id, query_path, query_sha256, result_sets }) =>
        ({ rule_id, query_path, query_sha256, result_sets })),
      query_inventory: codeql_query_execution?.query_inventory_sha256,
      suite: codeql_query_execution?.suite_sha256,
      profile_sha256, ruleset_sha256, source_accounting, sources, tool_version,
      source_rows: coverage.codeql_source_execution?.rows,
      archived_sources: coverage.codeql_source_execution?.archived_sources,
    };
  };
  const previous = semantics(first);
  const current = semantics(repeat);
  const differing = Object.keys(previous).find(key => !isDeepStrictEqual(previous[key], current[key]));
  if (differing) throw new Error(`Native report or source coverage changed on repeat (${differing})`);
}

function main([image, output, target]) {
  const language = {
    'codeql-java-worker': 'java',
    'codeql-csharp-worker': 'csharp',
    'codeql-go-worker': 'go',
  }[target];
  if (!image || !output || !language) throw new Error('Specify image, output, and a compiled CodeQL target');
  const fixtures = {
    java: { 'Example.java': 'public class Example { int sum(int x, int y) { return x + y; } }\n' },
    csharp: { 'Example.cs': 'public class Example { public int Sum(int x, int y) => x + y; }\n' },
    go: {
      'nested/go.mod': 'module example.test/native\n\ngo 1.24.0\n',
      'nested/compute.go': 'package native\n\nfunc Add(x, y int) int { return x + y }\n',
      'nested/compute_test.go': 'package native\n\nimport "testing"\n\nfunc TestCompileOnly(*testing.T) { panic("not an execution test") }\n',
    },
  }[language];
  const hash = value => createHash('sha256').update(value).digest('hex');
  const profilePath = `deploy/deep-adapters/profiles/codeql-${language}-full.json`;
  const profileRaw = readFileSync(profilePath);
  const profile = JSON.parse(profileRaw);
  const workspace = mkdtempSync(join(tmpdir(), 'cf-codeql-structural-'));
  const receipt = {
    schema: 'factory.codeql-structural-controls.v1',
    state: 'BLOCKED',
    scope: 'Benign offline source accounting fixture. No recall, signed family qualification, or release claim.',
    target, image, observed_at: new Date().toISOString(),
    candidate_commit: process.env.GITHUB_SHA ?? null,
    host: { platform: platform(), architecture: arch() },
    profile_sha256: hash(profileRaw),
    recipe_sha256: hash(readFileSync('deploy/deep-adapters/Dockerfile')),
  };
  try {
    mkdirSync(dirname(resolve(output)), { recursive: true });
    const id = docker(['image', 'inspect', image, '--format', '{{.Id}}']).stdout.trim();
    if (!/^sha256:[a-f0-9]{64}$/.test(id)) throw new Error('Immutable image ID required');
    receipt.image_id = id;
    receipt.host.docker = JSON.parse(docker(['version', '--format', '{{json .Server}}']).stdout);
    const isolation = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--user=1000:1000',
      '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=128', '--memory=3g', '--cpus=2',
      '--tmpfs', '/tmp:rw,nosuid,nodev,size=1024m,mode=1777', '--tmpfs', '/out:rw,nosuid,nodev,noexec,size=64m,mode=1777'];
    const installed = docker([...isolation, '--entrypoint', '/bin/cat', id, '/opt/factory/adapter-profile.json']).stdout;
    if (hash(installed) !== receipt.profile_sha256) throw new Error('Image profile differs from candidate');
    const source = join(workspace, 'source');
    const files = Object.entries(fixtures).map(([path, content]) => {
      mkdirSync(dirname(join(source, path)), { recursive: true });
      writeFileSync(join(source, path), content);
      return { path, sha256: hash(content), language: path.endsWith('go.mod') ? 'dependency' : language };
    });
    const candidate = hash(JSON.stringify(files));
    const lane = { id: 'codeql-structural-control', family: 'static', languages: [language],
      timeout_seconds: 900, memory_mib: 3072, report: 'native.json',
      coverage: 'coverage.json', challenge_report: 'challenges.json' };
    for (const key of ['engine', 'mode', 'tool_version', 'ruleset_sha256']) lane[key] = profile[key];
    const contract = { schema: 'factory.deep-adapter-input.v1', run_id: 'codeql-structural-control',
      manifest_sha256: hash(JSON.stringify({ profile: receipt.profile_sha256, candidate })),
      inventory: { candidate_sha256: candidate, files }, lane, obligations: [] };
    const contractPath = join(workspace, 'contract.json');
    writeFileSync(contractPath, JSON.stringify(contract));
    const argv = [...isolation,
      '--mount', `type=bind,source=${source},target=/src,readonly`,
      '--mount', `type=bind,source=${contractPath},target=/factory-contract.json,readonly`,
      id, profile.engine, '--mode', profile.mode];
    const expected = files.filter(file => file.language === language);
    // The adapter binds canonical profile JSON. The image check above binds the raw file bytes.
    const pins = { profile_sha256: hash(stableJson(profile)), ruleset_sha256: profile.ruleset_sha256,
      mode: profile.mode, tool_version: profile.tool_version };
    receipt.source_bindings = files;
    receipt.candidate_sha256 = candidate;
    receipt.repeat = { scope: 'Two fresh containers and tmpfs mounts on one host with the same local image.', runs: {} };
    const runs = ['', '.repeat'].map(suffix => {
      const started = performance.now();
      const { stdout, stderr, status } = docker(argv, [0, 1, 2], 960000);
      const elapsed_ms = Math.round(performance.now() - started);
      writeFileSync(`${output}${suffix}.bundle.json`, stdout);
      writeFileSync(`${output}${suffix}.stderr.txt`, stderr);
      const execution = { status, elapsed_ms, stdout_sha256: hash(stdout), stderr_sha256: hash(stderr) };
      receipt.repeat.runs[suffix ? 'second' : 'first'] = execution;
      if (status !== 0) {
        const code = stderr.match(/^E_[A-Z0-9_]+\r?$/m)?.[0].trim() ?? ('exit ' + status);
        throw new Error('Native control failed (' + code + ')');
      }
      return verifyStructuralBundle(JSON.parse(stdout), candidate, expected, pins);
    });
    assertStructuralParity(...runs);
    receipt.state = 'PASS';
  } catch (error) {
    receipt.error = error.message;
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    mkdirSync(dirname(resolve(output)), { recursive: true });
    writeFileSync(output, `${JSON.stringify(receipt, null, 2)}\n`);
  }
  console.log(JSON.stringify({ state: receipt.state, image_id: receipt.image_id, error: receipt.error }));
  process.exitCode = receipt.state === 'PASS' ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2));
}
