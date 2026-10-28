import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, symlink, mkdir, chmod, stat, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createEvidenceValidators } from './jev_evidence.mjs';
import {
  ENDPOINT, MODEL, evaluateCases as evaluateCasesRaw, loadTrial, parseArgs, runCli as runCliRaw,
  summarizeCosts, summarizeLatency, verifyJournal, recordOperatorFeedback,
} from './evaluate_jev.mjs';

const rubric = { instructions: 'Does the supplied state show a real finding?' };
const cases = [
  { id: 'positive', state: { snippet: 'unsafe operation' }, expected: true },
  { id: 'negative', state: 'guarded operation', expected: false },
];
function answer(probability, extra = {}, evidenceProbability = 0.99) {
  return new Response(JSON.stringify({
    model: MODEL,
    answers: { finding: { type: 'boolean', probability },
      evidence_sufficient: { type: 'boolean', probability: evidenceProbability } },
    providerMetadata: { gateway: { cost: '0.00001', routing: { finalProvider: 'typesafe-ai' } } },
    ...extra,
  }), { status: 200 });
}
const mock = (responses) => async () => responses.shift();

test('evidence validator services stay captured when the caller mutates its dependency object', () => {
  const dependencies = {
    requireValue(value, reason) { assert.ok(value, reason); },
    object: value => value !== null && typeof value === 'object' && !Array.isArray(value),
    sha: value => createHash('sha256').update(value).digest('hex'),
    TrialError: Error,
    readBounded: readFile,
  };
  const first = createEvidenceValidators(dependencies);
  assert.throws(() => first.validateNoRawSecrets({ password: 'example' }), /raw_secret_field_forbidden/);
  dependencies.requireValue = () => {};
  dependencies.object = () => false;
  assert.throws(() => first.validateNoRawSecrets({ password: 'example' }), /raw_secret_field_forbidden/);
  const second = createEvidenceValidators(dependencies);
  first.EVIDENCE_PROFILES.add('local-only');
  assert.equal(second.EVIDENCE_PROFILES.has('local-only'), false);
});

async function informedFixture(root) {
  const hash = value => createHash('sha256').update(value).digest('hex');
  const content = '# unrelated header\r\ndef load(payload):\r\n    return pickle.loads(payload)\r\n';
  const helper = 'def caller(body):\n    return load(body)\n';
  await writeFile(join(root, 'endpoint.py'), content);
  await writeFile(join(root, 'helper.py'), helper);
  const candidate = { commit: 'a'.repeat(40), path: 'endpoint.py', sha256: hash(content) };
  const excerpt = content.slice(content.indexOf('def load'));
  const artifact = { kind: 'source_excerpt', path: candidate.path, content: excerpt, sha256: hash(excerpt),
    candidate_commit: candidate.commit, candidate_sha256: candidate.sha256,
    source_binding: { path: candidate.path, sha256: candidate.sha256, start_line: 2, end_line: 3 } };
  const ref = { path: artifact.path, sha256: artifact.sha256, start_line: 2, end_line: 3 };
  const actionability = Object.fromEntries(Object.entries({ input_origin: 'known', sink_behavior: 'known',
    callers: 'resolved', trust_boundary: 'known', counterevidence: 'reviewed' })
    .map(([key, status]) => [key, { status, artifacts: [ref] }]));
  return { id: 'informed', state: { requirement: 'Is the source-supported deserialization an actionable defect?', candidate,
    evidence: { location: { path: candidate.path, start_line: 3, end_line: 3 }, artifacts: [artifact], actionability,
      dependencies: [{ path: 'helper.py', sha256: hash(helper) }] } } };
}

test('retrieval transport rejects missing receipts and dropped or altered source hints', async () => {
  const root = await mkdtemp(join(tmpdir(), 'jev-retrieval-'));
  try {
    const item = await informedFixture(root);
    const hash = value => createHash('sha256').update(value).digest('hex');
    const source = item.state.evidence.artifacts[0];
    item.state.evidence.dependencies.push({ path: source.path, sha256: source.source_binding.sha256 });
    const record = { schema: 'factory.retrieval-transport.v1', status: 'DELIVERED_UNVALIDATED', authority: 'none',
      classification_effect: 'NONE', consumption: 'UNASSESSED', validated_trace_edges: 0,
      coverage: 'RANKED_SUBSET_NOT_EXHAUSTIVE', finding_sha256: 'b'.repeat(64), source_manifest_sha256: 'c'.repeat(64),
      query_sha256: hash(item.state.requirement), delivered_hints: 1,
      hint_manifest: [{ ...source.source_binding, content_sha256: source.sha256 }] };
    const ledger = { schema: 'factory.informed-sink-context.v1', status: 'CAPTURED', truncation: [], retrieval: record };
    const native = { kind: 'native_sink_evidence', path: 'evidence/native-sink.json', content: JSON.stringify(ledger),
      candidate_commit: item.state.candidate.commit, candidate_sha256: item.state.candidate.sha256 };
    native.sha256 = hash(native.content);
    item.state.evidence.artifacts.push(native);
    const validators = createEvidenceValidators({ requireValue(value, reason) { assert.ok(value, reason); },
      object: value => value !== null && typeof value === 'object' && !Array.isArray(value), sha: hash, TrialError: Error, readBounded: readFile });
    validators.validateActionabilityState(item.state);
    for (const mutation of ['missing', 'query', 'dropped', 'count', 'authority', 'late-truncation', 'missing-status']) {
      const copy = structuredClone(item.state);
      const value = JSON.parse(copy.evidence.artifacts.at(-1).content);
      if (mutation === 'missing') delete value.retrieval;
      if (mutation === 'query') value.retrieval.query_sha256 = 'd'.repeat(64);
      if (mutation === 'dropped') copy.evidence.artifacts.shift();
      if (mutation === 'count') value.retrieval.delivered_hints = 0;
      if (mutation === 'authority') value.retrieval.authority = 'safe';
      if (mutation === 'late-truncation') value.truncation.push('max_sources');
      if (mutation === 'missing-status') delete value.status;
      copy.evidence.artifacts.at(-1).content = JSON.stringify(value);
      assert.throws(() => validators.validateActionabilityState(copy), /retrieval/);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});
function fixtureBudget(corpus, question = rubric) {
  const rows = corpus.map((item) => ({ id: item.id,
    case_sha256: createHash('sha256').update(JSON.stringify(item)).digest('hex'), risk: 'high',
    upper_bound_cost_usd: 0.001, upper_bound_latency_ms: 10_000 }));
  return { schema: 'factory.jev-dispatch-budget.v1', version: 1, approval_reference: 'declared-test-fixture',
    rubric_sha256: createHash('sha256').update(JSON.stringify(question)).digest('hex'),
    seed: 'fixed-test-seed', max_cases: 100, max_cost_usd: 1, max_latency_ms: 120_000,
    fractions: { low: 1, medium: 1, high: 1 }, cases: rows };
}
async function evaluateCases(corpus, question, options = {}) {
  const supplied = options.live && options.budgetPolicy === undefined
    ? { ...options, budgetPolicy: fixtureBudget(corpus, question) } : options;
  return evaluateCasesRaw(corpus, question, supplied);
}
async function runCli(args, context = {}) {
  if (!args.includes('--live') || args.includes('--budget-policy')) return runCliRaw(args, context);
  const index = args.indexOf('--cases');
  const casePath = index >= 0 ? args[index + 1] : undefined;
  if (!casePath) return runCliRaw(args, context);
  const value = JSON.parse(await readFile(casePath, 'utf8'));
  const corpus = Array.isArray(value) ? value : value.cases;
  const policyDir = await mkdtemp(join(tmpdir(), 'cf-jev-explicit-policy-'));
  const policyPath = join(policyDir, 'budget.json');
  const questionPath = args[args.indexOf('--rubric') + 1];
  const profile = args.includes('--profile') ? args[args.indexOf('--profile') + 1] : undefined;
  const trial = await loadTrial(casePath, questionPath, profile);
  await writeFile(policyPath, JSON.stringify(fixtureBudget(corpus, trial.rubric)));
  try { return await runCliRaw([...args, '--budget-policy', policyPath], context); }
  finally { await rm(policyDir, { recursive: true, force: true }); }
}


test('informed excerpts retain original line coordinates and revalidate every dependency before and after dispatch', async () => {
  const root = await mkdtemp(join(tmpdir(), 'cf-jev-informed-'));
  try {
    const item = await informedFixture(root);
    let calls = 0;
    const options = { live: true, profile: 'security_actionability', sourceRoot: root, apiKey: 'mock',
      fetchImpl: async () => { calls++; return answer(0.99); } };
    const report = await evaluateCases([item], rubric, options);
    assert.equal(report.results[0].prediction, true);
    assert.equal(report.state, 'ADVISORY_REVIEW');
    assert.equal(report.metrics.precision, null);
    assert.equal(calls, 1);
    await writeFile(join(root, 'helper.py'), '# changed dependency\n');
    const stale = await evaluateCases([item], rubric, options);
    assert.equal(stale.results[0].error, 'source_binding_stale');
    assert.equal(calls, 1);
    const restored = await informedFixture(root);
    const changedDuringRequest = await evaluateCases([restored], rubric, { ...options,
      fetchImpl: async () => { calls++; await writeFile(join(root, 'helper.py'), '# replaced during request\n'); return answer(0.99); } });
    assert.equal(changedDuringRequest.results[0].prediction, null);
    assert.equal(changedDuringRequest.results[0].error, 'source_binding_stale');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('informed excerpts reject shifted spans, substituted content, stale hashes, oversized input and symlinks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'cf-jev-informed-reject-'));
  try {
    const item = await informedFixture(root);
    const mutations = [
      copy => { copy.state.evidence.artifacts[0].source_binding.start_line = 1; },
      copy => { copy.state.evidence.artifacts[0].source_binding.sha256 = '0'.repeat(64); },
      copy => { copy.state.evidence.dependencies[0].path = '../outside.py'; },
      copy => { copy.state.evidence.artifacts[0].source_binding.path = 'helper.py'; },
    ];
    let calls = 0;
    for (const mutate of mutations) {
      const copy = structuredClone(item); mutate(copy);
      try {
        const report = await evaluateCases([copy], rubric, { live: true, profile: 'security_actionability',
          sourceRoot: root, apiKey: 'mock', fetchImpl: async () => { calls++; return answer(0.99); } });
        assert.equal(report.results[0].prediction, null);
      } catch (error) { assert.match(error.message, /source|actionability/); }
    }
    await writeFile(join(root, 'helper.py'), 'x'.repeat(1_000_001));
    const oversized = await evaluateCases([item], rubric, { live: true, profile: 'security_actionability',
      sourceRoot: root, apiKey: 'mock', fetchImpl: async () => { calls++; return answer(0.99); } });
    assert.equal(oversized.results[0].error, 'source_input_too_large');
    await rm(join(root, 'helper.py'));
    await symlink(join(root, 'endpoint.py'), join(root, 'helper.py'), 'file');
    const linked = await evaluateCases([item], rubric, { live: true, profile: 'security_actionability',
      sourceRoot: root, apiKey: 'mock', fetchImpl: async () => { calls++; return answer(0.99); } });
    assert.equal(linked.results[0].error, 'source_path_invalid');
    assert.equal(calls, 0);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('six evidence-review profiles accept bound lane evidence and keep insufficient judgments unresolved', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cf-jev-six-lane-'));
  try {
    const framework = fileURLToPath(new URL('../factoryline/data/judge_framework.json', import.meta.url));
    const makeHash = (value) => createHash('sha256').update(value, 'utf8').digest('hex');
    const commit = 'c'.repeat(40);
    const rawResponse = (finding, sufficiency) => JSON.stringify({ model: MODEL,
      answers: { finding: { type: 'boolean', probability: finding }, evidence_sufficient: { type: 'boolean', probability: sufficiency } },
      providerMetadata: { gateway: { cost: '0.00001', routing: { finalProvider: 'typesafe-ai' } } } });
    const source = 'candidate source bytes';
    const makeArtifact = (kind, path, content, candidateSha) => ({ kind, path, content,
      sha256: makeHash(content), candidate_commit: commit, candidate_sha256: candidateSha });
    const redacted = JSON.stringify({ schema: 'factory.jev-redacted-secret-report.v1', features: [
      { kind: 'credential_assignment', location: 'src/config.py:8', fingerprint: 'a'.repeat(16), entropy_bucket: 'high', context_redacted: true },
    ] });
    const packages = [{ ecosystem: 'PyPI', name: 'example-package', version: '1.2.3' }];
    const packageManifest = JSON.stringify(packages);
    const executionFor = (engine) => ({ command: `${engine} run candidate`, engine, exit_code: 1, timed_out: false });
    const traceFor = (execution, candidateSha) => JSON.stringify({ schema: 'factory.jev-execution-trace.v1',
      ...execution, candidate_commit: commit, candidate_sha256: candidateSha, trace: 'observed event trace' });
    const definitions = {
      static: (candidate) => ({ location: { path: candidate.path, start_line: 1, end_line: 1 },
        artifacts: [makeArtifact('source', candidate.path, source, candidate.sha256)] }),
      secrets: (candidate) => ({ artifacts: [makeArtifact('redacted_report', candidate.path, redacted, candidate.sha256)] }),
      configuration: (candidate) => ({ location: { path: candidate.path, start_line: 1, end_line: 1 },
        artifacts: [makeArtifact('configuration_source', candidate.path, source, candidate.sha256)] }),
      dependencies: (candidate) => ({ packages, artifacts: [makeArtifact('package_manifest', candidate.path, packageManifest, candidate.sha256),
        makeArtifact('advisory', 'advisories/CVE-2026-0001.json', '{"id":"CVE-2026-0001"}', candidate.sha256)] }),
      runtime: (candidate) => { const execution = executionFor('pytest'); return { execution, artifacts: [
        makeArtifact('source', candidate.path, source, candidate.sha256), makeArtifact('trace', 'evidence/runtime-trace.json', traceFor(execution, candidate.sha256), candidate.sha256)] }; },
      fuzz: (candidate) => { const execution = executionFor('atheris'); return { execution, artifacts: [
        makeArtifact('source', candidate.path, source, candidate.sha256), makeArtifact('trace', 'evidence/fuzz-trace.json', traceFor(execution, candidate.sha256), candidate.sha256)] }; },
    };
    for (const profile of Object.keys(definitions)) {
      const candidateContent = profile === 'secrets' ? redacted : profile === 'dependencies' ? packageManifest : source;
      const candidate = { commit, path: profile === 'secrets' ? 'reports/secrets.json'
        : profile === 'dependencies' ? 'requirements.lock' : `src/${profile}.txt`, sha256: makeHash(candidateContent) };
      const evidence = definitions[profile](candidate);
      const state = { requirement: profile === 'secrets' ? 'secret_pattern_detected' : `Review ${profile} criterion`, candidate, evidence };
      const input = join(dir, `${profile}.json`);
      await writeFile(input, JSON.stringify([{ id: profile, expected: false, state } ]));
      const selected = await loadTrial(input, framework, profile);
      assert.equal(selected.framework.review_profile, profile);
      for (const [finding, sufficiency, expectedStatus, expectedPrediction] of [
        [0.99, 0.99, 'decided', true], [0.01, 0.99, 'decided', false], [0.5, 0.5, 'abstain', null],
      ]) {
        const responseBody = rawResponse(finding, sufficiency);
        let request;
        const report = await runCli(['--cases', input, '--rubric', framework, '--profile', profile, '--live'], {
          env: { AI_GATEWAY_API_KEY: 'mock' },
          fetchImpl: async (_url, options) => { request = JSON.parse(options.body); return new Response(responseBody); },
        });
        assert.equal(request.questions.finding.type, 'boolean');
        assert.equal(request.questions.evidence_sufficient.type, 'boolean');
        assert.equal(report.results[0].status, expectedStatus);
        assert.equal(report.results[0].prediction, expectedPrediction);
        if (expectedPrediction === null) assert.equal(report.results[0].abstention_reason, 'insufficient_evidence');
        assert.equal(report.results[0].response_sha256, makeHash(responseBody));
        assert.equal(report.framework.full_protocol_executed, false);
        assert.equal(report.authority.scanner_override, false);
      }
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('six evidence-review profiles reject absent, stale, mismatched and raw-secret evidence before transport', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cf-jev-six-lane-reject-'));
  try {
    const framework = fileURLToPath(new URL('../factoryline/data/judge_framework.json', import.meta.url));
    const input = join(dir, 'cases.json');
    const content = 'candidate source';
    const digest = (value) => createHash('sha256').update(value, 'utf8').digest('hex');
    const commit = 'd'.repeat(40), path = 'src/candidate.py', sourceHash = digest(content);
    const artifact = (kind, artifactPath, body, candidateSha = sourceHash) => ({ kind, path: artifactPath, content: body,
      sha256: digest(body), candidate_commit: commit, candidate_sha256: candidateSha });
    const baseState = { requirement: 'Review criterion', candidate: { commit, path, sha256: sourceHash },
      evidence: { location: { path, start_line: 1, end_line: 1 }, artifacts: [artifact('source', path, content)] } };
    const invalid = [
      ['static', { ...baseState, evidence: { artifacts: [] } }],
      ['static', { ...baseState, candidate: { ...baseState.candidate, commit: 'bad' } }],
      ['static', { ...baseState, evidence: { artifacts: [artifact('source', path, content, '0'.repeat(64))] } }],
      ['configuration', baseState],
      ['dependencies', { ...baseState, evidence: { packages: [{ ecosystem: 'PyPI', name: 'pkg', version: '1' }], artifacts: [] } }],
      ['runtime', baseState],
      ['fuzz', baseState],
      ['secrets', (() => {
        const rawReport = JSON.stringify({ schema: 'factory.jev-redacted-secret-report.v1', features: [
          { kind: 'credential_assignment', location: 'src/app.py:4', fingerprint: 'b'.repeat(16), context_redacted: true },
        ],
          raw_token: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' });
        const rawHash = digest(rawReport);
        const candidate = { commit, path, sha256: rawHash };
        return { requirement: 'secret_pattern_detected', candidate,
          evidence: { artifacts: [artifact('redacted_report', path, rawReport, rawHash)] } };
      })()],
      ['secrets', { ...baseState, requirement: 'Review leaked credential ghp_abcdefghijklmnopqrstuvwxyz0123456789' }],
    ];
    for (const [profile, state] of invalid) {
      await writeFile(input, JSON.stringify([{ id: 'invalid', expected: true, state }]));
      let calls = 0;
      await assert.rejects(runCli(['--cases', input, '--rubric', framework, '--profile', profile, '--live'], {
        env: { AI_GATEWAY_API_KEY: 'mock' }, fetchImpl: async () => { calls++; return answer(0.99); },
      }));
      assert.equal(calls, 0, `${profile} must block before transport`);
    }
    let directCalls = 0;
    await assert.rejects(evaluateCases([{ id: 'direct-bypass', expected: true, state: baseState }], rubric, {
      profile: 'runtime', live: true, apiKey: 'mock', fetchImpl: async () => { directCalls++; return answer(0.99); },
    }), /missing_runtime_execution_evidence/);
    assert.equal(directCalls, 0, 'direct evaluator calls must enforce profile preflight too');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('selected test names and source coordinates bind before provider calls', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cf-jev-target-'));
  try {
    const input = join(dir, 'cases.json');
    const framework = fileURLToPath(new URL('../factoryline/data/judge_framework.json', import.meta.url));
    const source = 'def test_unrelated():\n    assert system() == 1\n\nasync def test_target():\n    pass\n';
    const candidate = { commit: 'a'.repeat(40), path: 'tests/test_value.py',
      excerpt_sha256: createHash('sha256').update(source).digest('hex') };
    const item = { id: 'target', expected: true, state: { requirement: 'Review only test_target',
      candidate, evidence: { source, selected_test: { name: 'test_target', start_line: 4, end_line: 5 } } } };
    await writeFile(input, JSON.stringify([item]));
    const trial = await loadTrial(input, framework, 'test_oracle');
    assert.match(trial.rubric.instructions, /Never credit assertions in unrelated tests/);
    assert.deepEqual(trial.cases[0].state.evidence.selected_test, item.state.evidence.selected_test);
    const excerpt = '    def test_method(self):\r\n        self.assertEqual(system(), 1)\r\n';
    const focused = structuredClone(item);
    focused.state.candidate.excerpt_sha256 = createHash('sha256').update(excerpt).digest('hex');
    focused.state.evidence = { source: excerpt, source_start_line: 503,
      selected_test: { name: 'test_method', start_line: 503, end_line: 504 } };
    await writeFile(input, JSON.stringify([focused]));
    await loadTrial(input, framework, 'test_oracle');
    for (const selected of [null, { name: 'test_missing', start_line: 4, end_line: 5 },
      { name: 'test_target', start_line: 2, end_line: 5 },
      { name: 'test_target', start_line: 4, end_line: 6 },
      { name: 'test_target', start_line: 4, end_line: 3 },
      { name: 'test_target', start_line: 4.5, end_line: 5 },
      { name: 'test_target.*', start_line: 4, end_line: 5 }]) {
      const invalid = structuredClone(item);
      invalid.state.evidence.selected_test = selected;
      await writeFile(input, JSON.stringify([invalid]));
      let calls = 0;
      await assert.rejects(runCli(['--cases', input, '--rubric', framework,
        '--profile', 'test_oracle', '--live'], {
        env: { AI_GATEWAY_API_KEY: 'mock' },
        fetchImpl: async () => { calls++; return answer(0.01); },
      }), /invalid_test_oracle_target_binding/);
      assert.equal(calls, 0);
    }
    for (const offset of [0, -1, 1.5, '503']) {
      const invalid = structuredClone(focused);
      invalid.state.evidence.source_start_line = offset;
      await writeFile(input, JSON.stringify([invalid]));
      await assert.rejects(loadTrial(input, framework, 'test_oracle'), /invalid_test_oracle_target_binding/);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('security actionability profile dispatches only candidate-bound source context and never sends expected labels', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cf-jev-security-actionability-'));
  try {
    const framework = fileURLToPath(new URL('../factoryline/data/judge_framework.json', import.meta.url));
    const hash = (value) => createHash('sha256').update(value, 'utf8').digest('hex');
    const commit = 'e'.repeat(40), sourcePath = 'src/endpoint.py';
    const candidateSource = 'def load(payload):\n    return pickle.loads(payload)\n';
    const candidateSha = hash(candidateSource);
    const makeArtifact = (kind, path, content) => ({ kind, path, content, sha256: hash(content),
      candidate_commit: commit, candidate_sha256: candidateSha });
    const artifacts = [
      makeArtifact('source', sourcePath, candidateSource),
      makeArtifact('input_origin', 'evidence/input-origin.json', '{"origin":"request body","status":"observed"}'),
      makeArtifact('sink_behavior', 'evidence/sink-behavior.json', '{"sink":"pickle.loads","behavior":"executes object reducers"}'),
      makeArtifact('caller_contract', 'evidence/callers.json', '{"callers":["handle_upload"]}'),
      makeArtifact('trust_boundary', 'evidence/trust-boundary.json', '{"boundary":"unauthenticated request to handler"}'),
      makeArtifact('counterevidence', 'evidence/counterevidence.json', '{"reviewed":true,"facts":[]}'),
    ];
    const refs = (kind) => {
      const artifact = artifacts.find((item) => item.kind === 'source');
      return [{ path: artifact.path, sha256: artifact.sha256, start_line: 1, end_line: 2 }];
    };
    const item = { id: 'actionable-source', category: 'security_actionability', expected: true,
      state: { requirement: 'Is this an actionable unsafe-deserialization defect?',
        candidate: { commit, path: sourcePath, sha256: candidateSha },
        evidence: { location: { path: sourcePath, start_line: 2, end_line: 2 }, artifacts,
          actionability: {
            input_origin: { status: 'known', artifacts: refs('input_origin') },
            sink_behavior: { status: 'known', artifacts: refs('sink_behavior') },
            callers: { status: 'resolved', artifacts: refs('caller_contract') },
            trust_boundary: { status: 'known', artifacts: refs('trust_boundary') },
            counterevidence: { status: 'reviewed', artifacts: refs('counterevidence') },
          } } } };
    const casesPath = join(dir, 'cases.json');
    const rubricPath = join(dir, 'framework.json');
    const policyPath = join(dir, 'budget.json');
    const archiveRoot = join(dir, 'evaluations');
    await writeFile(casesPath, JSON.stringify([item]));
    await writeFile(rubricPath, await readFile(framework));
    const selected = await loadTrial(casesPath, rubricPath, 'security_actionability');
    assert.equal(selected.framework.review_profile, 'security_actionability');
    await writeFile(policyPath, JSON.stringify(fixtureBudget([item], selected.rubric)));
    let endpoint, request;
    const report = await runCliRaw(['--cases', casesPath, '--rubric', rubricPath,
      '--profile', 'security_actionability', '--budget-policy', policyPath, '--live'], {
      env: { AI_GATEWAY_API_KEY: 'mock' }, archiveRoot, archiveBoundary: dir,
      fetchImpl: async (url, options) => { endpoint = url; request = JSON.parse(options.body); return answer(0.99); },
    });
    assert.equal(endpoint, ENDPOINT);
    assert.equal(request.model, MODEL);
    assert.deepEqual(request.state, item.state);
    assert.equal(Object.hasOwn(request, 'expected'), false);
    assert.equal(Object.hasOwn(request.state, 'expected'), false);
    assert.equal(JSON.stringify(request).includes('"expected":true'), false);
    assert.equal(report.framework.review_profile, 'security_actionability');
    assert.equal(report.authority.scanner_override, false);
    assert.equal(report.results[0].admission, 'admitted');
    assert.equal(report.results[0].status, 'decided');
    assert.equal(report.results[0].prediction, true);
    assert.equal(report.results[0].advisory_label, 'ACTIONABLE');
    for (const [probability, sufficient, label] of [[0.01, 0.99, 'NOT_ACTIONABLE'], [0.99, 0.4, 'INSUFFICIENT_EVIDENCE']]) {
      const followup = await runCliRaw(['--cases', casesPath, '--rubric', rubricPath,
        '--profile', 'security_actionability', '--budget-policy', policyPath, '--live'], {
        env: { AI_GATEWAY_API_KEY: 'mock' }, archiveRoot, archiveBoundary: dir,
        fetchImpl: async () => answer(probability, {}, sufficient),
      });
      assert.equal(followup.results[0].advisory_label, label);
      assert.equal(followup.authority.scanner_override, false);
    }
    const unlabelled = structuredClone(item);
    delete unlabelled.expected;
    await writeFile(casesPath, JSON.stringify([unlabelled]));
    await writeFile(policyPath, JSON.stringify(fixtureBudget([unlabelled], selected.rubric)));
    const advice = await runCliRaw(['--cases', casesPath, '--rubric', rubricPath,
      '--profile', 'security_actionability', '--budget-policy', policyPath, '--live'], {
      env: { AI_GATEWAY_API_KEY: 'mock' }, archiveRoot, archiveBoundary: dir,
      fetchImpl: async () => answer(0.99),
    });
    assert.equal(advice.results[0].advisory_label, 'ACTIONABLE');
    assert.equal(advice.metrics.labelled, 0);
    assert.equal(advice.metrics.unlabelled, 1);
    assert.equal(advice.metrics.precision, null);
    assert.equal(advice.metrics.recall, null);
    assert.equal(advice.metrics.accuracy, null);
    const journalPath = join(archiveRoot, report.tracking.journal_filename);
    const journalBytes = await readFile(journalPath);
    assert.equal((await verifyJournal(journalPath, { expectedJournalSha256:
      createHash('sha256').update(journalBytes).digest('hex') })).state, 'VERIFIED');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('security actionability profile locally abstains on missing or unknown context without transport', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cf-jev-security-actionability-unknown-'));
  try {
    const framework = fileURLToPath(new URL('../factoryline/data/judge_framework.json', import.meta.url));
    const hash = (value) => createHash('sha256').update(value, 'utf8').digest('hex');
    const commit = 'f'.repeat(40), sourcePath = 'src/loader.py';
    const source = 'def decode(payload):\n    return pickle.loads(payload)\n';
    const candidateSha = hash(source);
    const sourceArtifact = { kind: 'source', path: sourcePath, content: source, sha256: candidateSha,
      candidate_commit: commit, candidate_sha256: candidateSha };
    const baseEvidence = { location: { path: sourcePath, start_line: 2, end_line: 2 }, artifacts: [sourceArtifact] };
    const completeShapeUnknown = { input_origin: { status: 'unknown', artifacts: [] },
      sink_behavior: { status: 'known', artifacts: [{ path: sourcePath, sha256: candidateSha }] },
      callers: { status: 'resolved', artifacts: [{ path: sourcePath, sha256: candidateSha }] },
      trust_boundary: { status: 'known', artifacts: [{ path: sourcePath, sha256: candidateSha }] },
      counterevidence: { status: 'reviewed', artifacts: [{ path: sourcePath, sha256: candidateSha }] } };
    const cases = [
      { id: 'origin-unknown', expected: false, state: { requirement: 'Actionability check',
        candidate: { commit, path: sourcePath, sha256: candidateSha },
        evidence: { ...baseEvidence, actionability: completeShapeUnknown } } },
      { id: 'context-missing', expected: true, state: { requirement: 'Actionability check',
        candidate: { commit, path: sourcePath, sha256: candidateSha }, evidence: baseEvidence } },
      { id: 'unbounded-source-context', expected: false, state: { requirement: 'Actionability check',
        candidate: { commit, path: sourcePath, sha256: candidateSha },
        evidence: { ...baseEvidence, actionability: { ...completeShapeUnknown,
          input_origin: { status: 'known', artifacts: [{ path: sourcePath, sha256: candidateSha }] } } } } },
    ];
    const casesPath = join(dir, 'cases.json'), rubricPath = join(dir, 'framework.json'), policyPath = join(dir, 'budget.json');
    const archiveRoot = join(dir, 'evaluations');
    await writeFile(casesPath, JSON.stringify(cases));
    await writeFile(rubricPath, await readFile(framework));
    const selected = await loadTrial(casesPath, rubricPath, 'security_actionability');
    await writeFile(policyPath, JSON.stringify(fixtureBudget(cases, selected.rubric)));
    let calls = 0;
    const report = await runCliRaw(['--cases', casesPath, '--rubric', rubricPath,
      '--profile', 'security_actionability', '--budget-policy', policyPath, '--live'], {
      env: { AI_GATEWAY_API_KEY: 'mock' }, archiveRoot, archiveBoundary: dir,
      fetchImpl: async () => { calls++; return answer(0.99); },
    });
    assert.equal(calls, 0);
    assert.deepEqual(report.results.map((row) => row.status), ['abstain', 'abstain', 'abstain']);
    assert.deepEqual(report.results.map((row) => row.abstention_reason),
      ['insufficient_actionability_context', 'insufficient_actionability_context', 'insufficient_actionability_context']);
    assert.ok(report.results.every((row) => row.prediction === null && row.probability === null
      && row.evidence_probability === null && row.admission === 'not_run'));
    assert.equal(report.dispatch_budget.provider_reported_cost_usd, 0);
    const journalPath = join(archiveRoot, report.tracking.journal_filename);
    const journalBytes = await readFile(journalPath);
    assert.equal((await verifyJournal(journalPath, { expectedJournalSha256:
      createHash('sha256').update(journalBytes).digest('hex') })).state, 'VERIFIED');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('security actionability profile rejects stale evidence, labels and secrets before provider transport', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cf-jev-security-actionability-reject-'));
  try {
    const framework = fileURLToPath(new URL('../factoryline/data/judge_framework.json', import.meta.url));
    const hash = (value) => createHash('sha256').update(value, 'utf8').digest('hex');
    const commit = 'b'.repeat(40), sourcePath = 'src/loader.py';
    const source = 'def decode(payload):\n    return pickle.loads(payload)\n';
    const candidateSha = hash(source);
    const makeArtifact = (kind, path, content, changes = {}) => ({ kind, path, content, sha256: hash(content),
      candidate_commit: commit, candidate_sha256: candidateSha, ...changes });
    const artifacts = [makeArtifact('source', sourcePath, source),
      makeArtifact('input_origin', 'evidence/origin.json', '{"origin":"external"}'),
      makeArtifact('sink_behavior', 'evidence/sink.json', '{"behavior":"executes reducers"}'),
      makeArtifact('caller_contract', 'evidence/callers.json', '{"caller":"handle"}'),
      makeArtifact('trust_boundary', 'evidence/boundary.json', '{"boundary":"http"}'),
      makeArtifact('counterevidence', 'evidence/counter.json', '{"reviewed":true}')];
    const refs = (kind) => {
      const artifact = artifacts.find((item) => item.kind === kind);
      return [{ path: artifact.path, sha256: artifact.sha256 }];
    };
    const context = { input_origin: { status: 'known', artifacts: refs('input_origin') },
      sink_behavior: { status: 'known', artifacts: refs('sink_behavior') },
      callers: { status: 'resolved', artifacts: refs('caller_contract') },
      trust_boundary: { status: 'known', artifacts: refs('trust_boundary') },
      counterevidence: { status: 'reviewed', artifacts: refs('counterevidence') } };
    const baseState = { requirement: 'Actionability check', candidate: { commit, path: sourcePath, sha256: candidateSha },
      evidence: { location: { path: sourcePath, start_line: 2, end_line: 2 }, artifacts, actionability: context } };
    const invalidStates = [
      { ...baseState, evidence: { ...baseState.evidence, artifacts: artifacts.map((item) => item.kind === 'source'
        ? { ...item, sha256: '0'.repeat(64) } : item) } },
      { ...baseState, evidence: { ...baseState.evidence, actionability: { ...context,
        input_origin: { status: 'known', artifacts: [{ path: 'evidence/missing.json', sha256: 'a'.repeat(64) }] } } } },
      { ...baseState, expected_label: false },
      { ...baseState, requirement: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' },
      { ...baseState, candidate: { ...baseState.candidate, expected: true } },
      { ...baseState, evidence: { ...baseState.evidence, expected_label: false } },
      { ...baseState, evidence: { ...baseState.evidence, artifacts: artifacts.map(row => ({ ...row, expected_label: true })) } },
      { ...baseState, evidence: { ...baseState.evidence, artifacts: [...artifacts,
        makeArtifact('counterevidence', 'evidence/private.json', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789')] } },
    ];
    const casesPath = join(dir, 'cases.json'), rubricPath = join(dir, 'framework.json');
    await writeFile(rubricPath, await readFile(framework));
    for (const [index, state] of invalidStates.entries()) {
      const item = { id: `invalid-${index}`, expected: true, state };
      const policyPath = join(dir, `budget-${index}.json`);
      await writeFile(casesPath, JSON.stringify([item]));
      const selected = await loadTrial(casesPath, rubricPath, 'security_actionability').catch(() => null);
      const question = selected?.rubric ?? JSON.parse(await readFile(rubricPath, 'utf8')).review_profiles.security_actionability;
      await writeFile(policyPath, JSON.stringify(fixtureBudget([item], question)));
      let calls = 0;
      await assert.rejects(runCliRaw(['--cases', casesPath, '--rubric', rubricPath,
        '--profile', 'security_actionability', '--budget-policy', policyPath, '--live'], {
        env: { AI_GATEWAY_API_KEY: 'mock' }, archiveRoot: join(dir, 'evaluations'), archiveBoundary: dir,
        fetchImpl: async () => { calls++; return answer(0.99); },
      }));
      assert.equal(calls, 0, `invalid security actionability packet ${index} must not reach Vercel`);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
