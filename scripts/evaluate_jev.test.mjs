import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  ENDPOINT, MODEL, evaluateCases, loadTrial, parseArgs, runCli, summarizeCosts, summarizeLatency,
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

test('experimental score includes uncertain model assessments without admitting a grade', async () => {
  const options = () => ({ grade: true, live: true, apiKey: 'mock',
    fetchImpl: mock([answer(0.8, {}, 0.2), answer(0.2, {}, 0.3)]) });
  const report = await evaluateCases(cases, rubric, options());
  assert.equal(report.experimental_score.label, 'Experimental Jev score');
  assert.equal(report.experimental_score.state, 'EXPERIMENTAL');
  assert.equal(report.experimental_score.score, 50);
  assert.equal(report.experimental_score.admitted_criteria, 0);
  assert.equal(report.experimental_score.authority.approval, false);
  assert.equal(report.advisory_grade.grade, null);
  assert.equal(report.metrics.decided, 0);
  const relabelled = await evaluateCases(cases.map((item) => ({ ...item, expected: !item.expected })), rubric, options());
  assert.deepEqual(report.experimental_score, relabelled.experimental_score);
});

test('experimental score never fabricates missing responses or dry-run values', async () => {
  const report = await evaluateCases(cases, rubric, { grade: true, live: true, apiKey: 'mock',
    fetchImpl: mock([answer(0.2), new Response('{}', { status: 500 })]) });
  assert.equal(report.experimental_score.score, null);
  assert.equal(report.experimental_score.observed_mean_score, 80);
  assert.equal(report.experimental_score.model_response_coverage, 0.5);
  assert.equal(report.experimental_score.state, 'INCOMPLETE');
  const dry = await evaluateCases(cases, rubric, { grade: true });
  assert.equal(dry.experimental_score.score, null);
  assert.equal(dry.experimental_score.observed_mean_score, null);
  assert.equal(dry.experimental_score.observed_criteria, 0);
  assert.equal((await evaluateCases(cases, rubric)).experimental_score, null);
});

test('PRD and PR profiles select distinct hash-bound criteria through the operator CLI', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cf-jev-profiles-'));
  try {
    const input = join(dir, 'cases.json');
    await writeFile(input, JSON.stringify(cases));
    const framework = fileURLToPath(new URL('../factoryline/data/judge_framework.json', import.meta.url));
    const reports = [];
    for (const profile of ['prd', 'pr']) {
      const selected = await loadTrial(input, framework, profile);
      assert.equal(selected.framework.review_profile, profile);
      let request;
      const report = await runCli(['--cases', input, '--rubric', framework, '--profile', profile, '--grade', '--live'], {
        env: { AI_GATEWAY_API_KEY: 'mock' },
        fetchImpl: async (_url, options) => { request = JSON.parse(options.body); return answer(0.01); },
      });
      assert.ok(request.questions.finding.instructions.includes(profile === 'prd' ? 'PRD criterion' : 'PR criterion'));
      assert.ok(request.questions.evidence_sufficient.instructions.includes(profile === 'prd' ? 'document excerpt' : 'changed source'));
      assert.equal(report.advisory_grade.grade, 100);
      assert.equal(report.framework.review_profile, profile);
      assert.equal(JSON.stringify(request).includes('"expected"'), false);
      reports.push(report);
    }
    assert.notEqual(reports[0].hashes.configuration, reports[1].hashes.configuration);
    await assert.rejects(loadTrial(input, framework, 'unknown'), /invalid_review_profile/);
    const plain = join(dir, 'plain.json');
    await writeFile(plain, JSON.stringify(rubric));
    await assert.rejects(loadTrial(input, plain, 'pr'), /invalid_review_profile/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('criterion-specific evidence instructions are bounded and mandatory when supplied', async () => {
  for (const invalid of ['', 42, 'x'.repeat(8193)]) {
    await assert.rejects(evaluateCases(cases, { ...rubric, evidence_instructions: invalid }), /invalid_evidence_instructions/);
  }
});

test('advisory grading aggregates only admitted evaluator decisions', async () => {
  const corpus = [...cases, { id: 'uncertain', state: 'missing context', expected: true }];
  const report = await evaluateCases(corpus, rubric, { grade: true, live: true, apiKey: 'mock',
    fetchImpl: mock([answer(0.01), answer(0.99), answer(0.5)]) });
  assert.equal(report.advisory_grade.grade, null);
  assert.deepEqual(report.advisory_grade.counts, { total: 3, passed: 1, failed: 1, unresolved: 1 });
  assert.equal(report.advisory_grade.coverage, 2 / 3);
  assert.equal(report.advisory_grade.authority.scanner_override, false);
});

test('advisory grade has equal weights and ignores evaluation labels', async () => {
  for (const [probability, score] of [[0.01, 100], [0.99, 0]]) {
    const options = () => ({ grade: true, live: true, apiKey: 'mock', fetchImpl: mock([answer(probability), answer(probability)]) });
    const original = await evaluateCases(cases, rubric, options());
    const relabelled = await evaluateCases(cases.map(item => ({ ...item, expected: !item.expected })), rubric, options());
    assert.equal(original.advisory_grade.grade, score);
    assert.deepEqual(original.advisory_grade, relabelled.advisory_grade);
    assert.equal(original.advisory_grade.coverage, 1);
  }
});

test('grading helper is not a public bypass of evidence admission', async () => {
  const exported = await import('./evaluate_jev.mjs');
  assert.equal(exported.summarizeGrade, undefined);
});

test('grading is explicitly enabled, hash bound and blocked by insufficient evidence', async () => {
  const disabled = await evaluateCases(cases, rubric);
  const dryGrade = await evaluateCases(cases, rubric, { grade: true });
  assert.equal(disabled.advisory_grade, null);
  assert.equal(dryGrade.advisory_grade.grade, null);
  assert.equal(dryGrade.advisory_grade.counts.unresolved, 2);
  assert.notEqual(disabled.hashes.configuration, dryGrade.hashes.configuration);
  const report = await evaluateCases(cases, rubric, {
    grade: true, live: true, apiKey: 'mock', fetchImpl: mock([answer(0.01), answer(0.99, {}, 0.1)]),
  });
  assert.equal(report.advisory_grade.grade, null);
  assert.deepEqual(report.advisory_grade.counts, { total: 2, passed: 1, failed: 0, unresolved: 1 });
  assert.equal(report.metrics.confusion.fn, 1);
  await assert.rejects(evaluateCases(cases, rubric, { grade: 'true' }), /invalid_grade_flag/);
});

test('summarizeCosts preserves partial, complete, dry-run and overflow costs', () => {
  const complete = [{ reported_cost_usd: 0.001 }, { reported_cost_usd: 0.002 }];
  assert.deepEqual(summarizeCosts(complete, true), {
    total_usd: 0.003, reported_sum_usd: 0.003, unknown_requests: 0,
  });
  assert.deepEqual(summarizeCosts([{ reported_cost_usd: null }], true), {
    total_usd: null, reported_sum_usd: null, unknown_requests: 1,
  });
  assert.equal(summarizeCosts(complete, false).total_usd, null);
  assert.equal(summarizeCosts([{ reported_cost_usd: Number.MAX_VALUE },
    { reported_cost_usd: Number.MAX_VALUE }], true).total_usd, null);
});

test('summarizeLatency preserves measured request denominator and dry-run nulls', () => {
  assert.deepEqual(summarizeLatency([10, 30], true), {
    requests: 2, total_ms: 40, mean_ms: 20, max_ms: 30,
  });
  assert.deepEqual(summarizeLatency([], false), {
    requests: 0, total_ms: null, mean_ms: null, max_ms: null,
  });
});

test('default dry run never calls a transport or claims measured accuracy', async () => {
  const report = await evaluateCases(cases, rubric, {
    apiKey: 'configured-but-not-authorized',
    fetchImpl: () => { throw new Error('must not call'); },
  });
  assert.equal(report.mode, 'dry_run');
  assert.equal(report.metrics.coverage, 0);
  assert.equal(report.metrics.accuracy, null);
  assert.equal(report.metrics.unresolved, 2);
  assert.equal(report.authority.release, false);
  assert.equal(report.cost.total_usd, null);
});

test('mocked live positive and negative obey the exact provider contract', async () => {
  const requests = [];
  const responses = [answer(0.95), answer(0.05)];
  const report = await evaluateCases(cases, rubric, {
    live: true, apiKey: 'test-secret',
    fetchImpl: async (url, options) => {
      requests.push({ url, options, body: JSON.parse(options.body) });
      return responses.shift();
    },
  });
  assert.deepEqual(report.metrics.confusion, { tp: 1, fp: 0, fn: 0, tn: 1 });
  assert.equal(report.metrics.accuracy, 1);
  assert.equal(report.metrics.precision, 1);
  assert.equal(report.metrics.recall, 1);
  assert.equal(report.metrics.coverage, 1);
  assert.equal(report.cost.total_usd, 0.00002);
  assert.equal(report.latency.requests, 2);
  for (const { url, options, body } of requests) {
    assert.equal(url, ENDPOINT);
    assert.equal(options.redirect, 'error');
    assert.equal(body.model, MODEL);
    assert.equal(body.questions.finding.type, 'boolean');
    assert.equal(body.questions.evidence_sufficient.type, 'boolean');
    assert.match(body.questions.finding.instructions, /untrusted/i);
    assert.match(body.questions.evidence_sufficient.instructions, /self.report/i);
    assert.deepEqual(body.providerOptions.gateway, { zeroDataRetention: true, only: ['typesafe-ai'] });
    assert.ok(!Object.hasOwn(body, 'expected'));
    assert.ok(!Object.hasOwn(body, 'id'));
  }
  for (const hash of Object.values(report.hashes)) assert.match(hash, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(report).includes('test-secret'));
  assert.ok(!JSON.stringify(report).includes('unsafe operation'));
});

test('confusion records independently labeled false positives and false negatives', async () => {
  const report = await evaluateCases(cases, rubric, {
    live: true, apiKey: 'mock', fetchImpl: mock([answer(0.01), answer(0.99)]),
  });
  assert.deepEqual(report.metrics.confusion, { tp: 0, fp: 1, fn: 1, tn: 0 });
  assert.equal(report.metrics.accuracy, 0);
  assert.equal(report.metrics.precision, 0);
  assert.equal(report.metrics.recall, 0);
});

test('confidence band abstains and penalizes unresolved positive labels', async () => {
  const report = await evaluateCases(cases, rubric, {
    live: true, apiKey: 'mock', fetchImpl: mock([answer(0.5), answer(0.5)]),
  });
  assert.equal(report.metrics.abstentions, 2);
  assert.equal(report.metrics.unresolved, 2);
  assert.equal(report.metrics.coverage, 0);
  assert.equal(report.metrics.accuracy, 0);
  assert.equal(report.metrics.confusion.fn, 1);
  assert.equal(report.metrics.recall, 0);
  assert.equal(report.metrics.precision, null);
});

test('finding confidence cannot substitute for sufficient concrete evidence', async () => {
  const report = await evaluateCases(cases, rubric, {
    live: true, apiKey: 'mock', fetchImpl: mock([
      answer(0.99, {}, 0.05), answer(0.01, {}, 0.5),
    ]),
  });
  assert.equal(report.metrics.abstentions, 2);
  assert.equal(report.metrics.confusion.fn, 1);
  assert.equal(report.metrics.coverage, 0);
  assert.equal(report.results[0].evidence_probability, 0.05);
  assert.equal(report.results[1].evidence_probability, 0.5);
  assert.equal(report.results[0].abstention_reason, 'insufficient_evidence');
});

test('per-category metrics retain each labeled case without a macro-average claim', async () => {
  const report = await evaluateCases([
    { ...cases[0], category: 'escaping_callback' },
    { ...cases[1], category: 'type_check' },
    { id: 'unscoped', state: 'actual source', expected: true },
  ], rubric, {
    live: true, apiKey: 'mock', fetchImpl: mock([answer(0.99), answer(0.99), answer(0.99, {}, 0.1)]),
  });
  assert.equal(report.metrics.total, 3);
  assert.equal(report.metrics.accuracy, 1 / 3);
  assert.equal(report.category_metrics.escaping_callback.confusion.tp, 1);
  assert.equal(report.category_metrics.type_check.confusion.fp, 1);
  assert.equal(report.category_metrics.unspecified.confusion.fn, 1);
  assert.equal(Object.values(report.category_metrics).reduce((sum, item) => sum + item.total, 0), 3);
  assert.ok(!Object.hasOwn(report, 'macro_accuracy'));
});

test('threshold boundaries are inclusive and configuration is hash bound', async () => {
  const report = await evaluateCases(cases, rubric, {
    live: true, apiKey: 'mock', trueThreshold: 0.8, falseThreshold: 0.2,
    fetchImpl: mock([answer(0.8), answer(0.2)]),
  });
  assert.equal(report.metrics.accuracy, 1);
  assert.deepEqual(report.thresholds, { true: 0.8, false: 0.2 });
  const defaultReport = await evaluateCases(cases, rubric);
  assert.notEqual(report.hashes.configuration, defaultReport.hashes.configuration);
});

for (const [name, payload] of [
  ['missing answer', {}],
  ['wrong answer type', { answers: { finding: { type: 'score', probability: 0.99 } } }],
  ['string probability', { answers: { finding: { type: 'boolean', probability: '0.99' } } }],
  ['negative probability', { answers: { finding: { type: 'boolean', probability: -1 } } }],
  ['high probability', { answers: { finding: { type: 'boolean', probability: 2 } } }],
  ['wrong model', { model: 'other-provider/model' }],
  ['wrong routed provider', { providerMetadata: { gateway: { routing: { finalProvider: 'other' } } } }],
  ['missing evidence answer', { answers: { finding: { type: 'boolean', probability: 0.99 } } }],
  ['invalid evidence probability', { answers: {
    finding: { type: 'boolean', probability: 0.99 },
    evidence_sufficient: { type: 'boolean', probability: '0.99' },
  } }],
]) {
  test(`malformed response fails closed: ${name}`, async () => {
    const response = name === 'missing answer'
      ? new Response(JSON.stringify(payload)) : answer(0.99, payload);
    const report = await evaluateCases([cases[0]], rubric, {
      live: true, apiKey: 'mock', fetchImpl: mock([response]),
    });
    assert.equal(report.results[0].status, 'error');
    assert.equal(report.results[0].prediction, null);
    assert.equal(report.metrics.confusion.fn, 1);
    assert.equal(report.metrics.accuracy, 0);
  });
}

test('timeout aborts transport and records an unresolved label', async () => {
  let signal;
  const report = await evaluateCases([cases[0]], rubric, {
    live: true, apiKey: 'mock', timeoutMs: 15,
    fetchImpl: async (_url, options) => { signal = options.signal; return new Promise(() => {}); },
  });
  assert.equal(signal.aborted, true);
  assert.equal(report.results[0].error, 'timeout');
  assert.equal(report.metrics.confusion.fn, 1);
});

test('timeout covers response body reads too', async () => {
  const report = await evaluateCases([cases[0]], rubric, {
    live: true, apiKey: 'mock', timeoutMs: 15,
    fetchImpl: async () => new Response(new ReadableStream({ start() {} })),
  });
  assert.equal(report.results[0].error, 'timeout');
});

test('response byte bound rejects oversized streaming responses', async () => {
  const report = await evaluateCases([cases[0]], rubric, {
    live: true, apiKey: 'mock',
    fetchImpl: async () => new Response('x'.repeat(65_537)),
  });
  assert.equal(report.results[0].error, 'response_too_large');
});

test('HTTP and transport errors never echo provider or secret text', async () => {
  for (const fetchImpl of [
    async () => new Response('mock-secret-private-state', { status: 401 }),
    async () => { throw new Error('mock-secret-private-state'); },
    async () => new Response('mock-secret-private-state'),
  ]) {
    const report = await evaluateCases([cases[0]], rubric, { live: true, apiKey: 'mock-secret', fetchImpl });
    assert.equal(report.results[0].status, 'error');
    assert.ok(!JSON.stringify(report).includes('mock-secret'));
    assert.equal(report.cost.total_usd, null);
  }
});

test('unknown cost remains unknown rather than an invented zero', async () => {
  const report = await evaluateCases(cases, rubric, {
    live: true, apiKey: 'mock', fetchImpl: mock([
      answer(0.99, { providerMetadata: {} }), answer(0.01),
    ]),
  });
  assert.equal(report.cost.total_usd, null);
  assert.equal(report.cost.reported_sum_usd, 0.00001);
  assert.equal(report.cost.unknown_requests, 1);
});

test('invalid corpus, rubric and thresholds block before transport', async () => {
  const invalid = [
    [[], rubric, {}],
    [[{ ...cases[0], expected: 'true' }], rubric, {}],
    [[cases[0], cases[0]], rubric, {}],
    [cases, { instructions: '' }, {}],
    [cases, rubric, { trueThreshold: 0.1, falseThreshold: 0.9 }],
    [cases, rubric, { timeoutMs: 0 }],
    [cases, rubric, { live: true }],
    [cases, rubric, { live: 'true', apiKey: 'mock' }],
  ];
  for (const [input, question, options] of invalid) {
    await assert.rejects(evaluateCases(input, question, {
      ...options, fetchImpl: () => assert.fail('must not call'),
    }));
  }
});

test('CLI accepts only the explicit contract and rejects arbitrary URLs', () => {
  assert.deepEqual(parseArgs(['--cases', 'cases.json', '--rubric', 'rubric.json']), {
    casesPath: 'cases.json', rubricPath: 'rubric.json', live: false, grade: false,
  });
  assert.equal(parseArgs(['--cases', 'cases.json', '--rubric', 'rubric.json', '--grade']).grade, true);
  assert.throws(() => parseArgs(['--cases', 'cases.json', '--rubric', 'rubric.json', '--grade', '--grade']), /invalid_arguments/);
  assert.throws(() => parseArgs(['--endpoint', 'https://attacker.test']), /invalid_arguments/);
  assert.throws(() => parseArgs(['--live']), /invalid_arguments/);
});

test('CLI help states opt-in grading, unresolved score and live authorization boundaries', () => {
  const response = spawnSync(process.execPath, [fileURLToPath(new URL('./evaluate_jev.mjs', import.meta.url)), '--help'],
    { encoding: 'utf8', env: { ...process.env, AI_GATEWAY_API_KEY: '' } });
  assert.equal(response.status, 0);
  assert.match(response.stdout, /--grade/);
  assert.match(response.stdout, /numeric grade null/);
  assert.match(response.stdout, /Default is dry run/);
  assert.equal(response.stderr, '');
});

test('file loading binds raw input bytes; CLI default works with no key', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'jev-eval-'));
  try {
    const casesPath = join(directory, 'cases.json');
    const rubricPath = join(directory, 'rubric.json');
    const outPath = join(directory, 'report.json');
    await writeFile(casesPath, JSON.stringify({ cases }, null, 2));
    await writeFile(rubricPath, JSON.stringify(rubric));
    const loaded = await loadTrial(casesPath, rubricPath);
    assert.deepEqual(loaded.cases, cases);
    const report = await runCli(['--cases', casesPath, '--rubric', rubricPath, '--out', outPath], {
      env: {}, fetchImpl: () => assert.fail('must not call'),
    });
    assert.equal(report.hashes.input, loaded.hashes.input);
    assert.equal(JSON.parse(await readFile(outPath, 'utf8')).mode, 'dry_run');
    await assert.rejects(runCli(['--cases', casesPath, '--rubric', rubricPath, '--out', outPath, '--live'], {
      env: { AI_GATEWAY_API_KEY: 'mock' }, fetchImpl: () => assert.fail('must not call'),
    }), /output_write_error/);
    assert.equal(JSON.parse(await readFile(outPath, 'utf8')).mode, 'dry_run');
    await assert.rejects(loadTrial(casesPath, casesPath));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('input size bound blocks oversized files before JSON decoding', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'jev-eval-'));
  try {
    const casesPath = join(directory, 'cases.json');
    const rubricPath = join(directory, 'rubric.json');
    await writeFile(casesPath, 'x'.repeat(1_048_577));
    await writeFile(rubricPath, JSON.stringify(rubric));
    await assert.rejects(loadTrial(casesPath, rubricPath), /input_too_large/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('framework loader binds the entire contract and judges its nested rubric only', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'jev-framework-'));
  try {
    const casesPath = join(directory, 'cases.json');
    const rubricPath = join(directory, 'framework.json');
    await writeFile(casesPath, JSON.stringify(cases));
    const framework = { schema: 'factory.judge-framework.v1', version: '1.0.0',
      rubric, evaluation_protocol: { admission: 'Explicit independent approval' } };
    await writeFile(rubricPath, JSON.stringify(framework));
    const first = await loadTrial(casesPath, rubricPath);
    assert.deepEqual(first.rubric, rubric);
    const report = await runCli(['--cases', casesPath, '--rubric', rubricPath], { env: {} });
    assert.equal(report.framework.schema, framework.schema);
    assert.equal(report.framework.full_protocol_executed, false);
    framework.evaluation_protocol.admission = 'Updated reviewed requirement';
    await writeFile(rubricPath, JSON.stringify(framework));
    const second = await loadTrial(casesPath, rubricPath);
    assert.notEqual(first.hashes.rubric, second.hashes.rubric);
    for (const invalid of [ { ...framework, version: '' }, { ...framework, schema: 'other.schema' } ]) {
      await writeFile(rubricPath, JSON.stringify(invalid));
      await assert.rejects(loadTrial(casesPath, rubricPath), /invalid_framework/);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
