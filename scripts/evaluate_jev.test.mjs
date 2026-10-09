import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
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
    casesPath: 'cases.json', rubricPath: 'rubric.json', live: false,
  });
  assert.throws(() => parseArgs(['--endpoint', 'https://attacker.test']), /invalid_arguments/);
  assert.throws(() => parseArgs(['--live']), /invalid_arguments/);
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
