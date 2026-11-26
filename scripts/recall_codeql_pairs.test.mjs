import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { caseDigest, sha256, sortKeys } from './recall_harness.mjs';
import { scoreCodeqlPairs } from './recall_codeql_pairs.mjs';

function stagedPair(t, archivePrefix = 'src') {
  const root = mkdtempSync(join(tmpdir(), 'cf-codeql-pair-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (path, bytes) => {
    writeFileSync(join(root, path), bytes);
    return { path, sha256: sha256(bytes) };
  };
  const json = (path, value) => write(path, JSON.stringify(value));
  const row = { ghsa: 'GHSA-2222-3333-4444', repository: 'example/project', ecosystem: 'PyPI',
    fix: 'b'.repeat(40), cwes: ['CWE-89'] };
  const manifest = json('manifest.json', { cases: [row], cases_sha256: caseDigest([row]) });
  const diff = write('diff.patch', 'diff --git a/sample.py b/sample.py\n--- a/sample.py\n+++ b/sample.py\n@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 2\n');
  const changes = write('changes.z', 'M\0sample.py\0');
  const source = { old: 'VALUE = 1\n', fixed: 'VALUE = 2\n' };
  const revisions = { old: 'a'.repeat(40), fixed: row.fix };
  const source_packets = Object.fromEntries(Object.entries(source).map(([side, bytes]) => [
    side, [{ path: 'sample.py', bytes: bytes.length, sha256: sha256(bytes) }],
  ]));
  const binding = { ghsa: row.ghsa, revisions, source_packets, diff_sha256: diff.sha256, changed_files_sha256: changes.sha256 };
  const prepared = json('case.json', { ...binding, status: 'ready', case_sha256: caseDigest([row]) });
  const inputSha256 = sha256(JSON.stringify(sortKeys(binding)));
  const reference = json('reference.json', { schema: 'factory.recall-exposed-run-readback.v1',
    manifest_sha256: manifest.sha256, manifest_cases_sha256: caseDigest([row]),
    candidate: { registered: 1, hunk_hits: 0 }, cases: [{ advisory: row.ghsa, after: 'miss',
      input_sha256: inputSha256 }] });
  const id = 'test/fixture.scope.detail';
  const query = write('query.ql', '/**\n * @id ' + id + '\n * @tags external/cwe/cwe-089\n */\n');
  const zip = spawnSync(process.env.CF_RECALL_PYTHON ?? 'python', ['-I', '-c',
    'import json, sys, zipfile\nfor side, text in json.load(sys.stdin).items():\n with zipfile.ZipFile(side + ".zip", "w") as a:\n  a.writestr(sys.argv[1] + "/sample.py", text)\n  a.writestr(sys.argv[1] + "/helper.py", "VALUE = 0\\n")',
    archivePrefix],
  { cwd: root, input: JSON.stringify(source), encoding: 'utf8', windowsHide: true });
  assert.equal(zip.status, 0, zip.stderr ?? zip.error?.message);
  const capture = (side, invocations = [{ executionSuccessful: true }], located = true) => {
    const results = side === 'old' ? [{ ruleId: id, locations: located ? [
      { physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1 } } },
    ] : [] }] : [];
    const sarif = json(side + '.sarif', { version: '2.1.0', runs: [{ tool: { driver: { name: 'CodeQL',
      semanticVersion: '2.27.1', rules: [{ id, properties: { tags: ['external/cwe/cwe-089'] } }] } }, results, invocations }] });
    const observation = json(side + '.json', { case: row.ghsa, side, query: id, revision: revisions[side],
      query_sha256: query.sha256, native_sha256: sarif.sha256, reported_alerts: results.length });
    const path = side + '.zip';
    return { sarif, observation, archive: { path, sha256: sha256(readFileSync(join(root, path))) }, archive_prefix: archivePrefix };
  };
  const value = { schema: 'factory.recall-codeql-pairs.v1', engine_version: '2.27.1', manifest, reference,
    cases: [{ advisory: row.ghsa, prepared, query, query_id: id, old: capture('old'), fixed: capture('fixed') }] };
  return { root, row, value, capture, binding, inputSha256, json, write,
    run: (input, pattern) => scoreCodeqlPairs(join(root, json('bundle.json', input).path), pattern) };
}

test('paired CodeQL scoring requires both revisions and verifies actual source archive bytes', t => {
  const { value, capture, inputSha256, run } = stagedPair(t);
  const receipt = run(value);
  assert.equal(receipt.scope, 'supplemental');
  assert.equal(receipt.reference_hunk_hits, 0);
  assert.equal(receipt.scored_pairs, 1);
  assert.equal(receipt.strict_hits_on_reference_misses, 1);
  assert.equal(receipt.deleted_line_hits, 1);
  assert.equal(receipt.fixed_hunk_residuals, 0);
  assert.equal(receipt.cases[0].input_sha256, inputSha256);
  assert.deepEqual(receipt.cases[0].hunk_matches, [['test/fixture.scope.detail', 'sample.py', 1]]);
  const pair = value.cases[0];
  const withPair = changed => ({ ...value, cases: [{ ...pair, ...changed }] });
  assert.throws(() => run(withPair({ old: pair.fixed })), /Native case or revision differs/);
  assert.throws(() => run(withPair({ old: { ...pair.old, archive: pair.fixed.archive } })), /Source archive packet bytes differ/);
  assert.throws(() => run(withPair({ old: { ...pair.old, archive_prefix: 'other' } })), /Source archive entry is missing/);
  assert.throws(() => run({ ...value, cases: [pair, pair] }), /Duplicate CodeQL advisory pair/);
  assert.throws(() => run({ ...value, manifest: { ...value.manifest, path: '../manifest.json' } }), /leaves the work directory/);
  assert.throws(() => run(withPair({ old: capture('old', []) })), /Unqualified CodeQL report/);
  assert.throws(() => run(withPair({ old: capture('old', [{ executionSuccessful: true,
    toolExecutionNotifications: [{ level: 'error' }] }]) })), /Unqualified CodeQL report/);
  assert.throws(() => run(withPair({ old: capture('old', undefined, false) })), /Native alert location is missing/);
});

test('CodeQL uses the same source-root resolution for indexed endpoints and trace steps', t => {
  const { root, value, json, run } = stagedPair(t, 'D_/workspace archive/src');
  const pair = value.cases[0];
  const raw = JSON.parse(readFileSync(join(root, pair.old.sarif.path), 'utf8'));
  const observation = JSON.parse(readFileSync(join(root, pair.old.observation.path), 'utf8'));
  const native = raw.runs[0];
  native.originalUriBaseIds = { '%SRCROOT%': { uri: 'file:///src/' } };
  native.artifacts = [{ location: { uri: 'file:///src/sample.py' } }];
  const result = native.results[0];
  const physical = result.locations[0].physicalLocation;
  physical.artifactLocation = { index: 0 };
  const review = () => {
    const sarif = json('locations.sarif', raw);
    const observed = json('locations.json', { ...observation, native_sha256: sarif.sha256 });
    return run({ ...value, cases: [{ ...pair, old: { ...pair.old, sarif, observation: observed } }] }).cases[0];
  };
  const direct = review();
  assert.equal(direct.hunk_hit, true);
  assert.equal(direct.fingerprints.old.archive_sha256, pair.old.archive.sha256);
  assert.equal(direct.fingerprints.fixed.sarif_sha256, pair.fixed.sarif.sha256);
  native.originalUriBaseIds['%SRCROOT%'].uri = 'file:///D:/workspace%20archive/src/';
  native.artifacts[0].location.uri = 'file:///D:/workspace%20archive/src/sample.py';
  assert.equal(review().hunk_hit, true);
  physical.artifactLocation = { uri: 'd:\\workspace archive\\src\\sample.py', index: 0 };
  assert.equal(review().hunk_hit, true);
  physical.artifactLocation = { uri: 'sample.py', uriBaseId: '%SRCROOT%', index: 0 };
  physical.region.startLine = 4;
  const step = (artifactLocation, startLine) => ({ location: { physicalLocation: {
    artifactLocation, region: { startLine },
  } } });
  result.codeFlows = [{ threadFlows: [{ locations: [
    step({ index: 0 }, 1), step({ uri: 'helper.py' }, 1), step({ uri: 'missing.py' }, 1),
    step({ uri: 'helper.py' }, 0), { location: { logicalLocations: [{ name: 'fixture' }] } },
  ] }] }];
  const traced = review();
  assert.equal(traced.hunk_hit, false);
  assert.equal(traced.trace_hit, true);
  assert.equal(traced.file_hit, true);
  assert.equal(traced.fingerprints.old.packet_list_sha256, direct.fingerprints.old.packet_list_sha256);
  assert.notEqual(traced.fingerprints.old.sarif_sha256, direct.fingerprints.old.sarif_sha256);
  assert.notEqual(traced.fingerprints.old.location_trace_sha256, direct.fingerprints.old.location_trace_sha256);
  assert.notEqual(traced.fingerprints.old.flow_trace_sha256, direct.fingerprints.old.flow_trace_sha256);
  assert.notEqual(traced.fingerprints.old.trace_sources_sha256, direct.fingerprints.old.trace_sources_sha256);
  assert.deepEqual(traced.fingerprints.old.trace_source_states, { archive_verified: 1, missing: 1, packet_verified: 1 });
  assert.equal(traced.fingerprints.old.trace_steps, 5);
  assert.equal(traced.fingerprints.old.nonphysical_trace_steps, 1);
  assert.equal(traced.fingerprints.old.invalid_trace_steps, 1);
  assert.equal(traced.fingerprints.old.traced_findings, 1);
  assert.deepEqual(traced.fingerprints.fixed, direct.fingerprints.fixed);
  physical.artifactLocation.uri = 'other.py';
  assert.throws(review, /inline and indexed artifacts disagree/);
  physical.artifactLocation = { index: 1 };
  assert.throws(review, /artifact index is absent/);
  physical.artifactLocation = { uri: 'file:///other/sample.py' };
  assert.throws(review, /Untrusted native source root/);
  physical.artifactLocation = { uri: 'file:///D:/workspace%20archive/src-sibling/sample.py' };
  assert.throws(review, /Untrusted native source root/);
  physical.artifactLocation = { uri: 'file:///src/%2e%2e/sample.py' };
  assert.throws(review, /Invalid native source path/);
  physical.artifactLocation = { uri: 'file:///src/sub%5Csample.py' };
  assert.throws(review, /Invalid native source path/);
});

test('cross-file evidence requires one ordered, archive-verified thread to the reported sink', t => {
  const { root, value, json, run } = stagedPair(t);
  const pair = value.cases[0];
  const position = (uri, startLine = 1) => ({ physicalLocation: { artifactLocation: { uri }, region: { startLine } } });
  const finding = (...threads) => ({ ruleId: pair.query_id, locations: [position('helper.py')],
    codeFlows: [{ threadFlows: threads.map(thread => ({ locations: thread.map(location => ({ location })) })) }] });
  const captured = (side, results) => {
    const capture = pair[side];
    const report = JSON.parse(readFileSync(join(root, capture.sarif.path), 'utf8'));
    const binding = JSON.parse(readFileSync(join(root, capture.observation.path), 'utf8'));
    report.runs[0].results = results;
    const sarif = json(side + '.cross-file.sarif', report);
    const observation = json(side + '.cross-file.json', { ...binding, native_sha256: sarif.sha256,
      reported_alerts: results.length });
    return { ...capture, sarif, observation };
  };
  const score = (old, fixed = []) => run({ ...value, cases: [{ ...pair,
    old: captured('old', [old]), fixed: captured('fixed', fixed) }] });
  const anchor = position('sample.py');
  const sink = position('helper.py');
  const receipt = score(finding([anchor, sink]));
  assert.equal(receipt.strict_hunk_hits, 0);
  assert.equal(receipt.changed_file_hits, 0);
  assert.equal(receipt.cross_file_trace_hits, 1);
  assert.deepEqual(receipt.cases[0].cross_file_trace_matches, [{
    rule: pair.query_id, sink: { path: 'helper.py', line: 1 }, anchor: { path: 'sample.py', line: 1 },
    source_paths: ['helper.py', 'sample.py'], fixed_sink_residual: false,
  }]);
  assert.equal(score(finding([anchor, sink]), [finding()]).cases[0].cross_file_trace_matches[0].fixed_sink_residual, true);
  for (const trace of [finding([anchor], [sink]), finding([sink, anchor]),
    finding([position('sample.py', 2), sink]), finding([anchor, position('missing.py'), sink])]) {
    assert.equal(score(trace).cross_file_trace_hits, 0);
  }
});

test('native and pattern hits join only on identical evidence and are counted once', t => {
  const { root, row, value, binding, json, run } = stagedPair(t);
  const base = { ...row, ...binding, status: 'scored', outcome: 'miss', hunk_hit: false, file_hit: false, hunk_findings: [],
    file_coverage: { fixed: binding.source_packets.fixed.map(packet => ({
      ...packet, submitted: true, state: 'reported_scanned', reason: 'engine_scan_paths',
    })) }, fix_side_residual: [] };
  const score = (candidate, summary = {}) => {
    const pins = json('pattern-score.json', {
      schema: 'factory.recall-result.v1', scope: 'ecosystem', manifest_sha256: value.manifest.sha256,
      manifest_cases_sha256: caseDigest([row]), ruleset_sha256: 'c'.repeat(64), profile_sha256: 'd'.repeat(64),
      engine: { executable_sha256: 'e'.repeat(64) },
      summary: { cases: 1, hunk_hits: Number(candidate.hunk_hit), file_hits: Number(candidate.file_hit), ...summary },
      cases: [candidate],
    });
    return { ...pins, path: join(root, pins.path) };
  };
  const joined = (candidate, bundle = value) => run(bundle, score(candidate)).pattern_join;
  const detected = joined(base);
  assert.equal(detected.eligible_native_additions, 1);
  assert.equal(detected.observed_union_hunk_hits, 1);
  assert.equal(detected.observed_union_file_hits, 1);
  const found = joined({ ...base, outcome: 'hit', hunk_hit: true, file_hit: true,
    hunk_findings: [['test/rule', 'sample.py', 1]] });
  assert.equal(found.cases[0].disposition, 'overlap');
  assert.equal(found.combined_hunk_hits, 1);
  assert.equal(found.observed_union_file_hits, 1);
  assert.equal(found.eligible_native_additions, 0);
  assert.equal(joined({ ...base, fix_side_residual: [['test/rule', 'sample.py', 1]] }).cases[0].disposition,
    'fixed_side_residual');
  assert.equal(joined({ ...base, file_coverage: { fixed: [] } }).cases[0].disposition, 'fixed_coverage_unresolved');
  const [fixed] = base.file_coverage.fixed;
  assert.equal(joined({ ...base, file_coverage: { fixed: [fixed, fixed] } }).cases[0].disposition,
    'fixed_coverage_unresolved');
  assert.throws(() => joined({ ...base, diff_sha256: '0'.repeat(64) }), /Pattern case input differs/);
  assert.throws(() => run(value, { ...score(base), sha256: '0'.repeat(64) }), /Pattern score digest mismatch/);
  assert.throws(() => run(value, score(base, { file_hits: 1 })), /Pattern hit count differs/);

  const pair = value.cases[0];
  const nativeReport = JSON.parse(readFileSync(join(root, pair.old.sarif.path), 'utf8'));
  nativeReport.runs[0].results[0].locations[0].physicalLocation.region.startLine = 4;
  const sarif = json('file-only.sarif', nativeReport);
  const originalObservation = JSON.parse(readFileSync(join(root, pair.old.observation.path), 'utf8'));
  const observation = json('file-only.json', { ...originalObservation, native_sha256: sarif.sha256 });
  const fileOnly = { ...value, cases: [{ ...pair, old: { ...pair.old, sarif, observation } }] };
  const fileMatch = joined(base, fileOnly);
  assert.equal(fileMatch.observed_union_hunk_hits, 0);
  assert.equal(fileMatch.observed_union_file_hits, 1);
  assert.equal(fileMatch.eligible_native_additions, 0);
  assert.equal(joined({ ...base, file_hit: true }, fileOnly).observed_union_file_hits, 1);

  const result = nativeReport.runs[0].results[0];
  result.locations[0].physicalLocation.region.startLine = 1;
  result.codeFlows = [{ threadFlows: [{ locations: [{ location: { physicalLocation: {
    artifactLocation: { uri: 'missing.py' }, region: { startLine: 1 },
  } } }] }] }];
  const missingSarif = json('missing-source.sarif', nativeReport);
  const missingObservation = json('missing-source.json', { ...originalObservation, native_sha256: missingSarif.sha256 });
  const missingSource = { ...value, cases: [{ ...pair, old: {
    ...pair.old, sarif: missingSarif, observation: missingObservation,
  } }] };
  const unresolved = joined(base, missingSource);
  assert.equal(unresolved.observed_union_hunk_hits, 1);
  assert.equal(unresolved.eligible_native_additions, 0);
  assert.equal(unresolved.cases[0].disposition, 'native_trace_source_unresolved');
});

test('registered CodeQL plans reconcile the exact query set and keep absent cases visible', t => {
  const { root, row, value, binding, inputSha256, json, write, run } = stagedPair(t);
  const pair = value.cases[0];
  const unobserved = { ...row, ghsa: 'GHSA-3333-4444-5555', cwes: ['CWE-295'] };
  const unsupported = { ...row, ghsa: 'GHSA-4444-5555-6666', ecosystem: 'npm' };
  const alias = { ...row, ghsa: 'GHSA-5555-6666-7777' };
  const divergent = { ...row, ghsa: 'GHSA-6666-7777-8888' };
  const reuse = (registration, packets = binding.source_packets) => {
    const input = { ...binding, ghsa: registration.ghsa, source_packets: packets };
    const prepared = json(registration.ghsa + '.json',
      { ...input, status: 'ready', case_sha256: caseDigest([registration]) });
    return { observation: { advisory: registration.ghsa, after: 'miss', input_sha256: sha256(JSON.stringify(sortKeys(input))) },
      row: { advisory: registration.ghsa, prepared, capture_reused_from: row.ghsa } };
  };
  const linked = reuse(alias);
  const wrongFamily = reuse(unobserved);
  const wrongSource = reuse(divergent, { ...binding.source_packets,
    old: [{ ...binding.source_packets.old[0], sha256: 'f'.repeat(64) }] });
  const cases = [row, unobserved, unsupported, alias, divergent];
  const manifest = json('registry.json', { cases, cases_sha256: caseDigest(cases) });
  const previous = JSON.parse(readFileSync(join(root, value.reference.path), 'utf8'));
  const reference = json('registered-reference.json', { ...previous, candidate: { registered: 5, hunk_hits: 0 },
    manifest_sha256: manifest.sha256, manifest_cases_sha256: caseDigest(cases),
    cases: [...previous.cases, { advisory: unsupported.ghsa, after: 'miss' },
      ...[wrongFamily, linked, wrongSource].map(item => item.observation)] });
  const extra = { id: 'test/other-family',
    source: write('extra.ql', '/**\n * @id test/other-family\n * @tags external/cwe/cwe-079\n */\n') };
  const queries = [{ id: pair.query_id, source: pair.query }, extra];
  const plan = json('plan.json', { schema: 'factory.recall-codeql-plan.v1', engine_version: value.engine_version,
    manifest_sha256: manifest.sha256, reference_sha256: reference.sha256, policies: [{ ecosystem: 'PyPI', queries }],
    advisory_schedule: [row, unobserved, alias, divergent].map(item => item.ghsa) });
  const queries_sha256 = caseDigest(queries.map(({ id, source }) => ({ id, sha256: source.sha256 })));
  const capture = (side, complete = true) => {
    const raw = JSON.parse(readFileSync(join(root, pair[side].sarif.path), 'utf8'));
    const run = raw.runs[0];
    if (complete) {
      run.tool.driver.rules.push({ id: extra.id, properties: { tags: ['external/cwe/cwe-079'] } });
      if (side === 'fixed') run.results = [{ ruleId: extra.id, locations: [
        { physicalLocation: { artifactLocation: { uri: 'sample.py' }, region: { startLine: 1 } } },
      ] }];
    }
    const sarif = json('plan-' + side + '.sarif', raw);
    const prior = JSON.parse(readFileSync(join(root, pair[side].observation.path), 'utf8'));
    const observation = json('plan-' + side + '.json', { ...prior, plan_sha256: plan.sha256,
      queries_sha256, native_sha256: sarif.sha256, reported_alerts: run.results.length });
    return { ...pair[side], sarif, observation };
  };
  const bundle = { ...value, schema: 'factory.recall-codeql-pairs.v2', manifest, reference, plan,
    cases: [{ ...pair, old: capture('old'), fixed: capture('fixed') }] };
  const scored = run(bundle);
  assert.equal(scored.scope, 'registered-codeql-plan');
  assert.equal(scored.planned_cases, 4);
  assert.deepEqual(scored.unobserved_advisories, [unobserved.ghsa, alias.ghsa, divergent.ghsa]);
  assert.deepEqual(scored.unsupported_advisories, [unsupported.ghsa]);
  assert.deepEqual(scored.uncovered_advisory_families, [{ advisory: unobserved.ghsa, families: ['tls'] }]);
  assert.equal(scored.strict_hunk_hits, 1);
  assert.equal(scored.fixed_hunk_residuals, 0);
  assert.equal(scored.cases[0].native_alerts.fixed, 1);
  assert.equal(scored.cases[0].input_sha256, inputSha256);
  const withReuse = run({ ...bundle, cases: [linked.row, ...bundle.cases] });
  assert.equal(withReuse.scored_pairs, 2);
  assert.equal(withReuse.captured_pairs, 1);
  assert.equal(withReuse.reused_capture_pairs, 1);
  assert.equal(withReuse.strict_hunk_hits, 2);
  assert.equal(withReuse.cases[0].capture_reused_from, row.ghsa);
  assert.equal(withReuse.cases[0].input_sha256, linked.observation.input_sha256);
  assert.deepEqual(withReuse.cases[0].fingerprints, withReuse.cases[1].fingerprints);
  for (const item of [{ ...linked.row, old: pair.old }, { ...linked.row, capture_reused_from: alias.ghsa }]) {
    assert.throws(() => run({ ...bundle, cases: [...bundle.cases, item] }), /directly captured pair/);
  }
  assert.throws(() => run({ ...bundle, cases: [...bundle.cases, wrongFamily.row] }), /scored families differ/);
  assert.throws(() => run({ ...bundle, cases: [...bundle.cases, wrongSource.row] }), /source inputs differ/);
  const frozenPlan = JSON.parse(readFileSync(join(root, plan.path), 'utf8'));
  const truncated = json('truncated.json', { ...frozenPlan, advisory_schedule: [row.ghsa] });
  assert.throws(() => run({ ...bundle, plan: truncated }), /schedule omits or adds registered cases/);
  assert.throws(() => run({ ...bundle, cases: [{ ...bundle.cases[0], fixed: capture('fixed', false) }] }),
    /CodeQL query inventory or alert count differs/);
});
