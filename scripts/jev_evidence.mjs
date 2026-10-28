// Candidate-bound evidence validators; no provider or release authority.
import { lstat, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const encode = value => JSON.stringify(value);
const HASH = /^[a-f0-9]{64}$/i;
const REVISION = /^[a-f0-9]{40}$/i;
const SAFE_RELPATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\w./@+-]{1,512}$/;
const SECRET_KEY = /(?:secret|token|password|credential|private[_-]?key|authorization|api[_-]?key|raw[_-]?value)/i;
const SECRET_VALUE = /(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b)/;
const ACTIONABILITY_SLOTS = {
  input_origin: 'known', sink_behavior: 'known', callers: 'resolved',
  trust_boundary: 'known', counterevidence: 'reviewed',
};

/** Bind one isolated validator instance to its required evidence services. */
export function createEvidenceValidators({ requireValue, object, sha, TrialError, readBounded }) {
  const dependencies = { requireValue, object, sha, TrialError, readBounded };
  const EVIDENCE_PROFILES = new Set(['static', 'secrets', 'configuration', 'dependencies', 'runtime', 'fuzz', 'security_actionability']);
  return { EVIDENCE_PROFILES, validateEvidenceReviewCases: validateEvidenceReviewCases.bind(null, dependencies), validateTestOracleCases: validateTestOracleCases.bind(null, dependencies), verifySourceBindings: verifySourceBindings.bind(null, dependencies), validateNoRawSecrets: validateNoRawSecrets.bind(null, dependencies), validateActionabilityState: validateActionabilityState.bind(null, dependencies), actionabilityContextComplete: actionabilityContextComplete.bind(null, dependencies) };
}

function validateBoundArtifact(dependencies, artifact, candidate) {
  const { requireValue, object, sha } = dependencies;
  requireValue(object(artifact) && typeof artifact.kind === 'string'
    && typeof artifact.path === 'string' && SAFE_RELPATH.test(artifact.path) && typeof artifact.content === 'string'
    && HASH.test(artifact.sha256) && artifact.sha256.toLowerCase() === sha(Buffer.from(artifact.content, 'utf8'))
    && artifact.candidate_commit === candidate.commit
    && artifact.candidate_sha256 === candidate.sha256,
  'invalid_review_artifact_binding');
  if (artifact.kind === 'source_excerpt') {
    const bound = artifact.source_binding;
    requireValue(object(bound) && Object.keys(bound).every(key =>
      ['path', 'sha256', 'start_line', 'end_line'].includes(key))
      && SAFE_RELPATH.test(bound.path) && HASH.test(bound.sha256)
      && Number.isInteger(bound.start_line) && bound.start_line > 0
      && Number.isInteger(bound.end_line) && bound.end_line >= bound.start_line,
    'invalid_source_binding');
  } else requireValue(artifact.source_binding === undefined, 'invalid_source_binding');
}

async function readCapturedSource(dependencies, root, descriptor) {
  const { requireValue, object, readBounded, sha, TrialError } = dependencies;
  requireValue(object(descriptor) && typeof descriptor.path === 'string'
    && SAFE_RELPATH.test(descriptor.path) && HASH.test(descriptor.sha256), 'invalid_source_binding');
  let path = await realpath(root);
  try {
    for (const component of descriptor.path.split('/')) {
      requireValue(component && component !== '.', 'source_path_invalid');
      path = resolve(path, component);
      requireValue(!(await lstat(path)).isSymbolicLink(), 'source_path_invalid');
    }
    const suffix = relative(await realpath(root), await realpath(path));
    requireValue(suffix && !isAbsolute(suffix) && suffix !== '..'
      && !suffix.startsWith(`..${sep}`), 'source_path_invalid');
    requireValue((await lstat(path)).size <= 1_000_000, 'source_input_too_large');
    const bytes = await readBounded(path);
    requireValue(bytes.length <= 1_000_000, 'source_input_too_large');
    requireValue(sha(bytes) === descriptor.sha256.toLowerCase(), 'source_binding_stale');
    return bytes;
  } catch (error) { throw error instanceof TrialError ? error : new TrialError('source_read_error'); }
}

async function verifySourceBindings(dependencies, item, root) {
  const { requireValue, TrialError } = dependencies;
  const evidence = item.state?.evidence;
  const excerpts = evidence?.artifacts?.filter(artifact => artifact.kind === 'source_excerpt') ?? [];
  const descriptors = [...(evidence?.dependencies ?? []), ...excerpts.map(artifact => artifact.source_binding)];
  const sources = new Map();
  let total = 0;
  for (const descriptor of descriptors) {
    const previous = sources.get(descriptor.path);
    if (previous) {
      requireValue(previous.sha256 === descriptor.sha256, 'source_binding_conflict');
      continue;
    }
    requireValue(sources.size < 64, 'source_count_exceeded');
    const bytes = await readCapturedSource(dependencies, root, descriptor);
    total += bytes.length;
    requireValue(total <= 32_000_000, 'source_inventory_too_large');
    sources.set(descriptor.path, { sha256: descriptor.sha256, bytes });
  }
  for (const artifact of excerpts) {
    const bound = artifact.source_binding;
    let source;
    try { source = new TextDecoder('utf-8', { fatal: true }).decode(sources.get(bound.path).bytes); }
    catch { throw new TrialError('source_encoding_invalid'); }
    const lines = source.match(/[^\n]*(?:\n|$)/g).filter(line => line.length > 0);
    requireValue(bound.end_line <= lines.length
      && lines.slice(bound.start_line - 1, bound.end_line).join('') === artifact.content,
    'source_excerpt_mismatch');
  }
}

function validateNoRawSecrets(dependencies, value, key = '') {
  const { requireValue, object } = dependencies;
  if (typeof value === 'string') {
    requireValue(!SECRET_VALUE.test(value), 'raw_secret_forbidden');
    requireValue(!SECRET_KEY.test(key), 'raw_secret_field_forbidden');
  } else if (Array.isArray(value)) {
    for (const item of value) validateNoRawSecrets(dependencies, item, key);
  } else if (object(value)) {
    for (const [childKey, child] of Object.entries(value)) {
      requireValue(!SECRET_KEY.test(childKey), 'raw_secret_field_forbidden');
      validateNoRawSecrets(dependencies, child, childKey);
    }
  }
}

function actionabilityContextComplete(dependencies, evidence) {
  const { object } = dependencies;
  const context = evidence.actionability;
  return object(context) && Object.entries(ACTIONABILITY_SLOTS).every(([name, status]) =>
    context[name]?.status === status && context[name].artifacts.some(ref => sourceSpanBound(dependencies, ref, evidence.artifacts)))
    && (!context.unknowns || context.unknowns.length === 0);
}

function sourceSpanBound(dependencies, ref, artifacts) {
  const matches = artifacts.filter(artifact => artifact.path === ref.path && artifact.sha256 === ref.sha256);
  const lines = matches.length === 1 ? matches[0].content.replace(/\r?\n$/, '').split(/\r?\n/) : [];
  const first = matches[0]?.kind === 'source_excerpt' ? matches[0].source_binding.start_line : 1;
  return matches.length === 1 && ['source', 'source_excerpt'].includes(matches[0].kind)
    && Number.isInteger(ref.start_line) && Number.isInteger(ref.end_line)
    && ref.start_line >= first && ref.end_line >= ref.start_line
    && ref.end_line < first + lines.length
    && lines.slice(ref.start_line - first, ref.end_line - first + 1).join('\n').trim().length > 0;
}

function validateActionabilityState(dependencies, state) {
  const { requireValue, object } = dependencies;
  requireValue(Object.keys(state).every(key => ['requirement', 'candidate', 'evidence'].includes(key)),
    'invalid_actionability_state');
  const evidence = state.evidence, context = evidence.actionability;
  requireValue(Object.keys(state.candidate).every(key => ['commit', 'path', 'sha256'].includes(key))
    && Object.keys(evidence).every(key => ['location', 'artifacts', 'actionability', 'dependencies'].includes(key))
    && Object.keys(evidence.location).every(key => ['path', 'start_line', 'end_line'].includes(key))
    && evidence.artifacts.every(artifact => Object.keys(artifact).every(key =>
      ['kind', 'path', 'content', 'sha256', 'candidate_commit', 'candidate_sha256', 'source_binding'].includes(key))),
  'invalid_actionability_fields');
  requireValue(evidence.dependencies === undefined || (Array.isArray(evidence.dependencies)
    && evidence.dependencies.length <= 64 && evidence.dependencies.every(dependency => object(dependency)
      && Object.keys(dependency).length === 2 && SAFE_RELPATH.test(dependency.path) && HASH.test(dependency.sha256))),
  'invalid_source_dependencies');
  validateOutboundStrings(dependencies, state);
  validateRetrievalTransport(dependencies, state);
  if (context === undefined) return; // Missing semantic context abstains locally.
  requireValue(object(context) && Object.keys(context).every(key => Object.hasOwn(ACTIONABILITY_SLOTS, key) || key === 'unknowns')
    && (context.unknowns === undefined || (Array.isArray(context.unknowns) && context.unknowns.length <= 32
      && context.unknowns.every(value => typeof value === 'string' && value.length > 0 && value.length <= 1024))),
    'invalid_actionability_context');
  for (const [slot, known] of Object.entries(ACTIONABILITY_SLOTS)) {
    const value = context[slot];
    if (value === undefined) continue;
    requireValue(object(value) && Object.keys(value).every(key => ['status', 'artifacts'].includes(key))
      && [known, 'unknown'].includes(value.status) && Array.isArray(value.artifacts) && value.artifacts.length <= 32,
    'invalid_actionability_slot');
    for (const ref of value.artifacts) requireValue(object(ref)
      && Object.keys(ref).every(key => ['path', 'sha256', 'start_line', 'end_line'].includes(key))
      && evidence.artifacts.some(artifact => artifact.path === ref.path && artifact.sha256 === ref.sha256)
      && ((ref.start_line === undefined && ref.end_line === undefined) || sourceSpanBound(dependencies, ref, evidence.artifacts)),
    'invalid_actionability_reference');
  }
}

function validateRetrievalTransport({ requireValue, object, sha }, state) {
  for (const artifact of state.evidence.artifacts.filter(row => row.kind === 'native_sink_evidence')) {
    let ledger;
    try { ledger = JSON.parse(artifact.content); } catch { requireValue(false, 'invalid_native_sink_ledger'); }
    const record = ledger?.retrieval;
    requireValue(object(record) && record.schema === 'factory.retrieval-transport.v1'
      && ['NOT_RUN', 'DELIVERED_UNVALIDATED'].includes(record.status)
      && record.authority === 'none' && record.classification_effect === 'NONE'
      && record.consumption === 'UNASSESSED' && record.validated_trace_edges === 0
      && record.coverage === 'RANKED_SUBSET_NOT_EXHAUSTIVE'
      && HASH.test(record.finding_sha256) && HASH.test(record.source_manifest_sha256)
      && record.query_sha256 === sha(state.requirement)
      && Array.isArray(record.hint_manifest) && record.hint_manifest.length <= 8
      && record.delivered_hints === record.hint_manifest.length,
    'invalid_retrieval_transport');
    requireValue(record.status !== 'NOT_RUN' || record.delivered_hints === 0, 'invalid_retrieval_not_run');
    for (const hint of record.hint_manifest) requireValue(object(hint)
      && SAFE_RELPATH.test(hint.path) && HASH.test(hint.sha256) && HASH.test(hint.content_sha256)
      && Number.isInteger(hint.start_line) && Number.isInteger(hint.end_line)
      && hint.start_line > 0 && hint.end_line >= hint.start_line
      && state.evidence.dependencies?.some(row => row.path === hint.path && row.sha256 === hint.sha256)
      && state.evidence.artifacts.some(row => row.kind === 'source_excerpt'
        && row.path === hint.path && row.sha256 === hint.content_sha256
        && row.source_binding?.sha256 === hint.sha256
        && row.source_binding?.start_line === hint.start_line && row.source_binding?.end_line === hint.end_line),
    'retrieval_hint_not_delivered');
  }
}

function validateOutboundStrings(dependencies, value) {
  const { requireValue, object } = dependencies;
  if (typeof value === 'string') requireValue(!SECRET_VALUE.test(value), 'raw_secret_forbidden');
  else if (Array.isArray(value)) value.forEach(item => validateOutboundStrings(dependencies, item));
  else if (object(value)) Object.values(value).forEach(item => validateOutboundStrings(dependencies, item));
}

function validateEvidenceReviewCases(dependencies, cases, profile) {
  const { requireValue, object, TrialError } = dependencies;
  for (const item of cases) {
    const state = item.state;
    const candidate = state?.candidate;
    const evidence = state?.evidence;
    requireValue(object(state) && typeof state.requirement === 'string' && state.requirement.trim().length > 0
      && Buffer.byteLength(state.requirement) <= 8192 && object(candidate) && object(evidence)
      && REVISION.test(candidate.commit) && typeof candidate.path === 'string' && SAFE_RELPATH.test(candidate.path)
      && HASH.test(candidate.sha256) && Array.isArray(evidence.artifacts)
      && evidence.artifacts.length > 0 && evidence.artifacts.length <= 32,
    'invalid_review_candidate_binding');
    for (const artifact of evidence.artifacts) validateBoundArtifact(dependencies, artifact, candidate);
    const kinds = new Set(evidence.artifacts.map((artifact) => artifact.kind));
    const location = evidence.location;
    const validLocation = location => object(location) && typeof location.path === 'string'
      && SAFE_RELPATH.test(location.path) && Number.isInteger(location.start_line) && location.start_line > 0
      && Number.isInteger(location.end_line) && location.end_line >= location.start_line;
    if (profile === 'static' || profile === 'security_actionability') {
      requireValue(evidence.artifacts.some((artifact) => artifact.path === candidate.path
        && ((artifact.kind === 'source' && artifact.sha256.toLowerCase() === candidate.sha256.toLowerCase())
          || (profile === 'security_actionability' && artifact.kind === 'source_excerpt'
            && artifact.source_binding.sha256.toLowerCase() === candidate.sha256.toLowerCase())))
        && validLocation(location) && location.path === candidate.path,
      'missing_static_source');
      if (profile === 'security_actionability') validateActionabilityState(dependencies, state);
    } else if (profile === 'secrets') {
      requireValue(['secret_pattern_detected', 'credential_exposure_metadata', 'redacted_secret_finding']
        .includes(state.requirement), 'invalid_secret_criterion');
      requireValue(evidence.artifacts.length === 1 && evidence.artifacts[0].kind === 'redacted_report'
        && evidence.artifacts[0].path === candidate.path && evidence.artifacts[0].sha256.toLowerCase() === candidate.sha256.toLowerCase(),
      'invalid_redacted_report');
      requireValue(Object.keys(state).every((key) => ['requirement', 'candidate', 'evidence'].includes(key))
        && Object.keys(evidence).every((key) => key === 'artifacts'), 'raw_secret_field_forbidden');
      let report;
      try { report = JSON.parse(evidence.artifacts[0].content); }
      catch { throw new TrialError('invalid_redacted_report'); }
      requireValue(object(report) && report.schema === 'factory.jev-redacted-secret-report.v1'
        && Array.isArray(report.features) && report.features.length > 0 && report.features.length <= 256
        && Object.keys(report).every((key) => ['schema', 'features'].includes(key)), 'invalid_redacted_report');
      for (const feature of report.features) {
        requireValue(object(feature) && Object.keys(feature).every((key) =>
          ['kind', 'location', 'fingerprint', 'entropy_bucket', 'context_redacted'].includes(key))
          && ['high_entropy', 'credential_assignment', 'key_material', 'known_token_pattern'].includes(feature.kind)
          && typeof feature.location === 'string' && /^[\w./@+-]{1,512}(?::\d+)?$/.test(feature.location)
          && typeof feature.fingerprint === 'string' && /^[a-f0-9]{8,64}$/i.test(feature.fingerprint)
          && (feature.entropy_bucket === undefined || ['low', 'medium', 'high'].includes(feature.entropy_bucket))
          && (feature.context_redacted === undefined || feature.context_redacted === true), 'raw_secret_forbidden');
      }
      validateNoRawSecrets(dependencies, state);
    } else if (profile === 'configuration') {
      requireValue(evidence.artifacts.some((artifact) => ['configuration_source', 'configuration_report'].includes(artifact.kind)
        && artifact.path === candidate.path && artifact.sha256.toLowerCase() === candidate.sha256.toLowerCase())
        && validLocation(location) && location.path === candidate.path,
      'missing_configuration_evidence');
    } else if (profile === 'dependencies') {
      const packages = evidence.packages;
      const manifest = evidence.artifacts.find((artifact) => artifact.kind === 'package_manifest');
      let declaredPackages;
      try { declaredPackages = JSON.parse(manifest?.content ?? 'null'); }
      catch { throw new TrialError('invalid_dependency_manifest'); }
      requireValue(Array.isArray(packages) && packages.length > 0 && packages.length <= 256
        && packages.every((pkg) => object(pkg) && typeof pkg.ecosystem === 'string' && /^[\w.-]{1,64}$/.test(pkg.ecosystem)
          && typeof pkg.name === 'string' && /^[\w.@/+:-]{1,256}$/.test(pkg.name)
          && typeof pkg.version === 'string' && /^[\w.+-]{1,128}$/.test(pkg.version))
        && encode(declaredPackages) === encode(packages)
        && evidence.artifacts.some((artifact) => artifact.kind === 'package_manifest'
          && artifact.path === candidate.path && artifact.sha256.toLowerCase() === candidate.sha256.toLowerCase())
        && kinds.has('advisory'), 'missing_dependency_advisory_evidence');
      for (const advisory of evidence.artifacts.filter((artifact) => artifact.kind === 'advisory')) {
        let record;
        try { record = JSON.parse(advisory.content); }
        catch { throw new TrialError('invalid_advisory_evidence'); }
        requireValue(object(record) && typeof (record.advisory_id ?? record.id) === 'string'
          && (record.advisory_id ?? record.id).trim().length > 0
          && Object.keys(record).every((key) => ['advisory_id', 'id', 'source', 'details'].includes(key)),
        'invalid_advisory_evidence');
      }
    } else {
      const execution = evidence.execution;
      const trace = evidence.artifacts.find((artifact) => artifact.kind === 'trace');
      let traceRecord;
      try { traceRecord = JSON.parse(trace?.content ?? 'null'); }
      catch { throw new TrialError('invalid_execution_trace'); }
      requireValue(object(execution) && typeof execution.command === 'string' && execution.command.trim().length > 0
        && Buffer.byteLength(execution.command) <= 8192 && typeof execution.engine === 'string'
        && /^[\w .@/+:-]{1,128}$/.test(execution.engine)
        && ((Number.isInteger(execution.exit_code) && execution.exit_code >= -1 && execution.exit_code <= 255)
          || execution.timed_out === true)
        && (execution.timed_out === undefined || typeof execution.timed_out === 'boolean')
        && kinds.has('trace') && evidence.artifacts.some((artifact) => artifact.kind === 'source'
          && artifact.path === candidate.path && artifact.sha256.toLowerCase() === candidate.sha256.toLowerCase())
        && object(traceRecord) && traceRecord.schema === 'factory.jev-execution-trace.v1'
        && traceRecord.command === execution.command && traceRecord.engine === execution.engine
        && traceRecord.exit_code === execution.exit_code && traceRecord.timed_out === execution.timed_out
        && traceRecord.candidate_commit === candidate.commit && traceRecord.candidate_sha256 === candidate.sha256
        && typeof traceRecord.trace === 'string' && traceRecord.trace.length > 0,
      profile === 'runtime' ? 'missing_runtime_execution_evidence' : 'missing_fuzz_execution_evidence');
    }
  }
}

function validateTestOracleCases(dependencies, cases) {
  const { requireValue, object, sha } = dependencies;
  for (const item of cases) {
    const candidate = item.state?.candidate;
    const source = item.state?.evidence?.source;
    requireValue(object(item.state) && object(candidate) && object(item.state.evidence)
      && typeof candidate.commit === 'string' && /^[a-f0-9]{40}$/i.test(candidate.commit)
      && typeof candidate.path === 'string' && candidate.path.trim().length > 0
      && typeof source === 'string' && source.length > 0
      && typeof candidate.excerpt_sha256 === 'string' && /^[a-f0-9]{64}$/i.test(candidate.excerpt_sha256)
      && candidate.excerpt_sha256.toLowerCase() === sha(Buffer.from(source, 'utf8')),
    'invalid_test_oracle_evidence_binding');
    const selected = item.state.evidence.selected_test;
    if (selected !== undefined) {
      const firstLine = item.state.evidence.source_start_line ?? 1;
      const lines = source.split(/\r?\n/);
      if (lines.at(-1) === '') lines.pop();
      requireValue(object(selected) && typeof selected.name === 'string'
        && /^[A-Za-z_]\w*$/.test(selected.name)
        && Number.isInteger(firstLine) && firstLine > 0
        && Number.isInteger(selected.start_line) && selected.start_line >= firstLine
        && Number.isInteger(selected.end_line) && selected.end_line >= selected.start_line
        && selected.end_line < firstLine + lines.length,
      'invalid_test_oracle_target_binding');
      requireValue(new RegExp(`^\\s*(?:async\\s+)?def\\s+${selected.name}\\s*\\(`)
        .test(lines[selected.start_line - firstLine]), 'invalid_test_oracle_target_binding');
    }
  }
}
