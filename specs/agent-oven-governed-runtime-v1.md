# Spec: agent-oven-governed-runtime-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall provide a governed agent-composition and execution layer informed by Perplexity Agent API, Mastra Agent Builder, and MANTRA compliance research. The layer shall preserve Agent Oven's Convex control plane, BYOK isolation, hard budgets, human authority, and hosted-worker boundary.

### User roles

- Workspace admins publish frozen or managed runtime presets and database-operation policies.
- Workspace operators launch, inspect, suspend, and resume bounded runs.
- Trusted workers report redacted progress, findings, usage, artifacts, component scores, and trace paths.

### Requirements (EARS)

- The system shall store `GOVERNED_RUNTIME_PRESET` records with a frozen or managed update channel, exact step and token ceilings, allowlisted models, tools, and workflows, structured source filters, a rubric version, and draft or published state.
- When an admin publishes a preset, the system shall return `GOVERNED_PRESET_PUBLISHED`, store an immutable version digest, and copy the version and digest into every newly enqueued job.
- When a preset requires clarification, the system shall store one required `CLARIFICATION_GATE` question at enqueue and reject worker claim with `E_CLARIFICATION_REQUIRED` while `clarificationAnswered` is false.
- When a worker submits one progress event, the system shall append exactly one `RUN_PROGRESS_RECORDED` record whose phase is plan, gather, sufficiency, synthesize, act, validate, or complete, plus redacted findings and contradiction markers.
- When a worker reports usage within the published preset, the system shall store `EXACT_USAGE_RECORDED` with provider, model, integer cached, input, output, and reasoning token counts, direct provider cost in integer micros, latency in integer milliseconds, and integer tool-step count.
- When a worker produces an outcome, the system shall store `DURABLE_ARTIFACT_RECORDED` as an opaque object reference plus digest, media type, and editability flag.
- The system shall persist `RUN_SNAPSHOT_SUSPENDED` state with the executed step path, current step, output references, resume digest, and reason, and shall resume only after an authorized operator supplies the matching digest.
- The system shall record `COMPONENT_SCORE_RECORDED` results independently for retrieval, source selection, planning, synthesis, accuracy, completeness, objectivity, citation quality, connector reliability, and compliance.
- The system shall redact `SENSITIVE_TRACE_DATA` before persistence and shall reject raw passwords, API keys, bearer tokens, database credentials, customer email addresses, and customer phone numbers in progress, finding, snapshot, and artifact metadata.
- The system shall compile published `OPS_MANUAL_RULE` records into deterministic required-before, forbidden-after, requires-human-gate, or max-count trace checks; AI-proposed rules shall remain draft until a human publishes them.
- The system shall store `REMOTE_DATABASE_TOOL` connections for PostgreSQL, MySQL, SQL Server, MongoDB, and warehouses using only opaque `endpointRef` and `secretRef` values.
- When an agent requests a published remote database read, the system shall queue `DATABASE_READ_QUEUED` only for an allowlisted view or parameterized operation.
- When an agent requests a remote database write, the system shall store `DATABASE_WRITE_AWAITING_APPROVAL` only for a published stored procedure or parameterized operation and shall require a distinct human reviewer before queueing it.
- If an operation target contains select, insert, update, delete, drop, alter, create, grant, revoke, exec, or call syntax, the system shall return `ARBITRARY_SQL_REJECTED`.
- When a trusted worker returns a result digest for a queued operation, the system shall return `REMOTE_DATABASE_OPERATION_COMPLETED` and mark that operation succeeded.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Admin publishes a frozen governed preset
  Given a draft GOVERNED_RUNTIME_PRESET with allowlisted primitives and bounded tokens
  When an authorized admin publishes it
  Then GOVERNED_PRESET_PUBLISHED contains an immutable version digest
  And CLARIFICATION_GATE returns E_CLARIFICATION_REQUIRED while clarificationAnswered is false

Scenario: Worker produces transparent and resumable evidence
  Given a job pinned to a published preset
  When the worker reports RUN_PROGRESS_RECORDED, EXACT_USAGE_RECORDED, DURABLE_ARTIFACT_RECORDED, and COMPONENT_SCORE_RECORDED
  And suspends with RUN_SNAPSHOT_SUSPENDED
  Then an operator can resume only with the matching resume digest
  And SENSITIVE_TRACE_DATA is absent from every persisted record

Scenario: Remote database writes remain fail-closed
  Given a REMOTE_DATABASE_TOOL connection with a write operation
  When agentGeneratedSql is present or a distinct reviewer is absent
  Then ARBITRARY_SQL_REJECTED or DATABASE_WRITE_AWAITING_APPROVAL is returned before provider work
  And no database operation is marked complete

Scenario: Remote database reads use the allowlist
  Given a published allowlisted view
  When an agent requests that view
  Then DATABASE_READ_QUEUED is returned with no row payload
  And REMOTE_DATABASE_OPERATION_COMPLETED requires resultDigest from the trusted worker

Scenario: Operations manual rules govern traces
  Given a human-published OPS_MANUAL_RULE
  When a worker submits an execution path that violates its predicate
  Then the compliance component fails with the precise rule identifier

Scenario: Trace metadata is sanitized
  Given SENSITIVE_TRACE_DATA contains an email address or credential
  When the trusted worker records a finding
  Then the sensitive value is absent from persisted metadata
```

## SHOULD - Technical and structural

- Persist policy and runtime evidence in Convex; store large payloads externally by opaque reference and digest.
- Keep public routes authenticated and internal worker mutation routes non-public.
- Use deterministic checks for trace rules and structural budgets; allow model scorers only as explicitly labeled heuristic evidence.
- Show novice-friendly presets first and expose advanced filters, scoring, and database controls progressively.
- Govern autonomy as `supervised`; external writes always require an exact approval.

## SHOULD NOT - Implementation details

- Do not log prompts, completions, message bodies, query text, or database rows in trace records.
- Do not silently move a running job from a frozen preset to a newer version.
- Do not permit managed presets for regulated workloads unless the admin explicitly selects that channel.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `clarificationAnswered` is false | return `E_CLARIFICATION_REQUIRED` |
| 2 | `reportedUsage` exceeds `GOVERNED_RUNTIME_PRESET` ceilings | return `E_RUNTIME_PRESET_BUDGET_EXCEEDED` |
| 3 | `SENSITIVE_TRACE_DATA` is detected | redact before persistence |
| 4 | `resumeDigest` mismatches `RUN_SNAPSHOT_SUSPENDED` | return `E_RESUME_DIGEST_MISMATCH` |
| 5 | `distinctReviewerApproved` is false | return `DATABASE_WRITE_AWAITING_APPROVAL` |
| 6 | published `OPS_MANUAL_RULE` fails | record the exact rule identifier and score compliance zero |
