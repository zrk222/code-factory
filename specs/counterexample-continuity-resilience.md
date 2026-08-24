# Spec: counterexample-continuity-resilience
Status: approved
SpecFactor-target: 1.2

## MUST — Functional core

### Description

Code Factory shall add three local, deterministic planning and verification
surfaces which make known failure modes explicit before an agent, reviewer, or
release owner treats a change as ready. The surfaces are advisory unless a
separately approved existing command is run; none may access memory content,
modify source, approve a release, or invoke an external provider.

### User roles

- Developer: supplies explicit requirements, approved proof manifests, and graph lineage.
- Reviewer: independently promotes continuity records and evaluates guardrail applicability.
- Operator: may run an already-approved E2E command through the existing E2E gate.

### Requirements (EARS)

- When a developer supplies `COUNTEREXAMPLE_CASE_COMPLETE` requirement/tag pairs (1 through 128), the system shall emit one deterministic negative case for every supplied pair without inventing commands or source edits.
- When a counterexample plan is verified, the system shall reject a missing, altered, duplicate, or incomplete derived case with `HOLLOW_COUNTEREXAMPLE`.
- When an independently promoted continuity record has matching tenant, purpose, repository scope, and changed-path trigger facts, the system shall emit one `GUARDRAIL_ACTIVE_REDACTED` activation record.
- If continuity record status is draft or expiry, tenant, purpose, or scope facts do not match, the system shall emit `GUARDRAIL_WITHHELD`.
- When a verified graph lineage is supplied, the system shall emit at most 64 `TEMPORAL_RESILIENCE_SCHEDULED` schedules for declared stale-read, duplicate-effect, parallel-write, retry, and checkpoint-replay risks without executing a schedule.
- If a resilience plan is altered or its source lineage hash changes, the system shall fail verification closed with `TEMPORAL_RESILIENCE_SOURCE_STALE`.

## Decision logic

| # | Condition | Outcome |
|---|-----------|---------|
| 1 | `COUNTEREXAMPLE_CASE_COMPLETE` absent | Return `HOLLOW_COUNTEREXAMPLE` |
| 2 | `HOLLOW_COUNTEREXAMPLE` plan marker | Block verification |
| 3 | `GUARDRAIL_ACTIVE_REDACTED` facts match | Emit one redacted active row |
| 4 | `GUARDRAIL_WITHHELD` facts mismatch | Emit one withheld row |
| 5 | `TEMPORAL_RESILIENCE_SCHEDULED` lineage valid | Emit execution-locked schedules |
| 6 | `TEMPORAL_RESILIENCE_SOURCE_STALE` source changed | Fail verification closed |

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Counterexample coverage is complete and tamper evident
  Given two requirements with boundary and authorization risk tags
  When a counterexample plan is compiled and independently verified
  Then every requirement has one negative case per declared tag
  And a deleted case is reported as HOLLOW_COUNTEREXAMPLE

Scenario: A prior lesson becomes an eligible scoped guardrail
  Given a promoted local continuity lesson with a matching scope and purpose
  When a reviewer evaluates changed paths against its guardrail mapping
  Then only matching paths activate the guardrail
  And the record content and summary are not exposed

Scenario: Stateful graph risks receive a bounded resilience plan
  Given a verified graph lineage with a read, parallel writes, and an effect
  When a temporal resilience plan is compiled
  Then it contains deterministic stale-read, parallel-write, and duplicate-effect schedules
  And it records that execution remains locked
```

## SHOULD — Technical/structural

- ADR references: `docs/FACTORY_CONTINUITY.md`, `docs/GRAPH_FORENSICS.md`, `docs/E2E_PROOF_GATE.md`.
- Data model: canonical JSON, SHA-256 sealed plans, source-relative artifact paths, bounded lists.
- API contract: CLI-only `counterexample`, `guardrail`, and `resilience` subcommands plus read-only Graph Ops projection.

## SHOULD NOT — Implementation details

- No LLM, vector database, embeddings, memory body, prompt, transcript, source mutation, process launch, connector, credential, or network integration is introduced.
- No plan authorizes its own execution or promotion.
