# Spec: authoritative-source-control-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall fail closed when a regulated workflow depends on authoritative external data that is unlicensed, unobserved, unavailable, or older than its declared maximum age. External availability is not guaranteed; the control plane shall provide monitored redundant access, explicit degradation, and evidence-bound refusal rather than an "always available" claim.

### User roles

- Workspace admins configure credential-free authoritative source definitions and redundancy requirements.
- Trusted workers resolve endpoint and secret references, perform source checks, and record bounded observations.
- Operators inspect readiness and may run only when every required source group satisfies its declared authoritative minimum.

### Requirements (EARS)

- The system shall return `SOURCE_AUTHORITY_CATEGORY_REGISTRY` containing exactly `primary-law`, `official-regulator`, `official-registry`, `licensed-system-of-record`, and `secondary-corroboration`.
- When an admin submits `AUTHORITATIVE_SOURCE_CONFIGURATION`, the system shall store label, jurisdiction, publisher, source group, authority category, role, canonical HTTPS locator, optional opaque `env:` or `vault:` endpoint and license references, freshness SLO, maximum age, required authoritative count, required-for-runs flag, and canonical configuration digest.
- If `AUTHORITATIVE_SOURCE_REFERENCE` contains a non-HTTPS locator, embedded credentials, secret query parameters, or a reference outside opaque `env:` or `vault:` syntax, the system shall reject configuration with `E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN` before persistence.
- When validating `SOURCE_CONFIGURATION_INPUT_BOUNDS`, the system shall accept a canonical locator of 1 through 500 characters, an opaque reference of 1 through 240 characters, a source key, label, jurisdiction, or group of 1 through 120 characters, a publisher of 1 through 160 characters, and a content digest of 1 through 160 characters.
- If `SOURCE_FRESHNESS_BOUNDS` receives a freshness SLO below 60 seconds or above 2,592,000 seconds, or a maximum age below the freshness SLO or above 7,776,000 seconds, the system shall reject configuration before persistence.
- When calculating `SOURCE_AGE_SECONDS`, the system shall return the floor of non-negative elapsed milliseconds divided by exactly 1000 milliseconds per second.
- If a ready source matches `SOURCE_NEVER_OBSERVED`, with no successful trusted-worker observation, the system shall return source state `unavailable`.
- If a source matches `SOURCE_FRESH_NO_FAILURES`, with most-recent successful observation age no greater than its freshness SLO and consecutive failure count zero, the system shall return source state `healthy`.
- If a source matches `SOURCE_WITHIN_MAX_AGE_DEGRADED`, with successful observation age in seconds no greater than its configured maximum age of 60 through 7,776,000 seconds, zero through two consecutive failures, and either age greater than its freshness SLO or one or two consecutive failures, the system shall return source state `degraded`.
- If a source matches `SOURCE_OLDER_THAN_MAX_AGE`, with successful observation age greater than its maximum age and fewer than three consecutive failures, the system shall return source state `stale`.
- If a source matches `SOURCE_FAILURES_AT_LEAST_THREE`, the system shall return source state `unavailable` regardless of last-success age.
- If a source matches `SOURCE_SECONDARY_CORROBORATION`, with authority category `secondary-corroboration`, the system shall exclude that source from the authoritative redundancy count.
- When a required source group matches `GROUP_MINIMUM_AND_HEALTHY_MET`, containing at least its configured minimum number of non-secondary sources in `healthy` or `degraded` state and at least one qualifying source in `healthy` state, the system shall return group state `ready`.
- When a required source group matches `GROUP_REQUIREMENT_MISSED`, missing either the configured authoritative minimum or the one-healthy-source condition, the system shall return group state `blocked` and exact reason `AUTHORITATIVE_COUNT_BELOW_MINIMUM` or `NO_HEALTHY_AUTHORITATIVE_SOURCE`.
- When a trusted worker records a new `SOURCE_OBSERVATION`, the system shall require a unique observation key of 1 through 160 characters, source outcome, observed time, latency from 0 through 300,000 milliseconds, optional source-published time, optional content digest, and optional closed failure code, then store exactly one observation.
- When an observation matches `SOURCE_OBSERVATION_REPLAY`, with an existing source and observation-key pair, the system shall return the existing observation without altering failure counts.
- When an execution job is enqueued, every configured required-for-runs source group shall be evaluated at the same server timestamp; if any group is not ready, enqueue shall fail with `E_AUTHORITATIVE_SOURCES_NOT_READY` before credit reservation or job creation.
- The system shall display `SOURCE_ASSURANCE_STATUS_UI` with `healthy`, `degraded`, `stale`, `unavailable`, `setup-required`, and `disabled` labels, freshness age, authoritative coverage, last successful observation, and the exact blocking reason.
- The system shall display `SOURCE_ASSURANCE_GOVERNANCE_UI` as `supervised source assurance` until live worker checks, licensed production sources, and external alerting have been activated.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Redundant official access admits a run
  Given a required group with minimum authoritative count 2
  And one healthy official-regulator source
  And one degraded licensed-system-of-record source within maximum age
  When an operator enqueues a job
  Then the source group is ready
  And the job may proceed to normal credit and runtime admission

Scenario: Secondary summaries cannot replace authority
  Given a required group with one healthy secondary-corroboration source
  And no current official or licensed source
  When an operator enqueues a job
  Then enqueue returns E_AUTHORITATIVE_SOURCES_NOT_READY
  And no credit reservation or execution job is created

Scenario: Repeated source failure stops regulated execution
  Given a required official-registry source with a recent success
  When a trusted worker records three consecutive failed observations
  Then the source evaluates as unavailable
  And its required group blocks new execution

Scenario: Raw credentials never enter source records
  Given an authoritative source form
  When an admin submits a non-HTTPS locator or raw token
  Then E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN is returned
  And no source is persisted
```

## SHOULD - Technical and structural

- Keep deterministic source-state and group-readiness evaluation in a pure module outside Convex.
- Store only source metadata, opaque references, observations, and digests in Convex; fetching remains a trusted-worker responsibility.
- Preserve source-specific meaning during normalization and retain publisher, jurisdiction, observation time, and digest.
- Keep secondary sources visible as corroboration and discovery aids without promoting them to authority.

## SHOULD NOT - Implementation details

- Do not claim third-party or government uptime.
- Do not fetch external sources from Convex mutations or queries.
- Do not store raw credentials, response bodies, protected records, or licensed dataset contents in the control plane.
- Do not silently substitute an unofficial source when an official source is unavailable.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `SOURCE_AUTHORITY_CATEGORY_REGISTRY` | return five declared authority categories |
| 2 | `AUTHORITATIVE_SOURCE_CONFIGURATION` | persist credential-free metadata and configuration digest |
| 3 | invalid `AUTHORITATIVE_SOURCE_REFERENCE` | return `E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN` before persistence |
| 4 | `SOURCE_CONFIGURATION_INPUT_BOUNDS` | enforce declared character ranges |
| 5 | `SOURCE_FRESHNESS_BOUNDS` | enforce freshness and maximum-age ranges |
| 6 | `SOURCE_AGE_SECONDS` | return floored non-negative elapsed seconds |
| 7 | `SOURCE_NEVER_OBSERVED` | return `unavailable` |
| 8 | `SOURCE_FRESH_NO_FAILURES` | return `healthy` |
| 9 | `SOURCE_WITHIN_MAX_AGE_DEGRADED` | return `degraded` |
| 10 | `SOURCE_OLDER_THAN_MAX_AGE` | return `stale` |
| 11 | `SOURCE_FAILURES_AT_LEAST_THREE` | return `unavailable` |
| 12 | `SOURCE_SECONDARY_CORROBORATION` | exclude source from authoritative count |
| 13 | `GROUP_MINIMUM_AND_HEALTHY_MET` | return group `ready` |
| 14 | `GROUP_REQUIREMENT_MISSED` | return group `blocked` with exact reason |
| 15 | `SOURCE_OBSERVATION` | record exactly one new observation |
| 16 | `SOURCE_OBSERVATION_REPLAY` | return the existing observation without state changes |
| 17 | `SOURCE_ASSURANCE_STATUS_UI` | display source and group readiness evidence |
| 18 | `SOURCE_ASSURANCE_GOVERNANCE_UI` | display supervised-assurance boundary |
