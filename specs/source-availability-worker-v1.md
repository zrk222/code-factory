# Spec: source-availability-worker-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall provide a deployable trusted-worker contract that continuously probes configured authoritative sources, resolves opaque references only inside the worker boundary, retries bounded transient failures, emits content-free observations, and refuses configuration drift.

### Requirements (EARS)

- When an authorized operator requests `SOURCE_WORKER_DEFINITIONS`, the system shall return enabled source identifiers, configuration digests, canonical locators, opaque endpoint references, freshness intervals, and no resolved credential.
- If `SOURCE_CONFIG_DIGEST_MISMATCH` contains a worker configuration digest different from the stored source digest, the system shall reject it with `E_AUTHORITATIVE_SOURCE_DIGEST_MISMATCH` before state mutation.
- When `SOURCE_WORKER_PROBE` starts, the worker shall return `SOURCE_WORKER_ENDPOINT_READY` containing an HTTPS endpoint confined to the runtime boundary and an attempt timeout of 10 seconds.
- If `SOURCE_WORKER_ENDPOINT_UNSAFE_INPUT` contains a resolved endpoint that is not HTTPS, the worker shall reject the probe with `E_SOURCE_WORKER_ENDPOINT_UNSAFE` before an upstream request.
- When `SOURCE_TRANSIENT_FAILURE` is a timeout, HTTP 429, or HTTP 500 through 599 response, the worker shall emit no more than 3 upstream requests with backoff of 250 milliseconds then 1000 milliseconds.
- If `SOURCE_PERMANENT_HTTP_FAILURE` contains HTTP 401, HTTP 403, or any other HTTP 400 through 499 response except 429, the worker shall return `authentication`, `authorization`, or `invalid-response` respectively after exactly 1 upstream request.
- If `SOURCE_BODY_LIMIT_EXCEEDED` contains a response body above 2097152 bytes, the worker shall return failure code `invalid-response` without returning or persisting the body.
- When `SOURCE_SUCCESS_RESPONSE` occurs, the worker shall return an observation key of 1 through 160 characters, success outcome, observed time, latency from 0 through 300000 milliseconds, optional publisher time, and a 64-character SHA-256 content digest without a response body.
- When `SOURCE_ATTEMPT_LIMIT_REACHED` occurs after exactly 3 upstream requests, the worker shall return zero response-body bytes and one closed failure code.
- The system shall return `SOURCE_FAILURE_CODE_REGISTRY` containing exactly `timeout`, `authentication`, `authorization`, `rate-limited`, `upstream-unavailable`, `invalid-response`, and `unknown`.
- When `SOURCE_MONITORING_CYCLE` receives sources, the worker shall probe at most 5 sources concurrently and shall return one observation per source.
- While `SOURCE_WORKER_DEPLOYMENT_INCOMPLETE` means an external scheduler, alert destination, or independently failing worker path is not configured, the system shall return worker posture `deployment required`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Transient outage recovers without leaking source content
  Given an HTTPS official source returns 503 and then 200
  When the trusted worker probes the source
  Then exactly two attempts occur
  And the output contains a SHA-256 digest but no response body

Scenario: Configuration drift cannot borrow worker evidence
  Given a worker holds source digest A
  And the source configuration now has digest B
  When the worker records its observation
  Then E_AUTHORITATIVE_SOURCE_DIGEST_MISMATCH is returned
  And source health is unchanged
```

## SHOULD - Technical and structural

- Inject resolution, request, clock, sleep, and hashing dependencies for deterministic tests.
- Keep external I/O outside Convex.
- Preserve one observation per source even when a monitoring cycle contains failures.

## SHOULD NOT - Implementation details

- Do not claim external uptime.
- Do not persist source bodies or resolved endpoints.
- Do not retry authentication, authorization, licence, or invalid-response failures.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `SOURCE_WORKER_DEFINITIONS` | return credential-free worker definitions |
| 2 | `SOURCE_CONFIG_DIGEST_MISMATCH` | return `E_AUTHORITATIVE_SOURCE_DIGEST_MISMATCH` |
| 3 | `SOURCE_WORKER_PROBE` | resolve and probe inside worker boundary |
| 4 | `SOURCE_TRANSIENT_FAILURE` | perform at most 3 attempts with declared backoff |
| 5 | `SOURCE_BODY_LIMIT_EXCEEDED` | return `invalid-response` |
| 6 | `SOURCE_SUCCESS_RESPONSE` | return digest-bound content-free observation |
| 7 | `SOURCE_MONITORING_CYCLE` | probe at most 5 sources concurrently |
| 8 | `SOURCE_WORKER_ENDPOINT_READY` | return HTTPS endpoint contract inside worker boundary |
| 9 | `SOURCE_FAILURE_CODE_REGISTRY` | return exactly `timeout`, `authentication`, `authorization`, `rate-limited`, `upstream-unavailable`, `invalid-response`, and `unknown` |
| 10 | `SOURCE_ATTEMPT_LIMIT_REACHED` | return content-free failure observation |
| 11 | `SOURCE_WORKER_ENDPOINT_UNSAFE_INPUT` | return `E_SOURCE_WORKER_ENDPOINT_UNSAFE` |
| 12 | `SOURCE_WORKER_DEPLOYMENT_INCOMPLETE` | return `deployment required` |
| 13 | `SOURCE_PERMANENT_HTTP_FAILURE` | map HTTP 401, HTTP 403, and other non-429 HTTP 400 through 499 responses without retry |
