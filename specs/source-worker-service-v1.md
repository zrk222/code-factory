# Spec: source-worker-service-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall package the authoritative-source probe library as a supervised, independently deployable service with bounded scheduling, health and readiness signals, metadata-only alerts, controlled shutdown, and a least-privilege deployment template.

### Requirements (EARS)

- When `SOURCE_WORKER_CONFIG_VALID` contains an HTTPS Convex URL, an agent identifier, an OIDC token, an integer polling interval from 15 through 86400 seconds, and a health port from 1024 through 65535, the service shall return bounded configuration without a secret value in diagnostic output.
- If `SOURCE_WORKER_CONFIG_INVALID` contains a missing required value, non-HTTPS Convex URL, non-HTTPS alert URL, invalid polling interval, or invalid health port, the service shall fail before opening its health listener.
- When `SOURCE_WORKER_SCHEDULE_TICK` occurs, the service shall request current digest-pinned definitions, probe them in bounded batches, and record one content-free observation for each returned source.
- While `SOURCE_WORKER_DIRECT_OVERLAP` means a cycle is active, the service shall reject a second direct cycle with `E_SOURCE_WORKER_CYCLE_OVERLAP`.
- While `SOURCE_WORKER_SCHEDULER_OVERLAP` means a cycle is active, the entrypoint shall return without starting another cycle.
- If `SOURCE_WORKER_SOURCE_FAILURES` contains one or more failed observations, the service shall send only error code, failed-source count, observed-source count, and occurrence time to the configured alert destination.
- When `SOURCE_WORKER_ALERT_TRANSIENT_FAILURE` occurs, the service shall return successful delivery after no more than 3 alert attempts with backoff of 250 milliseconds then 1000 milliseconds.
- If `SOURCE_WORKER_ALERT_EXHAUSTED` occurs after exactly 3 failed alert attempts, the service shall record `E_SOURCE_WORKER_ALERT_FAILED` in health state without changing or concealing the monitoring-cycle result.
- When `SOURCE_WORKER_HEALTH_REQUEST` targets `/healthz`, the service shall return the `alive` boolean and no source locator, credential, response body, or identity token.
- When `SOURCE_WORKER_READINESS_REQUEST` targets `/readyz`, the service shall return ready only after a successful all-source cycle within the last 3 polling intervals.
- If `SOURCE_WORKER_SHUTDOWN_SIGNAL` is SIGTERM or SIGINT, the service shall stop scheduling, close the listener, wait no more than 10 seconds for an active cycle, and return failure when the deadline expires.
- When `SOURCE_WORKER_CONTAINER_STARTS`, the deployment manifest shall return `runAsNonRoot: true` and expose only health port 8080.
- While `SOURCE_WORKER_PRODUCTION_ACTIVATION_INCOMPLETE` means a digest-pinned image, secret injection, production OIDC identity, alert destination, or independent replica is absent, documentation shall return deployment posture `activation required`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A monitored source fails without leaking its location
  Given one digest-pinned source returns an upstream failure
  When the scheduled cycle completes
  Then its content-free observation is recorded
  And the alert contains only code, counts, and occurrence time
  And readiness is false

Scenario: An orchestrator drains the worker safely
  Given a monitoring cycle is active
  When SIGTERM reaches the process
  Then no new cycle starts
  And the process waits up to ten seconds for the active cycle
```

## SHOULD - Technical and structural

- Separate configuration, cycle execution, alert retry, and health-state logic from process bootstrap.
- Use a multi-stage Node 22 container and a read-only, no-capabilities Kubernetes security context.
- Keep externally supplied image and secret values explicit in the deployment template.

## SHOULD NOT - Implementation details

- Do not log OIDC tokens, resolved endpoints, source bodies, or webhook URLs.
- Do not treat one failed alert delivery as permission to discard an observation.
- Do not claim the checked-in deployment template is a live deployment.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `SOURCE_WORKER_CONFIG_VALID` | start with bounded configuration |
| 2 | `SOURCE_WORKER_CONFIG_INVALID` | fail before listening |
| 3 | `SOURCE_WORKER_SCHEDULE_TICK` | run one digest-pinned monitoring cycle |
| 4 | `SOURCE_WORKER_DIRECT_OVERLAP` | reject with `E_SOURCE_WORKER_CYCLE_OVERLAP` |
| 5 | `SOURCE_WORKER_SOURCE_FAILURES` | emit metadata-only alert |
| 6 | `SOURCE_WORKER_ALERT_TRANSIENT_FAILURE` | retry no more than 3 times |
| 7 | `SOURCE_WORKER_ALERT_EXHAUSTED` | expose `E_SOURCE_WORKER_ALERT_FAILED` without masking cycle state |
| 8 | `SOURCE_WORKER_HEALTH_REQUEST` | return liveness only |
| 9 | `SOURCE_WORKER_READINESS_REQUEST` | require recent successful cycle |
| 10 | `SOURCE_WORKER_SHUTDOWN_SIGNAL` | drain for at most 10 seconds |
| 11 | `SOURCE_WORKER_CONTAINER_STARTS` | run non-root |
| 12 | `SOURCE_WORKER_PRODUCTION_ACTIVATION_INCOMPLETE` | return `activation required` |
| 13 | `SOURCE_WORKER_SCHEDULER_OVERLAP` | return without starting another cycle |
