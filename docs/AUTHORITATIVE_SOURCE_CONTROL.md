# Agent Oven Authoritative Source Control

## Outcome

Agent Oven now separates ordinary retrieval context from sources that can justify a regulated run. The control plane will refuse new execution when a required authority group has too few current official or licensed sources, or when none of those sources is healthy.

This is a fail-closed availability control. It does not promise that a government, regulator, registry, or licensed vendor will remain online.

## Authority classes

| Class | Counts toward run readiness | Intended use |
|---|---:|---|
| `primary-law` | Yes | Statutes, regulations, gazettes, filed rules |
| `official-regulator` | Yes | Regulator guidance, bulletins, enforcement notices |
| `official-registry` | Yes | Licences, titles, permits, professional status |
| `licensed-system-of-record` | Yes | Contracted authoritative datasets and transactional systems |
| `secondary-corroboration` | No | Discovery, commentary, summaries, cross-checks |

Secondary sources remain visible, but never substitute for authority.

## Readiness rules

Each source declares a freshness SLO, maximum age, current consecutive failure count, and redundancy group. Evaluation uses one server timestamp for the entire enqueue decision.

- `healthy`: latest success is inside the freshness SLO and there are no consecutive failures.
- `degraded`: latest success is still inside maximum age, but freshness is outside SLO or one to two checks failed.
- `stale`: latest success is older than maximum age.
- `unavailable`: no successful worker observation exists, or three consecutive checks failed.
- `setup-required`: metadata exists but a trusted worker has not activated it.
- `disabled`: an admin has deliberately removed it from service.

A required group is ready only when:

1. its declared minimum number of non-secondary sources are healthy or degraded; and
2. at least one qualifying source is healthy.

Otherwise the exact blocker is `AUTHORITATIVE_COUNT_BELOW_MINIMUM` or `NO_HEALTHY_AUTHORITATIVE_SOURCE`.

## Trusted-worker boundary

Convex stores source metadata, opaque `env:` or `vault:` references, configuration digests, and bounded observations. It stores no raw credential, response body, protected record, or licensed dataset content. External fetching belongs to a separately deployed trusted worker.

Workers call the internal `authoritativeSources.recordObservation` mutation with:

- a unique 1â€“160-character observation key;
- `success` or `failure`;
- observation time and 0â€“300,000 ms latency;
- optional source-published time and content digest;
- a closed failure code for failures.

Replaying the same source and observation key returns the existing observation without incrementing failure counters.

The deployable worker library in `runtime/sourceWorker.ts` now supplies the bounded I/O contract: HTTPS-only resolved endpoints, 10-second attempt timeout, at most three attempts for timeout/429/5xx failures, 250 ms then 1000 ms backoff, a 2 MiB body ceiling, SHA-256-only output, and batches of at most five concurrent probes. An authenticated operator worker obtains credential-free definitions from `listWorkerDefinitions` and submits a digest-pinned result through `recordWorkerObservation`; configuration drift fails before source state changes.

The library is now packaged as a scheduled service with liveness/readiness endpoints, metadata-only alert retry, graceful draining, rotating workload-identity files, confined mounted-vault resolution, a redacted activation preflight and live rotation drill, a non-root container, and a hardened two-replica Kubernetes template. The preflight checks exact decoded issuer/audience/subject and bounded lifetime but explicitly does not claim signature verification; Convex remains the verifier. The repository does not claim that a trusted issuer/audience, service membership, secret-store CSI provider, digest-pinned image, independent failure-domain replicas, or alert destination is currently live. Production posture therefore remains `credential activation required`; see `docs/SOURCE_WORKER_SERVICE.md`.

## Execution safety

`execution.enqueue` evaluates all required source groups before admission counters, credit reservation, lease creation, or job persistence. A blocked group returns:

```text
E_AUTHORITATIVE_SOURCES_NOT_READY:<group>:<exact-reason>
```

Agents without configured required groups preserve existing behavior. This supports staged adoption while regulated templates can require the control explicitly.

## Production activation checklist

- Deploy at least two independently failing worker paths for critical groups.
- Resolve endpoint and licence references only inside the worker's secret boundary.
- Schedule checks faster than each source freshness SLO.
- Send alerts before maximum age, not after it.
- Use circuit breakers, bounded retry with jitter, rate-limit awareness, and cached metadata only within licence terms.
- Record content digests and publisher timestamps where permitted.
- Exercise primary outage, fallback outage, credential expiry, rate limit, and stale-cache drills.
- Monitor the source-control gate itself from another failure domain.

Until those external controls are activated and measured, the UI correctly labels the feature `supervised source assurance`.
