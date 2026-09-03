# Runtime assurance research and failure-pattern ledger

This is the canonical research source for the six-lane implementation. Sources are primary project documentation or recognized security guidance; CF claims only the checks implemented in this repository.

| Lane | Known failure patterns covered | Primary sources |
|---|---|---|
| Stateful invariants | invalid transition sequences, initialization gaps, unexercised actions/invariants, unreplayable counterexamples, state leakage between examples | [Hypothesis stateful testing](https://hypothesis.readthedocs.io/en/latest/stateful.html), [Hypothesis API reference](https://hypothesis.readthedocs.io/en/latest/reference/api.html) |
| Tenant isolation | IDOR/BOLA, client-supplied tenant context, warm-cache leakage, revoked-session access, cross-tenant exports/storage, async queue and reused-worker context | [OWASP Multi-Tenant Security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), [OWASP Authorization Testing Automation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html), [OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| Failure and recovery | timeout/reset/latency paths, duplicate delivery, simultaneous contenders, crash after side effect, retry storm, cleanup failure, lost update | [Toxiproxy](https://github.com/Shopify/toxiproxy), [AWS retry-safe idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/), [Amazon SQS at-least-once delivery](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/standard-queues-at-least-once-delivery.html), [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests?lang=curl) |
| Consumer compatibility | provider-state setup gaps, interaction mismatch hidden by pending/WIP status, missing older consumer versions, publish success confused with deployment safety | [Pact provider verification](https://docs.pact.io/provider), [Pact pending pacts](https://docs.pact.io/pact_broker/advanced_topics/pending_pacts), [Pact can-i-deploy](https://docs.pact.io/pact_broker/can_i_deploy) |
| Migration integrity | schema/history drift, historical constraint gaps, record loss, old/new reader breakage, unexercised rollback/forward fix, lock contention, failed concurrent index left invalid | [Flyway check](https://documentation.red-gate.com/flyway/reference/commands/check), [PostgreSQL ALTER TABLE](https://www.postgresql.org/docs/18/sql-altertable.html), [PostgreSQL CREATE INDEX](https://www.postgresql.org/docs/18/sql-createindex.html) |
| Performance and resources | incomparable workloads/environments, generator saturation, error/latency/capacity regression, insufficient soak/cooldown, retained memory/handles/connections, profiler findings | [k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/), [k6 automated testing](https://grafana.com/docs/k6/latest/testing-guides/automated-performance-testing/), [k6 large-test guidance](https://grafana.com/docs/k6/latest/testing-guides/running-large-tests/), [LeakSanitizer](https://clang.llvm.org/docs/LeakSanitizer.html), [Valgrind Memcheck](https://valgrind.org/docs/manual/mc-manual.html/manual-core-adv.html), [.NET memory leak diagnostics](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/debug-memory-leak), [Python tracemalloc](https://docs.python.org/3/library/tracemalloc.html), [Node heap snapshots](https://nodejs.org/learn/diagnostics/memory/using-heap-snapshot) |

## Design conclusions applied

- Generated action sequences need observed transition counts, invariant counts, isolated examples and a replayable reduced trace; a large configured example count alone is not evidence.
- Tenant evidence must cross the feature/role/data dimensions and revisit boundaries after cache warmup and revocation. HTTP endpoints alone are insufficient; exports, storage and asynchronous work are explicit signed surfaces.
- Retry safety requires duplicate delivery plus simultaneous work and fault injection. A successful second response does not prove a single durable side effect.
- Pact pending status is metadata, not a pass. CF evaluates mismatches and the deployment matrix separately.
- Migration success is not just process exit zero. Catalog state, reader compatibility, historical data, recovery and bounded lock impact are part of the result.
- A performance comparison is meaningful only when candidate and baseline share a signed workload and environment and the load generator is not saturated.
- Retention signals and confirmed leaks are separate. Finite clean runs do not establish “leak free.”
- The same signed scenario fingerprint must cross all six lanes so a green result cannot be assembled from unrelated fixtures. Cross-lane co-occurrence is useful for repair ordering but is not causal proof.

## Residual limits

The source projects define capable engines, but CF cannot authenticate a fabricated wrapper’s observations merely because its JSON is well-formed. The signed operator must bind the selected engine/version and run it in a trustworthy isolated environment. The target/known-bad pair proves discrimination for the signed scenario, not universal correctness, production safety, or absence of undiscovered defects.
