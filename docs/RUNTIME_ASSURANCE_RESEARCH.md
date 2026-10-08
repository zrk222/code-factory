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

## Deep penetration testing integration decision (2026-10)

### Recommended engine mix

Keep Code Factory as the signed scope, execution-control, evidence-normalization,
and decision layer. Add external scanners as version-pinned, no-shell runner
adapters; do not let their own `passed`/exit status bypass CF's normalized
evidence checks.

| Need | Preferred engine | CF lane / evidence | Why this fit | Gate limit |
|---|---|---|---|---|
| Authenticated web/API DAST | OWASP ZAP Automation Framework | tenant isolation, compatibility, failure recovery; imported alerts plus request/response metadata digest | Its plan supports explicit environments, authentication, spidering, active scans, job tests, alert filtering and result-based exit status. | Passive coverage and active findings are distinct. Active scans can mutate state; require disposable isolated targets, strict include-context, rate/budget bounds and cleanup. |
| OpenAPI stateful API exploration | RESTler for dependency-rich REST APIs; Schemathesis for property-based OpenAPI/GraphQL coverage | stateful, tenant, recovery, compatibility; operation/link/role/phase denominator, sequence trace, minimized replay | RESTler infers producer/consumer dependencies and explores request sequences. Schemathesis generates property-based requests and has stateful operation chaining. | Report discovered, eligible, executed and unexecuted operations/links separately. Zero successful producers or zero covered links is `INCOMPLETE`, never a pass. |
| Business-state sequence exploration | Hypothesis state machines | stateful invariants and failure recovery; seed, per-invariant checks, actions, minimized counterexample | Generates action sequences and shrinks failures to replayable traces. | Sequential state-machine testing does not by itself prove thread-safety or production race freedom. |
| Race and lost-update testing | Application-specific deterministic concurrency harness + database/queue native isolation tests; Toxiproxy only for dependency/network faults | failure recovery; barrier/schedule ID, overlap count, operation IDs, linearizable before/after state, retries, fault evidence | A deterministic interleaving exposes duplicate effects, lost updates, stale reads and lock-order failures; separate from ordinary request fuzzing. | If the harness cannot prove overlap or the runtime lacks a supported scheduler, report race coverage `UNSUPPORTED`/`INCOMPLETE`. |
| Source-to-sink security paths | CodeQL security queries/custom path packs | Python/JS/TS/Java/etc. static security lane, linked to DAST finding IDs where possible | Path queries carry source-to-sink reasoning and query packs allow domain-specific models. | Static reachability is not exploitability; pair high-risk paths with controlled runtime reproduction when possible. |
| Dependency, secret, and IaC surface | Trivy filesystem/repository/image scans | supply-chain and deployment-configuration evidence | One pinned engine can scan vulnerabilities/secrets and (when explicitly enabled) IaC misconfiguration. | Misconfiguration scans are not enabled by default in every Trivy command; the signed invocation must name scanners and rule/bundle version. |

These engines complement one another rather than form one “penetration score.”
ZAP is the web DAST choice; RESTler or Schemathesis is selected by the API
contract and statefulness; CodeQL and Trivy supply static/dependency/config
coverage, not runtime penetration evidence.

### Required CF adapter contract

Every external run must be admitted by the existing signed runtime-audit plan
and bind: candidate/source manifest, exact tool version or container digest,
rule/query pack digest, environment digest, explicit allowlisted origin(s),
test identity and role, command argv, resource/time/request budgets, raw report
digest, normalized report digest, and a reproducible finding or no-finding
coverage denominator. Keep raw bodies, authorization headers, credentials,
session cookies, and personal data out of CF receipts. Store detailed scanner
artifacts in the isolated run directory with access and retention governed by
the operator; receipts hold only bounded metadata and hashes.

The adapter must prove both sides of detection: a clean positive control stays
clean, and a seeded vulnerable control is detected with the expected rule or
finding family. Disagreement, scanner crash, auth failure, schema import error,
unexplored route, zero generated sequence, target drift, report parse error, or
cleanup failure is `INCOMPLETE`/`BLOCKED`, with a specific actionable next step.
An agent may draft a repair; CF reruns the same reproduction and adjacent
regressions, then requires a separately signed fresh audit. No agent may
auto-accept a finding, weaken scope, or deploy the repair.

### Pain points made explicit

- **Race conditions:** require controlled concurrent overlap, multiple
  interleavings/seeds, idempotency-key replay, and an oracle for linearizable
  final state. Record executed schedule count over planned schedule count; hash
  each schedule's declared IDs and overlap result canonically. This hash checks
  field consistency, while actual occurrence still depends on the approved
  runner and its candidate-bound raw report.
- **Mismatches:** compare contract-declared operations, consumers, versions,
  environments, roles, and response schemas against what was actually
  exercised. Missing consumer pairs, pending interactions, or zero covered
  links stay incomplete.
- **Nested errors and failures:** inject dependency timeout/reset, malformed or
  partial nested responses, cancellation, retry, and crash-after-effect at
  each declared boundary. Preserve a redacted cause chain with stable error
  class, originating component, phase, operation ID, and evidence hash; assert
  both user-visible failure semantics and absence of partial durable effects.
- **Authorization:** exercise owner, cross-tenant, anonymous, revoked, and
  least-privilege identities across cold/warm caches, API, exports, storage,
  queues and background workers. Require the owner positive control to match
  the signed expected data digest and fields, not only HTTP 2xx.
- **Coverage claims:** keep static file coverage, runtime statement/branch
  coverage, route/operation coverage, state-transition coverage, role/surface
  coverage, and mutation score separate. A missing denominator is not 100%.

### Rollout order

1. Land stricter CF evidence semantics and table-driven adversarial controls
   first: owner positive-control oracle, per-example invariant checks, per-fault
   evidence, and fail-closed nested-report handling.
2. Add one contract adapter at a time, beginning with Schemathesis for
   contract-driven API coverage and ZAP passive/authenticated baseline; keep
   active ZAP and RESTler deep fuzz behind explicit isolated-test policy.
3. Add deterministic race harness evidence and per-boundary failure injection;
   require replayable minimized traces for every finding.
4. Run nightly or manually triggered deep scans within a bounded disposable
   environment; retain fast static/changed-scope checks in PR CI and report the
   full-run age so stale deep evidence is not reused.
5. Calibrate with an independently authored development set and a sealed,
   externally contributed holdout. Publish per-lane TP/FP/FN/TN, denominators,
   confidence intervals, version, and known gaps; never tune against holdout.

### Verified source basis

- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) documents authentication, explicit environment configuration, active scans, job tests and exit status from scan results.
- [Microsoft RESTler](https://github.com/microsoft/restler-fuzzer) documents producer/consumer dependency inference, stateful REST sequences, distinct fuzz modes and warns that aggressive fuzz can disrupt a poorly implemented service.
- [Schemathesis stateful testing](https://schemathesis.readthedocs.io/en/latest/guides/stateful-testing/) documents OpenAPI links and reports zero covered links when no producer call succeeds; that state must not be interpreted as coverage.
- [Hypothesis stateful testing](https://hypothesis.readthedocs.io/en/latest/stateful.html) provides generated rule-based state machines and reproducible shrinking of failures.
- [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/) represent dataflow from source to sink with path explanations.
- [Trivy filesystem scans](https://trivy.dev/docs/latest/target/filesystem/) cover vulnerabilities, secrets and misconfiguration, while the [misconfiguration guide](https://trivy.dev/docs/latest/scanner/misconfiguration/) notes the need to explicitly enable misconfiguration scanning in filesystem/image/repo modes.
