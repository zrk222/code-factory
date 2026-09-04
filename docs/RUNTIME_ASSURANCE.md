# Six-lane runtime assurance

`factory runtime-audit` is the senior-engineering audit path for behavior that a unit-test-only gate can miss. It coordinates six independently reported lanes and computes the decision itself:

1. stateful business invariants;
2. runtime authorization and tenant isolation;
3. failure, concurrency, idempotency, cleanup and recovery;
4. API and consumer compatibility;
5. database migration, reader compatibility and data integrity;
6. equivalent-workload performance, capacity, resource retention and profiler findings.

The result is either `READY_FOR_HUMAN_REVIEW` or `BLOCKED`. It is never a release approval.

## Operator workflow

1. A named operator chooses the engine, exact version, environment fingerprint, source manifest, approved limits and six target/known-bad commands.
   The same contract also seals a cross-lane scenario and at least two controlled relations, such as the same business operation and runtime environment.
2. The operator signs `factory.runtime-audit-plan.v1` as DSSE/Ed25519 and separately pins the trust-root file SHA-256.
3. Inspect without execution:

   ```text
   factory runtime-audit inspect plan.dsse.json --root . --trust-root trust-root.json --trust-root-sha256 <sha256> --environment-sha256 <sha256>
   ```

4. Run the exact signed no-shell commands:

   ```text
   factory runtime-audit run plan.dsse.json --root . --trust-root trust-root.json --trust-root-sha256 <sha256> --environment-sha256 <sha256>
   ```

5. Review `factory runtime-audit status --root .`, Mission Control, or MCP tool `factory.runtime_audit_status`.

Each lane must emit bounded JSON to its single `{artifact}` path. CF rejects duplicate JSON keys, non-finite numbers, symlink artifacts, unstable reads, oversized evidence, raw body/header/token/password/secret fields, missing observations, and unknown schema fields. `passed`, `ok`, `verdict`, and `decision` fields are ignored. CF recomputes the finding from the signed policy and observations.

## Engine adapters and evidence boundaries

- `hypothesis` or an explicitly approved state-machine runner supplies transition traces; CF checks declared coverage, invariant execution, replay stability and the known-bad counterexample.
- `runtime_http_matrix` covers the signed API, cache, session, export, storage, queue and background-job surfaces in cold, warm and post-revocation phases.
- `toxiproxy` or an approved fault runner supplies fault observations; CF checks duplicate effects, lost updates, retry bounds, recovery postconditions and cleanup.
- `pact_verifier` or an approved schema runner supplies exercised interactions; CF also requires the signed deployment-matrix decision when configured. Pending/WIP does not turn a mismatch into a pass.
- `database_rehearsal` or `flyway` supplies an isolated rehearsal; CF checks schema/history, representative record counts, invariant digests, old/new readers, recovery, catalog validity and lock-wait budget.
- `k6` or an approved load runner supplies an equivalent baseline/candidate comparison. CF checks authoritative thresholds, correctness under load, load-generator saturation, soak/cooldown resource series, and the selected profiler result.

If the selected native engine is unavailable or does not emit the required evidence, the lane is `INCOMPLETE_TOOLING`; it does not silently fall back. An approved adapter is truthfully labelled as that adapter, not as Hypothesis, Pact, Flyway, Toxiproxy or k6.

## Memory and regression claims

RSS, heap, handle or connection growth after cooldown is reported as a **resource-retention regression**, not automatically as a memory leak. A clean LeakSanitizer, Valgrind, .NET, JVM, Node, Python `tracemalloc`, or runtime-metrics result means only “no finding within the declared profiler and workload coverage.” Known-bad controls must prove the configured lane can fail.

## Security and authority limits

The runner uses exact argv, `shell=False`, bounded time/output, fresh temporary home directories, a minimal inherited environment, separate artifact directories, and post-run source/plan re-verification. It is supervised execution, **not** a container, VM, kernel policy, network sandbox, or protection from a malicious operator-approved command. Use disposable isolated infrastructure for untrusted programs. Local mode permits only declared loopback origins; CF does not itself enforce egress.

Every blocking threshold must originate from `human_confirmed`, `trusted_source`, or `observed_production`. `agent_proposed` thresholds remain advisory. The agent under test cannot rewrite the signed plan, source manifest, expected negative finding, or trust-root pin.

## Actionable result contract

Every visible lane contains:

- the engineering question;
- `PASS`, `FAIL`, or `INCOMPLETE`;
- stable finding code;
- user consequence;
- bounded structured details;
- target and known-bad evidence digests;
- exact replay argv and timeout;
- smallest next remediation;
- scope limitation.

The composite adds an evidence-quality label (`native_engine` or
`approved_adapter`), a deterministic repair queue, and bounded compound review
signals. These signals highlight combinations such as tenant-boundary plus
retry failures or migration plus consumer-contract failures; they are
co-occurrence routing, never a claim that CF proved causation.

It also emits `factory.runtime-audit-kv.v1`: a sorted, self-hashed, immutable
fact index for IDE/MCP consumers. Only decision, candidate/scenario digests,
lane state/finding/evidence quality, and repair count are included. Raw prompts,
logs, headers, credentials, test bodies, and agent-supplied gate values are not
copied into the KV surface.

This keeps a failed audit from becoming a red light with no route forward while preserving human approval.
