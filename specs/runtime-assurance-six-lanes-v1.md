# Spec: runtime-assurance-six-lanes-v1
Status: approved
SpecFactor-target: 0.75-2.5

## Outcome

Code Factory shall coordinate six runtime assurance lanes against a specific candidate and return one hash-bound decision without treating a tool's `passed` field, an agent-authored threshold, or an absent tool as proof.

## MUST — Sealed authority and execution boundary

### Requirements (EARS)

- When `REQ_CONTRACT` accepts a plan, it shall verify an Ed25519 DSSE envelope of type `application/vnd.factory.runtime-audit-plan.v1+json` against an explicit local trust root, require schema `factory.runtime-audit-plan.v1`, bind one 64-hex candidate digest and 1 to 128 workspace files by relative path, SHA-256 and byte size, require exactly the six closed lane enums, and reject expiry after 24 hours, duplicate identifiers, unknown fields, path escape, missing files, source drift, or a future issue time. [R10]
- When `REQ_COUNTERFACTUAL_MESH` accepts a plan, it shall require one authoritative shared scenario digest and 2 to 5 closed transformation relations across the six lanes; agent-proposed scenario authority or a target/known-bad artifact with a different scenario digest shall block the composite result. [R15]
- When `REQ_RUNNER` executes a lane, it shall run only its signed argv without a shell through the existing supervised runner, enforce a signed timeout from 1 to 300 seconds for each command and exactly 2 commands per lane, create one unique workspace-contained evidence directory per command, bind command exit status plus stdout, stderr and declared artifact hashes, and label the boundary `supervised_subprocess_not_sandboxed`. [R20]
- If `REQ_NEGATIVE_CONTROL` validates a lane, it shall require exactly 1 target command to exit zero and exactly 1 separate known-bad command to exit nonzero within their signed 1-to-300-second timeouts; a known-bad exit zero shall return `HOLLOW_RUNTIME_AUDIT`. [R30]
- While `REQ_AUTHORITY` returns a result, it shall grant no source modification, merge, approval, publication, deployment, signing, credential, provider, connector or messaging authority. [R40]

## MUST — Six evidence adapters

- When `REQ_STATEFUL` evaluates the `stateful_invariant` lane, it shall return `PASS` only for an artifact from the signed engine identifier containing 2 to 1000 generated examples, 2 to 200 actions per example, 1 to 128 approved invariant identifiers, one integer seed from 0 to 4294967295 and zero invariant violations; for 1 or more violations it shall return `FAIL` with 1 to 200 action identifiers and exactly 1 failing invariant identifier. [R50]
- When `REQ_TENANT` evaluates the `tenant_isolation` lane, it shall require 2 to 256 runtime observations including allowed owner plus denied cross-tenant, anonymous and revoked-session cases for every signed API, cache, session, export, storage, queue or background-job surface in cold, warm and post-revocation phases; it shall reject any denied case returning a signed-plan forbidden field, a status outside the approved set, a nonempty tenant-data digest or a mutation effect. [R60]
- When `REQ_RECOVERY` evaluates the `failure_recovery` lane, it shall require 2 to 64 concurrent or duplicate operations, at least one declared network/dependency fault, pre-fault, during-fault and recovered observations, exact approved post-recovery invariants, and successful cleanup evidence; it shall reject duplicated side effects, lost updates, incomplete cleanup, or a recovery state mismatch. [R70]
- When `REQ_COMPATIBILITY` evaluates the `consumer_compatibility` lane, it shall accept only a native Pact verifier or approved schema validator artifact bound to 1 to 256 consumer interactions, require provider version, consumer version, branch/environment and any signed can-I-deploy-style matrix decision, reject any mismatch, missing interaction, incompatible/missing matrix pair or pending/WIP failure, and never infer compatibility from schema file validity alone. [R80]
- When `REQ_MIGRATION` evaluates the `migration_integrity` lane, it shall require exactly 1 isolated database rehearsal with 1 before-schema digest, 1 after-schema digest, 1 to 256 invariant query identifiers, 1 to 256 record-count checks, 1 integrity-violation count, exactly 1 old-reader decision, exactly 1 new-reader decision, exactly 1 tested rollback or explicit forward-fix rehearsal, signed required catalog objects and a lock-wait budget; it shall reject drift, loss, an integrity count above zero, a false reader decision, missing or invalid catalog state, excess lock wait or a missing recovery strategy. [R90]
- When `REQ_PERFORMANCE` evaluates the `performance_regression` lane, it shall require equivalent baseline and candidate workload digests, tool and environment fingerprints, 10 to 1000000 observations, bounded soak and cooldown series, load-generator capacity evidence, one selected memory/resource profiler and at least one latency, error-rate or resource threshold whose provenance is human-confirmed, trusted-source or observed-production; it shall fail when any approved threshold or profiler finding is exceeded, report post-cooldown growth as a retention signal rather than proof of a leak, and keep agent-proposed thresholds advisory. [R100]

## MUST — Independent evaluation and composite decision

- When `REQ_ARTIFACTS` reads a tool artifact, it shall parse one JSON object of at most 1048576 bytes with a recognized schema and adapter-specific field bounds, calculate the decision from numeric and categorical observations, reject NaN, infinity, negative counts, unknown enum values, duplicate IDs, any field named `body`, `headers`, `token`, `password` or `secret`, and an artifact hash that changes across two reads, and ignore any input `passed`, `ok`, `verdict` or `decision` field. [R110]
- When `REQ_DECISION` joins the six lanes, it shall return `BLOCKED` if any lane fails, is incomplete, lacks its negative control, uses stale evidence, or lacks runtime-environment attestation; only six fresh passing lanes may return `READY_FOR_HUMAN_REVIEW`, which is not release approval. [R120]
- When `REQ_MISSION` projects a run, it shall return exactly 6 lane records through the shared Mission and machine-readable MCP surfaces; every record shall contain 1 question, 1 state, 1 exact finding, 1 consequence, 1 evidence digest, 1 signed replay or remediation action, and 1 scope limitation, including failed and incomplete lanes. [R130]
- When `REQ_ACTIONS` projects a run, it shall emit exactly 1 repair record per failed or incomplete lane with a maximum of 6 records, sort those records by the closed lane priority, label native engines separately from approved adapters, and emit a maximum of 4 recognized cross-lane co-occurrence signals as review routing rather than causal proof. [R140]
- When `REQ_KV_FACTS` projects a run for an IDE or agent, it shall emit exactly 1 sorted immutable self-hashed typed key-value index containing exactly 28 entries: 4 composite decision/candidate/scenario/repair entries plus exactly 4 state/finding/evidence-digest/quality entries per 6 lanes; it shall exclude raw prompts, logs, headers, bodies, credentials and mutable gate values. [R150]

## Acceptance criteria

```gherkin
Scenario: All six independent observations satisfy approved contracts
  Given a signed unexpired plan bound to unchanged candidate sources and six target plus known-bad commands
  When REQ_RUNNER executes the plan and REQ_ARTIFACTS computes every lane result
  Then REQ_NEGATIVE_CONTROL rejects each known-bad case and REQ_DECISION returns READY_FOR_HUMAN_REVIEW
  And REQ_AUTHORITY grants no release action

Scenario: An agent weakens its own threshold
  Given a performance threshold has agent_proposed provenance
  When REQ_PERFORMANCE evaluates a candidate within that threshold
  Then the threshold remains advisory and REQ_DECISION returns BLOCKED because no authoritative threshold was exercised

Scenario: A green report omits a denied tenant case
  Given a tenant tool artifact says passed but lacks the revoked-session pair
  When REQ_TENANT and REQ_ARTIFACTS evaluate it
  Then the input passed field is ignored and the lane is incomplete

Scenario: A recovery command hides duplicate effects
  Given concurrent retries produce two durable effects for one idempotency key
  When REQ_RECOVERY compares approved post-state invariants
  Then the lane fails with the observed duplicate count and consequence

Scenario: One known-bad audit survives
  Given five known-bad commands fail but the compatibility known-bad command exits zero
  When REQ_NEGATIVE_CONTROL joins the run
  Then the composite decision is BLOCKED with HOLLOW_RUNTIME_AUDIT

Scenario: The signed plan drifts after approval
  Given REQ_CONTRACT receives a signed plan whose bound source file no longer matches its digest and byte size
  When REQ_CONTRACT verifies the plan against the pinned trust root
  Then REQ_CONTRACT rejects it before any lane command starts

Scenario: Stateful execution finds a sequence-only defect
  Given REQ_STATEFUL receives 20 examples with up to 40 actions and one approved invariant reports one violation
  When REQ_STATEFUL computes the state without reading an input verdict
  Then REQ_STATEFUL returns FAIL with the failing invariant identifier and a bounded action trace

Scenario: A schema exists but a deployed consumer interaction is missing
  Given REQ_COMPATIBILITY receives valid schema syntax and omits one signed required consumer interaction
  When REQ_COMPATIBILITY compares the observed interaction identifiers with the signed set
  Then REQ_COMPATIBILITY rejects the artifact instead of inferring compatibility

Scenario: A migration preserves row counts but breaks the old reader
  Given REQ_MIGRATION receives matching record counts and an old-reader decision of false
  When REQ_MIGRATION computes the migration state
  Then REQ_MIGRATION returns FAIL with the false old-reader decision

Scenario: Mission projection contains an incomplete lane
  Given REQ_MISSION receives six lane results including one incomplete result
  When REQ_MISSION creates the human and machine-readable projections
  Then REQ_MISSION returns six visible records and the incomplete record retains its finding, consequence and remediation

Scenario: One lane silently changes the shared scenario
  Given five lane artifacts bind the approved counterfactual scenario and one lane binds a different digest
  When REQ_COUNTERFACTUAL_MESH joins the evidence
  Then the divergent lane is incomplete and the composite decision is BLOCKED

Scenario: Multiple related lanes fail
  Given tenant isolation and recovery both fail within the signed shared scenario
  When REQ_ACTIONS builds the human result
  Then tenant isolation precedes recovery in the repair queue
  And the compound signal is explicitly labelled non-causal

Scenario: IDE fact index remains typed and secret-free
  Given REQ_KV_FACTS receives one six-lane receipt
  When REQ_KV_FACTS creates the immutable fact index
  Then the index contains exactly 28 sorted typed entries and one self-hash
  And no prompt, log, body, header, credential or mutable gate value is present
```

## SHOULD — Established engines

- Accept Hypothesis state-machine JSON, OWASP-informed tenant test matrices, Toxiproxy experiment artifacts, Pact verification results, database-native integrity output, and k6 summary JSON through separate version-pinned adapters.
- Preserve native artifacts and tool versions; CF computes normalized findings rather than relabeling native tool success as approval.
- Emit exact rerun commands only from the signed contract and never synthesize execution arguments from agent output.

## MUST NOT — Claims

- No target is a production environment. The runner shall refuse non-loopback HTTP origins unless the signed plan declares `environment=isolated_test` and the operator supplies a separate matching execution-environment digest at run time.
- No adapter proves business intent, full authorization coverage, complete consumer coverage, rollback safety on a production database, deterministic concurrency scheduling, or production performance by itself.
- Missing Hypothesis, Toxiproxy, Pact, database client or k6 runtime is `INCOMPLETE_TOOLING`, not a skipped or passing lane.
