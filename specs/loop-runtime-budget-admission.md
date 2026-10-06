# Spec: loop-runtime-budget-admission
Status: draft
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description
Add runtime admission and settlement to the existing Loop Passport budget
contract so a participating agent adapter must reserve its next action before
starting it, reconcile measured usage after it, and stop admitting work once
the declared budget is exhausted or evidence is incomplete.

The HSF workflow at `specs/loop-runtime-budget-admission.yaml` is a
non-authorizing advisory classifier. Every positive result still requires the
SQLite runtime API to verify the passport and create the durable reservation.
Its synthetic golden cases validate advice ordering and extraction fallback;
they do not execute adapters, mutate the ledger, or authorize real work.

### User roles
- Loop owner: supplies a validated Loop Passport and run/action identifiers.
- Agent adapter: requests an admission before each metered operation and
  settles it with measured usage afterward.
- Auditor: reads the manifest-bound session projection and durable action receipts.

### Requirements (EARS)
- The system shall return marker `RUNTIME_BUDGET_LEGACY_PRESERVED` while preserving the existing post-run `loop budget` command and fail-closed receipt behavior. [R1]
- The system shall return marker `RUNTIME_SESSION_PASSPORT_BOUND` after creating a runtime session associated with the exact Loop Passport manifest SHA256, configured budget values for iterations, wall seconds, tokens and USD, loop id and caller-supplied run id. [R2]
- When an adapter requests an action, the system shall return marker `RUNTIME_ACTION_RESERVED` after storing finite non-negative estimates for iterations, wall seconds, tokens and USD cost; one accepted action reserves exactly one iteration. [R3]
- When projected usage exceeds its configured budget, the system shall return marker `RUNTIME_BUDGET_EXCEEDED` and reject the requested action before execution. [R4]
- When an action id is replayed with identical input, the system shall return marker `RUNTIME_ACTION_IDEMPOTENT` and its existing receipt without another reservation; changed input returns `ACTION_CONFLICT`. [R5]
- When an action settles, the system shall return marker `RUNTIME_USAGE_SETTLED` after storing measured wall seconds, tokens and USD cost exactly once, including any measured overrun. [R6]
- The system shall return marker `RUNTIME_SESSION_INCOMPLETE` and status `INCOMPLETE` for malformed passport JSON, a non-object passport, an invalid or missing manifest, or a manifest digest mismatch; admission shall be rejected. [R7]
- If measured usage exceeds configured budget, the system shall return marker `RUNTIME_OVERRUN_RECORDED` after storing actuals, returning `BUDGET_EXCEEDED` and rejecting any subsequent admission request for that run. [R8]
- When concurrent admission requests target one run, the system shall return marker `RUNTIME_RESERVATIONS_SERIALIZED` after revalidating the passport and session, checking idempotency, aggregating usage, comparing all budgets, and inserting the reservation inside the same SQLite `BEGIN IMMEDIATE` transaction; a run with an unresolved reservation returns `ACTION_IN_PROGRESS` and creates no second reservation, while denial or error leaves no partial reservation. [R9]
- The system shall return marker `RUNTIME_ADAPTER_SCOPE_NOTICE` with the notice `Adapters must call admission before work and settle afterward.` [R10]
- The system shall return marker `RUNTIME_ENROLLMENT_SCOPE_NOTICE` with the notice `Unenrolled adapters are outside enforcement.` [R11]
- The system shall return marker `RUNTIME_PROVIDER_BILLING_SCOPE_NOTICE` with the notice `Provider billing is not queried.` [R12]
- The system shall return marker `RUNTIME_LEDGER_SECRET_FREE` after storing no prompt, source text, credential or raw provider response in the ledger. [R13]
- When the system computes projected usage, it shall return marker `RUNTIME_USAGE_ACCOUNTING_EXACT` after calculating settled actual usage plus estimates for every unresolved action across all four dimensions using exact integer base units without floating-point rounding. [R14]
- When an action settlement is retried with identical measured values, the system shall return marker `RUNTIME_SETTLEMENT_IDEMPOTENT` with the original settlement receipt; changed values for that action shall return `ACTION_CONFLICT` without modifying totals. [R15]
- If the adapter execution exits with an unresolved action, the system shall return marker `RUNTIME_PENDING_PRESERVED` after retaining its full reservation across restart and returning `ACTION_IN_PROGRESS` for new admissions until settlement; no automatic refund or reset is allowed. [R16]
- When caller-supplied run or action identifiers are admitted, the system shall return marker `RUNTIME_IDENTIFIERS_OPAQUE` after validating each as exactly 32 lowercase hexadecimal characters and persisting only its SHA-256 digest. [R17]
- When a budget session is started again for the same loop id and run token, the system shall return marker `RUNTIME_SESSION_REPLAY_SAFE` with the existing session and totals if the passport digest matches, or `ACTION_CONFLICT` if it differs, without resetting ledger state. [R18]
- When an already-settled action is replayed through admission, the system shall return marker `RUNTIME_ACTION_ALREADY_SETTLED` with its settlement state; a blocked session shall return marker `RUNTIME_ACTION_REPLAY_BLOCKED` and never authorize work. [R19]
- The system shall include marker `RUNTIME_PASSPORT_CLAIMS_BOUND` only after passport loop id and budget claims match the exact manifest bytes bound by SHA256; mismatches return `INCOMPLETE`. [R20]
- The system shall include marker `RUNTIME_LEDGER_PATH_CONFINED` only when its resolved SQLite path is within the configured workspace and is not a symlink alias; an escaping or linked path returns `INCOMPLETE` with marker `RUNTIME_LEDGER_PATH_BLOCKED`. [R21]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: reserve a within-budget action
  Given a valid manifest and an active budget session
  When the adapter reserves one action within all four declared limits
  Then the result is ADMITTED and the reservation is durable before execution

Scenario: deny an over-budget action before execution
  Given settled usage and reservations are near a declared limit
  When a new reservation would exceed that limit
  Then the result is BUDGET_EXCEEDED and no reservation is created

Scenario: replay an idempotent request
  Given an action id was already admitted with the same estimate
  When the same request is submitted again
  Then the original admission is returned without double-counting

Scenario: reject changed input for a used action id
  Given an action id is already bound to an estimate
  When that id is submitted with a different estimate
  Then the result is ACTION_CONFLICT and ledger totals remain unchanged

Scenario: stop after measured overrun
  Given an admitted reservation
  When settlement reports actual usage above the manifest limit
  Then actual usage is preserved and later reservations are rejected

Scenario: refuse unknown usage
  Given an admitted action with marker `RUNTIME_PENDING_PRESERVED`
  When settlement omits a required measurement
  Then settlement returns INCOMPLETE and preserves the estimate
  And a different action returns ACTION_IN_PROGRESS
  And a complete settlement for the admitted action can reconcile the estimate

Scenario: refuse stale or malformed state
  Given a session is bound to a manifest digest
  When the manifest changes or session data cannot be validated
  Then the system reports INCOMPLETE and performs no admission

Scenario: refuse structurally invalid passport JSON
  Given a passport file contains malformed JSON, an array, or null
  When a runtime session is started
  Then the system returns INCOMPLETE with `RUNTIME_SESSION_INCOMPLETE`
  And no ledger session is created

Scenario: do not reauthorize settled or blocked action replays
  Given an action is settled or its runtime session is blocked
  When the same action admission is replayed
  Then a settled action returns its settlement state without ADMITTED
  And a blocked session returns its blocked status without authorizing work

Scenario: bind passport claims and ledger location
  Given a passport's self-hash is recomputed after changing its loop id or budget
  When runtime admission verifies the passport and manifest
  Then the mismatched claims are rejected
  And a ledger path resolved outside the configured workspace or aliased to another run returns `RUNTIME_LEDGER_PATH_BLOCKED`

Scenario: Every requirement has an observable acceptance marker
  Given the legacy `loop budget` command and `RUNTIME_BUDGET_LEGACY_PRESERVED`
  When a runtime session uses `RUNTIME_SESSION_PASSPORT_BOUND`
  Then action reservation returns `RUNTIME_ACTION_RESERVED`
  And budget rejection returns `RUNTIME_BUDGET_EXCEEDED`
  And identical replay returns `RUNTIME_ACTION_IDEMPOTENT`
  And settlement returns `RUNTIME_USAGE_SETTLED`
  And stale session rejection returns `RUNTIME_SESSION_INCOMPLETE`
  And measured overrun returns `RUNTIME_OVERRUN_RECORDED`
  And concurrent reservations return `RUNTIME_RESERVATIONS_SERIALIZED`
  And an unresolved reservation returns `ACTION_IN_PROGRESS`
  And the adapter scope notice returns `RUNTIME_ADAPTER_SCOPE_NOTICE`
  And the enrollment scope notice returns `RUNTIME_ENROLLMENT_SCOPE_NOTICE`
  And the billing scope notice returns `RUNTIME_PROVIDER_BILLING_SCOPE_NOTICE`
  And the privacy check returns `RUNTIME_LEDGER_SECRET_FREE`
  And exact usage aggregation returns `RUNTIME_USAGE_ACCOUNTING_EXACT`
  And settlement replay returns `RUNTIME_SETTLEMENT_IDEMPOTENT`
  And restart handling returns `RUNTIME_PENDING_PRESERVED`
  And identifier validation returns `RUNTIME_IDENTIFIERS_OPAQUE`
  And session replay returns `RUNTIME_SESSION_REPLAY_SAFE`
  And settled admission replay returns `RUNTIME_ACTION_ALREADY_SETTLED`
  And blocked admission replay returns `RUNTIME_ACTION_REPLAY_BLOCKED`
  And successful passport binding returns `RUNTIME_PASSPORT_CLAIMS_BOUND`
  And successful ledger containment returns `RUNTIME_LEDGER_PATH_CONFINED`

Scenario: Reconcile reserved and settled usage exactly
  Given an admitted action with estimate `RUNTIME_ACTION_RESERVED`
  When measured settlement returns `RUNTIME_USAGE_SETTLED`
  Then its estimate is atomically replaced by actual usage under `RUNTIME_USAGE_ACCOUNTING_EXACT`

Scenario: Preserve a pending reservation after process loss
  Given a run with `RUNTIME_PENDING_PRESERVED` and one unresolved action
  When the ledger is opened after restart
  Then the reservation remains counted and no new action is admitted until settlement

Scenario: Keep caller-controlled identifiers private
  Given a run id and action id validated by `RUNTIME_IDENTIFIERS_OPAQUE`
  When the ledger stores their identities
  Then it persists their SHA-256 digests and not their caller-supplied values
```

## SHOULD - Technical/structural
- ADR references: existing Loop Passport contract in `specs/loop-passport.ssat.yaml`.
- Data model facts: `manifest_valid`, `manifest_digest_matches`,
  `estimate_complete`, `action_id_exists`, `request_hash_matches`,
  `projected_usage_within_limits`, `settlement_complete`,
  `settlement_within_limits`, `unresolved_action_exists`,
  `settlement_action_exists`, `settlement_hash_matches`, and
  `transaction_available`, `passport_claims_match_manifest`,
  `resolved_ledger_path_within_root`, `admission_replay_exists`,
  `session_blocked`, and `action_settled`.
- Data model: session statuses are `ACTIVE`, `INCOMPLETE`, and
  `BUDGET_EXCEEDED`; action statuses are `ADMITTED`, `SETTLED`,
  `ACTION_IN_PROGRESS`, `INCOMPLETE`, `BUDGET_EXCEEDED`, and `ACTION_CONFLICT`;
  SQLite session and action ledger live under `.factory/loop-runs/`, with
  transactional writes, canonical request hashes, manifest SHA256, aggregate
  reserved/settled usage, explicit session and action state. Session status and
  action rows are mutable projections (`ADMITTED` to `SETTLED`); persisted
  admission and settlement receipts are snapshots. The ledger is durable, not
  an append-only event log.
- Usage invariant: for each of iterations, wall seconds, tokens, and USD,
  projected usage equals settled actuals plus estimates for unresolved actions.
  Settlement atomically replaces that action's estimate with measured actuals.
  A run has at most one unresolved action; its reservation persists across
  restart and blocks new admission until settlement, so process loss never
  refunds reserved budget.
- Numeric invariant: values are non-negative and normalized to signed-64-bit
  integer quanta: iterations and tokens are whole counts; wall seconds and USD
  cost have at most six fractional digits and use microseconds and micro-USD.
  Inputs with finer precision or values above the signed-64-bit integer-unit
  range are rejected; the system never rounds. Conversion is independent of
  the ambient Decimal precision context. JSON decimal tokens are parsed as
  `Decimal`, and Python API floats are interpreted through their shortest
  decimal string. Aggregation and comparisons use integer quanta. Receipts emit
  integral values as JSON integers and fractional wall or USD values as
  normalized base-10 strings so serialization remains exact.
- Identifier invariant: run and action ids match
  `[a-f0-9]{32}`, are nonsecret 128-bit CSPRNG tokens generated as
  `secrets.token_hex(16)`, and reject all other values. The ledger stores only
  SHA256 digests for caller-supplied run and action ids.
- Session identity invariant: `(loop_id, run_id_digest)` is unique. Replaying
  `start_budget_session` with the same manifest digest returns the existing
  receipt/status/totals; a changed manifest digest returns `ACTION_CONFLICT`
  and cannot create or reset a session.
- Settlement replay invariant: same action id and identical canonical measured
  values return the prior settlement receipt without accounting changes;
  changed values return `ACTION_CONFLICT`.
- API contract: `start_budget_session`, `admit_budget_action`,
  `settle_budget_action`, `budget_session_status`; CLI remains inside the
  existing `factory loop` group as `factory loop runtime session|admit|settle|status`.
- Supported metering dimensions: iterations, wall seconds, tokens and USD cost.
  Iterations are one per admitted action; estimates and actual measurements
  for the remaining dimensions are mandatory.
- Failure states are non-authoritative: they cannot authorize an operation,
  approve a change, merge, publish, deploy or query provider billing.
- Threat boundary: the ledger rejects statically linked paths and rechecks
  containment at open time. It is a local workspace integrity mechanism, not
  protection against a hostile process with concurrent write access to the same
  workspace; adapters must run with the workspace protected from such writers.

## SHOULD NOT - Implementation details
- Do not claim enforcement for adapters that do not call the admission API.
- Do not silently reset or refund an admitted reservation after process loss.
- Do not raise existing budget limits to make a run pass.
- Do not remove existing behavioral tests or loosen the 460 Python-file limit.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `manifest_valid` is false or `manifest_digest_matches` is false | return `INCOMPLETE`; refuse admission |
| 2 | `estimate_complete` is false | return `INCOMPLETE`; refuse admission |
| 3 | `action_id_exists` and `request_hash_matches` | return the original action result without a write |
| 4 | `action_id_exists` and `request_hash_matches` is false | return `ACTION_CONFLICT`; refuse admission |
| 5 | `projected_usage_within_limits` is false | return `BUDGET_EXCEEDED`; refuse admission |
| 6 | `unresolved_action_exists` | return `ACTION_IN_PROGRESS`; refuse another reservation |
| 7 | all admission facts pass and `transaction_available` is true | persist transactionally; return `ADMITTED` |
| 8 | `settlement_complete` is false | mark run `INCOMPLETE`; refuse future admissions |
| 9 | `settlement_action_exists` and `settlement_hash_matches` | return its original receipt without accounting changes |
| 10 | `settlement_action_exists` and `settlement_hash_matches` is false | return `ACTION_CONFLICT`; leave totals unchanged |
| 11 | `settlement_within_limits` is false | preserve measured values; mark `BUDGET_EXCEEDED` |
| 12 | `transaction_available` is false | return `INCOMPLETE`; authorize no external operation |
| 13 | `passport_claims_match_manifest` is false | return `INCOMPLETE`; authorize no external operation |
| 14 | `resolved_ledger_path_within_root` is false | return `INCOMPLETE`; create no database outside the workspace |
| 15 | `admission_replay_exists` and `session_blocked` | return blocked status; never authorize work |
| 16 | `admission_replay_exists` and `action_settled` | return settlement state without reserving again |
