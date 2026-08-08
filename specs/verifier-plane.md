# Spec: verifier-plane
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall add a local, supervised Verifier Plane contract for a
mission candidate. It lets a worker prepare a candidate snapshot and lets a
distinct verifier attest to deterministic evidence, immutable verifier-bundle
hashes, and an explicit terminal verdict. The feature does not execute a model,
inject credentials, run an untrusted sandbox, merge, publish, or deploy.

### User roles

- Mission owner: creates a bounded verifier session and resolves a stalled or
  revision-required result.
- Worker: prepares one candidate snapshot beneath the declared workspace.
- Verifier: records an evidence-bound verdict from a fresh, separate context.
- Release reviewer: consumes the verified receipt but retains release authority.

### Requirements (EARS)

- The system shall return marker `VERIFIER_SESSION_BOUND` and schema `factory.verifier-session.v1` only when mission, candidate-root, verifier-bundle, and hard-budget SHA-256 digests are beneath the selected repository root.
- The system shall enforce `worker-result-rejection-contract/v1` by returning marker `VERIFIER_WORKER_RESULT_REJECTED` after rejecting worker-result records with candidate-root escape, verifier-bundle digest drift, hard-budget excess, or unsupported terminal state.
- When a distinct verifier records a result, the system shall enforce `verifier-evidence-contract/v1` and return marker `VERIFIER_RESULT_BOUND` only with schema `factory.verifier-result.v1`, session, verifier-bundle, toolchain, and evidence digests, fresh isolated context, and verdict `passed`, `needs_revision`, `failed`, `stalled`, or `budget_exhausted`.
- When failure_signature_repeated=true and deterministic_progress=false, the system shall return marker `VERIFIER_PROGRESS_STALLED` with verdict `stalled` and owner-review-required=true.
- If `identity-gate/v1` detects identity_distinct=false, session_valid=false, or verifier_evidence_complete=false, the system shall return marker `VERIFIER_RESULT_REJECTED` with a machine-readable error.
- When an execution-harness attestation is supplied, the system shall return marker `VERIFIER_HARNESS_ATTESTATION_BOUND` after storing its digest and environment declaration in the verifier result.
- When `budget-limits/v1` receives session inputs with hard budgets, the system shall reject a value above max_attempts=5 attempts, max_wall_seconds=3600 seconds, max_tokens=100000 tokens, or max_cost_usd=25.0 dollars with `VERIFIER_WORKER_RESULT_REJECTED` before a passing result can be emitted.
- When parsing evidence, the system shall enforce `evidence-parser-limits/v1` by rejecting a non-empty verdict longer than 32, SHA-256 digest or mission identifier longer than 64, owner or identity longer than 96, field label or failure signature longer than 160, or relative path longer than 400 with `VERIFIER_RESULT_REJECTED`; the system shall store a 12-character session digest prefix in the filename.
- When `factory verifier verify` validates a supplied receipt, the system shall
  return `VERIFIER_RESULT_BOUND` and CLI exit code 0 only when the receipt is
  valid and shall return a non-zero CLI exit code after rejecting a receipt.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Separate worker and verifier evidence
  Given a mission, candidate root, and immutable verifier bundle under one root
  When a worker result and a distinct verifier result bind the same session
  Then the verified result carries both candidate and verifier-bundle digests
  And a passed verdict is evidence-bound but grants no merge or release authority

Scenario: Detect a stalled repair loop
  Given two failed attempts with the same failure signature
  And no passed checks, failed checks, or requirement coverage fields improve
  When progress is evaluated
  Then the recommendation is stalled and requires owner review

Scenario: Refuse an editable verifier
  Given a worker result whose verifier bundle digest differs from the session
  When the result is verified
  Then verification fails closed without a completion receipt

Scenario: Refuse hard-budget and parser overrun
  Given a worker result that exceeds max_tokens=100000
  When the verifier result is checked
  Then the command returns `VERIFIER_WORKER_RESULT_REJECTED`
  And a 97-character verifier identity returns `VERIFIER_RESULT_REJECTED`

Scenario: Emit a valid CLI result only for bound evidence
  Given a valid independent worker and verifier receipt
  When `factory verifier verify` is invoked
  Then it returns `VERIFIER_RESULT_BOUND` with CLI exit code 0

Scenario: Reject contract-specific invalid input
  Given `worker-result-rejection-contract/v1`, `verifier-evidence-contract/v1`, and `identity-gate/v1`
  When `budget-limits/v1` or `evidence-parser-limits/v1` is violated
  Then the verifier rejects the receipt

Scenario: reject strict Verifier Plane requirement mutations
  Given the verifier-plane contract
  When strict validator mutation runs
  Then contract markers include `VERIFIER_SESSION_BOUND`, `VERIFIER_WORKER_RESULT_REJECTED`, `VERIFIER_RESULT_BOUND`, `VERIFIER_PROGRESS_STALLED`, `VERIFIER_RESULT_REJECTED`, and `VERIFIER_HARNESS_ATTESTATION_BOUND`
```

## SHOULD - Technical and structural

- ADR references: ADR-0008 Product Missions value compiler
- Data model: `factory.verifier-session.v1`, `factory.verifier-worker-result.v1`,
  `factory.verifier-result.v1`, `factory.verifier-progress.v1`
- API contract: `factory verifier session|verify|progress --root . --json`
- Decision facts: `session_valid: boolean`, `identity_distinct: boolean`,
  `budget_exceeded: boolean`, `failure_signature_repeated: boolean`,
  `deterministic_progress: boolean`, `required_checks_passed: boolean`, and
  `verifier_evidence_complete: boolean`.

## SHOULD NOT - Implementation details

- The feature shall not introduce a model provider dependency, a Docker
  dependency, implicit network access, a credential store, or automatic release
  authority.
- An LLM rubric can be attached as evidence but shall never override a failing
  compiler, test, policy, or schema verifier.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | session_valid=false or identity_distinct=false | reject the result |
| 2 | budget_exceeded=true | return `budget_exhausted` |
| 3 | failure_signature_repeated=true and deterministic_progress=false | return `stalled` |
| 4 | verifier_evidence_complete=true and required_checks_passed=true | return `passed` |
| 5 | verifier_evidence_complete=true and required_checks_passed=false | return `needs_revision` |
| 6 | `VERIFIER_SESSION_BOUND` | create a hash-bound session |
| 7 | `VERIFIER_WORKER_RESULT_REJECTED` | reject the worker result |
| 8 | `VERIFIER_RESULT_BOUND` | bind independent verifier evidence |
| 9 | `VERIFIER_PROGRESS_STALLED` | require owner review |
| 10 | `VERIFIER_RESULT_REJECTED` | reject malformed verifier evidence |
| 11 | `VERIFIER_HARNESS_ATTESTATION_BOUND` | bind external harness evidence |
