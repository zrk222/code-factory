# Spec: proof-reuse-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall compute content-addressed proof keys, route read-only gates
as RUN, REUSE, SKIP, or BLOCK, reject stale or side-effecting reuse, and emit
compact proof-plan receipts. Exact verified reuse may automatically create an
existing `factory.savings-pair.v1` receipt using the original full-run
observation and the measured reuse-routing observation.

### User roles

- Local developer planning the minimum safe proof set.
- CI workflow deduplicating identical validation across triggers.
- Coding agent consuming compact evidence instead of raw logs.
- Release reviewer verifying that side effects are never reused.

### Requirements (EARS)

- The system shall return marker `PROOF_KEY_CONTENT_ADDRESSED` with a SHA-256 derived from schema version, gate name, normalized command argv, relevant input file paths and SHA-256 values, toolchain identifiers, and environment identifiers. [R1]
- The system shall return marker `PROOF_PLAN_DISPOSITION_EXACT` with schema `factory.proof-plan.v1` and exactly 1 disposition from RUN, REUSE, SKIP, or BLOCK for every requested gate. [R2]
- If a gate is not explicitly read-only, the system shall return BLOCK with marker `PROOF_SIDE_EFFECT_REUSE_REFUSED`. [R3]
- If any declared input is missing, outside the workspace, not a regular file, or changes after proof recording, the system shall return marker `PROOF_INPUT_INTEGRITY_REQUIRED` with RUN or BLOCK and shall not return REUSE. [R4]
- When a green receipt has the exact proof key and all current input, output, toolchain, environment, and receipt hashes verify, the system shall return REUSE with marker `PROOF_RECEIPT_REUSED`. [R5]
- When no exact verified receipt exists for an affected read-only gate, the system shall return RUN with marker `PROOF_EXECUTION_REQUIRED`. [R6]
- When the reviewed relevance matcher returns `unaffected` for supplied changed paths, the system shall return SKIP with marker `PROOF_IRRELEVANT_CHANGE`. [R7]
- If relevance evidence is absent or ambiguous, the system shall return marker `PROOF_RELEVANCE_FAIL_CLOSED` with RUN rather than SKIP. [R8]
- When a proof is recorded, the system shall return marker `PROOF_RECEIPT_ATOMIC` after atomically writing exactly 1 private receipt under `.factory/proofs/` using schema `factory.proof-receipt.v1`. [R9]
- When a plan is created, the system shall return marker `PROOF_PLAN_COMPACT` after atomically writing exactly 1 compact receipt under `.factory/proof-plans/` without command output, source bodies, prompts, logs, credentials, or absolute workspace paths. [R10]
- When automatic savings eligibility is `eligible`, the system shall return marker `PROOF_AUTO_SAVINGS_EXACT` after creating a paired savings receipt from measured baseline and routing elapsed milliseconds. [R11]
- If token observations are absent on either side, the system shall return marker `PROOF_TOKEN_SAVINGS_UNKNOWN` with token savings null. [R12]
- When proof challenge mutates 1 declared input in an isolated temporary workspace, the system shall return marker `PROOF_MUTATION_REJECTED` only if the original receipt fails verification and the disposition is not REUSE. [R13]
- The system shall return marker `PROOF_PUBLICATION_AUTHORITY_UNCHANGED` because proof reuse shall never publish, deploy, sign, approve, send messages, discover credentials, or perform other external side effects. [R14]
- The system shall return marker `PROOF_CI_SHA_DEDUPLICATED` after the IntelliJ workflow restricts push validation to branch `main`, retains pull-request validation, and uses a SHA-keyed concurrency group with cancellation. [R15]
- The system shall return marker `RELEASE_023_SYNCHRONIZED` after identifying version 0.23.0 in package, runtime, citation, archive, hosted, editor, documentation, and release metadata. [R16]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Reuse an exact green read-only proof
  Given a green read-only proof with unchanged inputs, outputs, toolchain, and environment
  When the proof manifest is planned again
  Then the disposition is REUSE
  And marker `PROOF_RECEIPT_REUSED` is present

Scenario: Fail closed after input mutation
  Given a previously reusable proof receipt
  When 1 declared input byte changes
  Then the receipt fails verification
  And the disposition is RUN rather than REUSE

Scenario: Refuse side-effect reuse
  Given a publish gate with read_only false
  When the proof manifest is planned
  Then the disposition is BLOCK
  And no command executes

Scenario: Skip a reviewed unaffected gate
  Given supplied changed paths
  And the reviewed relevance matcher returns `unaffected`
  When the proof manifest is planned
  Then the disposition is SKIP
  And marker `PROOF_IRRELEVANT_CHANGE` is present

Scenario: Record an exact automatic savings pair
  Given automatic savings eligibility is `eligible`
  And a verified REUSE observation
  And measured baseline elapsed time 600000 milliseconds
  And measured routing elapsed time 1000 milliseconds
  When automatic savings is enabled
  Then exactly 1 `factory.savings-pair.v1` receipt is written
  And time saved is 599000 milliseconds
  And marker `PROOF_AUTO_SAVINGS_EXACT` is present

Scenario: Every requirement has an observable validator marker
  Given the Proof Reuse contract
  When strict validator mutation runs
  Then contract markers include `PROOF_KEY_CONTENT_ADDRESSED`, `PROOF_PLAN_DISPOSITION_EXACT`, `PROOF_SIDE_EFFECT_REUSE_REFUSED`, `PROOF_INPUT_INTEGRITY_REQUIRED`, `PROOF_RECEIPT_REUSED`, `PROOF_EXECUTION_REQUIRED`, `PROOF_IRRELEVANT_CHANGE`, `PROOF_RELEVANCE_FAIL_CLOSED`, `PROOF_RECEIPT_ATOMIC`, `PROOF_PLAN_COMPACT`, `PROOF_AUTO_SAVINGS_EXACT`, `PROOF_TOKEN_SAVINGS_UNKNOWN`, `PROOF_MUTATION_REJECTED`, `PROOF_PUBLICATION_AUTHORITY_UNCHANGED`, `PROOF_CI_SHA_DEDUPLICATED`, and `RELEASE_023_SYNCHRONIZED`
```

## SHOULD - Technical/structural

- ADR reference: `adr/proof-reuse-v1.md`.
- Data models: `factory.proof-request.v1`, `factory.proof-receipt.v1`, and `factory.proof-plan.v1`.
- API contract: `factory proofs record|plan|verify|challenge`.
- Manifests, receipts, and canonical hash inputs shall use UTF-8 encoding.
- Automatic savings identifiers shall use the first 16 hexadecimal characters
  of the proof key plus a local nanosecond suffix; the full proof key remains
  present in the bound equivalence evidence.

## SHOULD NOT - Implementation details

- Do not cache or replay external side effects.
- Do not infer relevance solely from file extensions when a gate requests SKIP.
- Do not treat GitHub Actions duration history as prospective savings.
- Do not include raw commands, logs, source contents, credentials, prompts, or absolute paths in public plan receipts.
- Do not add a third-party runtime dependency.

## Decision logic (factory candidates)

The ordered routing policy is handed off as the executable requirements R3
through R8. Its reviewed facts are `read_only`, `input_valid`, `skip_proven`,
and `receipt_valid`; mutation tests must reject every deleted or inverted rule.
