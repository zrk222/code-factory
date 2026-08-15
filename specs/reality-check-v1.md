# Spec: reality-check-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Reality Check binds one declared user-visible behavior to an approved positive
and negative E2E command pair. Intent inspection proves that the contract names
at least one success assertion and one failure assertion before execution. A
named human may authorize one exact receipt-bound re-run, but neither Graph Ops
nor Reality Check can design tests, repair source, merge, publish, or deploy.

### Requirements (EARS)

- When a Reality Check manifest omits a named promise, happy path, failure case, approved reviewer, workspace-contained E2E manifest, or 2 through 16 unique assertions containing both positive and negative evidence targets, the system shall reject the request before running a command.
- When the operator runs intent inspection on a valid Reality Check manifest, the system shall return the contract marker, assertion count, and positive and negative assertion identifiers without running a command.
- When the runner starts with a valid approved manifest, the system shall return the result of only the approved positive and negative argv arrays.
- When a Reality Check receipt is written, the system shall write one SHA-256-bound behavior receipt containing the public E2E result and one verification result for every declared intent assertion.
- When the negative command exits zero, the system shall return a hollow result with a non-passing status.
- When a named reviewer supplies the exact confirmation `AUTHORIZE run-approval`, an expiry at most 7 days after issuance, and a valid selected node, the system shall write one authorization receipt bound to the exact node and source bytes.
- When an approved authorization with an expiry at most 7 days after issuance is bound to a verified Reality Check receipt and its manifest bytes still match, the system shall execute the exact declared Reality Check one time, write the output proof card, and return the authorization as consumed.
- If a Graph Ops authorization has a state other than approved, an expiry timestamp earlier than issuance plus 7 days, malformed fields, an ineligible selected node, or a receipt or manifest SHA-256 mismatch, the system shall reject the execution request before running a command.
- When Graph Ops reads a stored Reality Check or authorization receipt, the system shall render the typed node and return without executing a command.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A valid behavior contract is inspected then independently exercised
  Given an approved Reality Check manifest has one positive and one negative intent assertion
  And its approved E2E positive command exits zero
  And its approved E2E negative command exits non-zero
  When the operator inspects then verifies the Reality Check
  Then intent inspection returns a contract-ready result without execution
  And verification returns a verified hash-bound receipt
  And every declared intent assertion is marked verified

Scenario: A named authorization executes only its exact sealed Reality Check once
  Given a verified Reality Check receipt and a named reviewer who supplies the required confirmation
  When Graph Ops records a one-hour reality_check_execution authorization
  And the reviewer confirms the authorized run
  Then the system records one authorization receipt
  And it runs only the receipt-bound manifest once
  And it marks the authorization consumed

Scenario: A negative path falsely passes or an authorization becomes stale
  Given a Reality Check negative command exits zero or its bound manifest bytes change
  When the operator attempts verification or authorized execution
  Then the system returns a non-passing behavior result or rejects the stale authorization
  And it does not repair, merge, publish, deploy, sign, message, or access credentials
```

## SHOULD - Technical and structural

- Data model: `factory.reality-check-manifest.v1`,
  `factory.reality-check-receipt.v1`, and
  `factory.graph-ops-authorization.v1`.
- Graph Ops shall expose novice-safe plain-language next action copy, team named
  approvals with expiry, and enterprise-readable hash, source, and authority
  facts through the same typed graph.

## SHOULD NOT - Implementation details

- The feature should not generate tests, create browser automation, host an
  application, infer production readiness, repair source, apply a repair plan,
  merge, publish, deploy, sign, message, access credentials, or grant
  connectors.
