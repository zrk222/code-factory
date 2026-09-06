# Spec: jetbrains-marketplace-admission-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Move JetBrains Marketplace protected-environment credential admission ahead of
checkout, Marketplace status lookup, Java setup, Gradle work, packaging, and
compatibility verification. Extend local release-route integrity so this
ordering remains a deterministic preflight rather than another late provider
workflow failure. The inspection observes declared workflow text only; it does
not inspect a secret or call JetBrains.

### User roles

- Maintainer: gets an early actionable failure when the protected release
  environment is not prepared, rather than after candidate work completes.
- Connected coding agent: reads the local preflight but cannot access a
  credential, dispatch a workflow, publish a plugin, or alter approval state.
- Reviewer: verifies that credential admission is separate from the external
  Marketplace binary-update-slot and moderation decisions.

### Requirements (EARS)

- When `JETBRAINS_AUTH_ROUTE_READ` reads the declared Marketplace workflow, the system shall return `JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY` only when an `authorize` job uses the `jetbrains-marketplace` environment and checks `JETBRAINS_MARKETPLACE_TOKEN` before candidate validation. [R1]
- When `JETBRAINS_ROUTE_DEPENDENCY_READ` reads the declared Marketplace workflow, the system shall return `JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY` only when `validate` depends on `authorize` and `publish` depends on successful `authorize`, `validate`, and `compatibility` jobs. [R2]
- If `JETBRAINS_ROUTE_MUTATED` removes protected environment assignment, token checking, the validate authorization dependency, or the publish authorization dependency, the system shall return `JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY` and `repair_release_workflow`. [R3]
- When `JETBRAINS_ROUTE_READ` reads the complete declared workflow, the system shall preserve `JETBRAINS_APPROVAL_GUARD` before Java or Gradle setup and `JETBRAINS_JDK21_EXACT` for all declared IntelliJ Java setup steps. [R4]
- When `JETBRAINS_EXTERNAL_REQUIREMENTS_READ` reads release-integrity or the Graph Ops release-decision node, the system shall list protected JetBrains credential admission and Marketplace binary-update-slot approval as declared external requirements while retaining `provider_state=unobserved`. [R5]
- When `JETBRAINS_AUTHORITY_READ` reads any local route result, the system shall retain zero authority for execution, approval, repair, merge, publication, deployment, signing, messaging, credential, and connector operations. [R6]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: credential admission occurs before candidate work
  Given JETBRAINS_AUTH_ROUTE_READ reads the declared Marketplace workflow
  When the protected environment checks the publisher token
  Then JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY passes

Scenario: validation cannot bypass authorization
  Given JETBRAINS_ROUTE_DEPENDENCY_READ reads the declared Marketplace workflow
  When validate depends on authorize and publish depends on all prior jobs
  Then JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY passes

Scenario: missing authorizer dependency blocks the route
  Given JETBRAINS_ROUTE_MUTATED removes the validate authorization dependency
  When release integrity is evaluated
  Then JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY fails

Scenario: JDK and Marketplace slot checks remain ordered
  Given JETBRAINS_ROUTE_READ reads the complete declared workflow
  When release integrity is evaluated
  Then JETBRAINS_APPROVAL_GUARD and JETBRAINS_JDK21_EXACT pass

Scenario: external state remains unobserved
  Given JETBRAINS_EXTERNAL_REQUIREMENTS_READ reads a healthy workspace
  When Graph Ops returns the release decision node
  Then provider_state is unobserved

Scenario: local inspection has no authority
  Given JETBRAINS_AUTHORITY_READ reads release integrity
  When a connected agent requests the result
  Then execution, approval, repair, merge, publication, deployment, signing, messaging, credential, and connector authority are false
```

## SHOULD - Technical and structural

- ADR references: `release_route_integrity`, `release_integrity`,
  release-decision card, JetBrains Marketplace workflow, and Graph Ops.
- Data model: add `JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY` immediately
  before `JETBRAINS_JDK21_EXACT` in ordered release checks.
- Runtime declaration: every inspected `actions/setup-java@v5` block must
  contain exactly one `java-version` value, and that value is the string `21`.
- Deterministic ordering: protected credential admission precedes validation;
  validation precedes compatibility; all three precede publication.

## SHOULD NOT - Implementation details

- Do not read, emit, persist, or infer a token value.
- Do not query the Marketplace API, inspect the upload slot, dispatch GitHub
  Actions, run Java or Gradle, or publish a plugin.
- Do not treat a declared protected environment as evidence that an approver,
  credential, binary-update slot, Marketplace processing, or moderation state
  is currently available.
