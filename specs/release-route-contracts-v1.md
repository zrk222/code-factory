# Spec: release-route-contracts-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Make the local release-integrity inspection cover the three declared workflow
boundaries that previously produce avoidable release-run failures: protected
Visual Studio Marketplace authorization, sealed VSIX candidate promotion, and
the Java 21 requirement for every declared IntelliJ Gradle workflow job. The
inspection is a static, read-only route preflight. It does not read secrets,
run a workflow, contact a marketplace, or assert that any external gate is
available.

### User roles

- Maintainer: finds the earliest locally repairable route defect before
  initiating a provider workflow.
- Connected coding agent: reads the same route facts but cannot obtain a
  credential, execute a workflow, upload a package, or change a release.
- Reviewer: sees which route prerequisites are declared locally and which
  external gates still remain unobserved.

### Requirements (EARS)

- When `VSCODE_AUTH_ROUTE_READ` reads the declared Visual Studio Marketplace workflow, the system shall return `VSCODE_MARKETPLACE_AUTHORIZATION_EARLY` only when a `publish=true` request requires the `vscode-marketplace` environment and `VSCE_PAT` before candidate validation. [R1]
- When `VSCODE_CANDIDATE_ROUTE_READ` reads the declared Visual Studio Marketplace workflow, the system shall return `VSCODE_MARKETPLACE_CANDIDATE_SEALED` only when the publish job depends on successful authorization and validation and verifies the candidate checksum, publisher `zrk222`, extension `factoryline-vscode`, and VSIX artifact before invoking VSCE. [R2]
- When `INTELLIJ_JAVA_ROUTE_READ` reads `intellij-plugin.yml` and `jetbrains-marketplace.yml`, the system shall return `JETBRAINS_JDK21_EXACT` only when every declared `actions/setup-java@v5` step configures `java-version: "21"`. [R3]
- If `VSCODE_ROUTE_MUTATED` removes any required R1 or R2 condition, the system shall return the corresponding failed check identifier and `repair_release_workflow`. [R4]
- If `INTELLIJ_JAVA_ROUTE_MUTATED` changes any declared Java setup step to a version other than `21`, the system shall return `JETBRAINS_JDK21_EXACT` and `repair_release_workflow`. [R5]
- When `RELEASE_ROUTE_GUIDANCE_READ` reads a healthy release-decision Graph Ops node, the node shall expose all declared external route requirements, keep `provider_state=unobserved`, and preserve zero authority for execution, approval, repair, merge, publication, deployment, signing, messaging, credential, and connector operations. [R6]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: healthy static marketplace route is recognized
  Given VSCODE_AUTH_ROUTE_READ reads the declared workflow
  When the workflow requires protected authorization before validation
  Then VSCODE_MARKETPLACE_AUTHORIZATION_EARLY passes

Scenario: candidate seal is required before VSCE publication
  Given VSCODE_CANDIDATE_ROUTE_READ reads the declared workflow
  When the publish job verifies the sealed candidate
  Then VSCODE_MARKETPLACE_CANDIDATE_SEALED passes

Scenario: Java 21 remains the declared IntelliJ runtime
  Given INTELLIJ_JAVA_ROUTE_READ reads both IntelliJ workflows
  When every Java setup step requests version 21
  Then JETBRAINS_JDK21_EXACT passes

Scenario: VSCE authorization moves after validation
  Given VSCODE_ROUTE_MUTATED removes the validation dependency on authorization
  When release integrity is evaluated
  Then VSCODE_MARKETPLACE_AUTHORIZATION_EARLY fails

Scenario: candidate identity verification is removed
  Given VSCODE_ROUTE_MUTATED removes publisher zrk222 verification
  When release integrity is evaluated
  Then VSCODE_MARKETPLACE_CANDIDATE_SEALED fails

Scenario: an IntelliJ route regresses to Java 17
  Given INTELLIJ_JAVA_ROUTE_MUTATED changes one Java setup step to version 17
  When release integrity is evaluated
  Then JETBRAINS_JDK21_EXACT fails

Scenario: Graph Ops preserves the provider boundary
  Given RELEASE_ROUTE_GUIDANCE_READ reads a healthy workspace
  When Graph Ops returns the release decision node
  Then provider_state is unobserved and authority remains zero
```

## SHOULD - Technical and structural

- ADR references: existing `release_integrity`, release-decision card,
  Mission Control, Graph Ops, and declared GitHub Actions workflow boundaries.
- Data model: add exactly three ordered checks after
  `OPENVSX_AUTHORIZATION_EARLY` and before `PYPI_TRUSTED_PUBLISHING`; expose
  the static external requirements through the release-decision graph facts.
- Deterministic ordering: release checks retain their declared source order;
  the external-requirements list retains its declaration order.

## SHOULD NOT - Implementation details

- Do not inspect, store, print, or infer any credential value.
- Do not invoke GitHub Actions, VSCE, Java, Gradle, Node, or a provider API.
- Do not claim that a protected environment is approved, configured, or
  available because workflow text names it.
- Do not turn local route results into publication, deployment, provider,
  processing, or approval evidence.
