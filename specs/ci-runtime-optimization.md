# Spec: ci-runtime-optimization
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Reduce Code Factory's CI latency without weakening package, verifier, or
cross-IDE compatibility evidence. Contributors receive faster feedback while
release maintainers retain one verified, immutable plugin package per run.

### User roles
- Contributor: needs dependable PR feedback.
- Release maintainer: needs each declared JetBrains IDE compatibility gate to
  verify the exact packaged plugin candidate.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall store Python package-download cache entries
  for every Python test-matrix job.
- When an IntelliJ compatibility job starts, the system shall store the
  candidate plugin archive path produced by the required package-and-verify job.
- The system shall emit a verification result for every selected compatibility
  product from the selected plugin archive and shall not execute buildPlugin in
  a compatibility job.
- If plugin archive selection returns a count other than one, the system shall
  reject the compatibility job before it executes verification.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: verify the single packaged plugin across the compatibility matrix
  Given the package-and-verify job has uploaded exactly one plugin archive
  When a compatibility job starts for a selected compatibility product
  Then it executes verification with that plugin archive without running buildPlugin

Scenario: refuse a missing package artifact
  Given the package artifact download contains zero or multiple plugin archives
  When a compatibility job starts
  Then the job fails before the verifier can run
```

## SHOULD — Technical/structural
- ADR references: no architecture decision required; this is CI evidence reuse.
- Data model: `plugin archive` is a ZIP file in the immutable Actions artifact;
  `plugin archive count` is the number of matching files; `compatibility
  product` is one matrix target; `compatibility job` is the matrix execution.
- API contract: Gradle property `factorylineVerificationArchive` maps to the
  IntelliJ Platform Gradle Plugin's `verifyPlugin.archiveFile` input.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
This feature has no HSF business-decision candidate. It reuses an immutable CI
artifact, runs a declared verification matrix, and fails closed on ambiguous
artifact input. Publication and all external effects remain human-controlled.
