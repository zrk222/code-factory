# AppForge Evidence Kit v1

## Intent

Reduce AppForge iOS release-preparation ceremony without permitting a template,
agent assertion, or source-only observation to become release evidence.

## MUST — Functional core

### Requirements

- When AppForge Init receives all eight mission and candidate inputs, the system shall write one candidate file, one user-design-input file, one design brief, and one next-actions file in a new workspace directory.
- When an evidence-kit request omits bundle identifier, version, build number, or source commit, the system shall reject the request with a candidate error.
- When an evidence kit is created, the system shall store the SHA-256 digest of the supplied user design input in the Store-media and quality contracts.
- When an evidence kit is created, the system shall write four candidate-bound templates: App Review, Store media, strict UX/full-stack audit, and assurance.
- When an evidence kit is created, the system shall write `user_design_input_considered: false` in its quality evidence template.
- When an evidence kit is created, the system shall write exactly two media sets requiring ten iPhone journeys and three 13-inch iPad journeys.
- If a requested path is outside the workspace or the destination exists, the system shall reject the request and preserve existing files byte-for-byte.
- If a request asks the evidence kit to access credentials, run a device, contact Apple, upload media, submit an app, or claim approval, the system shall reject the request as outside AppForge Evidence Kit authority.

## Acceptance scenarios

```gherkin
Scenario: Create a safe evidence kit
  Given a schema-valid release candidate and local user design input
  When AppForge creates an evidence kit in a new workspace directory
  Then every template is bound to that same candidate and design-input digest
  And the quality evidence template keeps design confirmation false
  And the Store media contract requires ten iPhone and three 13-inch iPad journeys

Scenario: Refuse a stale or unsafe destination
  Given an evidence-kit destination already exists
  When AppForge is asked to create another kit in that destination
  Then it refuses without overwriting any existing files
```

## Boundaries

The evidence kit is a local setup utility, not a screenshot generator, device
test runner, credential manager, TestFlight uploader, App Review submitter, or
Apple certification system.
