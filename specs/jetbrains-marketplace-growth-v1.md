# Spec: jetbrains-marketplace-growth-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Make the JetBrains plugin understandable and useful on first launch for developers
who want local, evidence-backed checks for AI-assisted code. The public listing
uses outcome-led language and real product evidence. Growth is measured from the
2026-08-01 Marketplace baseline of 46 downloads; no causal lift is claimed without
Marketplace analytics.

### User roles
- JetBrains developer evaluating the plugin
- Installed user running a first local proof
- Maintainer publishing through the protected Marketplace workflow

### Requirements (EARS)
- The system shall return `STABLE_MARKETPLACE_ID` only when the packaged descriptor contains `app.factoryline` and the unique, 20-character name `FactoryLine AI Proof`.
- The system shall emit `OUTCOME_LED_PREVIEW` only when the Marketplace preview begins with `Verify AI code before you ship.` and contains no unverifiable claim.
- The system shall emit a workspace confirmation before it can return `FIRST_PROOF_RESULT` from exactly `factory doctor --json` in the current project.
- When the first proof completes, the plugin shall emit `REDACTED_LOCAL_RESULT` in the FactoryLine tool window.
- If the workspace or executable is unavailable, the plugin shall reject execution with `FIRST_PROOF_BLOCKED` and show a local error.
- The system shall store `REAL_SCREENSHOT_BRIEF` only when the brief requires real default-theme JetBrains UI at 1200x760 or larger and rejects stale version or metric claims.
- The system shall emit `PRICING_NOTICE_BOUNDED` only when public copy says all features are free through 2026-12-31, labels the 2027 price as planned, and stores reproducible sample arithmetic without claiming that price is active.
- The system shall reject publication outside the protected GitHub environment and JetBrains moderation boundary with `HUMAN_PUBLICATION_REQUIRED`.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: A new user runs a first proof
  Given FactoryLine AI Proof is installed in a local JetBrains project
  When the user confirms Run First Proof
  Then the plugin executes exactly factory doctor --json in that project
  And shows the redacted result in the FactoryLine tool window
  And the result emits `FIRST_PROOF_RESULT`

Scenario: A user declines the local command
  Given FactoryLine AI Proof is installed in a local JetBrains project
  When the user cancels Run First Proof confirmation
  Then factory doctor does not execute
  And the result emits `FIRST_PROOF_BLOCKED`

Scenario: The Marketplace listing is previewed
  Given the plugin descriptor is packaged
  When Marketplace reads its name and description
  Then the name is FactoryLine AI Proof and the first sentence is Verify AI code before you ship.
  And the stable plugin ID remains app.factoryline
  And the result emits `OUTCOME_LED_PREVIEW`

Scenario: Planned pricing is disclosed without claiming activation
  Given the plugin remains free and paid-plugin onboarding is incomplete
  When the public pricing notice is inspected
  Then it states that all features are free through December 31, 2026
  And it labels the January 1, 2027 price as planned and subject to JetBrains approval
  And the result emits `PRICING_NOTICE_BOUNDED`

Scenario: Every requirement has an observable validator marker
  Given the FactoryLine AI Proof contract
  When strict validator mutation runs
  Then contract markers include `STABLE_MARKETPLACE_ID`, `OUTCOME_LED_PREVIEW`, `FIRST_PROOF_RESULT`, `REDACTED_LOCAL_RESULT`, `FIRST_PROOF_BLOCKED`, `REAL_SCREENSHOT_BRIEF`, `PRICING_NOTICE_BOUNDED`, and `HUMAN_PUBLICATION_REQUIRED`
```

## SHOULD - Technical/structural
- ADR references: protected JetBrains publication workflow and hash-bound release manifest
- Data model: no new persistent data
- API contract: `FactoryLineCommands.firstProof() -> ["doctor", "--json"]`

## SHOULD NOT - Implementation details
- Do not change the plugin ID, collect source code, add credentials, promise download lift, or publish before tests and protected approval.

## Decision logic (factory candidates)

This feature has no HSF business-decision candidate. It validates static listing
metadata, a bounded local command, and a human-controlled publication gate.
