# Spec: jetbrains-monetization-2027-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Prepare FactoryLine AI Proof for a human-controlled conversion from free to paid
on January 1, 2027 at exactly USD 4.95 per month. The active 0.7.2 descriptor
must remain free; paid descriptor and licensing changes are staged artifacts only
until the launch gate is approved.

### User roles

- Existing free user who needs advance notice
- New buyer evaluating price, trial, privacy, and support
- Maintainer preparing the paid binary and Marketplace sales record
- JetBrains reviewer approving listing, binary, and payment-model changes

### Requirements (EARS)

- The system shall emit `OWNER_PRICE_LOCKED` only when every public monetization artifact identifies USD 4.95 as the monthly launch price effective 2027-01-01.
- The system shall emit `FREE_PERIOD_PRESERVED` only when public copy states all current features remain free through 2026-12-31 and the active 0.7.2 descriptor contains no `product-descriptor`.
- The system shall store `PAID_DESCRIPTOR_STAGED` only when an inactive template contains proposed Product Code `PFACTORYLINE`, release date `20270101`, release version `20271`, paid mode `optional=false`, and target plugin version `2027.1.0`.
- The system shall emit `LICENSE_GATE_REQUIRED` only when the launch runbook blocks activation until JetBrains license verification passes for licensed, trial, unlicensed, offline-license, and uninitialized-facade states.
- The system shall emit `ADVANCE_NOTICE_COMPLETE` only when listing, README, upgrade FAQ, feature boundary, trial, price, effective date, customer contact `rkatz22@gmail.com`, no-SLA disclosure, and open-source implications are documented.
- The system shall return `MARKETPLACE_UPDATE_PENDING` with exit code 3 whenever Marketplace plugin 33009 reports `approve=false` or `hasUnapprovedUpdate=true`.
- The system shall return `MARKETPLACE_UPDATE_CLEAR` with exit code 0 only if Marketplace plugin 33009 reports `approve=true`, `hasUnapprovedUpdate=false`, and the expected version is approved and listed.
- The system shall reject January activation with `MONETIZATION_GATE_BLOCKED` unless trader/banking details, Product Code registration, paid-plugin approval, sales fields, licensing tests, artifact verification, the published customer-contact address, no-SLA disclosure, and a named rollback decision owner are evidenced.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: The approved price is published as a future change
  Given the Marketplace plugin is still free
  When a user reads any monetization document or listing notice
  Then the monthly launch price is USD 4.95
  And the effective date is January 1, 2027
  And the result emits `OWNER_PRICE_LOCKED`

Scenario: Paid metadata cannot activate early
  Given version 0.7.2 is the active free descriptor
  When publication metadata is tested before January 1, 2027
  Then plugin.xml has no product-descriptor
  And the paid descriptor exists only in the monetization staging directory
  And the result emits `FREE_PERIOD_PRESERVED`

Scenario: Rejected metadata blocks another submission
  Given plugin 33009 has approve false and hasUnapprovedUpdate false
  When the status checker runs with require-clear
  Then it exits 3
  And emits `MARKETPLACE_UPDATE_PENDING`

Scenario: A pending Marketplace draft blocks another submission
  Given plugin 33009 has approve true and hasUnapprovedUpdate true
  When the status checker runs with require-clear
  Then it exits 3
  And emits `MARKETPLACE_UPDATE_PENDING`

Scenario: Approved metadata and expected version clear publication
  Given plugin 33009 has approve true and hasUnapprovedUpdate false
  And expected version 0.7.2 is approved and listed
  When the status checker runs with require-clear
  Then it exits 0
  And emits `MARKETPLACE_UPDATE_CLEAR`

Scenario: The launch gate is reviewable
  Given the January launch manifest
  When each required evidence field is inspected
  Then no human-owned Marketplace or banking step is marked complete without a receipt
  And the result emits `MONETIZATION_GATE_BLOCKED` until every gate is satisfied

Scenario: Every requirement has an observable validator marker
  Given the JetBrains monetization contract
  When strict validator mutation runs
  Then contract markers include `OWNER_PRICE_LOCKED`, `FREE_PERIOD_PRESERVED`, `PAID_DESCRIPTOR_STAGED`, `LICENSE_GATE_REQUIRED`, `ADVANCE_NOTICE_COMPLETE`, `MARKETPLACE_UPDATE_PENDING`, `MARKETPLACE_UPDATE_CLEAR`, and `MONETIZATION_GATE_BLOCKED`
```

## SHOULD - Technical and structural

- Data model: `factory.jetbrains-monetization-plan.v1` and `factory.jetbrains-marketplace-status.v1`.
- API: public JetBrains plugin and update JSON endpoints for plugin 33009.
- Governance: `human_controlled` until a paid binary, vendor sales record, license tests, and public approval receipts exist.

## SHOULD NOT - Implementation details

- Do not add the paid product descriptor to active plugin.xml, create banking or trader records, send support mail, fabricate Product Code registration, or claim the January price is currently active.

## Decision logic (factory candidates)

This feature has no autonomous business-decision candidate. The owner fixed the
price; JetBrains and the owner retain payment-model activation authority.
