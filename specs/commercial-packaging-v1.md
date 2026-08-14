# Spec: commercial-packaging-v1

Status: approved

## MUST - Functional core

### Description

Publish one local, reviewable packaging contract that preserves the available
free core, describes the proposed Team Proof Hub without representing it as a
purchasable service, and keeps Enterprise Assurance and a managed runner behind
explicit human-controlled discovery and delivery gates.

### User roles

- Developer: evaluates the free local proof workflow.
- Team lead: decides whether to apply to a design-partner program.
- Enterprise buyer: needs an accurate statement of current and future
  assurance boundaries.
- Product owner: alone decides whether any partner is selected, a commercial
  term is accepted, or a paid service is activated.

### Data model

- `design-partner intake`: an optional public issue form for high-level,
  non-secret workflow discovery. It has no acceptance, contracting, billing,
  repository-access, or communication authority.

### Requirements (EARS)

- When a reader evaluates the structured packaging contract, the system shall emit `COMMERCIAL_FREE_CORE_AVAILABLE` only for the local, open-source proof workflow that is usable without a commercial account. [R1]
- When a reader evaluates the Team entry, the system shall emit `COMMERCIAL_TEAM_NOT_SELLABLE` and `purchasable: false` until a product owner records a separate commercial launch approval. [R2]
- When a reader evaluates Team pricing, the system shall return `COMMERCIAL_TEAM_PRICE_PROPOSED`, the suggested USD 12-15 per-active-PR-author-per-month range, and `status: proposed`; it shall not create checkout, billing, trial, entitlement, or payment authority. [R3]
- When a reader evaluates the Enterprise entry, the system shall emit `COMMERCIAL_ENTERPRISE_DISCOVERY_ONLY` and `purchasable: false` until a customer-specific deployment, security review, and delivery agreement are complete. [R4]
- When commercial copy describes the hosted adapter, the system shall emit `COMMERCIAL_CAPABILITY_BOUNDARY_PRESERVED` and reject managed-service, SOC 2, SSO/SCIM, KMS, SLA, and compliance-certification claims that are not listed as current capabilities. [R5]
- When a team opens the design-partner intake, the system shall emit `COMMERCIAL_INTAKE_DISCOVERY_ONLY`, render a no-source warning, and reject partner acceptance, repository-source collection, and contact authority. [R6]
- When a reader evaluates the managed-runner entry, the system shall emit `COMMERCIAL_MANAGED_RUNNER_NOT_OFFERED` and `purchasable: false`. [R7]
- When the packaging contract references JetBrains, the system shall return `COMMERCIAL_MARKETPLACE_SEPARATE`, path `docs/JETBRAINS_MONETIZATION_2027.json`, `activation_authority: false`, and `revision_authority: false`. [R8]

## Acceptance criteria

```gherkin
Scenario: A developer evaluates the free core
  Given a visitor reads the commercial packaging guide
  When they choose the local proof workflow
  Then it is described as available without a commercial account
  And it retains the existing no-upload and human-approval boundaries

Scenario: A team asks for a shared proof service
  Given Team Proof Hub is not launched
  When the team reads its packaging entry
  Then it is labelled design-partner only and not purchasable
  And its proposed price range is not shown as an active offer

Scenario: An enterprise buyer evaluates assurance
  Given no managed Enterprise Assurance service has launched
  When the buyer reads the commercial packaging guide
  Then current foundations and unshipped capabilities are separated
  And no compliance, managed-service, or SLA claim is made

Scenario: A team applies to the design-partner program
  Given a maintainer has enabled the design-partner intake
  When the applicant opens the form
  Then the form asks for high-level workflow information
  And it warns the applicant not to disclose code, secrets, credentials, or customer data
  And the form cannot accept the applicant or create a commercial agreement

Scenario: Every requirement has an observable validator marker
  Given the commercial packaging contract
  When strict validator mutation runs
  Then contract markers include `COMMERCIAL_FREE_CORE_AVAILABLE`, `COMMERCIAL_TEAM_NOT_SELLABLE`, `COMMERCIAL_TEAM_PRICE_PROPOSED`, `COMMERCIAL_ENTERPRISE_DISCOVERY_ONLY`, `COMMERCIAL_MANAGED_RUNNER_NOT_OFFERED`, `COMMERCIAL_CAPABILITY_BOUNDARY_PRESERVED`, `COMMERCIAL_INTAKE_DISCOVERY_ONLY`, and `COMMERCIAL_MARKETPLACE_SEPARATE`
```

## Non-goals and authority boundary

When the packaging assets are validated, the system shall reject any payment
processor, checkout, billing record, trial, entitlement, invoice, Marketplace
price update, or external message authority.

Where no product-owner selection exists, the system shall reject automatic
customer, applicant, or contact selection.

When the packaging assets are rendered, the system shall withhold usage,
savings, conversion, security, compliance, and availability claims that lack
their own bound measurement or release evidence.

## Verification

When the packaging contract is checked, the system shall return passing results
for `python -m pytest -q tests/test_commercial_packaging.py`,
`specline strict commercial-packaging-v1 --root .`, and
`specline verify-validators commercial-packaging-v1 --root .`.
