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

## Bounded inactive implementation consolidation

When the existing inactive offline commercial implementation is consolidated,
the system shall preserve all existing policy, usage, DSSE entitlement, CLI and
runtime-admission tests without changing their parameters or assertions. [R9]

When consolidation runs, the system shall move policy and admission into
`factoryline/enterprise_enforcement.py`, usage into `factoryline/enterprise_ops.py`,
entitlement verification into `factoryline/enterprise_receipts.py`, and lazy CLI
registration and dispatch into `factoryline/cli_enterprise.py`; it shall delete
the five duplicate implementation modules and four duplicate test modules. [R10]

When the consolidated default runs, the system shall retain mode `off`,
`activation: false`, no billing or provider activation, and unchanged schemas,
decisions, error codes, CLI commands, DSSE verification and native locking. [R11]

When documentation is consolidated, the system shall retain the existing local
implementation limitations in `docs/COMMERCIAL_PACKAGING.md` and remove
`docs/commercial-model.md`, without granting commercial activation authority. [R12]

This refactor preserves prepared local offline code only. It does not launch a
service or authorize billing, issuance, production enforcement or activation.

Scenario: Consolidated local code preserves the existing offline boundaries
  Given the inactive commercial implementation
  When its duplicate modules and tests are consolidated
  Then `R9`, `R10`, `R11`, and `R12` retain the exact existing behavior and authority

## Verification

## Authorized parameters

These are exact inherited local implementation values, not a commercial launch
or new thresholds. The baseline is commit
`f057734f8e94fafb7dea15976ab3ee394ab62bd0`; original dirty source bytes and hashes
are retained in `.factory/commercial-consolidation/before-hashes.json`.
The change-aware audit compares the six modified production modules to that
commit, so pre-existing enterprise and CLI parameters are not reauthorized here.

The defaults below preserve the inactive USD seat-month value, free and paid
workflow allowances, rerun count and days, six-hour TTL factors, and UTC epoch
initializer. They do not change those existing values.

DEFAULT_POLICY = 12.95
DEFAULT_POLICY = 5
DEFAULT_POLICY = 100
DEFAULT_POLICY = 2
DEFAULT_POLICY = 7
RESERVATION_TTL_SECONDS = 6
RESERVATION_TTL_SECONDS = 60
max_seen = 1970
max_seen = 1

## Reproducible verification

When direct public-API acceptance checks are added, the system shall execute
configuration parsing, policy loading and limits, local ledger views,
entitlement payload validation, and commercial CLI registration and plan/usage
JSON with positive and negative assertions, while retaining every prior test
body unchanged. Static test attribution is not runtime coverage.

When the existing commercial admission, ledger replay and CLI dispatch are
refined for the CI complexity gate, the system shall preserve every existing
condition, error, schema and CLI result and return passing Ruff C901 checks at
the existing maximum complexity of 10 and passing actual ForgeLine AST checks
including branch and Boolean-operation complexity; no exemption or threshold
change is permitted. Actual repo-wide quality and attribution artifacts remain
required and are not replaced by the narrower Ruff check.

When the minimal worker SDK imports enterprise receipts, the system shall defer
commercial storage dependencies until a commercial storage operation is called
and return a passing result for the existing worker-image entrypoint import
closure and omission-detection test, without expanding image copy lists.

When the packaging contract is checked, the system shall return passing results
for `python -m pytest -q tests/test_commercial_packaging.py`,
`specline strict commercial-packaging-v1 --root .`, and
`specline verify-validators commercial-packaging-v1 --root .`.
