# Spec: github-per-seat-monetization-v1

Status: approved

## MUST - Functional core

### Data model

- `GitHub monetization plan`: JSON object with `free_through`, `paid_from`,
  `price_per_named_seat_usd_month`, `price_status`, six activation gates, and
  a `current_verdict`.
- `GitHub Assurance Seat`: a planned customer-managed operating package; it is
  not repository access, a GitHub checkout, an entitlement service, or an
  automatic license-enforcement mechanism.

### Requirements

- When a reader opens the GitHub monetization plan, the system shall emit
  `GITHUB_FREE_WINDOW_DECLARED` only when the offer is free through
  `2026-12-01T23:59:59-05:00` and paid from `2026-12-02`. [R1]
- When a reader evaluates the scheduled price, the system shall emit
  `GITHUB_SEAT_PRICE_SCHEDULED` only when the price is exactly `USD 5.95` per
  named seat per month, where `USD` means United States dollars, and the status
  is `owner_approved_future_price_not_active`. [R2]
- When public copy describes the GitHub plan, the system shall emit
  `GITHUB_COMMERCIAL_BOUNDARY_PRESERVED` only when checkout, billing,
  entitlement, and automatic license enforcement are stated as not live. [R3]
- When a reader compares the GitHub and JetBrains plans, the system shall emit
  `GITHUB_JETBRAINS_PRICE_SEPARATED` only when JetBrains remains `USD 4.95` per
  month from `2027-01-01` and is labelled separate. [R4]
- When a GitHub Assurance Seat paid activation is evaluated, the system shall reject
  the GitHub Assurance Seat paid activation with `GITHUB_PAID_ACTIVATION_BLOCKED`
  unless all six named gates and
  product-owner approval have dated evidence. [R5]

## Acceptance criteria

```gherkin
Scenario: A visitor reads the planned GitHub price
  Given the GitHub monetization plan
  When the visitor reads the customer-facing notice
  Then it says free through December 1, 2026
  And it says $5.95 USD per named seat per month from December 2, 2026
  And it emits GITHUB_COMMERCIAL_BOUNDARY_PRESERVED

Scenario: A visitor compares platform plans
  Given the GitHub and JetBrains monetization plans
  When the visitor compares their dates and prices
  Then GitHub emits GITHUB_SEAT_PRICE_SCHEDULED at $5.95 per named seat from 2026-12-02
  And JetBrains emits GITHUB_JETBRAINS_PRICE_SEPARATED at $4.95 per month from 2027-01-01
```

## Non-goals

This change must not change the source license, restrict repository access,
create checkout, accept payment, provision entitlements, enable automatic
license enforcement, or activate either platform's paid plan.

## Verification

`python -m pytest -q tests/test_commercial_packaging.py tests/test_publication_metadata.py`
