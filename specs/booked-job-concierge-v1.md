# Spec: booked-job-concierge-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall let a novice local-service operator configure, test, activate, and measure a Booked Job Concierge without agent-architecture vocabulary. The repository shall provide a fully runnable sandbox journey. Production calendar, messaging, billing, and model operations shall remain blocked until their adapter bindings are activated by an external tenant.

### User roles

- Workspace owner or admin configures service, adapter, and outcome policy.
- Workspace operator launches sandbox leads and approves bookings.
- Workspace viewer inspects sanitized outcomes and value metrics.

### Requirements (EARS)

- The system shall store exactly one versioned concierge profile per AgentSpec with service name, service area, duration from 15 through 480 minutes, minimum lead score from 0 through 100, modeled job value in integer cents, and an approval-required authority invariant.
- The system shall expose calendar, messaging, billing, and model adapter bindings whose credential field accepts only an opaque secret reference and whose initial production state is `setup-required`.
- When a novice saves the four-step wizard, the system shall return `CONCIERGE_PROFILE_SAVED` with a readiness list and shall not reserve credits or call an external provider.
- When an operator submits a consented lead, the system shall score the declared facts `serviceMatch`, `areaMatch`, `urgency`, and `contactReady`, and shall return `qualified`, `needs-review`, or `rejected` using the saved `minimumLeadScore`.
- If `contactConsent` is false, the system shall reject intake with `E_CONTACT_CONSENT_REQUIRED` before writing a lead or outcome event.
- When a qualified lead requests a sandbox booking, the system shall create a pending `bookingApproval` with a `slotDigest` and shall not record a booking before an operator approves the exact lead and proposed slot.
- When an operator approves a sandbox booking, the system shall consume the pending approval once, write the booking and one simulated outcome event, and return `SANDBOX_BOOKING_CONFIRMED`.
- If a booking approval is replayed or the slot digest changes, the system shall fail with `E_BOOKING_APPROVAL_NOT_PENDING` or `E_BOOKING_SLOT_MISMATCH` without a second booking.
- While any required `productionAdapterSet` member is not active, the system shall reject production booking and return `E_CONCIERGE_ADAPTERS_NOT_READY` before an external side effect.
- When an operator records attendance, cancellation, no-show, or revenue confirmation, the system shall append an observed outcome event and preserve previous events.
- The system shall report counts for leads, qualified leads, bookings, attended jobs, no-shows, cancellations, modeled pipeline value, and observed revenue without converting missing observations into measured revenue.
- The system shall render one dominant `Test with a sample lead` action, an upfront credit explanation, adapter readiness, approval state, next action, and business-outcome metrics in language suitable for a first-time user.
- The system shall never store a raw API key, payment credential, message body, customer phone number, customer email address, or provider access token in concierge records.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A novice completes the sandbox journey
  Given an authenticated operator has a Booked Job Concierge AgentSpec and 500 platform credits
  And the operator saves a valid four-step service profile
  When the operator submits a consented sample lead scoring at or above the saved threshold
  And approves the exact proposed sandbox slot
  Then exactly one booking is confirmed
  And the value dashboard classifies its value as modeled until attendance or revenue is observed

Scenario: Production remains fail-closed
  Given one required production adapter has state setup-required
  When an operator requests a production booking
  Then the request fails with E_CONCIERGE_ADAPTERS_NOT_READY
  And no booking, credit transaction, or provider operation is written

Scenario: Approval cannot be replayed
  Given one sandbox booking approval has been consumed
  When the same approval is submitted again
  Then the request fails with E_BOOKING_APPROVAL_NOT_PENDING
  And the lead still has exactly one booking
```

## SHOULD - Technical and structural

- ADR references: `adr/agent-cloud-trust-capabilities-v1.md`, `adr/agent-cloud-budget-enforcement-v1.md`.
- Data model: `conciergeProfiles`, `conciergeAdapters`, `conciergeLeads`, `conciergeBookingApprovals`, `conciergeBookings`, `conciergeOutcomeEvents`.
- API contract: `convex/concierge.ts` public mutations and queries, all protected by `requireWorkspaceRole`.
- UI contract: one recipe-specific component mounted in the Builder view only when the Booked Job Concierge recipe is selected or saved.
- Evidence class: sandbox booking value is `modeled`; attendance and revenue supplied by an operator are `observed`.
- Governance: `supervised`; production side effects require activated adapters plus human approval.

## SHOULD NOT - Implementation details

- Do not call Stripe, Google, Microsoft, Twilio, or a model provider from a public Convex mutation.
- Do not present simulated bookings or modeled value as measured revenue.
- Do not require graph, node, vector, webhook, lease, or orchestration terminology in guided mode.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `contactConsent` is false | reject before write |
| 2 | `serviceMatch`, `areaMatch`, urgent `urgency`, and `contactReady` are true | return score 100 |
| 3 | `serviceMatch` and `areaMatch` are true with another declared fact false | return score 60 through 85 |
| 4 | `serviceMatch` or `areaMatch` is false | return score below 60 |
| 5 | score is at least `minimumLeadScore` | return qualified |
| 6 | score is within 20 points below `minimumLeadScore` | return needs-review |
| 7 | score is more than 20 points below `minimumLeadScore` | return rejected |
| 8 | `bookingApproval` is pending and `slotDigest` matches | confirm once |
| 9 | `productionAdapterSet` is incomplete | reject production booking |
