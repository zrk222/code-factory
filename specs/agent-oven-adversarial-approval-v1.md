# Spec: agent-oven-adversarial-approval-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add an independent, deterministic approval plane that attempts to falsify task readiness before any approval is final. It may automatically approve only content-addressed, low-cost analysis in a test environment. It shall deny malformed or unproved requests and shall escalate code changes, external sends, deployments, deletion, payments, credentials, and all production work to an authenticated human reviewer.

### Requirements (EARS)

- The system shall store the exact action digest, proof-bearing gate evidence, budget, action class, environment, worker identity, policy version, and expiry in every approval review.
- The system shall return Boolean facts `deterministicBoundaryFailed`, `highImpactAction`, and `priorComparableEvidence` from the validated approval input and review history.
- If the worker identity equals the approval-agent identity, the system shall deny the request with `E_INDEPENDENT_REVIEWER`.
- If the action digest differs, the budget is exceeded, fewer than three proof-bearing deterministic gates pass, evidence digests are malformed, or any gate blocks, the system shall deny and close the run without execution.
- When action class is `read` or `analyze`, environment is `test`, admitted cost is at most 100 cents, and every deterministic check passes, the system shall return `auto-approved`.
- When an action changes code, sends externally, deploys, deletes, transfers value, accesses credentials, or targets production, the system shall return `human-required` and shall not automatically approve.
- When a human decision is requested, the system shall reject it with `E_ADVERSARIAL_REVIEW_REQUIRED`, `E_ADVERSARIAL_REVIEW_DENIED`, or `E_ADVERSARIAL_REVIEW_EXPIRED` unless a non-denied review created no more than 24 hours earlier exists.
- If the human reviewer identity equals the worker or approval-agent identity, the system shall reject the decision with `E_SELF_APPROVAL_FORBIDDEN`.
- The system shall append an immutable approval receipt and audit event for every adversarial verdict.
- The system shall render deterministic checks, verdict, reason codes, policy version, and the exact Proof Delta in the run approval UI.
- The system shall compare content-addressed evidence with the prior comparable review and show reused, new, and missing evidence without inheriting prior authority.
- When paired measured receipts are absent, the system shall return `timeSavings = unavailable` and `tokenSavings = unavailable`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Automatically approve safe evidence analysis
  Given a test-only analysis costing at most one dollar with three proof-bearing gates and two evidence digests
  When the independent approval policy reviews it
  Then the verdict is auto-approved and an approval receipt is appended

Scenario: Require human accountability for a merge
  Given a production code-change proposal with all deterministic gates passing
  When the independent approval policy reviews it
  Then the verdict is human-required and the run remains pending

Scenario: Deny a compromised review
  Given the worker and approval agent share an identity or evidence is malformed
  When the review runs
  Then the verdict is denied and the run cannot execute

Scenario: Focus a repeat review
  Given a prior comparable review and a new set of content-addressed evidence
  When Proof Delta is computed
  Then reused, new, and missing evidence are shown and no prior decision is inherited
```

## SHOULD - Technical/structural

- Policy domain: `products/agent-cloud/app/convex/adversarialApprovalDomain.ts`.
- Persistence and transitions: `products/agent-cloud/app/convex/control.ts` and `products/agent-cloud/app/convex/schema.ts`.
- Supervision UI: `products/agent-cloud/app/src/components/RunPanel.tsx`.

## SHOULD NOT - Implementation details

- No model verdict authorizes an action.
- No memory record expands authority.
- No previous approval is replayed onto a new digest.
- No external credential or production endpoint is required for deterministic policy evaluation.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `deterministicBoundaryFailed = true` | deny |
| 2 | test-only read/analysis, cost <= 100 cents, all deterministic boundaries pass | auto-approve |
| 3 | `highImpactAction = true` | require human |
| 4 | `priorComparableEvidence = true` | show Proof Delta; do not inherit authority |
