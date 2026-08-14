# Commercial packaging: keep proof free, sell team operations only when real

## Current state

**The Free Core is available now.** It is the local Code Factory workflow: build
a contained MVP, inspect proof gaps, challenge hollow tests, and produce
receipts without a commercial account.

**The proposed Team Proof Hub, Enterprise Assurance, and a managed Proof Runner are not purchasable today.** The repository includes useful local and supervised
foundations, but a deployable reference is not a managed service. There is no
checkout, trial, entitlement, contract, SLA, or customer support commitment
behind these proposed offers yet.

This is deliberate. A proof tool should not put its most useful safety controls
behind a surprise paywall, and it should not market an operational promise
before the operating system exists.

The structured source of truth is
[`COMMERCIAL_PACKAGING.json`](COMMERCIAL_PACKAGING.json). The existing
[JetBrains Marketplace plan](JETBRAINS_MONETIZATION_2027.md) remains a separate,
owner-approved 2027 decision; this guide does not change its price, release
state, or Marketplace authority.

## The package boundary

| Package | Who it helps | Availability | What it includes | What it does not promise |
| --- | --- | --- | --- | --- |
| Free Core | Individual developers and open-source teams | Available | Local MVP assembly, PRD Grill, CDTE, Graph Ops, receipts, proof review, E2E proof gate, local MCP inspection | Managed hosting, human review, a compliance certification, or release authority |
| Team Proof Hub | Teams that need one shared proof history | Design-partner only; not purchasable | Proposed shared evidence history, team policy bundles, approval routing, and review-visible Proof Debt | A customer-facing service until onboarding, support, retention, and billing are delivered |
| Enterprise Assurance | Organizations with customer-specific assurance needs | Discovery only; not purchasable | Proposed deployment and operating boundary for identity, evidence, approvals, retention, and support | SOC 2, SSO/SCIM, external KMS, SLA, or managed-service availability |
| Managed Proof Runner | Teams that need isolated verification execution | Not offered | Future usage-based runner only after isolation and operating controls are proven | Any current hosted execution, credential handling, or egress guarantee |

## 1. Free Core: the non-negotiable foundation

The local proof workflow remains free and open source. It is the product that
must stand on its own:

```powershell
pip install factoryline-code-factory
factory mvp "Build an approval tracker" --root .
factory change review --root . --base origin/main
factory e2e verify .\e2e-proof.json --root .
```

Free Core protects the most important outcome: developers can see whether a
test, plan, or completion claim has enough evidence before a reviewer is asked
to trust it. It does not upload code, discover credentials, merge, publish,
deploy, approve, or claim production readiness.

## 2. Team Proof Hub: selected design partners before a public beta

The proposed paid layer is not "more code generation." It is the shared
operating layer around proof that a local repository cannot provide by itself:

- a team-owned evidence history with clear retention boundaries;
- policy bundles and approval routing that keep the human merge decision with
  the team;
- review-visible Proof Debt across pull requests and repositories; and
- a work surface for comparing what was declared, verified, deferred, or
  explicitly overridden.

The suggested future range is **USD 12-15 per active PR author per month**,
with a proposed five-author minimum. This is a planning hypothesis, not an
active price, invoice, trial, or purchase offer. It must be tested with real
partners against the value and operating cost before any launch decision.

The local codebase already demonstrates tenant-scoped evidence, audit chains,
independent approvals, signed receipts, and a supervised hosted reference
adapter. It does **not** yet provide the managed onboarding, shared workspace,
support, retention commitment, or billing needed to call Team Proof Hub a
service. See [Control Plane](CONTROL_PLANE.md) and [Hosted control plane]
(HOSTED_CONTROL_PLANE.md) for exact current boundaries.

### Design-partner entry criteria

Select no more than three initial partners only when all of the following are
true:

1. They review AI-assisted changes weekly and can name a recurring proof or
   review problem.
2. They need a shared evidence history, policy route, or approval trail - not
   merely another AI suggestion.
3. They will provide bounded, non-secret workflow feedback and allow the
   product owner to measure support and operating burden.
4. They understand that no partner is enrolled, billed, or promised a service
   merely by completing an intake form.

Use the optional [design-partner issue form](../.github/ISSUE_TEMPLATE/design-partner.yml)
only for high-level discovery. Do not attach source code, credentials, customer
data, security incidents, or private receipts to a public issue.

## 3. Enterprise Assurance: contract after evidence, not before it

Enterprise Assurance is a future customer-specific offer for organizations that
need a defined identity, evidence, approval, retention, and support boundary.
It should begin as a paid implementation pilot or annual contract only after a
separate design, security review, deployment decision, and commercial approval.

It is intentionally not priced today. The repository's enterprise foundations
are useful implementation evidence, but they are not evidence of managed
availability or certification. The exact current-versus-future split lives in
[Enterprise 1.0](ENTERPRISE_1_0.md) and [Enterprise PR Assurance]
(ENTERPRISE_PR_ASSURANCE.md).

## 4. Managed Proof Runner: earn the right to offer execution later

The managed runner remains deferred. It can only become an offer after
isolated-runner behavior, hostile verification, network and credential
boundaries, retention, incident response, support, and billing are all designed
and independently evidenced. Until then, an external runner remains outside the
trust claims of Code Factory.

## Promotion triggers and measurements

Do not launch a public Team beta because of sign-ups, a survey, raw command
counts, or a one-off demo. Promote the offer only after three selected partners:

- use proof review or evidence artifacts weekly;
- confirm that shared history or policy routing solves a recurring team problem;
- provide evidence about support load and data-boundary needs; and
- give the product owner a basis to decide whether a managed service is
  valuable, supportable, and safe to sell.

Any claimed time, token, cost, conversion, or reliability result needs its own
bound measurement and baseline. A packaging document is not such evidence.

## Authority boundary

All commercial activation remains **human-controlled**. Automation may validate
the local packaging contract; it may not select a partner, enter a contract,
collect payment, issue an entitlement, change Marketplace price, or publish a
service. A future service must add these authorities explicitly, with its own
security, product, and operational receipts.
