# Code Factory GitHub per-seat plan

## Decision record

The GitHub-oriented Code Factory offer is free through **December 31, 2026**
(11:59:59 PM Eastern time). An optional **$5.95 USD per named seat per month**
or **$60 USD per named seat per year** offer is scheduled to begin on
**January 1, 2027**.

This matches the JetBrains Marketplace Freemium plan, which remains optional
from January 1, 2027, subject to its own Marketplace approval and
activation gates. See [JetBrains monetization](JETBRAINS_MONETIZATION_2027.md).

The source of truth is
[`GITHUB_MONETIZATION_2026.json`](GITHUB_MONETIZATION_2026.json). The price is
owner-approved as a future price, not a live checkout or entitlement claim.
It is not active yet.

## What this does and does not change

- The repository remains source-available under `MIT OR Apache-2.0`.
- GitHub repository metadata cannot collect payment or enforce a per-seat
  license. No checkout, billing system, entitlement service, or automatic
  license enforcement is live.
- The future paid offer must have a clearly defined GitHub-oriented delivery and
  support scope before sale. It must not describe ordinary repository access as
  a paid entitlement.
- Taxes, currency conversion, refund terms, and total price must be disclosed
  by the chosen billing or contracting system before a purchase is approved.

## The $5.95 Assurance Seat value contract

This is deliberately not a toll for viewing open-source code. The planned
**GitHub Assurance Seat** is a low-friction, customer-managed operating package
for a named contributor working on GitHub pull requests:

| Included when activated | Why an engineering organization benefits |
| --- | --- |
| Commit-bound Proof Review Check and walkthrough | A reviewer can see the exact commit, proof gaps, and next supported action without treating an AI summary as proof. |
| Human-approved Plan-to-Proof envelope and visible Proof Debt | AI-assisted changes stay tied to declared scope, declared tests, and named deep-review routing. |
| Organization-authored policy bundles and named, expiring exceptions | Exceptions become reviewable records rather than permanent verbal waivers. |
| Supplied-policy drift dossier | A reviewer can see whether an exported ruleset weakened before relying on a merge decision. |
| Hash-bound evidence packets and attestations | A team can export the evidence it owns for its existing review, audit, or release process. |
| Local, customer-managed evidence | Code Factory does not need to host project source or resell opaque model-token credits. |

The seat does **not** include automatic merge, release, deploy, approval, or
policy-bypass authority; hosted evidence retention; managed execution; source
hosting; an SLA; SSO/SCIM; external KMS; a compliance certification; model
credits; or a claim that a test ran without a receipt. Those are separate
enterprise or delivery decisions, not hidden promises inside a $5.95 seat.

Before sale, publish a feature-by-feature availability matrix. Do not sell a
future roadmap as an entitlement.

## Customer-facing notice

> **Free through December 31, 2026.** A $5.95 USD per named seat per month or
> $60 USD per named seat per year GitHub Assurance Seat is scheduled for
> January 1, 2027. It is not active
> yet: no checkout, entitlement, or license enforcement is live.
> The open-source repository remains available under its existing license.

## Activation gate

Do not activate, imply availability of, or accept payment for the offer until
all six gates in the JSON plan have dated evidence: defined offer scope and
terms; billing and tax disclosure; seat and entitlement policy; support, refund,
and privacy boundary; public terms and checkout read-back; and product-owner
approval. A feature-by-feature availability matrix must be public before
activation. GitHub itself is not the billing or entitlement system.
