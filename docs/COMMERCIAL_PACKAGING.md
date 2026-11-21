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

The separate [GitHub plan](GITHUB_MONETIZATION_2026.md) is free through
December 31, 2026. From January 1, 2027, **$5.95 USD/month or $60 USD/year is
preserved as a grandfathered Founding Proof Pro offer**; the standard planning
price is **$9 USD/month or $90 USD/year**. It is not a live checkout, entitlement, or repository
access restriction; GitHub repository metadata cannot provide those functions.
It is framed as a customer-managed **GitHub Assurance Seat**: commit-bound proof
review, visible Proof Debt, policy and exception records, and exportable
evidence—not a charge for source access or an unverified enterprise promise.

The separate [Open VSX service plan](OPEN_VSX_MONETIZATION_2026.md) keeps the
registry extension and local proof core free. All shipped capabilities remain
free through December 14, 2026. Optional Proof Pro is planned at $9/month or
$90/year, AppForge Builder at $24/month or $240/year, and Team Assurance at
$20 per active contributor/month on an annual commitment or $24 monthly. The
$5.95/$60 Founding Proof Pro price is grandfathered. No offer may start until
the explicit commercial activation gates are evidenced.

## The package boundary

| Package | Who it helps | Availability | What it includes | What it does not promise |
| --- | --- | --- | --- | --- |
| Free Core | Individual developers and open-source teams | Available | Local MVP assembly, PRD Grill, CDTE, Graph Ops, receipts, proof review, E2E proof gate, local MCP inspection | Managed hosting, human review, a compliance certification, or release authority |
| Proof Pro | Individual developers who need continuity and deeper proof operations | Scheduled; not purchasable | Advanced proof, governed memory, IDE workflows, and supervised repair | Hosted agent/model usage, approval, merge, or deployment authority |
| AppForge Builder | SaaS and app builders | Scheduled; not purchasable | Proof Pro, AppForge storyboards/design contracts, SaaS proof, and supervised Junie missions | Unlimited model, build, render, device, or provider consumption |
| Team Proof Hub | Teams that need one shared proof history | Design-partner only; not purchasable | Proposed shared evidence history, team policy bundles, approval routing, and review-visible Proof Debt | A customer-facing service until onboarding, support, retention, and billing are delivered |
| Enterprise Assurance | Organizations with customer-specific assurance needs | Discovery only; not purchasable | Proposed deployment and operating boundary for identity, evidence, approvals, retention, and support | SOC 2, SSO/SCIM, external KMS, SLA, or managed-service availability |
| Managed Proof Runner | Teams that need isolated verification execution | Not offered | Future usage-based runner only after isolation and operating controls are proven | Any current hosted execution, credential handling, or egress guarantee |

The future GitHub Assurance Seat packages commit-bound Proof Review,
Plan-to-Proof, Proof Debt, supplied-policy drift dossiers, organization policy
bundles, named expiring exceptions, and exportable evidence. It remains subject
to its separate public activation gates; no checkout or entitlement is live.

The GitHub per-seat plan is a separate future delivery and support offer; it
does not change the available Free Core or turn ordinary source access into a
paid entitlement.

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

The suggested future price is **USD 20 per active contributor per month on an
annual commitment, or USD 24 monthly**, with a proposed three-contributor
minimum. This is a planning hypothesis, not an
active price, invoice, trial, or purchase offer. It must be tested with real
partners against the value and operating cost before any launch decision.

The local codebase now demonstrates tenant-scoped evidence, an auditable local
identity lifecycle, explicit Docker/process runner posture, required-check
evaluation, hash-linked outcome telemetry, independent approvals, signed
receipts, and a supervised hosted reference adapter. It still does **not**
provide the managed onboarding, hosted shared workspace, support, retention
commitment, or billing needed to call Team Proof Hub a service. See
[Enterprise Operations](ENTERPRISE_OPERATIONS.md), [Control Plane](CONTROL_PLANE.md),
and [Hosted control plane](HOSTED_CONTROL_PLANE.md) for exact current
boundaries.

For a selected design partner, the shipped [Team Pilot readiness gate]
(TEAM_PILOT_LAUNCH.md) can now hash-bind the five local operating decisions
needed for a **customer-managed reference** review. Its only success marker is
`TEAM_PILOT_READY_FOR_OWNER_REVIEW`; it cannot accept a partner, issue terms,
collect payment, provision access, or activate a service.

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

The current design-partner hypothesis is **USD 6,000-15,000 per year**, only
after a scoped deployment and support agreement. This is not a public purchase
offer. The repository's enterprise foundations
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

## Sponsorship and funding launch draft

Status: **draft; payment destinations and offers are not live**.

### Goal

Make recurring maintenance of the public Code Factory ecosystem sustainable
through voluntary community funding and separately scoped business services.
Measure monthly funds received, verified project costs, maintenance hours
funded, and work delivered. Set a public dollar goal only after costs and the
owner's target maintenance rate are known.

### Sponsor profile draft

I'm Rick Katz, founder of WizeMe and a builder of AI tools for people who
want to make better decisions and get meaningful work done.

After more than two decades building and scaling businesses, I've learned
that good ideas need evidence. That belief led me to build Code Factory, a
free, local-first tool that helps developers inspect AI-generated code,
challenge tests, and see what was actually checked.

I also share open-source projects exploring AI memory, development workflows,
and practical tools for founders. Your support helps maintain these projects,
improve documentation, run tests, and support new releases. I'll share public
updates on what I'm building. Thank you for being part of it.

Sponsorship does not guarantee a feature, support response, or security
certification.

### Proposed recurring sponsorship tiers (USD per month)

- **$5 Supporter:** support maintenance and public updates.
- **$25 Builder:** support tests and documentation; optional name recognition.
- **$100 Team:** optional name or logo and invitation to share use cases for
  roadmap consideration.
- **$500 Sustaining partner:** optional prominent recognition and a periodic
  roadmap conversation subject to availability.

One-time contributions: $10, $25, and custom amounts, where supported.
Recognition is opt-in. Updates are public, targeted monthly, and shared across
channels to avoid separate memberships with inconsistent benefits. Roadmap
input is not a promise of a feature or deadline.

These prices are proposals, not current entitlements. Verify tier terms and
sustainable capacity before publication.

### Channel roles

1. GitHub Sponsors: primary recurring open-source support, after approval and
   profile setup are verified.
2. Buy Me a Coffee: optional one-time support, after its account and payout setup
   are verified.
3. Stripe: separately scoped business service payments after the correct legal
   entity, currency, taxes, terms, and account access are confirmed.
4. PayPal: optional alternative when a verified business payment link exists.
5. Patreon: consider only if an ongoing creator membership is actually offered.

Do not publish guessed URLs or imply that funding or payment is available
before confirming each destination. Do not collect bank, tax, or API secrets
in public GitHub issues.

### Business-offer experiments

- **Code Factory onboarding:** proposed fixed-scope installation and workflow
  session, with a written deliverable and customer-controlled environment.
- **Review workflow workshop:** proposed team session on evidence and review
  practices; scope, scheduling, and cancellation terms must be agreed first.
- **WMM commercial use:** handle as a separate written agreement after review of
  the applicable WMM license and prior/third-party rights. Payment alone is not
  a license.
- **GTM experiment workshop:** proposed human-led service. Do not claim that
  the software validates a business or guarantees an outcome.

No automated checkout is authorized by this document. These ideas do not alter
the separately documented Code Factory commercial activation gates, prices, or
availability.

### Launch checklist

- Verify GitHub Sponsors application status and complete the profile, payout,
  tax, and 2FA requirements in GitHub's own dashboard.
- Verify payment account ownership, business identity, payout configuration,
  supported currency, and fees in each provider.
- Agree service scope, availability, price, refunds, tax disclosures, contact
  path, and delivery before accepting payment.
- Verify each actual live URL and add only working, authorized destinations to
  `.github/FUNDING.yml`; GitHub supports `github`, `buy_me_a_coffee`,
  `patreon`, and `custom` entries.
- Add concise funding links to public project READMEs after the destinations
  work. Keep open-source sponsorship distinct from purchases.
- Set a measurable monthly funding goal from actual expenses, planned hours,
  target hourly rate, and a reserve; account for fees and taxes.
- Publish a monthly update on maintenance, spending categories, and progress.

See the [GitHub per-seat plan](GITHUB_MONETIZATION_2026.md) for existing boundaries.


## Inactive local implementation reference

# Code Factory commercial model: decision record

November 21, 2026. Status: recorded and implemented **disabled**. No
enforcement, billing, telemetry, checkout or license replacement is active.

## Approved model

Approved by the project owner on November 21, 2026 (WhatsApp, model proposal
accepted with "Yes"; implementation and commit requested with "Resolve and
commit"):

- **Free:** 5 complete proof workflows per person per calendar month (UTC).
- **Paid:** 100 workflows per named human seat per month at **US$12.95** per
  seat, starting **January 1, 2027**. Everything before that date is free.
- Each workflow includes its checks and **2 repair reruns for the same change
  within 7 days**.
- One seat covers that person's **agents and devices**. The seat subject is the
  human owner; an AI agent's declared identity is never proof of subscription.
- **Reading and exporting results stays free.** Rejected starts and internal
  tool errors never consume allowance. **No overage charges**: over allowance
  is a hard stop with an upgrade path, never a bill.
- Personal users keep the recurring 5-workflow free allowance and can upgrade
  for heavier use; the paid seat is available to individuals and businesses.

The allowance counts are approved starting policy, not usage-tested economics.
Promotion duration and any price lock are unspecified.

## What was built

All of it disabled by default (`FACTORY_COMMERCIAL_MODE=off`; `activation:
false` in `commercial-policy.v1.json`):

- `commercial-policy.v1.json` — the versioned, inert policy document above.
- `factoryline/enterprise_enforcement.py` — policy parsing and pure admission
  decisions: `PRELAUNCH_FREE`, `ALLOW`, `ALLOW_INCLUDED_RERUN`,
  `UPGRADE_REQUIRED`, `ENTITLEMENT_INVALID`.
- `factoryline/enterprise_ops.py` — atomic local reservation ledger in a
  user-level data directory (`~/.factoryline/commercial`, not any project's
  resettable `.factory` folder), with POSIX `flock` or a Windows byte-range
  lock plus per-home thread serialization around reserve/finalize/release.
  Unsupported or failed locking aborts the operation. It also provides
  idempotency keys, crash-expiry of stale reservations, period rollover,
  clock-rollback protection, read-only export and an explicit, visible reset.
- `factoryline/enterprise_receipts.py` — offline verification of
  issuer-signed DSSE Ed25519 entitlements against a separately configured
  commercial trust root. No embedded issuer private key, no credential
  collection, no network call. `covered_versions.max` is required: open-ended
  future-version grants are deliberately not issuable.
- `factoryline/enterprise_enforcement.py` — one admission boundary (`off` / `shadow`
  / `enforce`) combining policy, ledger and entitlements.
- `factoryline/cli_enterprise.py` — `factory commercial plan | usage | export |
  reset | import-entitlement | entitlements`. No purchase or activation path.
- `factoryline/runtime_audit.py` — the Proof Agent execution route now passes
  through the gate after safety preflight and before dispatch, settling once
  at the terminal result.

## Honest boundaries

- **Soft local enforcement only.** The ledger is a transparent local file. A
  determined user can reset it (`factory commercial reset --yes` is explicit
  and visible), and it cannot see other devices. Reliable cross-device limits
  require a separately approved account/entitlement service with its own
  privacy, retention, outage and billing design; that service is **not built
  or authorized** by this change.
- **Coverage is one route.** The gate is wired into the Proof Agent execution
  route (`cli_agent.run` -> `execute_proof_agent`). Other execution routes
  (direct runtime-audit commands, assembly/repair paths, IDE subprocesses, CI)
  are **not** wrapped; no global quota is claimed. Read-only MCP gains no
  execution authority.
- **Proof integrity is untouched.** Quota status never changes a finding,
  never skips a check or negative control, never interrupts an admitted run,
  and never hides existing receipts. Payment status never replaces signed-plan
  verification or human approval. `agent_license.py` remains about agent
  autonomy evidence, unrelated to paid access. `meter.py` remains a
  measurement log, not a billing meter.
- **Repair-rerun semantics, defined explicitly:** a rerun is the same change
  when scope and plan digests match the original finalized workflow. A new
  candidate digest alone never disqualifies a repair; expanded scope or a
  different plan is a new workflow. The Proof Agent route currently always
  admits as a new workflow; included reruns are supported by the gate API for
  callers that supply the original workflow reference.

## License route

Existing `LICENSE-MIT`, `LICENSE-APACHE`, `LICENSE`, `NOTICE` and packaging
metadata are **unchanged**. Prior releases remain usable under their granted
terms; no retroactive restriction is made or implied, and no contributor
rights (human or AI-authored) are adjudicated here. GitHub's contributor list
is an investigation input, not evidence of ownership, assignment or consent.

Unresolved before any future commercial license switch, kept explicit rather
than invented:

1. Exact future version/component scope after rights review (recommended: no
   retroactive restrictions, no automatic SpecLine/ForgeLine/CompileLine/
   Prestige changes; core 0.50.0 / plugins 1.3.6 are publication targets, not
   approved license-switch versions).
2. Promotion duration and renewal treatment.
3. Counsel review of final terms; refunds, taxes, cancellation, seat
   reassignment and shared CI use before any payment launch.

## Verification

Deterministic tests cover policy decisions, ledger concurrency and idempotent
retry, crash recovery, period rollover, clock rollback, rerun window/scope
rules, entitlement signature/window/version validation, gate modes, and the
Proof Agent wiring (refusal before dispatch, settlement on completion and on
internal error, and the invariant that quota state never alters a proof
result). See `tests/test_commercial_*.py`.
