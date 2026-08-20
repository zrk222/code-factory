# Launch Kit

Copy-ready public launch material for Code Factory. Keep every
claim inside the linked artifact or receipt. Invite independent feedback; never
ask for votes, stars, or reviews.

## Code Factory: Product Hunt Maker Comment

> I made Code Factory because AI-assisted code is fast to produce and hard to
> trust. It is a local, open-source five-part workflow that turns intent into
> explicit specs, challenges whether tests prove behavior, compiles recurring
> decisions into deterministic code, checks design-token contracts, and joins
> the resulting evidence into reviewable receipts.
>
> The proof I care about most is not that a gate exists, but that it notices
> when the gate is sabotaged. For example, `factory verify-policy` deletes or
> inverts release rules and requires the evaluator to fail; otherwise it reports
> `HOLLOW_POLICY`.
>
> The core remains local tooling, not a substitute for human judgment. Version
> 0.18 adds an optional self-hosted GitHub adapter so teams can apply the same
> bounded assurance model to pull requests without turning the editor or local
> CLI into an ambient deployment authority.
>
> Version 0.18 verifies GitHub webhook signatures, pins immutable
> installation-to-tenant routes, validates RS256 OIDC approvals offline, forces
> PostgreSQL row-level security, and publishes GitHub Checks from a retained
> transactional outbox using short-lived GitHub App credentials. It is a
> deployable reference adapter—not a claim of managed HA, SCIM, SOC 2, or an
> SLA. The local core, Product Missions, signed Capability Packs, Factory
> Studio, and editor adapters remain independently usable.
>
> I would love feedback on one question: what would you need to prove before
> allowing an AI-generated change into a production repository?

**Current product media:** use the FactoryLine logo and the two exact local
Studio captures listed in `docs/PRODUCT_HUNT_GALLERY.md`. They show the
outcome-first MVP path and Graph Ops proof path without fabricated metrics or
a simulated IDE. Do not use the retired v0.17 recording, blank-dashboard
captures, or concept art in a public listing.

## Code Factory: Product Hunt Release Update - JetBrains

> Update: Code Factory now includes a JetBrains Platform adapter for IntelliJ
> IDEA, PyCharm, WebStorm, Rider, CLion, GoLand, RustRover, and DataGrip.
>
> It is a local control surface for the same FactoryLine CLI: assemble a
> feature, verify a feature, inspect changed-proof risk, check receipt status,
> and open the latest local receipt without leaving the IDE. Before it runs a
> command, it shows the exact local workspace and asks for confirmation.
>
> The adapter does not upload source or receipts, sign artifacts, or invent a
> green result. It shows receipts as unassessed until the normal FactoryLine
> verification path has checked them. The release ZIP carries a Marketplace
> preflight over its descriptor, logos, contact metadata, release notes, and
> packaged structure. It is installed from GitHub releases until the first
> Vendor-profile upload completes JetBrains review.
>
> This is the enterprise-team convenience layer, not a second control plane:
> the CLI, CI, and human review remain the authority.

## Code Factory: Product Hunt Release Update - Hosted PR Assurance

> Update: Code Factory 0.18 adds an optional self-hosted GitHub PR-assurance
> adapter while keeping the proof-first local core intact.
>
> The adapter verifies GitHub HMAC webhooks, maps each GitHub App installation
> to one immutable tenant, validates RS256 OIDC approvals against
> freshness-bounded HTTPS JWKS, and stores approvals plus outbound GitHub Check
> work in one PostgreSQL transaction. Forced row-level security is part of the
> schema, and publication uses short-lived GitHub App credentials.
>
> This is deliberately a deployable reference, not a managed-service claim. It
> does not promise HA, automatic disaster recovery, SSO/SCIM, SOC 2, or an SLA.
> What it provides is a concrete full-stack boundary that teams can inspect,
> run, and challenge.
>
> Repository and deployment contract:
> https://github.com/zrk222/code-factory

## LinkedIn: Code Factory

> AI coding is fast. Verification is the bottleneck.
>
> I released Code Factory, an open-source local workflow for making
> AI-assisted software work reviewable and reproducible.
>
> It has five independent pieces:
>
> - SpecLine turns intent into explicit contracts.
> - ForgeLine challenges whether tests prove behavior.
> - Harness Software Factory compiles recurring decisions into deterministic
>   code.
> - Prestige checks design-token contracts.
> - FactoryLine links the resulting evidence into receipts.
>
> The point is not to bypass engineering judgment. It is to give reviewers
> evidence that a gate actually enforces something. A policy rule that can be
> deleted without changing the result is not policy; it is `HOLLOW_POLICY`.
>
> Code Factory is local, installable, and MIT/Apache licensed:
> https://github.com/zrk222/code-factory
>
> The question I am working on: what would you want proved before trusting an
> AI-generated change in production?

Attach `docs/assets/factory-editor-control-room.svg`. It reflects the shipped
editor adapters without copying stale test counts into a launch post.

## Show HN

**Title**

```text
Show HN: A proof-first factory for AI-assisted software work
```

**Submission text**

> I made Code Factory because I wanted a more useful answer than “the agent
> wrote code and the tests passed.” It is a set of local Python CLIs that hold
> an AI-assisted change to explicit contracts, architecture gates, runtime
> checks, mutation challenges, and hash-linked receipts.
>
> The unusual part is proof by sabotage. We mutate or remove the thing that is
> supposed to protect you: requirements, behavioral tests, decision rules,
> design tokens, and release policies. If the evaluator still passes, the tool
> reports the control as hollow instead of treating its presence as proof.
>
> The components work independently, but the base package connects them:
>
> ```bash
> pip install factoryline-code-factory==0.24.2 code-factory-1-spec==0.5.4 code-factory-2-forge==0.10.7 code-factory-3-compile==0.5.5 code-factory-4-design==0.8.0
> factory doctor --strict --json
> ```
>
> It is local, MIT/Apache licensed, and does not replace code review. I would
> especially value criticism from people maintaining existing repositories:
> where would this add useful evidence, and where would it merely add ceremony?
>
> https://github.com/zrk222/code-factory

## Reply Bank

**“Is this just CI?”**

> CI runs checks. Code Factory also challenges the checks themselves and stores
> the result as a receipt. A green check that cannot fail for the intended
> reason is not useful evidence.

**“Can I use it with an existing repository?”**

> Yes. `forge adopt` writes a reviewable baseline for an existing repository;
> it does not require a greenfield scaffold. The first adoption should be small
> and reversible so the team can measure overhead before expanding use.

**“Does it replace code review?”**

> No. It makes review more concrete by showing what was checked, what was
> challenged, and what still needs a person to judge.

## Launch-Day Checklist

1. Publish the maker comment when the Product Hunt listing becomes live.
2. Share the direct Product Hunt link and invite people to read or comment,
   never to vote.
3. Reply promptly with specific, non-defensive answers for the first four hours.
4. Post the Show HN only when the install commands and live demo links are
   working.
5. Add the JetBrains release update only after the GitHub release contains the
   adapter ZIP and the cross-product compatibility matrix is green.
6. Record Product Hunt dashboard views, comments, GitHub traffic, PyPI downloads,
   and inbound issues as separate measures. Do not convert them into a single
   “traction” number.
