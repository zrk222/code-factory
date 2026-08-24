# Agent Oven by Code Factory

## Adversarial task approval

Deterministic policy may automatically approve only proved, low-cost evidence analysis in test. Code changes, external sends, deployments, deletion, payments, credential access, and production work remain human-controlled. Content-addressed Proof Delta shows reviewers what evidence changed without replaying prior authority. See `docs/ADVERSARIAL_APPROVAL.md`.

## Outcome Agent Exchange

Agent Oven now includes a full-stack result market: six preconfigured agents can be hired by an authenticated human or another authenticated agent, with a fixed platform-credit price released only after an independent deterministic evidence check. The same immutable contract powers the UI and machine clients; it binds intent, price, authority, proof obligations, expiry, idempotency, and a one-hop delegation limit before work starts.

Open `/app?view=exchange` for the supervision UI. Machine clients can inspect `/.well-known/agent-card.json` and `/.well-known/outcome-agent-contract.json`. External money rails remain explicitly `setup-required`; platform credits are the only active settlement rail in this release.

## Portable Agent Composer

Users can describe the result an agent must finish, choose Agent Oven-managed inference or BYOK, and compile the brief into a visible, versioned graph for Agent Oven native, LangGraph, or Mastra. The compiler fails closed on missing success criteria, source permissions, authority, or exception handling; saving a draft never activates it. See `docs/PORTABLE_AGENT_COMPOSER.md` and `/.well-known/runtime-compatibility.json`.

## The Agent Oven commercial model

Agent Oven is a hosted agent builder whose control plane remains in the operating path after an agent is created. Subscription tiers allocate platform credits. Each curated agent template has a fixed, server-owned credit price; a custom agent is quoted as a base price plus its workflow, memory, evidence, and automation ingredients. Runtime work reserves and reconciles additional platform credits.

Platform credits pay for Agent Oven orchestration. They do **not** hide or resell AI inference. Customers bring supported provider credentials, keep the raw value in an approved secret manager, and bind a shared workspace connection or a dedicated connection to each agent. Activated agents require Agent Oven policy, credit admission, runtime leases, cancellation, and evidence services.

Current plans are Starter (500 monthly credits / 2 agents), Growth (2,500 / 10), Business (10,000 / 50), and Enterprise (50,000 / 500). Billing provider checkout and webhook activation require a production tenant; the ledger and enforcement model are implemented and tested.

## Authenticated organization and workspace isolation

The Convex backend now includes an identity-derived membership guard, one-time empty-workspace owner bootstrap, owner-controlled member administration, last-owner protection, revoked-member denial, and protected AgentSpec reads that reject cross-workspace identifiers. The principal comes from Convex `tokenIdentifier`; access APIs accept no acting identity from the client, and evidence omits identity claims and tokens.

Every public query and mutation is classified by a route-authorization manifest. Enterprise controls add organization ownership, delegated administrators and auditors, SSO/SCIM metadata, directory-driven role mapping, idempotent provisioning, and cross-organization denial. Production OIDC and directory activation still requires real tenant configuration and credentials.

## Recipe builder and Knowledge Wall

- Twenty-eight novice-friendly recipes include the original business patterns plus governed legal, property, civic-planning, trade, environmental, healthcare credentialing, drug-safety, food-recall, UAS, energy-interconnection, chemical/workplace, security, revenue, and compliance workflows. Regulated recipes expose their evidence contract, preset automations, accountable owner, and hard boundaries before activation.
- Guided and Architect modes assemble typed retrieve/reason/act/validate/notify steps, triggers, human gates, memory, model, authority, evidence, and budget ingredients into an immutable versioned blueprint.
- The Knowledge Wall accepts governed manuals and small text/Markdown/CSV/JSON uploads, with provenance, purpose, confidence, retention, and untrusted-context labeling.
- Google Drive, OneDrive, SharePoint, Notion, Dropbox, Confluence, web, S3, Azure Blob, GitHub, and database connectors share one extensible adapter contract. Connector records contain metadata and opaque secret references; OAuth and sync workers require production tenant activation.
- Property, legal, and civic templates deliberately separate professional and consumer authority. See `docs/REGULATED_PROPERTY_AND_CIVIC_AGENTS.md` for licensing, source, currentness, fair-housing, and human-review boundaries.
- Eight high-priority regulated lanes include sixteen novice-ready automation presets with plain-language setup, exact deliverables, human approvals, and deterministic stop conditions. See `docs/REGULATED_AUTOMATION_OPPORTUNITIES.md`.

### Authoritative Source Control Plane

Regulated agents can now group primary law, official regulators, official registries, and licensed systems of record into freshness-bound redundancy sets. Secondary commentary remains useful context but never counts as authority. Every required group needs its declared current-source minimum and at least one healthy source; otherwise execution stops before job creation or credit reservation with an exact reason. The operator panel exposes source age, failures, coverage, and the honest `supervised source assurance` boundary. External checks remain a trusted-worker responsibility. See `docs/AUTHORITATIVE_SOURCE_CONTROL.md`.

The worker-side probe contract is also implemented: bounded retry for timeout/429/5xx responses, HTTPS-only endpoint resolution, response-size limits, content-free SHA-256 observations, five-source concurrency batches, operator-authenticated definition retrieval, and configuration-digest pinning. It is packaged as a non-root scheduled service with rotating workload identity, confined provider-neutral vault mounts, a redacted activation preflight and live rotation drill, liveness/readiness endpoints, bounded metadata-only alert retry, graceful draining, a multi-stage container, and a hardened two-replica Kubernetes template. The preflight never substitutes decoded claims for signature verification. Its posture remains `credential activation required` until a trusted issuer/audience, service membership, CSI provider, digest-pinned image, alert destination, and independent failure domains are activated. See `docs/SOURCE_WORKER_SERVICE.md`.

## Hosted runtime and enterprise operations

### Agent Recipe Lab

The six-stage Recipe Lab compares bounded combinations of allowlisted models, retrieval depth, memory policy, and authority mode against a tenant-owned evaluation set. The Convex control plane creates deterministic candidates, reserves credits before evaluation work, prunes policy violations and weak post-grace checkpoints, records digest-bound evidence, computes the eligible Pareto frontier, and proposes one deterministic weighted champion. A creator cannot approve the winner, and approval does not activate or deploy it.

Evaluation examples and provider credentials stay outside study records. Trusted hosted workers perform inference; Convex only issues candidate contracts and accepts bounded checkpoints and evidence. See `docs/AGENT_RECIPE_LAB.md`.

Execution requires an active blueprint, ready BYOK binding, sufficient credits, rate/concurrency admission, digest-bound input reference, lease, heartbeat, bounded retry, cooperative cancellation, reconciliation, and receipt. Enterprise governance adds residency and backup failure-domain policy, customer-managed key references, retention, legal holds, deletion admission, backup manifests, isolated restore drills, and explicit RTO/RPO.

The governed runtime adds frozen or managed presets, model/tool/workflow allowlists, clarification gates, structured source filters, visible progress and contradictions, exact provider usage, editable artifact references, component scores, redacted traces, and digest-bound suspend/resume snapshots. Blueprint steps support sequential, parallel, branch, and bounded-loop flow. Human-published operations-manual rules are checked against the actual path. See `docs/AGENT_INFRA_PATTERN_MATRIX.md`.

Remote operations databases are an assembly ingredient. PostgreSQL, MySQL, SQL Server, MongoDB, and warehouse connections use opaque endpoint and secret references. Agents never submit arbitrary SQL: admins publish named views, parameterized operations, or stored procedures; reads queue to a trusted worker, and writes require a distinct reviewer's exact digest approval.

## Execution-time Trust gateway

The Runs view can now issue a five-minute, one-use local capability for an independently approved action. The Convex policy binds subject, connector audience, scope, exact resource, environment, action digest, revocation state, and a per-action cost ceiling. Successful authorization consumes the grant and reserves spend in the same transaction; expired, replayed, revoked, wrong-audience, wrong-resource, and over-budget requests fail before side effects with exact error codes.

This is a supervised local capability record, not a signed bearer token. It invokes no connector, shares no raw human credential, and performs no production write. A future hosted connector adapter must pass this gateway before resolving its own narrowly scoped credential.

## Atomic budget enforcement

The local Convex gateway now reserves integer-cent model-call cost before any future provider work. Settled run cost and every outstanding reservation are checked and committed in one transaction, idempotent call keys block double reservation, reconciliation cannot exceed the reserved ceiling, and unused commitments can be released with receipt and audit evidence. The Runs view exposes hard limit, settled, reserved, remaining, utilization, and the exact refusal state.

This alpha is a ledger and gateway simulation. It invokes no provider, verifies no provider invoice, performs no payment processing, and does not yet aggregate monthly, team, or tenant budgets. A real provider adapter must reserve successfully before network access.

## Scoped memory recall safety

The local Convex pilot now treats persistent memory as quarantinable, untrusted context. Recall derives workspace and agent scope from the selected AgentSpec, requires exact subject and purpose matches before ranking, and excludes records flagged by a bounded five-phrase persistent-instruction heuristic. Each returned item explains its source, purpose, provenance, confidence, policy version, trust label, and match reason. These fields inform proposals only; they grant no capability or authority.

The heuristic is intentionally narrow and deterministic. An eligible result is not proof that content is universally safe. Suspicious content remains visible in the lifecycle ledger and can be corrected by appending a reclassified successor.

## Phase 2 release-safety alpha

The local Convex pilot includes supervised model-change releases: exactly six deterministic gates, a model score of at least 80, 5–25% canary traffic, append-only observations, promotion only after 20 healthy observations with zero failures, and operator rollback with receipt and audit evidence. These controls simulate and prove release policy; they do not deploy production workloads or claim hosted multi-tenancy, billing, or production identity.

The same safety surface now includes a local incident-response rehearsal. Containment suspends the AgentSpec, closes pending runs and approvals, rolls back active canaries, and preserves evidence in one transaction. Recovery remains operator-controlled and requires five unique checks before a previously active agent can resume. It does not page responders or operate production infrastructure.

A working Convex + React vertical slice for building and operating governed AI agents. The first product lane is **PR Assurance**: configure a bounded agent, launch a six-gate run, review an action digest, and retain evidence without allowing memory to grant authority.

## What works

- Ingredient-style agent builder for job, knowledge, memory, authority, provider profile, and hard budget.
- Convex system of record with realtime dashboards and indexed workspaces, specs, runs, gates, approvals, receipts, memories, usage, and audit events.
- Six deterministic run gates: requirements, tests, architecture, contracts, budget, and human approval.
- Fail-closed budget enforcement before a run writes any state.
- Digest-bound approval decisions with replay rejection.
- Short-lived, audience/resource-bound, single-use capabilities with revocation and atomic cost reservation.
- Provenance-bound memory that remains untrusted context and supports append-only correction lineage, sensitive-field erasure, retention enforcement, sanitized export, and deletion receipts.
- Explicitly unsigned prototype receipts so the UI never overclaims cryptographic proof.
- Append-only AgentSpec version history with canonical export/import and non-destructive rollback.
- Emergency pause/resume and permanent revoke controls that atomically close pending runs and approvals.
- Secret-free BYOK references for OpenAI and Anthropic using environment or vault schemes; provider secret values never enter Convex records.

## Run locally

Requirements: Node.js 20+ and npm.

```powershell
npm install
npx convex dev
```

In a second terminal:

```powershell
npm run dev
```

The first command can create a local Convex deployment without an account. The generated `.env.local` is ignored by git. Vite is fixed to [http://127.0.0.1:6670](http://127.0.0.1:6670) for both development and preview, with strict-port mode enabled so an occupied port fails visibly instead of moving the app. Port 6668 is deliberately avoided because Chromium-family browsers classify the 6665–6669 range as unsafe.

## Render web deployment

The repository-root `render.yaml` deploys the Agent Oven UI as a Render static site. Render must receive `VITE_CONVEX_URL`, `VITE_AUTH0_DOMAIN`, and `VITE_AUTH0_CLIENT_ID` through its Dashboard; no browser configuration value is committed. The source worker is intentionally excluded because Render static hosting cannot satisfy its projected workload-identity and CSI-mounted-secret contract.

## Verify

```powershell
npm run verify
npm audit --audit-level=high
```

Backend behavior is exercised with `convex-test`; UI behavior uses Testing Library. `verify:stack` rejects accidental introduction of an alternate backend SDK or URL marker.

## Release qualification

```powershell
npm run verify:enterprise
npm audit --audit-level=high
```

The enterprise gate runs all tests, typechecking, production build, Convex-only stack verification, secure-hosting manifest checks, and enterprise artifact checks. A separate `npm run verify:production-env` validates required production variable names and opaque references without printing values. `npm run test:load` refuses to target an unspecified or non-staging host.

## Product boundary

The repository is an enterprise release candidate, not a claim that an external production tenant is live. Real Auth0/SCIM tenants, billing and email providers, DNS, CSP host allowlists, runtime and backup workers, object storage, connector OAuth grants, DSSE production signing, telemetry, penetration testing, legal approval, support staffing, and measured live SLOs must be activated and recorded during deployment. See `docs/PRODUCTION_RUNBOOK.md` and `docs/ENTERPRISE_RC_HANDOFF.md`.
