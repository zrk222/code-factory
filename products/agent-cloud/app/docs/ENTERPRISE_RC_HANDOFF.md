# Agent Oven enterprise release-candidate handoff

## Completed missions

1. Twenty-eight priced agent recipes, including separately governed legal, professional MLS, consumer real-estate, civic-planning, trade, environmental, provider-credentialing, drug-safety, food-recall, UAS, energy, and workplace-safety recipes; sixteen novice automation presets; governed Knowledge Wall; and extensible connector definitions.
2. Immutable Agent Blueprint builder with guided/architect modes, typed ingredients, simulation, and credit-gated activation.
3. Subscription credit accounts, fixed template prices, custom base-plus-ingredient pricing, and shared/dedicated BYOK bindings.
4. Hosted execution substrate with admission, leases, heartbeats, retry, cancellation, credit reconciliation, and evidence.
5. Operations and production packaging: backup/restore control plane, secure headers, environment validation, legal/security drafts, incident/rollback/release runbooks, and qualification commands.

Enterprise hardening:

1. Organizations, delegated administration/audit, SSO/SCIM metadata, idempotent directory provisioning, and role mapping.
2. Residency, separate backup failure domain, customer-managed key references, retention, legal holds, deletion admission, and recovery targets.
3. Atomic rate/concurrency controls, load-test guardrails, security/procurement/SLA/DR packets, and an enterprise release gate.

## Verification receipt

Verified July 21, 2026 from the app directory:

- 33 test files passed; 96 tests passed.
- TypeScript project build passed.
- Vite production build passed: JS 237.59 kB (74.38 kB gzip), CSS 70.27 kB (14.31 kB gzip).
- Convex-only stack verified across 100 source and manifest files.
- Repository release and enterprise artifact qualification scripts passed. Runtime enterprise posture remains fail-closed until a directory is activated and real backup/restore evidence exists.
- `npm audit --audit-level=high`: zero vulnerabilities.

## Deployment activation ledger

The following are deliberately not represented as completed by repository tests: production Auth0/SCIM configuration, billing webhook signatures and checkout, transactional email delivery, runtime-worker provider calls, backup object writes, connector OAuth/sync, production DSSE key custody, DNS, telemetry alerts, external penetration test, legal approval, support staffing, and live SLO measurement. The production runbook converts each into an explicit deployment check and evidence receipt.
