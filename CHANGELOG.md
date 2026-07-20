# Changelog

## Unreleased

## 0.19.0 - 2026-07-19

### Added

- Added a supervised hosted tenant lifecycle with bootstrap platform authority,
  per-tenant OIDC/JWKS configuration, atomic group-to-role replacement,
  secret-manager references, and one-time GitHub installation state.
- Added immutable installation binding, forced PostgreSQL RLS for tenant
  control tables, serialized hash-linked administrative audit events, and a
  redacted tenant operational overview.
- Added a responsive read-only operator console with in-memory-only Bearer use,
  no mutation controls, `no-store` responses, and a restrictive content
  security policy.

### Security

- Tenant claims are used only as identity-configuration lookup hints; authority
  is granted only after RS256 signature, issuer, audience, expiry, tenant, and
  group verification.
- Bootstrap fallback is restricted to a verified `platform_admin` principal
  whose tenant claim is exactly `*`.
- Webhook secrets resolve from allowlisted `env://` references at request time;
  resolved values, references, installation state, and tokens are excluded
  from overview responses and structured operation events.

### Evidence boundary

- The hosted control plane is supervised and deployable, but it does not claim
  SCIM, SAML enrollment, managed KMS, HA, disaster recovery, SOC 2, or an SLA.

## 0.18.0 - 2026-07-19

### Added

- Added authenticated GitHub pull-request assurance with raw-body HMAC
  verification, immutable installation-to-tenant routing, durable delivery
  replay protection, and deterministic GitHub Check request contracts.
- Added offline RS256 OIDC verification against pinned JWKS, issuer, audience,
  expiry, not-before, tenant, groups, JTI replay, duplicate JSON member, and
  minimum RSA key-strength checks.
- Added the optional hosted adapter with PostgreSQL forced row-level security,
  transactional approval and Check outbox writes, freshness-bounded HTTPS JWKS
  rotation, short-lived GitHub App publication credentials, health/readiness
  routes, secret-free operation events, and a reference container.
- Added a PostgreSQL 17 integration workflow plus hostile hosted-adapter smoke
  and reverse-stub challenge receipts.

### Security

- Tenant identity is derived from immutable GitHub App installation mappings;
  caller-supplied tenant headers have no authority.
- Human decisions remain committed independently of GitHub availability, while
  failed publication remains classified in a bounded transactional outbox.
- Hosted network destinations require HTTPS, use five-second timeouts, and do
  not follow redirects.

### Evidence

- Enterprise PR assurance and the hosted adapter both reached ForgeLine grade A
  with strict SpecLine contracts, validator mutation gates, architecture gates,
  hostile tests, and non-hollow smoke checks.

## 0.17.3 - 2026-07-18

### Added

- Added `factory verify-receipts`, an offline Receipt v2 mutation gate that
  proves digest, signature, identity, and back-dated revocation failures with
  exact error codes and a canonical challenge receipt.
- Added property-based canonical JSON tests for stable round trips, dictionary
  ordering, Unicode, non-finite floats, lone surrogates, and unsupported values.
- Added an enforceable documentation contract and meaningful docstrings for
  every distributed public Python function and callable member.

### Security

- Added adversarial Studio mission-decision HTTP tests for wrong tokens,
  repository escapes, and replayed decisions without receipt replacement.
- Hardened migration receipt verification so malformed evidence rows and
  digests return structured invalid verdicts instead of unclassified errors.
- Added the receipt-chain mutation gate to the identity-pinned Sigstore CI path.

### CI

- Added Hypothesis to the standard development and release test dependency set.
- Updated Gradle Actions to `v6.2.0`, removing the deprecated Node 20 action
  runtime and the post-build Gradle cache-cleanup invocation.
- Updated the Marketplace workflow's immutable release default to `v0.17.3`;
  publication still requires the separately scoped JetBrains publisher token.

## 0.17.2 - 2026-07-18

### Added

- Added nine owner-supplied concept illustrations, an ordered SHA-256 asset
  manifest, and an accessible walkthrough for GitHub, PyPI, Product Hunt
  preparation, GitHub release assets, and the Zenodo source archive.
- Added deterministic publication tests for image identity, dimensions, order,
  alt text, absolute PyPI image URLs, and visual evidence boundaries.

### Fixed

- Aligned all public install instructions, IDE download links, and narrated
  quick-start asset names with the verified `0.17.1` release.
- Corrected Product Hunt instructions: gallery video entries require a full
  YouTube URL; a local MP4 is not a valid video entry.

### Evidence boundary

- The new artwork is labeled as concept illustration, not shipped UI or
  measured outcome evidence. The metric-bearing draft infographic is excluded.

## 0.17.1 - 2026-07-17

### Security

- Replaced the stored PyPI API-token publish path with GitHub OIDC Trusted
  Publishing and enabled distribution attestations.
- Added a release-workflow regression test that rejects stored PyPI
  credentials or removal of the protected environment and OIDC permission.
- Split validation from deployment so OIDC and release-write permissions exist
  only in the protected publish job.
- Added a pull-request package contract that builds, checks, installs, and
  exercises the wheel before release.

## 0.17.0 - 2026-07-17

### Added

- Runnable signed target packs for deterministic CLI, FastAPI, and local stdio
  MCP starters, alongside the existing worker, web, Expo, and agent UI targets.
- A 29-pack built-in catalog spanning targets, React/Next.js/Expo/browser
  extension surfaces, eight language families, seven common capabilities,
  data pipelines, evaluation harnesses, and admin operations.
- `factory pack compose` for compatible, hash-bound composition plans with no
  implicit generation, execution, deployment, or publication authority.
- Pack compatibility declarations for target support, required pack kinds,
  conflicts, and provided capabilities.

### Changed

- Capability Pack validation now rejects ten meaningful contract mutations,
  including generator drift, hollow validators/goldens, relaxed migration
  policy, and empty provided-capability declarations.
- Public architecture, Product Mission, pack, install, citation, and Zenodo
  metadata now describe the same 0.17.0 product surface.

### Compatibility

- Existing `local-split`, `split-hosting`, `expo-preview`, `eas-store`,
  `local-operator`, and `private-container-host` deployment profile IDs remain
  unchanged.
- Pack composition creates a review artifact only. Product-specific code still
  requires a Product Graph value slice, independent verification, and explicit
  release approval.

## 0.16.0 - 2026-07-17

- Added Product Graphs, value slices, bounded Missions, no-finish verification,
  evidence-linked PR drafts, classified outcomes, Meter v2, Studio product
  controls, IDE requirement proof links, and the first four signed target packs.
