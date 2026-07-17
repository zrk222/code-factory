# Changelog

## Unreleased

### Fixed

- Aligned all public install instructions, IDE download links, and narrated
  quick-start asset names with the verified `0.17.1` release.

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
