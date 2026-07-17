# ADR 0011: Composable Capability Pack Catalog

Status: Accepted for 0.17.0.

## Context

The first signed pack release proved that target metadata could replace a
hard-coded target list, but it covered only worker, web, mobile, and agent UI
starters. Product work also needs CLI, API, MCP, language, surface, common
capability, data, and operator contracts without claiming every combination has
already been implemented.

## Decision

- Ship seven executable target packs: CLI, API, MCP, worker, web, mobile, and
  supervised agent UI.
- Ship composable surface, language, capability, data, and operations packs as
  explicit integration contracts.
- Require every pack to declare compatible targets, required pack kinds,
  conflicts, and provided capabilities.
- Expand pack validation from five to ten meaningful mutations.
- Add `factory pack compose` to write an atomic, hash-bound compatibility plan.
- Keep `generate`, `execute`, `deploy`, and `publish` authority false in every
  composition. A Product Graph value slice and independent proof remain
  mandatory before those actions can be considered.
- Preserve all existing public deployment profile IDs.

## Consequences

Users can inspect and combine the supported software vocabulary before code is
generated. The catalog is useful for planning and validation but cannot be
misread as proof that product-specific auth, billing, offline sync, or other
integrations already exist. Release keys remain external to the repository;
only public trust roots and DSSE signatures are committed.
