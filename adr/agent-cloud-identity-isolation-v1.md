# ADR — Derive workspace authority from authenticated membership

## Decision

The Convex authorization seam derives a stable principal from `ctx.auth.getUserIdentity().tokenIdentifier` and resolves an active workspace membership before returning protected data. Resource ownership is checked after membership, so possession of a workspace or AgentSpec identifier grants no authority. One authenticated principal may bootstrap an empty workspace exactly once; later administration is owner-only and cannot remove the last owner.

## Why

Client-supplied tenant identifiers are routing hints, not authorization. Binding issuer and subject through Convex's verified identity and enforcing membership in the transaction creates a testable isolation boundary without storing raw tokens or identity claims.

## Consequences

This mission supplies a local backend foundation and readiness UI, not hosted multi-tenancy. Existing prototype routes remain local-only until an OIDC provider is selected and every route is migrated behind this guard. That later migration must be all-or-nothing before any hosted tenant data is accepted.
