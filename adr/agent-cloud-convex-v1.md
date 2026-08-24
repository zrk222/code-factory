# ADR: Convex for Agent Cloud v1

## Status

Accepted — 2026-07-20

## Decision

Use Convex as the exclusive v1 application backend, database, realtime synchronization layer, and server-function runtime. Use React, TypeScript, and Vite for the client. Do not include Supabase.

## Rationale

Convex provides runtime-enforced schemas, typed queries/mutations/actions, atomic mutations, and realtime React subscriptions within one TypeScript system. This fits the control-room workflow and reduces integration surfaces in the vertical slice.

## Boundaries

- Convex stores product records and prototype evidence; it does not store provider or connector secret values.
- Live GitHub writes, paid model calls, production identity, and cryptographic signing require separate approved adapters.
- Memory and Trust are clean-room logical modules behind explicit contracts and do not access WizeMe source.
- Prototype receipt fingerprints are lineage aids, not digital signatures.

## Consequences

- Local development uses the open-source Convex backend or a developer deployment.
- `VITE_CONVEX_URL` is the only client-visible backend location.
- Production deployment requires a Convex deployment key and separate security review.
