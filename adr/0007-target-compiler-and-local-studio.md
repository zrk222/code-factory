# ADR 0007: Four-target compiler and local Factory Studio

## Status

Accepted.

## Context

Factoryline already compiles PRDs into reviewable web starters and coordinates
proof across the five Code Factory bricks. Users need one discoverable entry
point for governed workers, web apps, mobile apps, and operator interfaces.

## Decision

Add a deterministic target compiler with four target kinds and a loopback-only
browser Studio. The CLI remains the authority. Studio delegates to the same
Python functions, writes only beneath its configured root, refuses non-empty
outputs, and has no publish, deploy, signing, credential, or external-message
capability. Editors may launch Studio only after their existing trust gate.

Mobile output follows Expo SDK 57 Continuous Native Generation, so generated
projects carry `app.json` and `package.json` but no committed native projects.

## Consequences

- One intent can begin four software shapes under the same proof contract.
- Generated projects are blocked until product-specific tests and gates pass.
- The local Studio is a development convenience, not a production server.
- Deployment, publication, signing, and connector authorization stay outside
  the Studio boundary and remain human-owned.
