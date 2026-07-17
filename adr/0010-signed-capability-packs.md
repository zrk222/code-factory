# ADR 0010: Signed Capability Packs

## Status

Accepted for 0.16.0.

## Decision

Target and capability diversity is represented by local pack directories whose
complete file maps are sealed in offline DSSE Ed25519 envelopes. Validation is
structural and mutation-tested. Installation is confined to
`.factory/packs/<pack-id>`, refuses replacement by default, and uses a staged
backup/swap/rollback sequence when force is explicit.

The initial pack set covers worker, web, mobile, and supervised agent UI
targets. The compiler consumes their metadata but retains its existing reviewed
generator implementations in 0.16.0. A future adapter registry may move those
implementations behind the same pack boundary after equivalent behavioral
proof exists.

## Consequences

- New target metadata no longer requires editing a central Python table.
- A copied or modified pack fails closed until a trusted publisher signs it.
- Pack installation grants no execution, connector, network, release, or
  publication authority.
- Private signing keys remain outside source and distribution artifacts.
