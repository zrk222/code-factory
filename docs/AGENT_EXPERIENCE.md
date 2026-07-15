# Agent Experience Contract

Code Factory treats its CLI as an interface for both people and coding agents.
The front door follows a small, testable subset of the AXI agent-experience
principles without inheriting external benchmark claims.

## Contract

| Principle | Factory behavior |
|---|---|
| Content first | `factory` returns live state instead of generic help. |
| Definitive empty states | Proof categories print explicit zero counts. |
| Pre-computed aggregates | Brick compatibility and proof counts arrive in one call. |
| Contextual disclosure | Every home response includes concrete next commands. |
| Structured automation | `factory home --json` and `factory doctor --json` are stable machine views. |
| Fail loud | Unknown commands and flags retain argparse exit code 2. |
| Bounded output | Home output contains counts and paths, not receipt bodies. |

Receipts remain JSON because they are durable interchange artifacts with schema
validation and hashing. Token-optimized display formats may be added only after
their parser, round-trip behavior, and measured token effect are benchmarked.

## First Call

```console
$ factory
bin: .../factory
description: Five-brick spec-to-proof software factory
bricks: 4 of 4 installed
proof:
  receipts: 0
  traces: 0
  challenges: 0
  passports: 0
next:
  - factory doctor --json
  - factory plan
  - factory init .
```

The home view complements the first-class Mermaid Factory Passport graph in
[ProofLab](PROOFLAB.md): one is the lowest-cost discovery surface; the other is
the durable visual proof artifact.
