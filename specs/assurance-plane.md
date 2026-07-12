# Spec: assurance-plane-foundation

Add deterministic assurance artifacts over the control-plane evidence
contract.

## Requirements

- The system shall build a tenant-scoped evidence graph, reject missing
  parents and cycles, and emit a deterministic graph digest.
- The system shall select a deterministic risk-adaptive gate order and include
  all dependencies of every selected gate.
- The system shall execute commands without a shell, inside a contained
  working directory, with an allow-listed environment and an explicit
  process-boundary limitation.
- The system shall emit sorted CycloneDX-shaped SBOM components and a digest.
- The system shall reject unknown VEX statuses and emit a deterministic VEX
  digest.
- The system shall delete and invert every explicit policy rule mutation and
  return `HOLLOW_POLICY` when a mutation is not caught by the supplied oracle.
- The system shall publish only a private challenge-set count and digest, not
  challenge payloads.

## Scope boundary

The local runner is not a kernel, container, or network sandbox. Production
deployments must supply a stronger isolated runner for untrusted code. Private
challenge manifests are digest-only; encryption and remote access control are
later privacy-plane work.

