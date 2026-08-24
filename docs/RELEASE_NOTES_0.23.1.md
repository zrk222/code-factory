# Code Factory 0.23.1

Code Factory 0.23.1 is a supply-chain security patch for the VS Code extension
build toolchain.

## Fixed

- Resolve `brace-expansion` to 5.0.9, addressing GHSA-mh99-v99m-4gvg.
- Resolve `fast-uri` to 3.1.5, addressing GHSA-v2hh-gcrm-f6hx.
- Run `npm audit --audit-level=high` after `npm ci` and before tests in both
  VS Code continuous integration and release packaging.

## Evidence

- The reviewed lockfile reports 0 vulnerabilities on Node 22.
- VS Code compilation, tests, and dependency-free VSIX packaging pass with the
  patched graph.
- Deterministic publication tests enforce the exact resolutions and workflow
  order.

## Scope boundary

The affected packages are development-only transitive packaging dependencies.
They were not bundled into the dependency-free VSIX, and this patch adds no
extension command, permission, activation event, or runtime authority.
