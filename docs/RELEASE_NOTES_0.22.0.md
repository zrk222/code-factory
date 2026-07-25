# Code Factory 0.22.0

Code Factory 0.22 adds a paired savings tracker for publishing exact,
auditable samples of elapsed-time, token, and cost changes.

## What shipped

- `factory savings record` writes an atomic private receipt for an exact
  baseline-versus-Factory pair.
- `factory savings report` produces an aggregate-safe public JSON report.
- Signed deltas preserve regressions, while absent counters remain unknown.
- Productivity gain remains withheld until equivalent-outcome evidence is
  explicitly asserted and hash-bound.
- Factory Studio, VS Code 0.7.0, and JetBrains 0.7.0 expose the same report.

## Evidence boundary

The tracker performs arithmetic over user-supplied observations. It does not
run the compared workflows, infer missing counters, certify causal attribution,
or establish outcome equivalence. Public exports deliberately exclude pair
identifiers, paths, evidence hashes, and per-pair measurements.
