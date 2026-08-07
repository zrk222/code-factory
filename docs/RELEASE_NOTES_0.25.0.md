# Code Factory 0.25.0

Code Factory 0.25.0 adds **CDTE**, the contradiction gate: a deterministic check
that runs after the spec is locked and before any build stage.

SpecLine removes ambiguity from a spec. CDTE removes contradiction. They are
different defects. "p95 under 50ms" and "field-level AES-256 on the checkout
path" are each perfectly unambiguous, so a contradictory spec passes every
clarity gate and reaches the build. CDTE stops it there.

## What shipped

- `factory cdte scan <run-id> <constraints.json>` detects lethal pairs by lookup
  over a decision table and writes an atomic receipt. It exits non-zero when the
  gate engages, so CI fails closed.
- `factory cdte report` produces aggregate-safe public JSON.
- `factory cdte resolve` records an ADR decision or an expiring, approver-named
  override.
- The assembly line pauses at `nfr_conflict` and offers a continuation command.
- Savings receipts now use exact decimal arithmetic for cash fields.

## Evidence boundary

CDTE reports contradictions between constraints it was given. It does not
measure systems, does not infer unstated requirements, and does not assert that
a conflict is unresolvable in principle.

Incompatibility analysis carries one of three tiers, declared in the registry
and never chosen at runtime: `measured` is bound to a benchmark file by SHA-256;
`modeled` prints the formula and every assumption it rests on; `structural`
carries no numbers at all. There is no fourth tier. An analysis whose inputs the
spec did not supply is withheld rather than estimated — the conflict is still
reported, the quantification is not.

Detection calls no model. Given the same constraints and registry it returns the
same conflicts, which is what allows the result into a receipt.

Public exports carry counts and pair frequencies only. Constraint text describes
an employer's unreleased system and does not leave the machine.
