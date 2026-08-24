# ADR: Adversarial approval with Proof Delta

## Decision

Use a deterministic independent approval policy as the authorization boundary. Model-based review remains heuristic input only. Permit policy auto-approval solely for proved, low-cost, test-only read/analysis tasks; preserve authenticated human accountability for consequential or production actions.

Use content-addressed Proof Delta to focus a reviewer on changed evidence. A prior review may narrow attention but never grants authority to a new action digest.

## Consequences

- Safe repetitive analysis can complete without a manual click.
- Consequential work remains explicitly supervised.
- Missing, stale, blocked, identity-colliding, or malformed evidence fails closed.
- Productivity is represented by exact evidence reuse counts, not an unsupported time-savings claim.
