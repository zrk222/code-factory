# Remaining CF and ForgeLine operations work

Authorized on 2026-10-15: Luna High implementation and Astra Medium review after
the completed one-time Astra audit. Completed implementation steps are removed
from this plan; local receipts remain in `.factory/operations-simplification/`.

## Delivery requirements

- Bind final Studio refresh and request-local meter source/tests, exact targeted
  observations and Astra review to a workflow receipt. Preserve the original
  failed attempts. Verify rendered UI checks against the current HTML bytes.
- Resolve ForgeLine PR #5's standalone CI dependency failures and conflicts.
  Optional CF absence must remain explicit; injected reviewer tests must work
  without an installed CF adapter. Retest affected failures only.
- Commit and push reviewed CF changes; complete required CI and merge gates in
  both repositories. A local receipt is not a merged or published package.
- Carry verified capabilities into agent manifests, taxonomy, previews and the
  next immutable distribution through the existing release requirements.

## Frozen constraints

No new module, dependency, scheduler, cache layer or product name. No guard
increase or detector/public API deletion based solely on missing references.
Normalized UTF-8 source ceilings: Studio 175000 bytes / 2797 lines; meter 23577 /
619; CF CLI 182786 / 4914; Mission Control 46322 / 1199; ForgeLine CLI 12501 / 220.
Tests keep their packet budgets. No accuracy or elapsed-time gain is inferred
from source review or the ledger-read count.

## Final smoke boundary

Investigate removal of CF's preliminary smoke only after proving the actual
ForgeLine executable owns final forced smoke and intermediate stages do not
require `SMOKED`. Retain standalone smoke, legacy behavior, source/tool/environment
binding, history validation and post-intent freshness checks. No skip is approved
by this plan. This does not close the broader daily-driver requirements.
