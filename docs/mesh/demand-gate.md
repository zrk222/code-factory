# Memory Platform demand gate

**Status:** pre-committed discovery benchmark
**Evidence convention:** `[F]` founder-supplied hypothesis; `[D]` data-verified only after a recorded conversation or audit receipt; `[U]` unknown until tested.

This gate prevents the Mesh product thesis from being treated as validated before buyers expose a real memory-governance problem. It is a market experiment, not a product claim.

## Kill criteria

Run **N = 12** qualified conversations with teams that have an agent in production or a live pilot using persistent memory. Count only conversations with a named operator, security/legal owner, or engineering owner who can describe the current memory path.

Pass requires both thresholds:

| Measure | Threshold | What counts as evidence |
|---|---:|---|
| Specific incident signal (`X`) | **X ≥ 4** of 12 | A participant describes a concrete past incident (not a hypothetical) where the team could not explain why an agent acted on, recalled, or retained a memory. Record date/period, system, impact, and how they investigated. `[D]` |
| Concierge audit commitment (`Y`) | **Y ≥ 3** of 12 | A qualified team agrees to a free, one-week manual audit of its memory configuration for cross-tenant leakage, unauthorized recall, missing provenance, and revocation/deletion failures, with a named owner and a start window. `[D]` |

These thresholds are the pre-committed founder hypothesis `[F]`; they are not evidence that demand exists. The experiment passes only when both are met. A result below either threshold kills the current demand thesis and triggers a documented pivot before expanding Mesh implementation scope. Do not reinterpret polite interest, a future-only answer, or a generic “that is interesting” as a pass.

## Interview protocol

Ask about observed history, not willingness to pay:

1. When an agent did something unexpected, how did you determine which memory it accessed and why?
2. Has legal, security, a customer, or an internal reviewer asked you to prove what an agent accessed? What did you provide?
3. What happens today when a customer asks you to delete data from agent memory? How do you verify deletion?
4. Which memory store, framework, or connector is in the path, and who owns its policy?

Do not pitch a feature before the historical answers are recorded. Store participant consent, role, source system, and the exact evidence class. Redact personal or customer data; never import a live customer memory store into the repository.

## Concierge audit offer

The audit is manual and free for the first experiment. It reviews configuration and representative receipts only; it does not request production credentials or unrestricted memory exports. The written report checks:

- tenant and purpose boundaries;
- unauthorized recall and cross-tenant access paths;
- provenance completeness and source authority;
- revocation, deletion, legal-hold, and cache/index behavior;
- an evidence-backed remediation list.

Record three outcomes separately: **blocked access**, **access granted with no meaningful concern**, or **access granted with an alarming finding**. All three are informative. Only a named owner and an accepted audit window count toward `Y`.

## Decision receipt

At the end of the experiment, publish a small redacted receipt beside the Mesh build evidence containing:

- `n_conversations`, `x_incident_signals`, `y_audit_commitments`;
- participant qualification and consent status;
- source-labeled notes or hashes for each counted signal;
- audit outcome counts and remediation themes;
- the pass/fail decision against the fixed thresholds;
- the pivot or continuation decision and its owner.

Until that receipt exists, demand is **`[U]`** and the Mesh PRD must not describe enterprise demand as established. Interleave this gate with implementation milestones; do not wait for the NEW units to finish before testing it.

## Commitment before cash

The first audits are deliberately free: they buy product information and avoid a procurement-heavy false negative. They are not low-friction favors. An audit counts only when the team commits to the costly inputs that make it useful:

- a named owner for the follow-up;
- an NDA or equivalent confidentiality approval when required;
- a representative configuration and receipt sample, with production secrets excluded;
- **three hours of a security or engineering reviewer’s time**; and
- an agreed one-week audit window.

Pre-commit the next gate now: run **N-free = 3** qualifying audits, and require **X-paid ≥ 1** paid follow-on (the second audit or fixed-scope remediation) from those three. `[F]` If fewer than one converts, do not call the audit a validated business or expand services. Record the clean no as evidence, keep the public benchmark and open Memory CI free, and revisit the product thesis rather than turning bespoke consulting into the default business.

Payment is accepted only for a fixed-scope follow-on with a written cap and an explicit deliverable that becomes a redacted Memory CI test case. The audit remains a research instrument that may bill; it is not permission to create an uncapped compliance-consulting lane.
