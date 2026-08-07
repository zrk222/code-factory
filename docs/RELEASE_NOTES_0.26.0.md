# Code Factory 0.26.0

Code Factory 0.26.0 adds the **habituation gate**.

Every gate in this package receipts an outcome: a check passed, a proof was
recorded, a conflict was found. None of them receipted the *reliability of the
signal that produced the outcome*. The most important such signal is a human
clicking approve, and that signal decays specifically for machine-authored
change: within the same reviewer, approval of agent code rises while inline
commenting falls. A gate that degrades quietly is worse than no gate, because
the receipt it produces still looks authoritative.

## What shipped

- `factory habituation record` observes a review event and computes scrutiny as
  seconds per 100 changed lines.
- `factory habituation status` evaluates the gate: surface, second approver, or
  fail closed at `scrutiny_floor`.
- `factory habituation sample` and `resample` run deterministic blind-spot
  re-review so the drift metric has an external correction term.
- `factory habituation report` exports aggregate-safe public JSON.

## Evidence boundary

Scrutiny ratio, comment density, and approval rate are **measured**. Drift is
measured against a reviewer's own baseline and never against peers, because
habituation is an exposure effect and ranking individuals would attribute a
systemic property to a person.

Drift is withheld below five agent-authored reviews or five baseline reviews.

**Blocking requires a corrected proxy.** Scrutiny time is a proxy for attention;
a fast expert is indistinguishable here from a habituated reviewer. Fail-closed
is refused until blind-spot re-review outcomes exist, however bad the drift
looks. Blocking a merge on a self-confirming proxy is not a gate.

Escaped-defect linkage is **modeled**, disabled by default, and withheld below
twenty outcomes. It reports a rate within a deliberately non-representative
sample. It is not the repository's defect rate, it is not causal, and it never
attributes a defect to an individual — that counterfactual cannot be tested and
does not belong in a receipt.

Reviewer identities are stored as digests. Public exports carry distributions
only, with no per-reviewer rows.
