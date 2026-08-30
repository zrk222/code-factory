# Code Factory 0.45.1 — catch the App Review gap before Apple does

You can have a polished interface, a passing test suite, and a configured
subscription—and still lose days because the selected build was never proven on
the reviewer path. Code Factory 0.45.1 adds a standalone and integrated AppForge
App Review gate that turns those hidden assumptions into visible stop-ship facts.

## What changed

- Thirty rules cover completeness, safety, performance, business/IAP, design,
  metadata, privacy, legal, accessibility, reviewer access, and export readiness.
- Every observation is bound to one bundle, version, build, and source commit.
- Conditional rules must be required or explicitly not applicable with a named
  reviewer and rationale; omission and non-boolean “truth” fail closed.
- Sanitized regression classes derived from prior real App Review findings cover
  purchase/restore Sandbox failures and reviewer-iPad navigation/screenshot gaps.
- AppForge + SaaS Mission Control presents the path as mission, tension,
  guidance, agency, transformation, and a calm evidence-backed handoff.
- Credential references can be prepared for a supervised agent without storing
  raw secrets. Final TestFlight/App Review submission remains a separate named,
  expiring human authorization.

## Value boundary

The workflow is designed to save days of avoidable review/rework waiting and to
minimize preventable rejection risk. A greater-than-90% rejection-reduction claim
is a target, not a measured result, and is withheld until representative evidence
supports it. Apple alone decides approval.
