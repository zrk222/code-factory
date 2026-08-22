# Code Factory 0.44.0 — First Proof

Code Factory's differentiated result is now one command away:

```powershell
factory first-proof --root .
```

## What changed

- A sealed local sandbox demonstrates a healthy positive control and catches an
  intentionally hollow negative control as `HOLLOW_E2E_TEST`.
- Verified receipts can produce opt-in Proof Cards as JSON, Markdown, and a
  light 1280x720 SVG. Cards exclude commands, paths, repository names, prompts,
  logs, and user identity and reject tampering.
- Local activation milestones can be aggregated without central telemetry.
  Missing provider visits and installs remain `null`, and downloads are never
  reported as people or verified outcomes.
- A 21-day adoption sprint pauses new subsystems while reliability, activation,
  onboarding, compatibility, and provider trust are improved.
- A voluntary Proof Clinic offers ten real repositories one supervised proof
  review, with separate consent required for any public case study or quote.
- Open VSX namespace ownership claim
  [#12688](https://github.com/EclipseFdn/open-vsx.org/issues/12688) is formally
  submitted. Verification remains pending until Eclipse grants the claim.

## Boundary

The first proof is an explicit demonstration, not an assessment of the user's
project. Proof Cards summarize one verified receipt; they are not production,
security, coverage, identity, or release certificates. No source, identity, or
activation event is centrally transmitted.
