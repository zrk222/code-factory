# Code Factory 0.31.0

## Prove an E2E check can reject the failure it names

`factory e2e verify` is a local, vendor-independent proof-by-sabotage gate for
one approved E2E command pair. Its manifest declares a positive command that
must exit `0`, a negative mutation command that must exit non-zero, explicit
argument vectors, a bounded timeout, and required artifacts.

```powershell
factory e2e verify `
  --root . `
  --manifest proofs/login-e2e.json `
  --out-dir .factory/e2e/login-e2e `
  --json
```

If the negative command exits `0`, the receipt reports `HOLLOW_E2E_TEST` and
the command exits non-zero. A passing result proves only the declared local
command pair and declared artifacts. It does not provision a browser grid,
enforce host network isolation, repair source, approve a merge, publish,
deploy, or claim production readiness.

## Prepare a bounded Team Pilot without pretending a service exists

`factory team-pilot readiness` compiles a hash-bound packet for an owner to
review after selecting one to three potential design partners. It requires five
local, non-secret decisions: partner selection, deployment/security boundary,
data retention, support/incident ownership, and commercial-terms review.

```powershell
factory team-pilot readiness `
  --root . `
  --manifest .\team-pilot.json `
  --out-dir .\.factory\team-pilot `
  --json
```

Its only success marker is `TEAM_PILOT_READY_FOR_OWNER_REVIEW`. The accepted
governance is `human_controlled`; the accepted delivery mode is
`customer_managed_reference`. The command cannot accept a customer, issue
terms, collect payment, provision access, or activate a managed Team Proof Hub.

The Free Core remains available. Team Proof Hub, Enterprise Assurance, and a
Managed Proof Runner are staged concepts, not purchasable offers. Read
[Commercial packaging](COMMERCIAL_PACKAGING.md) and the [Team Pilot
guide](TEAM_PILOT_LAUNCH.md) for the operating boundary.

## Release evidence

This release keeps the per-channel publication boundary explicit. GitHub and
PyPI release artifacts are created only by `publish.yml` after Python, VS Code,
and JetBrains candidate validation. The Hugging Face Space is uploaded through
its separate metadata-preflight workflow. Visual Studio Marketplace, Open VSX,
and JetBrains Marketplace publication each require their own credential and/or
moderation gate; a GitHub release asset is not a claim that a moderated listing
is live.

```powershell
pip install factoryline-code-factory==0.31.0
```
