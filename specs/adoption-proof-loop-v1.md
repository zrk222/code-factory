# Spec: adoption-proof-loop-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Make Code Factory's differentiated result understandable and reproducible in under two minutes: run a sealed local demonstration that catches a hollow test, emit privacy-safe proof that can be shared voluntarily, and measure the local activation funnel without inventing provider facts or transmitting identity.

### User roles
- Individual developer or vibe coder evaluating Code Factory.
- Team lead reviewing evidence from a governed repository.
- Maintainer operating a time-boxed adoption sprint and voluntary Proof Clinic.

### Requirements (EARS)
- The system shall return marker `HOLLOW_TEST_DETECTED` after running exactly 2 local commands, each capped at 30 seconds, inside a generated sandbox. [R1]
- When the hollow negative control exits zero, the system shall return `HOLLOW_E2E_TEST` and exit the demonstration with status 0 because detection is the expected result. [R2]
- The system shall write exactly 1 content-addressed JSON receipt and 1 Markdown receipt for the demonstration. [R3]
- The system shall write exactly 1 opt-in Proof Card in each of JSON, Markdown, and 1280x720 SVG formats from a verified receipt. [R4]
- The system shall return Proof Card privacy flags as false for commands, paths, repository names, prompts, logs, and user identity. [R5]
- If the named receipt digest or Proof Card digest changes, the system shall reject the named artifact with a deterministic invalid-card or invalid-source error. [R6]
- The system shall store only explicit local activation milestones (`first_proof_completed`, `proof_receipt_saved`, `proof_card_saved`, and `seven_day_return`) and shall transmit 0 events. [R7]
- Where provider visits, installs, or downloads are unavailable, the system shall return null rather than infer users. [R8]
- The system shall write a distribution scorecard and label downloads, local milestones, and verified outcomes as three non-additive evidence classes. [R9]
- The system shall write a 21-day adoption-sprint boundary that permits only critical reliability, security, activation, documentation, packaging, compatibility, and provider-trust work. [R10]
- The system shall write a voluntary Proof Clinic contract with exactly 10 repository slots and 0 claimed enrollments before owner opt-in. [R11]
- The system shall write the official Open VSX namespace claim URL and return verification status as externally pending until Eclipse grants ownership. [R12]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: A new user sees Code Factory catch a hollow test
  Given a clean workspace
  When the user runs factory first-proof --root .
  Then the command exits zero, reports HOLLOW_E2E_TEST, and writes verified proof artifacts

Scenario: A developer shares proof without leaking workspace data
  Given a verified first-proof receipt
  When the user creates a Proof Card
  Then the card contains the result and receipt hash but no command, path, repository, prompt, log, or identity

Scenario: An honest activation report has missing provider facts
  Given only local milestones are recorded
  When the user requests adoption status
  Then provider visits and installs are null and local milestones are aggregated without identity
```

## SHOULD — Technical/structural
- Reuse the existing E2E proof verifier and receipt machinery.
- Keep all adoption data under `.factory/adoption/` and sharing artifacts under `.factory/share/`.
- Preserve deterministic ordering and canonical JSON hashes.
- Public copy should lead with the outcome: catch AI-generated tests that could never fail.

## SHOULD NOT — Implementation details
- Do not add telemetry transmission, account creation, hidden uploads, or inferred user counts.
- Do not treat a Proof Card as production-readiness evidence beyond its bound receipt.
- Do not claim Open VSX verification before the provider grants it.

## Decision logic (factory candidates)
No prompt-routed factory candidate is permitted. Decisions are implemented by
the deterministic receipt, digest, milestone-allowlist, and null-preservation
rules above.
