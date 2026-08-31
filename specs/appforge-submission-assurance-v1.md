# AppForge Submission Assurance v1

## Intent

Fail closed before an iOS release candidate is treated as locally ready for
App Store submission. Produce a sealed Markdown checklist and PDF only after
four independent, exact-candidate receipts pass.

## MUST - Functional core

### Requirements

- The submission-assurance command shall reject any missing, malformed, or
  hash-invalid prerequisite receipt.
- When all four prerequisite receipts bind the exact same candidate and pass,
  the system shall write one sealed JSON receipt plus a Markdown checklist and
  PDF dossier.
- When any prerequisite gate is blocked, tampered, or candidate-mismatched,
  the system shall write only the blocked JSON receipt and shall not write the
  final Markdown or PDF dossier.
- While evaluating a quality audit, the system shall require a named reviewer
  to confirm that the submitted user-design input was considered.

## Acceptance scenarios

```gherkin
Scenario: complete candidate produces a dossier
  Given hash-valid App Review, Store media, SaaS, and quality-audit receipts for one candidate
  When submission assurance runs for that candidate
  Then it reports APPFORGE_SUBMISSION_DOSSIER_READY and writes Markdown and PDF artifacts

Scenario: stale or tampered evidence is blocked
  Given one prerequisite receipt has a changed candidate or invalid receipt hash
  When submission assurance runs
  Then it reports APPFORGE_SUBMISSION_DOSSIER_BLOCKED and emits no final report
```

## SHOULD - Governance constraints

## Invariants

1. Every evidence lane binds the same bundle identifier, version, build number,
   and source commit.
2. Receipt hashes are verified before they can satisfy a downstream lane.
3. Final human-readable reports are absent when any lane is missing, blocked,
   tampered, or bound to another candidate.
4. User design input is hash-bound and a named reviewer confirms it was
   considered; generic design assertions cannot replace this confirmation.
5. Visual, accessibility, device, runtime, identity, privacy, performance, and
   recovery checks require file-backed, hash-valid artifacts rather than booleans.
6. The system has no authority to execute a device test, upload, submit, or
   claim Apple certification or approval.

## Exit criteria

- Store media receipt reports `APPFORGE_STORE_MEDIA_READY`.
- App Review receipt reports `APP_REVIEW_READY`.
- SaaS proof reports `verdict: verified` and has the same release candidate.
- Quality audit reports `APPFORGE_QUALITY_AUDIT_READY`.
- Submission assurance reports `APPFORGE_SUBMISSION_DOSSIER_READY` and emits
  exactly one Markdown checklist and PDF per candidate/run.
