# Spec: compliance-plane-foundation

Emit versioned OSCAL-shaped assessment evidence from factory receipts without
claiming legal, audit, or certification status.

## Requirements

- The system shall expose versioned baseline packs for NIST SSDF, OWASP ASVS,
  SOC 2, and ISO 27001, plus reviewed customer controls.
- The system shall map explicit evidence control ids to `satisfied` results and
  leave absent controls `not_assessed`.
- The system shall include tenant, pack version, evidence observations, and a
  digest in every export.
- The system shall label every export `not-a-certification`.
- Unknown packs and malformed controls shall fail with structured errors.

