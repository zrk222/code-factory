# AKU: Team Pilot readiness

## Intent

Activate when a named owner wants to review whether up to three selected design
partners have the minimum, non-secret evidence to begin a **customer-managed
reference pilot**. Do not activate for public beta launch, payment, contract,
or hosted-service decisions.

## Procedure

1. Confirm each proposed partner is selected by a human and remains within the
   initial three-partner cap.
2. Write five non-secret local evidence files: selection, security review,
   retention decision, support/incident owner, and commercial terms review.
3. Record each file's exact SHA-256 in a `factory.team-pilot-launch.v1`
   manifest with a named owner and `customer_managed_reference` delivery.
4. Run `factory team-pilot readiness --root . --manifest team-pilot.json --out-dir .factory/team-pilot`.
5. Independently run `factory team-pilot verify <receipt.json>` and have the
   named owner review the packet before taking any external action.

## Tools

- `factory team-pilot readiness`
- `factory team-pilot verify`
- `certutil -hashfile <path> SHA256` on Windows or an equivalent local digest tool
- `docs/COMMERCIAL_PACKAGING.json`

## Metadata

- Owner: the named pilot owner in the manifest.
- Version: 1.
- Schema: `factory.team-pilot-launch.v1` and `factory.team-pilot-readiness.v1`.
- Source of truth: the local manifest, its five hash-bound evidence files, and
  the packaged commercial boundary.

## Governance

Human-controlled. This AKU may read local files and write an explicit receipt
packet. It cannot select partners, communicate with applicants, accept a
customer, create a contract, collect payment, provision access, activate a
Marketplace price, deploy a service, access credentials, or assert a managed
service or certification.

## Continuations

- Ready: the named owner decides whether to pursue external customer-managed
  pilot activation through approved company processes.
- Evidence drift: revise the evidence or manifest, then rerun locally.
- Commercial-boundary drift: restore the not-sellable design-partner boundary
  before any pilot review; do not bypass the gate.
- Need for managed delivery: stop and create a separate security, operations,
  support, retention, and commercial plan.

## Validators

- Pre: exactly five required evidence kinds, each an existing regular file
  below the workspace with an exact SHA-256; one through three partners; named
  owner; human-controlled, customer-managed delivery.
- Post: receipt canonical SHA-256, evidence projection, Markdown, Mermaid, and
  authority boundary all verify.
- Invariant: the Team offer remains `design_partner_only` and
  `purchasable: false`; no payment, contract, entitlement, activation,
  deployment, publication, or message action is possible from this workflow.
