# Spec: control-plane-foundation

Provide a local-first control-plane foundation for tenant-scoped evidence,
authorization, and human approval without claiming to be a hosted service.

## Requirements

- The system shall store each evidence record with a non-empty tenant id,
  stable evidence id, canonical payload digest, and append-only audit event.
- The system shall reject a write when the authenticated principal tenant does
  not equal the record tenant, unless the principal has an explicit platform
  role.
- The system shall reject a read or list operation that attempts to cross a
  tenant boundary, including by changing a tenant id in a request.
- The system shall deny actions that are not explicitly granted by the
  principal role and action policy.
- The system shall require a different authenticated principal to approve a
  pending request and shall record the decision, reason, and approver identity.
- The system shall reject approval of a request belonging to another tenant,
  an already-decided request, or a request approved by its requester.
- The system shall hash-link audit events and report tampering when an event's
  previous hash or event hash does not match the stored canonical event.
- The system shall return structured error codes and shall not return evidence
  from a denied tenant or action.

## Invariants

- No default principal may access a non-local tenant.
- Authorization is evaluated before storage access.
- Approval is never implied by evidence ingestion.
- Evidence payloads are stored as canonical JSON and never executed.
- This foundation does not claim SSO, SCIM, hosted availability, or external
  SCM webhook verification; those are later adapters over this contract.

## Verification scenarios

1. A tenant principal can write and read evidence for its own tenant.
2. A tenant principal cannot read, list, or write another tenant's evidence.
3. A principal without an action grant is denied before the store is queried.
4. A second principal can approve a pending request in the same tenant.
5. The requester, a different tenant, and a second decision are rejected.
6. Mutating an audit row makes verification fail closed.

