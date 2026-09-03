# Spec: enterprise-enforcement-reference-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add a fail-closed local reference Policy Enforcement Point (PEP) decision
surface above the Oracle Contract and semantic authority lease. It admits a
single proposed operation only after independent signed workload identity,
tenant policy, expiry, revocation, scope, action-class, and lease checks pass.
It records an immutable decision but never executes the operation.

### Requirements (EARS)

- When `ENTERPRISE_WORKLOAD_IDENTITY_SUBMITTED` is signed, the system shall return `ENTERPRISE_WORKLOAD_IDENTITY_SEALED` only for a tenant-bound identity with exact workload, subject, audience, normalized agent identity, allowed action categories, and a lifetime of more than zero and no more than 24 hours. [R1]
- When `ENTERPRISE_POLICY_SUBMITTED` is signed, the system shall return `ENTERPRISE_POLICY_SEALED` only for a tenant-bound policy that names the audience, allowed action categories, allowed workspace paths, and whether a semantic lease is required. [R2]
- If `ENTERPRISE_IDENTITY_BINDING_CHECK` differs from its signed identity in tenant, workload, subject, or audience, the system shall return `E_WORKLOAD_BINDING` and write 0 decision receipts. [R3]
- If `ENTERPRISE_POLICY_SCOPE_CHECK` names an action category or path not granted by both identity and policy, the system shall return `E_POLICY_DENY` and write 0 decision receipts. [R4]
- If `ENTERPRISE_REVOCATION_CHECK` finds an active signed revocation entry that matches the identity tenant, workload, and subject, the system shall return `E_WORKLOAD_REVOKED` and write 0 decision receipts. [R5]
- When `ENTERPRISE_LEASE_PRESENCE_CHECK` omits a semantic lease required by signed policy, the system shall return `E_SEMANTIC_LEASE_REQUIRED` and write 0 decision receipts. [R6]
- If `ENTERPRISE_LEASE_BINDING_CHECK` names a stale or mismatched semantic lease, the system shall return `E_SEMANTIC_AUTHORIZATION` and write 0 decision receipts. [R7]
- When `ENTERPRISE_ADMISSION_SUCCESS_CHECK` succeeds, the system shall return `ENTERPRISE_PEP_REFERENCE_ADMITTED` and write one immutable SHA-256-bound decision. [R8]
- If `ENTERPRISE_REPLAY_CHECK` repeats an action ID, the system shall return `E_ENFORCEMENT_REPLAY` and write 0 new decision receipts. [R9]
- When `ENTERPRISE_ENFORCEMENT_STATUS_REQUESTED` reaches Graph Ops or MCP, the system shall return `ENTERPRISE_ENFORCEMENT_READ_ONLY` local receipt facts and grant zero execution, approval, publication, deployment, signing, messaging, credential, or connector authority. [R10]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A bounded enterprise workload receives an admission receipt
  Given a current signed workload identity and tenant policy
  And an active semantic lease when policy requires it
  When a request has the exact identity, action, scope, and Oracle binding
  Then it returns ENTERPRISE_PEP_REFERENCE_ADMITTED
  And every authority flag remains false
  And no tool or runner executes

Scenario: A compromised or stale workload fails closed
  Given an expired, revoked, cross-tenant, or scope-expanded request
  When admission is evaluated
  Then it returns an exact refusal code
  And writes 0 decision receipts

Scenario: A decision cannot be replayed
  Given a recorded action ID
  When the same action ID is requested again
  Then it returns E_ENFORCEMENT_REPLAY
  And preserves the first immutable receipt
```

## SHOULD - Technical/structural

- Use DSSE Ed25519 envelopes and an explicit offline trust root.
- Keep immutable records below `.factory/enterprise-enforcement/decisions/`.
- Keep workload, policy, revocation, and decision schemas typed and bounded.
- Preserve the distinction between an admission reference and deployment-plane enforcement.

## SHOULD NOT - Implementation details

- Do not contact an IdP, infer a real-world identity, call a provider, execute
  a command, authenticate a cloud runner, access a credential, or claim
  sidecar/eBPF/sandbox enforcement.
- Do not allow a policy or workload identity to waive the Oracle or semantic
  authority boundary by merely declaring that it is safe.

## Decision logic

| # | if | then |
|---|---|---|
| 1 | `ENTERPRISE_WORKLOAD_IDENTITY_SUBMITTED` is valid | `ENTERPRISE_WORKLOAD_IDENTITY_SEALED` |
| 2 | `ENTERPRISE_POLICY_SUBMITTED` is valid | `ENTERPRISE_POLICY_SEALED` |
| 3 | `ENTERPRISE_IDENTITY_BINDING_CHECK` differs from signed identity | `E_WORKLOAD_BINDING` |
| 4 | `ENTERPRISE_POLICY_SCOPE_CHECK` names an ungranted policy action or path | `E_POLICY_DENY` |
| 5 | `ENTERPRISE_REVOCATION_CHECK` finds active revocation | `E_WORKLOAD_REVOKED` |
| 6 | `ENTERPRISE_LEASE_PRESENCE_CHECK` lacks required semantic lease | `E_SEMANTIC_LEASE_REQUIRED` |
| 7 | `ENTERPRISE_LEASE_BINDING_CHECK` names stale or mismatched semantic lease | `E_SEMANTIC_AUTHORIZATION` |
| 8 | `ENTERPRISE_ADMISSION_SUCCESS_CHECK` passes all independent checks | `ENTERPRISE_PEP_REFERENCE_ADMITTED` |
| 9 | `ENTERPRISE_REPLAY_CHECK` repeats action ID | `E_ENFORCEMENT_REPLAY` |
| 10 | `ENTERPRISE_ENFORCEMENT_STATUS_REQUESTED` reaches read-only status | `ENTERPRISE_ENFORCEMENT_READ_ONLY` |
