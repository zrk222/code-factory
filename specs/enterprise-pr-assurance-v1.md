# Spec: enterprise-pr-assurance-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Provide an offline, fail-closed enterprise boundary that turns an authenticated
GitHub pull-request webhook and an authenticated OIDC approval into durable,
tenant-scoped assurance evidence and a deterministic GitHub Check request.
The core returns a request body for an authorized connector to publish; it does
not make network calls or gain deployment authority.

### User roles
- GitHub App operator: submits an authenticated pull-request event.
- Enterprise approver: authenticates with OIDC and makes one independent decision.
- Audit viewer: verifies tenant evidence and the audit hash chain.

### Requirements (EARS)
- The system shall return marker `WEBHOOK_SIGNATURE_VERIFIED` only after verifying the raw GitHub webhook body with HMAC-SHA256 before JSON parsing or authorization.
- The system shall return marker `PR_EVENT_BOUND` after requiring an immutable installation-to-tenant mapping and storing tenant, delivery id, repository, pull-request number, installation id, and head SHA in one canonical evidence record.
- When a new delivery id is accepted, the system shall return marker `DELIVERY_RECORDED` only after committing the delivery id to a durable unique ledger and creating exactly one pending approval.
- If a delivery id is reused, the system shall fail closed with `E_WEBHOOK_REPLAY` and shall create zero additional approvals.
- If a webhook signature, event type, action, identifier, or payload is invalid, the system shall return marker `WEBHOOK_FAILURE_CLASSIFIED` with one stable webhook domain error before storing evidence.
- The system shall return marker `OIDC_IDENTITY_VERIFIED` only after cryptographically verifying one compact JWT against an explicitly supplied trusted JWKS and exact issuer and audience strings.
- The system shall return marker `OIDC_FAILURE_CLASSIFIED` with one stable OIDC domain error after rejecting JWT algorithm values other than `RS256`, tokens expired by at least 61 seconds under the maximum allowed skew, tokens premature by at least 61 seconds, reused non-empty JTI values, unknown key ids, RSA keys below 2048 bits, duplicate JSON claims, invalid signatures, and malformed compact tokens.
- When a pull-request event is accepted, the system shall return marker `PR_APPROVAL_SINGLETON` only after storing exactly one canonical tenant evidence record and exactly one independent approval request.
- When an approval decision is submitted, the system shall reject cross-tenant access with `E_TENANT_BOUNDARY`, self-approval with `E_SELF_APPROVAL`, and a second decision with `E_ALREADY_DECIDED` before emitting a terminal check request.
- When an independent approval decision is committed, the system shall return marker `APPROVAL_APPROVED` for status `approved` or marker `APPROVAL_REJECTED` for status `rejected`.
- The system shall emit marker `GITHUB_CHECK_BOUND` with a canonical GitHub Check request whose output binds the evidence digest and approval id to the exact head SHA.
- The system shall return marker `AUTHORITY_BOUNDARY_OFFLINE` only when the implementation contains no GitHub Check network client and invokes no deployment operation.
- The system shall return marker `PR_ASSURANCE_MUTATIONS_REJECTED` only after an offline hostile challenge observes the required domain errors for one signature tamper, delivery replay, token tamper, cross-tenant access, and self-approval mutation.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Authenticated pull request reaches independent approval
  Given a trusted GitHub webhook secret and trusted OIDC JWKS
  When a signed pull-request event is ingested and a distinct approver submits a valid OIDC token
  Then tenant evidence and approval audit events are durable
  And the final GitHub Check request concludes success for the exact head SHA

Scenario: Replayed GitHub delivery fails closed
  Given one accepted delivery id
  When the same delivery id is submitted again
  Then ingestion fails with E_WEBHOOK_REPLAY
  And no second approval request is created

Scenario: Identity or tenant substitution fails closed
  Given a pending tenant-a approval
  When a token is tampered, issued for another audience, or mapped to tenant-b
  Then the decision is rejected before tenant-a state changes

Scenario: Every assurance requirement has executable evidence
  Given the enterprise PR assurance smoke contract
  When its hostile tests and architecture scan pass
  Then WEBHOOK_SIGNATURE_VERIFIED is emitted only for a valid HMAC body
  And PR_EVENT_BOUND and DELIVERY_RECORDED bind exactly one durable request
  And PR_APPROVAL_SINGLETON proves exactly one evidence record and approval
  And invalid webhook fields return WEBHOOK_FAILURE_CLASSIFIED
  And OIDC_IDENTITY_VERIFIED is emitted only for a valid pinned RS256 identity
  And invalid OIDC inputs return OIDC_FAILURE_CLASSIFIED
  And E_TENANT_BOUNDARY, E_SELF_APPROVAL, and E_ALREADY_DECIDED preserve terminal constraints
  And APPROVAL_APPROVED or APPROVAL_REJECTED precedes GITHUB_CHECK_BOUND
  And PR_ASSURANCE_MUTATIONS_REJECTED records all five hostile refusals
  And AUTHORITY_BOUNDARY_OFFLINE proves the implementation contains no network or deployment client
```

## SHOULD - Technical/structural
- ADR references: docs/ENTERPRISE_PR_ASSURANCE.md
- Data model: existing EvidenceStore plus durable webhook and OIDC replay ledgers.
- API contract: Python interfaces in `factoryline.pr_assurance`; no hosted HTTP surface in v1.

## SHOULD NOT - Implementation details
- No hosted IdP discovery, SCIM, GitHub App installation flow, outbound HTTP, HA claim, or deployment authority.
- No trust in caller-provided `signature_verified` markers at the new boundary.

### Authorized bounded constants
- Webhook bodies contain 1 through 1048576 bytes and webhook secrets contain at least 16 bytes; the test secret contains 32 bytes.
- Delivery ids contain at most 128 characters and each repository-name component contains at most 100 characters.
- Git object and evidence digests contain 40 or 64 hexadecimal characters; the regular expression represents 64 as a 40-character base plus a 24-character suffix, and deterministic local evidence ids use 32 digest characters.
- HMAC uses SHA-256 and OIDC uses RS256 with exactly 1 selected trusted key, a minimum 2048-bit modulus, and test exponent 65537.
- OIDC clock skew is 60 seconds and may be configured only from 0 through 300 seconds.
- The example GitHub installation id is 4421.
- SSAT bounded functions contain at most 120 or 180 lines as declared, and smoke subprocesses have a 120-second timeout.
- UTF-8 is the only JSON text encoding; the numeral 8 in that encoding name is not a runtime parameter.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `WEBHOOK_SIGNATURE_VERIFIED` is absent | reject before JSON parsing |
| 2 | `DELIVERY_RECORDED` already exists | reject with `E_WEBHOOK_REPLAY` |
| 3 | `OIDC_IDENTITY_VERIFIED` is absent | reject before principal construction |
| 4 | `E_TENANT_BOUNDARY` or `E_SELF_APPROVAL` | reject without changing approval state |
| 5 | `APPROVAL_APPROVED` | emit `GITHUB_CHECK_BOUND` with success conclusion |
| 6 | `APPROVAL_REJECTED` | emit `GITHUB_CHECK_BOUND` with failure conclusion |
