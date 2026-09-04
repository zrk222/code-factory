# Spec: capability-evidence-audit-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Make capability claims mechanically inspectable

### Requirements (EARS)
- When `REQ_CLAIM_BINDINGS` audits a `factory.capability-evidence-manifest.v1`, the system shall reject any claim without a unique capability id, one approved maturity, at least one workspace-contained implementation file, at least one workspace-contained test file, and an argv-only verification command. [R10]
- When `REQ_CLAIM_HASHES` accepts a claim, the system shall return the SHA-256 and relative path of every implementation and test file without retaining file bodies. [R20]
- When `REQ_CLAIM_EXECUTION` is explicitly enabled, the system shall execute each declared command without a shell, replace only the leading portable `python` token with the current interpreter, enforce a timeout of 1 to 300 seconds per command, and emit `CAPABILITY_EVIDENCE_VERIFIED` only when every command exits zero. [R30]
- If `REQ_CLAIM_FAIL_CLOSED` encounters an invalid schema, duplicate id, unapproved maturity, escaping, missing or empty file, invalid command, timeout, or nonzero exit, the system shall return `CAPABILITY_EVIDENCE_BLOCKED` with a stable `E_CAPABILITY_EVIDENCE` finding and shall not report the claim verified. [R40]
- While `REQ_CLAIM_BOUNDARY` performs a structural-only audit, the system shall report `CAPABILITY_EVIDENCE_BOUND`, execution count zero, and state that structural binding is not independent battle-testing or production proof. [R50]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Bind a capability to inspectable evidence
  Given a valid manifest with implementation and test files
  When a structural audit runs
  Then REQ_CLAIM_BINDINGS rejects any detached claim and REQ_CLAIM_HASHES returns hashes for each accepted file
  And REQ_CLAIM_BOUNDARY emits CAPABILITY_EVIDENCE_BOUND with zero executions and no production claim

Scenario: Execute the declared verification
  Given a valid manifest whose argv command exits zero
  When execution is explicitly enabled
  Then REQ_CLAIM_EXECUTION emits CAPABILITY_EVIDENCE_VERIFIED with one passing execution

Scenario: Reject detached or hollow evidence
  Given a claim has an escaping, missing, or empty evidence file
  When the audit runs
  Then REQ_CLAIM_FAIL_CLOSED emits an E_CAPABILITY_EVIDENCE finding that blocks verification

Scenario: Refuse a failing verification command
  Given a structurally valid claim whose argv command exits nonzero
  When execution is explicitly enabled
  Then CAPABILITY_EVIDENCE_BLOCKED is returned and the claim is not verified
```

## SHOULD — Contract
- API: `audit_capability_evidence(root, manifest_path, execute=False) -> dict`.
- CLI: `factory evidence-audit [manifest] [--execute] [--json]`.
- Approved maturity values: `locally_verified_core`, `controlled_pilot`, `reference_pilot`, and `candidate_bound_preflight`.

## MUST NOT — Authority
- The audit shall not modify source, approve a release, publish, deploy, access credentials, call a provider, or describe local execution as independent validation.
