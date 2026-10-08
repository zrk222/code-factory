# Spec: code-review-audits-v1
Status: amended
SpecFactor-target: 0.75-2.5

Amendment: incorporate the independent 26-snippet diagnostic as regression
requirements. Its labels are user-authored examples, not a representative
benchmark; do not publish fixture agreement as precision or recall.

## MUST — Audit implementations, not just tests

### Requirements (EARS)
- When `REQ_PATTERN` receives a declared peer group, the system shall compare direct function-body call patterns, identify missing required calls with file, symbol, line and peer evidence, and never infer correctness from majority agreement. [R10]
- When `REQ_GUARD_PATH` receives a guard/effect rule, the system shall emit a structural witness for a sensitive effect reached before an unconditional guard statement while inspecting at most 64 live paths, 32 nesting levels and 4096 statement-path steps. [R20]
- If `REQ_INCOMPLETE` encounters unsupported control flow, an absent effect, or more than 64 live paths, the system shall return state incomplete instead of reporting no findings. [R30]
- When `REQ_BINDING` audits code, the system shall return SHA-256 bindings for its policy and every inspected source and reject escaping, missing, ambiguous or greater than 1000000 bytes inputs without executing repository code. [R40]
- When `REQ_INTEGRATION` runs change review, the system shall return both configured audits, preserve existing proof-gap priority, and return not_configured for missing configuration rather than passed. [R50]
- While `REQ_AUTHORITY` reports results, the system shall distinguish declared provenance from authenticated approval and shall grant no execution, merge, release, or deployment authority. [R60]
- When `REQ_TEST_ORACLE` finds only a tautological nonnegative-length check or a bounded numeric expression that folds to a constant assertion, the scanner shall classify the test as hollow; when it finds only a non-null or mock-self-state assertion, it shall emit an actionable weak-oracle finding without claiming a confirmed defect. A meaningful local helper assertion shall count as evidence only when the helper is statically visible. [R70]
- When `REQ_TENANT_ALIAS` finds a declared tenant-read argument copied through a simple local assignment, the scanner shall accept the alias only while its value is unchanged; reassignment or unsupported control flow shall not be treated as tenant proof. [R80]
- When `REQ_ORM_SCOPE` identifies a Python ORM read outside the tenant-read contract, the scan shall fail closed with a finding that names the candidate call and the contract action required to assess it. [R90]
- When `REQ_ASSERTION_API` encounters assertion-like calls, only visible local helpers with a real assertion or `unittest.TestCase` methods shall count as oracles; no-op methods with assertion-like names shall not suppress hollow-test findings. Weak `unittest` non-null and mock-call checks shall be reported as advisory weak oracles. [R100]
- When `REQ_TENANT_ALIAS` sees a pattern or exception capture overwrite a tenant alias, the overwritten name shall be invalidated before a later read. Recognized SQLModel `Session.exec` calls shall be treated as ORM reads requiring a declared tenant contract. [R110]
- When `REQ_TENANT_CONTRACT` runs the security CLI, it shall load the optional bounded `.factory/tenant-read-contract.json`, validate unique qualified calls and argument bindings, include its content hash in the receipt, and apply those declarations to custom reads as well as ORM reads. If the file is absent, the report shall state that tenant isolation is unassessed, return `INCOMPLETE` when no other finding already determines the result, and give the contract action. [R120]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Find an inconsistent peer
  Given two declared peers and one omits a required call
  When REQ_PATTERN compares the peers
  Then the missing call and the supporting peer are reported

Scenario: Catch a guard bypass that a call search misses
  Given a function calls the guard on only one branch before an effect
  When REQ_GUARD_PATH enumerates both branches
  Then the unguarded branch has a structural witness

Scenario: Refuse unsupported certainty
  Given a function contains unsupported control flow or no expected effect
  When REQ_INCOMPLETE analyzes the function
  Then the result is incomplete and never an approval

Scenario: Keep analysis bound and integrated
  Given a configured workspace policy
  When REQ_INTEGRATION runs change review
  Then REQ_BINDING hashes policy and source without executing code
  And REQ_AUTHORITY grants no release authority

Scenario: Distinguish weak and meaningful test oracles
  Given a test checks only a tautology, a non-null value, or a mock's own call state
  When REQ_TEST_ORACLE scans the test
  Then a hollow or weak-oracle finding identifies the missing independent assertion
  And a visible helper with a meaningful assertion is not reported as hollow

Scenario: Catch bounded constant arithmetic without rejecting runtime values
  Given a test reassigns a literal through bounded numeric arithmetic and asserts the resulting literal
  When REQ_TEST_ORACLE evaluates direct assignments in source order
  Then the constant-only assertion is reported as hollow
  And runtime call results, table-driven inputs, and branch-rebound values remain valid oracle evidence

Scenario: Preserve tenant evidence through simple aliases
  Given a declared tenant parameter is copied once to a local name before a read
  When REQ_TENANT_ALIAS checks the read argument
  Then the alias passes only if it is not rebound before that read

Scenario: Account for ORM reads outside the contract
  Given a recognized Python ORM query is present but undeclared
  When REQ_ORM_SCOPE scans the source
  Then the security result is blocked with an actionable tenant-contract finding

Scenario: Do not trust assertion-shaped no-op helpers
  Given a test calls a local method named like a unittest assertion
  And the method body contains no assertion
  When REQ_ASSERTION_API scans the test
  Then the call does not suppress a hollow-test finding
  And a unittest assertion counts only inside an explicit TestCase subclass

Scenario: Invalidate all tenant alias rebinding
  Given a tenant alias is overwritten by an exception or pattern capture
  When a declared tenant read uses the overwritten name
  Then the scanner reports missing tenant isolation
  And SQLModel `Session.exec` outside the tenant contract is reported

Scenario: Apply the declared tenant contract to independent read calls
  Given `.factory/tenant-read-contract.json` declares a read and its tenant parameter binding
  When the security CLI audits a custom read with a wrong argument and another with a renamed tenant parameter
  Then it reports the unscoped read and accepts the renamed parameter only when the declared binding matches
  And the receipt includes the tenant contract path and SHA-256

Scenario: Do not imply tenant coverage without a contract
  Given the tenant-read contract file is absent
  When the security CLI completes
  Then the receipt says tenant isolation is unassessed and gives the contract path
```

## SHOULD — Interface
- `factory audit patterns|guard-paths|all --policy .factory/review-audits.json --root . --json`.
- `factory audit security --root . --json` loads `.factory/tenant-read-contract.json` when present; the schema is `factory.tenant-read-contract.v1` with `reads: [{"call":"store.fetch","binding":"keyword:tenant_id:org_scope"}]`. Repeatable `--tenant-read-call` and `--tenant-read-binding` remain available for one-off declarations.
- `factory change review` discovers `.factory/review-audits.json`; explicit `--audit-policy` overrides it.
- Governance: human-controlled. Call names and guard semantics require reviewer assessment.

## MUST NOT — Claims
- Do not claim whole-program analysis, runtime reachability, authenticated policy approval, dynamic-language coverage, or semantic correctness. Tenant aliases are limited to simple statically traceable assignments; no interprocedural, concurrency or exception-path proof.
