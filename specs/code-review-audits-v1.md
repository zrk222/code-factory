# Spec: code-review-audits-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Audit implementations, not just tests

### Requirements (EARS)
- When `REQ_PATTERN` receives a declared peer group, the system shall compare direct function-body call patterns, identify missing required calls with file, symbol, line and peer evidence, and never infer correctness from majority agreement. [R10]
- When `REQ_GUARD_PATH` receives a guard/effect rule, the system shall emit a structural witness for a sensitive effect reached before an unconditional guard statement while inspecting at most 64 live paths, 32 nesting levels and 4096 statement-path steps. [R20]
- If `REQ_INCOMPLETE` encounters unsupported control flow, an absent effect, or more than 64 live paths, the system shall return state incomplete instead of reporting no findings. [R30]
- When `REQ_BINDING` audits code, the system shall return SHA-256 bindings for its policy and every inspected source and reject escaping, missing, ambiguous or greater than 1000000 bytes inputs without executing repository code. [R40]
- When `REQ_INTEGRATION` runs change review, the system shall return both configured audits, preserve existing proof-gap priority, and return not_configured for missing configuration rather than passed. [R50]
- While `REQ_AUTHORITY` reports results, the system shall distinguish declared provenance from authenticated approval and shall grant no execution, merge, release, or deployment authority. [R60]

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
```

## SHOULD — Interface
- `factory audit patterns|guard-paths|all --policy .factory/review-audits.json --root . --json`.
- `factory change review` discovers `.factory/review-audits.json`; explicit `--audit-policy` overrides it.
- Governance: human-controlled. Call names and guard semantics require reviewer assessment.

## MUST NOT — Claims
- Do not claim whole-program analysis, runtime reachability, authenticated policy approval, dynamic-language coverage, or semantic correctness. Python AST control-flow witnesses are conditional on declared guard semantics; no alias, interprocedural, concurrency or exception-path proof.
