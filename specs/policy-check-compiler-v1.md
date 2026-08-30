# Spec: policy-check-compiler-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Compile one explicit `factory.policy.v1` JSON file into a stable
`factory.enterprise-policy-checks.v1` manifest for human or CI review. The
compiler performs no model call, check execution, source write, merge,
deployment, release, billing, or policy activation.

### Declared facts

- `policy_schema_valid`: the input is a UTF-8 JSON object with schema `factory.policy.v1`.
- `policy_path_contained`: the input and output paths resolve beneath the selected workspace.
- `rule_types_valid`: every recognized rule has its declared boolean, non-negative numeric, list, or enum type.
- `unsupported_rules_present`: an unrecognized section or rule path is present.
- `all_rules_recognized`: no unsupported rule path is present and every supplied rule is recognized.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall emit `POLICY_INPUT_ACCEPTED` only for a workspace-contained UTF-8 object with schema `factory.policy.v1` and shall return `E_POLICY_SCHEMA_UNSUPPORTED` or `E_POLICY_PATH_ESCAPE` before writing when the input contract is invalid. [REQ-POLICY-INPUT]
- When a valid policy is compiled, the system shall emit `POLICY_MANIFEST_BOUND` with schema `factory.enterprise-policy-checks.v1`, a SHA-256 of the canonical source policy, sorted check identifiers, and `manifest_sha256`. [REQ-POLICY-MANIFEST]
- When a recognized boolean or non-negative numeric rule is present, the system shall emit `POLICY_RULE_COMPILED` with one deterministic check, its enabled state or explicit `gte`/`lte` operator, and no model call. [REQ-POLICY-RULES]
- When human-approval actions or a risk mode are present, the system shall emit `POLICY_GATE_EXPLICIT` with sorted human-gate records and `authority` equal to `human-required` or `none`; the compiler shall never grant execution, merge, deploy, release, or billing authority. [REQ-POLICY-GATES]
- If a section, rule, value type, or enum is unsupported, the system shall emit `POLICY_REVIEW_REQUIRED` with every unsupported path in `review_required` and shall not silently drop that input. [REQ-POLICY-FAIL-CLOSED]
- When `POLICY_CLI_WRITTEN` is emitted by the CLI command `factory ops policy factory.policy.json --root . --out .factory/ops/policy-checks.json`, the system shall write one workspace-contained JSON manifest atomically and shall return exit code 0 only when `status=COMPILED`; `REVIEW_REQUIRED` shall return exit code 1. [REQ-POLICY-CLI]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Equivalent policy key order produces the same semantic manifest
  Given two workspace policy files with the same factory.policy.v1 values in different key orders
  When both policies are compiled
  Then policy_sha256 and manifest_sha256 are equal
  And check identifiers are sorted

Scenario: Unsupported rules remain visible
  Given a policy with an unsupported nested rule
  When the policy is compiled
  Then status is REVIEW_REQUIRED
  And review_required names the exact path
  And no authority field allows execute, merge, deploy, release, or billing

Scenario: Every compiler obligation has a concrete marker
  Given a valid policy and a policy with one unsupported rule
  When both policies are compiled
  Then the results include `POLICY_INPUT_ACCEPTED`, `POLICY_MANIFEST_BOUND`, `POLICY_RULE_COMPILED`, `POLICY_GATE_EXPLICIT`, `POLICY_REVIEW_REQUIRED`, and `POLICY_CLI_WRITTEN`

Scenario: The CLI writes a bounded manifest
  Given a valid workspace policy
  When factory ops policy compiles it with an output path inside the workspace
  Then one JSON manifest is written atomically
  And its schema is factory.enterprise-policy-checks.v1
```

## SHOULD — Technical/structural
- ADR references: `docs/ENTERPRISE_OPERATIONS.md`, `docs/ENTERPRISE_1_0.md`.
- API contract: `factoryline.policy_compiler.compile_policy` and
  `write_compiled_policy`; CLI under `factory ops policy`.
- Stable error codes include `E_POLICY_INPUT_INVALID`,
  `E_POLICY_SCHEMA_UNSUPPORTED`, `E_POLICY_PATH_ESCAPE`, and `E_POLICY_OUTPUT`.

## SHOULD NOT — Implementation details

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `policy_path_contained` is false or `policy_schema_valid` is false | reject before output |
| 2 | `rule_types_valid` is false | include each invalid path in `review_required` |
| 3 | `unsupported_rules_present` is true | return `REVIEW_REQUIRED` and preserve each path |
| 4 | `all_rules_recognized` and `rule_types_valid` are true | return `COMPILED` with no authority |
```
