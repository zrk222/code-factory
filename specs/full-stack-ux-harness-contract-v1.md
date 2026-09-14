# Spec: full-stack-ux-harness-contract-v1
Status: proposed

## MUST

- When `UX_SPEC_INPUT` spec-validate reads the checked-in SSAT, the system shall reject invalid UTF-8/YAML, duplicate keys, unknown fields, unsafe paths, malformed digests, unsupported categories, duplicate triage rules, and return a stable E_UX_SPEC finding. [R10]
- When `UX_SPEC_LEGACY` the established full-stack-ux-harness-v1 SSAT shape is valid, the system shall emit six mobile evidence category records without changing the source contract. [R20]
- When `UX_SPEC_DIRECT` the explicit code-factory.io/v1alpha1 FullStackUXHarness shape is valid, the system shall validate visual media, privacy-to-listing, release chain, design system, production signal, and Android parity fields. [R30]
- When `UX_SPEC_RECEIPT` contract checking completes, the system shall write one immutable source-SHA-bound receipt and return FULL_STACK_UX_HARNESS_SPEC_VALIDATED or FULL_STACK_UX_HARNESS_SPEC_BLOCKED. [R40]
- When `UX_SPEC_REPLAY` spec-verify replays a receipt, the system shall fail closed if the source, normalized projection, or receipt digest changed. [R50]

## MUST NOT

- While `UX_SPEC_AUTHORITY` the parser checks a contract, the system shall not execute mobile tools, access credentials, modify source, contact a provider, upload media, submit a store review, or grant release authority. [R60]

## Acceptance criteria (Gherkin)

```gherkin
Scenario: repository SSAT projects to mobile categories
  Given the checked-in full-stack-ux-harness-v1 SSAT is unchanged
  When spec-validate reads the contract
  Then UX_SPEC_INPUT returns FULL_STACK_UX_HARNESS_SPEC_VALIDATED
  And the receipt lists exactly six mobile evidence categories

Scenario: explicit mobile contract validates and replays
  Given a code-factory.io/v1alpha1 FullStackUXHarness with bounded paths and SHA-256 values
  When spec-validate writes a receipt and spec-verify replays it
  Then UX_SPEC_LEGACY and UX_SPEC_REPLAY return a valid result bound to the same source digest

Scenario: unsafe YAML is rejected
  Given a specification with a duplicate key or unsupported triage category
  When spec-validate reads the contract
  Then UX_SPEC_DIRECT returns a blocked result with a stable E_UX_SPEC finding

Scenario: provider authority remains unavailable
  Given any structurally valid harness contract
  When validation completes
  Then UX_SPEC_RECEIPT and UX_SPEC_AUTHORITY mark execution, credentials, providers, approval, and deployment false
```
