# Spec: trusted-provider-profile-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
CF offers an explicit conditional dependency profile for native reconstruction analysis. Source-closed analysis remains the default. The first scanner-owned model covers a single-inheritance builtin Exception record with closed literal arguments and fields. Actual H280-021 is the first acceptance candidate; its outcome remains unmeasured until native admission accepts a regenerated witness.

### User roles
- A repository owner selects analysis assumptions and supplies provider artifact identities.
- A reviewer inspects conditional decisions, retained raw diagnostics and separate measurements.

### Requirements (EARS)
- When `PROVIDER_PROFILE_REQUESTED` is received, the system shall accept exactly source-closed-v1 or trusted-dependencies-v1 and select source-closed-v1 with 0 provider contracts when parameters are omitted. [R1]
- When `PROVIDER_PROFILE_INVALID` contains an unknown profile or a source-closed-v1 request with 1 or more contracts, the system shall reject E_ANALYSIS_PROFILE before scanning. [R2]
- When `PROVIDER_CONTRACT_REQUESTED` selects trusted-dependencies-v1, the system shall validate exactly 1 scanner-owned builtin-exception-record-v1 model with CPython 3.11 identity, explicit trusted-initialization assumptions and SHA-256 provider artifact identities. [R3]
- When `PROVIDER_PREMISE_UNRESOLVED` contains missing or mismatched artifacts, unsupported constructor/reducer behavior, escaped or mutated objects, or replaced dumped bytes, the system shall emit the raw finding and an active NEEDS_CONTEXT decision. [R4]
- When `PROVIDER_WITNESS_VALIDATED` has a same-iteration local dumps/loads witness and a regenerated constructor contract within 512 evidence states, the system shall emit the raw diagnostic plus CONDITIONAL_PROVIDER_CONTRACT with profile and contract hashes. [R5]
- When `PROVIDER_ADMISSION_REQUESTED` consumes at most 64 sources, 512 evidence states and 1000000 bytes per source, the system shall regenerate provider, constructor, object-state and byte-flow evidence from captured bytes and reject stale, forged or contradictory evidence with 0 target executions. [R6]
- When `PROVIDER_PROFILE_CHANGED` switches from trusted-dependencies-v1 to source-closed-v1, the system shall emit configuration, cache, checkpoint, scan and finding identities for the selected profile and contract digest with 0 reused conditional decisions. [R7]
- When `PROVIDER_ACTUAL_CASE_CHECKED` runs, the system shall add 0 production modules, 0 dependencies and 0 cross-application references and finish within 30 seconds or emit incomplete with the original case retained. [R8]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Default behavior remains source closed
  Given `PROVIDER_PROFILE_REQUESTED` with source-closed-v1 and zero provider contracts
  When the repository scan completes
  Then conditional provider decisions equal zero

Scenario: Unsupported profile is rejected
  Given `PROVIDER_PROFILE_INVALID` with an unknown analysis profile
  When scan admission runs
  Then E_ANALYSIS_PROFILE is returned before scanning

Scenario: Conditional reconstruction is independently checked
  Given `PROVIDER_CONTRACT_REQUESTED` with trusted-dependencies-v1 and SHA-256 builtin-exception-record-v1 artifacts for CPython 3.11
  When `PROVIDER_WITNESS_VALIDATED` satisfies R3, R4 and R6
  Then the raw diagnostic remains and the negative decision states CONDITIONAL_PROVIDER_CONTRACT

Scenario: Drift cannot clear a finding
  Given `PROVIDER_PREMISE_UNRESOLVED` with trusted-dependencies-v1 and a mismatched artifact
  When `PROVIDER_ADMISSION_REQUESTED` runs
  Then the finding remains active NEEDS_CONTEXT

Scenario: Profile identity and runtime limits remain explicit
  Given `PROVIDER_PROFILE_CHANGED`
  And `PROVIDER_ACTUAL_CASE_CHECKED`
  When the conditional profile is evaluated
  Then default decisions remain separate and the 30 seconds bound applies
```

## SHOULD — Technical/structural
- Reuse existing captured source indexes, configuration identities and primitive admission.
- API: security_scan analysis_profile and provider_contracts keyword parameters; collection context remains independent from trust assumptions.
- Measurement: default and conditional profiles have separate frozen receipts. Exposed-panel checks remain regression evidence.

### Canonical provider contract
The schema is `factory.provider-contract.v1`. Its only fields are schema, model,
runtime, artifacts, export, classes and assumptions. Unknown fields, duplicate
JSON keys, callbacks and caller validation flags are rejected. A request contains
exactly 1 contract; the model is exactly `builtin-exception-record-v1` version 1.
The scanner computes model_sha256 from its owned model declaration, not from a
caller assertion. The runtime object contains implementation=`cpython`,
version=`3.11.9`, executable_sha256, pickle_source_sha256 and
pickle_implementation_sha256; all 3 SHA256 values must match the selected local
interpreter artifacts. This is a conditional target-runtime requirement, not a
claim that target code executed under that interpreter.
For a builtin `_pickle`, pickle_implementation_sha256 identifies the interpreter
core binary containing the builtin (python311.dll on Windows); for a loadable
stdlib extension it identifies that extension file. An unidentified core binary
does not qualify and produces an explicit unsupported-runtime error.

Artifacts are a normalized relative POSIX path to lowercase SHA256 map with
1–64 entries. Absolute paths, parent traversal, path aliases, missing captured
bytes and digest mismatches are rejected. The export object contains path and
symbol; its captured import edge must resolve to the contract's first class.
Classes are an ordered MRO list, most-derived first, of path, name,
class_ast_sha256 and constructor_ast_sha256. The final base is builtin Exception;
each preceding source class has exactly 1 declared base. Source AST digests are
SHA256 of UTF-8 `ast.dump(node, include_attributes=False)` text. A class without
its own constructor uses null constructor_ast_sha256. The actual source chain
is regenerated, not accepted from the supplied list.

Assumptions are exactly the following sorted identifiers:
`CANONICAL_CPYTHON_PICKLE`, `IMMUTABLE_PROVIDER_ARTIFACTS`,
`NO_RUNTIME_MONKEY_PATCHING`, `TRUSTED_IMPORT_INITIALIZATION`.
These state the conditional analysis boundary. Source-visible reducer/registry
changes, class substitution, mutation and escapes invalidate the witness even
when these assumptions are declared. The 64-source bound covers the selected
evidence dependencies, not every file in the scanned repository inventory.

### Conditional decision consumption
`CONDITIONAL_PROVIDER_CONTRACT` is a disposition within PROVEN_PRIMITIVE under
trusted-dependencies-v1 only. It removes that row from the active defect set in
that profile while preserving the original raw record and severity. Every
conditional row includes analysis_profile, model_sha256 and contract_sha256;
the scan carries the same canonical profile identity. Native admission
regenerates all premises and compares the complete same-profile row. Positive
preconditions and negatives retain the same profile identity; contradictory
evidence remains active. A source-closed-v1 scan can never reuse this disposition
or cache/checkpoint identity. Default and conditional measurements remain
separate, including when the source inventory and source hashes are identical.

## SHOULD NOT — Implementation details
- Do not accept package names, test paths, caller assertions or model probabilities as proof.
- Do not execute target modules, install dependencies, change severity to improve a score, or pool profile results.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | PROVIDER_PROFILE_INVALID | reject E_ANALYSIS_PROFILE |
| 2 | PROVIDER_PREMISE_UNRESOLVED | emit active NEEDS_CONTEXT |
| 3 | PROVIDER_WITNESS_VALIDATED | emit raw and CONDITIONAL_PROVIDER_CONTRACT |
