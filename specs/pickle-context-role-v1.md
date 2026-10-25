# Spec: pickle-context-role-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Implement the owner's supplied context-role/output plan for test-owned pickle roundtrips. This is an explicit versioned actionability policy, not a claim of safe object reconstruction or improved legacy scanner recall. Keep the original diagnostic and severity in the audit ledger and report policy-specific alerts and abstentions separately.

### Requirements (EARS)
- When `PICKLE_ROLE_SELECTED` requests source-role-v1, the system shall emit exactly 1 selected policy identity and preserve 0 behavior changes for legacy-v1 and trusted-core-v1. [R1]
- When `PICKLE_TEST_ROUNDTRIP` has a source-bound imported pickle dump/load edge inside a directly collected test function or TestCase method with positive framework evidence and no captured production importer, the system shall emit 1 NEEDS_CONTEXT review item instead of a defect alert, with reconstruction effects and runtime reachability explicitly unassessed. [R2]
- When `PICKLE_ROLE_OVERRIDE` contains a proven dangerous input precondition, a reconstruction callback invoking eval, exec, subprocess, os.system, open, requests or socket, serializer replacement or an operational importer, the system shall emit the original active finding at its original severity with 0 context-policy exclusions. [R3]
- When `PICKLE_ROLE_INCOMPLETE` has incomplete source coverage, missing captured inventory, unmatched bytes or ambiguous test ownership, the system shall emit 0 exclusions and retain the original active finding. [R4]
- When `PICKLE_ROLE_REGENERATED` admits a review item, the system shall validate current source hashes, sink/dump spans, test/framework role, import edges and policy identity from at most 2000 source files and 32000000 source bytes, rejecting a stale or forged role with 0 exclusions. [R5]
- When `PICKLE_ROLE_MEASURED` evaluates the candidate, the system shall emit outcomes for all 37 original claims, retain both true positives and both unclear cases at their original severities, and report legacy precision, policy alert precision, review counts and true-positive retention separately with 0 fresh-held-out claims. [R6]
- When `PICKLE_ROLE_QUALIFIED` completes, the system shall add 0 production modules and 0 dependencies, and emit focused tests plus hash-bound paired observations without executing target-repository code. [R7]
- When `PICKLE_WORKER_PROTOCOL` binds a deserializer to a captured same-module subprocess pipe pair or a source-created interpreter queue with a captured serializer peer, the system shall emit 1 NEEDS_CONTEXT review with external writer authority and runtime identity explicitly unassessed; an external command, network stream, missing peer or serializer replacement shall retain the active finding. [R8]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: A test-owned local edge becomes an explicit unresolved review
  Given PICKLE_ROLE_SELECTED requests source-role-v1
  When PICKLE_TEST_ROUNDTRIP has complete captured evidence
  Then R1 and R2 emit an unresolved review item with original diagnostic severity

Scenario: Dangerous counterevidence preserves the alert
  Given PICKLE_ROLE_OVERRIDE has a production importer or dangerous callback
  When PICKLE_ROLE_REGENERATED evaluates the candidate
  Then R3 and R5 retain the active finding

Scenario: Missing context cannot exclude an alert
  Given PICKLE_ROLE_INCOMPLETE has missing source bytes
  When PICKLE_ROLE_REGENERATED runs
  Then R4 and R5 emit zero exclusions

Scenario: The changed output contract is not a detector gain
  Given PICKLE_ROLE_MEASURED contains 37 original claims
  When PICKLE_ROLE_QUALIFIED completes
  Then R6 reports the separate metrics and R7 executes no target repository

Scenario: Worker transport provenance remains an unresolved review
  Given PICKLE_WORKER_PROTOCOL binds a captured serializer peer and local transport
  When PICKLE_ROLE_REGENERATED evaluates the current sink and producer spans
  Then R8 emits 1 NEEDS_CONTEXT review with unassessed external writer authority
```

## SHOULD — Technical/structural
- Preserve raw findings and severities, primitive partitions, known true positives, and the existing default policy. Add a separate context-review collection and counts. Existing CLI consumers remain compatible unless this explicit policy is selected.
- Test ownership needs a test path plus a direct test function/method and positive framework evidence: a captured pytest/unittest import, an assert-based pytest collection shape, or a concrete captured Test-prefixed subclass inheriting the frame. A path alone, a nested web handler, a demo or vendored path does not qualify. Importers are checked against the complete captured Python inventory. This classification is scoped to static captured imports and explicit source test intent; dynamic deployment/test discovery remains unassessed.
- A context review is not PROVEN_PRIMITIVE, not a safe reconstruction, not a clean security result, and not proof that arbitrary runtime callers cannot invoke the function. The policy explains which role/provenance facts prompted human review.
- Source-bound unittest ancestry may cross captured imports and local intermediate classes. A class name containing TestCase is insufficient. For worker protocols, record the concrete process command/pipe or queue creation, peer serialization and sink spans; do not infer authenticated IPC or safe reconstruction.
- Keep definite dangerous preconditions and visible reconstruction effects as active counterevidence. A literal fixture is not permission to ignore an eval/subprocess/network reducer or an imported operational entrypoint.
- Measurements label this as output-policy precision and enumerate every excluded item; the original all-active score remains visible. An underpowered selected alert set never satisfies a publication or merge sample-size requirement.

## SHOULD NOT — Implementation details
- Do not hard-code study identifiers, repository/package names, labels or individual test paths.
- Do not drop original diagnostics or relabel unresolved object graphs as safe.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | PICKLE_ROLE_OVERRIDE | retain original finding |
| 2 | PICKLE_ROLE_INCOMPLETE | retain original finding |
| 3 | PICKLE_TEST_ROUNDTRIP | emit unresolved context review |
