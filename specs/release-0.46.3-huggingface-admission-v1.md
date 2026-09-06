# Spec: release-0.46.3-huggingface-admission-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Prepare the next core package candidate as `0.46.3` and make Hugging Face
Space publication fail before checkout, setup, metadata tooling, or upload when
its workflow has no declared `HF_TOKEN` check. Local inspection is static and
read-only: it cannot inspect a secret, contact Hugging Face, dispatch a
workflow, publish a Space, or prove remote availability.

### User roles

- Maintainer: receives an early, actionable workflow failure before spending
  time building an upload candidate with a missing credential boundary.
- Connected coding agent: can inspect the declared local route but cannot read
  credentials or run publication work.
- Reviewer: can verify that source package, MCP descriptor, and release
  references name one candidate version without treating it as a publication.

### Requirements (EARS)

- When `CORE_VERSION_READ` reads current package metadata, the system shall
  return `0.46.3` from `pyproject.toml`, `factoryline.__version__`,
  `CITATION.cff`, `.zenodo.json`, every current MCP package descriptor, and
  the aligned Code Factory LangGraph plugin manifests. [R1]
- When `HUGGINGFACE_AUTH_ROUTE_READ` reads the declared Space workflow, the system shall return `HUGGINGFACE_AUTHORIZATION_EARLY` only when an `HF_TOKEN` non-empty check occurs before checkout, Python setup, metadata validation, client installation, and `HfApi` upload. [R2]
- If `HUGGINGFACE_AUTH_ROUTE_MUTATED` removes the token check or moves it after any declared candidate-work marker, the system shall return `HUGGINGFACE_AUTHORIZATION_EARLY` and `repair_release_workflow`. [R3]
- When `HUGGINGFACE_METADATA_ROUTE_READ` reads the complete workflow, the system shall preserve `HUGGINGFACE_METADATA_PREFLIGHT` before client installation and the remote upload step. [R4]
- When `RELEASE_EXTERNAL_REQUIREMENTS_READ` reads release integrity or the Graph Ops release-decision projection, the system shall list the configured Hugging Face `HF_TOKEN` secret as an unobserved external requirement without treating its declaration as credential availability or remote publication. [R5]
- When `RELEASE_AUTHORITY_READ` reads version alignment or route integrity, the system shall retain false execution, approval, repair, merge, publication, deployment, signing, messaging, credential, and connector authority. [R6]
- When `RELEASE_ENCODING_AND_JAVA_READ` inspects tracked release workflow and source files, the system shall return `JETBRAINS_JDK21_EXACT` only when every read is `UTF-8` and every IntelliJ Java declaration is exactly 21. [R7]
- When `RUNTIME_LIMITS_READ` invokes the bounded runtime verifier, the system shall return its fact mapping only when captured stream output is capped at `8 * 1024 * 1024` bytes, an empty stream counts as 0 bytes, non-Windows creation flags equal 0, and a zero exit code remains the successful-command baseline. [R8]
- When `WINDOWS_TIMEOUT_CLEANUP_READ` observes `timed_out=true` after a declared integer `timeout_seconds` from 1 through 300, the system shall return `cleanup_confirmed=true` only when `child.poll()` is non-null, exactly two captured stream-reader threads are no longer alive, and Windows `Popen` uses `CREATE_NEW_PROCESS_GROUP`; both `taskkill` and the final child wait shall use an exact 10-second bound. [R9]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: source metadata identifies one 0.46.3 candidate
  Given CORE_VERSION_READ reads the current release sources
  When package and MCP metadata are compared
  Then every current release version is 0.46.3

Scenario: missing Hugging Face credentials stop before candidate work
  Given HUGGINGFACE_AUTH_ROUTE_READ reads the declared Space workflow
  When the workflow is inspected
  Then HUGGINGFACE_AUTHORIZATION_EARLY passes before checkout and upload tooling

Scenario: a late Hugging Face token check is rejected
  Given HUGGINGFACE_AUTH_ROUTE_MUTATED moves the token check after checkout
  When release integrity is evaluated
  Then HUGGINGFACE_AUTHORIZATION_EARLY fails and next action is repair_release_workflow

Scenario: Space metadata preflight remains ordered
  Given HUGGINGFACE_METADATA_ROUTE_READ reads the declared Space workflow
  When release integrity is evaluated
  Then HUGGINGFACE_METADATA_PREFLIGHT passes

Scenario: external provider state remains unobserved
  Given RELEASE_EXTERNAL_REQUIREMENTS_READ reads a healthy workspace
  When Graph Ops returns the release decision node
  Then provider_state is unobserved

Scenario: static release checks have no authority
  Given RELEASE_AUTHORITY_READ reads release integrity
  When a connected agent requests the result
  Then every authority flag is false

Scenario: source reads and IntelliJ Java remain exact
  Given RELEASE_ENCODING_AND_JAVA_READ reads tracked release source
  When release integrity is evaluated
  Then JETBRAINS_JDK21_EXACT requires `UTF-8` source reads and 21 Java

Scenario: bounded runtime receipt retains declared limits
  Given RUNTIME_LIMITS_READ runs a bounded runtime command
  When the command exits with code 0
  Then the fact mapping records `8 * 1024 * 1024` bytes as the output cap

Scenario: a raced Windows tree-termination status does not create a false failure
  Given WINDOWS_TIMEOUT_CLEANUP_READ runs a verifier that leaves a descendant holding captured streams
  When the verifier times out and the supervisor plus both streams close
  Then cleanup_confirmed is true without claiming sandbox isolation
```

## SHOULD - Technical and structural

- Add `HUGGINGFACE_AUTHORIZATION_EARLY` before
  `HUGGINGFACE_METADATA_PREFLIGHT` in the ordered release-integrity checks.
- Keep the historic `0.46.2` notes and receipts unchanged; add a dedicated
  `0.46.3` release-notes document for the current candidate.
- State release candidate status precisely: source alignment is not an upload,
  registry update, release tag, or provider approval.

## SHOULD NOT - Implementation details

- Do not read, write, print, infer, or persist `HF_TOKEN` or any other secret.
- Do not add an external provider call, release dispatch, tag, upload,
  deployment, credential configuration, or approval action.
- Do not change VS Code or JetBrains extension versions in this Python-core
  candidate slice.
