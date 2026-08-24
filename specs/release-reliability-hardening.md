# Spec: release-reliability-hardening
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Make Code Factory release checks faster to diagnose, harder to misconfigure,
and locally inspectable without turning missing external credentials or
Marketplace approval into false success. The Python package, VS Code VSIX, and
JetBrains ZIP validation paths run independently; publication remains blocked
until all verified artifacts are available. A local read-only command checks
the declared workflow topology before a maintainer dispatches publication.

### User roles
- Release maintainer: prepares a tag and needs an actionable local preflight.
- CI operator: needs independent failure attribution for Python, VS Code, and
  JetBrains release artifacts.
- Marketplace owner: retains control of protected tokens and approval actions.

### Requirements (EARS)
- The system shall expose `factory release integrity --root . --json` with
  schema `factory.release_integrity.v1`, marker `RELEASE_INTEGRITY_READ_ONLY`,
  a deterministic ordered check list, a fact-derived next action, and every
  external-effect authority set to `false`.
- The system shall return check ID `RELEASE_FAN_IN_EXACT` that passes only when independent
  `validate_python`, `validate_vscode`, and `validate_intellij` jobs have no
  dependency between them, `publish` requires all three, and each separately
  named artifact downloads into `release-bundle/python/` or
  `release-bundle/editors/`.
- The system shall return check ID `RELEASE_VALIDATION_PARTITIONED` that passes only when test, build,
  `twine check`, and clean-wheel smoke occur in `validate_python`; VS Code
  `npm ci`, high-severity audit, test, and VSIX packaging occur in
  `validate_vscode`; and JetBrains check, ZIP build, verification, and
  Marketplace preflight occur in `validate_intellij`.
- The system shall return check ID `OPENVSX_AUTHORIZATION_EARLY` that passes only when an Open VSX dispatch with `publish: true` requires the protected `OPENVSX_TOKEN` in `authorize` before candidate validation; `publish: false` permits token-free candidate validation; failed authorization does not publish or run candidate validation.
- The system shall return check ID `PYPI_TRUSTED_PUBLISHING` that passes only when the `publish` job uses
  the `pypi` environment, `id-token: write`, and no stored PyPI credential.
- The system shall return check ID `JETBRAINS_APPROVAL_GUARD` that passes only when `--require-clear`
  occurs before Java or Gradle setup.
- The system shall return check ID `INTELLIJ_COMPATIBILITY_DECLARED` that
  passes only when the IntelliJ adapter has no `Messages.showChooseDialog`
  call, its four `Messages.showDialog` selectors retain index `0` for the
  mission-operation, event, and role defaults and index `1` for the
  medium-risk default, and `org.jetbrains.kotlin.jvm` version `2.4.10` uses
  `JvmDefaultMode.NO_COMPATIBILITY`; the verified package shall emit neither
  `java-api-jars` nor `java-runtime-jars` and no `ToolWindowFactory` usage
  report.
- The system shall return check ID `HUGGINGFACE_METADATA_PREFLIGHT` that passes
  only when the static Space card has `short_description` of at most 60
  characters and the metadata validator runs before the Hugging Face client or
  remote upload; a rejected card shall return
  `HUGGINGFACE_SPACE_METADATA_INVALID`.
- The system shall return check ID `PYTHON_PACKAGE_DATA_EXPLICIT` that passes
  only when Python wheel data uses `include-package-data = false` with the
  declared builtin packs, JSON decision data, and static HTML templates, so
  setuptools does not infer an undeclared data package.
- The system shall return marker `RELEASE_INTEGRITY_FAILURE` with `ok: false`, failed check IDs, and `next_action.action=repair_release_workflow` when a required job, artifact boundary, protected Open VSX authorization, PyPI OIDC boundary, or JetBrains approval guard is absent; it shall not write a file or execute a workflow.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: inspect the hardened release topology locally
  Given the repository's hardened release workflows
  When a maintainer runs `factory release integrity --root . --json`
  Then the result is `factory.release_integrity.v1` with all checks passing
  And each external-effect authority is false
  And no workspace file is written

Scenario: reject a serial release fan-in regression
  Given a copy of the release workflow without validate_intellij in publish needs
  When the integrity command inspects that copy
  Then it returns `ok: false`
  And the failed check identifies the release artifact fan-in boundary

Scenario: fail Open VSX publication before candidate validation when token is absent
  Given a dispatch with publish true and no protected Open VSX token
  When the Open VSX workflow starts
  Then authorize fails before validate
  And candidate packaging and publication do not run

Scenario: preserve an honest pending JetBrains Marketplace block
  Given Marketplace reports a pending previous update
  When the Marketplace workflow runs
  Then it stops before Java or Gradle setup
  And it does not report a successful publication

Scenario: package the IntelliJ adapter without deprecated chooser calls
  Given the current IntelliJ adapter source
  When the plugin verification task runs
  Then it contains no `Messages.showChooseDialog` call
  And the mission risk selector defaults to medium
  And the integrity check `INTELLIJ_COMPATIBILITY_DECLARED` passes

Scenario: configure the IntelliJ build without legacy Gradle usage values
  Given the Gradle 9.5 wrapper
  When the IntelliJ help task runs with all warnings enabled
  Then the Kotlin build plugin emits neither `java-api-jars` nor `java-runtime-jars`
  And plugin verification finds no internal `ToolWindowFactory` usage

Scenario: reject an invalid Hugging Face Space card locally
  Given a static Space card whose `short_description` is longer than 60 characters
  When the metadata preflight runs before upload
  Then it returns `HUGGINGFACE_SPACE_METADATA_INVALID`
  And the Hugging Face client does not run

Scenario: retain explicit wheel data without inferred packages
  Given the Python package configuration
  When the release integrity preflight runs
  Then check `PYTHON_PACKAGE_DATA_EXPLICIT` passes
  And the built wheel contains its declared data files

Scenario: reject strict release-integrity requirement mutations
  Given the release-reliability-hardening contract
  When strict validator mutation runs
  Then checks include `RELEASE_FAN_IN_EXACT`, `RELEASE_VALIDATION_PARTITIONED`, `OPENVSX_AUTHORIZATION_EARLY`, `PYPI_TRUSTED_PUBLISHING`, `JETBRAINS_APPROVAL_GUARD`, `INTELLIJ_COMPATIBILITY_DECLARED`, `HUGGINGFACE_METADATA_PREFLIGHT`, and `PYTHON_PACKAGE_DATA_EXPLICIT`
  And the failure marker is `RELEASE_INTEGRITY_FAILURE`
```

## SHOULD — Technical/structural
- ADR references: immutable artifact promotion, protected environments, and
  Marketplace approval boundary.
- Data model: ordered static workflow `checks` with ID, pass state, evidence,
  and an overall boolean `ok`.
- API contract: `factory release integrity --root workspace [--json]`.
- Serialization: static workflow and IntelliJ source inspection reads UTF-8
  text only.

## SHOULD NOT — Implementation details
- Do not read, discover, transmit, or write a credential.
- Do not auto-approve JetBrains Marketplace updates or bypass protected
  environment review.
- Do not treat a missing token or pending external approval as CI success.
- Do not change package versioning, tags, releases, or public distribution in
  this hardening change.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `ok=false` | return `repair_release_workflow` |
| 2 | `ok=true` | return `review_external_publish_gates` |
