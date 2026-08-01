# Spec: vscode-supply-chain-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall remove the 2 high-severity vulnerabilities reported by npm
for the VS Code build toolchain, make the corrected transitive resolutions
durable, and block future high or critical npm audit findings in pull-request
and release workflows. This remediation changes build-time dependencies only;
the extension runtime and permissions remain unchanged.

### User roles

- Maintainer building the VS Code extension.
- Reviewer verifying the dependency and workflow evidence.
- User installing the dependency-free VSIX artifact.

### Requirements (EARS)

- The system shall return marker `VSCODE_AUDIT_ZERO` when `npm audit --audit-level=high` reports exactly 0 total vulnerabilities. [R1]
- The system shall return marker `VSCODE_TRANSITIVE_PATCHED` when reviewed fact BRACE_VERSION equals 5.0.9 and reviewed fact URI_VERSION equals 3.1.5. [R2]
- When VS Code pull-request or push CI runs, the system shall return marker `VSCODE_AUDIT_GATE_REQUIRED` only after executing the high-severity npm audit gate after `npm ci` and before tests. [R3]
- When the release workflow packages the VS Code extension, the system shall return marker `VSCODE_RELEASE_AUDIT_REQUIRED` only after executing the same audit gate after `npm ci` and before tests. [R4]
- The system shall return marker `VSCODE_RUNTIME_AUTHORITY_UNCHANGED` when production dependency count remains 1 and no extension command, permission, activation event, or runtime source file changes. [R5]
- The system shall return marker `RELEASE_0231_SYNCHRONIZED` after package, runtime, citation, archive, documentation, and current install surfaces identify version 0.23.1. [R6]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Remove both reported vulnerabilities
  Given npm previously reported exactly 2 high-severity vulnerabilities
  When npm installs the reviewed lockfile on Node 22
  Then npm audit reports exactly 0 vulnerabilities
  And brace-expansion resolves to 5.0.9
  And fast-uri resolves to 3.1.5
  And the receipt records `VSCODE_AUDIT_ZERO`
  And the receipt records `VSCODE_TRANSITIVE_PATCHED`

Scenario: Prevent a release regression
  Given the VS Code release packaging step
  When npm ci completes
  Then npm run audit executes before npm test
  And a high or critical finding exits nonzero
  And the CI receipt records `VSCODE_AUDIT_GATE_REQUIRED`
  And the release receipt records `VSCODE_RELEASE_AUDIT_REQUIRED`

Scenario: Preserve extension authority
  Given the dependency-only remediation
  When the VSIX is packaged
  Then production dependency count is 1
  And no extension command or permission is added
  And the receipt records `VSCODE_RUNTIME_AUTHORITY_UNCHANGED`

Scenario: Synchronize the patch release
  Given the approved security remediation
  When public release metadata is inspected
  Then package and current install surfaces identify version 0.23.1
  And the receipt records `RELEASE_0231_SYNCHRONIZED`
```

## SHOULD - Technical/structural

- Security advisories: GHSA-mh99-v99m-4gvg and GHSA-v2hh-gcrm-f6hx.
- Data model: npm package manifest and lockfile v3.
- Audit contract: `npm audit --audit-level=high`.
- Supported build runtime: Node 22.

## SHOULD NOT - Implementation details

- Do not upgrade unrelated direct dependencies.
- Do not suppress, omit, or downgrade audit findings.
- Do not claim the prior vulnerable packages were shipped inside the dependency-free VSIX.
- Do not change extension runtime authority.

## Decision logic (factory candidates)

Reviewed facts: `audit_total`, BRACE_VERSION, URI_VERSION,
`ci_audit_present`, and `release_audit_present`.

| # | if | then |
|---|----|------|
| 1 | `audit_total > 0` | BLOCK |
| 2 | BRACE_VERSION != 5.0.9 | BLOCK |
| 3 | URI_VERSION != 3.1.5 | BLOCK |
| 4 | `ci_audit_present == false` | BLOCK |
| 5 | `release_audit_present == false` | BLOCK |
| 6 | every preceding condition is false | SHIP |
