# Spec: source-worker-credential-rotation-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall rotate authoritative-source worker identity without restarting the process and resolve licensed-source secrets through a confined mounted-vault boundary without exposing secret values to Convex, health output, alerts, or logs.

### Requirements (EARS)

- When `WORKER_IDENTITY_TOKEN_FILE_CONFIGURED` contains an absolute token-file path, the service shall return identity mode `rotating-file` without returning token contents.
- If `WORKER_IDENTITY_CONFIGURATION_CONFLICT` contains both token-file and static-token configuration, the service shall reject startup with `E_SOURCE_WORKER_IDENTITY_CONFLICT`.
- If `WORKER_IDENTITY_CONFIGURATION_MISSING` contains neither token-file nor static-token configuration, the service shall reject startup with `E_SOURCE_WORKER_IDENTITY_MISSING`.
- When `WORKER_IDENTITY_CYCLE_STARTS` occurs in `rotating-file` mode, the service shall read and validate the token before every control-plane cycle and apply that token before the first Convex request.
- If `WORKER_IDENTITY_TOKEN_INVALID` contains an empty token, whitespace, fewer than 8 characters, or more than 16384 characters, the service shall reject the cycle with `E_SOURCE_WORKER_IDENTITY_INVALID` before a Convex request.
- When `WORKER_IDENTITY_FILE_ROTATES` contains a different valid token between two cycles, the service shall emit exactly one auth-application call per cycle and shall use the second token only in the second call.
- When `WORKER_VAULT_REFERENCE_VALID` contains `vault:` followed by 1 through 8 slash-separated segments of 1 through 40 ASCII characters from the letter, digit, dot, underscore, or hyphen alphabet with a total key length no greater than 120 characters, the resolver shall return the corresponding mounted secret value without returning its path or key in worker observations.
- If `WORKER_VAULT_REFERENCE_UNSAFE` contains traversal, a backslash, an empty or dot-only segment, more than 8 segments, or any character outside the closed key alphabet, the resolver shall reject it with `E_SOURCE_WORKER_VAULT_REFERENCE_INVALID` before file access.
- If `WORKER_VAULT_MOUNT_MISSING` occurs for a valid vault reference, the resolver shall reject it with `E_SOURCE_WORKER_VAULT_MOUNT_REQUIRED` before upstream access.
- If `WORKER_VAULT_FILE_UNSAFE` means the resolved file is outside the configured mount, is not a regular file, exceeds 65536 bytes, or is world-readable on a non-Windows host, the resolver shall reject it with `E_SOURCE_WORKER_SECRET_FILE_UNSAFE`.
- When `WORKER_ENV_REFERENCE_VALID` contains `env:SOURCE_ENDPOINT_` followed by 1 through 100 uppercase ASCII letters, digits, or underscores, the resolver shall return the current environment value and shall not cache it across cycles.
- If `WORKER_ENV_REFERENCE_FORBIDDEN` contains any environment key outside the `SOURCE_ENDPOINT_*` namespace, the resolver shall reject it with `E_SOURCE_WORKER_ENV_REFERENCE_INVALID` before environment access.
- While `WORKER_PRODUCTION_IDENTITY_REQUIRED` means the worker container is deployed, the Kubernetes template shall return `SOURCE_WORKER_OIDC_TOKEN_FILE` and shall omit `SOURCE_WORKER_OIDC_TOKEN`.
- When `WORKER_PROJECTED_TOKEN_CONFIGURED` occurs, the Kubernetes template shall return an explicit service-account token projection with an audience placeholder and expiration from 600 through 3600 seconds.
- While `WORKER_CREDENTIAL_ACTIVATION_INCOMPLETE` means the production issuer, audience, service identity membership, vault CSI provider, or secret rotation drill is absent, documentation shall return posture `credential activation required`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A projected identity rotates between cycles
  Given the worker token file contains token A for cycle one
  And the same file contains token B for cycle two
  When both control-plane cycles begin
  Then token A is applied only to cycle one
  And token B is applied to cycle two without process restart

Scenario: A vault reference attempts traversal
  Given an endpoint reference is vault:../production-token
  When the worker resolves the reference
  Then E_SOURCE_WORKER_VAULT_REFERENCE_INVALID is returned
  And no file read or upstream request occurs
```

## SHOULD - Technical and structural

- Keep credential parsing and rotation testable without importing Node filesystem APIs.
- Keep realpath, file type, size, and permissions checks inside the Node adapter.
- Use platform workload identity or a secret-store CSI driver to populate mounted files.

## SHOULD NOT - Implementation details

- Do not log token values, vault keys, mounted paths, resolved endpoints, or source bodies.
- Do not accept arbitrary `file:` references from source configuration.
- Do not claim a checked-in projection is trusted until its issuer and audience are configured in Convex OIDC.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `WORKER_IDENTITY_TOKEN_FILE_CONFIGURED` | return identity mode `rotating-file` |
| 2 | `WORKER_IDENTITY_CONFIGURATION_CONFLICT` | reject with `E_SOURCE_WORKER_IDENTITY_CONFLICT` |
| 3 | `WORKER_IDENTITY_CONFIGURATION_MISSING` | reject with `E_SOURCE_WORKER_IDENTITY_MISSING` |
| 4 | `WORKER_IDENTITY_CYCLE_STARTS` | apply a freshly read valid token before Convex access |
| 5 | `WORKER_IDENTITY_TOKEN_INVALID` | reject with `E_SOURCE_WORKER_IDENTITY_INVALID` |
| 6 | `WORKER_IDENTITY_FILE_ROTATES` | apply the next file value on the next cycle |
| 7 | `WORKER_VAULT_REFERENCE_VALID` | return the mounted secret value |
| 8 | `WORKER_VAULT_REFERENCE_UNSAFE` | reject with `E_SOURCE_WORKER_VAULT_REFERENCE_INVALID` |
| 9 | `WORKER_VAULT_MOUNT_MISSING` | reject with `E_SOURCE_WORKER_VAULT_MOUNT_REQUIRED` |
| 10 | `WORKER_VAULT_FILE_UNSAFE` | reject with `E_SOURCE_WORKER_SECRET_FILE_UNSAFE` |
| 11 | `WORKER_ENV_REFERENCE_VALID` | return the current environment value |
| 12 | `WORKER_ENV_REFERENCE_FORBIDDEN` | reject with `E_SOURCE_WORKER_ENV_REFERENCE_INVALID` |
| 13 | `WORKER_PRODUCTION_IDENTITY_REQUIRED` | return token-file configuration only |
| 14 | `WORKER_PROJECTED_TOKEN_CONFIGURED` | return bounded projected-token settings |
| 15 | `WORKER_CREDENTIAL_ACTIVATION_INCOMPLETE` | return `credential activation required` |
