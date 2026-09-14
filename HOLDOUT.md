# Holdout Scenarios (verifier-only)

This builder-safe manifest records that independent negative cases exist outside the workspace. The implementing agent must not read, modify, or infer their contents.

- Isolation: external verifier store
- Builder access: any access attempt contaminates the run and blocks activation
- Evidence: the verifier supplies a hash-bound scenario binding and a one-run admission

The holdout is a challenge boundary, not a release certificate. Human review remains required.
