# 0.48.1 / 1.1.4 cadence exception review

Review scope: `.github/workflows/publish.yml`, `openvsx.yml`, `vscode-marketplace.yml`, `jetbrains-marketplace.yml`, `factoryline/release_candidate.py`, `factoryline/release_integrity.py`, and their focused tests.

## Findings

No remaining exception-scope issue identified in the reviewed changes.

- The source model admits an exception only for a valid, available cadence state classified as `cooldown`, with `recent_count < max_releases_30d`. Monthly-cap, invalid-policy, unavailable/unknown, and inconsistent-at-cap results retain the normal blocker.
- Allowed candidate identities are exact: core `0.48.1` / `v0.48.1`; VS Code `1.1.4` / `vscode-v1.1.4` in `openvsx` or `vscode-marketplace`; JetBrains `1.1.4` / `jetbrains-v1.1.4` in `jetbrains-marketplace`.
- Workflow exception creation is limited to actor `zrk222`. Preflight binds exception identity to source commit, contract approver, exact candidate, protected environment authorization, publish intent, workflow run and attempt, and a short expiry. The source validator enforces the one-hour maximum TTL and current validity.
- Core publication separately checks actual published releases against the 30-day cap before applying its owner-only cooldown exception.
- VS Code `web_upload` defaults to true. With `publish=true`, authorization and candidate validation still run; the CLI publish job is skipped when `web_upload=true`.

## Checks and limits

- Parsed all four edited workflow files with `yaml.safe_load`: all returned `YAML_OK`.
- Focused release-candidate tests: 24 passed; C901 and `git diff --check` passed in the source-validation run.
- This is a static/source review. It does not establish GitHub Actions execution, protected-environment approval, provider publication, or marketplace state.
