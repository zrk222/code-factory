# Specialty security diff review: VS Code Marketplace token env

**Verdict: PASS for the scoped change.** The working diff moves the `VSCE_PAT` secret reference from inline shell interpolation to the authorize step's `env`, and the shell checks only the environment variable (`test -n "$VSCE_PAT"`). This avoids embedding the secret value into generated shell source. The publish step continues to pass the credential through its environment for the actual `vsce publish` invocation.

The authorize CLI-credential step remains conditional on `inputs.web_upload != true`. The website-upload step remains conditional on `inputs.web_upload == true`, has no `VSCE_PAT` environment/run usage, and the existing test asserts `web_upload` defaults to `true`; thus the default website-upload route does not require the CLI publishing token. The workflow and tests retain these conditions.

The updated tests assert the secret is step environment data rather than shell text, require the environment-variable check, and assert no inline `${{ secrets.VSCE_PAT }}` interpolation. `git diff --check` completed with no output. No tests were run, per review scope.

## Hash binding

- `.github/workflows/vscode-marketplace.yml`: SHA-1 blob `6eba80c3425563154394b6da1a88d8316dd7cd09`
- `tests/test_release_integrity.py`: SHA-1 blob `ac93e15e9dde4ee268b0121c2e223a0e42f249a1`

Hashes identify the exact reviewed file contents. Any subsequent edit invalidates this review binding.

## Limits

This is a source-level diff review only. It does not establish provider-side secret configuration, workflow execution, marketplace publication, or test execution.
