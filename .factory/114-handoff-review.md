# VS Code release feature-ID handoff review

Reviewed the current workflow and integrity-test diff for the VS Code internal release-contract feature ID.

The command now derives the internal feature name as `vscode-${RELEASE_REF//+/-}`, matching the existing Open VSX normalization. For `vscode-v1.1.4+build.1`, this yields the valid stable feature ID `vscode-v1.1.4-build.1` (the `+` is replaced with `-`). The original `RELEASE_REF` remains unchanged in the workflow input, immutable tag resolution and tag-to-commit checks, and cadence-exception identity/payload. The release preflight still receives `--candidate-tag "$RELEASE_REF"`, so the approved external tag remains `vscode-v1.1.4+build.1`.

The added integrity assertion checks that the contract preparation command uses this normalization. No tag, source-binding, exception, protected-environment, or publication gate is changed in this diff. This is a bounded static review; no workflow execution was performed.

Actual Bash expression execution produced vscode-vscode-v1.1.4-build.1 (existing channel prefix retained), which satisfies the unchanged handoff identifier grammar.
