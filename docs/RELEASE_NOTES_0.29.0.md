# Code Factory 0.29.0

## GitHub Proof Review

This release adds `factory github proof-review`: a deterministic, local adapter
that recompiles the current Diff-to-Proof Review and binds it to an exact GitHub
pull-request head SHA. Its optional workflow creates one neutral advisory
**FactoryLine / Proof Review** Check and one stable walkthrough comment.

The walkthrough carries the exact changed paths, deterministic cohorts, source
review SHA-256, findings, unproven claims, existing Mermaid map, and one
fact-derived next action. Altered review facts are rejected before an artifact
is written.

```powershell
pip install factoryline-code-factory==0.29.0
factory github proof-review `
  --root . `
  --base origin/main `
  --head-sha abcdefabcdefabcdefabcdefabcdefabcdefabcd `
  --changed factoryline/change_review.py `
  --json
```

## Works with CodeRabbit and other AI reviewers

Code Factory does not try to clone or consume CodeRabbit. CodeRabbit can keep
providing AI review findings and suggestions. FactoryLine contributes a
separate deterministic proof surface: declared gaps, coverage, stale evidence,
and the next review action. Both can appear on one pull request without a
CodeRabbit account, API key, credential, or comment becoming FactoryLine proof.

The Check is deliberately `neutral`. FactoryLine does not approve, merge,
close, label, assign, modify source, run a repair, execute a test, publish,
deploy, sign, or claim production readiness.

## Editor and public surfaces

The bundled VS Code and JetBrains adapters now explain the complementary
review-stack workflow. Their local proof controls remain unchanged; the GitHub
delivery adapter is configured per repository. The JetBrains Marketplace update
remains subject to the existing vendor review gate.

Read [GitHub Proof Review](GITHUB_PROOF_REVIEW.md) for setup and the exact
authority boundary.
