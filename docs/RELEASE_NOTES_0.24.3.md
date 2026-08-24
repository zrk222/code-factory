# Code Factory 0.24.3

Code Factory 0.24.3 adds **PRD Grill**, a small, local clarification stage
before PRD optimization, Product Graph compilation, and app scaffolding.

- `factory prd grill PRD.md --root . --mode quick` writes at most three
  dependency-safe current questions; `--mode deep` writes at most five and
  includes experience-state gaps.
- Each answer sheet is source-bound and carries observed evidence, the target
  PRD section, a recommendation, an answer stub, deferred dependencies, and a
  receipt that `factory prd verify` can check.
- PRD Grill does not modify the source, generate an answer, call a model, or
  grant implementation, release, or external-effect authority. `--confirm`
  records only a human shared-understanding marker when no observed gaps remain.
- GitHub, PyPI, Hugging Face, VS Code, JetBrains, and the ready-to-review
  Marketplace listing copy now explain this path. The JetBrains Marketplace
  update remains blocked by the existing pending Marketplace moderation gate;
  Open VSX remains blocked until its protected publisher token is configured.
