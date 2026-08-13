# Plan: github-proof-review-bot
Spec: specs/github-proof-review-bot.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Add a pure, SHA-validating GitHub Proof Review renderer above the existing
   deterministic Change Review facts.
2. Expose the renderer through a read-only local CLI and an opt-in GitHub
   pull-request workflow that publishes only a stable comment and advisory Check.
3. Document the CodeRabbit complement boundary and make the public product
   surfaces lead with independent proof rather than generic AI review claims.

## Tasks (atomic - each independently shippable)
- [ ] T1 | slice=factoryline | files=<=4 | verify=`pytest -q tests/test_github_proof_review.py` | Add the SHA-bound payload renderer, optional artifacts, and deterministic cohort coverage tests.
- [ ] T2 | slice=factoryline/.github | files=<=4 | verify=`pytest -q tests/test_github_proof_review.py tests/test_publication_metadata.py` | Add the local CLI and opt-in pull-request workflow with a stable comment and advisory Check only.
- [ ] T3 | slice=docs | files=<=4 | verify=`pytest -q tests/test_publication_metadata.py tests/test_huggingface_surface.py` | Reposition Code Factory as a complementary proof layer for CodeRabbit and a standalone local proof workflow.
